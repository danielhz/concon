use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use oxigraph::io::RdfFormat;
use oxigraph::sparql::{
    QueryEvaluationError, QueryResults, SparqlEvaluator, UpdateEvaluationError,
};
use oxigraph::store::Store;

/// Execute a SPARQL query on a store using the new SparqlEvaluator API.
pub fn sparql_query<'a>(
    store: &'a Store,
    query: &str,
) -> Result<QueryResults<'a>, QueryEvaluationError> {
    SparqlEvaluator::new()
        .parse_query(query)
        .map_err(QueryEvaluationError::from)?
        .on_store(store)
        .execute()
}

/// Execute a SPARQL update on a store using the new SparqlEvaluator API.
pub fn sparql_update(store: &Store, update: &str) -> Result<(), UpdateEvaluationError> {
    SparqlEvaluator::new()
        .parse_update(update)
        .map_err(UpdateEvaluationError::from)?
        .on_store(store)
        .execute()
}

/// Manages multiple Oxigraph stores, one per dataset.
pub struct StoreManager {
    /// The system store holds user, team, role, and dataset metadata.
    pub system: Store,
    /// Dataset stores, keyed by dataset name.
    datasets: RwLock<HashMap<String, Store>>,
    /// File catalog stores, keyed by team path (e.g., "root", "materials").
    catalogs: RwLock<HashMap<String, Store>>,
    /// Base directory for dataset storage.
    data_dir: PathBuf,
}

impl StoreManager {
    /// Create a new StoreManager with in-memory stores (for tests).
    pub fn new_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let system = Store::new()?;
        Ok(Self {
            system,
            datasets: RwLock::new(HashMap::new()),
            catalogs: RwLock::new(HashMap::new()),
            data_dir: PathBuf::new(),
        })
    }

    /// Create a new StoreManager with persistent stores on disk.
    pub fn new_persistent(data_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data_path = Path::new(data_dir);
        std::fs::create_dir_all(data_path.join("system"))?;
        std::fs::create_dir_all(data_path.join("datasets"))?;
        std::fs::create_dir_all(data_path.join("catalogs"))?;

        let system = Store::open(data_path.join("system"))?;

        Ok(Self {
            system,
            datasets: RwLock::new(HashMap::new()),
            catalogs: RwLock::new(HashMap::new()),
            data_dir: data_path.to_path_buf(),
        })
    }

    /// Open dataset stores for all datasets registered in the system store.
    pub fn open_existing_datasets(&self) -> Result<(), String> {
        let query = r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            SELECT ?name WHERE {
                ?ds a mlipe:Dataset ;
                    mlipe:datasetName ?name .
            }
        "#;

        let mut names = Vec::new();
        if let Ok(QueryResults::Solutions(solutions)) = sparql_query(&self.system, query) {
            for solution in solutions.flatten() {
                if let Some(name) = solution.get("name") {
                    let name = crate::auth::strip_literal(&name.to_string());
                    names.push(name);
                }
            }
        }

        let mut datasets = self.datasets.write().map_err(|e| e.to_string())?;
        for name in names {
            let path = self.data_dir.join("datasets").join(&name);
            let store = Store::open(&path)
                .map_err(|e| format!("Failed to open dataset '{}': {}", name, e))?;
            datasets.insert(name.clone(), store);
            tracing::info!("Opened dataset: {}", name);
        }

        Ok(())
    }

    /// Create a new dataset with a persistent store.
    pub fn create_dataset(&self, name: &str) -> Result<(), String> {
        let mut datasets = self.datasets.write().map_err(|e| e.to_string())?;
        if datasets.contains_key(name) {
            return Err(format!("Dataset '{}' already exists", name));
        }

        let store = if self.data_dir.as_os_str().is_empty() {
            // In-memory mode (tests)
            Store::new().map_err(|e| e.to_string())?
        } else {
            let path = self.data_dir.join("datasets").join(name);
            std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            Store::open(&path).map_err(|e| e.to_string())?
        };

        datasets.insert(name.to_string(), store);
        Ok(())
    }

    /// Get a reference to a dataset store by name.
    pub fn get_dataset(&self, name: &str) -> Option<Store> {
        let datasets = self.datasets.read().ok()?;
        datasets.get(name).cloned()
    }

    /// List all dataset names.
    pub fn list_datasets(&self) -> Vec<String> {
        let datasets = self.datasets.read().unwrap();
        datasets.keys().cloned().collect()
    }

    /// Delete a dataset.
    pub fn delete_dataset(&self, name: &str) -> Result<(), String> {
        let mut datasets = self.datasets.write().map_err(|e| e.to_string())?;
        datasets
            .remove(name)
            .ok_or_else(|| format!("Dataset '{}' not found", name))?;

        // Remove dataset files from disk
        if !self.data_dir.as_os_str().is_empty() {
            let path = self.data_dir.join("datasets").join(name);
            if path.exists() {
                let _ = std::fs::remove_dir_all(&path);
            }
        }

        // Remove dataset metadata from system store
        let update = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            DELETE WHERE {{
                ?ds a mlipe:Dataset ;
                    mlipe:datasetName "{name}" .
                ?ds ?p ?o .
            }}
            "#,
        );
        let _ = sparql_update(&self.system, &update);
        Ok(())
    }

    /// Insert dataset metadata triples into the system store with default public visibility
    /// and root team ownership.
    pub fn insert_dataset_metadata(&self, name: &str) -> Result<(), String> {
        self.insert_dataset_metadata_full(
            name,
            "PublicVisibility",
            "https://mlipe.2mia.org/teams/root",
        )
    }

    /// Insert dataset metadata triples with a specific visibility (defaults to root team).
    pub fn insert_dataset_metadata_with_visibility(
        &self,
        name: &str,
        visibility: &str,
    ) -> Result<(), String> {
        self.insert_dataset_metadata_full(name, visibility, "https://mlipe.2mia.org/teams/root")
    }

    /// Insert dataset metadata triples with visibility and team ownership.
    pub fn insert_dataset_metadata_full(
        &self,
        name: &str,
        visibility: &str,
        team_iri: &str,
    ) -> Result<(), String> {
        let update = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {{
                <https://mlipe.2mia.org/datasets/{name}> a mlipe:Dataset ;
                    mlipe:datasetName "{name}" ;
                    mlipe:hasVisibility mlipe:{visibility} .
                <{team_iri}> mlipe:ownsDataset <https://mlipe.2mia.org/datasets/{name}> .
            }}
            "#,
        );
        sparql_update(&self.system, &update).map_err(|e| e.to_string())
    }

    /// Check whether the system store has any triples.
    pub fn is_system_empty(&self) -> bool {
        sparql_query(&self.system, "ASK { ?s ?p ?o }")
            .ok()
            .and_then(|r| match r {
                QueryResults::Boolean(b) => Some(!b),
                _ => None,
            })
            .unwrap_or(true)
    }

    /// Load a Turtle file into the system store.
    pub fn load_system_data(&self, path: &str) -> Result<(), String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("Cannot open system data file '{}': {}", path, e))?;
        let reader = BufReader::new(file);
        self.system
            .load_from_reader(RdfFormat::Turtle, reader)
            .map_err(|e| format!("Failed to parse system data '{}': {}", path, e))
    }

    /// Get the catalogs base directory path.
    pub fn catalogs_dir(&self) -> Option<PathBuf> {
        if self.data_dir.as_os_str().is_empty() {
            None
        } else {
            Some(self.data_dir.join("catalogs"))
        }
    }

    /// Get or create a file catalog store for a team.
    /// The team_path is the joined team segments (e.g., "materials", "materials/atomistic").
    /// Use "root" for the root team.
    pub fn get_or_create_file_catalog(&self, team_path: &str) -> Result<Store, String> {
        // Check if already loaded
        {
            let catalogs = self.catalogs.read().map_err(|e| e.to_string())?;
            if let Some(store) = catalogs.get(team_path) {
                return Ok(store.clone());
            }
        }

        // Create or open
        let mut catalogs = self.catalogs.write().map_err(|e| e.to_string())?;
        // Double-check after acquiring write lock
        if let Some(store) = catalogs.get(team_path) {
            return Ok(store.clone());
        }

        let store = if self.data_dir.as_os_str().is_empty() {
            Store::new().map_err(|e| e.to_string())?
        } else {
            let path = self.data_dir.join("catalogs").join(team_path);
            std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            Store::open(&path).map_err(|e| e.to_string())?
        };

        catalogs.insert(team_path.to_string(), store.clone());
        Ok(store)
    }

    /// Get a file catalog store for a team (read-only, returns None if not yet created).
    pub fn get_file_catalog(&self, team_path: &str) -> Option<Store> {
        // Check in-memory first
        if let Ok(catalogs) = self.catalogs.read() {
            if let Some(store) = catalogs.get(team_path) {
                return Some(store.clone());
            }
        }

        // Try to open from disk if persistent
        if self.data_dir.as_os_str().is_empty() {
            return None;
        }

        let path = self.data_dir.join("catalogs").join(team_path);
        if !path.exists() {
            return None;
        }

        // Open and cache it
        if let Ok(mut catalogs) = self.catalogs.write() {
            if let Ok(store) = Store::open(&path) {
                catalogs.insert(team_path.to_string(), store.clone());
                return Some(store);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_query_new_api() {
        let store = Store::new().unwrap();
        sparql_update(&store, "INSERT DATA { <urn:s> <urn:p> <urn:o> }").unwrap();
        let results = sparql_query(&store, "SELECT * WHERE { ?s ?p ?o }").unwrap();
        let mut count = 0;
        if let QueryResults::Solutions(solutions) = results {
            for solution in solutions {
                solution.unwrap();
                count += 1;
            }
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_store_update_transaction() {
        let store = Store::new().unwrap();

        // Commit persists
        let mut tx = store.start_transaction().unwrap();
        SparqlEvaluator::new()
            .parse_update("INSERT DATA { <urn:s> <urn:p> <urn:o> }")
            .unwrap()
            .on_transaction(&mut tx)
            .execute()
            .unwrap();
        tx.commit().unwrap();

        let results = sparql_query(&store, "ASK { <urn:s> <urn:p> <urn:o> }").unwrap();
        assert!(matches!(results, QueryResults::Boolean(true)));

        // Drop (rollback) discards
        let mut tx2 = store.start_transaction().unwrap();
        SparqlEvaluator::new()
            .parse_update("INSERT DATA { <urn:a> <urn:b> <urn:c> }")
            .unwrap()
            .on_transaction(&mut tx2)
            .execute()
            .unwrap();
        drop(tx2); // rollback

        let results = sparql_query(&store, "ASK { <urn:a> <urn:b> <urn:c> }").unwrap();
        assert!(matches!(results, QueryResults::Boolean(false)));
    }

    #[test]
    fn test_rdf12_quoted_triples() {
        use oxigraph::io::RdfFormat;

        let store = Store::new().unwrap();

        // RDF 1.2 triple terms are loaded via Turtle I/O (rdf-12 feature).
        // The <<( s p o )>> syntax is for triple terms (object position),
        // while << s p o >> is for reified triples (subject position).
        let turtle = r#"
            @prefix concon: <https://concon.2mia.org/ontology#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            <urn:s> <urn:p> <urn:o> .
            << <urn:s> <urn:p> <urn:o> >> a concon:StatedTriple .
        "#;
        store
            .load_from_reader(RdfFormat::Turtle, turtle.as_bytes())
            .unwrap();

        // Verify the base triple exists
        let results = sparql_query(&store, "ASK { <urn:s> <urn:p> <urn:o> }").unwrap();
        assert!(matches!(results, QueryResults::Boolean(true)));

        // Verify the reified triple annotation was stored.
        // Oxigraph 0.5 decomposes << s p o >> into a blank node with rdf:reifies.
        let results = sparql_query(
            &store,
            r#"
            PREFIX concon: <https://concon.2mia.org/ontology#>
            SELECT ?reifier WHERE {
                ?reifier a concon:StatedTriple .
            }
            "#,
        )
        .unwrap();

        let mut found = false;
        if let QueryResults::Solutions(solutions) = results {
            for solution in solutions {
                solution.unwrap();
                found = true;
            }
        }
        assert!(found, "Expected to find RDF 1.2 reified triple annotation");
    }
}
