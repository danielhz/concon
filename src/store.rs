use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use std::time::Duration;

use oxigraph::io::RdfFormat;
use oxigraph::model::{
    GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNodeRef, QuadRef, TermRef,
};
use oxigraph::sparql::{
    CancellationToken, QueryEvaluationError, QueryResults, SparqlEvaluator, UpdateEvaluationError,
};
use oxigraph::store::Store;

/// Wall-clock limit for a single public SPARQL query (B4 hardening). A pathological
/// query is cancelled past this so it can't pin a CPU on the public endpoint.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Execute a SPARQL query with union-default-graph semantics: a pattern over
/// the default graph (no `GRAPH` clause) sees the union of all named graphs.
///
/// The `mlips` dataset stores schema, instances, and competency-question data
/// in separate named graphs so the loader can replace one graph idempotently
/// (replace-by-graph). Entity dereferencing and the public endpoint query the
/// union so cross-graph links resolve exactly as they would in a single store.
pub fn sparql_query_union<'a>(
    store: &'a Store,
    query: &str,
) -> Result<QueryResults<'a>, QueryEvaluationError> {
    let mut prepared = SparqlEvaluator::new()
        .parse_query(query)
        .map_err(QueryEvaluationError::from)?;
    prepared.dataset_mut().set_default_graph_as_union();
    prepared.on_store(store).execute()
}

/// Like `sparql_query_union`, but cancels the evaluation after `timeout`. Used
/// by the public `_sparql` endpoint so an arbitrary user query can't run
/// unbounded. Evaluation is lazy (the result iterator), so the timer also
/// bounds serialization of the results, not just planning.
///
/// A lightweight timer thread flips the cancellation token at the deadline; if
/// the query finishes first the cancel is a harmless no-op on a dropped token.
pub fn sparql_query_union_timeout<'a>(
    store: &'a Store,
    query: &str,
    timeout: Duration,
) -> Result<QueryResults<'a>, QueryEvaluationError> {
    let token = CancellationToken::new();
    let timer = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        timer.cancel();
    });
    let mut prepared = SparqlEvaluator::new()
        .with_cancellation_token(token)
        .parse_query(query)
        .map_err(QueryEvaluationError::from)?;
    prepared.dataset_mut().set_default_graph_as_union();
    prepared.on_store(store).execute()
}

/// Execute a SPARQL update on a store using the new SparqlEvaluator API.
pub fn sparql_update(store: &Store, update: &str) -> Result<(), UpdateEvaluationError> {
    SparqlEvaluator::new()
        .parse_update(update)
        .map_err(UpdateEvaluationError::from)?
        .on_store(store)
        .execute()
}

/// File name of the served ontology document within a dataset's doc store.
pub const DOC_INDEX_FILE: &str = "index.xhtml";

/// Namespace of the system-store vocabulary.
pub const MLIPE_NS: &str = "https://mlipe.2mia.org/ontology#";
/// IRI prefix of dataset resources in the system store (`…/datasets/<name>`).
pub const DATASET_IRI_PREFIX: &str = "https://mlipe.2mia.org/datasets/";

/// Upper bound on the length of one dataset/team name segment.
pub const MAX_NAME_SEGMENT_LEN: usize = 128;
/// Upper bound on the length of a whole qualified dataset name.
pub const MAX_DATASET_NAME_LEN: usize = 256;

/// Whether `s` is a safe, well-formed name segment — one path component of a
/// qualified dataset name (`team/sub/dataset`) or one team-path segment. The
/// allow-list is deliberately conservative: a segment becomes a filesystem
/// directory name, part of an IRI, and a SPARQL literal, so it must not be
/// able to escape any of those. ASCII letters, digits, `_`, `-` and `.` only;
/// no leading `.` (rules out `.`, `..` and hidden directories); length-capped.
pub fn is_valid_name_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_SEGMENT_LEN
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Whether `name` is a well-formed qualified dataset name: one or more
/// `/`-separated valid segments (see `is_valid_name_segment`), no empty
/// segment (so no leading/trailing/double `/`), total length capped. Every
/// dataset name reaching the store must pass this before it is used as a
/// path, an IRI, or a literal.
pub fn is_valid_dataset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DATASET_NAME_LEN
        && name.split('/').all(is_valid_name_segment)
}

/// Escape a string for use inside a SPARQL double-quoted string literal, so
/// a user-supplied value cannot break out of the literal in a query or an
/// INSERT. SPARQL has no parameter binding, so wherever a value must be
/// interpolated into query text it goes through this first. Prefer the
/// Oxigraph model API (`quads_for_pattern`, `insert`) where a lookup or write
/// can avoid query text altogether; names that are validated by an allow-list
/// (`is_valid_name_segment`, `auth::is_valid_username`,
/// `auth::is_valid_team_name`) contain nothing this would change.
pub fn escape_sparql_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// A `mlipe:` vocabulary term as a named node.
fn mlipe_node(local: &str) -> Result<NamedNode, String> {
    NamedNode::new(format!("{MLIPE_NS}{local}")).map_err(|e| e.to_string())
}

/// The three visibility levels a dataset may carry (`mlipe:hasVisibility`).
pub const VISIBILITIES: [&str; 3] = [
    "PublicVisibility",
    "LoggedUsersVisibility",
    "TeamOnlyVisibility",
];

/// Manages multiple Oxigraph stores, one per dataset.
pub struct StoreManager {
    /// The system store holds user, team, role, and dataset metadata.
    pub system: Store,
    /// Dataset stores, keyed by dataset name.
    datasets: RwLock<HashMap<String, Store>>,
    /// File catalog stores, keyed by team path (e.g., "root", "materials").
    catalogs: RwLock<HashMap<String, Store>>,
    /// SHACL stores, keyed by dataset name. Each dataset can have its own SHACL shapes.
    shacl_stores: RwLock<HashMap<String, Store>>,
    /// Curated documentation files (doc-as-file), keyed by (dataset name, file
    /// name). Holds the served ontology document and its companion assets
    /// (e.g. a stylesheet). In-memory mode keeps them here; persistent mode
    /// also mirrors them under `<data_dir>/docs/<name>/`.
    docs: RwLock<HashMap<(String, String), Vec<u8>>>,
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
            shacl_stores: RwLock::new(HashMap::new()),
            docs: RwLock::new(HashMap::new()),
            data_dir: PathBuf::new(),
        })
    }

    /// Create a new StoreManager with persistent stores on disk.
    pub fn new_persistent(data_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data_path = Path::new(data_dir);
        std::fs::create_dir_all(data_path.join("system"))?;
        std::fs::create_dir_all(data_path.join("datasets"))?;
        std::fs::create_dir_all(data_path.join("catalogs"))?;
        std::fs::create_dir_all(data_path.join("shacl"))?;
        std::fs::create_dir_all(data_path.join("docs"))?;

        let system = Store::open(data_path.join("system"))?;

        Ok(Self {
            system,
            datasets: RwLock::new(HashMap::new()),
            catalogs: RwLock::new(HashMap::new()),
            shacl_stores: RwLock::new(HashMap::new()),
            docs: RwLock::new(HashMap::new()),
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
        if !is_valid_dataset_name(name) {
            return Err(format!("Invalid dataset name '{}'", name));
        }
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

        // Remove SHACL store
        if let Ok(mut shacl) = self.shacl_stores.write() {
            shacl.remove(name);
        }
        if !self.data_dir.as_os_str().is_empty() {
            let shacl_path = self.data_dir.join("shacl").join(name);
            if shacl_path.exists() {
                let _ = std::fs::remove_dir_all(&shacl_path);
            }
        }

        // Remove dataset metadata from system store. Built with the model API
        // (no SPARQL text is assembled from `name`): find every resource whose
        // `mlipe:datasetName` is `name`, then drop all quads it is the subject
        // of (type, name, visibility) and all quads it is the object of (the
        // owning team's `mlipe:ownsDataset`).
        if let Err(e) = self.remove_dataset_metadata(name) {
            tracing::warn!(
                "Dataset '{}' deleted but its metadata was not removed: {}",
                name,
                e
            );
        }
        Ok(())
    }

    /// Remove every system-store quad about the dataset named `name` (as
    /// subject or object). Pure model-API traversal; `name` is only ever used
    /// as a literal value.
    fn remove_dataset_metadata(&self, name: &str) -> Result<(), String> {
        let dataset_name = mlipe_node("datasetName")?;
        let name_lit = Literal::new_simple_literal(name);
        let subjects: Vec<_> = self
            .system
            .quads_for_pattern(
                None,
                Some(dataset_name.as_ref()),
                Some(TermRef::from(name_lit.as_ref())),
                None,
            )
            .filter_map(|q| q.ok().map(|q| q.subject))
            .collect();
        for ds in subjects {
            let ds_ref = NamedOrBlankNodeRef::from(&ds);
            let as_subject = self
                .system
                .quads_for_pattern(Some(ds_ref), None, None, None)
                .filter_map(Result::ok);
            let as_object = self
                .system
                .quads_for_pattern(None, None, Some(TermRef::from(ds_ref)), None)
                .filter_map(Result::ok);
            let quads: Vec<_> = as_subject.chain(as_object).collect();
            for q in &quads {
                self.system.remove(q).map_err(|e| e.to_string())?;
            }
        }
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
        // Built with the model API rather than `format!`-ed SPARQL: `name` is
        // validated and then only ever an IRI path tail / a literal value, and
        // `visibility` must be one of the known levels.
        if !is_valid_dataset_name(name) {
            return Err(format!("Invalid dataset name '{}'", name));
        }
        if !VISIBILITIES.contains(&visibility) {
            return Err(format!("Invalid visibility '{}'", visibility));
        }
        let team_iri = team_iri.trim_matches(|c| c == '<' || c == '>');
        let team = NamedNode::new(team_iri).map_err(|e| format!("Invalid team IRI: {e}"))?;
        let ds = NamedNode::new(format!("{DATASET_IRI_PREFIX}{name}"))
            .map_err(|e| format!("Invalid dataset IRI: {e}"))?;
        let rdf_type =
            NamedNodeRef::new_unchecked("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
        let dataset_class = mlipe_node("Dataset")?;
        let p_name = mlipe_node("datasetName")?;
        let p_visibility = mlipe_node("hasVisibility")?;
        let p_owns = mlipe_node("ownsDataset")?;
        let visibility_node = mlipe_node(visibility)?;
        let name_lit = Literal::new_simple_literal(name);
        let g = GraphNameRef::DefaultGraph;
        let quads = [
            QuadRef::new(&ds, rdf_type, &dataset_class, g),
            QuadRef::new(&ds, &p_name, &name_lit, g),
            QuadRef::new(&ds, &p_visibility, &visibility_node, g),
            QuadRef::new(&team, &p_owns, &ds, g),
        ];
        for q in quads {
            self.system.insert(q).map_err(|e| e.to_string())?;
        }
        Ok(())
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

    /// Read a documentation file for a dataset — the served ontology document
    /// (`DOC_INDEX_FILE`) or a companion asset (e.g. a stylesheet). Checks the
    /// in-memory cache first, then the on-disk doc store. `None` if absent.
    pub fn read_doc_file(&self, name: &str, filename: &str) -> Option<Vec<u8>> {
        if let Ok(docs) = self.docs.read() {
            if let Some(bytes) = docs.get(&(name.to_string(), filename.to_string())) {
                return Some(bytes.clone());
            }
        }
        if self.data_dir.as_os_str().is_empty() {
            return None;
        }
        let path = self.data_dir.join("docs").join(name).join(filename);
        std::fs::read(path).ok()
    }

    /// Store a documentation file for a dataset (the served document or a
    /// companion asset). Idempotent replace: overwrites any existing file.
    pub fn write_doc_file(&self, name: &str, filename: &str, bytes: Vec<u8>) -> Result<(), String> {
        if !self.data_dir.as_os_str().is_empty() {
            let dir = self.data_dir.join("docs").join(name);
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(dir.join(filename), &bytes).map_err(|e| e.to_string())?;
        }
        let mut docs = self.docs.write().map_err(|e| e.to_string())?;
        docs.insert((name.to_string(), filename.to_string()), bytes);
        Ok(())
    }

    /// Whether a dataset has a served ontology document.
    pub fn has_doc(&self, name: &str) -> bool {
        self.read_doc_file(name, DOC_INDEX_FILE).is_some()
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

    /// Get or create a SHACL store for a dataset.
    pub fn get_or_create_shacl_store(&self, dataset_name: &str) -> Result<Store, String> {
        // Check if already loaded
        {
            let stores = self.shacl_stores.read().map_err(|e| e.to_string())?;
            if let Some(store) = stores.get(dataset_name) {
                return Ok(store.clone());
            }
        }

        // Create or open
        let mut stores = self.shacl_stores.write().map_err(|e| e.to_string())?;
        // Double-check after acquiring write lock
        if let Some(store) = stores.get(dataset_name) {
            return Ok(store.clone());
        }

        let store = if self.data_dir.as_os_str().is_empty() {
            Store::new().map_err(|e| e.to_string())?
        } else {
            let path = self.data_dir.join("shacl").join(dataset_name);
            std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            Store::open(&path).map_err(|e| e.to_string())?
        };

        stores.insert(dataset_name.to_string(), store.clone());
        Ok(store)
    }

    /// Get a SHACL store for a dataset (read-only, returns None if not yet created).
    pub fn get_shacl_store(&self, dataset_name: &str) -> Option<Store> {
        // Check in-memory first
        if let Ok(stores) = self.shacl_stores.read() {
            if let Some(store) = stores.get(dataset_name) {
                return Some(store.clone());
            }
        }

        // Try to open from disk if persistent
        if self.data_dir.as_os_str().is_empty() {
            return None;
        }

        let path = self.data_dir.join("shacl").join(dataset_name);
        if !path.exists() {
            return None;
        }

        // Open and cache it
        if let Ok(mut stores) = self.shacl_stores.write() {
            if let Ok(store) = Store::open(&path) {
                stores.insert(dataset_name.to_string(), store.clone());
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

    #[test]
    fn test_shacl_store_create_and_get() {
        let manager = StoreManager::new_in_memory().unwrap();
        manager.create_dataset("root/test-ds").unwrap();

        // Create SHACL store and insert a shape
        let shacl = manager.get_or_create_shacl_store("root/test-ds").unwrap();
        sparql_update(
            &shacl,
            r#"
            PREFIX sh: <http://www.w3.org/ns/shacl#>
            PREFIX ex: <http://example.org/>
            INSERT DATA {
                ex:PersonShape a sh:NodeShape ;
                    sh:targetClass ex:Person ;
                    sh:property ex:nameShape .
                ex:nameShape a sh:PropertyShape ;
                    sh:path ex:name ;
                    sh:minCount 1 .
            }
            "#,
        )
        .unwrap();

        // Retrieve the same store and verify data persisted
        let shacl2 = manager.get_shacl_store("root/test-ds").unwrap();
        let results = sparql_query(
            &shacl2,
            r#"
            PREFIX sh: <http://www.w3.org/ns/shacl#>
            SELECT ?shape WHERE { ?shape a sh:NodeShape }
            "#,
        )
        .unwrap();
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
    fn test_dataset_name_validation() {
        for ok in ["root/ds", "mlips/mlips", "a", "team/sub/ds-1.2_x", "A-b.c"] {
            assert!(is_valid_dataset_name(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            "/",
            "root/",
            "/ds",
            "root//ds",
            "../etc",
            "root/..",
            "root/.hidden",
            ".",
            "a b",
            "root/ds\"",
            "root/ds>",
            "root/ds;",
            "ro\u{e9}t/ds",
            "root/ds\n",
        ] {
            assert!(!is_valid_dataset_name(bad), "{bad:?} should be invalid");
        }
        let long_segment = "a".repeat(MAX_NAME_SEGMENT_LEN + 1);
        assert!(!is_valid_dataset_name(&long_segment));
        let long_name = (0..3)
            .map(|_| "a".repeat(100))
            .collect::<Vec<_>>()
            .join("/");
        assert!(!is_valid_dataset_name(&long_name));
    }

    #[test]
    fn test_create_dataset_rejects_invalid_name() {
        let manager = StoreManager::new_in_memory().unwrap();
        assert!(manager.create_dataset("../escape").is_err());
        assert!(manager.create_dataset("root/.hidden").is_err());
        assert!(manager.list_datasets().is_empty());
        assert!(manager.insert_dataset_metadata("root/\"x").is_err());
        assert!(
            manager
                .insert_dataset_metadata_with_visibility("root/x", "NotAVisibility")
                .is_err()
        );
    }

    #[test]
    fn test_dataset_metadata_insert_and_remove() {
        let manager = StoreManager::new_in_memory().unwrap();
        manager.create_dataset("team/meta-ds").unwrap();
        manager
            .insert_dataset_metadata_full(
                "team/meta-ds",
                "TeamOnlyVisibility",
                "<https://mlipe.2mia.org/teams/team>",
            )
            .unwrap();

        let ask = |q: &str| {
            matches!(
                sparql_query(&manager.system, q),
                Ok(QueryResults::Boolean(true))
            )
        };
        assert!(ask(r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
               ASK { <https://mlipe.2mia.org/datasets/team/meta-ds> a mlipe:Dataset ;
                         mlipe:datasetName "team/meta-ds" ;
                         mlipe:hasVisibility mlipe:TeamOnlyVisibility .
                     <https://mlipe.2mia.org/teams/team> mlipe:ownsDataset
                         <https://mlipe.2mia.org/datasets/team/meta-ds> . }"#));

        manager.delete_dataset("team/meta-ds").unwrap();
        assert!(!ask(
            r#"ASK { { <https://mlipe.2mia.org/datasets/team/meta-ds> ?p ?o }
                    UNION { ?s ?p <https://mlipe.2mia.org/datasets/team/meta-ds> } }"#
        ));
        // Unrelated metadata is untouched.
        manager.create_dataset("root/other").unwrap();
        manager.insert_dataset_metadata("root/other").unwrap();
        manager.create_dataset("root/gone").unwrap();
        manager.insert_dataset_metadata("root/gone").unwrap();
        manager.delete_dataset("root/gone").unwrap();
        assert!(ask(r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
               ASK { ?ds mlipe:datasetName "root/other" }"#));
    }

    #[test]
    fn test_shacl_store_deleted_with_dataset() {
        let manager = StoreManager::new_in_memory().unwrap();
        manager.create_dataset("root/del-ds").unwrap();

        let shacl = manager.get_or_create_shacl_store("root/del-ds").unwrap();
        sparql_update(&shacl, "INSERT DATA { <urn:x> <urn:y> <urn:z> }").unwrap();

        // Delete dataset should also remove SHACL store from memory
        manager.delete_dataset("root/del-ds").unwrap();
        assert!(manager.get_shacl_store("root/del-ds").is_none());
    }
}
