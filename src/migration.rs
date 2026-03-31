use std::path::{Path, PathBuf};

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use crate::auth;

/// The schema version expected by this build of the application.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

const SYSTEM_IRI: &str = "https://mlipe.2mia.org/system";

/// Read the schema version from the system store.
/// Returns 1 if no version triple exists (pre-versioning data).
pub fn get_schema_version(store: &Store) -> u32 {
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?v WHERE {{
            <{SYSTEM_IRI}> mlipe:schemaVersion ?v .
        }}
        LIMIT 1
        "#,
    );

    if let Ok(QueryResults::Solutions(solutions)) = store.query(&query) {
        for solution in solutions.flatten() {
            if let Some(val) = solution.get("v") {
                let s = auth::strip_literal(&val.to_string());
                if let Ok(v) = s.parse::<u32>() {
                    return v;
                }
            }
        }
    }
    1
}

/// Check that the system store schema version matches what the app expects.
/// Returns Ok if compatible, Err with instructions if not.
pub fn check_schema_version(store: &Store) -> Result<(), String> {
    let version = get_schema_version(store);
    if version == CURRENT_SCHEMA_VERSION {
        Ok(())
    } else if version < CURRENT_SCHEMA_VERSION {
        Err(format!(
            "Data schema version {} is older than expected version {}. \
             Run `./target/release/migrate` to upgrade.",
            version, CURRENT_SCHEMA_VERSION
        ))
    } else {
        Err(format!(
            "Data schema version {} is newer than expected version {}. \
             Upgrade the application to a newer version.",
            version, CURRENT_SCHEMA_VERSION
        ))
    }
}

/// Copy the entire data directory to a timestamped backup.
/// Returns the path to the backup directory.
pub fn backup_data(data_dir: &str) -> Result<PathBuf, String> {
    let src = Path::new(data_dir);
    if !src.exists() {
        return Err(format!("Data directory '{}' does not exist", data_dir));
    }

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup_name = format!("{}.backup-{}", data_dir, timestamp);
    let dest = Path::new(&backup_name);

    copy_dir_recursive(src, dest)
        .map_err(|e| format!("Failed to create backup at '{}': {}", backup_name, e))?;

    Ok(dest.to_path_buf())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Run all pending migrations from the current version to CURRENT_SCHEMA_VERSION.
pub fn migrate(data_dir: &str, store: &Store) -> Result<(), String> {
    let mut version = get_schema_version(store);

    if version == CURRENT_SCHEMA_VERSION {
        tracing::info!("Schema is already at version {}, nothing to migrate", version);
        return Ok(());
    }

    if version > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "Schema version {} is newer than expected {}. Cannot downgrade.",
            version, CURRENT_SCHEMA_VERSION
        ));
    }

    tracing::info!("Current schema version: {}", version);
    tracing::info!("Target schema version: {}", CURRENT_SCHEMA_VERSION);

    // Create backup before any changes
    let backup_path = backup_data(data_dir)?;
    tracing::info!("Backup created at: {}", backup_path.display());

    // Run migrations in order
    while version < CURRENT_SCHEMA_VERSION {
        let next = version + 1;
        tracing::info!("Migrating {} → {} ...", version, next);

        match version {
            1 => migrate_v1_to_v2(data_dir, store)?,
            _ => return Err(format!("No migration defined for {} → {}", version, next)),
        }

        set_schema_version(store, next)?;
        version = next;
        tracing::info!("Migration to version {} complete", version);
    }

    Ok(())
}

fn set_schema_version(store: &Store, version: u32) -> Result<(), String> {
    // Remove old version triple if any
    let delete = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        DELETE WHERE {{
            <{SYSTEM_IRI}> mlipe:schemaVersion ?old .
        }}
        "#,
    );
    let _ = store.update(&delete);

    // Insert new version
    let insert = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {{
            <{SYSTEM_IRI}> mlipe:schemaVersion {version} .
        }}
        "#,
    );
    store.update(&insert).map_err(|e| e.to_string())
}

/// Migration 1→2: Qualify dataset names with owning team path.
///
/// - Reads all datasets and their owning teams from the system store
/// - Resolves each team to a path (e.g., "root", "materials", "materials/atomistic")
/// - Renames mlipe:datasetName from "foo" to "root/foo" (or appropriate team path)
/// - Moves disk directories accordingly
fn migrate_v1_to_v2(data_dir: &str, store: &Store) -> Result<(), String> {
    // Get all datasets with their names and owning teams
    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?ds ?name ?team ?teamName WHERE {
            ?ds a mlipe:Dataset ;
                mlipe:datasetName ?name .
            ?team mlipe:ownsDataset ?ds ;
                  mlipe:teamName ?teamName .
        }
    "#;

    let mut renames: Vec<(String, String, String)> = Vec::new(); // (ds_iri, old_name, new_name)

    if let Ok(QueryResults::Solutions(solutions)) = store.query(query) {
        for solution in solutions.flatten() {
            let ds_iri = solution.get("ds").map(|v| v.to_string()).unwrap_or_default();
            let old_name = solution.get("name").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default();
            let team_iri = solution.get("team").map(|v| v.to_string()).unwrap_or_default();

            // Resolve team path from IRI
            let team_path = resolve_team_path_from_iri(store, &team_iri);

            let new_name = format!("{}/{}", team_path, old_name);

            if old_name != new_name {
                renames.push((ds_iri, old_name, new_name));
            }
        }
    }

    let datasets_dir = Path::new(data_dir).join("datasets");

    for (ds_iri, old_name, new_name) in &renames {
        tracing::info!("  Renaming dataset '{}' → '{}'", old_name, new_name);

        // Move disk directory
        let old_path = datasets_dir.join(old_name);
        let new_path = datasets_dir.join(new_name);
        if old_path.exists() {
            if let Some(parent) = new_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
            }
            std::fs::rename(&old_path, &new_path)
                .map_err(|e| format!("Failed to move {} → {}: {}", old_path.display(), new_path.display(), e))?;
        }

        // Update dataset name in system store
        let ds_iri_clean = ds_iri.trim_matches(|c| c == '<' || c == '>');
        let update = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            DELETE {{ <{ds_iri_clean}> mlipe:datasetName "{old_name}" }}
            INSERT {{ <{ds_iri_clean}> mlipe:datasetName "{new_name}" }}
            WHERE {{ <{ds_iri_clean}> mlipe:datasetName "{old_name}" }}
            "#,
        );
        store.update(&update).map_err(|e| format!("Failed to update dataset name: {}", e))?;
    }

    tracing::info!("  Migrated {} dataset(s)", renames.len());
    Ok(())
}

/// Resolve a team IRI to its path by walking parent teams.
/// E.g., root team → "root", a child team → "root/materials".
/// For migration purposes, we build the path from team names.
fn resolve_team_path_from_iri(store: &Store, team_iri: &str) -> String {
    let iri = team_iri.trim_matches(|c| c == '<' || c == '>');
    let mut segments = Vec::new();

    let mut current_iri = iri.to_string();
    loop {
        // Get team name and parent
        let query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            SELECT ?name ?parent WHERE {{
                <{current_iri}> mlipe:teamName ?name .
                OPTIONAL {{ <{current_iri}> mlipe:hasParentTeam ?parent }}
            }}
            LIMIT 1
            "#,
        );

        let mut name = None;
        let mut parent = None;

        if let Ok(QueryResults::Solutions(solutions)) = store.query(&query) {
            for solution in solutions.flatten() {
                name = solution.get("name").map(|v| auth::strip_literal(&v.to_string()));
                parent = solution.get("parent").map(|v| {
                    v.to_string().trim_matches(|c| c == '<' || c == '>').to_string()
                });
            }
        }

        match name {
            Some(n) => segments.push(n),
            None => break,
        }

        match parent {
            Some(p) => current_iri = p,
            None => break, // reached root
        }
    }

    segments.reverse();
    segments.join("/")
}
