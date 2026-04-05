//! One-off migration: assign all existing datasets to the root team via mlipe:ownsDataset.
//! Run with: cargo run --bin migrate_team_ownership

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use concon::store::{sparql_query, sparql_update};

fn main() {
    let data_dir = std::env::var("MLIPE_DATA_DIR").unwrap_or_else(|_| "data".into());
    let system_path = format!("{}/system", data_dir);

    println!("Opening system store at: {}", system_path);
    let store = Store::open(&system_path).expect("Failed to open system store");

    // Find all datasets
    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?ds ?name WHERE {
            ?ds a mlipe:Dataset ;
                mlipe:datasetName ?name .
        }
    "#;

    let mut datasets = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(&store,query) {
        for solution in solutions.flatten() {
            let ds_iri = solution.get("ds").unwrap().to_string();
            let name = solution.get("name").unwrap().to_string();
            datasets.push((ds_iri, name));
        }
    }

    if datasets.is_empty() {
        println!("No datasets found in system store.");
        return;
    }

    println!("Found {} datasets:", datasets.len());
    for (iri, name) in &datasets {
        println!("  {} ({})", name, iri);
    }

    // Check which already have ownsDataset
    let check_query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?ds WHERE {
            ?team mlipe:ownsDataset ?ds .
        }
    "#;

    let mut already_owned = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(&store,check_query) {
        for solution in solutions.flatten() {
            already_owned.push(solution.get("ds").unwrap().to_string());
        }
    }

    let root_team = "https://mlipe.2mia.org/teams/root";

    for (ds_iri, name) in &datasets {
        if already_owned.contains(ds_iri) {
            println!("  SKIP {} — already has team ownership", name);
            continue;
        }

        let ds_iri_clean = ds_iri.trim_matches(|c| c == '<' || c == '>');
        let update = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {{
                <{root_team}> mlipe:ownsDataset <{ds_iri_clean}> .
            }}
            "#,
        );

        match sparql_update(&store,&update) {
            Ok(()) => println!("  OK assigned {} to root team", name),
            Err(e) => println!("  ERROR on {}: {}", name, e),
        }
    }

    println!("Migration complete.");
}
