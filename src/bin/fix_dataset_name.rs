//! Fix: insert missing dataset metadata for MLIPs Literature

use oxigraph::store::Store;

use concon::store::{sparql_query, sparql_update};

fn main() {
    let store = Store::open("data/system").expect("Failed to open system store");

    let update = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {
            <https://mlipe.2mia.org/datasets/MetaLearn/MLIPs%20Literature> a mlipe:Dataset ;
                mlipe:datasetName "MetaLearn/MLIPs Literature" ;
                mlipe:hasVisibility mlipe:TeamOnlyVisibility .
            <https://mlipe.2mia.org/teams/MetaLearn> mlipe:ownsDataset
                <https://mlipe.2mia.org/datasets/MetaLearn/MLIPs%20Literature> .
        }
    "#;

    match sparql_update(&store,update) {
        Ok(()) => println!("Inserted dataset metadata for MetaLearn/MLIPs Literature"),
        Err(e) => eprintln!("Failed: {}", e),
    }

    // Verify
    use oxigraph::sparql::QueryResults;
    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?name ?team WHERE {
            ?ds a mlipe:Dataset ; mlipe:datasetName ?name .
            ?team mlipe:ownsDataset ?ds .
        }
    "#;
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(&store,query) {
        for solution in solutions.flatten() {
            println!("  dataset: {:?}, team: {:?}",
                solution.get("name"), solution.get("team"));
        }
    }
}
