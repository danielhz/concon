//! One-off fix: rename dataset "MLIPs Literature" to "MetaLearn/MLIPs Literature"

use oxigraph::store::Store;

fn main() {
    let store = Store::open("data/system").expect("Failed to open system store");

    let update = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        DELETE { <https://mlipe.2mia.org/datasets/MLIPs%20Literature> mlipe:datasetName "MLIPs Literature" }
        INSERT { <https://mlipe.2mia.org/datasets/MLIPs%20Literature> mlipe:datasetName "MetaLearn/MLIPs Literature" }
        WHERE { <https://mlipe.2mia.org/datasets/MLIPs%20Literature> mlipe:datasetName "MLIPs Literature" }
    "#;

    match store.update(update) {
        Ok(()) => println!("Fixed dataset name: MLIPs Literature -> MetaLearn/MLIPs Literature"),
        Err(e) => eprintln!("Failed: {}", e),
    }
}
