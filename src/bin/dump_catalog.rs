//! Dump file catalog for a team.

use oxigraph::io::RdfFormat;
use oxigraph::model::GraphNameRef;
use oxigraph::store::Store;

fn main() {
    let team = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "MetaLearn".into());
    let path = format!("data/catalogs/{}", team);
    println!("Opening catalog at: {}", path);
    match Store::open(&path) {
        Ok(store) => {
            let buf = store
                .dump_graph_to_writer(GraphNameRef::DefaultGraph, RdfFormat::Turtle, Vec::new())
                .expect("dump");
            let content = String::from_utf8(buf).expect("utf8");
            if content.trim().is_empty() {
                println!("(empty catalog)");
            } else {
                println!("{}", content);
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
