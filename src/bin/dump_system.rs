//! Dump all triples from the system store for debugging.

use oxigraph::io::RdfFormat;
use oxigraph::model::GraphNameRef;
use oxigraph::store::Store;

fn main() {
    let store = Store::open("data/system").expect("Failed to open system store");
    let buf = store
        .dump_graph_to_writer(GraphNameRef::DefaultGraph, RdfFormat::Turtle, Vec::new())
        .expect("dump");
    println!("{}", String::from_utf8(buf).expect("utf8"));
}
