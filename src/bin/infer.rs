//! Dev-only helper for the inference reference-oracle cross-check
//! (`docs/inference-oracle/`). Reads Turtle from stdin into one source graph,
//! runs `inference::recompute`, and writes the derived `computed` graph as
//! N-Triples to stdout. Not used by the running server; exists so the owlrl
//! oracle script can obtain concon's materialization for a fixture.

use std::io::{self, Read, Write};

use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode};
use oxigraph::store::Store;

use concon::inference;

/// A single source graph following the `…/graph/` convention, so
/// `recompute` derives `https://ex.org/ds/graph/computed`.
const SOURCE_GRAPH: &str = "https://ex.org/ds/graph/kg";

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("read stdin");

    let store = Store::new().expect("in-memory store");
    let src = NamedNode::new(SOURCE_GRAPH).expect("valid source graph IRI");
    let parser =
        RdfParser::from_format(RdfFormat::Turtle).with_default_graph(GraphName::NamedNode(src));
    store
        .load_from_reader(parser, input.as_slice())
        .expect("parse Turtle from stdin");

    let report = inference::recompute(&store).expect("recompute");

    if let Some(computed) = report.computed_graph {
        let node = NamedNode::new(computed).expect("valid computed graph IRI");
        let buf = store
            .dump_graph_to_writer(
                GraphNameRef::NamedNode(node.as_ref()),
                RdfFormat::NTriples,
                Vec::new(),
            )
            .expect("dump computed graph");
        io::stdout().write_all(&buf).expect("write stdout");
    }
}
