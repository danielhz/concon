//! Ontology-document view with content negotiation (epic A2).
//!
//! Served at a dataset's base URL (`<dataset-base>/`, i.e. the `None` view):
//!
//! - `Accept: text/html` / `application/xhtml+xml` → the curated XHTML document
//!   (doc-as-file; stored via the ingest endpoint, served here). The document
//!   is the literate source of truth — concon serves it, it does **not**
//!   regenerate it from the triples. Serve-time augmentation with the Epic-B
//!   controls (per-concept "explore individuals" + the CQ section) hooks in
//!   here later; for now the document is served verbatim.
//! - `Accept: text/turtle` / `application/rdf+xml` → the ontology serialized
//!   from its schema + vocabulary named graphs.
//!
//! Companion assets referenced by the document (e.g. its stylesheet) are served
//! from the same doc store at `<dataset-base>/{file}`.
//!
//! When a dataset has no stored document, the caller falls back to the YASGUI
//! editor (preserving the platform-generic default for ordinary datasets).

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use oxigraph::io::{RdfFormat, RdfSerializer};
use oxigraph::sparql::QueryResults;

use super::entity;
use crate::state::AppState;
use crate::store::{DOC_INDEX_FILE, sparql_query};

/// Named graphs whose union is "the ontology" serialized at the base URL —
/// the extracted schema and the controlled vocabulary (the `mlips#` terms the
/// document documents), but NOT the per-paper instance KG. These graph names
/// match the ingest contract; hardcoded to the MLIPs resource for now (the
/// driving published dataset), consistent with the entity-base scoping choice.
const ONTOLOGY_GRAPHS: [&str; 2] = [
    "https://w3id.org/mlips/graph/schema",
    "https://w3id.org/mlips/graph/vocab",
];

/// Serve the curated ontology document for `dataset_name`. `url_prefix` is the
/// dataset base, threaded through for the Epic-B serve-time augmentation that
/// will inject per-concept controls; the document is currently served verbatim.
pub fn serve_doc(state: &AppState, dataset_name: &str, url_prefix: &str) -> Response {
    let Some(bytes) = state.store_manager.read_doc_file(dataset_name, DOC_INDEX_FILE) else {
        return (StatusCode::NOT_FOUND, "No document for this dataset").into_response();
    };
    let html = augment_doc(String::from_utf8_lossy(&bytes).into_owned(), url_prefix);
    // Serve as text/html: the HTML5 parser handles the curated document's named
    // entities (e.g. &ldquo;) and RDFa, where the strict application/xhtml+xml
    // XML parser would reject them and fail to render in a browser.
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// Serve-time augmentation (epics B2/B3): inject the client-side enhancer that
/// adds per-concept "explore individuals" controls and the competency-question
/// section. The enhancer is a static asset; we only inject a `<link>` + a
/// `<script>` (carrying the dataset's endpoint URLs as data attributes) before
/// `</body>`. The curated document is otherwise served verbatim — no
/// regeneration from the triples. The tags are XHTML-well-formed (self-closed
/// `<link/>`, explicit `</script>`, `defer="defer"`).
fn augment_doc(doc: String, url_prefix: &str) -> String {
    let inject = format!(
        concat!(
            "<link rel=\"stylesheet\" href=\"/static/concon-explore.css\"/>",
            "<script src=\"/static/concon-explore.js\" defer=\"defer\"",
            " data-base=\"{p}\" data-sparql=\"{p}/_sparql\" data-query=\"{p}/_query\"></script>",
        ),
        p = url_prefix
    );
    match doc.rfind("</body>") {
        Some(idx) => {
            let mut out = String::with_capacity(doc.len() + inject.len());
            out.push_str(&doc[..idx]);
            out.push_str(&inject);
            out.push_str(&doc[idx..]);
            out
        }
        // No </body> (unexpected for the curated XHTML): append, still valid.
        None => doc + &inject,
    }
}

/// Serve a companion asset of the document (e.g. its stylesheet) from the
/// dataset's doc store. The file name is a single path segment; it is
/// sanitised to block traversal before touching the store.
pub fn serve_doc_asset(state: &AppState, dataset_name: &str, filename: &str) -> Response {
    if !is_safe_asset_name(filename) {
        return (StatusCode::BAD_REQUEST, "Invalid asset name").into_response();
    }
    match state.store_manager.read_doc_file(dataset_name, filename) {
        Some(bytes) => (
            [(header::CONTENT_TYPE, asset_content_type(filename))],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Asset not found").into_response(),
    }
}

/// Serialize the ontology (schema + vocabulary graphs) of `dataset_name` as
/// Turtle (`format = "ttl"`) or RDF/XML (`format = "owl"`).
pub fn dump_ontology_rdf(state: &AppState, dataset_name: &str, format: &str) -> Response {
    let Some(store) = state.store_manager.get_dataset(dataset_name) else {
        return (
            StatusCode::NOT_FOUND,
            format!("Dataset '{dataset_name}' not found"),
        )
            .into_response();
    };
    let values = ONTOLOGY_GRAPHS
        .iter()
        .map(|g| format!("<{g}>"))
        .collect::<Vec<_>>()
        .join(" ");
    let q = format!(
        "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH ?g {{ ?s ?p ?o }} VALUES ?g {{ {values} }} }}"
    );
    let triples = match sparql_query(&store, &q) {
        Ok(QueryResults::Graph(t)) => t,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "Query error").into_response(),
    };
    let rdf_format = if format == "ttl" {
        RdfFormat::Turtle
    } else {
        RdfFormat::RdfXml
    };
    let mut serializer = RdfSerializer::from_format(rdf_format).for_writer(Vec::new());
    for t in triples.flatten() {
        if serializer.serialize_triple(t.as_ref()).is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Serialize error").into_response();
        }
    }
    match serializer.finish() {
        Ok(buf) => (
            [(header::CONTENT_TYPE, entity::content_type_for(format))],
            buf,
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Finish error").into_response(),
    }
}

/// Accept only simple, single-segment asset names — alphanumerics plus
/// `. _ -`, no `..`, no path separators. Defends the doc store against
/// traversal even though the router already passes a single path segment.
pub(crate) fn is_safe_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn asset_content_type(filename: &str) -> &'static str {
    if filename.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if filename.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if filename.ends_with(".svg") {
        "image/svg+xml"
    } else if filename.ends_with(".png") {
        "image/png"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_asset_name() {
        assert!(is_safe_asset_name("mlips.css"));
        assert!(is_safe_asset_name("style-1_v2.css"));
        assert!(!is_safe_asset_name("../secret"));
        assert!(!is_safe_asset_name("a/b"));
        assert!(!is_safe_asset_name(""));
        assert!(!is_safe_asset_name("with space.css"));
    }

    #[test]
    fn test_asset_content_type() {
        assert_eq!(asset_content_type("mlips.css"), "text/css; charset=utf-8");
        assert_eq!(asset_content_type("x.png"), "image/png");
        assert_eq!(asset_content_type("x.bin"), "application/octet-stream");
    }

    #[test]
    fn test_augment_doc_injects_before_body() {
        let out = augment_doc(
            "<html><body><h1>Doc</h1></body></html>".to_string(),
            "/mlips/_ds/mlips",
        );
        assert!(out.contains("/static/concon-explore.js"));
        assert!(out.contains("data-sparql=\"/mlips/_ds/mlips/_sparql\""));
        assert!(out.contains("data-query=\"/mlips/_ds/mlips/_query\""));
        // Injected before </body>, original content preserved.
        assert!(out.find("concon-explore.js").unwrap() < out.find("</body>").unwrap());
        assert!(out.contains("<h1>Doc</h1>"));
    }

    #[test]
    fn test_augment_doc_without_body_appends() {
        let out = augment_doc("<html>no body</html>".to_string(), "/x/_ds/y");
        assert!(out.contains("/static/concon-explore.js"));
        assert!(out.contains("no body"));
    }

    #[tokio::test]
    async fn test_base_view_negotiation() {
        use crate::routes::create_router;
        use crate::store::sparql_update;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("root/onto-test").unwrap();
        // Public so the anonymous-read gate admits these requests.
        state
            .store_manager
            .insert_dataset_metadata("root/onto-test")
            .unwrap();
        state
            .store_manager
            .write_doc_file(
                "root/onto-test",
                DOC_INDEX_FILE,
                b"<html>THE CURATED DOC</html>".to_vec(),
            )
            .unwrap();
        state
            .store_manager
            .write_doc_file("root/onto-test", "mlips.css", b"body { color: teal; }".to_vec())
            .unwrap();
        let ds = state.store_manager.get_dataset("root/onto-test").unwrap();
        sparql_update(
            &ds,
            "INSERT DATA { GRAPH <https://w3id.org/mlips/graph/schema> \
             { <urn:s> <urn:p> <urn:o> } }",
        )
        .unwrap();

        let server = TestServer::new(create_router(state));

        // HTML → the curated document, served publicly (no login).
        let resp = server.get("/_ds/onto-test/").add_header("accept", "text/html").await;
        resp.assert_status_ok();
        // Served as text/html so the browser's HTML5 parser (not the strict XML
        // parser) renders the XHTML+RDFa document and its named entities.
        assert!(
            resp.header(header::CONTENT_TYPE)
                .to_str()
                .unwrap()
                .starts_with("text/html"),
            "the document must be served as text/html"
        );
        assert!(resp.text().contains("THE CURATED DOC"));

        // Turtle → the ontology graph serialization.
        let resp = server
            .get("/_ds/onto-test/")
            .add_header("accept", "text/turtle")
            .await;
        resp.assert_status_ok();
        assert!(resp.text().contains("urn:s"));

        // Companion asset resolves under the base.
        let resp = server.get("/_ds/onto-test/mlips.css").await;
        resp.assert_status_ok();
        assert!(resp.text().contains("teal"));
        // (Asset-name traversal rejection is covered by `test_is_safe_asset_name`;
        // it can't be exercised over HTTP because the client normalises `..`.)
    }

    #[tokio::test]
    async fn test_base_view_no_doc_redirects_to_login() {
        use crate::routes::create_router;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("root/no-doc").unwrap();
        // Public, so the gate admits the request; the editor fallback still
        // redirects an anonymous visitor to login.
        state
            .store_manager
            .insert_dataset_metadata("root/no-doc")
            .unwrap();
        let server = TestServer::new(create_router(state));

        // No document and not logged in → editor fallback redirects to login.
        let resp = server
            .get("/_ds/no-doc/")
            .add_header("accept", "text/html")
            .await;
        resp.assert_status(StatusCode::SEE_OTHER);
    }
}
