//! Write/ingest endpoints for publishing a dataset (epic A1).
//!
//! These are the endpoints the D1 loader calls to populate the `mlips` dataset
//! (and the same path A1's initial load uses):
//!
//! - `PUT  <base>/_graph?graph=<iri>`  — replace a named graph (clear + load)
//! - `POST <base>/_graph?graph=<iri>`  — merge into a named graph
//! - `DELETE <base>/_graph?graph=<iri>` — clear a named graph
//! - `PUT  <base>/_doc[/<asset>]`      — store the curated document / an asset
//!
//! Replace-by-named-graph is idempotent (re-running the loader fully replaces a
//! graph's contents). All writes require authorization: a session cookie (web
//! UI) or HTTP Basic (the non-interactive loader), and the authenticated user
//! must be able to write the target dataset (`auth::can_write_dataset`).

// These helpers intentionally carry a ready-to-return `Response` in their
// `Err` variant (a 401/403/400/404 already shaped for the client); the error
// being "large" is by design, so silence the perf lint for this module.
#![allow(clippy::result_large_err)]

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::model::{GraphName, NamedNode};
use oxigraph::store::Store;
use tower_cookies::Cookies;

use super::{ontology, web};
use crate::inference;
use crate::state::AppState;
use crate::store::DOC_INDEX_FILE;

/// Constant-time string comparison (length is not secret here; contents are).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authorize a write to `dataset_name`. Two credentials are accepted: the
/// write-only ingest token (`Authorization: Bearer <token>`, used by the
/// loader); or a session cookie / HTTP Basic, in which case the resolved user
/// must have write permission on the dataset (`can_write_dataset`). Returns
/// `Err(response)` (401/403) when not authorized.
pub fn authorize_write(
    state: &AppState,
    headers: &HeaderMap,
    cookies: &Cookies,
    dataset_name: &str,
) -> Result<(), Response> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // Write-only ingest token (a deploy secret, not a user account). Valid for
    // any dataset's write endpoints; it grants no read/UI identity.
    if let Some(expected) = &state.ingest_token
        && let Some(tok) =
            authorization.and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        && ct_eq(tok.trim(), expected)
    {
        return Ok(());
    }

    // 2. Session or HTTP Basic → a user identity with per-dataset write check.
    let user_iri = web::get_username(cookies, state)
        .map(|s| s.user_iri)
        .or_else(|| crate::auth::authenticate_basic(&state.store_manager.system, authorization));

    let Some(user_iri) = user_iri else {
        return Err((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"concon ingest\"")],
            "Authentication required",
        )
            .into_response());
    };

    if !crate::auth::can_write_dataset(&state.store_manager.system, &user_iri, dataset_name) {
        return Err(
            (StatusCode::FORBIDDEN, "No write permission for this dataset").into_response(),
        );
    }
    Ok(())
}

/// Map the request `Content-Type` to an RDF parsing format. Defaults to Turtle
/// (the loader's wire format).
fn body_format(headers: &HeaderMap) -> RdfFormat {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match ct.split(';').next().unwrap_or("").trim() {
        "application/n-triples" => RdfFormat::NTriples,
        "application/n-quads" => RdfFormat::NQuads,
        "application/rdf+xml" => RdfFormat::RdfXml,
        "application/trig" => RdfFormat::TriG,
        // "text/turtle", "application/x-turtle", or unspecified
        _ => RdfFormat::Turtle,
    }
}

/// Resolve and validate the `?graph=<iri>` parameter into a named node.
fn graph_node(graph: Option<&str>) -> Result<NamedNode, Response> {
    let iri = graph.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Missing 'graph' query parameter").into_response()
    })?;
    NamedNode::new(iri)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid graph IRI").into_response())
}

fn dataset_store(state: &AppState, dataset_name: &str) -> Result<oxigraph::store::Store, Response> {
    state.store_manager.get_dataset(dataset_name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Dataset '{dataset_name}' not found"),
        )
            .into_response()
    })
}

/// Reject a consumer write to the concon-derived `…/graph/computed` graph
/// (Epic M3): it is read-only to consumers and rebuilt automatically from the
/// source graphs. Returns `Some(409)` when `node` addresses that graph.
fn reject_if_computed(node: &NamedNode) -> Option<Response> {
    inference::is_reserved_computed_graph(node.as_str()).then(|| {
        (
            StatusCode::CONFLICT,
            "The '…/graph/computed' graph is concon-derived and read-only; it is rebuilt \
             automatically from the source graphs after each ingest. Use `POST _recompute` \
             to force a rebuild.",
        )
            .into_response()
    })
}

/// Rebuild the dataset's derived `computed` graph after a source-graph write
/// (Epic M2 auto-recompute). Best-effort: the source write already succeeded,
/// so a rebuild failure is logged and swallowed (the derived graph is left
/// stale until the next successful recompute) rather than failing the write.
fn auto_recompute(store: &Store, dataset_name: &str) {
    match inference::recompute(store) {
        Ok(report) => {
            if let Some(graph) = &report.computed_graph {
                tracing::info!(
                    dataset = dataset_name,
                    graph = graph.as_str(),
                    inserted = report.inserted,
                    "recomputed derived graph"
                );
            }
        }
        Err(e) => tracing::warn!(
            dataset = dataset_name,
            error = %e,
            "auto-recompute of derived graph failed; it is left stale"
        ),
    }
}

/// Rebuild `computed` after a successful `_update` (Epic M2). A SPARQL update
/// can touch source graphs — leaving `computed` stale — or write `computed`
/// directly (the 409 read-only guard only covers `_graph`, not arbitrary
/// `_update`). Recomputing after every successful update keeps `computed`
/// coherent and makes any `_update`-written `computed` triples non-durable (the
/// rebuild clears and re-derives). Best-effort, like [`auto_recompute`].
pub(crate) fn recompute_after_update(state: &AppState, dataset_name: &str) {
    if let Some(store) = state.store_manager.get_dataset(dataset_name) {
        auto_recompute(&store, dataset_name);
    }
}

/// `PUT _graph` — replace a named graph: clear it, then load the body into it.
/// Idempotent replace-by-graph (not atomic across the clear+load; a re-PUT
/// recovers from a mid-load failure).
pub fn put_graph(
    state: &AppState,
    dataset_name: &str,
    graph: Option<&str>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let store = match dataset_store(state, dataset_name) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let node = match graph_node(graph) {
        Ok(n) => n,
        Err(r) => return r,
    };
    if let Some(r) = reject_if_computed(&node) {
        return r;
    }
    if store.clear_graph(node.as_ref()).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to clear graph").into_response();
    }
    let resp = load_into_graph(&store, node, body_format(headers), body);
    if resp.status() == StatusCode::NO_CONTENT {
        auto_recompute(&store, dataset_name);
    }
    resp
}

/// `POST _graph` — merge the body into a named graph (no clear).
pub fn post_graph(
    state: &AppState,
    dataset_name: &str,
    graph: Option<&str>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let store = match dataset_store(state, dataset_name) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let node = match graph_node(graph) {
        Ok(n) => n,
        Err(r) => return r,
    };
    if let Some(r) = reject_if_computed(&node) {
        return r;
    }
    let resp = load_into_graph(&store, node, body_format(headers), body);
    if resp.status() == StatusCode::NO_CONTENT {
        auto_recompute(&store, dataset_name);
    }
    resp
}

fn load_into_graph(
    store: &oxigraph::store::Store,
    node: NamedNode,
    format: RdfFormat,
    body: &Bytes,
) -> Response {
    let parser = RdfParser::from_format(format).with_default_graph(GraphName::NamedNode(node));
    match store.load_from_reader(parser, body.as_ref()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("Load error: {e}")).into_response(),
    }
}

/// `DELETE _graph` — clear a named graph.
pub fn delete_graph(state: &AppState, dataset_name: &str, graph: Option<&str>) -> Response {
    let store = match dataset_store(state, dataset_name) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let node = match graph_node(graph) {
        Ok(n) => n,
        Err(r) => return r,
    };
    if let Some(r) = reject_if_computed(&node) {
        return r;
    }
    match store.clear_graph(node.as_ref()) {
        Ok(()) => {
            auto_recompute(&store, dataset_name);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to clear graph").into_response(),
    }
}

/// `POST _recompute` — force a full rebuild of the dataset's derived `computed`
/// graph (Epic M2 explicit trigger), e.g. after a rule change or a missed
/// auto-recompute. Write-authorized (checked by the caller). Returns a JSON
/// summary of the rebuild.
pub fn recompute_graph(state: &AppState, dataset_name: &str) -> Response {
    let store = match dataset_store(state, dataset_name) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match inference::recompute(&store) {
        Ok(report) => (StatusCode::OK, axum::Json(report)).into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Recompute failed: {e}")).into_response()
        }
    }
}

/// `PUT _doc[/<asset>]` — store the curated document (`asset = None`) or a
/// companion asset (e.g. the stylesheet). Idempotent replace.
pub fn put_doc(state: &AppState, dataset_name: &str, asset: Option<&str>, body: &Bytes) -> Response {
    let filename = match asset {
        None => DOC_INDEX_FILE.to_string(),
        Some(name) if ontology::is_safe_asset_name(name) => name.to_string(),
        Some(_) => return (StatusCode::BAD_REQUEST, "Invalid asset name").into_response(),
    };
    match state
        .store_manager
        .write_doc_file(dataset_name, &filename, body.to_vec())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use crate::routes::create_router;
    use crate::state::AppState;
    use crate::store::sparql_update;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use base64::Engine;

    fn basic_header(user: &str, pw: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"));
        format!("Basic {creds}")
    }

    /// In-memory state with a root-team admin user "admin"/"secret" and a Public
    /// dataset `root/pubds`.
    fn setup_state() -> AppState {
        let state = AppState::new().unwrap();
        let hash = crate::auth::hash_password("secret");
        sparql_update(
            &state.store_manager.system,
            &format!(
                r#"
                PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                INSERT DATA {{
                    <https://mlipe.2mia.org/teams/root> a mlipe:Team ;
                        mlipe:teamName "root" ;
                        mlipe:hasAdmin <https://mlipe.2mia.org/users/admin> .
                    <https://mlipe.2mia.org/users/admin> mlipe:username "admin" ;
                        mlipe:passwordHash "{hash}" .
                }}
                "#
            ),
        )
        .unwrap();
        state.store_manager.create_dataset("root/pubds").unwrap();
        state.store_manager.insert_dataset_metadata("root/pubds").unwrap();
        state
    }

    #[tokio::test]
    async fn test_put_graph_requires_auth() {
        let server = TestServer::new(create_router(setup_state()));
        let r = server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
            .add_header("content-type", "text/turtle")
            .text("<urn:s> <urn:p> <urn:o> .")
            .await;
        r.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_put_graph_bad_password_unauthorized() {
        let server = TestServer::new(create_router(setup_state()));
        let r = server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
            .add_header("authorization", basic_header("admin", "WRONG"))
            .add_header("content-type", "text/turtle")
            .text("<urn:s> <urn:p> <urn:o> .")
            .await;
        r.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_put_graph_authed_then_queryable() {
        let server = TestServer::new(create_router(setup_state()));
        let r = server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
            .add_header("authorization", basic_header("admin", "secret"))
            .add_header("content-type", "text/turtle")
            .text("<urn:s> <urn:p> <urn:o> .")
            .await;
        r.assert_status(StatusCode::NO_CONTENT);

        // The public _sparql endpoint (union default graph) sees the
        // named-graph triple without a GRAPH clause.
        let q = server
            .get("/_ds/pubds/_sparql")
            .add_query_param("query", "ASK { <urn:s> <urn:p> <urn:o> }")
            .await;
        q.assert_status_ok();
        assert!(q.text().contains("true"));
    }

    #[tokio::test]
    async fn test_put_graph_replace_is_idempotent() {
        let server = TestServer::new(create_router(setup_state()));
        let auth = basic_header("admin", "secret");
        let put = |body: &'static str| {
            server
                .put("/_ds/pubds/_graph")
                .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
                .add_header("authorization", auth.clone())
                .add_header("content-type", "text/turtle")
                .text(body)
        };
        put("<urn:s> <urn:p> <urn:a> .").await.assert_status(StatusCode::NO_CONTENT);
        // Replace: the old triple must be gone, only the new one remains.
        put("<urn:s> <urn:p> <urn:b> .").await.assert_status(StatusCode::NO_CONTENT);

        let q = server
            .get("/_ds/pubds/_sparql")
            .add_query_param("query", "ASK { <urn:s> <urn:p> <urn:a> }")
            .await;
        assert!(q.text().contains("false"), "old triple should be replaced");
    }

    #[tokio::test]
    async fn test_put_doc_authed_then_served() {
        let server = TestServer::new(create_router(setup_state()));
        let r = server
            .put("/_ds/pubds/_doc")
            .add_header("authorization", basic_header("admin", "secret"))
            .text("<html>THE DOC</html>")
            .await;
        r.assert_status(StatusCode::NO_CONTENT);

        // The base view now serves the stored document.
        let d = server
            .get("/_ds/pubds/")
            .add_header("accept", "text/html")
            .await;
        d.assert_status_ok();
        assert!(d.text().contains("THE DOC"));
    }

    #[tokio::test]
    async fn test_put_graph_with_ingest_token() {
        let mut state = setup_state();
        state.ingest_token = Some("s3cr3t".to_string());
        let server = TestServer::new(create_router(state));

        // Valid Bearer ingest token → authorized (no user account).
        let ok = server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
            .add_header("authorization", "Bearer s3cr3t")
            .add_header("content-type", "text/turtle")
            .text("<urn:s> <urn:p> <urn:o> .")
            .await;
        ok.assert_status(StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_put_graph_wrong_ingest_token_rejected() {
        let mut state = setup_state();
        state.ingest_token = Some("s3cr3t".to_string());
        let server = TestServer::new(create_router(state));

        // Wrong token → falls through to user auth → 401.
        let bad = server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
            .add_header("authorization", "Bearer WRONG")
            .add_header("content-type", "text/turtle")
            .text("<urn:s> <urn:p> <urn:o> .")
            .await;
        bad.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_ct_eq() {
        use super::ct_eq;
        assert!(ct_eq("token", "token"));
        assert!(!ct_eq("token", "tokem"));
        assert!(!ct_eq("token", "tok"));
        assert!(!ct_eq("", "x"));
    }

    // ---- Epic M: inference triggers + read-only computed graph ----

    /// PUT to the reserved `…/graph/computed` graph is rejected (409) even with
    /// valid write auth: it is concon-derived and read-only (M3).
    #[tokio::test]
    async fn test_put_computed_graph_rejected() {
        let server = TestServer::new(create_router(setup_state()));
        let r = server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/computed")
            .add_header("authorization", basic_header("admin", "secret"))
            .add_header("content-type", "text/turtle")
            .text("<urn:s> <urn:p> <urn:o> .")
            .await;
        r.assert_status(StatusCode::CONFLICT);
    }

    /// DELETE to the reserved computed graph is likewise rejected.
    #[tokio::test]
    async fn test_delete_computed_graph_rejected() {
        let server = TestServer::new(create_router(setup_state()));
        let r = server
            .delete("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/computed")
            .add_header("authorization", basic_header("admin", "secret"))
            .await;
        r.assert_status(StatusCode::CONFLICT);
    }

    /// After a source-graph PUT with an `owl:inverseOf` declaration and a
    /// forward triple, auto-recompute materializes the inverse into `computed`,
    /// visible through the public union `_sparql` endpoint.
    #[tokio::test]
    async fn test_put_source_auto_recomputes_inverse() {
        let server = TestServer::new(create_router(setup_state()));
        let ttl = "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n\
                   @prefix ex: <https://w3id.org/mlips#> .\n\
                   ex:hasResult owl:inverseOf ex:isResultOf .\n\
                   ex:study ex:hasResult ex:r .";
        server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/kg")
            .add_header("authorization", basic_header("admin", "secret"))
            .add_header("content-type", "text/turtle")
            .text(ttl)
            .await
            .assert_status(StatusCode::NO_CONTENT);

        // The inverse triple is derived (not uploaded) and visible in the union.
        let q = server
            .get("/_ds/pubds/_sparql")
            .add_query_param(
                "query",
                "ASK { <https://w3id.org/mlips#r> \
                 <https://w3id.org/mlips#isResultOf> <https://w3id.org/mlips#study> }",
            )
            .await;
        q.assert_status_ok();
        assert!(q.text().contains("true"), "inverse should be auto-materialized");

        // And it lives specifically in the computed graph.
        let g = server
            .get("/_ds/pubds/_sparql")
            .add_query_param(
                "query",
                "ASK { GRAPH <https://w3id.org/mlips/graph/computed> { \
                 <https://w3id.org/mlips#r> <https://w3id.org/mlips#isResultOf> \
                 <https://w3id.org/mlips#study> } }",
            )
            .await;
        assert!(g.text().contains("true"), "derived triple should be in computed graph");
    }

    /// `POST _recompute` requires write auth and returns a JSON summary.
    #[tokio::test]
    async fn test_recompute_endpoint_auth_and_summary() {
        let server = TestServer::new(create_router(setup_state()));

        // Unauthenticated → 401.
        server
            .post("/_ds/pubds/_recompute")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        // Load a source graph, then force a rebuild.
        server
            .put("/_ds/pubds/_graph")
            .add_query_param("graph", "https://w3id.org/mlips/graph/schema")
            .add_header("authorization", basic_header("admin", "secret"))
            .add_header("content-type", "text/turtle")
            .text("<urn:a> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <urn:b> .")
            .await
            .assert_status(StatusCode::NO_CONTENT);

        let r = server
            .post("/_ds/pubds/_recompute")
            .add_header("authorization", basic_header("admin", "secret"))
            .await;
        r.assert_status_ok();
        let body: serde_json::Value = r.json();
        assert_eq!(
            body["computed_graph"], "https://w3id.org/mlips/graph/computed",
            "summary reports the derived graph IRI"
        );
    }
}
