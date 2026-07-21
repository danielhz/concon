use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use oxigraph::io::{RdfFormat, RdfSerializer};
use oxigraph::sparql::QueryResults;
use oxigraph::sparql::results::{QueryResultsFormat, QueryResultsSerializer};
use oxigraph::store::Store;
use serde::Deserialize;

use crate::state::AppState;
use crate::store::{QUERY_TIMEOUT, sparql_query, sparql_query_union_timeout, sparql_update};

/// Cap on the number of rows/triples serialized from a single result set (B4
/// hardening). Beyond this the response is truncated and flagged with the
/// `x-concon-results-truncated` header.
const MAX_RESULT_ROWS: usize = 10_000;

#[derive(Deserialize)]
pub struct SparqlQueryParams {
    pub query: Option<String>,
}

pub async fn sparql_query_get(
    state: &AppState,
    dataset_name: &str,
    params: &SparqlQueryParams,
    headers: &HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let query = params
        .query
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' parameter".into()))?;
    execute_query(state, dataset_name, query, graph_format_from_accept(headers))
}

/// Execute a SPARQL query directly on a given store (used for file catalogs).
pub async fn sparql_query_get_on_store(
    store: &Store,
    params: &SparqlQueryParams,
    headers: &HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let query = params
        .query
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' parameter".into()))?;
    execute_query_on_store(store, query, graph_format_from_accept(headers))
}

/// Execute a SPARQL query (POST) directly on a given store (used for file catalogs).
pub async fn sparql_query_post_on_store(
    store: &Store,
    headers: &HeaderMap,
    body: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let sparql = if content_type.starts_with("application/x-www-form-urlencoded") {
        #[derive(Deserialize)]
        struct FormParams {
            query: Option<String>,
        }
        let params: FormParams = serde_urlencoded::from_str(body)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        params
            .query
            .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' parameter".into()))?
    } else {
        body.to_string()
    };

    execute_query_on_store(store, &sparql, graph_format_from_accept(headers))
}

pub async fn sparql_query_post(
    state: &AppState,
    dataset_name: &str,
    headers: &HeaderMap,
    body: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Extract the SPARQL text from form-encoded or raw body
    let sparql = if content_type.starts_with("application/x-www-form-urlencoded") {
        // YASGUI sends as form-encoded: query=... or update=...
        #[derive(Deserialize)]
        struct FormParams {
            query: Option<String>,
            update: Option<String>,
        }
        let params: FormParams = serde_urlencoded::from_str(body)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        params.query.or(params.update).ok_or((
            StatusCode::BAD_REQUEST,
            "Missing 'query' or 'update' parameter".into(),
        ))?
    } else {
        body.to_string()
    };

    // The `_sparql` endpoint is query-only: it does NOT fall back to executing
    // updates (that path is `_update`, which requires write auth). Queries run
    // with union-default-graph semantics so a pattern without a `GRAPH` clause
    // spans the dataset's named graphs (schema/vocab/kg/cq) as a single store.
    let store = state.store_manager.get_dataset(dataset_name).ok_or((
        StatusCode::NOT_FOUND,
        format!("Dataset '{}' not found", dataset_name),
    ))?;

    let results = sparql_query_union_timeout(&store, &sparql, QUERY_TIMEOUT)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    format_results(results, graph_format_from_accept(headers))
}

fn execute_query(
    state: &AppState,
    dataset_name: &str,
    query: &str,
    graph_format: RdfFormat,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let store = state.store_manager.get_dataset(dataset_name).ok_or((
        StatusCode::NOT_FOUND,
        format!("Dataset '{}' not found", dataset_name),
    ))?;

    let results = sparql_query_union_timeout(&store, query, QUERY_TIMEOUT)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    format_results(results, graph_format)
}

fn execute_query_on_store(
    store: &Store,
    query: &str,
    graph_format: RdfFormat,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let results =
        sparql_query(store, query).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    format_results(results, graph_format)
}

fn ise<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// RDF serialization for CONSTRUCT/DESCRIBE results, negotiated from `Accept`
/// (Turtle / RDF-XML / N-Triples / JSON-LD); Turtle when nothing RDF matches.
/// SELECT/ASK results are unaffected (always SPARQL-results JSON).
fn graph_format_from_accept(headers: &HeaderMap) -> RdfFormat {
    super::entity::rdf_format_for(super::entity::negotiate_format(headers))
        .unwrap_or(RdfFormat::Turtle)
}

/// Serialize query results, capping output at `MAX_RESULT_ROWS`. CONSTRUCT/
/// DESCRIBE results are serialized directly from the result iterator — they are
/// NOT inserted back into the store (the previous code did, which let an
/// anonymous CONSTRUCT mutate the dataset and dump the whole default graph).
pub(crate) fn format_results(
    results: QueryResults,
    graph_format: RdfFormat,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let mut headers = HeaderMap::new();
    let mut truncated = false;

    let body = match results {
        QueryResults::Graph(triples) => {
            // CONSTRUCT/DESCRIBE results honor the `Accept` header
            // (Turtle / RDF-XML / N-Triples / JSON-LD; Turtle by default).
            headers.insert(
                header::CONTENT_TYPE,
                graph_format.media_type().parse().unwrap(),
            );
            let mut serializer = RdfSerializer::from_format(graph_format).for_writer(Vec::new());
            for (n, triple) in triples.enumerate() {
                if n >= MAX_RESULT_ROWS {
                    truncated = true;
                    break;
                }
                serializer.serialize_triple(triple.map_err(ise)?.as_ref()).map_err(ise)?;
            }
            String::from_utf8(serializer.finish().map_err(ise)?).map_err(ise)?
        }
        QueryResults::Boolean(value) => {
            headers.insert(
                header::CONTENT_TYPE,
                "application/sparql-results+json".parse().unwrap(),
            );
            let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
            let buf = serializer
                .serialize_boolean_to_writer(Vec::new(), value)
                .map_err(ise)?;
            String::from_utf8(buf).map_err(ise)?
        }
        QueryResults::Solutions(solutions) => {
            headers.insert(
                header::CONTENT_TYPE,
                "application/sparql-results+json".parse().unwrap(),
            );
            let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
            let mut writer = serializer
                .serialize_solutions_to_writer(Vec::new(), solutions.variables().to_vec())
                .map_err(ise)?;
            for (n, solution) in solutions.enumerate() {
                if n >= MAX_RESULT_ROWS {
                    truncated = true;
                    break;
                }
                writer.serialize(&solution.map_err(ise)?).map_err(ise)?;
            }
            String::from_utf8(writer.finish().map_err(ise)?).map_err(ise)?
        }
    };

    if truncated {
        headers.insert("x-concon-results-truncated", "true".parse().unwrap());
    }
    Ok((headers, body))
}

pub async fn sparql_update_post(
    state: &AppState,
    dataset_name: &str,
    headers: &HeaderMap,
    body: &str,
) -> Result<StatusCode, (StatusCode, String)> {
    let store = state.store_manager.get_dataset(dataset_name).ok_or((
        StatusCode::NOT_FOUND,
        format!("Dataset '{}' not found", dataset_name),
    ))?;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let update = if content_type.starts_with("application/x-www-form-urlencoded") {
        #[derive(Deserialize)]
        struct UpdateParams {
            update: Option<String>,
        }
        let params: UpdateParams = serde_urlencoded::from_str(body)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        params
            .update
            .ok_or((StatusCode::BAD_REQUEST, "Missing 'update' parameter".into()))?
    } else {
        body.to_string()
    };

    sparql_update(&store, &update).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Execute a SPARQL Update directly on a given store (used for SHACL stores).
pub async fn sparql_update_post_on_store(
    store: &Store,
    headers: &HeaderMap,
    body: &str,
) -> Result<StatusCode, (StatusCode, String)> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let update = if content_type.starts_with("application/x-www-form-urlencoded") {
        #[derive(Deserialize)]
        struct UpdateParams {
            update: Option<String>,
        }
        let params: UpdateParams = serde_urlencoded::from_str(body)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        params
            .update
            .ok_or((StatusCode::BAD_REQUEST, "Missing 'update' parameter".into()))?
    } else {
        body.to_string()
    };

    sparql_update(store, &update).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum_test::TestServer;

    use crate::routes::create_router;
    use crate::state::AppState;

    fn test_server() -> TestServer {
        let state = AppState::new().unwrap();
        let app = create_router(state);
        TestServer::new(app)
    }

    #[tokio::test]
    async fn test_sparql_query_on_nonexistent_dataset() {
        let server = test_server();
        let response = server
            .get("/_ds/nonexistent/_sparql")
            .add_query_param("query", "SELECT * WHERE { ?s ?p ?o }")
            .await;
        response.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_sparql_query_empty_dataset() {
        let server = test_server();

        server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "root/sparql-test"}))
            .await;

        let response = server
            .get("/_ds/sparql-test/_sparql")
            .add_query_param("query", "SELECT * WHERE { ?s ?p ?o }")
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        assert!(body["results"]["bindings"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_sparql_query_missing_param() {
        let server = test_server();

        server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "root/sparql-test-2"}))
            .await;

        let response = server.get("/_ds/sparql-test-2/_sparql").await;
        response.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sparql_post_query() {
        let server = test_server();

        server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "root/sparql-post-test"}))
            .await;

        let response = server
            .post("/_ds/sparql-post-test/_sparql")
            .text("SELECT * WHERE { ?s ?p ?o }")
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        assert!(body["results"]["bindings"].as_array().unwrap().is_empty());
    }
}
