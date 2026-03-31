use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use oxigraph::io::RdfFormat;
use oxigraph::model::{GraphNameRef, QuadRef};
use oxigraph::sparql::QueryResults;
use oxigraph::sparql::results::QueryResultsFormat;
use oxigraph::store::Store;
use serde::Deserialize;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct SparqlQueryParams {
    pub query: Option<String>,
}

pub async fn sparql_query_get(
    state: &AppState,
    dataset_name: &str,
    params: &SparqlQueryParams,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let query = params
        .query
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' parameter".into()))?;
    execute_query(state, dataset_name, query)
}

/// Execute a SPARQL query directly on a given store (used for file catalogs).
pub async fn sparql_query_get_on_store(
    store: &Store,
    params: &SparqlQueryParams,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let query = params
        .query
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' parameter".into()))?;
    execute_query_on_store(store, query)
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
        params
            .query
            .or(params.update)
            .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' or 'update' parameter".into()))?
    } else {
        body.to_string()
    };

    // Try as a read query first; if that fails, try as an update
    let store = state
        .store_manager
        .get_dataset(dataset_name)
        .ok_or((StatusCode::NOT_FOUND, format!("Dataset '{}' not found", dataset_name)))?;

    match store.query(&sparql) {
        Ok(results) => format_results(results, &store),
        Err(_query_err) => {
            // Not a valid query — try as a SPARQL Update
            store
                .update(&sparql)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            Ok((headers, r#"{"message":"Update executed successfully."}"#.to_string()))
        }
    }
}

fn execute_query(
    state: &AppState,
    dataset_name: &str,
    query: &str,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let store = state
        .store_manager
        .get_dataset(dataset_name)
        .ok_or((StatusCode::NOT_FOUND, format!("Dataset '{}' not found", dataset_name)))?;

    let results = store
        .query(query)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    format_results(results, &store)
}

fn execute_query_on_store(
    store: &Store,
    query: &str,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let results = store
        .query(query)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    format_results(results, store)
}

fn format_results(
    results: QueryResults,
    store: &Store,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let mut headers = HeaderMap::new();

    let body = if let QueryResults::Graph(triples) = results {
        headers.insert(
            header::CONTENT_TYPE,
            "text/turtle".parse().unwrap(),
        );
        for triple in triples {
            let triple = triple.map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            })?;
            store
                .insert(QuadRef::new(
                    triple.subject.as_ref(),
                    triple.predicate.as_ref(),
                    triple.object.as_ref(),
                    GraphNameRef::DefaultGraph,
                ))
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        let buf = store
            .dump_graph_to_writer(GraphNameRef::DefaultGraph, RdfFormat::Turtle, Vec::new())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        String::from_utf8(buf)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            "application/sparql-results+json".parse().unwrap(),
        );
        let buf = results
            .write(Vec::new(), QueryResultsFormat::Json)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        String::from_utf8(buf)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    Ok((headers, body))
}

pub async fn sparql_update_post(
    state: &AppState,
    dataset_name: &str,
    headers: &HeaderMap,
    body: &str,
) -> Result<StatusCode, (StatusCode, String)> {
    let store = state
        .store_manager
        .get_dataset(dataset_name)
        .ok_or((StatusCode::NOT_FOUND, format!("Dataset '{}' not found", dataset_name)))?;

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

    store
        .update(&update)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

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

        let response = server
            .get("/_ds/sparql-test-2/_sparql")
            .await;
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
