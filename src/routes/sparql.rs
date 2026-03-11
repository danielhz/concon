use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::{Router, routing::get};
use oxigraph::io::RdfFormat;
use oxigraph::model::{GraphNameRef, QuadRef};
use oxigraph::sparql::QueryResults;
use oxigraph::sparql::results::QueryResultsFormat;
use serde::Deserialize;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/datasets/{name}/sparql",
        get(sparql_query_get).post(sparql_query_post),
    )
}

#[derive(Deserialize)]
struct SparqlQueryParams {
    query: Option<String>,
}

async fn sparql_query_get(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<SparqlQueryParams>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let query = params
        .query
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'query' parameter".into()))?;
    execute_query(&state, &name, &query)
}

async fn sparql_query_post(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: String,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    execute_query(&state, &name, &body)
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
            .get("/datasets/nonexistent/sparql")
            .add_query_param("query", "SELECT * WHERE { ?s ?p ?o }")
            .await;
        response.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_sparql_query_empty_dataset() {
        let server = test_server();

        server
            .post("/datasets")
            .json(&serde_json::json!({"name": "sparql-test"}))
            .await;

        let response = server
            .get("/datasets/sparql-test/sparql")
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
            .post("/datasets")
            .json(&serde_json::json!({"name": "sparql-test-2"}))
            .await;

        let response = server
            .get("/datasets/sparql-test-2/sparql")
            .await;
        response.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sparql_post_query() {
        let server = test_server();

        server
            .post("/datasets")
            .json(&serde_json::json!({"name": "sparql-post-test"}))
            .await;

        let response = server
            .post("/datasets/sparql-post-test/sparql")
            .text("SELECT * WHERE { ?s ?p ?o }")
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        assert!(body["results"]["bindings"].as_array().unwrap().is_empty());
    }
}
