use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};

use crate::shacl;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_api/datasets", get(list_datasets).post(create_dataset))
        .route(
            "/_api/datasets/{name}",
            axum::routing::delete(delete_dataset),
        )
        .route("/_api/search", get(entity_search))
}

#[derive(Serialize)]
struct DatasetList {
    datasets: Vec<String>,
}

#[derive(Deserialize)]
struct CreateDataset {
    name: String,
}

async fn list_datasets(State(state): State<AppState>) -> Json<DatasetList> {
    let datasets = state.store_manager.list_datasets();
    Json(DatasetList { datasets })
}

async fn create_dataset(
    State(state): State<AppState>,
    Json(payload): Json<CreateDataset>,
) -> Result<StatusCode, (StatusCode, String)> {
    state
        .store_manager
        .create_dataset(&payload.name)
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    // Insert dataset metadata into system store
    state
        .store_manager
        .insert_dataset_metadata(&payload.name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(StatusCode::CREATED)
}

async fn delete_dataset(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    state
        .store_manager
        .delete_dataset(&name)
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(|e| (StatusCode::NOT_FOUND, e))
}

#[derive(Deserialize)]
struct SearchParams {
    q: String,
    dataset: String,
    class: Option<String>,
}

async fn entity_search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Result<Json<Vec<shacl::SearchResult>>, (StatusCode, String)> {
    let store = state.store_manager.get_dataset(&params.dataset).ok_or((
        StatusCode::NOT_FOUND,
        format!("Dataset '{}' not found", params.dataset),
    ))?;

    let results = shacl::search_entities(&store, &params.q, params.class.as_deref());
    Ok(Json(results))
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
    async fn test_list_datasets_empty() {
        let server = test_server();
        let response = server.get("/_api/datasets").await;
        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_create_and_list_dataset() {
        let server = test_server();

        let response = server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "test-dataset"}))
            .await;
        response.assert_status(axum::http::StatusCode::CREATED);

        let response = server.get("/_api/datasets").await;
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!(["test-dataset"]));
    }

    #[tokio::test]
    async fn test_create_duplicate_dataset() {
        let server = test_server();

        server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "dup"}))
            .await;

        let response = server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "dup"}))
            .await;
        response.assert_status(axum::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_delete_dataset() {
        let server = test_server();

        server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "to-delete"}))
            .await;

        let response = server.delete("/_api/datasets/to-delete").await;
        response.assert_status(axum::http::StatusCode::NO_CONTENT);

        let response = server.get("/_api/datasets").await;
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_dataset() {
        let server = test_server();
        let response = server.delete("/_api/datasets/nonexistent").await;
        response.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_entity_search_endpoint() {
        let server = test_server();

        // Create dataset
        server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "root/search-test"}))
            .await;

        // Insert entities via SPARQL Update
        let sparql = r#"
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX ex: <http://example.org/>
            INSERT DATA {
                ex:alice a ex:Person ; rdfs:label "Alice Smith" .
                ex:bob a ex:Person ; rdfs:label "Bob Jones" .
            }
        "#;
        server.post("/_ds/search-test/_update").text(sparql).await;

        // Search
        let response = server
            .get("/_api/search")
            .add_query_param("q", "alice")
            .add_query_param("dataset", "root/search-test")
            .await;
        response.assert_status_ok();
        let body: Vec<serde_json::Value> = response.json();
        assert_eq!(body.len(), 1);
        assert!(body[0]["label"].as_str().unwrap().contains("Alice"));
    }
}
