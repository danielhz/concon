use axum::extract::State;
use axum::http::StatusCode;
use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/datasets", get(list_datasets).post(create_dataset))
        .route("/datasets/{name}", axum::routing::delete(delete_dataset))
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
        .map(|_| StatusCode::CREATED)
        .map_err(|e| (StatusCode::CONFLICT, e))
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
        let response = server.get("/datasets").await;
        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_create_and_list_dataset() {
        let server = test_server();

        let response = server
            .post("/datasets")
            .json(&serde_json::json!({"name": "test-dataset"}))
            .await;
        response.assert_status(axum::http::StatusCode::CREATED);

        let response = server.get("/datasets").await;
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!(["test-dataset"]));
    }

    #[tokio::test]
    async fn test_create_duplicate_dataset() {
        let server = test_server();

        server
            .post("/datasets")
            .json(&serde_json::json!({"name": "dup"}))
            .await;

        let response = server
            .post("/datasets")
            .json(&serde_json::json!({"name": "dup"}))
            .await;
        response.assert_status(axum::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_delete_dataset() {
        let server = test_server();

        server
            .post("/datasets")
            .json(&serde_json::json!({"name": "to-delete"}))
            .await;

        let response = server.delete("/datasets/to-delete").await;
        response.assert_status(axum::http::StatusCode::NO_CONTENT);

        let response = server.get("/datasets").await;
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_dataset() {
        let server = test_server();
        let response = server.delete("/datasets/nonexistent").await;
        response.assert_status(axum::http::StatusCode::NOT_FOUND);
    }
}
