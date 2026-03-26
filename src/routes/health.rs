use axum::{Router, routing::get};
use axum::http::StatusCode;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/_health", get(health_check))
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use axum_test::TestServer;

    use crate::routes::create_router;
    use crate::state::AppState;

    #[tokio::test]
    async fn test_health_check() {
        let state = AppState::new().unwrap();
        let app = create_router(state);
        let server = TestServer::new(app);

        let response = server.get("/_health").await;
        response.assert_status_ok();
    }
}
