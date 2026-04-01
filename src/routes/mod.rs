mod content;
mod datasets;
pub mod files;
mod health;
mod sparql;
pub mod web;

use axum::extract::DefaultBodyLimit;
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .merge(health::routes())
        .merge(datasets::routes())
        .merge(web::routes())
        .merge(content::routes())
        .nest_service("/static", ServeDir::new("static"))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024)) // 100 MB
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
