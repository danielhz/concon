mod content;
mod datasets;
mod entity;
pub mod files;
mod health;
mod ingest;
mod ontology;
mod sparql;
pub mod web;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::Method;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    // Public Linked Open Data: any origin may *read* (cross-origin YASGUI /
    // WebVOWL), but only the safe read methods and headers are exposed and no
    // credentials are echoed. Writes (PUT/DELETE) are server-side (the loader),
    // not cross-origin browser calls, so they are intentionally not CORS-allowed.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::HEAD, Method::OPTIONS])
        .allow_headers([ACCEPT, CONTENT_TYPE]);

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
