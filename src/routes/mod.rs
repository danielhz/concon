mod content;
mod datasets;
mod health;
mod sparql;
pub mod web;

use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(datasets::routes())
        .merge(web::routes())
        .merge(content::routes())
        .nest_service("/static", ServeDir::new("static"))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
