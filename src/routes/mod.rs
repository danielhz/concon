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
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Method};
use axum::middleware::map_response;
use axum::response::Response;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::state::AppState;

/// Make `/static` assets always revalidate. concon does not fingerprint asset
/// filenames, so without this browsers apply *heuristic* caching (no
/// `Cache-Control` is sent, only `Last-Modified`) and keep serving a stale
/// stylesheet for hours after a redeploy. `no-cache` still allows a cached copy
/// but forces an `If-Modified-Since` revalidation first, so unchanged files
/// cost a cheap 304 and changed files are picked up immediately.
async fn revalidate_static(mut res: Response) -> Response {
    res.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    res
}

pub fn create_router(state: AppState) -> Router {
    // Public Linked Open Data: any origin may *read* (cross-origin YASGUI /
    // WebVOWL), but only the safe read methods and headers are exposed and no
    // credentials are echoed. Writes (PUT/DELETE) are server-side (the loader),
    // not cross-origin browser calls, so they are intentionally not CORS-allowed.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::HEAD, Method::OPTIONS])
        .allow_headers([ACCEPT, CONTENT_TYPE]);

    let static_routes = Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .layer(map_response(revalidate_static));

    Router::new()
        .merge(health::routes())
        .merge(datasets::routes())
        .merge(web::routes())
        .merge(content::routes())
        .merge(static_routes)
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024)) // 100 MB
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
