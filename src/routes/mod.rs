mod datasets;
mod health;
mod sparql;

use axum::Router;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(datasets::routes())
        .merge(sparql::routes())
        .with_state(state)
}
