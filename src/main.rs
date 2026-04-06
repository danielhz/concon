mod auth;
mod config;
mod grobid;
mod migration;
mod routes;
mod state;
mod store;

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cfg = config::load_or_create().expect("Failed to load config");

    config::ensure_system_data(&cfg.store.system_data).expect("Failed to ensure system data file");

    let app_state =
        state::AppState::new_persistent(&cfg.store.data_dir, &cfg.store.files_dir, &cfg.grobid.url)
            .expect("Failed to initialize application state");

    if app_state.store_manager.is_system_empty() {
        app_state
            .store_manager
            .load_system_data(&cfg.store.system_data)
            .expect("Failed to load system data");
        tracing::info!("Loaded system data from {}", cfg.store.system_data);
    } else {
        tracing::info!("System store already initialized, skipping seed load");
    }

    migration::check_schema_version(&app_state.store_manager.system)
        .expect("Schema version mismatch");

    app_state
        .store_manager
        .open_existing_datasets()
        .expect("Failed to open existing datasets");

    let app = routes::create_router(app_state);

    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .expect("Invalid host/port in config");
    tracing::info!("MLIPE listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");
    axum::serve(listener, app).await.expect("Server error");
}
