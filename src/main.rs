use std::net::SocketAddr;

// The binary uses the library crate rather than re-declaring the modules with
// `mod` — re-declaring compiled a second copy into the binary and made every
// lib function the binary didn't call look like dead code.
use concon::{auth, config, migration, routes, state};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cfg = config::load_or_create().expect("Failed to load config");

    config::ensure_system_data(&cfg.store.system_data).expect("Failed to ensure system data file");

    let app_state = state::AppState::new_persistent(
        &cfg.store.data_dir,
        &cfg.store.files_dir,
        &cfg.grobid.url,
        cfg.server.secure_cookies,
    )
    .expect("Failed to initialize application state");
    if !cfg.server.secure_cookies {
        tracing::warn!(
            "server.secure_cookies = false: session cookie is not marked Secure (development only)"
        );
    }

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

    // Accounts that predate the username rule keep working (lookups treat the
    // username as data), but are reported so the operator can rename them;
    // they cannot be re-created or imported as they are.
    for name in auth::invalid_usernames(&app_state.store_manager.system) {
        tracing::warn!(
            "stored username {name:?} does not pass the username rule \
             (ASCII letters, digits, '_', '-', '.', '@'; no leading '.'; at most {} bytes); \
             the account still logs in, but consider renaming it",
            auth::MAX_USERNAME_LEN
        );
    }
    // Likewise for team names: a team whose name predates the rule cannot be
    // reached by URL (its path segment is rejected before lookup) and should
    // be renamed.
    for name in auth::invalid_team_names(&app_state.store_manager.system) {
        tracing::warn!(
            "stored team name {name:?} does not pass the team-name rule \
             (ASCII letters, digits, '_', '-', '.'; no leading '.' or '_'; at most {} bytes); \
             the team is unreachable by URL until renamed",
            concon::store::MAX_NAME_SEGMENT_LEN
        );
    }

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
