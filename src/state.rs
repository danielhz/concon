use std::path::PathBuf;
use std::sync::Arc;

use crate::auth::SessionStore;
use crate::store::StoreManager;

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub store_manager: Arc<StoreManager>,
    pub session_store: Arc<SessionStore>,
    pub templates: Arc<minijinja::Environment<'static>>,
    pub files_dir: PathBuf,
}

impl AppState {
    /// Create AppState with in-memory stores (for tests).
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store_manager = StoreManager::new_in_memory()?;

        let mut env = minijinja::Environment::new();
        env.set_loader(minijinja::path_loader("templates"));

        Ok(Self {
            store_manager: Arc::new(store_manager),
            session_store: Arc::new(SessionStore::new()),
            templates: Arc::new(env),
            files_dir: PathBuf::new(),
        })
    }

    /// Create AppState with persistent stores on disk.
    pub fn new_persistent(data_dir: &str, files_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let store_manager = StoreManager::new_persistent(data_dir)?;

        let mut env = minijinja::Environment::new();
        env.set_loader(minijinja::path_loader("templates"));

        let files_path = PathBuf::from(files_dir);
        std::fs::create_dir_all(&files_path)?;

        Ok(Self {
            store_manager: Arc::new(store_manager),
            session_store: Arc::new(SessionStore::new()),
            templates: Arc::new(env),
            files_dir: files_path,
        })
    }
}
