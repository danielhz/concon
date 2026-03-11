use std::sync::Arc;

use crate::store::StoreManager;

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub store_manager: Arc<StoreManager>,
}

impl AppState {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store_manager = StoreManager::new_in_memory()?;
        Ok(Self {
            store_manager: Arc::new(store_manager),
        })
    }
}
