use std::collections::HashMap;
use std::sync::RwLock;

use oxigraph::store::Store;

/// Manages multiple Oxigraph stores, one per dataset.
pub struct StoreManager {
    /// The system store holds user, team, role, and dataset metadata.
    pub system: Store,
    /// Dataset stores, keyed by dataset name.
    datasets: RwLock<HashMap<String, Store>>,
}

impl StoreManager {
    /// Create a new StoreManager with in-memory stores.
    pub fn new_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let system = Store::new()?;
        Ok(Self {
            system,
            datasets: RwLock::new(HashMap::new()),
        })
    }

    /// Create a new dataset with an in-memory store.
    pub fn create_dataset(&self, name: &str) -> Result<(), String> {
        let mut datasets = self.datasets.write().map_err(|e| e.to_string())?;
        if datasets.contains_key(name) {
            return Err(format!("Dataset '{}' already exists", name));
        }
        let store = Store::new().map_err(|e| e.to_string())?;
        datasets.insert(name.to_string(), store);
        Ok(())
    }

    /// Get a reference to a dataset store by name.
    pub fn get_dataset(&self, name: &str) -> Option<Store> {
        let datasets = self.datasets.read().ok()?;
        datasets.get(name).cloned()
    }

    /// List all dataset names.
    pub fn list_datasets(&self) -> Vec<String> {
        let datasets = self.datasets.read().unwrap();
        datasets.keys().cloned().collect()
    }

    /// Delete a dataset.
    pub fn delete_dataset(&self, name: &str) -> Result<(), String> {
        let mut datasets = self.datasets.write().map_err(|e| e.to_string())?;
        datasets
            .remove(name)
            .ok_or_else(|| format!("Dataset '{}' not found", name))?;
        Ok(())
    }
}
