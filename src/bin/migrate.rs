//! CLI tool to migrate MLIPE data to the current schema version.
//!
//! Usage: ./target/release/migrate
//!
//! Reads concon.toml for the data directory, creates a backup, and runs
//! all pending migrations.

// Import from the mlipe library crate.
// Since this is a binary in the same package, we use `concon::` to access lib items.
// However, mlipe is a binary crate (no lib.rs). We need to restructure slightly
// or duplicate the config loading. For simplicity, we duplicate the config load.

use std::path::Path;

use oxigraph::store::Store;

fn main() {
    tracing_subscriber::fmt::init();

    let config_path = "concon.toml";
    let config_contents = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "Error: Cannot read {}. Run this from the application directory.",
                config_path
            );
            std::process::exit(1);
        }
    };

    #[derive(serde::Deserialize)]
    struct Config {
        store: StoreConfig,
    }
    #[derive(serde::Deserialize)]
    struct StoreConfig {
        data_dir: Option<String>,
    }

    let config: Config = match toml::from_str(&config_contents) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to parse {}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    let data_dir = config.store.data_dir.as_deref().unwrap_or("data");
    let system_path = Path::new(data_dir).join("system");

    if !system_path.exists() {
        eprintln!(
            "Error: System store not found at {}. Is the data directory correct?",
            system_path.display()
        );
        std::process::exit(1);
    }

    let store = match Store::open(&system_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Failed to open system store: {}", e);
            std::process::exit(1);
        }
    };

    let version = concon::migration::get_schema_version(&store);
    println!("Current schema version: {}", version);
    println!(
        "Target schema version:  {}",
        concon::migration::CURRENT_SCHEMA_VERSION
    );

    if version == concon::migration::CURRENT_SCHEMA_VERSION {
        println!("Already up to date. Nothing to do.");
        return;
    }

    match concon::migration::migrate(data_dir, &store) {
        Ok(()) => {
            println!("Migration completed successfully.");
        }
        Err(e) => {
            eprintln!("Migration failed: {}", e);
            eprintln!("Your data backup is intact. Check the backup directory.");
            std::process::exit(1);
        }
    }
}
