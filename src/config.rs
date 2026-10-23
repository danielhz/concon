use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::auth;

const DEFAULT_CONFIG_PATH: &str = "concon.toml";
const DEFAULT_SYSTEM_DATA_PATH: &str = "system.ttl";

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub store: StoreConfig,
    #[serde(default)]
    pub grobid: GrobidConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GrobidConfig {
    #[serde(default = "default_grobid_url")]
    pub url: String,
}

fn default_grobid_url() -> String {
    "http://localhost:8070".into()
}

impl Default for GrobidConfig {
    fn default() -> Self {
        Self {
            url: default_grobid_url(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Mark the session cookie `Secure` so browsers only send it over HTTPS.
    /// Defaults to `true` (concon is deployed behind TLS); set to `false` only
    /// for local development over plain `http://`, where a `Secure` cookie
    /// would never be sent back and login would appear not to work.
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
}

fn default_secure_cookies() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StoreConfig {
    pub system_data: String,
    pub data_dir: String,
    #[serde(default = "default_files_dir")]
    pub files_dir: String,
}

fn default_files_dir() -> String {
    "data/files".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".into(),
                port: 3000,
                secure_cookies: default_secure_cookies(),
            },
            store: StoreConfig {
                system_data: DEFAULT_SYSTEM_DATA_PATH.into(),
                data_dir: "data".into(),
                files_dir: default_files_dir(),
            },
            grobid: GrobidConfig::default(),
        }
    }
}

/// Load the config file, or create a default one if it doesn't exist.
pub fn load_or_create() -> Result<Config, Box<dyn std::error::Error>> {
    let path = Path::new(DEFAULT_CONFIG_PATH);

    if path.exists() {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    } else {
        let config = Config::default();
        let contents = toml::to_string_pretty(&config)?;
        std::fs::write(path, &contents)?;
        tracing::info!("Created default config file: {}", DEFAULT_CONFIG_PATH);
        Ok(config)
    }
}

/// Ensure the system data Turtle file exists; create it with a default admin
/// user if it doesn't.
pub fn ensure_system_data(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        return Ok(());
    }

    let admin_user = std::env::var("MLIPE_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let admin_pass = std::env::var("MLIPE_ADMIN_PASS").unwrap_or_else(|_| "admin".into());
    // The admin username is interpolated into the Turtle seed below, as an IRI
    // path tail and as a literal: `is_valid_username` admits only characters
    // that need no escaping in either position.
    if !auth::is_valid_username(&admin_user) {
        return Err(format!(
            "MLIPE_ADMIN_USER '{admin_user}' is not a valid username \
             (ASCII letters, digits, '_', '-', '.', '@'; no leading '.'; at most {} bytes)",
            auth::MAX_USERNAME_LEN
        )
        .into());
    }
    let password_hash = auth::hash_password(&admin_pass);
    // Stamp the current schema version so a fresh store starts at it; a seed
    // without this defaults to v1 and the startup version check would panic.
    let version = crate::migration::CURRENT_SCHEMA_VERSION;

    let ttl = format!(
        r#"@prefix mlipe: <https://mlipe.2mia.org/ontology#> .

<https://mlipe.2mia.org/system> mlipe:schemaVersion {version} .

<https://mlipe.2mia.org/teams/root> a mlipe:Team ;
    mlipe:teamName "root" ;
    mlipe:hasMember <https://mlipe.2mia.org/users/{admin_user}> ;
    mlipe:hasAdmin <https://mlipe.2mia.org/users/{admin_user}> .

<https://mlipe.2mia.org/users/{admin_user}> a mlipe:User ;
    mlipe:username "{admin_user}" ;
    mlipe:passwordHash "{password_hash}" .
"#,
    );

    std::fs::write(path, &ttl)?;
    tracing::info!(
        "Created default system data file: {} (admin user: '{}')",
        path,
        admin_user,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Config;

    /// `cp concon.example.toml concon.toml` must start without edits: the
    /// example must parse into a complete `Config` (it previously omitted the
    /// required `store.data_dir`).
    #[test]
    fn example_config_parses() {
        let contents = std::fs::read_to_string("concon.example.toml")
            .expect("concon.example.toml present at the crate root");
        let _: Config = toml::from_str(&contents).expect("example config parses into Config");
    }

    /// `secure_cookies` is opt-out: a config that omits it gets `true`, and an
    /// explicit `false` (local HTTP development) is honoured.
    #[test]
    fn secure_cookies_defaults_to_true() {
        let minimal = r#"
            [server]
            host = "127.0.0.1"
            port = 3000
            [store]
            system_data = "system.ttl"
            data_dir = "data"
        "#;
        let cfg: Config = toml::from_str(minimal).unwrap();
        assert!(cfg.server.secure_cookies);

        let dev = minimal.replace("port = 3000", "port = 3000\nsecure_cookies = false");
        let cfg: Config = toml::from_str(&dev).unwrap();
        assert!(!cfg.server.secure_cookies);
    }

    /// A freshly-seeded system store must report the current schema version, so
    /// a first-time deploy starts without the version-mismatch panic.
    #[test]
    fn seeded_system_data_is_at_current_schema_version() {
        let path = std::env::temp_dir().join(format!("concon-seed-{}.ttl", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        super::ensure_system_data(p).expect("seed system data");
        let store = oxigraph::store::Store::new().unwrap();
        store
            .load_from_reader(oxigraph::io::RdfFormat::Turtle, std::fs::read(p).unwrap().as_slice())
            .expect("seed is valid turtle");
        assert_eq!(
            crate::migration::get_schema_version(&store),
            crate::migration::CURRENT_SCHEMA_VERSION
        );
        let _ = std::fs::remove_file(p);
    }
}
