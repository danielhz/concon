//! Provision the public `mlips` resource: a top-level `mlips` team holding a
//! Public `mlips` dataset, served at `<host>/mlips/_ds/mlips/`. Idempotent —
//! safe to re-run. Run before starting the server (the server opens existing
//! datasets at startup); the D1 loader then PUTs graphs/doc into it.
//!
//! Usage: ./target/release/provision_mlips   (reads concon.toml for data_dir)

use concon::store::{StoreManager, sparql_update};

const ROOT_TEAM_IRI: &str = "https://mlipe.2mia.org/teams/root";
const MLIPS_TEAM_IRI: &str = "https://mlipe.2mia.org/teams/mlips";
const DATASET_NAME: &str = "mlips/mlips";

fn main() {
    tracing_subscriber::fmt::init();

    let config_contents = std::fs::read_to_string("concon.toml").unwrap_or_else(|_| {
        eprintln!("Error: cannot read concon.toml. Run from the application directory.");
        std::process::exit(1);
    });

    #[derive(serde::Deserialize)]
    struct Config {
        store: StoreConfig,
    }
    #[derive(serde::Deserialize)]
    struct StoreConfig {
        data_dir: Option<String>,
    }

    let config: Config = toml::from_str(&config_contents).unwrap_or_else(|e| {
        eprintln!("Error: failed to parse concon.toml: {e}");
        std::process::exit(1);
    });
    let data_dir = config.store.data_dir.as_deref().unwrap_or("data");

    let manager = StoreManager::new_persistent(data_dir).unwrap_or_else(|e| {
        eprintln!("Error: failed to open stores at '{data_dir}': {e}");
        std::process::exit(1);
    });

    // 1. The top-level `mlips` team (child of root). INSERT DATA is a no-op for
    //    triples that already exist (RDF set semantics), so this is idempotent.
    let insert_team = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {{
            <{MLIPS_TEAM_IRI}> a mlipe:Team ;
                mlipe:teamName "mlips" ;
                mlipe:hasParentTeam <{ROOT_TEAM_IRI}> .
        }}
        "#,
    );
    if let Err(e) = sparql_update(&manager.system, &insert_team) {
        eprintln!("Error: failed to create the mlips team: {e}");
        std::process::exit(1);
    }

    // 2. The `mlips` dataset store (create_dir_all + open is safe if it exists).
    if let Err(e) = manager.create_dataset(DATASET_NAME) {
        // Only a genuine open failure matters; "already present" is fine.
        eprintln!("Note: create_dataset returned: {e}");
    }

    // 3. Public visibility + ownership by the mlips team.
    if let Err(e) =
        manager.insert_dataset_metadata_full(DATASET_NAME, "PublicVisibility", MLIPS_TEAM_IRI)
    {
        eprintln!("Error: failed to write dataset metadata: {e}");
        std::process::exit(1);
    }

    println!(
        "Provisioned: team <{MLIPS_TEAM_IRI}> + Public dataset '{DATASET_NAME}' \
         (served at <host>/mlips/_ds/mlips/). Restart the server to open it."
    );
}
