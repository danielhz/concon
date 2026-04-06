//! Reset a user's password.
//! Usage: ./target/release/reset_password <username> <new_password>

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use concon::store::{sparql_query, sparql_update};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: reset_password <username> <new_password>");
        std::process::exit(1);
    }
    let username = &args[1];
    let new_password = &args[2];

    let store = Store::open("data/system").expect("Failed to open system store");
    let hash = concon::auth::hash_password(new_password);

    let query = format!(
        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user WHERE {{ ?user mlipe:username "{username}" }} LIMIT 1"#
    );

    let mut found = false;
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(&store, &query) {
        for solution in solutions.flatten() {
            let iri = solution.get("user").unwrap().to_string();
            let iri = iri.trim_matches(|c| c == '<' || c == '>');
            let update = format!(
                r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                DELETE {{ <{iri}> mlipe:passwordHash ?old }}
                INSERT {{ <{iri}> mlipe:passwordHash "{hash}" }}
                WHERE {{ <{iri}> mlipe:passwordHash ?old }}"#
            );
            sparql_update(&store, &update).expect("update password");
            println!("Password reset for {}", username);
            found = true;
        }
    }

    if !found {
        eprintln!("User '{}' not found", username);
        std::process::exit(1);
    }
}
