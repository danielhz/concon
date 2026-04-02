//! Add all non-admin users as members of team MetaLearn.

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

fn main() {
    let store = Store::open("data/system").expect("Failed to open system store");

    // Find MetaLearn team IRI
    let team_query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team WHERE {
            ?team a mlipe:Team ; mlipe:teamName "MetaLearn" .
        } LIMIT 1
    "#;

    let mut team_iri = String::new();
    if let Ok(QueryResults::Solutions(solutions)) = store.query(team_query) {
        for solution in solutions.flatten() {
            if let Some(t) = solution.get("team") {
                team_iri = t.to_string().trim_matches(|c| c == '<' || c == '>').to_string();
            }
        }
    }

    if team_iri.is_empty() {
        eprintln!("MetaLearn team not found");
        std::process::exit(1);
    }
    println!("MetaLearn team: {}", team_iri);

    // Find all non-admin users
    let users_query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user ?username WHERE {
            ?user a mlipe:User ; mlipe:username ?username .
            FILTER(?username != "admin")
        }
    "#;

    let mut users = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = store.query(users_query) {
        for solution in solutions.flatten() {
            if let (Some(user), Some(name)) = (solution.get("user"), solution.get("username")) {
                let iri = user.to_string().trim_matches(|c| c == '<' || c == '>').to_string();
                let name = name.to_string();
                users.push((iri, name));
            }
        }
    }

    for (user_iri, username) in &users {
        let insert = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {{
                <{team_iri}> mlipe:hasMember <{user_iri}> .
            }}
            "#,
        );
        match store.update(&insert) {
            Ok(()) => println!("  Added {} to MetaLearn", username),
            Err(e) => eprintln!("  Failed to add {}: {}", username, e),
        }
    }

    println!("Done. Added {} users.", users.len());
}
