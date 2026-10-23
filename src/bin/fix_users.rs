//! Fix users: rename st154713 to xiang.xu, add wenchuan.liu
//!
//! A one-off maintenance script kept as the worked example of renaming a user
//! with the `auth` helpers (model API; usernames never reach SPARQL text).

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use concon::auth;
use concon::store::{sparql_query, sparql_update};

/// IRI (without `<>`) of the first team matching `query`'s `?team`, if any.
fn team_iri(store: &Store, query: &str) -> Option<String> {
    if let Ok(QueryResults::Solutions(sols)) = sparql_query(store, query) {
        for sol in sols.flatten() {
            if let Some(t) = sol.get("team") {
                return Some(
                    t.to_string()
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string(),
                );
            }
        }
    }
    None
}

/// `<team> mlipe:hasMember <user>` — both IRIs come from the store / the
/// validated `create_user`, never from free text.
fn add_member(store: &Store, team: &str, user_iri: &str, label: &str) {
    let insert = format!(
        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {{ <{team}> mlipe:hasMember <{user_iri}> }}"#
    );
    sparql_update(store, &insert).unwrap_or_else(|e| panic!("add to {label}: {e}"));
}

fn main() {
    let store = Store::open("data/system").expect("Failed to open system store");

    let root_query = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team WHERE { ?team a mlipe:Team . FILTER NOT EXISTS { ?team mlipe:hasParentTeam ?p } } LIMIT 1"#;
    let ml_query = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team WHERE { ?team mlipe:teamName "MetaLearn" } LIMIT 1"#;
    let root = team_iri(&store, root_query);
    let metalearn = team_iri(&store, ml_query);

    // Enrol a freshly created user in root and MetaLearn.
    let enrol = |user_iri: &str| {
        if let Some(root) = &root {
            add_member(&store, root, user_iri, "root");
        }
        if let Some(ml) = &metalearn {
            add_member(&store, ml, user_iri, "MetaLearn");
        }
    };

    // 1. Rename st154713@stud.uni-stuttgart.de -> xiang.xu@imw.uni-stuttgart.de
    let old_user = "st154713@stud.uni-stuttgart.de";
    let new_user = "xiang.xu@imw.uni-stuttgart.de";

    if let Some((old_iri, hash)) = auth::find_user_by_username(&store, old_user) {
        // Delete the old user (profile + memberships/roles — `delete_user`
        // also drops any `hasAdmin` role, which is not re-granted below), then
        // re-create it under the new name with the same password hash.
        auth::delete_user(&store, &old_iri).expect("delete old user");
        let new_iri = auth::create_user(&store, new_user, &hash, None).expect("insert new user");
        enrol(new_iri.as_str());
        println!("Renamed {} -> {}", old_user, new_user);
    }

    // 2. Add wenchuan.liu@imw.uni-stuttgart.de. Not idempotent: `create_user`
    // refuses an existing username, so a second run of this script panics here
    // (the script ran once; it is kept as the worked example).
    let new_username = "wenchuan.liu@imw.uni-stuttgart.de";
    let password_hash = auth::hash_password("1234");
    let new_iri =
        auth::create_user(&store, new_username, &password_hash, None).expect("insert wenchuan.liu");
    enrol(new_iri.as_str());

    println!("Created user {}", new_username);
    println!("Done.");
}
