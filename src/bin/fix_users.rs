//! Fix users: rename st154713 to xiang.xu, add wenchuan.liu

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use concon::store::{sparql_query, sparql_update};

fn main() {
    let store = Store::open("data/system").expect("Failed to open system store");

    // 1. Rename st154713@stud.uni-stuttgart.de -> xiang.xu@imw.uni-stuttgart.de
    let old_user = "st154713@stud.uni-stuttgart.de";
    let new_user = "xiang.xu@imw.uni-stuttgart.de";

    // Find old user IRI
    let query = format!(
        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user ?hash WHERE {{
            ?user mlipe:username "{old_user}" ; mlipe:passwordHash ?hash .
        }} LIMIT 1"#
    );

    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(&store, &query) {
        for solution in solutions.flatten() {
            let user_iri = solution.get("user").unwrap().to_string();
            let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
            let hash = solution
                .get("hash")
                .map(|v| {
                    let s = v.to_string();
                    // Strip quotes and datatype
                    let s = s.trim();
                    if let Some(s) = s.strip_prefix('"') {
                        if let Some(end) = s.rfind('"') {
                            return s[..end].to_string();
                        }
                    }
                    s.to_string()
                })
                .unwrap_or_default();

            let new_iri = format!("https://mlipe.2mia.org/users/{}", new_user);

            // Delete old user
            let del = format!(
                r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                DELETE WHERE {{ <{iri}> ?p ?o }}"#
            );
            sparql_update(&store, &del).expect("delete old user");

            // Delete old membership references
            let del_refs = format!(
                r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                DELETE WHERE {{ ?team mlipe:hasMember <{iri}> }}"#
            );
            sparql_update(&store, &del_refs).expect("delete old memberships");

            // Insert new user with same password hash
            let ins = format!(
                r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                INSERT DATA {{
                    <{new_iri}> a mlipe:User ;
                        mlipe:username "{new_user}" ;
                        mlipe:passwordHash "{hash}" .
                }}"#
            );
            sparql_update(&store, &ins).expect("insert new user");

            // Add to root team
            let root_query = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                SELECT ?team WHERE { ?team a mlipe:Team . FILTER NOT EXISTS { ?team mlipe:hasParentTeam ?p } } LIMIT 1"#;
            if let Ok(QueryResults::Solutions(sols)) = sparql_query(&store, root_query) {
                for sol in sols.flatten() {
                    let root = sol.get("team").unwrap().to_string();
                    let root = root.trim_matches(|c| c == '<' || c == '>');
                    let ins_member = format!(
                        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                        INSERT DATA {{ <{root}> mlipe:hasMember <{new_iri}> }}"#
                    );
                    sparql_update(&store, &ins_member).expect("add to root");
                }
            }

            // Add to MetaLearn
            let ml_query = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                SELECT ?team WHERE { ?team mlipe:teamName "MetaLearn" } LIMIT 1"#;
            if let Ok(QueryResults::Solutions(sols)) = sparql_query(&store, ml_query) {
                for sol in sols.flatten() {
                    let ml = sol.get("team").unwrap().to_string();
                    let ml = ml.trim_matches(|c| c == '<' || c == '>');
                    let ins_member = format!(
                        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                        INSERT DATA {{ <{ml}> mlipe:hasMember <{new_iri}> }}"#
                    );
                    sparql_update(&store, &ins_member).expect("add to MetaLearn");
                }
            }

            println!("Renamed {} -> {}", old_user, new_user);
        }
    }

    // 2. Add wenchuan.liu@imw.uni-stuttgart.de
    let new_username = "wenchuan.liu@imw.uni-stuttgart.de";
    let password_hash = concon::auth::hash_password("1234");
    let new_iri = format!("https://mlipe.2mia.org/users/{}", new_username);

    let ins = format!(
        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {{
            <{new_iri}> a mlipe:User ;
                mlipe:username "{new_username}" ;
                mlipe:passwordHash "{password_hash}" .
        }}"#
    );
    sparql_update(&store, &ins).expect("insert wenchuan.liu");

    // Add to root and MetaLearn
    let root_query = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team WHERE { ?team a mlipe:Team . FILTER NOT EXISTS { ?team mlipe:hasParentTeam ?p } } LIMIT 1"#;
    if let Ok(QueryResults::Solutions(sols)) = sparql_query(&store, root_query) {
        for sol in sols.flatten() {
            let root = sol.get("team").unwrap().to_string();
            let root = root.trim_matches(|c| c == '<' || c == '>');
            sparql_update(
                &store,
                &format!(
                    r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                INSERT DATA {{ <{root}> mlipe:hasMember <{new_iri}> }}"#
                ),
            )
            .expect("add to root");
        }
    }
    let ml_query = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team WHERE { ?team mlipe:teamName "MetaLearn" } LIMIT 1"#;
    if let Ok(QueryResults::Solutions(sols)) = sparql_query(&store, ml_query) {
        for sol in sols.flatten() {
            let ml = sol.get("team").unwrap().to_string();
            let ml = ml.trim_matches(|c| c == '<' || c == '>');
            sparql_update(
                &store,
                &format!(
                    r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                INSERT DATA {{ <{ml}> mlipe:hasMember <{new_iri}> }}"#
                ),
            )
            .expect("add to MetaLearn");
        }
    }

    println!("Created user {}", new_username);
    println!("Done.");
}
