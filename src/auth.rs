use std::collections::HashMap;
use std::sync::RwLock;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[derive(Clone)]
pub struct Session {
    pub username: String,
    pub user_iri: String,
}

pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn create_session(&self, username: String, user_iri: String) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session { username, user_iri };
        self.sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }

    pub fn remove_session(&self, session_id: &str) {
        self.sessions.write().unwrap().remove(session_id);
    }
}

#[derive(Clone)]
pub struct DatasetInfo {
    pub name: String,
}

#[derive(Clone)]
pub struct TeamInfo {
    pub iri: String,
    pub name: String,
}

/// Find a user by username in the system store.
/// Returns (user_iri, password_hash) if found.
pub fn find_user_by_username(store: &Store, username: &str) -> Option<(String, String)> {
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user ?hash WHERE {{
            ?user mlipe:username "{}" ;
                  mlipe:passwordHash ?hash .
        }}
        LIMIT 1
        "#,
        username.replace('"', r#"\""#)
    );

    if let Ok(QueryResults::Solutions(solutions)) = store.query(&query) {
        for solution in solutions.flatten() {
            let user_iri = solution.get("user")?.to_string();
            let hash = solution.get("hash")?.to_string();
            // Strip surrounding quotes and datatype from literal
            let hash = strip_literal(&hash);
            return Some((user_iri, hash));
        }
    }
    None
}

/// Update the password hash for a user in the system store.
pub fn update_password_hash(store: &Store, user_iri: &str, new_hash: &str) -> Result<(), String> {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let update = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        DELETE {{ <{iri}> mlipe:passwordHash ?old }}
        INSERT {{ <{iri}> mlipe:passwordHash "{new_hash}" }}
        WHERE {{ <{iri}> mlipe:passwordHash ?old }}
        "#,
    );
    store.update(&update).map_err(|e| e.to_string())
}

/// Get all public datasets from the system store.
pub fn get_public_datasets(store: &Store) -> Vec<DatasetInfo> {
    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?name WHERE {
            ?ds a mlipe:Dataset ;
                mlipe:datasetName ?name ;
                mlipe:hasVisibility mlipe:PublicVisibility .
        }
    "#;

    let mut datasets = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = store.query(query) {
        for solution in solutions.flatten() {
            if let Some(name) = solution.get("name") {
                datasets.push(DatasetInfo {
                    name: strip_literal(&name.to_string()),
                });
            }
        }
    }
    datasets
}

/// Check if a user is an admin of the root team.
pub fn is_root_admin(store: &Store, user_iri: &str) -> bool {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        ASK {{
            ?team a mlipe:Team .
            FILTER NOT EXISTS {{ ?team mlipe:hasParentTeam ?parent }}
            ?team mlipe:hasAdmin <{iri}> .
        }}
        "#,
    );
    store
        .query(&query)
        .ok()
        .and_then(|r| match r {
            QueryResults::Boolean(b) => Some(b),
            _ => None,
        })
        .unwrap_or(false)
}

/// Get datasets accessible to a user.
///
/// - Root team admins see ALL datasets.
/// - Public datasets are visible to everyone (handled by get_public_datasets).
/// - LoggedUsersVisibility datasets are visible to any authenticated user.
/// - TeamOnlyVisibility datasets are visible only if the user is an admin of
///   the owning team, or has a role with QueryAction in the owning team.
pub fn get_user_datasets(store: &Store, user_iri: &str) -> Vec<DatasetInfo> {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');

    // Root team admins see everything
    if is_root_admin(store, user_iri) {
        let query = r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            SELECT DISTINCT ?name WHERE {
                ?ds a mlipe:Dataset ;
                    mlipe:datasetName ?name .
            }
        "#;
        return query_dataset_names(store, query);
    }

    // Regular authenticated users
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT DISTINCT ?name WHERE {{
            ?ds a mlipe:Dataset ;
                mlipe:datasetName ?name .
            {{
                ?ds mlipe:hasVisibility mlipe:PublicVisibility .
            }} UNION {{
                ?ds mlipe:hasVisibility mlipe:LoggedUsersVisibility .
            }} UNION {{
                ?ds mlipe:hasVisibility mlipe:TeamOnlyVisibility .
                ?team mlipe:ownsDataset ?ds ;
                      mlipe:hasAdmin <{iri}> .
            }} UNION {{
                ?ds mlipe:hasVisibility mlipe:TeamOnlyVisibility .
                ?team mlipe:ownsDataset ?ds .
                <{iri}> mlipe:hasRole ?role .
                ?role mlipe:roleInTeam ?team ;
                      mlipe:permitsAction mlipe:QueryAction .
            }}
        }}
        "#,
    );

    query_dataset_names(store, &query)
}

fn query_dataset_names(store: &Store, query: &str) -> Vec<DatasetInfo> {
    let mut datasets = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = store.query(query) {
        for solution in solutions.flatten() {
            if let Some(name) = solution.get("name") {
                datasets.push(DatasetInfo {
                    name: strip_literal(&name.to_string()),
                });
            }
        }
    }
    datasets
}

/// Get teams where the user is an admin (for dataset creation).
pub fn get_user_admin_teams(store: &Store, user_iri: &str) -> Vec<TeamInfo> {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team ?name WHERE {{
            ?team a mlipe:Team ;
                  mlipe:teamName ?name ;
                  mlipe:hasAdmin <{iri}> .
        }}
        "#,
    );

    let mut teams = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = store.query(&query) {
        for solution in solutions.flatten() {
            if let (Some(iri), Some(name)) = (solution.get("team"), solution.get("name")) {
                teams.push(TeamInfo {
                    iri: iri.to_string(),
                    name: strip_literal(&name.to_string()),
                });
            }
        }
    }
    teams
}

/// Strip surrounding quotes and optional datatype suffix from an RDF literal string.
pub fn strip_literal(s: &str) -> String {
    let s = s.trim();
    if let Some(s) = s.strip_prefix('"') {
        // Find the closing quote (handle ^^datatype)
        if let Some(end) = s.rfind('"') {
            return s[..end].to_string();
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "test-password";
        let hash = hash_password(password);
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn test_session_store() {
        let store = SessionStore::new();
        let sid = store.create_session("alice".into(), "http://example.org/alice".into());
        let session = store.get_session(&sid).unwrap();
        assert_eq!(session.username, "alice");
        store.remove_session(&sid);
        assert!(store.get_session(&sid).is_none());
    }

    #[test]
    fn test_strip_literal() {
        assert_eq!(strip_literal(r#""hello""#), "hello");
        assert_eq!(
            strip_literal(r#""hello"^^<http://www.w3.org/2001/XMLSchema#string>"#),
            "hello"
        );
    }
}
