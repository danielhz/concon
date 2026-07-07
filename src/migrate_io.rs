//! Export/import of users and teams for cross-instance migration (Epic I).
//!
//! A bundle is a self-describing JSON document that records the **producing
//! instance's `mlipe:schemaVersion`** (and the concon package version) so an
//! import can detect a version mismatch and reconcile rather than blind-merge.
//! Import is **merge-not-replace**: an object already present on the target is
//! skipped, never clobbered.
//!
//! This module holds the bundle types and the *pure* planning logic (testable
//! without a store or HTTP); the admin-gated web handlers live in `routes::web`.
//! This first slice covers **users** (the motivating migration: users on an old
//! instance → a newer one). argon2 password hashes are PHC strings (algorithm,
//! parameters and salt are self-describing), so preserving `mlipe:passwordHash`
//! verbatim carries passwords across instances that share the argon2 family.
//! Teams (subtree + datasets' graphs + files + roles) are a later slice.

use std::collections::HashSet;

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;
use serde::{Deserialize, Serialize};

use crate::migration;
use crate::store::{sparql_query, sparql_update};

/// The concon package version, stamped into every bundle alongside the schema
/// version.
pub const CONCON_VERSION: &str = env!("CARGO_PKG_VERSION");

const USER_IRI_PREFIX: &str = "https://mlipe.2mia.org/users/";
const ROOT_TEAM_IRI: &str = "https://mlipe.2mia.org/teams/root";

/// One exported user: its IRI, username, and argon2 password hash (PHC string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserRecord {
    pub iri: String,
    pub username: String,
    pub password_hash: String,
}

/// A portable bundle of users, version-annotated for safe cross-version import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersBundle {
    /// Bundle discriminator; always `"users"` for this kind.
    pub kind: String,
    /// The producing instance's `mlipe:schemaVersion`.
    pub schema_version: u32,
    /// The producing instance's concon package version.
    pub concon_version: String,
    pub users: Vec<UserRecord>,
}

impl UsersBundle {
    pub fn new(schema_version: u32, users: Vec<UserRecord>) -> Self {
        Self {
            kind: "users".to_string(),
            schema_version,
            concon_version: CONCON_VERSION.to_string(),
            users,
        }
    }
}

/// The outcome of planning a users import against a target instance — what a
/// dry-run shows and what an apply then executes.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UsersImportReport {
    pub bundle_schema_version: u32,
    pub target_schema_version: u32,
    /// True when the bundle and target schema versions differ — surfaced to the
    /// admin so a cross-version import is a conscious choice. (The user record
    /// shape — username + PHC hash — is version-stable, so users still import
    /// safely; teams/datasets will care about this more.)
    pub version_mismatch: bool,
    /// Usernames not present on the target — these would be (or were) added.
    pub to_add: Vec<String>,
    /// Usernames already present on the target — skipped (never clobbered).
    pub skipped_existing: Vec<String>,
    /// Bundle entries rejected as malformed (empty/invalid username).
    pub rejected: Vec<String>,
    /// True once the additions have actually been written (false for a dry-run).
    pub applied: bool,
}

/// Whether a username is a safe, well-formed local name (it becomes the last
/// path segment of the user IRI). Conservative on purpose — a migration should
/// not be able to inject odd IRIs.
pub fn is_valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 128
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Plan a users import: decide, per bundle entry, add vs skip (already present)
/// vs reject (malformed), and flag a schema-version mismatch. Pure — no store
/// mutation — so a dry-run and the real apply share exactly this decision.
pub fn plan_users_import(
    bundle: &UsersBundle,
    existing_usernames: &HashSet<String>,
    target_schema_version: u32,
) -> UsersImportReport {
    let mut to_add = Vec::new();
    let mut skipped_existing = Vec::new();
    let mut rejected = Vec::new();
    let mut seen_in_bundle = HashSet::new();

    for u in &bundle.users {
        let name = u.username.trim().to_string();
        if !is_valid_username(&name) || u.password_hash.trim().is_empty() {
            rejected.push(u.username.clone());
        } else if existing_usernames.contains(&name) {
            skipped_existing.push(name);
        } else if seen_in_bundle.contains(&name) {
            // Duplicate within the bundle itself — count once.
            skipped_existing.push(name);
        } else {
            seen_in_bundle.insert(name.clone());
            to_add.push(name);
        }
    }

    UsersImportReport {
        bundle_schema_version: bundle.schema_version,
        target_schema_version,
        version_mismatch: bundle.schema_version != target_schema_version,
        to_add,
        skipped_existing,
        rejected,
        applied: false,
    }
}

/// Escape a string for a SPARQL double-quoted literal (see also the annotation
/// path in `routes::entity`). Kept local to avoid a cross-module dependency.
fn escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the users bundle from the system store, stamped with its current
/// schema version.
pub fn export_users(store: &Store) -> UsersBundle {
    let q = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user ?username ?hash WHERE {
            ?user a mlipe:User ;
                  mlipe:username ?username ;
                  mlipe:passwordHash ?hash .
        } ORDER BY ?username
    "#;
    let mut users = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query(store, q) {
        for sol in sols.flatten() {
            if let (Some(user), Some(username), Some(hash)) =
                (sol.get("user"), sol.get("username"), sol.get("hash"))
            {
                users.push(UserRecord {
                    iri: user.to_string().trim_matches(|c| c == '<' || c == '>').to_string(),
                    username: lit(&username.to_string()),
                    password_hash: lit(&hash.to_string()),
                });
            }
        }
    }
    UsersBundle::new(migration::get_schema_version(store), users)
}

/// Extract the lexical value from an oxigraph term's display form
/// (`"value"^^type` / `"value"@lang` / `"value"`).
fn lit(term_display: &str) -> String {
    let s = term_display.trim();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.rfind('"') {
            return rest[..end].to_string();
        }
    }
    s.to_string()
}

/// Apply a users import to the system store: add every planned `to_add` user
/// (reconciled into the target's user-IRI scheme, keyed on username), preserving
/// its argon2 hash, and enrol it in the root team. Returns the report with
/// `applied = true`. Never touches an existing user (merge-not-replace).
pub fn apply_users_import(
    store: &Store,
    bundle: &UsersBundle,
    existing_usernames: &HashSet<String>,
    target_schema_version: u32,
) -> UsersImportReport {
    let mut report = plan_users_import(bundle, existing_usernames, target_schema_version);
    for name in &report.to_add {
        // The record is guaranteed present + valid by the plan.
        let rec = bundle
            .users
            .iter()
            .find(|u| u.username.trim() == name.as_str());
        let Some(rec) = rec else { continue };
        let iri = format!("{USER_IRI_PREFIX}{name}");
        let hash = escape_literal(rec.password_hash.trim());
        let uname = escape_literal(name);
        let insert = format!(
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {{
                <{iri}> a mlipe:User ;
                        mlipe:username "{uname}" ;
                        mlipe:passwordHash "{hash}" .
                <{ROOT_TEAM_IRI}> mlipe:hasMember <{iri}> .
            }}"#
        );
        let _ = sparql_update(store, &insert);
    }
    report.applied = true;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(names: &[&str], version: u32) -> UsersBundle {
        UsersBundle::new(
            version,
            names
                .iter()
                .map(|n| UserRecord {
                    iri: format!("{USER_IRI_PREFIX}{n}"),
                    username: n.to_string(),
                    password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string(),
                })
                .collect(),
        )
    }

    #[test]
    fn plan_merges_not_replaces_and_flags_version() {
        let b = bundle(&["alice", "bob", "carol"], 1);
        let existing: HashSet<String> = ["bob".to_string()].into_iter().collect();
        let r = plan_users_import(&b, &existing, 2);
        assert_eq!(r.to_add, vec!["alice", "carol"]);
        assert_eq!(r.skipped_existing, vec!["bob"]); // never clobbered
        assert!(r.version_mismatch); // bundle v1 vs target v2
        assert!(!r.applied); // dry-run
        assert_eq!(r.bundle_schema_version, 1);
        assert_eq!(r.target_schema_version, 2);
    }

    #[test]
    fn plan_rejects_bad_usernames_and_dedups_bundle() {
        let mut b = bundle(&["ok", "ok"], 2); // duplicate within bundle
        b.users.push(UserRecord {
            iri: "x".into(),
            username: "bad name/../x".into(),
            password_hash: "h".into(),
        });
        b.users.push(UserRecord {
            iri: "y".into(),
            username: "nohash".into(),
            password_hash: "   ".into(),
        });
        let existing = HashSet::new();
        let r = plan_users_import(&b, &existing, 2);
        assert_eq!(r.to_add, vec!["ok"]); // duplicate counted once
        assert_eq!(r.skipped_existing, vec!["ok"]); // second "ok" skipped as dup
        assert!(r.rejected.contains(&"bad name/../x".to_string()));
        assert!(r.rejected.contains(&"nohash".to_string()));
        assert!(!r.version_mismatch);
    }

    #[test]
    fn is_valid_username_guards_iri_safety() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("a.b-c_1"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("a/b"));
        assert!(!is_valid_username("a b"));
        assert!(!is_valid_username("a\"b"));
    }

    #[test]
    fn export_import_roundtrips_through_a_store() {
        // Export from a source store, import into an empty target, and confirm
        // the users (and their hashes) arrive exactly once.
        let src = Store::new().unwrap();
        sparql_update(
            &src,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
                <https://mlipe.2mia.org/users/alice> a mlipe:User ;
                    mlipe:username "alice" ; mlipe:passwordHash "$argon2id$AAA" .
                <https://mlipe.2mia.org/users/bob> a mlipe:User ;
                    mlipe:username "bob" ; mlipe:passwordHash "$argon2id$BBB" .
            }"#,
        )
        .unwrap();
        let b = export_users(&src);
        assert_eq!(b.users.len(), 2);
        assert!(b.users.iter().any(|u| u.username == "alice" && u.password_hash == "$argon2id$AAA"));

        let target = Store::new().unwrap();
        let existing = HashSet::new();
        let r = apply_users_import(&target, &b, &existing, b.schema_version);
        assert!(r.applied);
        assert_eq!(r.to_add.len(), 2);
        let after = export_users(&target);
        assert_eq!(after.users.len(), 2);
        // Re-import is idempotent (all now existing → skipped).
        let existing2: HashSet<String> = after.users.iter().map(|u| u.username.clone()).collect();
        let r2 = apply_users_import(&target, &b, &existing2, b.schema_version);
        assert!(r2.to_add.is_empty());
        assert_eq!(export_users(&target).users.len(), 2);
    }
}
