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

use crate::auth::{
    self, ROOT_TEAM_IRI, TEAM_IRI_PREFIX, is_reserved_root_team_name, is_valid_team_name,
    is_valid_username,
};
use crate::migration;
use crate::store::{sparql_query, sparql_update};

/// The concon package version, stamped into every bundle alongside the schema
/// version.
pub const CONCON_VERSION: &str = env!("CARGO_PKG_VERSION");

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
/// Users are written through `auth::create_user` (model API, validated
/// username); a user the store refuses is moved from `to_add` to `rejected`.
pub fn apply_users_import(
    store: &Store,
    bundle: &UsersBundle,
    existing_usernames: &HashSet<String>,
    target_schema_version: u32,
) -> UsersImportReport {
    let mut report = plan_users_import(bundle, existing_usernames, target_schema_version);
    let mut added = Vec::with_capacity(report.to_add.len());
    for name in std::mem::take(&mut report.to_add) {
        // The record is guaranteed present + valid by the plan.
        let rec = bundle
            .users
            .iter()
            .find(|u| u.username.trim() == name.as_str());
        let Some(rec) = rec else { continue };
        match auth::create_user(store, &name, rec.password_hash.trim(), Some(ROOT_TEAM_IRI)) {
            Ok(_) => added.push(name),
            Err(_) => report.rejected.push(name),
        }
    }
    report.to_add = added;
    report.applied = true;
    report
}

// ---------------------------------------------------------------------------
// Teams slice: export/import a team subtree (organisational structure —
// sub-teams + membership + roles). Datasets' RDF payloads and files are a
// documented follow-up slice; this slice recreates the team hierarchy and its
// memberships/roles, which is the structural core migration reuses.
// ---------------------------------------------------------------------------

/// One team in a subtree bundle. `rel_path` is the team's path **relative to
/// (and including) the exported subtree root** — e.g. root "materials" has
/// `rel_path = "materials"`, its child "atomistic" has `"materials/atomistic"`.
/// This makes re-parenting on import a pure prefix operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamRecord {
    pub rel_path: String,
    pub name: String,
    pub members: Vec<String>,
    pub admins: Vec<String>,
}

/// A portable bundle of a team subtree, version-annotated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsBundle {
    pub kind: String,
    pub schema_version: u32,
    pub concon_version: String,
    /// `rel_path` of the subtree root (informational).
    pub subtree_root: String,
    pub teams: Vec<TeamRecord>,
}

impl TeamsBundle {
    pub fn new(schema_version: u32, subtree_root: String, teams: Vec<TeamRecord>) -> Self {
        Self {
            kind: "teams".to_string(),
            schema_version,
            concon_version: CONCON_VERSION.to_string(),
            subtree_root,
            teams,
        }
    }
}

/// Per-team import outcome for the report.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TeamPlanRow {
    /// Resolved path on the target (e.g. "org/materials/atomistic").
    pub target_path: String,
    /// True when a team already existed at that path — creation is skipped AND
    /// the existing team (including its memberships/roles) is left completely
    /// untouched (merge-not-replace).
    pub skipped_existing: bool,
    /// True when the entry resolves to the special root team (`teams/root`) —
    /// refused outright (never created, re-parented, or linked). Guards against
    /// a crafted bundle escalating a user to root admin via import.
    pub rejected_root: bool,
    /// Members/admins linked — populated ONLY for teams this import creates
    /// (present users only); empty for skipped/refused rows.
    pub linked_members: Vec<String>,
    pub linked_admins: Vec<String>,
    /// Set by apply when a team the plan meant to create could not be
    /// written after all — a team appeared at that path since the plan, or
    /// the store failed — with the reason. Nothing is linked on such a row,
    /// and it is not counted as created.
    pub failed: Option<String>,
}

/// The plan/outcome of a teams import.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TeamsImportReport {
    pub bundle_schema_version: u32,
    pub target_schema_version: u32,
    pub version_mismatch: bool,
    pub target_parent_path: String,
    pub rows: Vec<TeamPlanRow>,
    /// Usernames referenced by *created* teams but absent on the target (their
    /// links are skipped — import users first to include them).
    pub missing_users: Vec<String>,
    /// Target paths refused because they resolve to the root team.
    pub rejected_root: Vec<String>,
    pub created_count: usize,
    pub skipped_count: usize,
    pub applied: bool,
}

/// The path part of a team IRI (`…/teams/<path>`), or `None` if not a team IRI.
fn team_path_from_iri(iri: &str) -> Option<String> {
    iri.trim_matches(|c| c == '<' || c == '>')
        .strip_prefix(TEAM_IRI_PREFIX)
        .map(|s| s.to_string())
}

/// The IRI for a team addressed by path segments (root = the special
/// `teams/root`; anything else is `teams/<segments-joined>`).
fn team_iri_for(segments: &[String]) -> String {
    if segments.is_empty() {
        ROOT_TEAM_IRI.to_string()
    } else {
        format!("{TEAM_IRI_PREFIX}{}", segments.join("/"))
    }
}

fn usernames_with_role(store: &Store, team_iri: &str, role_pred: &str) -> Vec<String> {
    let q = format!(
        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?n WHERE {{ <{team_iri}> mlipe:{role_pred} ?u . ?u mlipe:username ?n }} ORDER BY ?n"#
    );
    let mut out = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query(store, &q) {
        for sol in sols.flatten() {
            if let Some(n) = sol.get("n") {
                out.push(lit(&n.to_string()));
            }
        }
    }
    out
}

/// Export the team subtree rooted at `root_iri` (resolved by the caller) as a
/// bundle: the root and all descendants, each with its members and admins.
pub fn export_teams(store: &Store, root_iri: &str) -> TeamsBundle {
    let root_clean = root_iri.trim_matches(|c| c == '<' || c == '>');
    let root_path = team_path_from_iri(root_clean).unwrap_or_default();
    // The prefix to strip so rel_path keeps the subtree root's own name.
    let parent_prefix = match root_path.rfind('/') {
        Some(i) => root_path[..=i].to_string(), // includes trailing '/'
        None => String::new(),
    };

    let q = format!(
        r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?t ?name WHERE {{
            {{ BIND(<{root_clean}> AS ?t) ?t mlipe:teamName ?name }}
            UNION
            {{ ?t mlipe:hasParentTeam+ <{root_clean}> ; mlipe:teamName ?name }}
        }}"#
    );
    let mut teams = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query(store, &q) {
        for sol in sols.flatten() {
            let (Some(t), Some(name)) = (sol.get("t"), sol.get("name")) else {
                continue;
            };
            let iri = t.to_string();
            let Some(path) = team_path_from_iri(&iri) else { continue };
            let rel_path = path.strip_prefix(&parent_prefix).unwrap_or(&path).to_string();
            let clean = iri.trim_matches(|c| c == '<' || c == '>').to_string();
            teams.push(TeamRecord {
                rel_path,
                name: lit(&name.to_string()),
                members: usernames_with_role(store, &clean, "hasMember"),
                admins: usernames_with_role(store, &clean, "hasAdmin"),
            });
        }
    }
    // Parents before children: shallower rel_path first.
    teams.sort_by_key(|t| (t.rel_path.matches('/').count(), t.rel_path.clone()));
    TeamsBundle::new(migration::get_schema_version(store), root_path, teams)
}

/// Resolve a bundle team's target segments = `target_parent_segments ++
/// rel_path segments`. Pure (used by plan and apply).
fn target_segments_for(target_parent_segments: &[String], rel_path: &str) -> Vec<String> {
    let mut segs = target_parent_segments.to_vec();
    segs.extend(rel_path.split('/').filter(|s| !s.is_empty()).map(String::from));
    segs
}

/// Check that every team in `bundle` can be created on a target: each
/// `rel_path` is one or more valid team names ([`is_valid_team_name`]) and
/// `name` is its last segment (the team IRI is minted from the path, so the
/// two must agree), and no team would land directly under the root team with
/// a [`auth::RESERVED_ROOT_TEAM_NAMES`] name. Also checks
/// `target_parent_segments`. The first offender is named in the error. A
/// bundle is validated as a whole, before anything is planned or written: an
/// invalid name anywhere rejects the import.
pub fn validate_teams_bundle(
    bundle: &TeamsBundle,
    target_parent_segments: &[String],
) -> Result<(), String> {
    if let Some(bad) = target_parent_segments
        .iter()
        .find(|s| !is_valid_team_name(s))
    {
        return Err(format!("Invalid target parent team segment {bad:?}"));
    }
    for team in &bundle.teams {
        let segs: Vec<&str> = team.rel_path.split('/').collect();
        if let Some(bad) = segs.iter().find(|s| !is_valid_team_name(s)) {
            return Err(format!(
                "Invalid team path segment {bad:?} in team path {:?}",
                team.rel_path
            ));
        }
        if !is_valid_team_name(&team.name) {
            return Err(format!("Invalid team name {:?}", team.name));
        }
        if segs.last().copied() != Some(team.name.as_str()) {
            return Err(format!(
                "Team name {:?} does not match the last segment of its path {:?}",
                team.name, team.rel_path
            ));
        }
        let target = target_segments_for(target_parent_segments, &team.rel_path);
        if target.len() == 1 && is_reserved_root_team_name(&target[0]) {
            return Err(format!(
                "Team name {:?} is reserved directly under the root team",
                target[0]
            ));
        }
    }
    Ok(())
}

/// Plan a teams import under `target_parent_segments` (empty = root): resolve
/// each team's target path, decide create-vs-skip (merge-not-replace), and note
/// which referenced users are missing on the target. Pure — shared by dry-run
/// and apply. Fails, without a plan, when the bundle or the target parent
/// does not pass [`validate_teams_bundle`].
pub fn plan_teams_import(
    bundle: &TeamsBundle,
    target_parent_segments: &[String],
    existing_team_paths: &HashSet<String>,
    existing_usernames: &HashSet<String>,
    target_schema_version: u32,
) -> Result<TeamsImportReport, String> {
    validate_teams_bundle(bundle, target_parent_segments)?;
    let mut rows = Vec::new();
    let mut missing = HashSet::new();
    let mut rejected_root = Vec::new();
    let mut created = 0usize;
    let mut skipped = 0usize;

    let mut ordered = bundle.teams.clone();
    ordered.sort_by_key(|t| (t.rel_path.matches('/').count(), t.rel_path.clone()));

    for team in &ordered {
        let segs = target_segments_for(target_parent_segments, &team.rel_path);
        let target_path = segs.join("/");
        // Root guard: refuse anything resolving to the root team — a crafted
        // bundle must never create/re-parent/link on `teams/root` (that would
        // escalate a user to root admin during import).
        let is_root = segs.is_empty() || team_iri_for(&segs) == ROOT_TEAM_IRI;
        let exists = existing_team_paths.contains(&target_path);
        let will_create = !is_root && !exists;

        // Members/admins are linked ONLY for teams we actually create; skipped
        // (pre-existing) and refused (root) teams are left untouched — that is
        // what merge-not-replace means, and it closes the confused-deputy path
        // where an import could grant roles on any pre-existing team.
        let mut linked_members = Vec::new();
        let mut linked_admins = Vec::new();
        if will_create {
            created += 1;
            let mut link = |names: &[String], out: &mut Vec<String>| {
                for u in names {
                    if existing_usernames.contains(u) {
                        out.push(u.clone());
                    } else {
                        missing.insert(u.clone());
                    }
                }
            };
            link(&team.members, &mut linked_members);
            link(&team.admins, &mut linked_admins);
        } else if is_root {
            rejected_root.push(target_path.clone());
        } else {
            skipped += 1;
        }

        rows.push(TeamPlanRow {
            target_path,
            skipped_existing: exists && !is_root,
            rejected_root: is_root,
            linked_members,
            linked_admins,
            failed: None,
        });
    }

    let mut missing_users: Vec<String> = missing.into_iter().collect();
    missing_users.sort();
    Ok(TeamsImportReport {
        bundle_schema_version: bundle.schema_version,
        target_schema_version,
        version_mismatch: bundle.schema_version != target_schema_version,
        target_parent_path: target_parent_segments.join("/"),
        rows,
        missing_users,
        rejected_root,
        created_count: created,
        skipped_count: skipped,
        applied: false,
    })
}

/// Apply a teams import: create each not-yet-existing team under its resolved
/// parent (merge-not-replace) and link the members/admins whose users exist on
/// the target. Never modifies an existing team's own triples. Fails, without
/// writing anything, when the bundle does not pass [`validate_teams_bundle`].
pub fn apply_teams_import(
    store: &Store,
    bundle: &TeamsBundle,
    target_parent_segments: &[String],
    existing_team_paths: &HashSet<String>,
    existing_usernames: &HashSet<String>,
    target_schema_version: u32,
) -> Result<TeamsImportReport, String> {
    let mut report = plan_teams_import(
        bundle,
        target_parent_segments,
        existing_team_paths,
        existing_usernames,
        target_schema_version,
    )?;
    // Recompute the ordered list identically to the plan.
    let mut ordered = bundle.teams.clone();
    ordered.sort_by_key(|t| (t.rel_path.matches('/').count(), t.rel_path.clone()));

    for (team, row) in ordered.iter().zip(report.rows.iter_mut()) {
        // Only teams this import creates are written. Pre-existing (skipped) and
        // root-refused rows are left completely untouched — including their
        // memberships/roles — so an import can neither clobber an existing team
        // nor grant roles on it (esp. root). This is the fix for the
        // import privilege-escalation.
        if row.skipped_existing || row.rejected_root {
            continue;
        }
        let segs = target_segments_for(target_parent_segments, &team.rel_path);
        let parent_iri = team_iri_for(&segs[..segs.len() - 1]);
        // Model-API write (the name is a literal value, never query text). The
        // plan found no team at this path; if one appeared since (the IRI or
        // the name under this parent is taken), or the store fails, do not
        // link roles onto it — that would be the role grant on a pre-existing
        // team the plan refuses — and say so in the report.
        let team_iri = match auth::create_team(store, &parent_iri, &team.name) {
            Ok(team) => team.into_string(),
            Err(e) => {
                tracing::warn!(
                    "teams import: could not create {:?} planned for creation: {e}",
                    row.target_path
                );
                row.failed = Some(e.to_string());
                row.linked_members.clear();
                row.linked_admins.clear();
                report.created_count -= 1;
                continue;
            }
        };

        // Link members/admins (present users only) — created teams only.
        for (pred, names) in [("hasMember", &row.linked_members), ("hasAdmin", &row.linked_admins)] {
            for u in names {
                // Present users only (checked by the plan). The link targets
                // the user's stored node, looked up by username, so a legacy
                // account whose IRI is not `<USER_IRI_PREFIX><username>` is
                // linked correctly rather than left dangling.
                let Some(user_iri) = auth::find_user_iri(store, u) else {
                    continue;
                };
                let user_iri = user_iri.trim_matches(|c| c == '<' || c == '>');
                let insert = format!(
                    r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                    INSERT DATA {{ <{team_iri}> mlipe:{pred} <{user_iri}> }}"#
                );
                let _ = sparql_update(store, &insert);
            }
        }
    }
    report.applied = true;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::USER_IRI_PREFIX;

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
        assert!(is_valid_username("first.last@example.org"));
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

    #[test]
    fn teams_export_import_roundtrip() {
        let src = Store::new().unwrap();
        sparql_update(
            &src,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
              <https://mlipe.2mia.org/teams/materials> a mlipe:Team ; mlipe:teamName "materials" ;
                  mlipe:hasParentTeam <https://mlipe.2mia.org/teams/root> .
              <https://mlipe.2mia.org/teams/materials/atomistic> a mlipe:Team ;
                  mlipe:teamName "atomistic" ;
                  mlipe:hasParentTeam <https://mlipe.2mia.org/teams/materials> .
              <https://mlipe.2mia.org/users/alice> a mlipe:User ; mlipe:username "alice" .
              <https://mlipe.2mia.org/teams/materials> mlipe:hasAdmin <https://mlipe.2mia.org/users/alice> .
              <https://mlipe.2mia.org/teams/materials/atomistic> mlipe:hasMember <https://mlipe.2mia.org/users/alice> .
            }"#,
        )
        .unwrap();

        let bundle = export_teams(&src, "https://mlipe.2mia.org/teams/materials");
        assert_eq!(bundle.teams.len(), 2, "subtree = materials + atomistic");
        let mat = bundle.teams.iter().find(|t| t.rel_path == "materials").unwrap();
        assert_eq!(mat.name, "materials");
        assert_eq!(mat.admins, vec!["alice"]);
        let atom = bundle.teams.iter().find(|t| t.rel_path == "materials/atomistic").unwrap();
        assert_eq!(atom.members, vec!["alice"]);

        // Import into a fresh target that has root + alice.
        let tgt = Store::new().unwrap();
        sparql_update(
            &tgt,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
              <https://mlipe.2mia.org/users/alice> a mlipe:User ; mlipe:username "alice" .
            }"#,
        )
        .unwrap();
        let existing_users: HashSet<String> = ["alice".to_string()].into_iter().collect();
        let r = apply_teams_import(
            &tgt,
            &bundle,
            &[],
            &HashSet::new(),
            &existing_users,
            bundle.schema_version,
        )
        .unwrap();
        assert!(r.applied);
        assert_eq!(r.created_count, 2);
        assert!(r.missing_users.is_empty());

        // The subtree (and its membership) is recreated on the target.
        let after = export_teams(&tgt, "https://mlipe.2mia.org/teams/materials");
        assert_eq!(after.teams.len(), 2);
        let atom2 = after.teams.iter().find(|t| t.rel_path == "materials/atomistic").unwrap();
        assert_eq!(atom2.members, vec!["alice"]);

        // Re-import is idempotent (all paths now exist → skipped).
        let existing_teams: HashSet<String> =
            ["materials".to_string(), "materials/atomistic".to_string()].into_iter().collect();
        let r2 = plan_teams_import(&bundle, &[], &existing_teams, &existing_users, bundle.schema_version)
            .unwrap();
        assert_eq!(r2.created_count, 0);
        assert_eq!(r2.skipped_count, 2);
    }

    #[test]
    fn teams_import_flags_missing_users_and_version_and_reparents() {
        let bundle = TeamsBundle::new(
            1,
            "materials".into(),
            vec![TeamRecord {
                rel_path: "materials".into(),
                name: "materials".into(),
                members: vec!["ghost".into()],
                admins: vec![],
            }],
        );
        // Re-parent under "org": target path becomes org/materials.
        let r = plan_teams_import(
            &bundle,
            &["org".to_string()],
            &HashSet::new(),
            &HashSet::new(), // ghost absent
            2,
        )
        .unwrap();
        assert!(r.version_mismatch); // bundle v1 vs target v2
        assert_eq!(r.missing_users, vec!["ghost"]);
        assert_eq!(r.rows[0].target_path, "org/materials"); // re-parented
        assert!(r.rows[0].linked_members.is_empty()); // ghost not linked
    }

    fn team_has_role(store: &Store, team: &str, pred: &str, user: &str) -> bool {
        matches!(
            sparql_query(
                store,
                &format!(
                    "PREFIX mlipe: <https://mlipe.2mia.org/ontology#> ASK {{ <{team}> mlipe:{pred} <{user}> }}"
                )
            ),
            Ok(QueryResults::Boolean(true))
        )
    }

    /// Security regression: a crafted bundle with a team resolving to the root
    /// team must be refused — no team write and, crucially, no `hasAdmin`
    /// granted on `teams/root` (would be root-admin escalation via import).
    #[test]
    fn teams_import_refuses_root_escalation() {
        let bundle = TeamsBundle::new(
            2,
            "root".into(),
            vec![TeamRecord {
                rel_path: "root".into(),
                name: "root".into(),
                members: vec![],
                admins: vec!["alice".into()],
            }],
        );
        let existing_users: HashSet<String> = ["alice".to_string()].into_iter().collect();

        let plan = plan_teams_import(&bundle, &[], &HashSet::new(), &existing_users, 2).unwrap();
        assert_eq!(plan.created_count, 0);
        assert!(plan.rejected_root.contains(&"root".to_string()));
        assert!(plan.rows[0].rejected_root);
        assert!(plan.rows[0].linked_admins.is_empty());

        let store = Store::new().unwrap();
        sparql_update(
            &store,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
              <https://mlipe.2mia.org/users/alice> a mlipe:User ; mlipe:username "alice" .
            }"#,
        )
        .unwrap();
        apply_teams_import(&store, &bundle, &[], &HashSet::new(), &existing_users, 2).unwrap();
        assert!(
            !team_has_role(
                &store,
                "https://mlipe.2mia.org/teams/root",
                "hasAdmin",
                "https://mlipe.2mia.org/users/alice"
            ),
            "import must never grant root admin"
        );
    }

    /// Security regression: importing a bundle whose team path matches an
    /// existing team must NOT touch that team — no membership/role clobbering
    /// (merge-not-replace / confused-deputy fix).
    #[test]
    fn teams_import_leaves_existing_team_untouched() {
        let bundle = TeamsBundle::new(
            2,
            "materials".into(),
            vec![TeamRecord {
                rel_path: "materials".into(),
                name: "materials".into(),
                members: vec![],
                admins: vec!["alice".into()],
            }],
        );
        let store = Store::new().unwrap();
        sparql_update(
            &store,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
              <https://mlipe.2mia.org/teams/materials> a mlipe:Team ; mlipe:teamName "materials" ;
                  mlipe:hasParentTeam <https://mlipe.2mia.org/teams/root> .
              <https://mlipe.2mia.org/users/alice> a mlipe:User ; mlipe:username "alice" .
            }"#,
        )
        .unwrap();
        let existing_teams: HashSet<String> = ["materials".to_string()].into_iter().collect();
        let existing_users: HashSet<String> = ["alice".to_string()].into_iter().collect();
        let r =
            apply_teams_import(&store, &bundle, &[], &existing_teams, &existing_users, 2).unwrap();
        assert_eq!(r.created_count, 0);
        assert_eq!(r.skipped_count, 1);
        assert!(
            !team_has_role(
                &store,
                "https://mlipe.2mia.org/teams/materials",
                "hasAdmin",
                "https://mlipe.2mia.org/users/alice"
            ),
            "import must not grant admin on a pre-existing team"
        );
    }

    fn team_record(rel_path: &str, name: &str) -> TeamRecord {
        TeamRecord {
            rel_path: rel_path.into(),
            name: name.into(),
            members: vec![],
            admins: vec!["alice".into()],
        }
    }

    /// A bundle carrying a team name (or path segment) that is not a valid
    /// team name is refused as a whole, before planning or writing: nothing is
    /// created, no role is granted, and the offender is named.
    #[test]
    fn teams_import_rejects_invalid_names_before_writing() {
        let store = Store::new().unwrap();
        sparql_update(
            &store,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
              <https://mlipe.2mia.org/users/alice> a mlipe:User ; mlipe:username "alice" .
            }"#,
        )
        .unwrap();
        let existing_users: HashSet<String> = ["alice".to_string()].into_iter().collect();
        let bad_bundles = [
            // a quote that would end a SPARQL literal
            TeamsBundle::new(2, "x".into(), vec![team_record("x\"y", "x\"y")]),
            // an injection attempt in the name only
            TeamsBundle::new(2, "ok".into(), vec![team_record("ok", "ok\" } #")]),
            // a path segment that is not a team name
            TeamsBundle::new(
                2,
                "ok".into(),
                vec![team_record("ok", "ok"), team_record("ok/a b", "a b")],
            ),
            // a reserved `_` view prefix and a hidden `.` name
            TeamsBundle::new(2, "_files".into(), vec![team_record("_files", "_files")]),
            TeamsBundle::new(2, ".hidden".into(), vec![team_record(".hidden", ".hidden")]),
            // a name that disagrees with its path (the IRI is minted from the path)
            TeamsBundle::new(2, "ok".into(), vec![team_record("ok", "other")]),
        ];
        for bundle in &bad_bundles {
            let plan = plan_teams_import(bundle, &[], &HashSet::new(), &existing_users, 2);
            assert!(plan.is_err(), "{:?}", bundle.teams);
            let r = apply_teams_import(&store, bundle, &[], &HashSet::new(), &existing_users, 2);
            assert!(r.is_err(), "{:?}", bundle.teams);
        }
        // An invalid target parent segment is refused the same way.
        let ok = TeamsBundle::new(2, "ok".into(), vec![team_record("ok", "ok")]);
        let r = apply_teams_import(
            &store,
            &ok,
            &["a\"b".to_string()],
            &HashSet::new(),
            &existing_users,
            2,
        );
        assert!(r.is_err());
        // Nothing but the seed is in the store: exactly one team, no admin role.
        let teams = store
            .quads_for_pattern(
                None,
                Some(
                    oxigraph::model::NamedNode::new("https://mlipe.2mia.org/ontology#teamName")
                        .unwrap()
                        .as_ref(),
                ),
                None,
                None,
            )
            .count();
        assert_eq!(teams, 1);
        let roles = store
            .quads_for_pattern(
                None,
                Some(
                    oxigraph::model::NamedNode::new("https://mlipe.2mia.org/ontology#hasAdmin")
                        .unwrap()
                        .as_ref(),
                ),
                None,
                None,
            )
            .count();
        assert_eq!(roles, 0);
    }

    /// A team that appears at a planned path between plan and apply (here:
    /// it exists but was absent from the caller's path set) is not created,
    /// is reported as failed rather than created, and gets no role linked.
    #[test]
    fn teams_import_reports_a_team_it_could_not_create() {
        let bundle = TeamsBundle::new(
            2,
            "materials".into(),
            vec![team_record("materials", "materials"), team_record("materials/sub", "sub")],
        );
        let store = Store::new().unwrap();
        sparql_update(
            &store,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
              <https://mlipe.2mia.org/teams/materials> a mlipe:Team ; mlipe:teamName "materials" ;
                  mlipe:hasParentTeam <https://mlipe.2mia.org/teams/root> .
              <https://mlipe.2mia.org/users/alice> a mlipe:User ; mlipe:username "alice" .
            }"#,
        )
        .unwrap();
        let existing_users: HashSet<String> = ["alice".to_string()].into_iter().collect();
        let r = apply_teams_import(&store, &bundle, &[], &HashSet::new(), &existing_users, 2)
            .unwrap();
        assert_eq!(r.created_count, 1, "only the sub-team was created");
        let mat = r.rows.iter().find(|x| x.target_path == "materials").unwrap();
        assert!(mat.failed.as_deref().unwrap_or("").contains("already exists"));
        assert!(mat.linked_admins.is_empty());
        assert!(
            !team_has_role(
                &store,
                "https://mlipe.2mia.org/teams/materials",
                "hasAdmin",
                "https://mlipe.2mia.org/users/alice"
            ),
            "no role may be granted on a team the import did not create"
        );
        let sub = r.rows.iter().find(|x| x.target_path == "materials/sub").unwrap();
        assert!(sub.failed.is_none());
        assert_eq!(sub.linked_admins, vec!["alice"]);
    }

    /// `static` is refused directly under the root team (the router serves
    /// `/static`), with the bundle as a whole; deeper it is an ordinary name.
    #[test]
    fn teams_import_refuses_reserved_root_level_name() {
        let users: HashSet<String> = HashSet::new();
        let at_root = TeamsBundle::new(2, "static".into(), vec![team_record("static", "static")]);
        assert!(plan_teams_import(&at_root, &[], &HashSet::new(), &users, 2).is_err());
        // The same bundle re-parented under "org" is fine …
        let under_org = ["org".to_string()];
        assert!(plan_teams_import(&at_root, &under_org, &HashSet::new(), &users, 2).is_ok());
        // … and so is a nested `static`.
        let nested = TeamsBundle::new(
            2,
            "materials".into(),
            vec![team_record("materials", "materials"), team_record("materials/static", "static")],
        );
        assert!(plan_teams_import(&nested, &[], &HashSet::new(), &users, 2).is_ok());
    }

    /// Valid names with every admitted character import and come back the
    /// same, through the model API, and are reachable by path.
    #[test]
    fn teams_import_accepts_every_admitted_character() {
        let store = Store::new().unwrap();
        sparql_update(
            &store,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
            }"#,
        )
        .unwrap();
        let name = "Az09_-.x";
        let bundle = TeamsBundle::new(
            2,
            name.into(),
            vec![
                team_record(name, name),
                team_record(&format!("{name}/sub.1"), "sub.1"),
            ],
        );
        let r =
            apply_teams_import(&store, &bundle, &[], &HashSet::new(), &HashSet::new(), 2).unwrap();
        assert_eq!(r.created_count, 2);
        let sub =
            auth::resolve_team_path(&store, &[name.to_string(), "sub.1".to_string()]).unwrap();
        assert_eq!(sub, format!("<{TEAM_IRI_PREFIX}{name}/sub.1>"));
        let after = export_teams(&store, &format!("{TEAM_IRI_PREFIX}{name}"));
        assert_eq!(after.teams.len(), 2);
        assert_eq!(after.teams[0].name, name);
    }
}
