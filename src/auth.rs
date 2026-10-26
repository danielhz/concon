use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use oxigraph::model::{
    GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode, Quad, QuadRef, Term, TermRef,
};
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use crate::store::{MLIPE_NS, is_valid_name_segment, sparql_query};

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

/// How long a login session stays valid, counted from login. The server
/// enforces this in [`SessionStore::get_session`]; the login handler sets the
/// same value as the cookie's `Max-Age` so browser and server agree.
pub const SESSION_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone)]
pub struct Session {
    pub username: String,
    pub user_iri: String,
    /// When the session was created; sessions older than the store's max age
    /// are rejected and dropped.
    pub created_at: Instant,
}

pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
    max_age: Duration,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self::with_max_age(SESSION_MAX_AGE)
    }

    /// A store whose sessions expire `max_age` after creation.
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_age,
        }
    }

    /// The configured session lifetime.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    fn is_expired(&self, session: &Session) -> bool {
        session.created_at.elapsed() >= self.max_age
    }

    pub fn create_session(&self, username: String, user_iri: String) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            username,
            user_iri,
            created_at: Instant::now(),
        };
        let mut sessions = self.sessions.write().unwrap();
        // Sweep expired sessions so ids that were never presented again do not
        // accumulate for the life of the process.
        sessions.retain(|_, s| !self.is_expired(s));
        sessions.insert(session_id.clone(), session);
        session_id
    }

    /// Look up a session; an expired session is treated as absent and removed.
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let session = self.sessions.read().unwrap().get(session_id).cloned()?;
        if self.is_expired(&session) {
            self.sessions.write().unwrap().remove(session_id);
            return None;
        }
        Some(session)
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

/// IRI prefix under which user IRIs are minted: `<USER_IRI_PREFIX><username>`.
pub const USER_IRI_PREFIX: &str = "https://mlipe.2mia.org/users/";
/// Upper bound on a username's length, in bytes.
pub const MAX_USERNAME_LEN: usize = 128;
/// IRI prefix under which team IRIs are minted: `<TEAM_IRI_PREFIX><path>`,
/// where `<path>` is the team's `/`-joined name path from the root team
/// (`materials/atomistic`); the root team itself is [`ROOT_TEAM_IRI`].
pub const TEAM_IRI_PREFIX: &str = "https://mlipe.2mia.org/teams/";
/// Well-known root team IRI (created by the first-run seed).
pub const ROOT_TEAM_IRI: &str = "https://mlipe.2mia.org/teams/root";

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// Whether `u` is a well-formed username. A username becomes the last path
/// segment of the user IRI, a literal value in the system store, a URL path
/// segment (`/_users/{username}`) and a Turtle literal in the first-run seed,
/// so the allow-list is deliberately small — the username counterpart of
/// `store::is_valid_name_segment` for dataset names: ASCII letters, digits,
/// `_`, `-`, `.` and `@` (the deployed accounts are email-style, e.g.
/// `first.last@example.org`); no leading `.`; at most `MAX_USERNAME_LEN`
/// bytes. None of these characters needs escaping in an IRI path, a SPARQL or
/// Turtle literal, or a URL path.
///
/// Enforced on every path that *creates* a user (admin form, first-run seed,
/// users import, maintenance binaries). Lookups deliberately do not enforce
/// it: they match the username as a literal *value* through the model API, so
/// an account that predates the rule keeps logging in. [`invalid_usernames`]
/// reports such accounts.
pub fn is_valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= MAX_USERNAME_LEN
        && !u.starts_with('.')
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'))
}

/// Whether `name` is a well-formed team name. A team name is one segment of
/// the team path: it becomes a URL path segment (`/materials/atomistic`), part
/// of the team IRI, a prefix of its datasets' qualified names, a file-catalog
/// directory on disk and a `mlipe:teamName` literal, so it follows the dataset
/// segment rule (`store::is_valid_name_segment`: ASCII letters, digits, `_`,
/// `-`, `.`; no leading `.`; length-capped) and additionally may not start
/// with `_`, which the URL space reserves for views and actions (`_files`,
/// `_new_team`, …) — a team named `_x` could never be addressed. None of the
/// admitted characters needs escaping in an IRI, a SPARQL or Turtle literal,
/// or a URL path.
///
/// Enforced on every path that *creates* a team (sub-team form, teams
/// import) and on every lookup by path ([`resolve_team_path`]): a URL
/// segment that is not a valid team name is "not found" before the store is
/// consulted. [`invalid_team_names`] reports stored teams that predate the
/// rule, which are therefore unreachable by URL until renamed.
pub fn is_valid_team_name(name: &str) -> bool {
    is_valid_name_segment(name) && !name.starts_with('_')
}

/// Names a team directly under the root team may not take, because the
/// router serves that top-level path itself (`/static` is the asset
/// directory): such a team would be created but shadowed. The names are
/// valid team names elsewhere (`materials/static` is fine), so this is checked
/// by [`create_team`] and the teams import, not by [`is_valid_team_name`].
pub const RESERVED_ROOT_TEAM_NAMES: [&str; 1] = ["static"];

/// Whether `name` is reserved for a team directly under the root team
/// ([`RESERVED_ROOT_TEAM_NAMES`]).
pub fn is_reserved_root_team_name(name: &str) -> bool {
    RESERVED_ROOT_TEAM_NAMES.contains(&name)
}

/// Why [`create_team`] refused or failed; the HTTP layer maps the variants
/// to 400, 409 and 500.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateTeamError {
    /// The name does not pass [`is_valid_team_name`] (or is reserved at the
    /// root level), or the parent IRI is not a team IRI.
    Invalid(String),
    /// A team with that name already exists under the parent, or the IRI the
    /// team would get is already in use.
    Exists(String),
    /// The store failed (transaction, write).
    Store(String),
}

impl std::fmt::Display for CreateTeamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Exists(m) | Self::Store(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CreateTeamError {}

/// The user IRI for `username`, minted under [`USER_IRI_PREFIX`]. Fails unless
/// the username passes [`is_valid_username`], so the IRI is always well-formed.
pub fn user_iri_for(username: &str) -> Result<NamedNode, String> {
    if !is_valid_username(username) {
        return Err(format!("Invalid username '{username}'"));
    }
    NamedNode::new(format!("{USER_IRI_PREFIX}{username}")).map_err(|e| e.to_string())
}

/// A `mlipe:` vocabulary term. The namespace is a constant valid IRI, so the
/// result is always well-formed.
fn mlipe(local: &str) -> NamedNode {
    NamedNode::new_unchecked(format!("{MLIPE_NS}{local}"))
}

/// Every node whose `mlipe:username` is exactly `username`. Model-API lookup:
/// the username is matched as a literal value and never reaches query text.
fn user_nodes(store: &Store, username: &str) -> Vec<NamedOrBlankNode> {
    let p_username = mlipe("username");
    let name = Literal::new_simple_literal(username);
    store
        .quads_for_pattern(
            None,
            Some(p_username.as_ref()),
            Some(TermRef::from(name.as_ref())),
            None,
        )
        .filter_map(|q| q.ok().map(|q| q.subject))
        .collect()
}

/// The lexical value of a literal term (any other term: its display form).
/// Unlike `strip_literal(term.to_string())`, this returns the stored value
/// itself, so a legacy username holding `"` or `\` comes back unescaped.
fn literal_value(term: &Term) -> String {
    match term {
        Term::Literal(l) => l.value().to_string(),
        other => other.to_string(),
    }
}

/// The first literal object of `(subject, predicate, ?)`, as its lexical value.
fn literal_object(
    store: &Store,
    subject: &NamedOrBlankNode,
    predicate: &NamedNode,
) -> Option<String> {
    store
        .quads_for_pattern(Some(subject.as_ref()), Some(predicate.as_ref()), None, None)
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

/// The stored node carrying `mlipe:username = username`, in its `<…>` display
/// form, whether or not the user has a password hash (an account with no
/// hash exists but cannot log in). Model-API literal match, like
/// [`find_user_by_username`].
pub fn find_user_iri(store: &Store, username: &str) -> Option<String> {
    user_nodes(store, username)
        .into_iter()
        .next()
        .map(|u| u.to_string())
}

/// Find a user by username in the system store.
/// Returns (user_iri, password_hash) if found — the IRI in its `<…>` display
/// form. The username is only ever a literal value here (no SPARQL text is
/// built), so any string is safe to look up; it either matches a stored
/// `mlipe:username` exactly or finds nothing.
pub fn find_user_by_username(store: &Store, username: &str) -> Option<(String, String)> {
    let p_hash = mlipe("passwordHash");
    user_nodes(store, username).into_iter().find_map(|user| {
        let hash = literal_object(store, &user, &p_hash)?;
        Some((user.to_string(), hash))
    })
}

/// Update the password hash for a user in the system store (model API; the
/// hash replaces any existing `mlipe:passwordHash` of the user).
pub fn update_password_hash(store: &Store, user_iri: &str, new_hash: &str) -> Result<(), String> {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let user = NamedNode::new(iri).map_err(|e| format!("Invalid user IRI: {e}"))?;
    let p_hash = mlipe("passwordHash");
    // One transaction: the old hash(es) and the new one swap atomically.
    let mut tx = store.start_transaction().map_err(|e| e.to_string())?;
    let old: Vec<Quad> = tx
        .quads_for_pattern(
            Some(user.as_ref().into()),
            Some(p_hash.as_ref()),
            None,
            None,
        )
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for q in &old {
        tx.remove(q);
    }
    let hash = Literal::new_simple_literal(new_hash);
    tx.insert(QuadRef::new(
        &user,
        &p_hash,
        &hash,
        GraphNameRef::DefaultGraph,
    ));
    tx.commit().map_err(|e| e.to_string())
}

/// Create a user: `<user> a mlipe:User ; mlipe:username ; mlipe:passwordHash`
/// (an argon2 PHC string), enrolled as `mlipe:hasMember` of `member_of` when
/// given (normally the root team). The one creation path shared by the admin
/// form, the users import and the maintenance binaries. Validates the
/// username ([`is_valid_username`]), refuses a username already in use, and
/// writes through the model API in one transaction, so neither the username
/// nor the hash ever reaches SPARQL text and a user is never half-written.
/// Returns the new user's IRI.
pub fn create_user(
    store: &Store,
    username: &str,
    password_hash: &str,
    member_of: Option<&str>,
) -> Result<NamedNode, String> {
    let user = user_iri_for(username)?;
    let team = member_of
        .map(|t| {
            NamedNode::new(t.trim_matches(|c| c == '<' || c == '>'))
                .map_err(|e| format!("Invalid team IRI: {e}"))
        })
        .transpose()?;
    let rdf_type = NamedNodeRef::new_unchecked(RDF_TYPE);
    let (c_user, p_username, p_hash, p_member) = (
        mlipe("User"),
        mlipe("username"),
        mlipe("passwordHash"),
        mlipe("hasMember"),
    );
    let name = Literal::new_simple_literal(username);
    let hash = Literal::new_simple_literal(password_hash);
    let g = GraphNameRef::DefaultGraph;
    let mut tx = store.start_transaction().map_err(|e| e.to_string())?;
    // The existence check runs inside the transaction, on the same snapshot
    // the writes land on.
    let taken = tx
        .quads_for_pattern(
            None,
            Some(p_username.as_ref()),
            Some(TermRef::from(name.as_ref())),
            None,
        )
        .next()
        .is_some();
    if taken {
        return Err(format!("User '{username}' already exists"));
    }
    tx.insert(QuadRef::new(&user, rdf_type, &c_user, g));
    tx.insert(QuadRef::new(&user, &p_username, &name, g));
    tx.insert(QuadRef::new(&user, &p_hash, &hash, g));
    if let Some(team) = &team {
        tx.insert(QuadRef::new(team, &p_member, &user, g));
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(user)
}

/// Delete a user: every system-store quad with the user as subject (its
/// profile) or as object (team memberships and admin roles), in one
/// transaction. Model API only.
pub fn delete_user(store: &Store, user_iri: &str) -> Result<(), String> {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let user = NamedNode::new(iri).map_err(|e| format!("Invalid user IRI: {e}"))?;
    let mut tx = store.start_transaction().map_err(|e| e.to_string())?;
    let as_subject = tx.quads_for_pattern(Some(user.as_ref().into()), None, None, None);
    let as_object = tx.quads_for_pattern(None, None, Some(user.as_ref().into()), None);
    let quads: Vec<Quad> = as_subject
        .chain(as_object)
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for q in &quads {
        tx.remove(q);
    }
    tx.commit().map_err(|e| e.to_string())
}

/// Stored usernames that do not pass [`is_valid_username`] — accounts created
/// before the rule existed. They can still log in (lookups treat the username
/// as data), but cannot be re-created or imported as they are; the operator
/// should rename them. Sorted, deduplicated. Reported at startup.
pub fn invalid_usernames(store: &Store) -> Vec<String> {
    let p_username = mlipe("username");
    let mut names: Vec<String> = store
        .quads_for_pattern(None, Some(p_username.as_ref()), None, None)
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .filter(|n| !is_valid_username(n))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Create a sub-team `name` under the team `parent_iri`: `<team> a
/// mlipe:Team ; mlipe:teamName "<name>" ; mlipe:hasParentTeam <parent>`. The
/// one creation path shared by the sub-team form and the teams import. The
/// team IRI is minted from the parent's path (`<TEAM_IRI_PREFIX><name>` under
/// the root team, `<parent>/<name>` elsewhere), so it stays the `/`-joined
/// name path. Validates the name ([`is_valid_team_name`]), refuses a name
/// already used under the same parent or an IRI already in use (this also
/// keeps `root` from being re-minted under the root team), and writes through
/// the model API in one transaction, so the name never reaches SPARQL text
/// and a team is never half-written. Directly under the root team the
/// [`RESERVED_ROOT_TEAM_NAMES`] are refused as invalid. Returns the new
/// team's IRI.
pub fn create_team(
    store: &Store,
    parent_iri: &str,
    name: &str,
) -> Result<NamedNode, CreateTeamError> {
    use CreateTeamError::{Exists, Invalid, Store as StoreErr};
    if !is_valid_team_name(name) {
        return Err(Invalid(format!("Invalid team name '{name}'")));
    }
    let parent_iri = parent_iri.trim_matches(|c| c == '<' || c == '>');
    let parent = NamedNode::new(parent_iri)
        .map_err(|e| Invalid(format!("Invalid parent team IRI: {e}")))?;
    let team_iri = if parent_iri == ROOT_TEAM_IRI {
        if is_reserved_root_team_name(name) {
            return Err(Invalid(format!(
                "Team name '{name}' is reserved at the root level (/{name} is served by the site)"
            )));
        }
        format!("{TEAM_IRI_PREFIX}{name}")
    } else if parent_iri.starts_with(TEAM_IRI_PREFIX) {
        format!("{parent_iri}/{name}")
    } else {
        return Err(Invalid(format!(
            "Parent team IRI '{parent_iri}' is not under {TEAM_IRI_PREFIX}"
        )));
    };
    let team = NamedNode::new(team_iri).map_err(|e| Invalid(e.to_string()))?;
    let rdf_type = NamedNodeRef::new_unchecked(RDF_TYPE);
    let (c_team, p_name, p_parent) = (mlipe("Team"), mlipe("teamName"), mlipe("hasParentTeam"));
    let name_lit = Literal::new_simple_literal(name);
    let g = GraphNameRef::DefaultGraph;
    let mut tx = store
        .start_transaction()
        .map_err(|e| StoreErr(e.to_string()))?;
    // Both existence checks run inside the transaction, on the same snapshot
    // the writes land on.
    let iri_taken = tx
        .quads_for_pattern(Some(team.as_ref().into()), None, None, None)
        .next()
        .is_some();
    let name_taken = tx
        .quads_for_pattern(
            None,
            Some(p_name.as_ref()),
            Some(TermRef::from(name_lit.as_ref())),
            None,
        )
        .filter_map(Result::ok)
        .any(|q| {
            tx.contains(QuadRef::new(
                q.subject.as_ref(),
                p_parent.as_ref(),
                parent.as_ref(),
                g,
            ))
            .unwrap_or(false)
        });
    if iri_taken || name_taken {
        return Err(Exists(format!("Team '{name}' already exists here")));
    }
    tx.insert(QuadRef::new(&team, rdf_type, &c_team, g));
    tx.insert(QuadRef::new(&team, &p_name, &name_lit, g));
    tx.insert(QuadRef::new(&team, &p_parent, &parent, g));
    tx.commit().map_err(|e| StoreErr(e.to_string()))?;
    Ok(team)
}

/// Stored team names that do not pass [`is_valid_team_name`] — teams created
/// before the rule existed. Such a team cannot be reached by URL (its path
/// segment is rejected before lookup), re-created or imported as it is; the
/// operator should rename it. Sorted, deduplicated. Reported at startup.
pub fn invalid_team_names(store: &Store) -> Vec<String> {
    let p_name = mlipe("teamName");
    let mut names: Vec<String> = store
        .quads_for_pattern(None, Some(p_name.as_ref()), None, None)
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .filter(|n| !is_valid_team_name(n))
        .collect();
    names.sort();
    names.dedup();
    names
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
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, query) {
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

/// Whether a dataset (by its qualified `datasetName`, e.g. "mlips/mlips") has
/// `mlipe:hasVisibility = PublicVisibility`. Used for the anonymous-read gate.
/// Resolved by membership in `get_public_datasets` so the URL-derived name is
/// never interpolated into SPARQL (no injection).
pub fn is_dataset_public(store: &Store, name: &str) -> bool {
    get_public_datasets(store).iter().any(|d| d.name == name)
}

/// Verify HTTP Basic credentials from an `Authorization` header against the
/// user store. Returns the authenticated user's IRI (e.g. `<https://…/users/x>`)
/// on success. Used to authenticate the non-interactive ingest loader.
pub fn authenticate_basic(store: &Store, authorization: Option<&str>) -> Option<String> {
    use base64::Engine;
    let value = authorization?;
    let b64 = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (username, password) = creds.split_once(':')?;
    let (user_iri, hash) = find_user_by_username(store, username)?;
    if verify_password(password, &hash) {
        Some(user_iri)
    } else {
        None
    }
}

/// Whether `user_iri` may write (publish/ingest/update) `dataset_name`.
/// Minimal write-authorization (the rest of the role matrix is Epic B4):
/// root-team admins may write any dataset; otherwise the user must be an admin
/// (`mlipe:hasAdmin`) of the dataset's owning team. The dataset name is escaped
/// before interpolation.
pub fn can_write_dataset(store: &Store, user_iri: &str, dataset_name: &str) -> bool {
    if is_root_admin(store, user_iri) {
        return true;
    }
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let name = dataset_name.replace('\\', r"\\").replace('"', r#"\""#);
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        ASK {{
            ?team mlipe:ownsDataset ?ds ;
                  mlipe:hasAdmin <{iri}> .
            ?ds mlipe:datasetName "{name}" .
        }}
        "#,
    );
    matches!(sparql_query(store, &query), Ok(QueryResults::Boolean(true)))
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
    sparql_query(store, &query)
        .ok()
        .and_then(|r| match r {
            QueryResults::Boolean(b) => Some(b),
            _ => None,
        })
        .unwrap_or(false)
}

/// Whether `user_iri` is a direct admin (`mlipe:hasAdmin`) of `team_iri`.
/// Model-API lookup — neither IRI is interpolated into SPARQL text.
pub fn is_team_admin(store: &Store, user_iri: &str, team_iri: &str) -> bool {
    let strip = |s: &str| s.trim_matches(|c| c == '<' || c == '>').to_string();
    let (Ok(team), Ok(user), Ok(has_admin)) = (
        NamedNode::new(strip(team_iri)),
        NamedNode::new(strip(user_iri)),
        NamedNode::new(format!("{MLIPE_NS}hasAdmin")),
    ) else {
        return false;
    };
    store
        .quads_for_pattern(
            Some(team.as_ref().into()),
            Some(has_admin.as_ref()),
            Some(user.as_ref().into()),
            None,
        )
        .next()
        .is_some_and(|q| q.is_ok())
}

/// Whether `user_iri` may create a dataset owned by `team_iri`: root-team
/// admins may create anywhere; otherwise the user must be an admin of that
/// team. (The pre-creation counterpart of `can_write_dataset`, which needs the
/// dataset's metadata to exist.)
pub fn can_create_dataset_in_team(store: &Store, user_iri: &str, team_iri: &str) -> bool {
    is_root_admin(store, user_iri) || is_team_admin(store, user_iri, team_iri)
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
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, query) {
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
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            if let (Some(iri), Some(name)) = (solution.get("team"), solution.get("name")) {
                teams.push(TeamInfo {
                    iri: iri.to_string(),
                    name: literal_value(name),
                });
            }
        }
    }
    teams
}

/// User info for display purposes.
#[derive(Clone)]
pub struct UserInfo {
    pub username: String,
    pub iri: String,
    pub teams: Vec<TeamInfo>,
}

/// List all users in the system store.
pub fn list_all_users(store: &Store) -> Vec<UserInfo> {
    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user ?username WHERE {
            ?user a mlipe:User ;
                  mlipe:username ?username .
        }
        ORDER BY ?username
    "#;

    let mut users = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, query) {
        for solution in solutions.flatten() {
            if let (Some(user), Some(username)) = (solution.get("user"), solution.get("username")) {
                let iri = user.to_string();
                let username = literal_value(username);
                let teams = get_user_member_teams(store, &iri);
                users.push(UserInfo {
                    username,
                    iri,
                    teams,
                });
            }
        }
    }
    users
}

/// Get teams where the user is a member.
pub fn get_user_member_teams(store: &Store, user_iri: &str) -> Vec<TeamInfo> {
    let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team ?name WHERE {{
            ?team a mlipe:Team ;
                  mlipe:teamName ?name ;
                  mlipe:hasMember <{iri}> .
        }}
        "#,
    );

    let mut teams = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            if let (Some(iri), Some(name)) = (solution.get("team"), solution.get("name")) {
                teams.push(TeamInfo {
                    iri: iri.to_string(),
                    name: literal_value(name),
                });
            }
        }
    }
    teams
}

/// Get user info by username.
pub fn get_user_info(store: &Store, username: &str) -> Option<UserInfo> {
    let (iri, _) = find_user_by_username(store, username)?;
    let teams = get_user_member_teams(store, &iri);
    Some(UserInfo {
        username: username.to_string(),
        iri,
        teams,
    })
}

/// Get datasets owned by a team.
pub fn get_team_datasets(store: &Store, team_iri: &str) -> Vec<DatasetInfo> {
    let iri = team_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?name WHERE {{
            <{iri}> mlipe:ownsDataset ?ds .
            ?ds mlipe:datasetName ?name .
        }}
        "#,
    );
    query_dataset_names(store, &query)
}

/// File action types for permission checking.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileAction {
    Read,
    Write,
    Delete,
}

/// Check if a user can perform a file action on a team's files.
///
/// Permission model:
/// - Team admins: all actions (Read, Write, Delete)
/// - Team members: Read + Write
/// - Explicit role grants via mlipe:permitsAction
/// - Monotonic: access on a parent team implies access on child teams
pub fn can_access_files(store: &Store, user_iri: &str, team_iri: &str, action: FileAction) -> bool {
    let user_clean = user_iri.trim_matches(|c| c == '<' || c == '>');

    // Walk up the team hierarchy (monotonic permissions)
    let mut current_team = team_iri.trim_matches(|c| c == '<' || c == '>').to_string();

    loop {
        // Check admin
        let admin_query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            ASK {{ <{current_team}> mlipe:hasAdmin <{user_clean}> }}
            "#,
        );
        if let Ok(QueryResults::Boolean(true)) = sparql_query(store, &admin_query) {
            return true; // Admins can do anything
        }

        // Check member (Read + Write)
        if action != FileAction::Delete {
            let member_query = format!(
                r#"
                PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                ASK {{ <{current_team}> mlipe:hasMember <{user_clean}> }}
                "#,
            );
            if let Ok(QueryResults::Boolean(true)) = sparql_query(store, &member_query) {
                return true;
            }
        }

        // Check explicit role grants
        let action_iri = match action {
            FileAction::Read => "mlipe:FileReadAction",
            FileAction::Write => "mlipe:FileWriteAction",
            FileAction::Delete => "mlipe:FileDeleteAction",
        };
        let role_query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            ASK {{
                <{user_clean}> mlipe:hasRole ?role .
                ?role mlipe:roleInTeam <{current_team}> ;
                      mlipe:permitsAction {action_iri} .
            }}
            "#,
        );
        if let Ok(QueryResults::Boolean(true)) = sparql_query(store, &role_query) {
            return true;
        }

        // Walk up to parent team
        let parent_query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            SELECT ?parent WHERE {{
                <{current_team}> mlipe:hasParentTeam ?parent .
            }}
            LIMIT 1
            "#,
        );

        let mut parent = None;
        if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &parent_query) {
            for solution in solutions.flatten() {
                parent = solution.get("parent").map(|v| {
                    v.to_string()
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string()
                });
            }
        }

        match parent {
            Some(p) => current_team = p,
            None => break, // Reached root, no access
        }
    }

    false
}

/// Get members of a team by team IRI.
/// Check if a user can see a team.
///
/// Rules (monotonic):
/// - Root admins: can see all teams
/// - User is member or admin of the team: can see it
/// - User is member or admin of any ancestor team: can see it
pub fn can_see_team(store: &Store, user_iri: &str, team_iri: &str) -> bool {
    if is_root_admin(store, user_iri) {
        return true;
    }

    let user_clean = user_iri.trim_matches(|c| c == '<' || c == '>');
    let mut current_team = team_iri.trim_matches(|c| c == '<' || c == '>').to_string();

    loop {
        // Check member
        let member_query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            ASK {{ <{current_team}> mlipe:hasMember <{user_clean}> }}
            "#,
        );
        if let Ok(QueryResults::Boolean(true)) = sparql_query(store, &member_query) {
            return true;
        }

        // Check admin
        let admin_query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            ASK {{ <{current_team}> mlipe:hasAdmin <{user_clean}> }}
            "#,
        );
        if let Ok(QueryResults::Boolean(true)) = sparql_query(store, &admin_query) {
            return true;
        }

        // Walk up to parent team
        let parent_query = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            SELECT ?parent WHERE {{
                <{current_team}> mlipe:hasParentTeam ?parent .
            }}
            LIMIT 1
            "#,
        );

        let mut parent = None;
        if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &parent_query) {
            for solution in solutions.flatten() {
                parent = solution.get("parent").map(|v| {
                    v.to_string()
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string()
                });
            }
        }

        match parent {
            Some(p) => current_team = p,
            None => break,
        }
    }

    false
}

/// Filter sub-teams by visibility for a user.
pub fn get_visible_sub_teams(
    store: &Store,
    user_iri: &str,
    parent_segments: &[String],
) -> Vec<TeamInfo> {
    let all = get_sub_teams(store, parent_segments);
    if is_root_admin(store, user_iri) {
        return all;
    }
    all.into_iter()
        .filter(|t| {
            let iri = t.iri.trim_matches(|c| c == '<' || c == '>');
            can_see_team(store, user_iri, iri)
        })
        .collect()
}

/// Get members of a team and all its sub-teams recursively.
/// Deduplicates by username.
pub fn get_team_members_recursive(store: &Store, team_iri: &str) -> Vec<UserInfo> {
    let iri = team_iri.trim_matches(|c| c == '<' || c == '>');
    // Use a SPARQL property path to find all descendant teams
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT DISTINCT ?user ?username WHERE {{
            {{
                <{iri}> mlipe:hasMember ?user .
            }} UNION {{
                ?subteam mlipe:hasParentTeam+ <{iri}> .
                ?subteam mlipe:hasMember ?user .
            }}
            ?user mlipe:username ?username .
        }}
        ORDER BY ?username
        "#,
    );

    let mut users = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            if let (Some(user), Some(username)) = (solution.get("user"), solution.get("username")) {
                users.push(UserInfo {
                    username: literal_value(username),
                    iri: user.to_string(),
                    teams: Vec::new(),
                });
            }
        }
    }
    users
}

pub fn get_team_members(store: &Store, team_iri: &str) -> Vec<UserInfo> {
    let iri = team_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?user ?username WHERE {{
            <{iri}> mlipe:hasMember ?user .
            ?user mlipe:username ?username .
        }}
        ORDER BY ?username
        "#,
    );

    let mut users = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            if let (Some(user), Some(username)) = (solution.get("user"), solution.get("username")) {
                users.push(UserInfo {
                    username: literal_value(username),
                    iri: user.to_string(),
                    teams: Vec::new(),
                });
            }
        }
    }
    users
}

/// Resolve a team path (e.g., `["materials", "atomistic"]`) to a team IRI in
/// its `<…>` display form, walking the hierarchy root → materials →
/// atomistic by `mlipe:teamName` + `mlipe:hasParentTeam`. Returns `None` if
/// any segment does not resolve — and, before the store is consulted, if any
/// segment is not a valid team name ([`is_valid_team_name`]): a URL segment
/// that could not name a team is simply not found. Each segment is matched as
/// a literal *value* through the model API; no query text is built from it.
pub fn resolve_team_path(store: &Store, segments: &[String]) -> Option<String> {
    if !segments.iter().all(|s| is_valid_team_name(s)) {
        return None;
    }
    let mut current = root_team(store)?;
    for segment in segments {
        current = child_team_named(store, &current, segment)?;
    }
    Some(current.to_string())
}

/// The root team: the one `mlipe:Team` without a `mlipe:hasParentTeam`.
fn root_team(store: &Store) -> Option<NamedOrBlankNode> {
    let root_query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team WHERE {
            ?team a mlipe:Team .
            FILTER NOT EXISTS { ?team mlipe:hasParentTeam ?parent }
        }
        LIMIT 1
    "#;
    let QueryResults::Solutions(solutions) = sparql_query(store, root_query).ok()? else {
        return None;
    };
    solutions.flatten().find_map(|sol| match sol.get("team") {
        Some(Term::NamedNode(n)) => Some(NamedOrBlankNode::from(n.clone())),
        Some(Term::BlankNode(b)) => Some(NamedOrBlankNode::from(b.clone())),
        _ => None,
    })
}

/// The `mlipe:Team` whose `mlipe:teamName` is exactly `name` and whose
/// `mlipe:hasParentTeam` is `parent`. Model-API lookup: the name is a literal
/// value, never query text.
fn child_team_named(
    store: &Store,
    parent: &NamedOrBlankNode,
    name: &str,
) -> Option<NamedOrBlankNode> {
    let rdf_type = NamedNodeRef::new_unchecked(RDF_TYPE);
    let (c_team, p_name, p_parent) = (mlipe("Team"), mlipe("teamName"), mlipe("hasParentTeam"));
    let name_lit = Literal::new_simple_literal(name);
    let g = GraphNameRef::DefaultGraph;
    store
        .quads_for_pattern(
            None,
            Some(p_name.as_ref()),
            Some(TermRef::from(name_lit.as_ref())),
            None,
        )
        .filter_map(Result::ok)
        .map(|q| q.subject)
        .find(|team| {
            let parent_term = TermRef::from(parent.as_ref());
            store
                .contains(QuadRef::new(
                    team.as_ref(),
                    p_parent.as_ref(),
                    parent_term,
                    g,
                ))
                .unwrap_or(false)
                && store
                    .contains(QuadRef::new(team.as_ref(), rdf_type, c_team.as_ref(), g))
                    .unwrap_or(false)
        })
}

/// Get direct sub-teams of a team identified by path segments.
pub fn get_sub_teams(store: &Store, parent_segments: &[String]) -> Vec<TeamInfo> {
    let parent_iri = if parent_segments.is_empty() {
        // Root team
        match resolve_team_path(store, &[]) {
            Some(iri) => iri,
            None => return Vec::new(),
        }
    } else {
        match resolve_team_path(store, parent_segments) {
            Some(iri) => iri,
            None => return Vec::new(),
        }
    };

    let parent_clean = parent_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?team ?name WHERE {{
            ?team a mlipe:Team ;
                  mlipe:teamName ?name ;
                  mlipe:hasParentTeam <{parent_clean}> .
        }}
        ORDER BY ?name
        "#,
    );

    let mut teams = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            if let (Some(iri), Some(name)) = (solution.get("team"), solution.get("name")) {
                teams.push(TeamInfo {
                    iri: iri.to_string(),
                    name: literal_value(name),
                });
            }
        }
    }
    teams
}

/// Get datasets owned by a team and all its sub-teams, identified by path segments.
/// Uses the dataset name prefix to match (e.g., "MetaLearn/" matches all
/// datasets under MetaLearn and its sub-teams).
pub fn get_team_datasets_by_path(store: &Store, team_segments: &[String]) -> Vec<DatasetInfo> {
    let prefix = if team_segments.is_empty() {
        // Root team: return all datasets
        String::new()
    } else {
        format!("{}/", team_segments.join("/"))
    };

    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?name WHERE {
            ?ds a mlipe:Dataset ;
                mlipe:datasetName ?name .
        }
        ORDER BY ?name
    "#;

    let mut datasets = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, query) {
        for solution in solutions.flatten() {
            if let Some(name) = solution.get("name") {
                let name = strip_literal(&name.to_string());
                if prefix.is_empty() || name.starts_with(&prefix) {
                    datasets.push(DatasetInfo { name });
                }
            }
        }
    }
    datasets
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

    /// A session older than the store's max age is rejected server-side, even
    /// if the client still presents its id.
    #[test]
    fn test_session_expires_after_max_age() {
        let store = SessionStore::with_max_age(std::time::Duration::from_millis(20));
        let sid = store.create_session("alice".into(), "http://example.org/alice".into());
        assert!(store.get_session(&sid).is_some());
        std::thread::sleep(std::time::Duration::from_millis(40));
        assert!(store.get_session(&sid).is_none());
        // Still absent on a second lookup (it was dropped, not just hidden).
        assert!(store.get_session(&sid).is_none());
    }

    /// Creating a session sweeps expired ones from the store.
    #[test]
    fn test_create_session_sweeps_expired() {
        let store = SessionStore::with_max_age(std::time::Duration::from_millis(20));
        let old = store.create_session("alice".into(), "http://example.org/alice".into());
        std::thread::sleep(std::time::Duration::from_millis(40));
        let fresh = store.create_session("bob".into(), "http://example.org/bob".into());
        assert_eq!(store.sessions.read().unwrap().len(), 1);
        assert!(store.get_session(&old).is_none());
        assert_eq!(store.get_session(&fresh).unwrap().username, "bob");
    }

    #[test]
    fn test_strip_literal() {
        assert_eq!(strip_literal(r#""hello""#), "hello");
        assert_eq!(
            strip_literal(r#""hello"^^<http://www.w3.org/2001/XMLSchema#string>"#),
            "hello"
        );
    }

    /// Insert a user straight through the model API, bypassing validation —
    /// stands in for an account created before the username rule existed.
    fn insert_legacy_user(store: &Store, iri: &str, username: &str, password: &str) {
        let user = NamedNode::new(iri).unwrap();
        let name = Literal::new_simple_literal(username);
        let hash = Literal::new_simple_literal(hash_password(password));
        let (p_name, p_hash) = (mlipe("username"), mlipe("passwordHash"));
        let g = GraphNameRef::DefaultGraph;
        let rdf_type = NamedNodeRef::new_unchecked(RDF_TYPE);
        store
            .insert(QuadRef::new(&user, rdf_type, &mlipe("User"), g))
            .unwrap();
        store
            .insert(QuadRef::new(&user, &p_name, &name, g))
            .unwrap();
        store
            .insert(QuadRef::new(&user, &p_hash, &hash, g))
            .unwrap();
    }

    fn basic(username: &str, password: &str) -> String {
        use base64::Engine;
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        format!("Basic {creds}")
    }

    #[test]
    fn username_rule_allow_list() {
        for ok in [
            "alice",
            "a.b-c_1",
            "first.last@example.org",
            "st154713@stud.uni-stuttgart.de",
            "A1",
        ] {
            assert!(is_valid_username(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            ".hidden",
            "a/b",
            "a b",
            "a\"b",
            "a\\b",
            "a'b",
            "a}b",
            "a<b",
            "a\nb",
            "ä",
            "a:b",
            "\"} ?u mlipe:username ?n . {\"",
        ] {
            assert!(!is_valid_username(bad), "{bad:?} should be invalid");
        }
        let max = "a".repeat(MAX_USERNAME_LEN);
        assert!(is_valid_username(&max));
        assert!(!is_valid_username(&format!("{max}a")));
        assert!(user_iri_for("a/b").is_err());
        assert_eq!(
            user_iri_for("first.last@example.org").unwrap().as_str(),
            "https://mlipe.2mia.org/users/first.last@example.org"
        );
    }

    #[test]
    fn lookup_treats_the_username_as_data() {
        let store = Store::new().unwrap();
        create_user(&store, "alice", &hash_password("pw-a"), None).unwrap();
        // A legacy account whose name would break a quoted SPARQL literal.
        let weird = "o'hara \"quoted\" \\ back } . ?x ?y ?z";
        insert_legacy_user(&store, "https://mlipe.2mia.org/users/legacy", weird, "pw-w");

        let (iri, hash) = find_user_by_username(&store, "alice").unwrap();
        assert_eq!(iri, "<https://mlipe.2mia.org/users/alice>");
        assert!(verify_password("pw-a", &hash));

        // Query-shaped input finds nothing (and does not error).
        for hostile in [
            "alice\"",
            "alice\" } LIMIT 1 #",
            "\" } UNION { ?user mlipe:username ?any . ?user mlipe:passwordHash ?hash } #",
            "alice\\",
            "*",
            "",
        ] {
            assert!(
                find_user_by_username(&store, hostile).is_none(),
                "{hostile:?}"
            );
        }

        // The legacy account is found by its exact name only.
        let (iri, hash) = find_user_by_username(&store, weird).unwrap();
        assert_eq!(iri, "<https://mlipe.2mia.org/users/legacy>");
        assert!(verify_password("pw-w", &hash));
        assert!(find_user_by_username(&store, "o'hara").is_none());

        assert_eq!(invalid_usernames(&store), vec![weird.to_string()]);

        // Listings hand the UI the stored value, not its SPARQL serialisation,
        // so the profile link and the delete form work for legacy names too.
        let listed: Vec<String> = list_all_users(&store)
            .into_iter()
            .map(|u| u.username)
            .collect();
        assert!(listed.contains(&weird.to_string()), "{listed:?}");
        assert!(listed.contains(&"alice".to_string()));
    }

    #[test]
    fn basic_auth_with_unusual_usernames() {
        let store = Store::new().unwrap();
        create_user(
            &store,
            "first.last@example.org",
            &hash_password("s3cret"),
            None,
        )
        .unwrap();
        insert_legacy_user(
            &store,
            "https://mlipe.2mia.org/users/legacy",
            "we\"ird",
            "pw",
        );

        assert_eq!(
            authenticate_basic(&store, Some(&basic("first.last@example.org", "s3cret"))).as_deref(),
            Some("<https://mlipe.2mia.org/users/first.last@example.org>")
        );
        assert_eq!(
            authenticate_basic(&store, Some(&basic("we\"ird", "pw"))).as_deref(),
            Some("<https://mlipe.2mia.org/users/legacy>")
        );
        assert!(authenticate_basic(&store, Some(&basic("we\"ird", "wrong"))).is_none());
        assert!(
            authenticate_basic(
                &store,
                Some(&basic("first.last@example.org\" } #", "s3cret"))
            )
            .is_none()
        );
        assert!(authenticate_basic(&store, Some(&basic("", "s3cret"))).is_none());
    }

    #[test]
    fn create_user_validates_and_enrols() {
        let store = Store::new().unwrap();
        let root = format!("<{ROOT_TEAM_IRI}>");
        let hash = hash_password("pw");

        for bad in ["", "a b", "a\"b", "a/b", ".x"] {
            assert!(
                create_user(&store, bad, &hash, Some(&root)).is_err(),
                "{bad:?}"
            );
        }
        assert!(find_user_by_username(&store, "a b").is_none());

        let user = create_user(&store, "first.last@example.org", &hash, Some(&root)).unwrap();
        assert_eq!(
            user.as_str(),
            "https://mlipe.2mia.org/users/first.last@example.org"
        );
        assert!(
            create_user(&store, "first.last@example.org", &hash, None).is_err(),
            "duplicate"
        );
        let has_member = mlipe("hasMember");
        let root_node = NamedNode::new(ROOT_TEAM_IRI).unwrap();
        assert!(
            store
                .quads_for_pattern(
                    Some(root_node.as_ref().into()),
                    Some(has_member.as_ref()),
                    Some(user.as_ref().into()),
                    None
                )
                .next()
                .is_some(),
            "enrolled in root"
        );
        let (_, stored) = find_user_by_username(&store, "first.last@example.org").unwrap();
        assert_eq!(stored, hash);
        assert!(invalid_usernames(&store).is_empty());
    }

    #[test]
    fn update_and_delete_user() {
        let store = Store::new().unwrap();
        let root = format!("<{ROOT_TEAM_IRI}>");
        let user = create_user(&store, "alice", &hash_password("one"), Some(&root)).unwrap();
        // Also an admin role pointing at the user.
        let has_admin = mlipe("hasAdmin");
        let root_node = NamedNode::new(ROOT_TEAM_IRI).unwrap();
        store
            .insert(QuadRef::new(
                &root_node,
                &has_admin,
                &user,
                GraphNameRef::DefaultGraph,
            ))
            .unwrap();

        update_password_hash(&store, user.as_str(), &hash_password("two")).unwrap();
        let (_, hash) = find_user_by_username(&store, "alice").unwrap();
        assert!(verify_password("two", &hash) && !verify_password("one", &hash));
        let p_hash = mlipe("passwordHash");
        assert_eq!(
            store
                .quads_for_pattern(
                    Some(user.as_ref().into()),
                    Some(p_hash.as_ref()),
                    None,
                    None
                )
                .count(),
            1,
            "exactly one hash after an update"
        );

        delete_user(&store, &format!("<{}>", user.as_str())).unwrap();
        assert!(find_user_by_username(&store, "alice").is_none());
        assert_eq!(
            store
                .quads_for_pattern(Some(user.as_ref().into()), None, None, None)
                .count(),
            0
        );
        assert_eq!(
            store
                .quads_for_pattern(None, None, Some(user.as_ref().into()), None)
                .count(),
            0
        );
    }

    #[test]
    fn is_valid_team_name_matches_the_segment_rule_minus_views() {
        for ok in ["materials", "MetaLearn", "Az09_-.x", "a.b", "x_y", "sub.1"] {
            assert!(is_valid_team_name(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            " ",
            "a b",
            "a/b",
            "a\"b",
            "a\\b",
            "a'b",
            "a\nb",
            ".hidden",
            "..",
            "_files",
            "_new_team",
            "ünïcode",
            "a{b",
            "a#b",
            "a<b>",
            "a}b",
        ] {
            assert!(!is_valid_team_name(bad), "{bad:?} should be invalid");
        }
        let max = "a".repeat(crate::store::MAX_NAME_SEGMENT_LEN);
        assert!(is_valid_team_name(&max));
        assert!(!is_valid_team_name(&format!("{max}a")));
    }

    fn seeded_store() -> Store {
        let store = Store::new().unwrap();
        crate::store::sparql_update(
            &store,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            INSERT DATA {
              <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
            }"#,
        )
        .unwrap();
        store
    }

    #[test]
    fn create_team_and_resolve_team_path_treat_names_as_data() {
        let store = seeded_store();
        let root = resolve_team_path(&store, &[]).unwrap();
        assert_eq!(root, format!("<{ROOT_TEAM_IRI}>"));

        let t = create_team(&store, ROOT_TEAM_IRI, "materials").unwrap();
        assert_eq!(t.as_str(), "https://mlipe.2mia.org/teams/materials");
        let sub = create_team(&store, t.as_str(), "atomistic").unwrap();
        assert_eq!(
            sub.as_str(),
            "https://mlipe.2mia.org/teams/materials/atomistic"
        );
        // The `<…>` display form the callers expect.
        assert_eq!(
            create_team(&store, &format!("<{}>", t.as_str()), "sub.2")
                .unwrap()
                .as_str(),
            "https://mlipe.2mia.org/teams/materials/sub.2"
        );

        let seg = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            resolve_team_path(&store, &seg(&["materials", "atomistic"])).unwrap(),
            "<https://mlipe.2mia.org/teams/materials/atomistic>"
        );
        assert!(resolve_team_path(&store, &seg(&["atomistic"])).is_none());
        assert!(resolve_team_path(&store, &seg(&["materials", "nope"])).is_none());
        // Unusual segments are not found, including ones that would have
        // altered the old query text.
        for bad in ["materials\"", "x\" } #", "a b", "_files", ".", ""] {
            assert!(resolve_team_path(&store, &seg(&[bad])).is_none(), "{bad:?}");
            assert!(
                resolve_team_path(&store, &seg(&["materials", bad])).is_none(),
                "{bad:?}"
            );
        }

        // Invalid names and duplicates are refused, each with its own error
        // kind; nothing is written.
        type Created = Result<NamedNode, CreateTeamError>;
        let invalid = |r: Created| matches!(r, Err(CreateTeamError::Invalid(_)));
        let exists = |r: Created| matches!(r, Err(CreateTeamError::Exists(_)));
        for bad in ["x\"y", "a b", "", "_x", ".x"] {
            assert!(invalid(create_team(&store, ROOT_TEAM_IRI, bad)), "{bad:?}");
        }
        assert!(exists(create_team(&store, ROOT_TEAM_IRI, "materials")));
        assert!(exists(create_team(&store, t.as_str(), "atomistic")));
        assert!(exists(create_team(&store, ROOT_TEAM_IRI, "root")));
        assert!(invalid(create_team(&store, "https://example.org/not-a-team", "x")));
        // `static` is served by the router at the top level, so it is reserved
        // directly under root only.
        assert!(invalid(create_team(&store, ROOT_TEAM_IRI, "static")));
        assert!(create_team(&store, t.as_str(), "static").is_ok());
        assert!(invalid_team_names(&store).is_empty());
        assert_eq!(get_sub_teams(&store, &[]).len(), 1);
    }
}
