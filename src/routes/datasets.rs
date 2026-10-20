//! Dataset management API (`/_api/datasets`) and entity search.
//!
//! Listing respects visibility exactly like the home page: an anonymous
//! caller sees the Public datasets (`auth::get_public_datasets`); an
//! authenticated user sees what `auth::get_user_datasets` grants (root admins
//! everything). Creating and deleting a dataset are privileged: both resolve
//! the caller to a *user* (session cookie or HTTP Basic — the write-only
//! ingest token is deliberately not accepted, it carries no identity) and
//! check the role matrix — a root-team admin may do anything; otherwise the
//! user must be an admin of the dataset's owning team (the team named by the
//! qualified name's path, e.g. `materials/foo` is owned by team `materials`;
//! a bare `foo` lives under `root/`). Names are validated against
//! `store::is_valid_dataset_name` before they reach the filesystem, an IRI,
//! or the system store.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use super::ingest;
use crate::auth;
use crate::shacl;
use crate::state::AppState;
use crate::store::is_valid_dataset_name;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_api/datasets", get(list_datasets).post(create_dataset))
        // Wildcard: qualified names contain `/` (`/_api/datasets/root/foo`).
        .route(
            "/_api/datasets/{*name}",
            axum::routing::delete(delete_dataset),
        )
        .route("/_api/search", get(entity_search))
}

#[derive(Serialize)]
struct DatasetList {
    datasets: Vec<String>,
}

#[derive(Deserialize)]
struct CreateDataset {
    name: String,
}

async fn list_datasets(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
) -> Json<DatasetList> {
    let system = &state.store_manager.system;
    let infos = match ingest::authenticate_user(&state, &headers, &cookies) {
        Some(user_iri) => auth::get_user_datasets(system, &user_iri),
        None => auth::get_public_datasets(system),
    };
    let mut datasets: Vec<String> = infos.into_iter().map(|d| d.name).collect();
    datasets.sort();
    datasets.dedup();
    Json(DatasetList { datasets })
}

/// Qualify a dataset name the way the web form does: a bare `foo` becomes
/// `root/foo`; a name that already carries a team path is kept as is.
fn qualify_dataset_name(name: &str) -> String {
    if name.contains('/') {
        name.to_string()
    } else {
        format!("root/{name}")
    }
}

/// Team-path segments of a qualified dataset name (everything before the last
/// `/`); the `root` prefix maps to the root team (no segments).
fn owning_team_segments(qualified: &str) -> Vec<String> {
    match qualified.rsplit_once('/') {
        Some(("root", _)) | None => Vec::new(),
        Some((team_path, _)) => team_path.split('/').map(str::to_string).collect(),
    }
}

async fn create_dataset(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(payload): Json<CreateDataset>,
) -> Response {
    // Identity first: an anonymous caller learns nothing about names/teams.
    // The ingest token is deliberately not accepted here — creating a dataset
    // needs a user whose team-admin rights can be checked.
    let Some(user_iri) = ingest::authenticate_user(&state, &headers, &cookies) else {
        return ingest::unauthorized_response();
    };

    let name = qualify_dataset_name(payload.name.trim());
    if !is_valid_dataset_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid dataset name: use ASCII letters, digits, '_', '-' and '.', \
             segments separated by '/', no segment starting with '.'",
        )
            .into_response();
    }

    let system = &state.store_manager.system;
    let Some(team_iri) = auth::resolve_team_path(system, &owning_team_segments(&name)) else {
        return (StatusCode::BAD_REQUEST, "Unknown team in dataset name").into_response();
    };
    if !auth::can_create_dataset_in_team(system, &user_iri, &team_iri) {
        return (
            StatusCode::FORBIDDEN,
            "Only root-team admins or admins of the owning team may create datasets",
        )
            .into_response();
    }

    if let Err(e) = state.store_manager.create_dataset(&name) {
        return (StatusCode::CONFLICT, e).into_response();
    }
    match state
        .store_manager
        .insert_dataset_metadata_full(&name, "PublicVisibility", &team_iri)
    {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => {
            // Do not leave an ownerless, metadata-less store behind.
            let _ = state.store_manager.delete_dataset(&name);
            (StatusCode::INTERNAL_SERVER_ERROR, e).into_response()
        }
    }
}

async fn delete_dataset(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Path(name): Path<String>,
) -> Response {
    // User-only, the same shape as create: the shared ingest token may
    // replace graphs but not drop a whole dataset (irreversible; also removes
    // docs, SHACL and metadata). The user needs write permission on the
    // dataset (root admin / owning-team admin).
    let Some(user_iri) = ingest::authenticate_user(&state, &headers, &cookies) else {
        return ingest::unauthorized_response();
    };
    if !auth::can_write_dataset(&state.store_manager.system, &user_iri, &name) {
        return (
            StatusCode::FORBIDDEN,
            "No write permission for this dataset",
        )
            .into_response();
    }
    if !is_valid_dataset_name(&name) {
        return (StatusCode::BAD_REQUEST, "Invalid dataset name").into_response();
    }
    match state.store_manager.delete_dataset(&name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e).into_response(),
    }
}

#[derive(Deserialize)]
struct SearchParams {
    q: String,
    dataset: String,
    class: Option<String>,
}

async fn entity_search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Result<Json<Vec<shacl::SearchResult>>, (StatusCode, String)> {
    let store = state.store_manager.get_dataset(&params.dataset).ok_or((
        StatusCode::NOT_FOUND,
        format!("Dataset '{}' not found", params.dataset),
    ))?;

    let results = shacl::search_entities(&store, &params.q, params.class.as_deref());
    Ok(Json(results))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use base64::Engine;
    use oxigraph::sparql::QueryResults;
    use tower_cookies::Cookie;

    use crate::routes::create_router;
    use crate::state::AppState;
    use crate::store::{sparql_query, sparql_update};

    const USERS: &str = "https://mlipe.2mia.org/users/";
    const TEAMS: &str = "https://mlipe.2mia.org/teams/";

    fn basic(user: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:secret"));
        format!("Basic {creds}")
    }

    /// A session cookie for `user` (the web-UI identity path).
    fn session_cookie(state: &AppState, user: &str) -> Cookie<'static> {
        let id = state
            .session_store
            .create_session(user.to_string(), format!("<{USERS}{user}>"));
        Cookie::new("mlipe_session", id)
    }

    /// In-memory state, password `secret` for everyone:
    /// - root team, admin `admin`;
    /// - sub-team `materials` (parent root), admin `alice`, member `bob`;
    /// - `bob` is admin of nothing;
    /// - an existing Public dataset `root/existing` owned by root.
    fn setup_state() -> AppState {
        let state = AppState::new().unwrap();
        let hash = crate::auth::hash_password("secret");
        sparql_update(
            &state.store_manager.system,
            &format!(
                r#"
                PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                INSERT DATA {{
                    <{TEAMS}root> a mlipe:Team ;
                        mlipe:teamName "root" ;
                        mlipe:hasAdmin <{USERS}admin> .
                    <{TEAMS}materials> a mlipe:Team ;
                        mlipe:teamName "materials" ;
                        mlipe:hasParentTeam <{TEAMS}root> ;
                        mlipe:hasMember <{USERS}alice>, <{USERS}bob> ;
                        mlipe:hasAdmin <{USERS}alice> .
                    <{USERS}admin> mlipe:username "admin" ; mlipe:passwordHash "{hash}" .
                    <{USERS}alice> mlipe:username "alice" ; mlipe:passwordHash "{hash}" .
                    <{USERS}bob> mlipe:username "bob" ; mlipe:passwordHash "{hash}" .
                }}
                "#
            ),
        )
        .unwrap();
        state.store_manager.create_dataset("root/existing").unwrap();
        state
            .store_manager
            .insert_dataset_metadata("root/existing")
            .unwrap();
        state
    }

    fn test_server() -> TestServer {
        TestServer::new(create_router(setup_state()))
    }

    fn owner_of(state: &AppState, name: &str) -> Option<String> {
        let q = format!(
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
               SELECT ?team WHERE {{ ?team mlipe:ownsDataset ?ds . ?ds mlipe:datasetName "{name}" }}"#
        );
        match sparql_query(&state.store_manager.system, &q).ok()? {
            QueryResults::Solutions(mut s) => s.next()?.ok()?.get("team").map(|t| {
                t.to_string()
                    .trim_matches(|c| c == '<' || c == '>')
                    .to_string()
            }),
            _ => None,
        }
    }

    async fn list(server: &TestServer) -> Vec<String> {
        let body: serde_json::Value = server.get("/_api/datasets").await.json();
        let mut v: Vec<String> = body["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    }

    // ── listing ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_datasets_empty_is_public() {
        let server = TestServer::new(create_router(AppState::new().unwrap()));
        let response = server.get("/_api/datasets").await;
        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["datasets"], serde_json::json!([]));
    }

    // ── anonymous ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anonymous_create_is_unauthorized() {
        let server = test_server();
        let r = server
            .post("/_api/datasets")
            .json(&serde_json::json!({"name": "root/anon"}))
            .await;
        r.assert_status(StatusCode::UNAUTHORIZED);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_anonymous_delete_is_unauthorized() {
        let server = test_server();
        let r = server.delete("/_api/datasets/root/existing").await;
        r.assert_status(StatusCode::UNAUTHORIZED);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_bad_password_is_unauthorized() {
        let server = test_server();
        let creds = base64::engine::general_purpose::STANDARD.encode("admin:WRONG");
        let r = server
            .delete("/_api/datasets/root/existing")
            .add_header("authorization", format!("Basic {creds}"))
            .await;
        r.assert_status(StatusCode::UNAUTHORIZED);
    }

    // ── non-admin user ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_non_admin_create_is_forbidden() {
        let server = test_server();
        for name in ["root/bobs", "materials/bobs", "bobs"] {
            let r = server
                .post("/_api/datasets")
                .add_header("authorization", basic("bob"))
                .json(&serde_json::json!({"name": name}))
                .await;
            r.assert_status(StatusCode::FORBIDDEN);
        }
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_non_admin_delete_is_forbidden() {
        let server = test_server();
        let r = server
            .delete("/_api/datasets/root/existing")
            .add_header("authorization", basic("bob"))
            .await;
        r.assert_status(StatusCode::FORBIDDEN);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    // ── team admin ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_team_admin_can_manage_own_team_only() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));

        // Alice may create under her team; the dataset is owned by that team.
        let r = server
            .post("/_api/datasets")
            .add_header("authorization", basic("alice"))
            .json(&serde_json::json!({"name": "materials/alices"}))
            .await;
        r.assert_status(StatusCode::CREATED);
        assert_eq!(
            owner_of(&state, "materials/alices").as_deref(),
            Some("https://mlipe.2mia.org/teams/materials")
        );

        // …but not under root (bare or explicit).
        for name in ["root/alices", "alices"] {
            let r = server
                .post("/_api/datasets")
                .add_header("authorization", basic("alice"))
                .json(&serde_json::json!({"name": name}))
                .await;
            r.assert_status(StatusCode::FORBIDDEN);
        }

        // She may delete her own team's dataset, not root's.
        let r = server
            .delete("/_api/datasets/root/existing")
            .add_header("authorization", basic("alice"))
            .await;
        r.assert_status(StatusCode::FORBIDDEN);
        let r = server
            .delete("/_api/datasets/materials/alices")
            .add_header("authorization", basic("alice"))
            .await;
        r.assert_status(StatusCode::NO_CONTENT);
        assert_eq!(list(&server).await, vec!["root/existing"]);
        assert_eq!(owner_of(&state, "materials/alices"), None);
    }

    // ── root admin ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_root_admin_create_and_delete() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));

        // Bare name → qualified under root, owned by root.
        let r = server
            .post("/_api/datasets")
            .add_header("authorization", basic("admin"))
            .json(&serde_json::json!({"name": "test-dataset"}))
            .await;
        r.assert_status(StatusCode::CREATED);
        assert_eq!(
            owner_of(&state, "root/test-dataset").as_deref(),
            Some("https://mlipe.2mia.org/teams/root")
        );

        // Root admin may also create in a sub-team.
        let r = server
            .post("/_api/datasets")
            .add_header("authorization", basic("admin"))
            .json(&serde_json::json!({"name": "materials/from-root"}))
            .await;
        r.assert_status(StatusCode::CREATED);
        assert_eq!(
            list(&server).await,
            vec!["materials/from-root", "root/existing", "root/test-dataset"]
        );

        // Duplicate → 409.
        let r = server
            .post("/_api/datasets")
            .add_header("authorization", basic("admin"))
            .json(&serde_json::json!({"name": "root/test-dataset"}))
            .await;
        r.assert_status(StatusCode::CONFLICT);

        // Delete (session-cookie identity this time), then 404 on a second try.
        let cookie = session_cookie(&state, "admin");
        let r = server
            .delete("/_api/datasets/root/test-dataset")
            .add_cookie(cookie.clone())
            .await;
        r.assert_status(StatusCode::NO_CONTENT);
        let r = server
            .delete("/_api/datasets/root/test-dataset")
            .add_cookie(cookie)
            .await;
        r.assert_status(StatusCode::NOT_FOUND);
        let r = server
            .delete("/_api/datasets/materials/from-root")
            .add_header("authorization", basic("admin"))
            .await;
        r.assert_status(StatusCode::NO_CONTENT);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_unknown_team_is_bad_request() {
        let server = test_server();
        let r = server
            .post("/_api/datasets")
            .add_header("authorization", basic("admin"))
            .json(&serde_json::json!({"name": "nosuchteam/ds"}))
            .await;
        r.assert_status(StatusCode::BAD_REQUEST);
    }

    // ── name validation ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_invalid_names_are_bad_request() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));
        for name in [
            "",
            "../escape",
            "root/..",
            "root/.hidden",
            "root//ds",
            "root/ds/",
            "root/has space",
            "root/x\"y",
            "root/x;y",
            "root/x>y",
        ] {
            let r = server
                .post("/_api/datasets")
                .add_header("authorization", basic("admin"))
                .json(&serde_json::json!({"name": name}))
                .await;
            r.assert_status(StatusCode::BAD_REQUEST);
        }
        assert_eq!(list(&server).await, vec!["root/existing"]);

        for path in ["root/.hidden", "root/has%20space", "root/x%22y"] {
            let r = server
                .delete(&format!("/_api/datasets/{path}"))
                .add_header("authorization", basic("admin"))
                .await;
            r.assert_status(StatusCode::BAD_REQUEST);
        }
    }

    // ── ingest token ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ingest_token_is_not_an_identity() {
        let mut state = setup_state();
        state.ingest_token = Some("tok-123".into());
        let server = TestServer::new(create_router(state));

        let r = server
            .post("/_api/datasets")
            .add_header("authorization", "Bearer tok-123")
            .json(&serde_json::json!({"name": "root/via-token"}))
            .await;
        r.assert_status(StatusCode::UNAUTHORIZED);

        let r = server
            .delete("/_api/datasets/root/existing")
            .add_header("authorization", "Bearer tok-123")
            .await;
        r.assert_status(StatusCode::UNAUTHORIZED);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    // ── listing respects visibility ──────────────────────────────────────

    #[tokio::test]
    async fn test_list_respects_visibility() {
        let state = setup_state();
        state
            .store_manager
            .create_dataset("materials/hidden")
            .unwrap();
        state
            .store_manager
            .insert_dataset_metadata_full(
                "materials/hidden",
                "TeamOnlyVisibility",
                "https://mlipe.2mia.org/teams/materials",
            )
            .unwrap();
        state.store_manager.create_dataset("root/members").unwrap();
        state
            .store_manager
            .insert_dataset_metadata_with_visibility("root/members", "LoggedUsersVisibility")
            .unwrap();
        let server = TestServer::new(create_router(state.clone()));

        // Anonymous: Public only.
        assert_eq!(list(&server).await, vec!["root/existing"]);

        let listed = |cookie: Cookie<'static>| async {
            let body: serde_json::Value =
                server.get("/_api/datasets").add_cookie(cookie).await.json();
            let mut v: Vec<String> = body["datasets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            v.sort();
            v
        };
        // Bob (member, no admin): Public + LoggedUsers.
        assert_eq!(
            listed(session_cookie(&state, "bob")).await,
            vec!["root/existing", "root/members"]
        );
        // Alice (materials admin): also her team's TeamOnly dataset.
        assert_eq!(
            listed(session_cookie(&state, "alice")).await,
            vec!["materials/hidden", "root/existing", "root/members"]
        );
        // Root admin: everything.
        assert_eq!(
            listed(session_cookie(&state, "admin")).await,
            vec!["materials/hidden", "root/existing", "root/members"]
        );
    }

    // ── web form handlers (/_datasets/new, /_datasets/delete) ────────────

    #[tokio::test]
    async fn test_web_forms_anonymous_redirects_to_login() {
        let server = test_server();
        let r = server
            .post("/_datasets/new")
            .form(&serde_json::json!({"name": "x", "visibility": "Public", "team": ""}))
            .await;
        r.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(r.header("location"), "/_login");
        let r = server
            .post("/_datasets/delete")
            .form(&serde_json::json!({"name": "root/existing"}))
            .await;
        r.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(r.header("location"), "/_login");
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_web_forms_non_admin_forbidden() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));
        let cookie = session_cookie(&state, "bob");
        let r = server
            .post("/_datasets/new")
            .add_cookie(cookie.clone())
            .form(&serde_json::json!({"name": "bobs", "visibility": "Public", "team": "materials"}))
            .await;
        r.assert_status(StatusCode::FORBIDDEN);
        let r = server
            .post("/_datasets/delete")
            .add_cookie(cookie)
            .form(&serde_json::json!({"name": "root/existing"}))
            .await;
        r.assert_status(StatusCode::FORBIDDEN);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_web_forms_invalid_names_bad_request() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));
        let cookie = session_cookie(&state, "admin");
        for (name, team) in [
            ("../x", ""),
            (".hidden", ""),
            ("a/b", ""),
            ("ok", "../x"),
            ("ok", "mat erials"),
            ("ok", "nosuchteam"),
        ] {
            let r = server
                .post("/_datasets/new")
                .add_cookie(cookie.clone())
                .form(&serde_json::json!({"name": name, "visibility": "Public", "team": team}))
                .await;
            r.assert_status(StatusCode::BAD_REQUEST);
        }
        let r = server
            .post("/_datasets/delete")
            .add_cookie(cookie)
            .form(&serde_json::json!({"name": "root/.."}))
            .await;
        r.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_web_forms_team_admin_create_and_delete() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));
        let alice = session_cookie(&state, "alice");

        // Alice creates in her team (TeamOnly), is redirected home.
        let r = server
            .post("/_datasets/new")
            .add_cookie(alice.clone())
            .form(&serde_json::json!({"name": "shapes", "visibility": "TeamOnly", "team": "materials"}))
            .await;
        r.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(r.header("location"), "/");
        assert_eq!(
            owner_of(&state, "materials/shapes").as_deref(),
            Some("https://mlipe.2mia.org/teams/materials")
        );

        // Not in root.
        let r = server
            .post("/_datasets/new")
            .add_cookie(alice.clone())
            .form(&serde_json::json!({"name": "rooty", "visibility": "Public", "team": ""}))
            .await;
        r.assert_status(StatusCode::FORBIDDEN);

        // Cannot delete root's dataset; can delete her own.
        let r = server
            .post("/_datasets/delete")
            .add_cookie(alice.clone())
            .form(&serde_json::json!({"name": "root/existing"}))
            .await;
        r.assert_status(StatusCode::FORBIDDEN);
        let r = server
            .post("/_datasets/delete")
            .add_cookie(alice)
            .form(&serde_json::json!({"name": "materials/shapes"}))
            .await;
        r.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(list(&server).await, vec!["root/existing"]);
    }

    #[tokio::test]
    async fn test_web_forms_root_admin() {
        let state = setup_state();
        let server = TestServer::new(create_router(state.clone()));
        let admin = session_cookie(&state, "admin");
        let r = server
            .post("/_datasets/new")
            .add_cookie(admin.clone())
            .form(&serde_json::json!({"name": "new-root", "visibility": "LoggedUsers", "team": ""}))
            .await;
        r.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            owner_of(&state, "root/new-root").as_deref(),
            Some("https://mlipe.2mia.org/teams/root")
        );
        // Duplicate → 409.
        let r = server
            .post("/_datasets/new")
            .add_cookie(admin.clone())
            .form(&serde_json::json!({"name": "new-root", "visibility": "Public", "team": ""}))
            .await;
        r.assert_status(StatusCode::CONFLICT);
        let r = server
            .post("/_datasets/delete")
            .add_cookie(admin.clone())
            .form(&serde_json::json!({"name": "root/new-root"}))
            .await;
        r.assert_status(StatusCode::SEE_OTHER);
        let r = server
            .post("/_datasets/delete")
            .add_cookie(admin)
            .form(&serde_json::json!({"name": "root/new-root"}))
            .await;
        r.assert_status(StatusCode::NOT_FOUND);
    }

    // ── search ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_entity_search_endpoint() {
        // Seed entities directly on the store: both `_update` and dataset
        // creation now require authorization, so the fixture bypasses HTTP.
        let state = AppState::new().unwrap();
        state
            .store_manager
            .create_dataset("root/search-test")
            .unwrap();
        let ds = state.store_manager.get_dataset("root/search-test").unwrap();
        sparql_update(
            &ds,
            r#"
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX ex: <http://example.org/>
            INSERT DATA {
                ex:alice a ex:Person ; rdfs:label "Alice Smith" .
                ex:bob a ex:Person ; rdfs:label "Bob Jones" .
            }
        "#,
        )
        .unwrap();
        let server = TestServer::new(create_router(state));

        let response = server
            .get("/_api/search")
            .add_query_param("q", "alice")
            .add_query_param("dataset", "root/search-test")
            .await;
        response.assert_status_ok();
        let body: Vec<serde_json::Value> = response.json();
        assert_eq!(body.len(), 1);
        assert!(body[0]["label"].as_str().unwrap().contains("Alice"));
    }
}
