use std::collections::HashSet;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Router, routing::get};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::auth;
use crate::migrate_io;
use crate::state::AppState;
use crate::store::{is_valid_dataset_name, is_valid_name_segment, sparql_update};

const SESSION_COOKIE: &str = "mlipe_session";

/// Build the session cookie with its hardening attributes: `HttpOnly` (no
/// script access), `SameSite=Lax` (not sent on cross-site POSTs, which closes
/// form CSRF), `Secure` unless `server.secure_cookies = false`, `Path=/` so one
/// cookie covers every route, and a `Max-Age` equal to the server-side session
/// lifetime so the browser and the `SessionStore` expire it together.
fn session_cookie(state: &AppState, session_id: String) -> tower_cookies::Cookie<'static> {
    use tower_cookies::cookie::{SameSite, time};
    let max_age = time::Duration::try_from(state.session_store.max_age())
        .expect("session max age fits in a cookie Max-Age");
    tower_cookies::Cookie::build((SESSION_COOKIE, session_id))
        .path("/")
        .http_only(true)
        .secure(state.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(max_age)
        .build()
}

/// The cookie to pass to `Cookies::remove` on logout. It mirrors the login
/// cookie's attributes: the `Path` must match or the browser keeps the
/// original, and RFC 6265bis lets a user agent refuse a non-`Secure` removal
/// of a `Secure` cookie, so the flags are mirrored too.
fn session_cookie_removal(state: &AppState) -> tower_cookies::Cookie<'static> {
    use tower_cookies::cookie::SameSite;
    tower_cookies::Cookie::build(SESSION_COOKIE)
        .path("/")
        .http_only(true)
        .secure(state.secure_cookies)
        .same_site(SameSite::Lax)
        .build()
}

/// Example pre-filled query over the schema (classes & properties) — the
/// "query the ontology" entry point. Generic enough for any ontology dataset.
const EXAMPLE_ONTOLOGY_QUERY: &str = "PREFIX owl: <http://www.w3.org/2002/07/owl#>\n\
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n\
# Classes and properties defined in the ontology\n\
SELECT ?term ?type ?label WHERE {\n  \
?term a ?type .\n  \
FILTER(?type IN (owl:Class, owl:ObjectProperty, owl:DatatypeProperty))\n  \
OPTIONAL { ?term rdfs:label ?label }\n\
} ORDER BY ?type ?term LIMIT 200";

/// Example pre-filled query over the instance data — the "query the knowledge
/// graph" entry point.
const EXAMPLE_DATA_QUERY: &str = "# A sample of the instance data (triples)\n\
SELECT ?subject ?predicate ?object WHERE {\n  \
?subject ?predicate ?object .\n\
} LIMIT 100";

/// concon-native serving base for a dataset, from its qualified name
/// (e.g. "mlips/mlips" → "/mlips/_ds/mlips"; "root/foo" → "/_ds/foo").
pub fn dataset_base_url(qualified: &str) -> String {
    match qualified.rsplit_once('/') {
        Some(("root", name)) => format!("/_ds/{name}"),
        Some((team, name)) => format!("/{team}/_ds/{name}"),
        None => format!("/_ds/{qualified}"),
    }
}

/// Build a `_query` deep link that pre-fills the YASGUI editor with `query`.
fn query_deep_link(base: &str, query: &str) -> String {
    let qs = serde_urlencoded::to_string([("query", query)]).unwrap_or_default();
    format!("{base}/_query?{qs}")
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/_login", get(login_page).post(login_submit))
        .route("/_logout", axum::routing::post(logout))
        .route("/_datasets/new", axum::routing::post(create_dataset_web))
        .route("/_datasets/delete", axum::routing::post(delete_dataset_web))
        .route(
            "/_change-password",
            get(change_password_page).post(change_password_submit),
        )
        .route("/_teams", get(teams_list))
        .route("/_api/files/upload", axum::routing::post(upload_file))
        .route("/_admin", get(admin_dashboard))
        .route("/_admin/users", get(admin_users))
        .route("/_admin/users/new", axum::routing::post(admin_create_user))
        .route(
            "/_admin/users/delete",
            axum::routing::post(admin_delete_user),
        )
        // Epic I — versioned user export/import (cross-instance migration).
        .route("/_admin/users/export", get(admin_export_users))
        .route(
            "/_admin/users/import",
            axum::routing::post(admin_import_users),
        )
        // Epic I — versioned team-subtree export/import.
        .route("/_admin/teams", get(admin_teams))
        .route("/_admin/teams/export", get(admin_export_teams))
        .route(
            "/_admin/teams/import",
            axum::routing::post(admin_import_teams),
        )
        .route("/_users", get(users_list))
        .route("/_users/{username}", get(user_profile))
}

pub fn get_username(cookies: &Cookies, state: &AppState) -> Option<auth::Session> {
    let cookie = cookies.get(SESSION_COOKIE)?;
    state.session_store.get_session(cookie.value())
}

/// Check if the current session user is a root team admin.
pub fn is_root_admin(session: &Option<auth::Session>, state: &AppState) -> bool {
    session.as_ref().map_or(false, |s| {
        auth::is_root_admin(&state.store_manager.system, &s.user_iri)
    })
}

async fn index(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);

    if session.is_some() {
        // Logged in: show root team page
        return team_page(&state, &[], &cookies, 1).await;
    }

    // Anonymous: show public landing page
    let admin = false;
    let datasets = auth::get_public_datasets(&state.store_manager.system);

    let tmpl = state
        .templates
        .get_template("index.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => Option::<String>::None,
            is_admin => admin,
            datasets => datasets.iter().map(|d| {
                let (team_name, short_name) = match d.name.rsplit_once('/') {
                    Some((team, name)) => {
                        let display_team = if team == "root" { "Root".to_string() } else { team.to_string() };
                        (display_team, name.to_string())
                    }
                    None => ("Root".to_string(), d.name.clone()),
                };
                let base = dataset_base_url(&d.name);
                minijinja::context! {
                    name => short_name,
                    team => team_name,
                    url => format!("{base}/"),
                    query_url => format!("{base}/_query"),
                    example_ontology_url => query_deep_link(&base, EXAMPLE_ONTOLOGY_QUERY),
                    example_data_url => query_deep_link(&base, EXAMPLE_DATA_QUERY),
                }
            }).collect::<Vec<_>>(),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn login_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);
    let admin = is_root_admin(&session, &state);

    let tmpl = state
        .templates
        .get_template("login.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            error => "",
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Some((user_iri, password_hash)) =
        auth::find_user_by_username(&state.store_manager.system, &form.username)
    {
        if auth::verify_password(&form.password, &password_hash) {
            // A re-login replaces the session the browser already presented,
            // so the old id does not stay valid for the rest of its 12 h.
            if let Some(old) = cookies.get(SESSION_COOKIE) {
                state.session_store.remove_session(old.value());
            }
            let session_id = state.session_store.create_session(form.username, user_iri);
            cookies.add(session_cookie(&state, session_id));
            return Redirect::to("/").into_response();
        }
    }

    // Login failed — re-render form with error
    let tmpl = match state.templates.get_template("login.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let html = match tmpl.render(minijinja::context! {
        username => Option::<String>::None,
        error => "Invalid username or password.",
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Html(html).into_response()
}

async fn logout(State(state): State<AppState>, cookies: Cookies) -> Redirect {
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        state.session_store.remove_session(cookie.value());
        cookies.remove(session_cookie_removal(&state));
    }
    Redirect::to("/")
}

async fn change_password_page(State(state): State<AppState>, cookies: Cookies) -> Response {
    let session = get_username(&cookies, &state);
    let admin = is_root_admin(&session, &state);
    if session.is_none() {
        return Redirect::to("/_login").into_response();
    }

    let tmpl = match state.templates.get_template("change_password.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let html = match tmpl.render(minijinja::context! {
        username => session.map(|s| s.username),
        is_admin => admin,
        error => "",
        success => "",
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Html(html).into_response()
}

#[derive(Deserialize)]
struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

async fn change_password_submit(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let session = match get_username(&cookies, &state) {
        Some(s) => s,
        None => return Redirect::to("/_login").into_response(),
    };

    let render = |error: &str, success: &str| -> Response {
        let tmpl = match state.templates.get_template("change_password.html") {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let html = match tmpl.render(minijinja::context! {
            username => &session.username,
            error => error,
            success => success,
        }) {
            Ok(h) => h,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        Html(html).into_response()
    };

    // Verify current password
    let current_hash =
        match auth::find_user_by_username(&state.store_manager.system, &session.username) {
            Some((_, hash)) => hash,
            None => return render("User not found.", ""),
        };

    if !auth::verify_password(&form.current_password, &current_hash) {
        return render("Current password is incorrect.", "");
    }

    if form.new_password != form.confirm_password {
        return render("New passwords do not match.", "");
    }

    if form.new_password.is_empty() {
        return render("New password cannot be empty.", "");
    }

    // Update password in the system store
    let new_hash = auth::hash_password(&form.new_password);
    if let Err(e) =
        auth::update_password_hash(&state.store_manager.system, &session.user_iri, &new_hash)
    {
        return render(&format!("Failed to update password: {}", e), "");
    }

    render("", "Password changed successfully.")
}

#[derive(Deserialize)]
struct CreateDatasetForm {
    name: String,
    visibility: String,
    team: String,
}

/// Create a dataset from the team page form. Requires a logged-in user who is
/// a root-team admin or an admin of the owning team (the form's `team` path;
/// empty or `root` means the root team). Name and team segments are validated
/// before they reach the filesystem, an IRI, or the system store.
async fn create_dataset_web(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreateDatasetForm>,
) -> Response {
    let Some(session) = get_username(&cookies, &state) else {
        return Redirect::to("/_login").into_response();
    };

    let name = form.name.trim();
    let team_path = form.team.trim().trim_matches('/');
    let team_segments: Vec<String> = if team_path.is_empty() || team_path == "root" {
        Vec::new()
    } else {
        team_path.split('/').map(str::to_string).collect()
    };
    if !is_valid_name_segment(name) || !team_segments.iter().all(|s| is_valid_name_segment(s)) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid dataset or team name: use ASCII letters, digits, '_', '-' and '.', \
             not starting with '.'",
        )
            .into_response();
    }

    let visibility = match form.visibility.as_str() {
        "LoggedUsers" => "LoggedUsersVisibility",
        "TeamOnly" => "TeamOnlyVisibility",
        _ => "PublicVisibility",
    };

    // Resolve the team path to an IRI; an unknown team is an error, never a
    // silent fallback to root.
    let system = &state.store_manager.system;
    let Some(team_iri) = auth::resolve_team_path(system, &team_segments) else {
        return (StatusCode::BAD_REQUEST, "Unknown team").into_response();
    };
    let team_iri = team_iri.trim_matches(|c| c == '<' || c == '>').to_string();
    if !auth::can_create_dataset_in_team(system, &session.user_iri, &team_iri) {
        return (
            StatusCode::FORBIDDEN,
            "Only root-team admins or admins of this team may create datasets here",
        )
            .into_response();
    }

    let qualified_name = if team_segments.is_empty() {
        format!("root/{name}")
    } else {
        format!("{}/{name}", team_segments.join("/"))
    };

    if let Err(e) = state.store_manager.create_dataset(&qualified_name) {
        return (StatusCode::CONFLICT, e).into_response();
    }
    if let Err(e) =
        state
            .store_manager
            .insert_dataset_metadata_full(&qualified_name, visibility, &team_iri)
    {
        // Do not leave an ownerless, metadata-less store behind.
        let _ = state.store_manager.delete_dataset(&qualified_name);
        return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }

    Redirect::to("/").into_response()
}

#[derive(Deserialize)]
struct DeleteDatasetForm {
    name: String,
}

/// Delete a dataset from the dataset page form (`name` is the qualified name,
/// e.g. `materials/foo`). Requires a logged-in user with write permission on
/// that dataset (root-team admin or admin of the owning team).
async fn delete_dataset_web(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<DeleteDatasetForm>,
) -> Response {
    let Some(session) = get_username(&cookies, &state) else {
        return Redirect::to("/_login").into_response();
    };

    let name = form.name.trim();
    if !is_valid_dataset_name(name) {
        return (StatusCode::BAD_REQUEST, "Invalid dataset name").into_response();
    }
    if !auth::can_write_dataset(&state.store_manager.system, &session.user_iri, name) {
        return (
            StatusCode::FORBIDDEN,
            "No write permission for this dataset",
        )
            .into_response();
    }

    match state.store_manager.delete_dataset(name) {
        Ok(()) => Redirect::to("/").into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e).into_response(),
    }
}

pub async fn dataset_query(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    cookies: &Cookies,
    initial_query: Option<&str>,
) -> Result<Html<String>, (StatusCode, String)> {
    // Check dataset exists
    if state.store_manager.get_dataset(dataset_name).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Dataset '{}' not found", dataset_name),
        ));
    }

    let session = get_username(cookies, state);
    let admin = is_root_admin(&session, state);

    // Extract short name and team path for display
    let display_name = dataset_name.rsplit('/').next().unwrap_or(dataset_name);

    // Build breadcrumbs from the team segments in the qualified name
    let team_segments: Vec<&str> = match dataset_name.rsplit_once('/') {
        Some((team_path, _)) => {
            let segs: Vec<&str> = team_path
                .split('/')
                .filter(|s| !s.is_empty() && *s != "root")
                .collect();
            segs
        }
        None => Vec::new(),
    };
    let breadcrumbs: Vec<_> = team_segments
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let url = format!("/{}", team_segments[..=i].join("/"));
            minijinja::context! { name => *name, url => url }
        })
        .collect();

    let tmpl = state
        .templates
        .get_template("dataset.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            dataset_name => display_name,
            qualified_name => dataset_name,
            url_prefix => url_prefix,
            breadcrumbs => breadcrumbs,
            initial_query => initial_query,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

pub async fn team_page(
    state: &AppState,
    team_segments: &[String],
    cookies: &Cookies,
    files_page: u32,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(cookies, state);
    let admin = is_root_admin(&session, state);

    let team_path = team_segments.join("/");
    let team_name = team_segments.last().map(|s| s.as_str()).unwrap_or("Root");

    // Resolve the team IRI. A path that does not name a team — including one
    // with a segment that could not be a team name, which the resolver rejects
    // before touching the store — is 404.
    let team_iri = auth::resolve_team_path(&state.store_manager.system, team_segments);
    if team_iri.is_none() {
        return Err((StatusCode::NOT_FOUND, "Team not found".into()));
    }

    // Check team visibility. Logged-in users must be able to see the team;
    // anonymous visitors are allowed here only when the caller established the
    // team has a Public dataset (content::team_has_public_dataset), and they see
    // a public-only view (datasets/files filtered, no admin controls) below.
    if !team_segments.is_empty() {
        if let (Some(iri), Some(s)) = (team_iri.as_ref(), session.as_ref()) {
            if !auth::can_see_team(&state.store_manager.system, &s.user_iri, iri) {
                return Err((
                    StatusCode::FORBIDDEN,
                    "You do not have access to this team".into(),
                ));
            }
        }
    }

    // Build breadcrumbs: each ancestor team as (name, url)
    let breadcrumbs: Vec<_> = team_segments
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let url = format!("/{}", team_segments[..=i].join("/"));
            minijinja::context! { name => name, url => url }
        })
        .collect();

    // Check if current user is admin of this specific team
    let is_team_admin = admin
        || session.as_ref().map_or(false, |s| {
            team_iri.as_ref().map_or(false, |iri| {
                let iri_clean = iri.trim_matches(|c| c == '<' || c == '>');
                auth::get_user_admin_teams(&state.store_manager.system, &s.user_iri)
                    .iter()
                    .any(|t| t.iri.trim_matches(|c| c == '<' || c == '>') == iri_clean)
            })
        });

    // Get sub-teams (filtered by visibility) and datasets
    let sub_teams = if let Some(ref s) = session {
        auth::get_visible_sub_teams(&state.store_manager.system, &s.user_iri, team_segments)
    } else {
        Vec::new()
    };
    let mut datasets = auth::get_team_datasets_by_path(&state.store_manager.system, team_segments);
    if session.is_none() {
        // Anonymous public view: only Public datasets.
        let public = auth::get_public_datasets(&state.store_manager.system);
        datasets.retain(|d| public.iter().any(|p| p.name == d.name));
    }

    // Get team members (recursive) if admin
    let members = if is_team_admin {
        team_iri.as_ref().map_or(Vec::new(), |iri| {
            auth::get_team_members_recursive(&state.store_manager.system, iri)
        })
    } else {
        Vec::new()
    };

    // Get files for this team
    let team_path_for_files = if team_segments.is_empty() {
        "root".to_string()
    } else {
        team_path.clone()
    };
    // Files are shown to authenticated viewers only; anonymous gets the
    // public-only view (datasets, not the team's papers).
    let all_files = if session.is_some() {
        super::files::list_files_recursive(state, &team_path_for_files)
    } else {
        Vec::new()
    };
    let files_per_page: usize = 10;
    let total_files = all_files.len();
    let total_pages = ((total_files + files_per_page - 1) / files_per_page).max(1);
    let current_page = (files_page as usize).clamp(1, total_pages);
    let skip = (current_page - 1) * files_per_page;
    let files: Vec<_> = all_files
        .into_iter()
        .skip(skip)
        .take(files_per_page)
        .collect();
    let can_upload = is_team_admin
        || session.as_ref().map_or(false, |s| {
            team_iri.as_ref().map_or(false, |iri| {
                auth::can_access_files(
                    &state.store_manager.system,
                    &s.user_iri,
                    iri,
                    auth::FileAction::Write,
                )
            })
        });

    let team_url_prefix = if team_segments.is_empty() {
        String::new()
    } else {
        format!("/{}", team_path)
    };

    let tmpl = state
        .templates
        .get_template("team.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            is_team_admin => is_team_admin,
            team_name => team_name,
            breadcrumbs => breadcrumbs,
            team_path => team_path,
            team_url_prefix => team_url_prefix,
            sub_teams => sub_teams.iter().map(|t| minijinja::context! {
                name => t.name,
            }).collect::<Vec<_>>(),
            datasets => datasets.iter().map(|d| {
                // Relative display name from the current team.
                let display = if team_path.is_empty() {
                    d.name.strip_prefix("root/").unwrap_or(&d.name).to_string()
                } else {
                    d.name.strip_prefix(&format!("{}/", team_path)).unwrap_or(&d.name).to_string()
                };
                let base = dataset_base_url(&d.name);
                minijinja::context! {
                    name => display,
                    url => format!("{base}/"),                 // documentation
                    query_url => format!("{base}/_query"),     // YASGUI editor
                    example_ontology_url => query_deep_link(&base, EXAMPLE_ONTOLOGY_QUERY),
                    example_data_url => query_deep_link(&base, EXAMPLE_DATA_QUERY),
                }
            }).collect::<Vec<_>>(),
            members => members.iter().map(|u| minijinja::context! {
                username => u.username,
            }).collect::<Vec<_>>(),
            files => files,
            files_page => current_page,
            files_total_pages => total_pages,
            files_total => total_files,
            can_upload => can_upload,
            team_path_for_files => team_path_for_files,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn users_list(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);
    let admin = is_root_admin(&session, &state);

    let all_users = auth::list_all_users(&state.store_manager.system);

    let tmpl = state
        .templates
        .get_template("users.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            users => all_users.iter().map(|u| minijinja::context! {
                username => u.username,
                teams => u.teams.iter().map(|t| &t.name).cloned().collect::<Vec<_>>().join(", "),
            }).collect::<Vec<_>>(),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn user_profile(
    State(state): State<AppState>,
    axum::extract::Path(profile_name): axum::extract::Path<String>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);
    let admin = is_root_admin(&session, &state);

    let user_info = auth::get_user_info(&state.store_manager.system, &profile_name).ok_or((
        StatusCode::NOT_FOUND,
        format!("User '{}' not found", profile_name),
    ))?;

    let admin_teams = auth::get_user_admin_teams(&state.store_manager.system, &user_info.iri);
    let admin_team_iris: Vec<_> = admin_teams.iter().map(|t| &t.iri).collect();

    let datasets = auth::get_user_datasets(&state.store_manager.system, &user_info.iri);

    let tmpl = state
        .templates
        .get_template("user_profile.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            profile_username => profile_name,
            teams => user_info.teams.iter().map(|t| minijinja::context! {
                name => t.name,
                is_admin => admin_team_iris.contains(&&t.iri),
            }).collect::<Vec<_>>(),
            datasets => datasets.iter().map(|d| {
                let (team_prefix, short_name) = match d.name.rsplit_once('/') {
                    Some((team, name)) => {
                        let prefix = if team == "root" { String::new() } else { format!("/{}", team) };
                        (prefix, name.to_string())
                    }
                    None => (String::new(), d.name.clone()),
                };
                minijinja::context! {
                    name => short_name,
                    url => format!("{}/_ds/{}/_query", team_prefix, short_name),
                }
            }).collect::<Vec<_>>(),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

// ─── Site Administration ─────────────────────────────────────────

async fn admin_dashboard(State(state): State<AppState>, cookies: Cookies) -> Response {
    let session = get_username(&cookies, &state);
    let admin = is_root_admin(&session, &state);
    if !admin {
        return Redirect::to("/").into_response();
    }

    let user_count = auth::list_all_users(&state.store_manager.system).len();
    let dataset_count = state.store_manager.list_datasets().len();
    let team_count = auth::get_sub_teams(&state.store_manager.system, &[]).len() + 1; // +1 for root

    let tmpl = match state.templates.get_template("admin/index.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let html = match tmpl.render(minijinja::context! {
        username => session.map(|s| s.username),
        is_admin => true,
        user_count => user_count,
        dataset_count => dataset_count,
        team_count => team_count,
        schema_version => crate::migration::get_schema_version(&state.store_manager.system),
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Html(html).into_response()
}

async fn admin_users(State(state): State<AppState>, cookies: Cookies) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }
    render_admin_users(&state, session.map(|s| s.username), None, None)
}

#[derive(Deserialize)]
struct CreateUserForm {
    username: String,
    password: String,
}

async fn admin_create_user(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }

    let admin = session.map(|s| s.username);
    let username = form.username.trim().to_string();
    // A malformed username (or an empty password) is a client error: the users
    // page is re-rendered with the reason, with status 400.
    let reject = |msg: String| {
        let mut response = render_admin_users(&state, admin.clone(), Some(msg), None);
        if response.status() == StatusCode::OK {
            *response.status_mut() = StatusCode::BAD_REQUEST;
        }
        response
    };
    if !auth::is_valid_username(&username) {
        return reject(format!(
            "Invalid username '{username}': use ASCII letters, digits, '_', '-', '.' or '@' \
             (no leading '.'), at most {} characters.",
            auth::MAX_USERNAME_LEN
        ));
    }
    if form.password.is_empty() {
        return reject("The password must not be empty.".to_string());
    }

    // Check if user already exists
    if auth::find_user_by_username(&state.store_manager.system, &username).is_some() {
        return Redirect::to("/_admin/users").into_response();
    }

    let password_hash = auth::hash_password(&form.password);

    // Find root team IRI
    let root_iri = auth::resolve_team_path(&state.store_manager.system, &[])
        .unwrap_or_else(|| format!("<{}>", auth::ROOT_TEAM_IRI));

    // Model-API write: the username and hash are literal values only.
    if let Err(e) = auth::create_user(
        &state.store_manager.system,
        &username,
        &password_hash,
        Some(&root_iri),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }

    Redirect::to("/_admin/users").into_response()
}

#[derive(Deserialize)]
struct DeleteUserForm {
    username: String,
}

async fn admin_delete_user(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }

    // Don't allow deleting yourself
    if let Some(ref s) = session {
        if s.username == form.username {
            return Redirect::to("/_admin/users").into_response();
        }
    }

    // The username is resolved to the stored user node (literal match, no
    // query text); the delete then removes the user's profile and every team
    // membership / admin role that points at it.
    if let Some((user_iri, _)) =
        auth::find_user_by_username(&state.store_manager.system, &form.username)
        && let Err(e) = auth::delete_user(&state.store_manager.system, &user_iri)
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }

    Redirect::to("/_admin/users").into_response()
}

/// Epic I — download a version-annotated bundle of all users (admin only).
async fn admin_export_users(State(state): State<AppState>, cookies: Cookies) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }
    let bundle = migrate_io::export_users(&state.store_manager.system);
    let json = match serde_json::to_string_pretty(&bundle) {
        Ok(j) => j,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"concon-users-export.json\"",
            ),
        ],
        json,
    )
        .into_response()
}

/// Epic I — import a users bundle (admin only). Multipart form: `bundle` (the
/// uploaded JSON) and optional `dry_run` (present = preview only). Merge-not-
/// replace; renders the users page with an import report.
async fn admin_import_users(
    State(state): State<AppState>,
    cookies: Cookies,
    mut multipart: axum::extract::Multipart,
) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }

    let mut data: Option<Vec<u8>> = None;
    let mut dry_run = false;
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(|s| s.to_string());
        match name.as_deref() {
            Some("bundle") => data = field.bytes().await.ok().map(|b| b.to_vec()),
            Some("dry_run") => {
                dry_run = true;
                let _ = field.text().await;
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let sys = &state.store_manager.system;
    let username = session.map(|s| s.username);

    let mut error: Option<String> = None;
    let mut report_ctx: Option<minijinja::Value> = None;

    match data {
        None => error = Some("No bundle file was uploaded.".to_string()),
        Some(bytes) => match serde_json::from_slice::<migrate_io::UsersBundle>(&bytes) {
            Err(e) => error = Some(format!("Could not parse bundle JSON: {e}")),
            Ok(bundle) if bundle.kind != "users" => {
                error = Some(format!("Not a users bundle (kind = '{}').", bundle.kind))
            }
            Ok(bundle) => {
                let existing: HashSet<String> = auth::list_all_users(sys)
                    .into_iter()
                    .map(|u| u.username)
                    .collect();
                let target_v = crate::migration::get_schema_version(sys);
                let report = if dry_run {
                    migrate_io::plan_users_import(&bundle, &existing, target_v)
                } else {
                    migrate_io::apply_users_import(sys, &bundle, &existing, target_v)
                };
                report_ctx = Some(minijinja::context! {
                    applied => report.applied,
                    dry_run => !report.applied,
                    version_mismatch => report.version_mismatch,
                    bundle_schema_version => report.bundle_schema_version,
                    target_schema_version => report.target_schema_version,
                    concon_version => bundle.concon_version,
                    to_add => report.to_add,
                    skipped_existing => report.skipped_existing,
                    rejected => report.rejected,
                    add_count => report.to_add.len(),
                    skip_count => report.skipped_existing.len(),
                    reject_count => report.rejected.len(),
                });
            }
        },
    }

    render_admin_users(&state, username, error, report_ctx)
}

/// Render the user-management page, optionally with an import report. Shared by
/// the users GET and the import POST.
fn render_admin_users(
    state: &AppState,
    username: Option<String>,
    error: Option<String>,
    import_report: Option<minijinja::Value>,
) -> Response {
    let all_users = auth::list_all_users(&state.store_manager.system);
    let tmpl = match state.templates.get_template("admin/users.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let html = match tmpl.render(minijinja::context! {
        username => username,
        is_admin => true,
        users => all_users.iter().map(|u| minijinja::context! {
            username => u.username,
            teams => u.teams.iter().map(|t| &t.name).cloned().collect::<Vec<_>>().join(", "),
        }).collect::<Vec<_>>(),
        error => error.unwrap_or_default(),
        success => "",
        import_report => import_report,
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Html(html).into_response()
}

/// All team paths in the system store (IRI `…/teams/<path>` minus the special
/// root), for the admin teams page's export picker.
fn all_team_paths(state: &AppState) -> Vec<String> {
    let q = r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?t WHERE { ?t a mlipe:Team } ORDER BY ?t"#;
    let mut paths = Vec::new();
    if let Ok(oxigraph::sparql::QueryResults::Solutions(sols)) =
        crate::store::sparql_query(&state.store_manager.system, q)
    {
        for sol in sols.flatten() {
            if let Some(t) = sol.get("t") {
                let iri = t.to_string();
                if let Some(p) = iri
                    .trim_matches(|c| c == '<' || c == '>')
                    .strip_prefix(auth::TEAM_IRI_PREFIX)
                {
                    if p != "root" {
                        paths.push(p.to_string());
                    }
                }
            }
        }
    }
    paths
}

async fn admin_teams(State(state): State<AppState>, cookies: Cookies) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }
    render_admin_teams(&state, session.map(|s| s.username), None, None)
}

#[derive(Deserialize)]
struct ExportTeamsQuery {
    team: Option<String>,
}

/// Epic I — download a version-annotated bundle of a team subtree (admin only).
async fn admin_export_teams(
    State(state): State<AppState>,
    cookies: Cookies,
    axum::extract::Query(q): axum::extract::Query<ExportTeamsQuery>,
) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }
    let team = q.team.unwrap_or_default();
    let segments: Vec<String> = team
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if segments.is_empty() {
        return render_admin_teams(
            &state,
            session.map(|s| s.username),
            Some("Choose a team subtree to export.".to_string()),
            None,
        );
    }
    let Some(root_iri) = auth::resolve_team_path(&state.store_manager.system, &segments) else {
        return render_admin_teams(
            &state,
            session.map(|s| s.username),
            Some(format!("No such team: '{team}'.")),
            None,
        );
    };
    let bundle = migrate_io::export_teams(&state.store_manager.system, &root_iri);
    let json = match serde_json::to_string_pretty(&bundle) {
        Ok(j) => j,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let fname = format!("concon-team-{}.json", segments.join("-"));
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{fname}\""),
            ),
        ],
        json,
    )
        .into_response()
}

/// Epic I — import a team-subtree bundle (admin only). Multipart: `bundle` (the
/// JSON), `parent` (target parent team path, empty = root), optional `dry_run`.
async fn admin_import_teams(
    State(state): State<AppState>,
    cookies: Cookies,
    mut multipart: axum::extract::Multipart,
) -> Response {
    let session = get_username(&cookies, &state);
    if !is_root_admin(&session, &state) {
        return Redirect::to("/").into_response();
    }

    let mut data: Option<Vec<u8>> = None;
    let mut dry_run = false;
    let mut parent = String::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(|s| s.to_string());
        match name.as_deref() {
            Some("bundle") => data = field.bytes().await.ok().map(|b| b.to_vec()),
            Some("parent") => parent = field.text().await.unwrap_or_default(),
            Some("dry_run") => {
                dry_run = true;
                let _ = field.text().await;
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let sys = &state.store_manager.system;
    let username = session.map(|s| s.username);
    let parent_segments: Vec<String> = parent
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let mut error: Option<String> = None;
    let mut report_ctx: Option<minijinja::Value> = None;

    match data {
        None => error = Some("No bundle file was uploaded.".to_string()),
        Some(bytes) => match serde_json::from_slice::<migrate_io::TeamsBundle>(&bytes) {
            Err(e) => error = Some(format!("Could not parse bundle JSON: {e}")),
            Ok(bundle) if bundle.kind != "teams" => {
                error = Some(format!("Not a teams bundle (kind = '{}').", bundle.kind))
            }
            Ok(_) if auth::resolve_team_path(sys, &parent_segments).is_none() => {
                error = Some(format!("No such target parent team: '{parent}'."))
            }
            Ok(bundle) => {
                let existing_team_paths: HashSet<String> =
                    all_team_paths(&state).into_iter().collect();
                let existing_usernames: HashSet<String> = auth::list_all_users(sys)
                    .into_iter()
                    .map(|u| u.username)
                    .collect();
                let target_v = crate::migration::get_schema_version(sys);
                let report = if dry_run {
                    migrate_io::plan_teams_import(
                        &bundle,
                        &parent_segments,
                        &existing_team_paths,
                        &existing_usernames,
                        target_v,
                    )
                } else {
                    migrate_io::apply_teams_import(
                        sys,
                        &bundle,
                        &parent_segments,
                        &existing_team_paths,
                        &existing_usernames,
                        target_v,
                    )
                };
                // Plan and apply validate the bundle's team names as a whole
                // before anything is planned or written; an invalid name is a
                // client error, shown on the page with status 400.
                let report = match report {
                    Ok(r) => r,
                    Err(e) => {
                        let mut response = render_admin_teams(&state, username, Some(e), None);
                        if response.status() == StatusCode::OK {
                            *response.status_mut() = StatusCode::BAD_REQUEST;
                        }
                        return response;
                    }
                };
                report_ctx = Some(minijinja::context! {
                    applied => report.applied,
                    dry_run => !report.applied,
                    version_mismatch => report.version_mismatch,
                    bundle_schema_version => report.bundle_schema_version,
                    target_schema_version => report.target_schema_version,
                    concon_version => bundle.concon_version,
                    target_parent_path => report.target_parent_path,
                    created_count => report.created_count,
                    skipped_count => report.skipped_count,
                    missing_users => report.missing_users,
                    rejected_root => report.rejected_root,
                    rows => report.rows.iter().map(|r| minijinja::context! {
                        target_path => r.target_path,
                        skipped_existing => r.skipped_existing,
                        rejected_root => r.rejected_root,
                        failed => r.failed.clone(),
                        members => r.linked_members.join(", "),
                        admins => r.linked_admins.join(", "),
                    }).collect::<Vec<_>>(),
                });
            }
        },
    }

    render_admin_teams(&state, username, error, report_ctx)
}

/// Render the team-migration admin page, optionally with an import report.
fn render_admin_teams(
    state: &AppState,
    username: Option<String>,
    error: Option<String>,
    import_report: Option<minijinja::Value>,
) -> Response {
    let team_paths = all_team_paths(state);
    let tmpl = match state.templates.get_template("admin/teams.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let html = match tmpl.render(minijinja::context! {
        username => username,
        is_admin => true,
        team_paths => team_paths,
        error => error.unwrap_or_default(),
        import_report => import_report,
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Html(html).into_response()
}

#[derive(Deserialize)]
pub struct CreateTeamForm {
    pub name: String,
}

/// Create a sub-team under the given parent team segments (root-team admins
/// only). The name is validated ([`auth::is_valid_team_name`], and the
/// root-level reserved names) and rejected with 400 otherwise; an unknown
/// parent is 404; a name already used under that parent is 409; a store
/// failure is 500. The write goes through `auth::create_team` (model API),
/// so the name never reaches SPARQL text.
pub async fn create_team(
    state: &AppState,
    parent_segments: &[String],
    cookies: &Cookies,
    form: CreateTeamForm,
) -> Response {
    let session = get_username(cookies, state);
    if !is_root_admin(&session, state) {
        return Redirect::to("/").into_response();
    }

    let name = form.name.trim();
    if !auth::is_valid_team_name(name) {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid team name '{name}': use ASCII letters, digits, '_', '-' and '.', \
                 not starting with '.' or '_', at most {} characters.",
                crate::store::MAX_NAME_SEGMENT_LEN
            ),
        )
            .into_response();
    }

    let system = &state.store_manager.system;
    let Some(parent_iri) = auth::resolve_team_path(system, parent_segments) else {
        return (StatusCode::NOT_FOUND, "Team not found").into_response();
    };
    if let Err(e) = auth::create_team(system, &parent_iri, name) {
        let status = match e {
            auth::CreateTeamError::Invalid(_) => StatusCode::BAD_REQUEST,
            auth::CreateTeamError::Exists(_) => StatusCode::CONFLICT,
            auth::CreateTeamError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, e.to_string()).into_response();
    }

    // Redirect back to the parent team page
    let parent_path = parent_segments.join("/");
    if parent_path.is_empty() {
        Redirect::to("/").into_response()
    } else {
        Redirect::to(&format!("/{}", parent_path)).into_response()
    }
}

async fn upload_file(
    State(state): State<AppState>,
    cookies: Cookies,
    multipart: axum::extract::Multipart,
) -> Response {
    let session = match get_username(&cookies, &state) {
        Some(s) => s,
        None => return Redirect::to("/_login").into_response(),
    };

    // The team_path is sent as a hidden field in the form
    let mut team_path = String::new();
    let mut mp = multipart;
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name = String::new();

    while let Ok(Some(field)) = mp.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "team_path" => {
                team_path = field.text().await.unwrap_or_default();
            }
            "file" => {
                file_name = field.file_name().unwrap_or("unknown.pdf").to_string();
                match field.bytes().await {
                    Ok(bytes) => file_data = Some(bytes.to_vec()),
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Failed to read file: {}", e),
                        )
                            .into_response();
                    }
                }
            }
            _ => {}
        }
    }

    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => return (StatusCode::BAD_REQUEST, "No file provided").into_response(),
    };

    if team_path.is_empty() {
        team_path = "root".to_string();
    }

    let team_url_prefix = if team_path == "root" {
        String::new()
    } else {
        format!("/{}", team_path)
    };

    // Check permissions
    let team_iri = match auth::resolve_team_path(
        &state.store_manager.system,
        &if team_path == "root" {
            Vec::new()
        } else {
            team_path.split('/').map(|s| s.to_string()).collect()
        },
    ) {
        Some(iri) => iri,
        None => return (StatusCode::NOT_FOUND, "Team not found").into_response(),
    };

    if !auth::can_access_files(
        &state.store_manager.system,
        &session.user_iri,
        &team_iri,
        auth::FileAction::Write,
    ) {
        return (StatusCode::FORBIDDEN, "Not authorized to upload files").into_response();
    }

    let file_size = data.len();
    let uuid = uuid::Uuid::new_v4().to_string();

    // Save file to disk
    let file_dir = state.files_dir.join(&team_path);
    if let Err(e) = std::fs::create_dir_all(&file_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create directory: {}", e),
        )
            .into_response();
    }

    let file_path_on_disk = file_dir.join(format!("{}.pdf", uuid));
    if let Err(e) = std::fs::write(&file_path_on_disk, &data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to write file: {}", e),
        )
            .into_response();
    }

    // Insert metadata into catalog
    let catalog = match state.store_manager.get_or_create_file_catalog(&team_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to open catalog: {}", e),
            )
                .into_response();
        }
    };

    let now = chrono::Utc::now().to_rfc3339();
    let user_iri = session.user_iri.trim_matches(|c| c == '<' || c == '>');
    let file_name_escaped = file_name.replace('"', r#"\""#);

    let insert = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        PREFIX dcterms: <http://purl.org/dc/terms/>
        PREFIX bibo: <http://purl.org/ontology/bibo/>
        PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
        INSERT DATA {{
            <https://mlipe.2mia.org/files/{uuid}> a mlipe:File ;
                mlipe:fileName "{file_name_escaped}" ;
                dcterms:title "" ;
                dcterms:creator "" ;
                dcterms:date "" ;
                bibo:doi "" ;
                dcterms:abstract "" ;
                dcterms:isPartOf "" ;
                bibo:volume "" ;
                bibo:issue "" ;
                bibo:pages "" ;
                dcterms:publisher "" ;
                bibo:issn "" ;
                dcterms:identifier "" ;
                dcterms:subject "" ;
                mlipe:affiliation "" ;
                mlipe:fileSize {file_size} ;
                mlipe:mimeType "application/pdf" ;
                mlipe:uploadedBy <{user_iri}> ;
                mlipe:uploadedAt "{now}"^^xsd:dateTime .
        }}
        "#,
    );

    if let Err(e) = sparql_update(&catalog, &insert) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to insert metadata: {}", e),
        )
            .into_response();
    }

    // Extract metadata from PDF using GROBID (best-effort, don't fail upload)
    let pdf_path = file_path_on_disk.clone();
    let catalog_clone = catalog.clone();
    let uuid_clone = uuid.clone();
    let grobid_url = state.grobid_url.clone();
    tokio::spawn(async move {
        if grobid_url.is_empty() {
            return;
        }
        match crate::grobid::extract_metadata(&pdf_path, &grobid_url).await {
            Ok(meta) => {
                if meta.title.is_empty() && meta.authors.is_empty() && meta.doi.is_empty() {
                    tracing::info!("GROBID: no metadata extracted for {}", uuid_clone);
                    return;
                }

                let esc = |s: &str| s.replace('\\', "\\\\").replace('"', r#"\""#);
                let file_iri = format!("https://mlipe.2mia.org/files/{}", uuid_clone);

                let update = format!(
                    r#"
                    PREFIX dcterms: <http://purl.org/dc/terms/>
                    PREFIX bibo: <http://purl.org/ontology/bibo/>
                    PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                    DELETE {{
                        <{file_iri}> dcterms:title ?t ; dcterms:creator ?a ; dcterms:date ?y ;
                                     bibo:doi ?d ; dcterms:abstract ?ab ; dcterms:isPartOf ?j ;
                                     bibo:volume ?v ; bibo:issue ?is ; bibo:pages ?p ;
                                     dcterms:publisher ?pb ; bibo:issn ?issn ;
                                     dcterms:identifier ?ax ; dcterms:subject ?kw ;
                                     mlipe:affiliation ?af .
                    }}
                    INSERT {{
                        <{file_iri}> dcterms:title "{title}" ; dcterms:creator "{authors}" ;
                                     dcterms:date "{year}" ; bibo:doi "{doi}" ;
                                     dcterms:abstract "{abstract_text}" ;
                                     dcterms:isPartOf "{journal}" ;
                                     bibo:volume "{volume}" ; bibo:issue "{issue}" ;
                                     bibo:pages "{pages}" ; dcterms:publisher "{publisher}" ;
                                     bibo:issn "{issn}" ; dcterms:identifier "{arxiv_id}" ;
                                     dcterms:subject "{keywords}" ;
                                     mlipe:affiliation "{affiliations}" .
                    }}
                    WHERE {{
                        OPTIONAL {{ <{file_iri}> dcterms:title ?t }}
                        OPTIONAL {{ <{file_iri}> dcterms:creator ?a }}
                        OPTIONAL {{ <{file_iri}> dcterms:date ?y }}
                        OPTIONAL {{ <{file_iri}> bibo:doi ?d }}
                        OPTIONAL {{ <{file_iri}> dcterms:abstract ?ab }}
                        OPTIONAL {{ <{file_iri}> dcterms:isPartOf ?j }}
                        OPTIONAL {{ <{file_iri}> bibo:volume ?v }}
                        OPTIONAL {{ <{file_iri}> bibo:issue ?is }}
                        OPTIONAL {{ <{file_iri}> bibo:pages ?p }}
                        OPTIONAL {{ <{file_iri}> dcterms:publisher ?pb }}
                        OPTIONAL {{ <{file_iri}> bibo:issn ?issn }}
                        OPTIONAL {{ <{file_iri}> dcterms:identifier ?ax }}
                        OPTIONAL {{ <{file_iri}> dcterms:subject ?kw }}
                        OPTIONAL {{ <{file_iri}> mlipe:affiliation ?af }}
                    }}
                    "#,
                    title = esc(&meta.title),
                    authors = esc(&meta.authors),
                    year = esc(&meta.year),
                    doi = esc(&meta.doi),
                    abstract_text = esc(&meta.abstract_text),
                    journal = esc(&meta.journal),
                    volume = esc(&meta.volume),
                    issue = esc(&meta.issue),
                    pages = esc(&meta.pages),
                    publisher = esc(&meta.publisher),
                    issn = esc(&meta.issn),
                    arxiv_id = esc(&meta.arxiv_id),
                    keywords = esc(&meta.keywords),
                    affiliations = esc(&meta.affiliations),
                );

                match sparql_update(&catalog_clone, &update) {
                    Ok(()) => tracing::info!(
                        "GROBID: extracted metadata for {}: '{}'",
                        uuid_clone,
                        meta.title
                    ),
                    Err(e) => tracing::warn!("GROBID: failed to update metadata: {}", e),
                }

                // Store references as bibo:cites
                for ref_doi in &meta.references {
                    let ref_escaped = esc(ref_doi);
                    let ref_insert = format!(
                        r#"
                        PREFIX bibo: <http://purl.org/ontology/bibo/>
                        INSERT DATA {{
                            <{file_iri}> bibo:cites <https://doi.org/{ref_escaped}> .
                        }}
                        "#,
                    );
                    let _ = sparql_update(&catalog_clone, &ref_insert);
                }
            }
            Err(e) => {
                tracing::warn!("GROBID extraction failed for {}: {}", uuid_clone, e);
            }
        }
    });

    Redirect::to(&format!("{}/_files", team_url_prefix)).into_response()
}

// ─── Entity Editor ──────────────────────────────────────────────

pub async fn entity_editor(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    cookies: &Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(cookies, state);
    let admin = is_root_admin(&session, state);

    // Check dataset exists
    if state.store_manager.get_dataset(dataset_name).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Dataset '{}' not found", dataset_name),
        ));
    }

    // Parse SHACL shapes from the dataset's SHACL store
    let shapes_json = match state.store_manager.get_shacl_store(dataset_name) {
        Some(shacl_store) => {
            let descriptors = crate::shacl::parse_shapes_from_store(&shacl_store);
            crate::shacl::form_descriptors_to_json(&descriptors)
        }
        None => serde_json::json!([]),
    };

    // Extract display name and breadcrumbs
    let display_name = dataset_name.rsplit('/').next().unwrap_or(dataset_name);
    let team_segments: Vec<&str> = match dataset_name.rsplit_once('/') {
        Some((team_path, _)) => team_path
            .split('/')
            .filter(|s| !s.is_empty() && *s != "root")
            .collect(),
        None => Vec::new(),
    };
    let breadcrumbs: Vec<_> = team_segments
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let url = format!("/{}", team_segments[..=i].join("/"));
            minijinja::context! { name => *name, url => url }
        })
        .collect();

    let tmpl = state
        .templates
        .get_template("entity_editor.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            dataset_name => display_name,
            url_prefix => url_prefix,
            breadcrumbs => breadcrumbs,
            shapes_json => shapes_json.to_string(),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn teams_list(State(state): State<AppState>, cookies: Cookies) -> Response {
    let session = get_username(&cookies, &state);
    if session.is_none() {
        return Redirect::to("/_login").into_response();
    }
    let admin = is_root_admin(&session, &state);

    // Get visible top-level teams (children of root)
    let teams = auth::get_visible_sub_teams(
        &state.store_manager.system,
        &session.as_ref().unwrap().user_iri,
        &[],
    );

    let tmpl = match state.templates.get_template("teams_list.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let html = match tmpl.render(minijinja::context! {
        username => session.map(|s| s.username),
        is_admin => admin,
        teams => teams.iter().map(|t| minijinja::context! {
            name => t.name,
        }).collect::<Vec<_>>(),
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Html(html).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use axum_test::TestServer;

    use super::SESSION_COOKIE;
    use crate::auth::SessionStore;
    use crate::routes::create_router;
    use crate::state::AppState;
    use crate::store::sparql_update;

    /// In-memory state with one user "admin"/"secret" (root-team admin).
    fn setup_state() -> AppState {
        let state = AppState::new().unwrap();
        let hash = crate::auth::hash_password("secret");
        sparql_update(
            &state.store_manager.system,
            &format!(
                r#"
                PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
                INSERT DATA {{
                    <https://mlipe.2mia.org/teams/root> a mlipe:Team ;
                        mlipe:teamName "root" ;
                        mlipe:hasAdmin <https://mlipe.2mia.org/users/admin> .
                    <https://mlipe.2mia.org/users/admin> mlipe:username "admin" ;
                        mlipe:passwordHash "{hash}" .
                }}
                "#
            ),
        )
        .unwrap();
        state
    }

    /// A server that keeps cookies between requests, like a browser.
    fn server_for(state: AppState) -> TestServer {
        TestServer::builder()
            .save_cookies()
            .build(create_router(state))
    }

    async fn login(server: &TestServer) -> axum_test::TestResponse {
        server
            .post("/_login")
            .form(&[("username", "admin"), ("password", "secret")])
            .await
    }

    /// The raw `Set-Cookie` header for the session cookie on a response.
    fn session_set_cookie(response: &axum_test::TestResponse) -> String {
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|v| v.starts_with(&format!("{SESSION_COOKIE}=")))
            .expect("login response sets the session cookie")
    }

    /// Case-insensitive attribute check on a raw `Set-Cookie` value, matching
    /// on `; name` so a value cannot satisfy an attribute name.
    fn has_attr(set_cookie: &str, attr: &str) -> bool {
        set_cookie
            .split(';')
            .skip(1)
            .any(|part| part.trim().eq_ignore_ascii_case(attr))
    }

    #[tokio::test]
    async fn login_sets_hardened_session_cookie() {
        let server = server_for(setup_state());
        let response = login(&server).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let set_cookie = session_set_cookie(&response);
        assert!(has_attr(&set_cookie, "HttpOnly"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "Secure"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "SameSite=Lax"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "Path=/"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "Max-Age=43200"), "{set_cookie}");

        // The browser-side cookie is also usable: a login-gated page renders.
        let page = server.get("/_change-password").await;
        page.assert_status_ok();
    }

    #[tokio::test]
    async fn secure_cookies_false_drops_only_the_secure_flag() {
        let mut state = setup_state();
        state.secure_cookies = false;
        let server = server_for(state);
        let set_cookie = session_set_cookie(&login(&server).await);
        assert!(!has_attr(&set_cookie, "Secure"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "HttpOnly"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "SameSite=Lax"), "{set_cookie}");
    }

    #[tokio::test]
    async fn bad_password_sets_no_cookie() {
        let server = server_for(setup_state());
        let response = server
            .post("/_login")
            .form(&[("username", "admin"), ("password", "WRONG")])
            .await;
        response.assert_status_ok();
        assert!(response.headers().get("set-cookie").is_none());
    }

    #[tokio::test]
    async fn logout_clears_the_cookie_and_the_server_session() {
        let state = setup_state();
        let session_store = state.session_store.clone();
        let server = server_for(state);

        let login_response = login(&server).await;
        let session_id = login_response.cookie(SESSION_COOKIE).value().to_string();
        assert!(session_store.get_session(&session_id).is_some());

        let logout_response = server.post("/_logout").await;
        logout_response.assert_status(StatusCode::SEE_OTHER);

        // The removal cookie must match the login cookie's path, otherwise the
        // browser keeps the original cookie alongside the expired one.
        let set_cookie = session_set_cookie(&logout_response);
        assert!(has_attr(&set_cookie, "Path=/"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "Max-Age=0"), "{set_cookie}");
        // Same flags as the login cookie, so a user agent that refuses to let
        // a non-Secure Set-Cookie touch a Secure cookie still clears it.
        assert!(has_attr(&set_cookie, "HttpOnly"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "Secure"), "{set_cookie}");
        assert!(has_attr(&set_cookie, "SameSite=Lax"), "{set_cookie}");
        assert!(session_store.get_session(&session_id).is_none());

        // Gated pages are closed again.
        let page = server.get("/_change-password").await;
        page.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(page.headers()["location"], "/_login");
    }

    /// Logging in while already logged in replaces the server-side session:
    /// the id the browser presented stops working, only the new one is valid.
    #[tokio::test]
    async fn relogin_drops_the_previous_session() {
        let state = setup_state();
        let session_store = state.session_store.clone();
        let server = server_for(state);

        let first = login(&server)
            .await
            .cookie(SESSION_COOKIE)
            .value()
            .to_string();
        assert!(session_store.get_session(&first).is_some());

        let second = login(&server)
            .await
            .cookie(SESSION_COOKIE)
            .value()
            .to_string();
        assert_ne!(first, second);
        assert!(session_store.get_session(&first).is_none());
        assert!(session_store.get_session(&second).is_some());
        server.get("/_change-password").await.assert_status_ok();
    }

    /// A cookie whose session has outlived the server-side max age is
    /// rejected even though the browser still sends it.
    #[tokio::test]
    async fn expired_session_is_rejected_server_side() {
        let mut state = setup_state();
        state.session_store = Arc::new(SessionStore::with_max_age(
            std::time::Duration::from_millis(50),
        ));
        let server = server_for(state);

        login(&server).await.assert_status(StatusCode::SEE_OTHER);
        server.get("/_change-password").await.assert_status_ok();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let page = server.get("/_change-password").await;
        page.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(page.headers()["location"], "/_login");
    }

    /// Login must treat a query-shaped username as data: a failed login, not
    /// a parse error.
    #[tokio::test]
    async fn login_with_hostile_username_is_just_a_failed_login() {
        let server = server_for(setup_state());
        for hostile in [
            "admin\"",
            "admin\" } LIMIT 1 #",
            "\" } UNION { ?user mlipe:username ?any . ?user mlipe:passwordHash ?hash } #",
        ] {
            let response = server
                .post("/_login")
                .form(&[("username", hostile), ("password", "secret")])
                .await;
            response.assert_status_ok();
            assert!(
                response.text().contains("Invalid username or password."),
                "{hostile:?}"
            );
            assert!(
                !response.headers().get_all("set-cookie").iter().any(|v| v
                    .to_str()
                    .unwrap()
                    .starts_with(&format!("{SESSION_COOKIE}="))),
                "no session for {hostile:?}"
            );
        }
    }

    /// Existing accounts keep logging in whatever their username looks like:
    /// the deployed email-style names, and even a name that predates the rule.
    #[tokio::test]
    async fn login_works_for_email_style_and_legacy_usernames() {
        let state = setup_state();
        let sys = &state.store_manager.system;
        crate::auth::create_user(
            sys,
            "first.last@example.org",
            &crate::auth::hash_password("pw1"),
            None,
        )
        .unwrap();
        {
            use oxigraph::model::{GraphNameRef, Literal, NamedNode, QuadRef};
            let user = NamedNode::new("https://mlipe.2mia.org/users/legacy").unwrap();
            let p_name = NamedNode::new("https://mlipe.2mia.org/ontology#username").unwrap();
            let p_hash = NamedNode::new("https://mlipe.2mia.org/ontology#passwordHash").unwrap();
            let name = Literal::new_simple_literal("we\"ird name");
            let hash = Literal::new_simple_literal(crate::auth::hash_password("pw2"));
            sys.insert(QuadRef::new(
                &user,
                &p_name,
                &name,
                GraphNameRef::DefaultGraph,
            ))
            .unwrap();
            sys.insert(QuadRef::new(
                &user,
                &p_hash,
                &hash,
                GraphNameRef::DefaultGraph,
            ))
            .unwrap();
        }
        let server = server_for(state);
        for (user, pw) in [("first.last@example.org", "pw1"), ("we\"ird name", "pw2")] {
            let response = server
                .post("/_login")
                .form(&[("username", user), ("password", pw)])
                .await;
            response.assert_status(StatusCode::SEE_OTHER);
            session_set_cookie(&response);
            let wrong = server
                .post("/_login")
                .form(&[("username", user), ("password", "nope")])
                .await;
            wrong.assert_status_ok();
        }
        // The profile page resolves the name as data too.
        let page = server.get("/_users/first.last@example.org").await;
        page.assert_status_ok();
    }

    /// The admin form validates the username (400 with the reason on the users
    /// page), accepts the deployed email-style names, and the created user can
    /// log in.
    #[tokio::test]
    async fn admin_create_user_validates_username() {
        let state = setup_state();
        let server = server_for(state.clone());
        login(&server).await.assert_status(StatusCode::SEE_OTHER);

        for bad in ["bad\"name", "a b", "a/b", ".hidden", "", "x\" } #"] {
            let response = server
                .post("/_admin/users/new")
                .form(&[("username", bad), ("password", "pw")])
                .await;
            response.assert_status(StatusCode::BAD_REQUEST);
            assert!(response.text().contains("Invalid username"), "{bad:?}");
            assert!(crate::auth::find_user_by_username(&state.store_manager.system, bad).is_none());
        }
        let response = server
            .post("/_admin/users/new")
            .form(&[("username", "first.last@example.org"), ("password", "")])
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        assert!(response.text().contains("password must not be empty"));

        let response = server
            .post("/_admin/users/new")
            .form(&[("username", "first.last@example.org"), ("password", "pw")])
            .await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/_admin/users");
        let (iri, _) = crate::auth::find_user_by_username(
            &state.store_manager.system,
            "first.last@example.org",
        )
        .unwrap();
        assert_eq!(iri, "<https://mlipe.2mia.org/users/first.last@example.org>");
        assert!(crate::auth::invalid_usernames(&state.store_manager.system).is_empty());

        // The new user logs in (replacing the admin session on this client).
        let response = server
            .post("/_login")
            .form(&[("username", "first.last@example.org"), ("password", "pw")])
            .await;
        response.assert_status(StatusCode::SEE_OTHER);

        // Deleting by a query-shaped username is a no-op redirect, not an error.
        let server = server_for(state.clone());
        login(&server).await.assert_status(StatusCode::SEE_OTHER);
        let response = server
            .post("/_admin/users/delete")
            .form(&[("username", "first.last@example.org\" } #")])
            .await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            crate::auth::find_user_by_username(
                &state.store_manager.system,
                "first.last@example.org"
            )
            .is_some()
        );
        let response = server
            .post("/_admin/users/delete")
            .form(&[("username", "first.last@example.org")])
            .await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            crate::auth::find_user_by_username(
                &state.store_manager.system,
                "first.last@example.org"
            )
            .is_none()
        );
    }

    /// The sub-team form validates the name (400, nothing written), creates a
    /// valid one through the model API (reachable at its URL, listed as a
    /// sub-team), and refuses a duplicate under the same parent (409) — which
    /// also keeps `root` from being re-minted under the root team.
    #[tokio::test]
    async fn create_team_validates_name_and_refuses_duplicates() {
        let state = setup_state();
        let server = server_for(state.clone());
        login(&server).await.assert_status(StatusCode::SEE_OTHER);
        let sys = &state.store_manager.system;

        for bad in [
            "bad\"name",
            "a b",
            "a/b",
            ".hidden",
            "_files",
            "",
            "x\" } #",
            "x\\y",
        ] {
            let response = server.post("/_new_team").form(&[("name", bad)]).await;
            response.assert_status(StatusCode::BAD_REQUEST);
            assert!(response.text().contains("Invalid team name"), "{bad:?}");
            assert!(
                crate::auth::invalid_team_names(sys).is_empty(),
                "{bad:?} was stored"
            );
        }
        // Nothing but the root team exists.
        assert_eq!(crate::auth::get_sub_teams(sys, &[]).len(), 0);

        let response = server
            .post("/_new_team")
            .form(&[("name", "Az09_-.x")])
            .await;
        response.assert_status(StatusCode::SEE_OTHER);
        let iri = crate::auth::resolve_team_path(sys, &["Az09_-.x".to_string()]).unwrap();
        assert_eq!(iri, "<https://mlipe.2mia.org/teams/Az09_-.x>");
        server.get("/Az09_-.x").await.assert_status_ok();

        // A nested team under it, then the same name again: conflict.
        let response = server
            .post("/Az09_-.x/_new_team")
            .form(&[("name", "sub")])
            .await;
        response.assert_status(StatusCode::SEE_OTHER);
        server.get("/Az09_-.x/sub").await.assert_status_ok();
        let response = server
            .post("/Az09_-.x/_new_team")
            .form(&[("name", "sub")])
            .await;
        response.assert_status(StatusCode::CONFLICT);
        assert_eq!(
            crate::auth::get_sub_teams(sys, &["Az09_-.x".to_string()]).len(),
            1
        );
        // The same name under a different parent is fine (distinct IRI).
        server
            .post("/_new_team")
            .form(&[("name", "sub")])
            .await
            .assert_status(StatusCode::SEE_OTHER);
        // `root` under the root team would collide with the root team's IRI.
        let response = server.post("/_new_team").form(&[("name", "root")]).await;
        response.assert_status(StatusCode::CONFLICT);
        // `static` is served by the router at the top level: reserved there,
        // an ordinary name deeper down.
        let response = server.post("/_new_team").form(&[("name", "static")]).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        assert!(response.text().contains("reserved"));
        server
            .post("/Az09_-.x/_new_team")
            .form(&[("name", "static")])
            .await
            .assert_status(StatusCode::SEE_OTHER);
        server.get("/Az09_-.x/static").await.assert_status_ok();
        // An unknown parent is 404, with nothing written.
        let response = server
            .post("/nope/_new_team")
            .form(&[("name", "sub")])
            .await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    /// Team URLs with segments that could not be team names are 404 — the
    /// store is not consulted — and so are valid-looking unknown teams; an
    /// existing team keeps working, including the deployed-style names.
    #[tokio::test]
    async fn team_page_with_unusual_url_is_not_found() {
        let state = setup_state();
        let server = server_for(state.clone());
        login(&server).await.assert_status(StatusCode::SEE_OTHER);
        let sys = &state.store_manager.system;
        crate::auth::create_team(sys, crate::auth::ROOT_TEAM_IRI, "MetaLearn").unwrap();
        crate::auth::create_team(sys, "https://mlipe.2mia.org/teams/MetaLearn", "sub.1").unwrap();

        server.get("/MetaLearn").await.assert_status_ok();
        server.get("/MetaLearn/sub.1").await.assert_status_ok();
        for bad in [
            "/we%22ird",
            "/MetaLearn/a%20b",
            "/MetaLearn/x%22%20%7D%20%23",
            "/.hidden",
            "/MetaLearn/%E2%9C%93",
            "/nope",
            "/MetaLearn/nope",
        ] {
            let response = server.get(bad).await;
            response.assert_status(StatusCode::NOT_FOUND);
        }
        // A new-sub-team POST on such a URL is 404 as well.
        server
            .post("/we%22ird/_new_team")
            .form(&[("name", "x")])
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    /// A legacy team whose stored name would not pass the rule is matched as a
    /// literal value by the resolver (no query text), so its name cannot
    /// alter a query; it is reported at startup and is not reachable by URL.
    #[tokio::test]
    async fn legacy_team_name_is_data_and_reported() {
        let state = setup_state();
        let sys = &state.store_manager.system;
        {
            use oxigraph::model::{GraphNameRef, Literal, NamedNode, QuadRef};
            let team = NamedNode::new("https://mlipe.2mia.org/teams/legacy").unwrap();
            let rdf_type =
                NamedNode::new("http://www.w3.org/1999/02/22-rdf-syntax-ns#type").unwrap();
            let c_team = NamedNode::new("https://mlipe.2mia.org/ontology#Team").unwrap();
            let p_name = NamedNode::new("https://mlipe.2mia.org/ontology#teamName").unwrap();
            let p_parent = NamedNode::new("https://mlipe.2mia.org/ontology#hasParentTeam").unwrap();
            let root = NamedNode::new(crate::auth::ROOT_TEAM_IRI).unwrap();
            let name = Literal::new_simple_literal("we\"ird } #");
            let g = GraphNameRef::DefaultGraph;
            sys.insert(QuadRef::new(&team, &rdf_type, &c_team, g))
                .unwrap();
            sys.insert(QuadRef::new(&team, &p_name, &name, g)).unwrap();
            sys.insert(QuadRef::new(&team, &p_parent, &root, g))
                .unwrap();
        }
        assert_eq!(crate::auth::invalid_team_names(sys), vec!["we\"ird } #"]);
        assert!(crate::auth::resolve_team_path(sys, &["we\"ird } #".to_string()]).is_none());
        // It is still listed as a sub-team of root, by value, unescaped.
        let subs = crate::auth::get_sub_teams(sys, &[]);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].name, "we\"ird } #");
        let server = server_for(state.clone());
        login(&server).await.assert_status(StatusCode::SEE_OTHER);
        server
            .get("/we%22ird%20%7D%20%23")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    /// The teams import rejects a bundle with an invalid team name as a
    /// whole (400, nothing written) and imports a valid one.
    #[tokio::test]
    async fn admin_import_teams_validates_names() {
        let state = setup_state();
        let server = server_for(state.clone());
        login(&server).await.assert_status(StatusCode::SEE_OTHER);
        let sys = &state.store_manager.system;

        let bundle = |rel_path: &str, name: &str| {
            serde_json::to_vec(&crate::migrate_io::TeamsBundle::new(
                crate::migration::get_schema_version(sys),
                rel_path.to_string(),
                vec![crate::migrate_io::TeamRecord {
                    rel_path: rel_path.to_string(),
                    name: name.to_string(),
                    members: vec![],
                    admins: vec!["admin".to_string()],
                }],
            ))
            .unwrap()
        };
        let post = |bytes: Vec<u8>, parent: &str| {
            server.post("/_admin/teams/import").multipart(
                axum_test::multipart::MultipartForm::new()
                    .add_part(
                        "bundle",
                        axum_test::multipart::Part::bytes(bytes)
                            .file_name("b.json")
                            .mime_type("application/json"),
                    )
                    .add_text("parent", parent.to_string()),
            )
        };

        for (rel_path, name, reason) in [
            ("we\"ird", "we\"ird", "Invalid team path segment"),
            ("ok", "ok\" } #", "Invalid team name"),
            ("_files", "_files", "Invalid team path segment"),
            ("ok/a b", "a b", "Invalid team path segment"),
            ("ok", "other", "does not match the last segment"),
            ("static", "static", "reserved directly under the root team"),
        ] {
            let response = post(bundle(rel_path, name), "").await;
            response.assert_status(StatusCode::BAD_REQUEST);
            assert!(response.text().contains(reason), "{rel_path:?} {name:?}");
            assert_eq!(
                crate::auth::get_sub_teams(sys, &[]).len(),
                0,
                "{rel_path:?} {name:?}"
            );
            assert!(crate::auth::invalid_team_names(sys).is_empty());
        }
        // An unusual target parent is "no such team", nothing written.
        let response = post(bundle("ok", "ok"), "we\"ird").await;
        response.assert_status_ok();
        assert!(response.text().contains("No such target parent team"));
        assert_eq!(crate::auth::get_sub_teams(sys, &[]).len(), 0);

        let response = post(bundle("ok.1", "ok.1"), "").await;
        response.assert_status_ok();
        assert!(crate::auth::resolve_team_path(sys, &["ok.1".to_string()]).is_some());
        server.get("/ok.1").await.assert_status_ok();
    }
}
