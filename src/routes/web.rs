use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Router, routing::get};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::auth;
use crate::state::AppState;
use crate::store::sparql_update;

const SESSION_COOKIE: &str = "mlipe_session";

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
                minijinja::context! {
                    name => short_name,
                    team => team_name,
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
            let session_id = state.session_store.create_session(form.username, user_iri);
            cookies.add(tower_cookies::Cookie::new(SESSION_COOKIE, session_id));
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
        cookies.remove(tower_cookies::Cookie::from(SESSION_COOKIE));
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

async fn create_dataset_web(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreateDatasetForm>,
) -> Response {
    // Require login
    if get_username(&cookies, &state).is_none() {
        return Redirect::to("/_login").into_response();
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Redirect::to("/").into_response();
    }

    let visibility = match form.visibility.as_str() {
        "LoggedUsers" => "LoggedUsersVisibility",
        "TeamOnly" => "TeamOnlyVisibility",
        _ => "PublicVisibility",
    };

    // Resolve team path to IRI
    let team_path = form.team.trim().to_string();
    let team_segments: Vec<String> = if team_path.is_empty() {
        Vec::new()
    } else {
        team_path.split('/').map(|s| s.to_string()).collect()
    };
    let team_iri = auth::resolve_team_path(&state.store_manager.system, &team_segments)
        .unwrap_or_else(|| "https://mlipe.2mia.org/teams/root".to_string());
    let team_iri = team_iri.trim_matches(|c| c == '<' || c == '>').to_string();

    // Qualify dataset name with team path
    let qualified_name = if team_path.is_empty() {
        format!("root/{}", name)
    } else {
        format!("{}/{}", team_path, name)
    };

    if state.store_manager.create_dataset(&qualified_name).is_ok() {
        let _ = state.store_manager.insert_dataset_metadata_full(
            &qualified_name,
            visibility,
            &team_iri,
        );
    }

    Redirect::to("/").into_response()
}

#[derive(Deserialize)]
struct DeleteDatasetForm {
    name: String,
}

async fn delete_dataset_web(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<DeleteDatasetForm>,
) -> Response {
    if get_username(&cookies, &state).is_none() {
        return Redirect::to("/_login").into_response();
    }

    let _ = state.store_manager.delete_dataset(&form.name);
    Redirect::to("/").into_response()
}

pub async fn dataset_query(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    cookies: &Cookies,
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
            url_prefix => url_prefix,
            breadcrumbs => breadcrumbs,
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

    // Check team visibility (root team is always visible to logged-in users)
    if !team_segments.is_empty() {
        let team_iri_check = auth::resolve_team_path(&state.store_manager.system, team_segments);
        if let Some(ref iri) = team_iri_check {
            if let Some(ref s) = session {
                if !auth::can_see_team(&state.store_manager.system, &s.user_iri, iri) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "You do not have access to this team".into(),
                    ));
                }
            } else {
                return Err((StatusCode::UNAUTHORIZED, "Login required".into()));
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

    // Resolve team IRI for permission checks
    let team_iri = auth::resolve_team_path(&state.store_manager.system, team_segments);

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
    let datasets = auth::get_team_datasets_by_path(&state.store_manager.system, team_segments);

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
    let all_files = super::files::list_files_recursive(state, &team_path_for_files);
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
                // Build display name and URL from qualified name
                let (team_prefix, short_name) = match d.name.rsplit_once('/') {
                    Some((team, name)) => {
                        let prefix = if team == "root" { String::new() } else { format!("/{}", team) };
                        (prefix, name.to_string())
                    }
                    None => (String::new(), d.name.clone()),
                };
                // Show relative path from current team for display
                let display = if team_path.is_empty() {
                    d.name.strip_prefix("root/").unwrap_or(&d.name).to_string()
                } else {
                    d.name.strip_prefix(&format!("{}/", team_path)).unwrap_or(&d.name).to_string()
                };
                minijinja::context! {
                    name => display,
                    url => format!("{}/_ds/{}/_query", team_prefix, short_name),
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
    let admin = is_root_admin(&session, &state);
    if !admin {
        return Redirect::to("/").into_response();
    }

    let all_users = auth::list_all_users(&state.store_manager.system);

    let tmpl = match state.templates.get_template("admin/users.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let html = match tmpl.render(minijinja::context! {
        username => session.map(|s| s.username),
        is_admin => true,
        users => all_users.iter().map(|u| minijinja::context! {
            username => u.username,
            teams => u.teams.iter().map(|t| &t.name).cloned().collect::<Vec<_>>().join(", "),
        }).collect::<Vec<_>>(),
        error => "",
        success => "",
    }) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Html(html).into_response()
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

    let username = form.username.trim().to_string();
    if username.is_empty() || form.password.is_empty() {
        return Redirect::to("/_admin/users").into_response();
    }

    // Check if user already exists
    if auth::find_user_by_username(&state.store_manager.system, &username).is_some() {
        return Redirect::to("/_admin/users").into_response();
    }

    let password_hash = auth::hash_password(&form.password);
    let user_iri = format!("https://mlipe.2mia.org/users/{}", username);

    // Find root team IRI
    let root_iri = auth::resolve_team_path(&state.store_manager.system, &[])
        .unwrap_or_else(|| "<https://mlipe.2mia.org/teams/root>".to_string());
    let root_clean = root_iri.trim_matches(|c| c == '<' || c == '>');

    let insert = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {{
            <{user_iri}> a mlipe:User ;
                mlipe:username "{username}" ;
                mlipe:passwordHash "{password_hash}" .
            <{root_clean}> mlipe:hasMember <{user_iri}> .
        }}
        "#,
    );
    let _ = sparql_update(&state.store_manager.system, &insert);

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

    if let Some((user_iri, _)) =
        auth::find_user_by_username(&state.store_manager.system, &form.username)
    {
        let iri = user_iri.trim_matches(|c| c == '<' || c == '>');
        let delete = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            DELETE WHERE {{ <{iri}> ?p ?o }}
            "#,
        );
        let _ = sparql_update(&state.store_manager.system, &delete);

        // Also remove team memberships pointing to this user
        let delete_refs = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            DELETE WHERE {{ ?team mlipe:hasMember <{iri}> }}
            "#,
        );
        let _ = sparql_update(&state.store_manager.system, &delete_refs);

        let delete_admin = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            DELETE WHERE {{ ?team mlipe:hasAdmin <{iri}> }}
            "#,
        );
        let _ = sparql_update(&state.store_manager.system, &delete_admin);
    }

    Redirect::to("/_admin/users").into_response()
}

#[derive(Deserialize)]
pub struct CreateTeamForm {
    pub name: String,
}

/// Create a sub-team under the given parent team segments.
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

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Redirect::to("/_teams").into_response();
    }

    let parent_iri = match auth::resolve_team_path(&state.store_manager.system, parent_segments) {
        Some(iri) => iri,
        None => return Redirect::to("/_teams").into_response(),
    };
    let parent_clean = parent_iri.trim_matches(|c| c == '<' || c == '>');

    let parent_path = parent_segments.join("/");
    let team_path = if parent_path.is_empty() {
        name.clone()
    } else {
        format!("{}/{}", parent_path, name)
    };
    let team_iri = format!("https://mlipe.2mia.org/teams/{}", team_path);

    let insert = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        INSERT DATA {{
            <{team_iri}> a mlipe:Team ;
                mlipe:teamName "{name}" ;
                mlipe:hasParentTeam <{parent_clean}> .
        }}
        "#,
    );
    let _ = sparql_update(&state.store_manager.system, &insert);

    // Redirect back to the parent team page
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
