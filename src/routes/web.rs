use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Router, routing::get};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::auth;
use crate::state::AppState;

const SESSION_COOKIE: &str = "mlipe_session";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/_login", get(login_page).post(login_submit))
        .route("/_logout", axum::routing::post(logout))
        .route("/_datasets/new", axum::routing::post(create_dataset_web))
        .route("/_users", get(users_list))
        .route("/_users/{username}", get(user_profile))
}

pub fn get_username(cookies: &Cookies, state: &AppState) -> Option<auth::Session> {
    let cookie = cookies.get(SESSION_COOKIE)?;
    state.session_store.get_session(cookie.value())
}

async fn index(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);

    let datasets = match &session {
        Some(s) => auth::get_user_datasets(&state.store_manager.system, &s.user_iri),
        None => auth::get_public_datasets(&state.store_manager.system),
    };

    let teams = match &session {
        Some(s) => auth::get_user_admin_teams(&state.store_manager.system, &s.user_iri),
        None => Vec::new(),
    };

    let tmpl = state
        .templates
        .get_template("index.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.as_ref().map(|s| s.username.clone()),
            datasets => datasets.iter().map(|d| minijinja::context! { name => d.name }).collect::<Vec<_>>(),
            teams => teams.iter().map(|t| minijinja::context! { iri => t.iri, name => t.name }).collect::<Vec<_>>(),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn login_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);

    let tmpl = state
        .templates
        .get_template("login.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
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
            let session_id =
                state
                    .session_store
                    .create_session(form.username, user_iri);
            cookies.add(tower_cookies::Cookie::new(
                SESSION_COOKIE,
                session_id,
            ));
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

async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Redirect {
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        state.session_store.remove_session(cookie.value());
        cookies.remove(tower_cookies::Cookie::from(SESSION_COOKIE));
    }
    Redirect::to("/")
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

    let team_iri = if form.team.is_empty() {
        "https://mlipe.2mia.org/teams/root".to_string()
    } else {
        let iri = form.team.trim().to_string();
        // Strip angle brackets if present
        iri.trim_matches(|c| c == '<' || c == '>').to_string()
    };

    if state.store_manager.create_dataset(&name).is_ok() {
        let _ = state
            .store_manager
            .insert_dataset_metadata_full(&name, visibility, &team_iri);
    }

    Redirect::to("/").into_response()
}

pub async fn dataset_query(
    state: &AppState,
    dataset_name: &str,
    cookies: &Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    // Check dataset exists
    if state.store_manager.get_dataset(dataset_name).is_none() {
        return Err((StatusCode::NOT_FOUND, format!("Dataset '{}' not found", dataset_name)));
    }

    let session = get_username(cookies, state);

    let tmpl = state
        .templates
        .get_template("dataset.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            dataset_name => dataset_name,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn users_list(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);

    let tmpl = state
        .templates
        .get_template("base.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

async fn user_profile(
    State(state): State<AppState>,
    axum::extract::Path(username): axum::extract::Path<String>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(&cookies, &state);

    let tmpl = state
        .templates
        .get_template("base.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            profile_username => username,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}
