use axum::extract::{FromRequest, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use tower_cookies::Cookies;

use super::entity;
use super::files;
use super::ingest;
use super::ontology;
use super::sparql;
use super::web;

/// Query parameters for the Graph Store Protocol-style `_graph` endpoint.
#[derive(serde::Deserialize)]
pub struct GraphParams {
    pub graph: Option<String>,
}
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/{*path}",
        get(content_get)
            .post(content_post)
            .put(content_put)
            .delete(content_delete),
    )
}

/// Result of parsing a URL path.
#[derive(Debug, PartialEq)]
pub enum ParsedPath {
    /// /{team-path} — show team page
    TeamPage { team_segments: Vec<String> },
    /// /{team-path}/_ds/{dataset}/{_view} — dataset view
    DatasetView {
        team_segments: Vec<String>,
        dataset: String,
        view: Option<String>,
        /// Trailing non-`_` path segment after the view, e.g. the entity id in
        /// `_ds/{dataset}/_entity/{id}`. `None` for views without an argument.
        view_arg: Option<String>,
    },
    /// /{team-path}/_files/{_view} — file catalog
    FileCatalog {
        team_segments: Vec<String>,
        view: Option<String>,
    },
    /// /{team-path}/_files/{uuid}/{_action} — single file
    FileItem {
        team_segments: Vec<String>,
        file_id: String,
        action: Option<String>,
    },
    /// /{team-path}/_new_team — create sub-team action
    NewTeam { team_segments: Vec<String> },
}

impl ParsedPath {
    /// Get the team path as a joined string (e.g., "materials/atomistic").
    /// Empty string for root team.
    pub fn team_path(&self) -> String {
        match self {
            Self::TeamPage { team_segments }
            | Self::DatasetView { team_segments, .. }
            | Self::FileCatalog { team_segments, .. }
            | Self::FileItem { team_segments, .. }
            | Self::NewTeam { team_segments } => team_segments.join("/"),
        }
    }

    /// Get the team-qualified dataset name (e.g., "materials/potentials").
    /// Only valid for DatasetView.
    pub fn qualified_dataset_name(&self) -> Option<String> {
        match self {
            Self::DatasetView {
                team_segments,
                dataset,
                ..
            } => {
                if team_segments.is_empty() {
                    Some(format!("root/{}", dataset))
                } else {
                    Some(format!("{}/{}", team_segments.join("/"), dataset))
                }
            }
            _ => None,
        }
    }
}

/// Parse a URL path into a structured ParsedPath.
///
/// Rules:
/// - Non-`_` segments are team hierarchy
/// - `_ds` switches to dataset mode: next segment is dataset name, then optional view
/// - `_files` switches to file mode: next segment (if non-`_`) is file UUID, then optional action
/// - Other `_`-prefixed segments at the end are views/actions on the current context
pub fn parse_path(path: &str) -> ParsedPath {
    let path = path.trim_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut team_segments: Vec<String> = Vec::new();
    let mut i = 0;

    while i < segments.len() {
        let seg = segments[i];

        if seg == "_ds" {
            // Dataset mode
            i += 1;
            let dataset = if i < segments.len() {
                let d = segments[i].to_string();
                i += 1;
                d
            } else {
                return ParsedPath::TeamPage { team_segments };
            };
            // Collect all remaining _-prefixed segments as a compound view
            let mut view_parts = Vec::new();
            while i < segments.len() && segments[i].starts_with('_') {
                view_parts.push(segments[i].to_string());
                i += 1;
            }
            let view = if view_parts.is_empty() {
                None
            } else {
                Some(view_parts.join("/"))
            };
            // Capture a single trailing non-`_` segment as the view argument,
            // e.g. the entity id in `_ds/{dataset}/_entity/{id}`.
            let view_arg = if i < segments.len() && !segments[i].starts_with('_') {
                Some(segments[i].to_string())
            } else {
                None
            };
            return ParsedPath::DatasetView {
                team_segments,
                dataset,
                view,
                view_arg,
            };
        }

        if seg == "_new_team" {
            return ParsedPath::NewTeam { team_segments };
        }

        if seg == "_files" {
            i += 1;
            // Check what follows: nothing, a view (_query, _upload), or a file UUID
            if i >= segments.len() {
                return ParsedPath::FileCatalog {
                    team_segments,
                    view: None,
                };
            }
            let next = segments[i];
            if next.starts_with('_') {
                // It's a view on the catalog (_query, _upload, etc.)
                return ParsedPath::FileCatalog {
                    team_segments,
                    view: Some(next.to_string()),
                };
            }
            // It's a file UUID
            let file_id = next.to_string();
            i += 1;
            let action = if i < segments.len() && segments[i].starts_with('_') {
                Some(segments[i].to_string())
            } else {
                None
            };
            return ParsedPath::FileItem {
                team_segments,
                file_id,
                action,
            };
        }

        if seg.starts_with('_') {
            // Unknown _ segment at team level — treat as team page
            // (could be an error, but we'll be lenient)
            return ParsedPath::TeamPage { team_segments };
        }

        team_segments.push(seg.to_string());
        i += 1;
    }

    ParsedPath::TeamPage { team_segments }
}

async fn content_get(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(params): Query<sparql::SparqlQueryParams>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    headers: HeaderMap,
    cookies: Cookies,
) -> Response {
    let parsed = parse_path(&path);

    // Extract page parameter from query string
    let page: u32 = raw_query
        .as_deref()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("page="))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(1);

    // Require login for UI pages (team pages, dataset query UI, file browsing).
    // SPARQL endpoints remain accessible for programmatic access.
    let needs_login = match &parsed {
        ParsedPath::TeamPage { .. } => true,
        ParsedPath::DatasetView { view, .. } => {
            // Public read endpoints: the SPARQL endpoint, entity dereferencing,
            // and the ontology-document base view (`None`). The base view's
            // editor fallback re-checks login inside the handler.
            !matches!(view.as_deref(), Some("_sparql") | Some("_entity") | None)
        }
        ParsedPath::FileCatalog { view, .. } => view.as_deref() != Some("_query"),
        ParsedPath::FileItem { .. } => true,
        ParsedPath::NewTeam { .. } => true,
    };

    let session = web::get_username(&cookies, &state);

    // A non-root team that owns at least one Public dataset is a public landing
    // page: let anonymous visitors view it (team_page renders only public
    // content for them — no private datasets, sub-teams, members, or files).
    let anon_public_team = session.is_none()
        && matches!(&parsed, ParsedPath::TeamPage { team_segments } if !team_segments.is_empty())
        && team_has_public_dataset(&state, &parsed.team_path());

    if needs_login && session.is_none() && !anon_public_team {
        return axum::response::Redirect::to("/_login").into_response();
    }

    // Minimal Public-read gate (the cheap half of Epic B4): anonymous access
    // to a dataset's public-read views (`_sparql`, `_entity`, the base view)
    // is allowed only when the dataset is Public. Any anonymous DatasetView
    // reaching this point is a public-read view — the non-public views above
    // already required login — so a non-Public dataset is 404 to anonymous
    // (don't reveal its existence). Full team/role visibility is later B4.
    let anon_dataset = session.is_none() && matches!(&parsed, ParsedPath::DatasetView { .. });
    if anon_dataset
        && !crate::auth::is_dataset_public(
            &state.store_manager.system,
            &parsed.qualified_dataset_name().unwrap(),
        )
    {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    match &parsed {
        ParsedPath::TeamPage { team_segments } => {
            // Backward compatibility: if a single segment matches an existing
            // root-team dataset, show the dataset query page
            if team_segments.len() == 1 {
                let legacy_name = format!("root/{}", team_segments[0]);
                if state.store_manager.get_dataset(&legacy_name).is_some() {
                    return match web::dataset_query(
                        &state,
                        &legacy_name,
                        &team_segments.join("/"),
                        &cookies,
                    )
                    .await
                    {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    };
                }
            }
            match web::team_page(&state, team_segments, &cookies, page).await {
                Ok(html) => html.into_response(),
                Err(e) => e.into_response(),
            }
        }
        ParsedPath::DatasetView {
            view, view_arg, ..
        } => {
            let qualified = parsed.qualified_dataset_name().unwrap();
            match view.as_deref() {
                Some("_sparql") => {
                    match sparql::sparql_query_get(&state, &qualified, &params).await {
                        Ok(resp) => resp.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_entity") => match view_arg.as_deref() {
                    Some(id) => {
                        let url_prefix = build_dataset_url_prefix(&parsed);
                        let session = web::get_username(&cookies, &state);
                        let is_admin = web::is_root_admin(&session, &state);
                        let username = session.map(|s| s.username);
                        entity::serve_entity(
                            &state, &qualified, &url_prefix, id, &headers, username, is_admin,
                        )
                        .await
                    }
                    None => (StatusCode::NOT_FOUND, "Missing entity id".to_string()).into_response(),
                },
                Some("_query") => {
                    let url_prefix = build_dataset_url_prefix(&parsed);
                    match web::dataset_query(&state, &qualified, &url_prefix, &cookies).await {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                None => {
                    let url_prefix = build_dataset_url_prefix(&parsed);
                    match view_arg.as_deref() {
                        // Companion asset of the served document (e.g. stylesheet).
                        Some(asset) => ontology::serve_doc_asset(&state, &qualified, asset),
                        None => {
                            // Content negotiation at the base URL.
                            let fmt = entity::negotiate_format(&headers);
                            if fmt == "ttl" || fmt == "owl" {
                                ontology::dump_ontology_rdf(&state, &qualified, fmt)
                            } else if state.store_manager.has_doc(&qualified) {
                                ontology::serve_doc(&state, &qualified, &url_prefix)
                            } else if web::get_username(&cookies, &state).is_none() {
                                // No document: fall back to the editor, which is
                                // not public.
                                axum::response::Redirect::to("/_login").into_response()
                            } else {
                                match web::dataset_query(&state, &qualified, &url_prefix, &cookies)
                                    .await
                                {
                                    Ok(html) => html.into_response(),
                                    Err(e) => e.into_response(),
                                }
                            }
                        }
                    }
                }
                Some("_update") | Some("_shacl/_update") => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Use POST for SPARQL Update".to_string(),
                )
                    .into_response(),
                Some("_shacl/_query") => {
                    let shacl_store = state.store_manager.get_or_create_shacl_store(&qualified);
                    match shacl_store {
                        Ok(store) => {
                            match sparql::sparql_query_get_on_store(&store, &params).await {
                                Ok(resp) => resp.into_response(),
                                Err(e) => e.into_response(),
                            }
                        }
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
                    }
                }
                Some("_entities") => {
                    let url_prefix = build_dataset_url_prefix(&parsed);
                    match web::entity_editor(&state, &qualified, &url_prefix, &cookies).await {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some(unknown) => {
                    (StatusCode::NOT_FOUND, format!("Unknown view: {}", unknown)).into_response()
                }
            }
        }
        ParsedPath::FileCatalog {
            team_segments,
            view,
        } => {
            let team_path = team_path_str(team_segments);
            let team_url_prefix = build_team_url_prefix(team_segments);
            match view.as_deref() {
                Some("_query") => {
                    // SPARQL query on file catalog
                    let catalog = state.store_manager.get_file_catalog(&team_path);
                    match catalog {
                        Some(store) => {
                            match sparql::sparql_query_get_on_store(&store, &params).await {
                                Ok(resp) => resp.into_response(),
                                Err(e) => e.into_response(),
                            }
                        }
                        None => {
                            (StatusCode::NOT_FOUND, "No file catalog for this team").into_response()
                        }
                    }
                }
                Some("_upload") => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Use POST for file upload".to_string(),
                )
                    .into_response(),
                None => {
                    match files::files_browse(&state, &team_path, &team_url_prefix, &cookies).await
                    {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some(unknown) => (
                    StatusCode::NOT_FOUND,
                    format!("Unknown files view: {}", unknown),
                )
                    .into_response(),
            }
        }
        ParsedPath::FileItem {
            team_segments,
            file_id,
            action,
        } => {
            let team_path = team_path_str(team_segments);
            let team_url_prefix = build_team_url_prefix(team_segments);
            match action.as_deref() {
                None => files::file_download(&state, &team_path, file_id).await,
                Some("_view") => {
                    match files::file_view(&state, &team_path, &team_url_prefix, file_id, &cookies)
                        .await
                    {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_edit") => {
                    match files::file_edit_form(
                        &state,
                        &team_path,
                        &team_url_prefix,
                        file_id,
                        &cookies,
                    )
                    .await
                    {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_delete") => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Use POST to delete files".to_string(),
                )
                    .into_response(),
                Some(unknown) => (
                    StatusCode::NOT_FOUND,
                    format!("Unknown file action: {}", unknown),
                )
                    .into_response(),
            }
        }
        ParsedPath::NewTeam { .. } => (
            StatusCode::METHOD_NOT_ALLOWED,
            "Use POST to create a team".to_string(),
        )
            .into_response(),
    }
}

async fn content_post(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(gparams): Query<GraphParams>,
    headers: HeaderMap,
    cookies: Cookies,
    body: axum::body::Bytes,
) -> Response {
    let parsed = parse_path(&path);

    // SPARQL endpoints reach the handler without a login redirect; write views
    // (`_update`, `_shacl/_update`, `_graph`) enforce write auth inside the
    // handler (session or HTTP Basic), so they are exempt from the redirect too.
    let needs_login = match &parsed {
        ParsedPath::DatasetView { view, .. } => !matches!(
            view.as_deref(),
            Some("_sparql")
                | Some("_update")
                | Some("_graph")
                | Some("_shacl/_query")
                | Some("_shacl/_update")
        ),
        _ => true,
    };

    let session = web::get_username(&cookies, &state);

    if needs_login && session.is_none() {
        return axum::response::Redirect::to("/_login").into_response();
    }

    // Minimal Public-read gate for the read-via-POST endpoint: anonymous
    // `_sparql` POST is allowed only on Public datasets. Write views enforce
    // their own write auth (see `ingest::authorize_write`) in the handler.
    let anon_sparql_post = session.is_none()
        && matches!(&parsed, ParsedPath::DatasetView { view, .. } if view.as_deref() == Some("_sparql"));
    if anon_sparql_post
        && !crate::auth::is_dataset_public(
            &state.store_manager.system,
            &parsed.qualified_dataset_name().unwrap(),
        )
    {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    match &parsed {
        ParsedPath::DatasetView { view, .. } => {
            let qualified = parsed.qualified_dataset_name().unwrap();
            let body_str = String::from_utf8_lossy(&body).to_string();
            match view.as_deref() {
                Some("_sparql") | Some("_query") => {
                    match sparql::sparql_query_post(&state, &qualified, &headers, &body_str).await {
                        Ok(resp) => resp.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_update") => {
                    if let Err(r) =
                        ingest::authorize_write(&state, &headers, &cookies, &qualified)
                    {
                        return r;
                    }
                    match sparql::sparql_update_post(&state, &qualified, &headers, &body_str).await
                    {
                        Ok(status) => status.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_graph") => {
                    if let Err(r) =
                        ingest::authorize_write(&state, &headers, &cookies, &qualified)
                    {
                        return r;
                    }
                    ingest::post_graph(&state, &qualified, gparams.graph.as_deref(), &headers, &body)
                }
                Some("_shacl/_query") => {
                    let shacl_store = state.store_manager.get_or_create_shacl_store(&qualified);
                    match shacl_store {
                        Ok(store) => {
                            match sparql::sparql_query_post_on_store(&store, &headers, &body_str)
                                .await
                            {
                                Ok(resp) => resp.into_response(),
                                Err(e) => e.into_response(),
                            }
                        }
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
                    }
                }
                Some("_shacl/_update") => {
                    if let Err(r) =
                        ingest::authorize_write(&state, &headers, &cookies, &qualified)
                    {
                        return r;
                    }
                    let shacl_store = state.store_manager.get_or_create_shacl_store(&qualified);
                    match shacl_store {
                        Ok(store) => {
                            match sparql::sparql_update_post_on_store(&store, &headers, &body_str)
                                .await
                            {
                                Ok(status) => status.into_response(),
                                Err(e) => e.into_response(),
                            }
                        }
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
                    }
                }
                _ => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "POST not supported for this dataset view".to_string(),
                )
                    .into_response(),
            }
        }
        ParsedPath::FileCatalog {
            team_segments,
            view,
        } => {
            let team_path = team_path_str(team_segments);
            let body_str = String::from_utf8_lossy(&body).to_string();
            match view.as_deref() {
                Some("_query") => {
                    let catalog = state.store_manager.get_file_catalog(&team_path);
                    match catalog {
                        Some(store) => {
                            match sparql::sparql_query_post_on_store(&store, &headers, &body_str)
                                .await
                            {
                                Ok(resp) => resp.into_response(),
                                Err(e) => e.into_response(),
                            }
                        }
                        None => {
                            (StatusCode::NOT_FOUND, "No file catalog for this team").into_response()
                        }
                    }
                }
                Some("_upload") => (
                    StatusCode::BAD_REQUEST,
                    "Use the file upload form".to_string(),
                )
                    .into_response(),
                _ => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "POST not supported for this files view".to_string(),
                )
                    .into_response(),
            }
        }
        ParsedPath::FileItem {
            team_segments,
            file_id,
            action,
        } => {
            let team_path = team_path_str(team_segments);
            let team_url_prefix = build_team_url_prefix(team_segments);
            match action.as_deref() {
                Some("_edit") => {
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    let form: files::FileEditForm =
                        serde_urlencoded::from_str(&body_str).unwrap_or_default();
                    files::file_edit_submit(
                        &state,
                        &team_path,
                        &team_url_prefix,
                        file_id,
                        &cookies,
                        form,
                    )
                    .await
                }
                Some("_delete") => {
                    files::file_delete(&state, &team_path, &team_url_prefix, file_id, &cookies)
                        .await
                }
                _ => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "POST not supported for this file path".to_string(),
                )
                    .into_response(),
            }
        }
        ParsedPath::NewTeam { team_segments } => {
            let body_str = String::from_utf8_lossy(&body).to_string();
            let form: web::CreateTeamForm =
                serde_urlencoded::from_str(&body_str).unwrap_or(web::CreateTeamForm {
                    name: String::new(),
                });
            web::create_team(&state, team_segments, &cookies, form).await
        }
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            "POST not supported for this path".to_string(),
        )
            .into_response(),
    }
}

/// PUT — ingest writes: `_graph` (replace a named graph) and `_doc` (store the
/// curated document or a companion asset). Both require write authorization.
async fn content_put(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(gparams): Query<GraphParams>,
    headers: HeaderMap,
    cookies: Cookies,
    body: axum::body::Bytes,
) -> Response {
    let parsed = parse_path(&path);
    let ParsedPath::DatasetView { view, view_arg, .. } = &parsed else {
        return (StatusCode::METHOD_NOT_ALLOWED, "PUT not supported for this path").into_response();
    };
    let qualified = parsed.qualified_dataset_name().unwrap();
    match view.as_deref() {
        Some("_graph") => {
            if let Err(r) = ingest::authorize_write(&state, &headers, &cookies, &qualified) {
                return r;
            }
            ingest::put_graph(&state, &qualified, gparams.graph.as_deref(), &headers, &body)
        }
        Some("_doc") => {
            if let Err(r) = ingest::authorize_write(&state, &headers, &cookies, &qualified) {
                return r;
            }
            ingest::put_doc(&state, &qualified, view_arg.as_deref(), &body)
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, "PUT not supported for this view").into_response(),
    }
}

/// DELETE — clear a named graph (`_graph`). Requires write authorization.
async fn content_delete(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(gparams): Query<GraphParams>,
    headers: HeaderMap,
    cookies: Cookies,
) -> Response {
    let parsed = parse_path(&path);
    let ParsedPath::DatasetView { view, .. } = &parsed else {
        return (StatusCode::METHOD_NOT_ALLOWED, "DELETE not supported for this path")
            .into_response();
    };
    let qualified = parsed.qualified_dataset_name().unwrap();
    match view.as_deref() {
        Some("_graph") => {
            if let Err(r) = ingest::authorize_write(&state, &headers, &cookies, &qualified) {
                return r;
            }
            ingest::delete_graph(&state, &qualified, gparams.graph.as_deref())
        }
        _ => {
            (StatusCode::METHOD_NOT_ALLOWED, "DELETE not supported for this view").into_response()
        }
    }
}

/// Whether the team at `team_path` (e.g. "mlips") owns at least one Public
/// dataset — i.e. its page is a public landing anonymous visitors may view.
fn team_has_public_dataset(state: &AppState, team_path: &str) -> bool {
    if team_path.is_empty() {
        return false;
    }
    let prefix = format!("{team_path}/");
    crate::auth::get_public_datasets(&state.store_manager.system)
        .iter()
        .any(|d| d.name.starts_with(&prefix))
}

/// Build team path string: "root" for empty segments, otherwise joined.
fn team_path_str(segments: &[String]) -> String {
    if segments.is_empty() {
        "root".to_string()
    } else {
        segments.join("/")
    }
}

/// Build URL prefix for team (e.g., "/materials" or "" for root).
fn build_team_url_prefix(segments: &[String]) -> String {
    if segments.is_empty() {
        String::new()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Build a URL prefix for dataset views (used in templates for YASGUI endpoint).
/// E.g., "/materials/_ds/potentials" for team materials, dataset potentials.
fn build_dataset_url_prefix(parsed: &ParsedPath) -> String {
    match parsed {
        ParsedPath::DatasetView {
            team_segments,
            dataset,
            ..
        } => {
            if team_segments.is_empty() {
                format!("/_ds/{}", dataset)
            } else {
                format!("/{}/_ds/{}", team_segments.join("/"), dataset)
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_team_page() {
        assert_eq!(
            parse_path("materials"),
            ParsedPath::TeamPage {
                team_segments: vec!["materials".into()]
            }
        );
        assert_eq!(
            parse_path("materials/atomistic"),
            ParsedPath::TeamPage {
                team_segments: vec!["materials".into(), "atomistic".into()]
            }
        );
    }

    #[test]
    fn test_parse_root_team() {
        assert_eq!(
            parse_path(""),
            ParsedPath::TeamPage {
                team_segments: vec![]
            }
        );
    }

    #[test]
    fn test_parse_dataset_view() {
        assert_eq!(
            parse_path("materials/_ds/potentials/_query"),
            ParsedPath::DatasetView {
                team_segments: vec!["materials".into()],
                dataset: "potentials".into(),
                view: Some("_query".into()),
                view_arg: None,
            }
        );
    }

    #[test]
    fn test_parse_dataset_default_view() {
        assert_eq!(
            parse_path("materials/_ds/potentials"),
            ParsedPath::DatasetView {
                team_segments: vec!["materials".into()],
                dataset: "potentials".into(),
                view: None,
                view_arg: None,
            }
        );
    }

    #[test]
    fn test_parse_root_dataset() {
        assert_eq!(
            parse_path("_ds/my-dataset/_sparql"),
            ParsedPath::DatasetView {
                team_segments: vec![],
                dataset: "my-dataset".into(),
                view: Some("_sparql".into()),
                view_arg: None,
            }
        );
    }

    #[test]
    fn test_parse_nested_dataset() {
        assert_eq!(
            parse_path("materials/atomistic/_ds/potentials/_update"),
            ParsedPath::DatasetView {
                team_segments: vec!["materials".into(), "atomistic".into()],
                dataset: "potentials".into(),
                view: Some("_update".into()),
                view_arg: None,
            }
        );
    }

    #[test]
    fn test_parse_files_browse() {
        assert_eq!(
            parse_path("materials/_files"),
            ParsedPath::FileCatalog {
                team_segments: vec!["materials".into()],
                view: None,
            }
        );
    }

    #[test]
    fn test_parse_files_query() {
        assert_eq!(
            parse_path("materials/_files/_query"),
            ParsedPath::FileCatalog {
                team_segments: vec!["materials".into()],
                view: Some("_query".into()),
            }
        );
    }

    #[test]
    fn test_parse_files_upload() {
        assert_eq!(
            parse_path("materials/_files/_upload"),
            ParsedPath::FileCatalog {
                team_segments: vec!["materials".into()],
                view: Some("_upload".into()),
            }
        );
    }

    #[test]
    fn test_parse_file_download() {
        assert_eq!(
            parse_path("materials/_files/550e8400-e29b-41d4-a716-446655440000"),
            ParsedPath::FileItem {
                team_segments: vec!["materials".into()],
                file_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                action: None,
            }
        );
    }

    #[test]
    fn test_parse_file_edit() {
        assert_eq!(
            parse_path("materials/_files/550e8400/_edit"),
            ParsedPath::FileItem {
                team_segments: vec!["materials".into()],
                file_id: "550e8400".into(),
                action: Some("_edit".into()),
            }
        );
    }

    #[test]
    fn test_parse_file_delete() {
        assert_eq!(
            parse_path("materials/_files/550e8400/_delete"),
            ParsedPath::FileItem {
                team_segments: vec!["materials".into()],
                file_id: "550e8400".into(),
                action: Some("_delete".into()),
            }
        );
    }

    #[test]
    fn test_parse_root_files() {
        assert_eq!(
            parse_path("_files"),
            ParsedPath::FileCatalog {
                team_segments: vec![],
                view: None,
            }
        );
    }

    #[test]
    fn test_qualified_dataset_name() {
        let p = parse_path("materials/_ds/potentials/_query");
        assert_eq!(
            p.qualified_dataset_name(),
            Some("materials/potentials".into())
        );

        let p = parse_path("_ds/my-dataset/_query");
        assert_eq!(p.qualified_dataset_name(), Some("root/my-dataset".into()));

        let p = parse_path("materials/atomistic/_ds/gap17/_sparql");
        assert_eq!(
            p.qualified_dataset_name(),
            Some("materials/atomistic/gap17".into())
        );
    }

    #[test]
    fn test_build_dataset_url_prefix() {
        let p = parse_path("materials/_ds/potentials/_query");
        assert_eq!(build_dataset_url_prefix(&p), "/materials/_ds/potentials");

        let p = parse_path("_ds/my-dataset/_query");
        assert_eq!(build_dataset_url_prefix(&p), "/_ds/my-dataset");
    }

    #[test]
    fn test_parse_shacl_query_path() {
        assert_eq!(
            parse_path("materials/_ds/pot/_shacl/_query"),
            ParsedPath::DatasetView {
                team_segments: vec!["materials".into()],
                dataset: "pot".into(),
                view: Some("_shacl/_query".into()),
                view_arg: None,
            }
        );
    }

    #[test]
    fn test_parse_shacl_update_path() {
        assert_eq!(
            parse_path("_ds/my-ds/_shacl/_update"),
            ParsedPath::DatasetView {
                team_segments: vec![],
                dataset: "my-ds".into(),
                view: Some("_shacl/_update".into()),
                view_arg: None,
            }
        );
    }

    #[test]
    fn test_parse_entities_view() {
        assert_eq!(
            parse_path("materials/_ds/pot/_entities"),
            ParsedPath::DatasetView {
                team_segments: vec!["materials".into()],
                dataset: "pot".into(),
                view: Some("_entities".into()),
                view_arg: None,
            }
        );
    }

    #[tokio::test]
    async fn test_anonymous_public_read_gate() {
        use crate::routes::create_router;
        use crate::state::AppState;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        // Public dataset: anonymous reads allowed.
        state.store_manager.create_dataset("root/pub").unwrap();
        state.store_manager.insert_dataset_metadata("root/pub").unwrap();
        // Non-public dataset: anonymous reads denied (404, no existence leak).
        state.store_manager.create_dataset("root/secret").unwrap();
        state
            .store_manager
            .insert_dataset_metadata_with_visibility("root/secret", "LoggedUsersVisibility")
            .unwrap();

        let server = TestServer::new(create_router(state));

        // _sparql GET: public → 200, non-public → 404.
        let r = server
            .get("/_ds/pub/_sparql")
            .add_query_param("query", "ASK {}")
            .await;
        r.assert_status_ok();
        let r = server
            .get("/_ds/secret/_sparql")
            .add_query_param("query", "ASK {}")
            .await;
        r.assert_status(StatusCode::NOT_FOUND);

        // _sparql POST on non-public → 404.
        let r = server.post("/_ds/secret/_sparql").text("ASK {}").await;
        r.assert_status(StatusCode::NOT_FOUND);

        // Entity dereferencing on a non-public dataset → 404 to anonymous.
        let r = server.get("/_ds/secret/_entity/foo").await;
        r.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_anonymous_public_team_landing() {
        use crate::routes::create_router;
        use crate::state::AppState;
        use crate::store::sparql_update;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        let sys = &state.store_manager.system;
        sparql_update(
            sys,
            r#"PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
               INSERT DATA {
                 <https://mlipe.2mia.org/teams/root> a mlipe:Team ; mlipe:teamName "root" .
                 <https://mlipe.2mia.org/teams/mlips> a mlipe:Team ; mlipe:teamName "mlips" ;
                   mlipe:hasParentTeam <https://mlipe.2mia.org/teams/root> .
                 <https://mlipe.2mia.org/teams/secret> a mlipe:Team ; mlipe:teamName "secret" ;
                   mlipe:hasParentTeam <https://mlipe.2mia.org/teams/root> .
               }"#,
        )
        .unwrap();
        // A Public dataset in team "mlips"; a non-public one in team "secret".
        state.store_manager.create_dataset("mlips/mlips").unwrap();
        state
            .store_manager
            .insert_dataset_metadata_full(
                "mlips/mlips",
                "PublicVisibility",
                "https://mlipe.2mia.org/teams/mlips",
            )
            .unwrap();
        state.store_manager.create_dataset("secret/priv").unwrap();
        state
            .store_manager
            .insert_dataset_metadata_with_visibility("secret/priv", "LoggedUsersVisibility")
            .unwrap();

        let server = TestServer::new(create_router(state));

        // Anonymous can view the public team landing; it lists the dataset with
        // documentation + query links. (URL slashes are HTML-escaped to `&#x2f;`
        // by the template — harmless in hrefs — so assert on escaping-robust
        // tokens.)
        let r = server.get("/mlips/").await;
        r.assert_status_ok();
        let body = r.text();
        assert!(body.contains(">mlips</a>"), "dataset listed");
        assert!(body.contains("Query (YASGUI)"), "query link present");
        assert!(body.contains("_query?query="), "example query deep links present");

        // The home page surfaces the public dataset with the same links.
        let home = server.get("/").await;
        home.assert_status_ok();
        let home = home.text();
        assert!(home.contains("Public datasets") && home.contains("_query?query="));

        // A team with no Public dataset is not anonymously viewable → login.
        let r = server.get("/secret/").await;
        r.assert_status(StatusCode::SEE_OTHER);
    }

    #[test]
    fn test_parse_entity_view_with_id() {
        assert_eq!(
            parse_path("mlips/_ds/mlips/_entity/kumar2025"),
            ParsedPath::DatasetView {
                team_segments: vec!["mlips".into()],
                dataset: "mlips".into(),
                view: Some("_entity".into()),
                view_arg: Some("kumar2025".into()),
            }
        );
    }

    #[test]
    fn test_parse_entity_view_without_id() {
        assert_eq!(
            parse_path("mlips/_ds/mlips/_entity"),
            ParsedPath::DatasetView {
                team_segments: vec!["mlips".into()],
                dataset: "mlips".into(),
                view: Some("_entity".into()),
                view_arg: None,
            }
        );
    }
}
