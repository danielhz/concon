use axum::extract::{FromRequest, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use tower_cookies::Cookies;

use crate::state::AppState;
use super::files;
use super::sparql;
use super::web;

pub fn routes() -> Router<AppState> {
    Router::new().route("/{*path}", get(content_get).post(content_post))
}

/// Result of parsing a URL path.
#[derive(Debug, PartialEq)]
pub enum ParsedPath {
    /// /{team-path} — show team page
    TeamPage {
        team_segments: Vec<String>,
    },
    /// /{team-path}/_ds/{dataset}/{_view} — dataset view
    DatasetView {
        team_segments: Vec<String>,
        dataset: String,
        view: Option<String>,
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
    NewTeam {
        team_segments: Vec<String>,
    },
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
            Self::DatasetView { team_segments, dataset, .. } => {
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
            let view = if i < segments.len() && segments[i].starts_with('_') {
                Some(segments[i].to_string())
            } else {
                None
            };
            return ParsedPath::DatasetView { team_segments, dataset, view };
        }

        if seg == "_new_team" {
            return ParsedPath::NewTeam { team_segments };
        }

        if seg == "_files" {
            i += 1;
            // Check what follows: nothing, a view (_query, _upload), or a file UUID
            if i >= segments.len() {
                return ParsedPath::FileCatalog { team_segments, view: None };
            }
            let next = segments[i];
            if next.starts_with('_') {
                // It's a view on the catalog (_query, _upload, etc.)
                return ParsedPath::FileCatalog { team_segments, view: Some(next.to_string()) };
            }
            // It's a file UUID
            let file_id = next.to_string();
            i += 1;
            let action = if i < segments.len() && segments[i].starts_with('_') {
                Some(segments[i].to_string())
            } else {
                None
            };
            return ParsedPath::FileItem { team_segments, file_id, action };
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
    cookies: Cookies,
) -> Response {
    let parsed = parse_path(&path);

    // Require login for UI pages (team pages, dataset query UI, file browsing).
    // SPARQL endpoints remain accessible for programmatic access.
    let needs_login = match &parsed {
        ParsedPath::TeamPage { .. } => true,
        ParsedPath::DatasetView { view, .. } => view.as_deref() != Some("_sparql"),
        ParsedPath::FileCatalog { view, .. } => view.as_deref() != Some("_query"),
        ParsedPath::FileItem { .. } => true,
        ParsedPath::NewTeam { .. } => true,
    };

    if needs_login && web::get_username(&cookies, &state).is_none() {
        return axum::response::Redirect::to("/_login").into_response();
    }

    match &parsed {
        ParsedPath::TeamPage { team_segments } => {
            // Backward compatibility: if a single segment matches an existing
            // root-team dataset, show the dataset query page
            if team_segments.len() == 1 {
                let legacy_name = format!("root/{}", team_segments[0]);
                if state.store_manager.get_dataset(&legacy_name).is_some() {
                    return match web::dataset_query(&state, &legacy_name, &team_segments.join("/"), &cookies).await {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    };
                }
            }
            match web::team_page(&state, team_segments, &cookies).await {
                Ok(html) => html.into_response(),
                Err(e) => e.into_response(),
            }
        }
        ParsedPath::DatasetView { dataset, view, .. } => {
            let qualified = parsed.qualified_dataset_name().unwrap();
            match view.as_deref() {
                Some("_sparql") => {
                    match sparql::sparql_query_get(&state, &qualified, &params).await {
                        Ok(resp) => resp.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_query") | None => {
                    let url_prefix = build_dataset_url_prefix(&parsed);
                    match web::dataset_query(&state, &qualified, &url_prefix, &cookies).await {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_update") => {
                    (StatusCode::METHOD_NOT_ALLOWED, "Use POST for SPARQL Update".to_string())
                        .into_response()
                }
                Some(unknown) => {
                    (StatusCode::NOT_FOUND, format!("Unknown view: {}", unknown)).into_response()
                }
            }
        }
        ParsedPath::FileCatalog { team_segments, view } => {
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
                        None => (StatusCode::NOT_FOUND, "No file catalog for this team").into_response(),
                    }
                }
                Some("_upload") => {
                    (StatusCode::METHOD_NOT_ALLOWED, "Use POST for file upload".to_string())
                        .into_response()
                }
                None => {
                    match files::files_browse(&state, &team_path, &team_url_prefix, &cookies).await {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some(unknown) => {
                    (StatusCode::NOT_FOUND, format!("Unknown files view: {}", unknown)).into_response()
                }
            }
        }
        ParsedPath::FileItem { team_segments, file_id, action } => {
            let team_path = team_path_str(team_segments);
            let team_url_prefix = build_team_url_prefix(team_segments);
            match action.as_deref() {
                None => {
                    files::file_download(&state, &team_path, file_id).await
                }
                Some("_edit") => {
                    match files::file_edit_form(&state, &team_path, &team_url_prefix, file_id, &cookies).await {
                        Ok(html) => html.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                Some("_delete") => {
                    (StatusCode::METHOD_NOT_ALLOWED, "Use POST to delete files".to_string())
                        .into_response()
                }
                Some(unknown) => {
                    (StatusCode::NOT_FOUND, format!("Unknown file action: {}", unknown)).into_response()
                }
            }
        }
        ParsedPath::NewTeam { .. } => {
            (StatusCode::METHOD_NOT_ALLOWED, "Use POST to create a team".to_string())
                .into_response()
        }
    }
}

async fn content_post(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    cookies: Cookies,
    body: axum::body::Bytes,
) -> Response {
    let parsed = parse_path(&path);

    // SPARQL endpoints remain accessible; everything else requires login
    let needs_login = match &parsed {
        ParsedPath::DatasetView { view, .. } => {
            view.as_deref() != Some("_sparql") && view.as_deref() != Some("_update")
        }
        _ => true,
    };

    if needs_login && web::get_username(&cookies, &state).is_none() {
        return axum::response::Redirect::to("/_login").into_response();
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
                    match sparql::sparql_update_post(&state, &qualified, &headers, &body_str).await {
                        Ok(status) => status.into_response(),
                        Err(e) => e.into_response(),
                    }
                }
                _ => {
                    (StatusCode::METHOD_NOT_ALLOWED, "POST not supported for this dataset view".to_string())
                        .into_response()
                }
            }
        }
        ParsedPath::FileCatalog { team_segments, view } => {
            let team_path = team_path_str(team_segments);
            let team_url_prefix = build_team_url_prefix(team_segments);
            match view.as_deref() {
                Some("_upload") => {
                    // File uploads are handled by the dedicated route in web.rs
                    // This path shouldn't be reached, but redirect just in case
                    (StatusCode::BAD_REQUEST, "Use the file upload form".to_string())
                        .into_response()
                }
                _ => {
                    (StatusCode::METHOD_NOT_ALLOWED, "POST not supported for this files view".to_string())
                        .into_response()
                }
            }
        }
        ParsedPath::FileItem { team_segments, file_id, action } => {
            let team_path = team_path_str(team_segments);
            let team_url_prefix = build_team_url_prefix(team_segments);
            match action.as_deref() {
                Some("_edit") => {
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    let form: files::FileEditForm = serde_urlencoded::from_str(&body_str)
                        .unwrap_or_default();
                    files::file_edit_submit(&state, &team_path, &team_url_prefix, file_id, &cookies, form).await
                }
                Some("_delete") => {
                    files::file_delete(&state, &team_path, &team_url_prefix, file_id, &cookies).await
                }
                _ => {
                    (StatusCode::METHOD_NOT_ALLOWED, "POST not supported for this file path".to_string())
                        .into_response()
                }
            }
        }
        ParsedPath::NewTeam { team_segments } => {
            let body_str = String::from_utf8_lossy(&body).to_string();
            let form: web::CreateTeamForm = serde_urlencoded::from_str(&body_str)
                .unwrap_or(web::CreateTeamForm { name: String::new() });
            web::create_team(&state, team_segments, &cookies, form).await
        }
        _ => {
            (StatusCode::METHOD_NOT_ALLOWED, "POST not supported for this path".to_string())
                .into_response()
        }
    }
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
        ParsedPath::DatasetView { team_segments, dataset, .. } => {
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
            ParsedPath::TeamPage { team_segments: vec!["materials".into()] }
        );
        assert_eq!(
            parse_path("materials/atomistic"),
            ParsedPath::TeamPage { team_segments: vec!["materials".into(), "atomistic".into()] }
        );
    }

    #[test]
    fn test_parse_root_team() {
        assert_eq!(
            parse_path(""),
            ParsedPath::TeamPage { team_segments: vec![] }
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
        assert_eq!(p.qualified_dataset_name(), Some("materials/potentials".into()));

        let p = parse_path("_ds/my-dataset/_query");
        assert_eq!(p.qualified_dataset_name(), Some("root/my-dataset".into()));

        let p = parse_path("materials/atomistic/_ds/gap17/_sparql");
        assert_eq!(p.qualified_dataset_name(), Some("materials/atomistic/gap17".into()));
    }

    #[test]
    fn test_build_dataset_url_prefix() {
        let p = parse_path("materials/_ds/potentials/_query");
        assert_eq!(build_dataset_url_prefix(&p), "/materials/_ds/potentials");

        let p = parse_path("_ds/my-dataset/_query");
        assert_eq!(build_dataset_url_prefix(&p), "/_ds/my-dataset");
    }
}
