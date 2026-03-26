use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use tower_cookies::Cookies;

use crate::state::AppState;
use super::sparql;
use super::web;

pub fn routes() -> Router<AppState> {
    Router::new().route("/{*path}", get(content_get).post(content_post))
}

/// Parse a content path into (content_segments, view).
/// The view is the last segment starting with `_`, if any.
/// Returns (content_path_joined, optional_view).
fn parse_content_path(path: &str) -> (String, Option<String>) {
    let path = path.trim_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return (String::new(), None);
    }

    // Check if the last segment is a view (starts with _)
    let last = segments.last().unwrap();
    if last.starts_with('_') {
        let view = last.to_string();
        let content_segments = &segments[..segments.len() - 1];
        let content_path = content_segments.join("/");
        (content_path, Some(view))
    } else {
        let content_path = segments.join("/");
        (content_path, None)
    }
}

/// Resolve a content path to a dataset name.
/// For now, since there's only the root team and no subteam hierarchy,
/// the content path is just the dataset name (the last segment).
/// This can be extended later to walk a team tree.
fn resolve_dataset_name(content_path: &str) -> Option<String> {
    let segments: Vec<&str> = content_path.split('/').filter(|s| !s.is_empty()).collect();
    // For now, just use the last segment as the dataset name
    segments.last().map(|s| s.to_string())
}

async fn content_get(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(params): Query<sparql::SparqlQueryParams>,
    cookies: Cookies,
) -> Response {
    let (content_path, view) = parse_content_path(&path);

    let dataset_name = match resolve_dataset_name(&content_path) {
        Some(name) => name,
        None => {
            return (StatusCode::NOT_FOUND, "Not found".to_string()).into_response();
        }
    };

    match view.as_deref() {
        Some("_sparql") => {
            match sparql::sparql_query_get(&state, &dataset_name, &params).await {
                Ok(resp) => resp.into_response(),
                Err(e) => e.into_response(),
            }
        }
        Some("_query") => {
            match web::dataset_query(&state, &dataset_name, &cookies).await {
                Ok(html) => html.into_response(),
                Err(e) => e.into_response(),
            }
        }
        Some("_update") => {
            // GET not supported for update
            (StatusCode::METHOD_NOT_ALLOWED, "Use POST for SPARQL Update".to_string())
                .into_response()
        }
        Some(unknown) => {
            (StatusCode::NOT_FOUND, format!("Unknown view: {}", unknown)).into_response()
        }
        None => {
            // Default view: show dataset page (same as _query for now)
            match web::dataset_query(&state, &dataset_name, &cookies).await {
                Ok(html) => html.into_response(),
                Err(e) => e.into_response(),
            }
        }
    }
}

async fn content_post(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    _cookies: Cookies,
    body: String,
) -> Response {
    let (content_path, view) = parse_content_path(&path);

    let dataset_name = match resolve_dataset_name(&content_path) {
        Some(name) => name,
        None => {
            return (StatusCode::NOT_FOUND, "Not found".to_string()).into_response();
        }
    };

    match view.as_deref() {
        Some("_sparql") => {
            match sparql::sparql_query_post(&state, &dataset_name, &headers, &body).await {
                Ok(resp) => resp.into_response(),
                Err(e) => e.into_response(),
            }
        }
        Some("_update") => {
            match sparql::sparql_update_post(&state, &dataset_name, &headers, &body).await {
                Ok(status) => status.into_response(),
                Err(e) => e.into_response(),
            }
        }
        _ => {
            (StatusCode::METHOD_NOT_ALLOWED, "POST not supported for this path".to_string())
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_content_path_with_view() {
        let (content, view) = parse_content_path("my-dataset/_sparql");
        assert_eq!(content, "my-dataset");
        assert_eq!(view, Some("_sparql".to_string()));
    }

    #[test]
    fn test_parse_content_path_nested_with_view() {
        let (content, view) = parse_content_path("team-a/team-b/dataset/_query");
        assert_eq!(content, "team-a/team-b/dataset");
        assert_eq!(view, Some("_query".to_string()));
    }

    #[test]
    fn test_parse_content_path_no_view() {
        let (content, view) = parse_content_path("my-dataset");
        assert_eq!(content, "my-dataset");
        assert_eq!(view, None);
    }

    #[test]
    fn test_parse_content_path_empty() {
        let (content, view) = parse_content_path("");
        assert_eq!(content, "");
        assert_eq!(view, None);
    }

    #[test]
    fn test_resolve_dataset_name() {
        assert_eq!(resolve_dataset_name("my-dataset"), Some("my-dataset".to_string()));
        assert_eq!(resolve_dataset_name("team-a/team-b/dataset"), Some("dataset".to_string()));
        assert_eq!(resolve_dataset_name(""), None);
    }
}
