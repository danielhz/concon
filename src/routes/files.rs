use axum::body::Body;
use axum::extract::Multipart;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use oxigraph::sparql::QueryResults;
use serde::Deserialize;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::auth::{self, FileAction};
use crate::state::AppState;
use super::web::get_username;

/// Browse files for a team.
pub async fn files_browse(
    state: &AppState,
    team_path: &str,
    team_url_prefix: &str,
    cookies: &Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(cookies, state);
    let admin = super::web::is_root_admin(&session, state);

    let files = list_files_from_catalog(state, team_path);

    let can_upload = session.as_ref().map_or(false, |s| {
        if let Some(team_iri) = resolve_team_iri(state, team_path) {
            auth::can_access_files(&state.store_manager.system, &s.user_iri, &team_iri, FileAction::Write)
        } else {
            false
        }
    });

    let can_delete = session.as_ref().map_or(false, |s| {
        if let Some(team_iri) = resolve_team_iri(state, team_path) {
            auth::can_access_files(&state.store_manager.system, &s.user_iri, &team_iri, FileAction::Delete)
        } else {
            false
        }
    });

    let tmpl = state
        .templates
        .get_template("files_browse.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            team_path => team_path,
            team_url_prefix => team_url_prefix,
            files => files,
            can_upload => can_upload,
            can_delete => can_delete,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

/// Upload a file (POST, multipart).
pub async fn files_upload(
    state: &AppState,
    team_path: &str,
    team_url_prefix: &str,
    cookies: &Cookies,
    mut multipart: Multipart,
) -> Response {
    let session = match get_username(cookies, state) {
        Some(s) => s,
        None => return Redirect::to("/_login").into_response(),
    };

    let team_iri = match resolve_team_iri(state, team_path) {
        Some(iri) => iri,
        None => return (StatusCode::NOT_FOUND, "Team not found").into_response(),
    };

    if !auth::can_access_files(&state.store_manager.system, &session.user_iri, &team_iri, FileAction::Write) {
        return (StatusCode::FORBIDDEN, "Not authorized to upload files").into_response();
    }

    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name = String::new();
    let mut title = String::new();
    let mut authors = String::new();
    let mut year = String::new();
    let mut doi = String::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                file_name = field.file_name().unwrap_or("unknown.pdf").to_string();
                let content_type = field.content_type().unwrap_or("application/octet-stream").to_string();
                if content_type != "application/pdf" {
                    return (StatusCode::BAD_REQUEST, "Only PDF files are accepted").into_response();
                }
                match field.bytes().await {
                    Ok(bytes) => file_data = Some(bytes.to_vec()),
                    Err(e) => return (StatusCode::BAD_REQUEST, format!("Failed to read file: {}", e)).into_response(),
                }
            }
            "title" => { title = field.text().await.unwrap_or_default(); }
            "authors" => { authors = field.text().await.unwrap_or_default(); }
            "year" => { year = field.text().await.unwrap_or_default(); }
            "doi" => { doi = field.text().await.unwrap_or_default(); }
            _ => {}
        }
    }

    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => return (StatusCode::BAD_REQUEST, "No file provided").into_response(),
    };

    let file_size = data.len();
    let uuid = Uuid::new_v4().to_string();

    // Save file to disk
    let file_dir = state.files_dir.join(team_path);
    if let Err(e) = std::fs::create_dir_all(&file_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create directory: {}", e)).into_response();
    }

    let file_path = file_dir.join(format!("{}.pdf", uuid));
    if let Err(e) = std::fs::write(&file_path, &data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write file: {}", e)).into_response();
    }

    // Insert metadata into catalog
    let catalog = match state.store_manager.get_or_create_file_catalog(team_path) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to open catalog: {}", e)).into_response(),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let user_iri = session.user_iri.trim_matches(|c| c == '<' || c == '>');

    // Escape quotes in metadata strings
    let title_escaped = title.replace('"', r#"\""#);
    let authors_escaped = authors.replace('"', r#"\""#);
    let file_name_escaped = file_name.replace('"', r#"\""#);
    let doi_escaped = doi.replace('"', r#"\""#);

    let insert = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
        INSERT DATA {{
            <https://mlipe.2mia.org/files/{uuid}> a mlipe:File ;
                mlipe:fileName "{file_name_escaped}" ;
                mlipe:fileTitle "{title_escaped}" ;
                mlipe:fileAuthors "{authors_escaped}" ;
                mlipe:fileYear "{year}" ;
                mlipe:fileDOI "{doi_escaped}" ;
                mlipe:fileSize {file_size} ;
                mlipe:mimeType "application/pdf" ;
                mlipe:uploadedBy <{user_iri}> ;
                mlipe:uploadedAt "{now}"^^xsd:dateTime .
        }}
        "#,
    );

    if let Err(e) = catalog.update(&insert) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to insert metadata: {}", e)).into_response();
    }

    Redirect::to(&format!("{}/_files", team_url_prefix)).into_response()
}

/// Download a file by UUID.
pub async fn file_download(
    state: &AppState,
    team_path: &str,
    file_id: &str,
) -> Response {
    // Get original filename from catalog
    let original_name = get_file_metadata_field(state, team_path, file_id, "mlipe:fileName")
        .unwrap_or_else(|| format!("{}.pdf", file_id));

    let file_path = state.files_dir.join(team_path).join(format!("{}.pdf", file_id));

    match tokio::fs::read(&file_path).await {
        Ok(data) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, "application/pdf".parse().unwrap());
            headers.insert(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", original_name).parse().unwrap(),
            );
            (headers, Body::from(data)).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "File not found on disk").into_response(),
    }
}

/// Show file metadata edit form (GET).
pub async fn file_edit_form(
    state: &AppState,
    team_path: &str,
    team_url_prefix: &str,
    file_id: &str,
    cookies: &Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = match get_username(cookies, state) {
        Some(s) => s,
        None => return Err((StatusCode::UNAUTHORIZED, "Login required".into())),
    };

    let team_iri = resolve_team_iri(state, team_path)
        .ok_or((StatusCode::NOT_FOUND, "Team not found".into()))?;

    if !auth::can_access_files(&state.store_manager.system, &session.user_iri, &team_iri, FileAction::Write) {
        return Err((StatusCode::FORBIDDEN, "Not authorized".into()));
    }

    let meta = get_file_all_metadata(state, team_path, file_id)
        .ok_or((StatusCode::NOT_FOUND, format!("File '{}' not found", file_id)))?;

    let tmpl = state.templates.get_template("file_edit.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.username,
            team_path => team_path,
            team_url_prefix => team_url_prefix,
            file_id => file_id,
            file_name => meta.file_name,
            title => meta.title,
            authors => meta.authors,
            year => meta.year,
            doi => meta.doi,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

#[derive(Deserialize)]
pub struct FileEditForm {
    pub title: String,
    pub authors: String,
    pub year: String,
    pub doi: String,
}

/// Submit file metadata edit (POST).
pub async fn file_edit_submit(
    state: &AppState,
    team_path: &str,
    team_url_prefix: &str,
    file_id: &str,
    cookies: &Cookies,
    form: FileEditForm,
) -> Response {
    let session = match get_username(cookies, state) {
        Some(s) => s,
        None => return Redirect::to("/_login").into_response(),
    };

    let team_iri = match resolve_team_iri(state, team_path) {
        Some(iri) => iri,
        None => return (StatusCode::NOT_FOUND, "Team not found").into_response(),
    };

    if !auth::can_access_files(&state.store_manager.system, &session.user_iri, &team_iri, FileAction::Write) {
        return (StatusCode::FORBIDDEN, "Not authorized").into_response();
    }

    let catalog = match state.store_manager.get_file_catalog(team_path) {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, "File catalog not found").into_response(),
    };

    let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);

    // Update editable fields
    let title_escaped = form.title.replace('"', r#"\""#);
    let authors_escaped = form.authors.replace('"', r#"\""#);
    let doi_escaped = form.doi.replace('"', r#"\""#);

    let update = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        DELETE {{
            <{file_iri}> mlipe:fileTitle ?oldTitle ;
                         mlipe:fileAuthors ?oldAuthors ;
                         mlipe:fileYear ?oldYear ;
                         mlipe:fileDOI ?oldDoi .
        }}
        INSERT {{
            <{file_iri}> mlipe:fileTitle "{title_escaped}" ;
                         mlipe:fileAuthors "{authors_escaped}" ;
                         mlipe:fileYear "{year}" ;
                         mlipe:fileDOI "{doi_escaped}" .
        }}
        WHERE {{
            OPTIONAL {{ <{file_iri}> mlipe:fileTitle ?oldTitle }}
            OPTIONAL {{ <{file_iri}> mlipe:fileAuthors ?oldAuthors }}
            OPTIONAL {{ <{file_iri}> mlipe:fileYear ?oldYear }}
            OPTIONAL {{ <{file_iri}> mlipe:fileDOI ?oldDoi }}
        }}
        "#,
        year = form.year,
    );

    if let Err(e) = catalog.update(&update) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update: {}", e)).into_response();
    }

    Redirect::to(&format!("{}/_files", team_url_prefix)).into_response()
}

/// Delete a file (POST).
pub async fn file_delete(
    state: &AppState,
    team_path: &str,
    team_url_prefix: &str,
    file_id: &str,
    cookies: &Cookies,
) -> Response {
    let session = match get_username(cookies, state) {
        Some(s) => s,
        None => return Redirect::to("/_login").into_response(),
    };

    let team_iri = match resolve_team_iri(state, team_path) {
        Some(iri) => iri,
        None => return (StatusCode::NOT_FOUND, "Team not found").into_response(),
    };

    if !auth::can_access_files(&state.store_manager.system, &session.user_iri, &team_iri, FileAction::Delete) {
        return (StatusCode::FORBIDDEN, "Not authorized to delete files").into_response();
    }

    // Remove from catalog
    if let Some(catalog) = state.store_manager.get_file_catalog(team_path) {
        let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);
        let delete = format!(
            r#"
            PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
            DELETE WHERE {{
                <{file_iri}> ?p ?o .
            }}
            "#,
        );
        let _ = catalog.update(&delete);
    }

    // Remove from disk
    let file_path = state.files_dir.join(team_path).join(format!("{}.pdf", file_id));
    let _ = std::fs::remove_file(&file_path);

    Redirect::to(&format!("{}/_files", team_url_prefix)).into_response()
}

// ─── Helpers ────────────────────────────────────────────────────────

fn resolve_team_iri(state: &AppState, team_path: &str) -> Option<String> {
    if team_path == "root" || team_path.is_empty() {
        auth::resolve_team_path(&state.store_manager.system, &[])
    } else {
        let segments: Vec<String> = team_path.split('/').map(|s| s.to_string()).collect();
        auth::resolve_team_path(&state.store_manager.system, &segments)
    }
}

struct FileMeta {
    file_name: String,
    title: String,
    authors: String,
    year: String,
    doi: String,
}

fn get_file_all_metadata(state: &AppState, team_path: &str, file_id: &str) -> Option<FileMeta> {
    let catalog = state.store_manager.get_file_catalog(team_path)?;
    let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);

    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?fileName ?title ?authors ?year ?doi WHERE {{
            <{file_iri}> a mlipe:File .
            OPTIONAL {{ <{file_iri}> mlipe:fileName ?fileName }}
            OPTIONAL {{ <{file_iri}> mlipe:fileTitle ?title }}
            OPTIONAL {{ <{file_iri}> mlipe:fileAuthors ?authors }}
            OPTIONAL {{ <{file_iri}> mlipe:fileYear ?year }}
            OPTIONAL {{ <{file_iri}> mlipe:fileDOI ?doi }}
        }}
        LIMIT 1
        "#,
    );

    if let Ok(QueryResults::Solutions(solutions)) = catalog.query(&query) {
        for solution in solutions.flatten() {
            return Some(FileMeta {
                file_name: solution.get("fileName").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                title: solution.get("title").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                authors: solution.get("authors").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                year: solution.get("year").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                doi: solution.get("doi").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
            });
        }
    }

    None
}

fn get_file_metadata_field(state: &AppState, team_path: &str, file_id: &str, field: &str) -> Option<String> {
    let catalog = state.store_manager.get_file_catalog(team_path)?;
    let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);

    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?val WHERE {{
            <{file_iri}> {field} ?val .
        }}
        LIMIT 1
        "#,
    );

    if let Ok(QueryResults::Solutions(solutions)) = catalog.query(&query) {
        for solution in solutions.flatten() {
            return solution.get("val").map(|v| auth::strip_literal(&v.to_string()));
        }
    }

    None
}

fn list_files_from_catalog(state: &AppState, team_path: &str) -> Vec<minijinja::Value> {
    let catalog = match state.store_manager.get_file_catalog(team_path) {
        Some(c) => c,
        None => return Vec::new(),
    };

    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        SELECT ?file ?fileName ?title ?authors ?year ?doi ?size ?uploadedAt WHERE {
            ?file a mlipe:File .
            OPTIONAL { ?file mlipe:fileName ?fileName }
            OPTIONAL { ?file mlipe:fileTitle ?title }
            OPTIONAL { ?file mlipe:fileAuthors ?authors }
            OPTIONAL { ?file mlipe:fileYear ?year }
            OPTIONAL { ?file mlipe:fileDOI ?doi }
            OPTIONAL { ?file mlipe:fileSize ?size }
            OPTIONAL { ?file mlipe:uploadedAt ?uploadedAt }
        }
        ORDER BY DESC(?uploadedAt)
    "#;

    let mut files = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = catalog.query(query) {
        for solution in solutions.flatten() {
            let file_iri = solution.get("file").map(|v| v.to_string()).unwrap_or_default();
            // Extract UUID from IRI
            let uuid = file_iri
                .rsplit('/')
                .next()
                .unwrap_or("")
                .trim_matches('>');

            files.push(minijinja::context! {
                uuid => uuid,
                file_name => solution.get("fileName").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                title => solution.get("title").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                authors => solution.get("authors").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                year => solution.get("year").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                doi => solution.get("doi").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                size => solution.get("size").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
                uploaded_at => solution.get("uploadedAt").map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default(),
            });
        }
    }

    files
}
