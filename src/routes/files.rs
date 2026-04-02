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

    // Build breadcrumbs from team path
    let team_segments: Vec<&str> = if team_path == "root" {
        Vec::new()
    } else {
        team_path.split('/').filter(|s| !s.is_empty()).collect()
    };
    let breadcrumbs: Vec<_> = team_segments.iter().enumerate().map(|(i, name)| {
        let url = format!("/{}", team_segments[..=i].join("/"));
        minijinja::context! { name => *name, url => url }
    }).collect();

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
            breadcrumbs => breadcrumbs,
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
    let original_name = get_file_metadata_field(state, team_path, file_id, "mlipe:fileName", "mlipe")
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

/// Show file metadata detail page (GET).
pub async fn file_view(
    state: &AppState,
    team_path: &str,
    team_url_prefix: &str,
    file_id: &str,
    cookies: &Cookies,
) -> Result<Html<String>, (StatusCode, String)> {
    let session = get_username(cookies, state);
    let admin = super::web::is_root_admin(&session, state);

    let meta = get_file_all_metadata(state, team_path, file_id)
        .ok_or((StatusCode::NOT_FOUND, format!("File '{}' not found", file_id)))?;

    let references = get_file_references(state, team_path, file_id);

    let can_edit = session.as_ref().map_or(false, |s| {
        if let Some(team_iri) = resolve_team_iri(state, team_path) {
            auth::can_access_files(&state.store_manager.system, &s.user_iri, &team_iri, FileAction::Write)
        } else {
            false
        }
    });

    let tmpl = state.templates.get_template("file_view.html")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let html = tmpl
        .render(minijinja::context! {
            username => session.map(|s| s.username),
            is_admin => admin,
            team_path => team_path,
            team_url_prefix => team_url_prefix,
            file_id => file_id,
            file_name => meta.file_name,
            title => meta.title,
            authors => meta.authors,
            year => meta.year,
            doi => meta.doi,
            abstract_text => meta.abstract_text,
            journal => meta.journal,
            volume => meta.volume,
            issue => meta.issue,
            pages => meta.pages,
            publisher => meta.publisher,
            issn => meta.issn,
            arxiv_id => meta.arxiv_id,
            keywords => meta.keywords,
            affiliations => meta.affiliations,
            references => references,
            can_edit => can_edit,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
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
            abstract_text => meta.abstract_text,
            journal => meta.journal,
            volume => meta.volume,
            issue => meta.issue,
            pages => meta.pages,
            publisher => meta.publisher,
            issn => meta.issn,
            arxiv_id => meta.arxiv_id,
            keywords => meta.keywords,
            affiliations => meta.affiliations,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(html))
}

#[derive(Deserialize, Default)]
pub struct FileEditForm {
    pub title: String,
    pub authors: String,
    pub year: String,
    pub doi: String,
    pub abstract_text: String,
    pub journal: String,
    pub volume: String,
    pub issue: String,
    pub pages: String,
    pub publisher: String,
    pub issn: String,
    pub arxiv_id: String,
    pub keywords: String,
    pub affiliations: String,
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

    // Escape all string fields
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', r#"\""#);
    let title = esc(&form.title);
    let authors = esc(&form.authors);
    let doi = esc(&form.doi);
    let abstract_text = esc(&form.abstract_text);
    let journal = esc(&form.journal);
    let volume = esc(&form.volume);
    let issue = esc(&form.issue);
    let pages = esc(&form.pages);
    let publisher = esc(&form.publisher);
    let issn = esc(&form.issn);
    let arxiv_id = esc(&form.arxiv_id);
    let keywords = esc(&form.keywords);
    let affiliations = esc(&form.affiliations);
    let year = esc(&form.year);

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
    abstract_text: String,
    journal: String,
    volume: String,
    issue: String,
    pages: String,
    publisher: String,
    issn: String,
    arxiv_id: String,
    keywords: String,
    affiliations: String,
}

fn get_file_all_metadata(state: &AppState, team_path: &str, file_id: &str) -> Option<FileMeta> {
    let catalog = state.store_manager.get_file_catalog(team_path)?;
    let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);

    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        PREFIX dcterms: <http://purl.org/dc/terms/>
        PREFIX bibo: <http://purl.org/ontology/bibo/>
        SELECT ?fileName ?title ?authors ?year ?doi ?abstract ?journal
               ?volume ?issue ?pages ?publisher ?issn ?arxivId ?keywords ?affiliations
        WHERE {{
            <{file_iri}> a mlipe:File .
            OPTIONAL {{ <{file_iri}> mlipe:fileName ?fileName }}
            OPTIONAL {{ <{file_iri}> dcterms:title ?title }}
            OPTIONAL {{ <{file_iri}> dcterms:creator ?authors }}
            OPTIONAL {{ <{file_iri}> dcterms:date ?year }}
            OPTIONAL {{ <{file_iri}> bibo:doi ?doi }}
            OPTIONAL {{ <{file_iri}> dcterms:abstract ?abstract }}
            OPTIONAL {{ <{file_iri}> dcterms:isPartOf ?journal }}
            OPTIONAL {{ <{file_iri}> bibo:volume ?volume }}
            OPTIONAL {{ <{file_iri}> bibo:issue ?issue }}
            OPTIONAL {{ <{file_iri}> bibo:pages ?pages }}
            OPTIONAL {{ <{file_iri}> dcterms:publisher ?publisher }}
            OPTIONAL {{ <{file_iri}> bibo:issn ?issn }}
            OPTIONAL {{ <{file_iri}> dcterms:identifier ?arxivId }}
            OPTIONAL {{ <{file_iri}> dcterms:subject ?keywords }}
            OPTIONAL {{ <{file_iri}> mlipe:affiliation ?affiliations }}
        }}
        LIMIT 1
        "#,
    );

    let g = |sol: &oxigraph::sparql::QuerySolution, name: &str| -> String {
        sol.get(name).map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default()
    };

    if let Ok(QueryResults::Solutions(solutions)) = catalog.query(&query) {
        for solution in solutions.flatten() {
            return Some(FileMeta {
                file_name: g(&solution, "fileName"),
                title: g(&solution, "title"),
                authors: g(&solution, "authors"),
                year: g(&solution, "year"),
                doi: g(&solution, "doi"),
                abstract_text: g(&solution, "abstract"),
                journal: g(&solution, "journal"),
                volume: g(&solution, "volume"),
                issue: g(&solution, "issue"),
                pages: g(&solution, "pages"),
                publisher: g(&solution, "publisher"),
                issn: g(&solution, "issn"),
                arxiv_id: g(&solution, "arxivId"),
                keywords: g(&solution, "keywords"),
                affiliations: g(&solution, "affiliations"),
            });
        }
    }

    None
}

fn get_file_metadata_field(state: &AppState, team_path: &str, file_id: &str, field: &str, _ns_hint: &str) -> Option<String> {
    let catalog = state.store_manager.get_file_catalog(team_path)?;
    let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);

    let query = format!(
        r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        PREFIX dcterms: <http://purl.org/dc/terms/>
        PREFIX bibo: <http://purl.org/ontology/bibo/>
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

fn get_file_references(state: &AppState, team_path: &str, file_id: &str) -> Vec<String> {
    let catalog = match state.store_manager.get_file_catalog(team_path) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let file_iri = format!("https://mlipe.2mia.org/files/{}", file_id);

    let query = format!(
        r#"
        PREFIX bibo: <http://purl.org/ontology/bibo/>
        SELECT ?ref WHERE {{
            <{file_iri}> bibo:cites ?ref .
        }}
        "#,
    );

    let mut refs = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = catalog.query(&query) {
        for solution in solutions.flatten() {
            if let Some(val) = solution.get("ref") {
                let iri = val.to_string();
                let doi = iri.trim_matches(|c| c == '<' || c == '>')
                    .strip_prefix("https://doi.org/")
                    .unwrap_or(&iri)
                    .to_string();
                refs.push(doi);
            }
        }
    }
    refs
}

/// List files from this team's catalog and all sub-team catalogs recursively.
pub fn list_files_recursive(state: &AppState, team_path: &str) -> Vec<minijinja::Value> {
    let mut all_files = Vec::new();

    // List this team's files
    all_files.extend(list_files_from_catalog(state, team_path));

    // Scan for sub-team catalogs on disk
    if let Some(catalogs_dir) = state.store_manager.catalogs_dir() {
        if team_path == "root" {
            // Root team: scan all top-level catalogs
            scan_all_catalogs(&catalogs_dir, state, &mut all_files);
        } else {
            // Sub-team: scan children under this team's path
            let target = catalogs_dir.join(team_path);
            if target.exists() {
                scan_subdirs(&target, team_path, state, &mut all_files);
            }
        }
    }

    all_files
}

fn scan_all_catalogs(base: &std::path::Path, state: &AppState, files: &mut Vec<minijinja::Value>) {
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            if !entry.file_type().map_or(false, |t| t.is_dir()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            // Check if this is an Oxigraph store (catalog)
            if entry.path().join("CURRENT").exists() {
                files.extend(list_files_from_catalog(state, &name));
            }
            // Also recurse into subdirectories
            scan_subdirs(&entry.path(), &name, state, files);
        }
    }
}

fn scan_subdirs(dir: &std::path::Path, parent_path: &str, state: &AppState, files: &mut Vec<minijinja::Value>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if !entry.file_type().map_or(false, |t| t.is_dir()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip Oxigraph internal files
            if name.starts_with('.') {
                continue;
            }
            let child_path = format!("{}/{}", parent_path, name);
            if entry.path().join("CURRENT").exists() {
                files.extend(list_files_from_catalog(state, &child_path));
            }
            scan_subdirs(&entry.path(), &child_path, state, files);
        }
    }
}

fn find_catalog_dirs(base: &std::path::Path, prefix: &str, state: &AppState, files: &mut Vec<minijinja::Value>) {
    let target = base.join(prefix.trim_end_matches('/'));
    if !target.exists() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(&target) {
        for entry in entries.flatten() {
            if entry.file_type().map_or(false, |t| t.is_dir()) {
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip Oxigraph internal files
                if name == "." || name == ".." || name.ends_with(".log") || name.ends_with(".sst") {
                    continue;
                }
                let sub_path = format!("{}{}", prefix, name);
                // Check if this looks like a catalog (has CURRENT file = Oxigraph store)
                if entry.path().join("CURRENT").exists() {
                    // This is a catalog store, not a subdirectory of catalogs
                    continue;
                }
                // It's a subdirectory — check for catalog and recurse
                let catalog_path = format!("{}/{}", prefix.trim_end_matches('/'), name);
                files.extend(list_files_from_catalog(state, &catalog_path));
                find_catalog_dirs(base, &format!("{}/", catalog_path), state, files);
            }
        }
    }
}

pub fn list_files_from_catalog(state: &AppState, team_path: &str) -> Vec<minijinja::Value> {
    let catalog = match state.store_manager.get_file_catalog(team_path) {
        Some(c) => c,
        None => return Vec::new(),
    };

    let query = r#"
        PREFIX mlipe: <https://mlipe.2mia.org/ontology#>
        PREFIX dcterms: <http://purl.org/dc/terms/>
        PREFIX bibo: <http://purl.org/ontology/bibo/>
        SELECT ?file ?fileName ?title ?authors ?year ?doi ?size ?uploadedAt WHERE {
            ?file a mlipe:File .
            OPTIONAL { ?file mlipe:fileName ?fileName }
            OPTIONAL { ?file dcterms:title ?title }
            OPTIONAL { ?file dcterms:creator ?authors }
            OPTIONAL { ?file dcterms:date ?year }
            OPTIONAL { ?file bibo:doi ?doi }
            OPTIONAL { ?file mlipe:fileSize ?size }
            OPTIONAL { ?file mlipe:uploadedAt ?uploadedAt }
        }
        ORDER BY DESC(?uploadedAt)
    "#;

    let mut files = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = catalog.query(query) {
        for solution in solutions.flatten() {
            let file_iri = solution.get("file").map(|v| v.to_string()).unwrap_or_default();
            let uuid = file_iri
                .rsplit('/')
                .next()
                .unwrap_or("")
                .trim_matches('>');

            let g = |name: &str| -> String {
                solution.get(name).map(|v| auth::strip_literal(&v.to_string())).unwrap_or_default()
            };

            files.push(minijinja::context! {
                uuid => uuid,
                file_name => g("fileName"),
                title => g("title"),
                authors => g("authors"),
                year => g("year"),
                doi => g("doi"),
                size => g("size"),
                uploaded_at => g("uploadedAt"),
            });
        }
    }

    files
}
