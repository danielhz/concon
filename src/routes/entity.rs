//! Per-entity dereferencing for published Linked Data datasets (epic A3).
//!
//! Ported from the standalone onto-server's `serve_entity` (see
//! `../code/src/main.rs`) into concon's native URL scheme: an entity is served
//! at `<dataset-base>/_entity/{id}` (e.g. `/mlips/_ds/mlips/_entity/kumar2025`),
//! NOT under a `/mlips/entity/…` compatibility route. The canonical identifier
//! stays `https://w3id.org/mlips/entity/{id}`; IRI stability is preserved at the
//! edge (nginx / w3id `.htaccess`, Daniel's deploy step), which redirects the
//! canonical slash-IRI here preserving `Accept`. concon does the Accept-based
//! content negotiation at this native URL and answers 200 with the negotiated
//! representation — the 303 "thing vs. document" hop, if any, lives at the edge.
//!
//! Queries run with union-default-graph semantics (see
//! `store::sparql_query_union`) so links resolve across the dataset's named
//! graphs (schema / instances / CQ) exactly as in a single store.

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use oxigraph::io::{RdfFormat, RdfSerializer};
use oxigraph::model::Term;
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;
use serde::Serialize;

use crate::state::AppState;
use crate::store::sparql_query_union;

/// Canonical namespace for per-paper instance data. This is the published
/// (citable) identity of the individuals; concon serves them but never mints
/// them under a concon namespace. Hardcoded to the MLIPs resource for now —
/// the driving published dataset; generalising to a per-dataset entity base
/// (read from dataset metadata) is a deliberate later refinement once concon
/// hosts multiple Linked Data datasets.
const ENTITY_BASE: &str = "https://w3id.org/mlips/entity/";

const RDFS_LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const RDF_LANGSTRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

/// Pick the response serialization from the `Accept` header. Mirrors the
/// onto-server: Turtle, RDF/XML (a.k.a. OWL/XML), or XHTML (default).
pub(crate) fn negotiate_format(headers: &HeaderMap) -> &'static str {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/html");

    for t in accept.split(',').map(|s| s.split(';').next().unwrap_or("").trim()) {
        match t {
            "text/turtle" => return "ttl",
            "application/rdf+xml" | "application/owl+xml" => return "owl",
            "text/html" | "application/xhtml+xml" => return "xhtml",
            _ => {}
        }
    }
    "xhtml"
}

pub(crate) fn content_type_for(format: &str) -> &'static str {
    match format {
        "ttl" => "text/turtle; charset=utf-8",
        "owl" => "application/rdf+xml; charset=utf-8",
        "xhtml" => "application/xhtml+xml; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Abbreviate a well-known IRI to a `prefix:local` short form for display.
fn short_form(iri: &str) -> String {
    const PREFIXES: &[(&str, &str)] = &[
        ("https://w3id.org/mlips/entity/", "entity:"),
        ("https://w3id.org/mlips#", "mlips:"),
        ("http://www.w3.org/ns/mls#", "mls:"),
        ("http://www.w3.org/ns/prov#", "prov:"),
        ("http://www.w3.org/2000/01/rdf-schema#", "rdfs:"),
        ("http://www.w3.org/1999/02/22-rdf-syntax-ns#", "rdf:"),
        ("http://www.w3.org/2001/XMLSchema#", "xsd:"),
        ("https://schema.org/", "schema:"),
        ("http://qudt.org/schema/qudt/", "qudt:"),
        ("http://qudt.org/vocab/unit/", "unit:"),
        ("https://w3id.org/mdo/core/", "mdo:"),
        ("https://w3id.org/mdo/calculation/", "mdo-calc:"),
        ("https://orcid.org/", "orcid:"),
        ("https://doi.org/", "doi:"),
    ];
    for (uri, prefix) in PREFIXES {
        if let Some(rest) = iri.strip_prefix(uri) {
            return format!("{prefix}{rest}");
        }
    }
    iri.to_string()
}

/// Local name (after the last `/` or `#`) for fallback display.
fn local_name(iri: &str) -> String {
    iri.rsplit_once(['#', '/'])
        .map(|(_, last)| last.to_string())
        .unwrap_or_else(|| iri.to_string())
}

/// Map a target IRI to a URL the browser can follow. Entity IRIs under this
/// resource are rewritten to their concon-native dereferencing URL so the
/// published graph is self-navigable even before the edge redirect exists;
/// every other IRI keeps its canonical form (resolved by its own authority).
fn native_href(iri: &str, url_prefix: &str) -> String {
    match iri.strip_prefix(ENTITY_BASE) {
        Some(id) => format!("{url_prefix}/_entity/{id}"),
        None => iri.to_string(),
    }
}

/// Datatype/language annotation for a literal object, e.g. `^^xsd:integer`,
/// `@en`, or empty for a plain `xsd:string`.
fn literal_annotation(language: Option<&str>, datatype: &str) -> String {
    if let Some(lang) = language {
        format!("@{lang}")
    } else if datatype == XSD_STRING || datatype == RDF_LANGSTRING {
        String::new()
    } else {
        format!("^^{}", short_form(datatype))
    }
}

#[derive(Serialize)]
struct PropertyRow {
    predicate_iri: String,
    predicate_short: String,
    predicate_label: Option<String>,
    /// "iri", "literal", or "bnode".
    kind: &'static str,
    /// Canonical IRI of the object (kind = "iri"); empty otherwise.
    target_iri: String,
    /// URL to follow for an IRI object (native for entities); empty otherwise.
    target_href: String,
    /// Display text for the object cell.
    target_display: String,
    /// rdfs:label of an IRI/bnode object, if any.
    target_label: Option<String>,
    /// Literal datatype/language annotation (kind = "literal").
    annotation: String,
}

/// Forward triples `<subject> ?p ?o`, with predicate and object labels pulled
/// in the same query (no N+1 lookups).
fn forward_rows(store: &Store, subject_iri: &str) -> Vec<PropertyRow> {
    let q = format!(
        r#"SELECT ?p ?o ?pl ?ol WHERE {{
            <{subject_iri}> ?p ?o .
            OPTIONAL {{ ?p <{RDFS_LABEL}> ?pl }}
            OPTIONAL {{ ?o <{RDFS_LABEL}> ?ol }}
        }} ORDER BY ?p ?o"#
    );
    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            let Some(Term::NamedNode(p)) = sol.get("p") else {
                continue;
            };
            let p_iri = p.as_str().to_string();
            let predicate_label = literal_value(sol.get("pl"));
            let predicate_short = short_form(&p_iri);
            let target_label = literal_value(sol.get("ol"));
            match sol.get("o") {
                Some(Term::NamedNode(o)) => {
                    let iri = o.as_str().to_string();
                    rows.push(PropertyRow {
                        predicate_iri: p_iri,
                        predicate_short,
                        predicate_label,
                        kind: "iri",
                        target_href: native_href(&iri, ""),
                        target_display: short_form(&iri),
                        target_iri: iri,
                        target_label,
                        annotation: String::new(),
                    });
                }
                Some(Term::BlankNode(b)) => {
                    rows.push(PropertyRow {
                        predicate_iri: p_iri,
                        predicate_short,
                        predicate_label,
                        kind: "bnode",
                        target_iri: String::new(),
                        target_href: String::new(),
                        target_display: format!("_:{}", b.as_str()),
                        target_label,
                        annotation: String::new(),
                    });
                }
                Some(Term::Literal(lit)) => {
                    rows.push(PropertyRow {
                        predicate_iri: p_iri,
                        predicate_short,
                        predicate_label,
                        kind: "literal",
                        target_iri: String::new(),
                        target_href: String::new(),
                        target_display: lit.value().to_string(),
                        target_label: None,
                        annotation: literal_annotation(lit.language(), lit.datatype().as_str()),
                    });
                }
                _ => {}
            }
        }
    }
    rows
}

#[derive(Serialize)]
struct ReverseRow {
    source_iri: String,
    source_href: String,
    source_display: String,
    source_label: Option<String>,
    /// "iri" or "bnode".
    source_kind: &'static str,
    predicate_iri: String,
    predicate_short: String,
    predicate_label: Option<String>,
}

/// Reverse triples `?s ?p <object>`, with labels in the same query.
fn reverse_rows(store: &Store, object_iri: &str) -> Vec<ReverseRow> {
    let q = format!(
        r#"SELECT ?s ?p ?sl ?pl WHERE {{
            ?s ?p <{object_iri}> .
            OPTIONAL {{ ?s <{RDFS_LABEL}> ?sl }}
            OPTIONAL {{ ?p <{RDFS_LABEL}> ?pl }}
        }} ORDER BY ?p ?s"#
    );
    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            let Some(Term::NamedNode(p)) = sol.get("p") else {
                continue;
            };
            let p_iri = p.as_str().to_string();
            let predicate_short = short_form(&p_iri);
            let predicate_label = literal_value(sol.get("pl"));
            let source_label = literal_value(sol.get("sl"));
            match sol.get("s") {
                Some(Term::NamedNode(s)) => {
                    let iri = s.as_str().to_string();
                    rows.push(ReverseRow {
                        source_href: native_href(&iri, ""),
                        source_display: short_form(&iri),
                        source_iri: iri,
                        source_label,
                        source_kind: "iri",
                        predicate_iri: p_iri,
                        predicate_short,
                        predicate_label,
                    });
                }
                Some(Term::BlankNode(b)) => {
                    rows.push(ReverseRow {
                        source_iri: String::new(),
                        source_href: String::new(),
                        source_display: format!("_:{}", b.as_str()),
                        source_label,
                        source_kind: "bnode",
                        predicate_iri: p_iri,
                        predicate_short,
                        predicate_label,
                    });
                }
                _ => {}
            }
        }
    }
    rows
}

#[derive(Serialize)]
struct TypeRef {
    iri: String,
    short: String,
    label: Option<String>,
}

fn types_of(store: &Store, subject_iri: &str) -> Vec<TypeRef> {
    let q = format!(
        r#"SELECT ?t ?tl WHERE {{
            <{subject_iri}> a ?t .
            OPTIONAL {{ ?t <{RDFS_LABEL}> ?tl }}
        }} ORDER BY ?t"#
    );
    let mut out = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            if let Some(Term::NamedNode(t)) = sol.get("t") {
                let iri = t.as_str().to_string();
                out.push(TypeRef {
                    short: short_form(&iri),
                    label: literal_value(sol.get("tl")),
                    iri,
                });
            }
        }
    }
    out
}

fn lookup_label(store: &Store, subject_iri: &str) -> Option<String> {
    let q = format!(r#"SELECT ?l WHERE {{ <{subject_iri}> <{RDFS_LABEL}> ?l }} LIMIT 1"#);
    let QueryResults::Solutions(mut sols) = sparql_query_union(store, &q).ok()? else {
        return None;
    };
    literal_value(sols.next()?.ok()?.get("l"))
}

/// Extract the lexical value of a literal term, if the term is a literal.
fn literal_value(term: Option<&Term>) -> Option<String> {
    match term {
        Some(Term::Literal(lit)) => Some(lit.value().to_string()),
        _ => None,
    }
}

fn entity_not_found(state: &AppState, subject_iri: &str, format: &str) -> Response {
    if format == "ttl" || format == "owl" {
        return (
            StatusCode::NOT_FOUND,
            format!("No triples for <{subject_iri}>"),
        )
            .into_response();
    }
    let body = state
        .templates
        .get_template("entity_not_found.html")
        .and_then(|t| t.render(minijinja::context! { subject_iri => subject_iri }))
        .unwrap_or_else(|_| {
            format!(
                "<!DOCTYPE html><html><body><h1>404 Not Found</h1>\
                 <p>No triples for <code>{}</code> in the current release.</p></body></html>",
                subject_iri
            )
        });
    (
        StatusCode::NOT_FOUND,
        // Entity pages are generated HTML (the base.html chrome, no CDATA), so
        // text/html — the HTML5 parser handles base.html's void elements, which
        // are not XML-well-formed. (Only the curated doc is served xhtml+xml.)
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Dereference `<ENTITY_BASE>{id}` against `dataset_name`, negotiating the
/// representation from `Accept`. `url_prefix` is the dataset base used to build
/// native links (e.g. `/mlips/_ds/mlips`).
pub async fn serve_entity(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    id: &str,
    headers: &HeaderMap,
    username: Option<String>,
    is_admin: bool,
) -> Response {
    let store = match state.store_manager.get_dataset(dataset_name) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("Dataset '{dataset_name}' not found"),
            )
                .into_response();
        }
    };

    let subject_iri = format!("{ENTITY_BASE}{id}");
    let format = negotiate_format(headers);

    // Existence: at least one forward or reverse triple.
    let exists = matches!(
        sparql_query_union(&store, &format!("ASK {{ <{subject_iri}> ?p ?o }}")),
        Ok(QueryResults::Boolean(true))
    ) || matches!(
        sparql_query_union(&store, &format!("ASK {{ ?s ?p <{subject_iri}> }}")),
        Ok(QueryResults::Boolean(true))
    );
    if !exists {
        return entity_not_found(state, &subject_iri, format);
    }

    match format {
        "ttl" | "owl" => {
            // Concise Bounded Description: forward triples of the subject.
            let q = format!(
                r#"CONSTRUCT {{ <{subject_iri}> ?p ?o }} WHERE {{ <{subject_iri}> ?p ?o }}"#
            );
            let triples = match sparql_query_union(&store, &q) {
                Ok(QueryResults::Graph(t)) => t,
                _ => return (StatusCode::INTERNAL_SERVER_ERROR, "Query error").into_response(),
            };
            let rdf_format = if format == "ttl" {
                RdfFormat::Turtle
            } else {
                RdfFormat::RdfXml
            };
            let mut serializer = RdfSerializer::from_format(rdf_format).for_writer(Vec::new());
            for t in triples.flatten() {
                if serializer.serialize_triple(t.as_ref()).is_err() {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Serialize error").into_response();
                }
            }
            match serializer.finish() {
                Ok(buf) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, content_type_for(format))],
                    buf,
                )
                    .into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Finish error").into_response(),
            }
        }
        _ => {
            // HTML view (default). Rewrite native hrefs against this dataset.
            let mut forward = forward_rows(&store, &subject_iri);
            for r in &mut forward {
                if r.kind == "iri" {
                    r.target_href = native_href(&r.target_iri, url_prefix);
                }
            }
            let mut reverse = reverse_rows(&store, &subject_iri);
            for r in &mut reverse {
                if r.source_kind == "iri" {
                    r.source_href = native_href(&r.source_iri, url_prefix);
                }
            }
            let types = types_of(&store, &subject_iri);
            let label = lookup_label(&store, &subject_iri);

            let tmpl = match state.templates.get_template("entity.html") {
                Ok(t) => t,
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Template missing").into_response();
                }
            };
            let html = match tmpl.render(minijinja::context! {
                subject_iri => &subject_iri,
                subject_short => short_form(&subject_iri),
                subject_local => local_name(&subject_iri),
                entity_url => format!("{url_prefix}/_entity/{id}"),
                label => label,
                types => &types,
                forward => &forward,
                reverse => &reverse,
                forward_count => forward.len(),
                reverse_count => reverse.len(),
                username => username,
                is_admin => is_admin,
            }) {
                Ok(s) => s,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Render error: {e}"),
                    )
                        .into_response();
                }
            };
            (
                StatusCode::OK,
                // Entity pages are generated HTML (the base.html chrome, no CDATA), so
        // text/html — the HTML5 parser handles base.html's void elements, which
        // are not XML-well-formed. (Only the curated doc is served xhtml+xml.)
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_form() {
        assert_eq!(short_form("https://w3id.org/mlips#MLIPMethod"), "mlips:MLIPMethod");
        assert_eq!(
            short_form("https://w3id.org/mlips/entity/kumar2025"),
            "entity:kumar2025"
        );
        assert_eq!(short_form("https://example.org/x"), "https://example.org/x");
    }

    #[test]
    fn test_local_name() {
        assert_eq!(local_name("https://w3id.org/mlips#MLIPMethod"), "MLIPMethod");
        assert_eq!(local_name("https://w3id.org/mlips/entity/kumar2025"), "kumar2025");
    }

    #[test]
    fn test_native_href() {
        assert_eq!(
            native_href("https://w3id.org/mlips/entity/kumar2025", "/mlips/_ds/mlips"),
            "/mlips/_ds/mlips/_entity/kumar2025"
        );
        // Non-entity IRIs keep their canonical form.
        assert_eq!(
            native_href("https://w3id.org/mlips#MLIPMethod", "/mlips/_ds/mlips"),
            "https://w3id.org/mlips#MLIPMethod"
        );
    }

    #[test]
    fn test_literal_annotation() {
        assert_eq!(literal_annotation(Some("en"), XSD_STRING), "@en");
        assert_eq!(literal_annotation(None, XSD_STRING), "");
        assert_eq!(
            literal_annotation(None, "http://www.w3.org/2001/XMLSchema#integer"),
            "^^xsd:integer"
        );
    }

    #[test]
    fn test_negotiate_format() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, "text/turtle".parse().unwrap());
        assert_eq!(negotiate_format(&h), "ttl");
        h.insert(header::ACCEPT, "application/rdf+xml".parse().unwrap());
        assert_eq!(negotiate_format(&h), "owl");
        h.insert(
            header::ACCEPT,
            "text/html,application/xhtml+xml".parse().unwrap(),
        );
        assert_eq!(negotiate_format(&h), "xhtml");
        // Unknown / missing → default xhtml.
        assert_eq!(negotiate_format(&HeaderMap::new()), "xhtml");
    }
}
