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
use axum::response::{IntoResponse, Redirect, Response};
use oxigraph::io::{RdfFormat, RdfSerializer};
use oxigraph::model::{NamedNode, Term};
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;
use serde::Serialize;

use super::ontology;
use crate::state::AppState;
use crate::store::{QUERY_TIMEOUT, sparql_query_union, sparql_query_union_timeout, sparql_update};

// Epic H — annotations. An `oa:Annotation` per note, targeting the resource
// IRI, kept in its own named graph (out of the ontology/KG graphs).
const ANNOTATIONS_GRAPH: &str = "https://w3id.org/mlips/graph/annotations";
const OA_ANNOTATION: &str = "http://www.w3.org/ns/oa#Annotation";
const OA_HAS_TARGET: &str = "http://www.w3.org/ns/oa#hasTarget";
const OA_HAS_BODY: &str = "http://www.w3.org/ns/oa#hasBody";
const DCTERMS_CREATOR: &str = "http://purl.org/dc/terms/creator";
const DCTERMS_CREATED: &str = "http://purl.org/dc/terms/created";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// Canonical namespace for per-paper instance data. This is the published
/// (citable) identity of the individuals; concon serves them but never mints
/// them under a concon namespace. Hardcoded to the MLIPs resource for now —
/// the driving published dataset; generalising to a per-dataset entity base
/// (read from dataset metadata) is a deliberate later refinement once concon
/// hosts multiple Linked Data datasets.
const ENTITY_BASE: &str = "https://w3id.org/mlips/entity/";

const RDFS_LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
const RDFS_SUBCLASS_OF: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const RDF_LANGSTRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

/// Page size of a resource view's instance / usage list (issue #4). The list
/// is collapsed by default and paginated server-side (`?page=N`), so a view
/// never loads more than one page of rows — the Epic B4 per-view bound — while
/// every row stays reachable.
const RESOURCE_LIST_PAGE_SIZE: usize = 50;

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
            "application/n-triples" => return "nt",
            "application/ld+json" => return "jsonld",
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
        "nt" => "application/n-triples; charset=utf-8",
        "jsonld" => "application/ld+json; charset=utf-8",
        "xhtml" => "application/xhtml+xml; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Map a negotiated format code to the oxigraph RDF serializer format, or
/// `None` for non-RDF codes (e.g. `"xhtml"`). JSON-LD is obtained via its media
/// type so we don't have to name the profile-set type. Shared by entity
/// dereferencing and the ontology dump so they negotiate the same set.
pub(crate) fn rdf_format_for(format: &str) -> Option<RdfFormat> {
    match format {
        "ttl" => Some(RdfFormat::Turtle),
        "owl" => Some(RdfFormat::RdfXml),
        "nt" => Some(RdfFormat::NTriples),
        "jsonld" => RdfFormat::from_media_type("application/ld+json"),
        _ => None,
    }
}

/// Abbreviate a well-known IRI to a `prefix:local` short form for display.
pub(crate) fn short_form(iri: &str) -> String {
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

/// Namespaces whose terms earn a local resource view (Epic G3 policy): our own
/// vocabulary plus the external *domain* vocabularies actually modelled in the
/// dataset. Structural built-ins (`rdf`/`rdfs`/`owl`/`xsd`) and generic
/// annotation vocabularies are deliberately excluded — a local view of
/// `xsd:string` or `dcterms:title` would be noise — so their links resolve
/// straight to the defining authority instead.
const VIEWABLE_NAMESPACES: &[&str] = &[
    "https://w3id.org/mlips#",
    "https://schema.org/",
    "http://www.w3.org/ns/prov#",
    "http://qudt.org/schema/qudt/",
    "http://qudt.org/vocab/unit/",
    "http://www.w3.org/ns/mls#",
    "https://purls.helmholtz-metadaten.de/cmso/",
    "https://w3id.org/mdo/core/",
    "https://w3id.org/mdo/calculation/",
];

/// Whether `iri` is a domain-vocabulary term that earns its own local view
/// (see `VIEWABLE_NAMESPACES`). Entity IRIs are handled separately (they use
/// the short `_entity/{id}` form).
pub(crate) fn earns_local_view(iri: &str) -> bool {
    VIEWABLE_NAMESPACES.iter().any(|ns| iri.starts_with(ns))
}

/// Map a target IRI to a URL the browser can follow, keeping navigation inside
/// concon (view→view) wherever the resource earns a local view:
///   - an entity IRI under this resource → its short `_entity/{id}` URL;
///   - any other domain-vocab IRI that earns a local view (Epic G3) → the
///     generic `_view?iri=<encoded>` resource view;
///   - everything else (built-ins, annotation vocabs, foreign authorities) →
///     the canonical IRI itself, resolved by its own authority.
pub(crate) fn native_href(iri: &str, url_prefix: &str) -> String {
    if let Some(id) = iri.strip_prefix(ENTITY_BASE) {
        format!("{url_prefix}/_entity/{id}")
    } else if earns_local_view(iri) {
        let qs = serde_urlencoded::to_string([("iri", iri)]).unwrap_or_default();
        format!("{url_prefix}/_view?{qs}")
    } else {
        iri.to_string()
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
    // GROUP BY the triple and SAMPLE the labels: a predicate or object may
    // carry several `rdfs:label`s (e.g. a plain and an `@en`-tagged copy, or
    // genuinely multilingual labels), and a plain OPTIONAL join would emit one
    // duplicate row per extra label. Grouping yields exactly one row per
    // (predicate, object) pair.
    let q = format!(
        r#"SELECT ?p ?o (SAMPLE(?pl) AS ?plab) (SAMPLE(?ol) AS ?olab) WHERE {{
            <{subject_iri}> ?p ?o .
            OPTIONAL {{ ?p <{RDFS_LABEL}> ?pl }}
            OPTIONAL {{ ?o <{RDFS_LABEL}> ?ol }}
        }} GROUP BY ?p ?o ORDER BY ?p ?o"#
    );
    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            let Some(Term::NamedNode(p)) = sol.get("p") else {
                continue;
            };
            let p_iri = p.as_str().to_string();
            let predicate_label = literal_value(sol.get("plab"));
            let predicate_short = short_form(&p_iri);
            let target_label = literal_value(sol.get("olab"));
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

#[derive(Serialize, Debug)]
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
/// Reverse links of `object_iri` (the "Referenced by" table). With
/// `exclude_type_links`, the `?s rdf:type <object_iri>` rows are left out —
/// on a class view they are exactly the (collapsed, paginated) instance list
/// (issue #4), and listing every instance again below it defeats the collapse.
fn reverse_rows(store: &Store, object_iri: &str, exclude_type_links: bool) -> Vec<ReverseRow> {
    // GROUP BY + SAMPLE so multi-labelled subjects/predicates don't multiply
    // rows (see `forward_rows`).
    let type_filter = if exclude_type_links {
        format!("FILTER(?p != <{RDF_TYPE}>)")
    } else {
        String::new()
    };
    let q = format!(
        r#"SELECT ?s ?p (SAMPLE(?sl) AS ?slab) (SAMPLE(?pl) AS ?plab) WHERE {{
            ?s ?p <{object_iri}> .
            {type_filter}
            OPTIONAL {{ ?s <{RDFS_LABEL}> ?sl }}
            OPTIONAL {{ ?p <{RDFS_LABEL}> ?pl }}
        }} GROUP BY ?s ?p ORDER BY ?p ?s"#
    );
    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            let Some(Term::NamedNode(p)) = sol.get("p") else {
                continue;
            };
            let p_iri = p.as_str().to_string();
            let predicate_short = short_form(&p_iri);
            let predicate_label = literal_value(sol.get("plab"));
            let source_label = literal_value(sol.get("slab"));
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
    // GROUP BY + SAMPLE so a multi-labelled class isn't listed once per label.
    let q = format!(
        r#"SELECT ?t (SAMPLE(?tl) AS ?tlab) WHERE {{
            <{subject_iri}> a ?t .
            OPTIONAL {{ ?t <{RDFS_LABEL}> ?tl }}
        }} GROUP BY ?t ORDER BY ?t"#
    );
    let mut out = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            if let Some(Term::NamedNode(t)) = sol.get("t") {
                let iri = t.as_str().to_string();
                out.push(TypeRef {
                    short: short_form(&iri),
                    label: literal_value(sol.get("tlab")),
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

/// Escape a string for use inside a SPARQL double-quoted string literal, so
/// user-supplied note text (and the creator name) cannot break out of the
/// literal in an INSERT. (No parameter binding exists in SPARQL Update, so the
/// value must be escaped before interpolation.)
fn escape_sparql_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the SPARQL Update that INSERTs one annotation. `subject_iri` must be
/// pre-validated (a real IRI); `note`/`username` are escaped as string literals
/// here. A fresh annotation IRI (STRUUID) and the timestamp (NOW) are minted
/// server-side, so no client value reaches an IRI position.
fn build_annotation_insert(subject_iri: &str, note: &str, username: &str) -> String {
    let body = escape_sparql_literal(note);
    let creator = escape_sparql_literal(username);
    format!(
        r#"INSERT {{ GRAPH <{ANNOTATIONS_GRAPH}> {{
            ?ann <{RDF_TYPE}> <{OA_ANNOTATION}> ;
                 <{OA_HAS_TARGET}> <{subject_iri}> ;
                 <{OA_HAS_BODY}> "{body}" ;
                 <{DCTERMS_CREATOR}> "{creator}" ;
                 <{DCTERMS_CREATED}> ?now .
        }} }} WHERE {{
            BIND(NOW() AS ?now)
            BIND(IRI(CONCAT("https://w3id.org/mlips/annotation/", STRUUID())) AS ?ann)
        }}"#
    )
}

/// One annotation note on a resource (Epic H): author, timestamp, text.
#[derive(Serialize)]
struct AnnotationRow {
    /// Fragment id for citing this note from another one (`#note-<uuid>`),
    /// derived from the annotation IRI minted by [`build_annotation_insert`].
    anchor: String,
    creator: String,
    created: String,
    /// The note as written — Markdown source.
    body: String,
    /// `body` rendered through [`crate::markdown::render_note_html`]:
    /// sanitised HTML, emitted with `| safe` by the template.
    body_html: String,
}

/// Fragment id for an annotation: `note-` + the IRI's local part, kept only
/// when it is fragment-safe (the server mints `…/annotation/<uuid>`, so this
/// holds for every stored note); otherwise fall back to the note's position.
fn annotation_anchor(annotation_iri: &str, position: usize) -> String {
    let local = annotation_iri.rsplit('/').next().unwrap_or("");
    let safe = !local.is_empty()
        && local.len() <= 128
        && local.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    if safe { format!("note-{local}") } else { format!("note-{position}") }
}

/// Notes targeting `subject_iri`, oldest first (Epic H). Read from the
/// dedicated annotations graph only.
fn annotations_of(store: &Store, subject_iri: &str) -> Vec<AnnotationRow> {
    let q = format!(
        r#"SELECT ?a ?body ?creator ?created WHERE {{
            GRAPH <{ANNOTATIONS_GRAPH}> {{
                ?a <{OA_HAS_TARGET}> <{subject_iri}> ; <{OA_HAS_BODY}> ?body .
                OPTIONAL {{ ?a <{DCTERMS_CREATOR}> ?creator }}
                OPTIONAL {{ ?a <{DCTERMS_CREATED}> ?created }}
            }}
        }} ORDER BY ?created"#
    );
    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, &q) {
        for sol in sols.flatten() {
            let Some(body) = literal_value(sol.get("body")) else {
                continue;
            };
            let ann_iri = match sol.get("a") {
                Some(Term::NamedNode(n)) => n.as_str(),
                _ => "",
            };
            rows.push(AnnotationRow {
                anchor: annotation_anchor(ann_iri, rows.len() + 1),
                creator: literal_value(sol.get("creator")).unwrap_or_else(|| "anonymous".into()),
                created: literal_value(sol.get("created")).unwrap_or_default(),
                body_html: crate::markdown::render_note_html(&body),
                body,
            });
        }
    }
    rows
}

/// Add a note to the entity `<ENTITY_BASE>{id}` (the `_entity/{id}` POST). A
/// thin wrapper over [`add_annotation_iri`] that expands the id to the entity
/// IRI.
pub async fn add_annotation(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    id: &str,
    username: &str,
    note: &str,
) -> Response {
    let subject_iri = format!("{ENTITY_BASE}{id}");
    add_annotation_iri(state, dataset_name, url_prefix, &subject_iri, username, note).await
}

/// Add a note to an arbitrary resource `subject_iri` (Epic H, generalised to
/// all resource/term views — the `_view?iri=` POST). Caller MUST have enforced
/// a logged-in session (both POST routes do — neither `_entity` nor `_view` is
/// in the write-exempt list, so anonymous is redirected to login); `username`
/// is that user. INSERTs an `oa:Annotation` into the annotations graph with the
/// text/creator escaped and the timestamp taken server-side via SPARQL `NOW()`.
/// Redirects (PRG) back to the resource's native view.
pub async fn add_annotation_iri(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    subject_iri: &str,
    username: &str,
    note: &str,
) -> Response {
    if NamedNode::new(subject_iri).is_err() {
        return (StatusCode::BAD_REQUEST, "Malformed resource IRI").into_response();
    }
    let note = note.trim();
    let redirect_to = native_href(subject_iri, url_prefix);
    if note.is_empty() {
        // Nothing to add — just bounce back to the view.
        return Redirect::to(&redirect_to).into_response();
    }
    if note.len() > crate::markdown::MAX_NOTE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Note too long: {} bytes, maximum {} bytes",
                note.len(),
                crate::markdown::MAX_NOTE_BYTES
            ),
        )
            .into_response();
    }
    let Some(store) = state.store_manager.get_dataset(dataset_name) else {
        return (StatusCode::NOT_FOUND, "Dataset not found").into_response();
    };
    let update = build_annotation_insert(subject_iri, note, username);
    match sparql_update(&store, &update) {
        Ok(()) => Redirect::to(&redirect_to).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Insert error: {e}")).into_response(),
    }
}

/// A resource's broad kind, which selects the extra per-kind content of its
/// view (Epic G2): a class lists its instances, a property lists its usage.
fn resource_kind(types: &[TypeRef]) -> &'static str {
    let is = |iri: &str| types.iter().any(|t| t.iri == iri);
    if is("http://www.w3.org/2002/07/owl#Class") || is("http://www.w3.org/2000/01/rdf-schema#Class")
    {
        "class"
    } else if is("http://www.w3.org/2002/07/owl#ObjectProperty")
        || is("http://www.w3.org/2002/07/owl#DatatypeProperty")
        || is("http://www.w3.org/1999/02/22-rdf-syntax-ns#Property")
    {
        "property"
    } else {
        "individual"
    }
}

/// A link to another resource (instance-list / usage-list rows), with its
/// native (view→view) href resolved.
#[derive(Serialize, Debug, PartialEq)]
struct LinkRow {
    iri: String,
    href: String,
    display: String,
    label: Option<String>,
}

/// Run a `SELECT ?<var> (SAMPLE(?l) AS ?lab)` list query and map each row to a
/// `LinkRow` (native href + short display + optional label). Shared by the
/// class-instance and property-usage lists.
fn link_rows(store: &Store, query: &str, var: &str, url_prefix: &str) -> Vec<LinkRow> {
    let mut rows = Vec::new();
    // Bounded like the public `_sparql` endpoint: a page of a very large
    // class must not hold a worker indefinitely.
    if let Ok(QueryResults::Solutions(sols)) =
        sparql_query_union_timeout(store, query, QUERY_TIMEOUT)
    {
        for sol in sols.flatten() {
            if let Some(Term::NamedNode(n)) = sol.get(var) {
                let iri = n.as_str().to_string();
                rows.push(LinkRow {
                    href: native_href(&iri, url_prefix),
                    display: short_form(&iri),
                    label: literal_value(sol.get("lab")),
                    iri,
                });
            }
        }
    }
    rows
}

/// Run a `SELECT (COUNT(DISTINCT ?x) AS ?n)` query and return the count.
/// A failed or timed-out query counts as 0 (the list then renders empty), and
/// is logged so that state is diagnosable.
fn count_query(store: &Store, query: &str) -> usize {
    match sparql_query_union_timeout(store, query, QUERY_TIMEOUT) {
        Ok(QueryResults::Solutions(mut sols)) => match sols.next() {
            Some(Ok(sol)) => match sol.get("n") {
                Some(Term::Literal(lit)) => lit.value().parse().unwrap_or(0),
                _ => 0,
            },
            Some(Err(e)) => {
                tracing::warn!("resource-list count failed: {e}");
                0
            }
            None => 0,
        },
        Ok(_) => 0,
        Err(e) => {
            tracing::warn!("resource-list count failed: {e}");
            0
        }
    }
}

/// Number of distinct (subclass-aware) instances of a class. Deliberately
/// label-free: no `OPTIONAL`/`GROUP BY`, so it stays cheap on a large class.
/// Counts IRIs only, like the page query (blank-node instances have no link
/// to render), so the total and the rows agree.
fn class_instance_count(store: &Store, class_iri: &str) -> usize {
    let q = format!(
        r#"SELECT (COUNT(DISTINCT ?i) AS ?n) WHERE {{
            ?i a/<{RDFS_SUBCLASS_OF}>* <{class_iri}> .
            FILTER(isIRI(?i))
        }}"#
    );
    count_query(store, &q)
}

/// One page of the subclass-aware instance list for a class view (the B2
/// Explore query, with the merged `GROUP BY`+`SAMPLE` label dedup), ordered
/// by IRI so pages are stable.
fn class_instances(
    store: &Store,
    class_iri: &str,
    url_prefix: &str,
    offset: usize,
    limit: usize,
) -> Vec<LinkRow> {
    let q = format!(
        r#"SELECT ?i (SAMPLE(?l) AS ?lab) WHERE {{
            ?i a/<{RDFS_SUBCLASS_OF}>* <{class_iri}> .
            FILTER(isIRI(?i))
            OPTIONAL {{ ?i <{RDFS_LABEL}> ?l }}
        }} GROUP BY ?i ORDER BY ?i LIMIT {limit} OFFSET {offset}"#
    );
    link_rows(store, &q, "i", url_prefix)
}

/// Number of distinct IRI subjects that use a property (blank-node subjects
/// are not listed, so they are not counted).
fn property_usage_count(store: &Store, property_iri: &str) -> usize {
    let q = format!(
        r#"SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE {{
            ?s <{property_iri}> ?o .
            FILTER(isIRI(?s))
        }}"#
    );
    count_query(store, &q)
}

/// One page of the distinct subjects that use a property (its usage list for
/// a property view), ordered by IRI so pages are stable.
fn property_usages(
    store: &Store,
    property_iri: &str,
    url_prefix: &str,
    offset: usize,
    limit: usize,
) -> Vec<LinkRow> {
    let q = format!(
        r#"SELECT ?s (SAMPLE(?l) AS ?lab) WHERE {{
            ?s <{property_iri}> ?o .
            FILTER(isIRI(?s))
            OPTIONAL {{ ?s <{RDFS_LABEL}> ?l }}
        }} GROUP BY ?s ORDER BY ?s LIMIT {limit} OFFSET {offset}"#
    );
    link_rows(store, &q, "s", url_prefix)
}

/// A collapsible, server-paginated resource list (a class's instances or a
/// property's usages — issue #4). The template renders it as a `<details>`
/// block whose summary carries `total`, with `prev_href`/`next_href` page
/// links; no client-side script is involved.
#[derive(Serialize, Debug, PartialEq)]
struct ResourceList {
    /// The rows of the current page.
    rows: Vec<LinkRow>,
    /// Total number of rows across all pages.
    total: usize,
    /// Current page (1-based, clamped into `1..=pages`).
    page: usize,
    /// Number of pages (at least 1, so an empty list still has "page 1 of 1").
    pages: usize,
    /// 1-based index of the first / last row on this page (`0`/`0` when empty).
    first: usize,
    last: usize,
    prev_href: Option<String>,
    next_href: Option<String>,
    /// Whether the `<details>` starts expanded: the list is collapsed when the
    /// view is opened, and expanded when the user has asked for a page
    /// (`?page=N`), so following a page link lands on a visible list.
    open: bool,
}

/// Build the page `page` (1-based; `None` = page 1, collapsed) of a list with
/// `total` rows, `page_size` rows per page. `fetch(offset, limit)` loads the
/// rows of the chosen page; it is called exactly once, after the page has been
/// clamped, so a `?page=` beyond the end shows the last page rather than an
/// empty one (`Some(0)` is clamped to page 1 and, like any explicit page,
/// expanded — the route maps `?page=0` to `None` before it gets here). Page
/// links are `self_href` + `page=N` + `#fragment`.
fn paginate(
    total: usize,
    page: Option<u32>,
    page_size: usize,
    self_href: &str,
    fragment: &str,
    fetch: impl FnOnce(usize, usize) -> Vec<LinkRow>,
) -> ResourceList {
    let page_size = page_size.max(1);
    let pages = total.div_ceil(page_size).max(1);
    let current = (page.unwrap_or(1) as usize).clamp(1, pages);
    let offset = (current - 1) * page_size;
    let rows = if total == 0 {
        Vec::new()
    } else {
        fetch(offset, page_size)
    };
    let href = |n: usize| {
        let sep = if self_href.contains('?') { '&' } else { '?' };
        format!("{self_href}{sep}page={n}#{fragment}")
    };
    ResourceList {
        first: if rows.is_empty() { 0 } else { offset + 1 },
        last: if rows.is_empty() {
            0
        } else {
            offset + rows.len()
        },
        total,
        page: current,
        pages,
        prev_href: (current > 1).then(|| href(current - 1)),
        next_href: (current < pages).then(|| href(current + 1)),
        open: page.is_some(),
        rows,
    }
}

/// Extract the lexical value of a literal term, if the term is a literal.
fn literal_value(term: Option<&Term>) -> Option<String> {
    match term {
        Some(Term::Literal(lit)) => Some(lit.value().to_string()),
        _ => None,
    }
}

fn entity_not_found(state: &AppState, subject_iri: &str, format: &str) -> Response {
    // For any RDF representation, a plain-text 404 (no HTML body with the wrong
    // content type).
    if rdf_format_for(format).is_some() {
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

/// Dereference the entity `<ENTITY_BASE>{id}` (the short `_entity/{id}` route).
/// A thin wrapper over the generic [`serve_resource`]; the entity route is kept
/// as the canonical, ergonomic form for our own `entity/` namespace.
#[allow(clippy::too_many_arguments)] // mirrors `serve_resource`
pub async fn serve_entity(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    id: &str,
    headers: &HeaderMap,
    username: Option<String>,
    is_admin: bool,
    page: Option<u32>,
) -> Response {
    let subject_iri = format!("{ENTITY_BASE}{id}");
    serve_resource(
        state,
        dataset_name,
        url_prefix,
        &subject_iri,
        headers,
        username,
        is_admin,
        page,
    )
    .await
}

/// Serve a local view of an arbitrary resource `subject_iri` (the generic
/// `_view?iri=<encoded>` route — Epic G). Negotiates the representation from
/// `Accept` exactly like the entity route; the HTML view is the generalised
/// per-resource page. `url_prefix` is the dataset base used to build native
/// (view→view) links, e.g. `/mlips/_ds/mlips`.
#[allow(clippy::too_many_arguments)] // route-dispatch signature: request facts + `?page=`
pub async fn serve_resource(
    state: &AppState,
    dataset_name: &str,
    url_prefix: &str,
    subject_iri: &str,
    headers: &HeaderMap,
    username: Option<String>,
    is_admin: bool,
    page: Option<u32>,
) -> Response {
    let format = negotiate_format(headers);

    // Validate the IRI with oxigraph before it is interpolated into any SPARQL
    // (`<{subject_iri}>`): a valid IRI cannot contain the `<`/`>`/whitespace
    // that would let arbitrary `?iri=` input break out of the term. Reject
    // rather than 404 so a malformed request is not mistaken for a missing one.
    if NamedNode::new(subject_iri).is_err() {
        return (StatusCode::BAD_REQUEST, "Malformed resource IRI").into_response();
    }

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

    let subject_iri = subject_iri.to_string();

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

    match rdf_format_for(format) {
        Some(rdf_format) => {
            // Concise Bounded Description: forward triples of the subject.
            let q = format!(
                r#"CONSTRUCT {{ <{subject_iri}> ?p ?o }} WHERE {{ <{subject_iri}> ?p ?o }}"#
            );
            let triples = match sparql_query_union(&store, &q) {
                Ok(QueryResults::Graph(t)) => t,
                _ => return (StatusCode::INTERNAL_SERVER_ERROR, "Query error").into_response(),
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
        None => {
            // HTML view (default). Rewrite native hrefs against this dataset.
            let mut forward = forward_rows(&store, &subject_iri);
            for r in &mut forward {
                if r.kind == "iri" {
                    r.target_href = native_href(&r.target_iri, url_prefix);
                }
            }
            let types = types_of(&store, &subject_iri);
            let kind = resource_kind(&types);
            // On a class view the `rdf:type` back-links are the instance list
            // (collapsed and paginated below), so the table leaves them out.
            let mut reverse = reverse_rows(&store, &subject_iri, kind == "class");
            for r in &mut reverse {
                if r.source_kind == "iri" {
                    r.source_href = native_href(&r.source_iri, url_prefix);
                }
            }
            let label = lookup_label(&store, &subject_iri);

            // Self permalink (the concon-native view URL: `_entity/{id}` for
            // an entity, `_view?iri=…` for any other resource); also the base
            // for the "Other formats" content-negotiated fetches and for the
            // list page links.
            let self_href = native_href(&subject_iri, url_prefix);

            // Per-kind content (G2): a class lists its (subclass-aware)
            // instances; a property lists the subjects that use it. Both are
            // collapsed and paginated (issue #4); `?page=` selects the page.
            let instances = (kind == "class").then(|| {
                paginate(
                    class_instance_count(&store, &subject_iri),
                    page,
                    RESOURCE_LIST_PAGE_SIZE,
                    &self_href,
                    "instances",
                    |offset, limit| {
                        class_instances(&store, &subject_iri, url_prefix, offset, limit)
                    },
                )
            });
            let usages = (kind == "property").then(|| {
                paginate(
                    property_usage_count(&store, &subject_iri),
                    page,
                    RESOURCE_LIST_PAGE_SIZE,
                    &self_href,
                    "usages",
                    |offset, limit| {
                        property_usages(&store, &subject_iri, url_prefix, offset, limit)
                    },
                )
            });

            // Epic H — annotations. Notes are readable by anyone who can read
            // the view; the add-note form is shown to any logged-in user, on
            // every resource/term view (the POST routes handle both
            // `_entity/{id}` and `_view?iri=`). The form posts to `self_href`.
            let annotations = annotations_of(&store, &subject_iri);
            let can_annotate = username.is_some();

            // Breadcrumb (Home / <team> / <dataset> / <entity>), same parts as
            // the ontology-doc chrome; the entity itself is the <h1> text.
            let (team_href, team_label, dataset_label) = ontology::breadcrumb_parts(url_prefix);

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
                self_href => &self_href,
                // "↗ canonical URL": the subject's own canonical IRI (Epic G3).
                // For a term this resolves to its defining authority (our doc,
                // or schema.org, …); for an entity, to itself.
                defined_at => &subject_iri,
                team_href => team_href,
                team_label => team_label,
                dataset_label => dataset_label,
                label => label,
                kind => kind,
                types => &types,
                forward => &forward,
                reverse => &reverse,
                forward_count => forward.len(),
                reverse_count => reverse.len(),
                instances => &instances,
                usages => &usages,
                annotations => &annotations,
                annotation_count => annotations.len(),
                can_annotate => can_annotate,
                // Dataset base for the client-side graph explorer (Epic J):
                // it derives `_sparql` from this and centres on `subject_iri`.
                dataset_base => url_prefix,
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
        // Entities keep the short `_entity/{id}` dereference URL.
        assert_eq!(
            native_href("https://w3id.org/mlips/entity/kumar2025", "/mlips/_ds/mlips"),
            "/mlips/_ds/mlips/_entity/kumar2025"
        );
        // A local domain term now routes to its generic resource view (Epic G),
        // keeping navigation inside concon (view→view).
        assert_eq!(
            native_href("https://w3id.org/mlips#MLIPMethod", "/mlips/_ds/mlips"),
            "/mlips/_ds/mlips/_view?iri=https%3A%2F%2Fw3id.org%2Fmlips%23MLIPMethod"
        );
        // An external *domain* vocab term also earns a local view.
        assert_eq!(
            native_href("https://schema.org/ScholarlyArticle", "/mlips/_ds/mlips"),
            "/mlips/_ds/mlips/_view?iri=https%3A%2F%2Fschema.org%2FScholarlyArticle"
        );
        // Structural built-ins do NOT — they resolve to their own spec.
        assert_eq!(
            native_href("http://www.w3.org/2002/07/owl#Class", "/mlips/_ds/mlips"),
            "http://www.w3.org/2002/07/owl#Class"
        );
        assert_eq!(
            native_href("http://www.w3.org/2001/XMLSchema#string", "/mlips/_ds/mlips"),
            "http://www.w3.org/2001/XMLSchema#string"
        );
    }

    #[test]
    fn test_earns_local_view() {
        assert!(earns_local_view("https://w3id.org/mlips#MLIPMethod"));
        assert!(earns_local_view("https://schema.org/ScholarlyArticle"));
        assert!(earns_local_view("http://www.w3.org/ns/prov#Entity"));
        assert!(earns_local_view("https://purls.helmholtz-metadaten.de/cmso/Sample"));
        // Built-ins and annotation vocabs are excluded.
        assert!(!earns_local_view("http://www.w3.org/2002/07/owl#Class"));
        assert!(!earns_local_view("http://www.w3.org/2000/01/rdf-schema#label"));
        assert!(!earns_local_view("http://www.w3.org/2001/XMLSchema#string"));
        assert!(!earns_local_view("http://purl.org/dc/terms/title"));
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

    /// A term with several `rdfs:label`s (here a plain copy and an `@en` copy
    /// of the same text, as seen on `mlips:numLayers`) must not duplicate the
    /// property row in the entity view. Regression for the doubled
    /// "for hyperparameter / number of layers" row.
    #[test]
    fn forward_rows_dedups_multi_labelled_object() {
        let store = Store::new().unwrap();
        let ttl = r#"@prefix mlips: <https://w3id.org/mlips#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
<https://w3id.org/mlips/entity/s> mlips:forHyperparameter mlips:numLayers .
mlips:numLayers rdfs:label "number of layers" ;
                rdfs:label "number of layers"@en ."#;
        store
            .load_from_reader(RdfFormat::Turtle, ttl.as_bytes())
            .unwrap();
        let rows = forward_rows(&store, "https://w3id.org/mlips/entity/s");
        let hp: Vec<_> = rows
            .iter()
            .filter(|r| r.predicate_iri == "https://w3id.org/mlips#forHyperparameter")
            .collect();
        assert_eq!(hp.len(), 1, "multi-labelled object duplicated the property row");
        assert_eq!(hp[0].target_label.as_deref(), Some("number of layers"));
    }

    /// G2 per-kind content: a class view lists its subclass-aware instances
    /// (deduped, native hrefs), a property view lists its usage subjects, and
    /// resource_kind classifies from the rdf:type set.
    #[test]
    fn class_instances_and_property_usages() {
        let store = Store::new().unwrap();
        let ttl = r#"@prefix mlips: <https://w3id.org/mlips#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
mlips:Method a owl:Class .
mlips:MLMethod a owl:Class ; rdfs:subClassOf mlips:Method .
mlips:usesFramework a owl:ObjectProperty .
<https://w3id.org/mlips/entity/a> a mlips:Method ; mlips:usesFramework <https://w3id.org/mlips/entity/tf> .
<https://w3id.org/mlips/entity/b> a mlips:MLMethod ; rdfs:label "B" ; rdfs:label "B"@en .
<https://w3id.org/mlips/entity/c> a mlips:Method ; mlips:usesFramework <https://w3id.org/mlips/entity/tf> .
[] a mlips:Method ; mlips:usesFramework <https://w3id.org/mlips/entity/tf> ."#;
        store
            .load_from_reader(RdfFormat::Turtle, ttl.as_bytes())
            .unwrap();
        let prefix = "/mlips/_ds/mlips";

        // Subclass-aware: a, b (via MLMethod ⊑ Method), c — three distinct, and
        // the multi-labelled b appears once (dedup), with a native _entity href.
        // The count query agrees with the list (same subclass-aware pattern,
        // DISTINCT so the double label does not double-count b; the blank-node
        // instance is neither listed nor counted).
        assert_eq!(
            class_instance_count(&store, "https://w3id.org/mlips#Method"),
            3
        );
        assert_eq!(
            class_instance_count(&store, "https://w3id.org/mlips#MLMethod"),
            1
        );
        let instances = class_instances(&store, "https://w3id.org/mlips#Method", prefix, 0, 50);
        assert_eq!(
            instances.len(),
            3,
            "expected 3 distinct instances (b not doubled)"
        );
        let b = instances
            .iter()
            .find(|r| r.iri.ends_with("/b"))
            .expect("instance b present");
        assert_eq!(b.label.as_deref(), Some("B"));
        assert_eq!(b.href, "/mlips/_ds/mlips/_entity/b");

        // Property usage: a and c use usesFramework → two distinct subjects.
        assert_eq!(
            property_usage_count(&store, "https://w3id.org/mlips#usesFramework"),
            2
        );
        let usages = property_usages(
            &store,
            "https://w3id.org/mlips#usesFramework",
            prefix,
            0,
            50,
        );
        assert_eq!(usages.len(), 2);

        // Paging slices (issue #4): ordered by IRI (a, b, c), offset/limit
        // select a stable window, and an offset past the end is empty.
        let ids = |rows: &[LinkRow]| -> Vec<String> {
            rows.iter()
                .map(|r| r.iri.rsplit('/').next().unwrap().to_string())
                .collect()
        };
        assert_eq!(ids(&instances), ["a", "b", "c"]);
        let page2 = class_instances(&store, "https://w3id.org/mlips#Method", prefix, 2, 2);
        assert_eq!(ids(&page2), ["c"]);
        assert_eq!(
            ids(&class_instances(
                &store,
                "https://w3id.org/mlips#Method",
                prefix,
                1,
                1
            )),
            ["b"]
        );
        assert!(class_instances(&store, "https://w3id.org/mlips#Method", prefix, 3, 2).is_empty());
        let u2 = property_usages(&store, "https://w3id.org/mlips#usesFramework", prefix, 1, 5);
        assert_eq!(ids(&u2), ["c"]);

        // "Referenced by" on a class: the rdf:type back-links (a, c, and the
        // blank node) are the instance list, so a class view drops them and
        // keeps the other reverse links (MLMethod ⊑ Method).
        let all = reverse_rows(&store, "https://w3id.org/mlips#Method", false);
        assert_eq!(all.len(), 4, "{all:?}");
        let non_type = reverse_rows(&store, "https://w3id.org/mlips#Method", true);
        assert_eq!(non_type.len(), 1, "{non_type:?}");
        assert_eq!(non_type[0].predicate_iri, RDFS_SUBCLASS_OF);
        assert!(non_type[0].source_iri.ends_with("#MLMethod"));

        // Kind classification.
        assert_eq!(resource_kind(&types_of(&store, "https://w3id.org/mlips#Method")), "class");
        assert_eq!(
            resource_kind(&types_of(&store, "https://w3id.org/mlips#usesFramework")),
            "property"
        );
        assert_eq!(
            resource_kind(&types_of(&store, "https://w3id.org/mlips/entity/a")),
            "individual"
        );
    }

    /// Epic H: the annotation INSERT actually writes to the annotations graph
    /// and reads back via annotations_of — validates NOW()/STRUUID()/GRAPH
    /// against oxigraph, and that a note with quotes/newlines is stored intact
    /// (escaping did not corrupt or break out of the literal).
    #[test]
    fn annotation_insert_and_read_roundtrip() {
        let store = Store::new().unwrap();
        let entity = "https://w3id.org/mlips/entity/kumar2025";
        let note = "great work!\nsays \"me\" — needs \\escaping";
        let upd = build_annotation_insert(entity, note, "alice");
        sparql_update(&store, &upd).expect("annotation insert");

        let rows = annotations_of(&store, entity);
        assert_eq!(rows.len(), 1, "one note should be stored and read back");
        assert_eq!(rows[0].body, note, "note text preserved through escape/store");
        assert_eq!(rows[0].creator, "alice");
        assert!(!rows[0].created.is_empty(), "NOW() stamped a created time");
        // The anchor comes from the STRUUID-minted annotation IRI, and the
        // body is also served as rendered Markdown (newline → <br>, quotes
        // intact, nothing script-like).
        assert!(rows[0].anchor.starts_with("note-"), "{}", rows[0].anchor);
        assert!(rows[0].anchor.len() > "note-".len(), "{}", rows[0].anchor);
        let html = &rows[0].body_html;
        assert!(html.contains("great work!<br />"), "{html}");
        assert!(html.contains("says \"me\""), "{html}");

        // Targets are isolated: a different entity has no notes.
        assert!(annotations_of(&store, "https://w3id.org/mlips/entity/other").is_empty());
    }

    /// Epic H-ext: annotations round-trip for a non-entity (term/class) IRI
    /// too — the same INSERT/read path works for any resource view, not only
    /// `entity/` subjects.
    #[test]
    fn annotation_roundtrip_on_a_term_iri() {
        let store = Store::new().unwrap();
        let term = "https://w3id.org/mlips#Hyperparameter";
        sparql_update(&store, &build_annotation_insert(term, "a note on a class", "bob"))
            .expect("insert on term");
        let rows = annotations_of(&store, term);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].body, "a note on a class");
        assert_eq!(rows[0].creator, "bob");
    }

    /// Markdown in a stored note is rendered (link + code) and sanitised
    /// (script dropped) on read-back; the raw source is kept as-is.
    #[test]
    fn annotation_markdown_is_rendered_and_sanitised() {
        let store = Store::new().unwrap();
        let term = "https://w3id.org/mlips#Method";
        let note = "see [the paper](https://example.org/p) and `run()` <script>alert(1)</script>";
        sparql_update(&store, &build_annotation_insert(term, note, "bob")).expect("insert");
        let rows = annotations_of(&store, term);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].body, note, "raw Markdown source is stored untouched");
        let html = &rows[0].body_html;
        assert!(html.contains(r#"<a href="https://example.org/p""#), "{html}");
        assert!(html.contains("<code>run()</code>"), "{html}");
        assert!(!html.contains("<script"), "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)"), "{html}");
    }

    /// The add-note POST refuses a note over `MAX_NOTE_BYTES` with 413 and
    /// stores nothing; a note exactly at the cap is accepted.
    #[tokio::test]
    async fn oversized_note_is_rejected_before_storing() {
        use crate::markdown::MAX_NOTE_BYTES;
        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("t/d").unwrap();
        let subject = "https://w3id.org/mlips#Method";
        let too_long = "x".repeat(MAX_NOTE_BYTES + 1);
        let resp = add_annotation_iri(&state, "t/d", "/t/_ds/d", subject, "alice", &too_long).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let store = state.store_manager.get_dataset("t/d").unwrap();
        assert!(annotations_of(&store, subject).is_empty(), "nothing stored");

        let at_cap = "y".repeat(MAX_NOTE_BYTES);
        let resp = add_annotation_iri(&state, "t/d", "/t/_ds/d", subject, "alice", &at_cap).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(annotations_of(&store, subject).len(), 1);
    }

    #[test]
    fn annotation_anchor_is_fragment_safe() {
        assert_eq!(
            annotation_anchor("https://w3id.org/mlips/annotation/0b1c-2d3e", 7),
            "note-0b1c-2d3e"
        );
        // Unsafe or missing local part → positional fallback.
        assert_eq!(annotation_anchor("https://x/annotation/a b", 3), "note-3");
        assert_eq!(annotation_anchor("https://x/annotation/\"><x", 4), "note-4");
        assert_eq!(annotation_anchor("", 5), "note-5");
    }

    #[test]
    fn escape_sparql_literal_neutralizes_quotes() {
        assert_eq!(escape_sparql_literal(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_sparql_literal("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_negotiate_format() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, "text/turtle".parse().unwrap());
        assert_eq!(negotiate_format(&h), "ttl");
        h.insert(header::ACCEPT, "application/rdf+xml".parse().unwrap());
        assert_eq!(negotiate_format(&h), "owl");
        h.insert(header::ACCEPT, "application/n-triples".parse().unwrap());
        assert_eq!(negotiate_format(&h), "nt");
        h.insert(header::ACCEPT, "application/ld+json".parse().unwrap());
        assert_eq!(negotiate_format(&h), "jsonld");
        // q-values / parameters are stripped; first recognized type wins.
        h.insert(
            header::ACCEPT,
            "application/ld+json;q=0.9, text/turtle".parse().unwrap(),
        );
        assert_eq!(negotiate_format(&h), "jsonld");
        h.insert(
            header::ACCEPT,
            "text/html,application/xhtml+xml".parse().unwrap(),
        );
        assert_eq!(negotiate_format(&h), "xhtml");
        // Unknown / missing → default xhtml.
        assert_eq!(negotiate_format(&HeaderMap::new()), "xhtml");
    }

    /// Every negotiated RDF format must actually serialize a triple at runtime
    /// (not just resolve) — guards the JSON-LD/N-Triples codecs end-to-end so a
    /// serialize failure can't surface only in production.
    #[test]
    fn rdf_formats_serialize_a_triple() {
        use oxigraph::io::RdfSerializer;
        use oxigraph::model::{LiteralRef, NamedNodeRef, TripleRef};
        let s = NamedNodeRef::new("https://w3id.org/mlips/entity/x").unwrap();
        let p = NamedNodeRef::new("https://w3id.org/mlips#settingValue").unwrap();
        let o = LiteralRef::new_simple_literal("4");
        let triple = TripleRef::new(s, p, o);
        for code in ["ttl", "owl", "nt", "jsonld"] {
            let fmt = rdf_format_for(code).unwrap();
            let mut ser = RdfSerializer::from_format(fmt).for_writer(Vec::new());
            ser.serialize_triple(triple).unwrap();
            let buf = ser.finish().unwrap();
            assert!(!buf.is_empty(), "{code} serialized to empty output");
        }
    }

    #[test]
    fn test_rdf_format_for() {
        use oxigraph::io::RdfFormat;
        assert_eq!(rdf_format_for("ttl"), Some(RdfFormat::Turtle));
        assert_eq!(rdf_format_for("owl"), Some(RdfFormat::RdfXml));
        assert_eq!(rdf_format_for("nt"), Some(RdfFormat::NTriples));
        // JSON-LD resolves (codec present) and round-trips its media type.
        let jsonld = rdf_format_for("jsonld").expect("jsonld supported");
        assert_eq!(jsonld.media_type(), "application/ld+json");
        // Non-RDF codes map to None (→ HTML/doc path).
        assert_eq!(rdf_format_for("xhtml"), None);
        assert_eq!(rdf_format_for("nonsense"), None);
        // content_type_for stays consistent with the new codes.
        assert_eq!(
            content_type_for("nt"),
            "application/n-triples; charset=utf-8"
        );
        assert_eq!(
            content_type_for("jsonld"),
            "application/ld+json; charset=utf-8"
        );
    }

    /// The `<details id="{id}">…</details>` block of a rendered entity view
    /// (the list under test), so row assertions are not confused by the same
    /// labels appearing in the "Referenced by" table.
    fn list_block(body: &str, id: &str) -> String {
        let start = body
            .find(&format!(r#"<details id="{id}""#))
            .unwrap_or_else(|| panic!("no <details id={id}> in:\n{body}"));
        let end = body[start..]
            .find("</details>")
            .expect("closing </details>");
        body[start..start + end].to_string()
    }

    fn fake_rows(offset: usize, limit: usize) -> Vec<LinkRow> {
        (offset..offset + limit)
            .map(|i| LinkRow {
                iri: format!("https://x/{i}"),
                href: format!("/x/{i}"),
                display: format!("x:{i}"),
                label: None,
            })
            .collect()
    }

    /// Issue #4 paging boundaries: page clamping, first/last indices, prev/next
    /// links, and the collapsed-by-default rule (`open` only with `?page=`).
    #[test]
    fn paginate_boundaries() {
        // `fetch` receives the clamped window and is told the page size.
        let calls = std::cell::Cell::new(0);
        let fetch = |offset: usize, limit: usize| {
            calls.set(calls.get() + 1);
            fake_rows(offset, limit.min(7usize.saturating_sub(offset)))
        };

        // Empty list: one page, no rows, no links, collapsed, fetch not called.
        let l = paginate(0, None, 3, "/d/_entity/C", "instances", fetch);
        assert_eq!(calls.get(), 0);
        assert_eq!((l.total, l.page, l.pages, l.first, l.last), (0, 1, 1, 0, 0));
        assert!(l.rows.is_empty() && l.prev_href.is_none() && l.next_href.is_none());
        assert!(!l.open, "collapsed when no page was requested");

        // 7 rows, page size 3 → 3 pages. Page 1 (implicit): rows 1–3, next only.
        let l = paginate(7, None, 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.page, l.pages, l.first, l.last), (1, 3, 1, 3));
        assert_eq!(l.rows.len(), 3);
        assert_eq!(l.prev_href, None);
        assert_eq!(
            l.next_href.as_deref(),
            Some("/d/_entity/C?page=2#instances")
        );
        assert!(!l.open);

        // Explicit page 1: same page, but expanded.
        let l = paginate(7, Some(1), 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.page, l.first, l.last), (1, 1, 3));
        assert!(l.open, "expanded when a page was requested");

        // Middle page: both links.
        let l = paginate(7, Some(2), 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.first, l.last), (4, 6));
        assert_eq!(
            l.prev_href.as_deref(),
            Some("/d/_entity/C?page=1#instances")
        );
        assert_eq!(
            l.next_href.as_deref(),
            Some("/d/_entity/C?page=3#instances")
        );

        // Last (partial) page: one row, prev only.
        let l = paginate(7, Some(3), 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.first, l.last), (7, 7));
        assert_eq!(l.rows.len(), 1);
        assert!(l.prev_href.is_some() && l.next_href.is_none());

        // Out of range clamps: 0 → 1, 99 → last page (never an empty page).
        let l = paginate(7, Some(0), 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.page, l.first), (1, 1));
        let l = paginate(7, Some(99), 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.page, l.first, l.last), (3, 7, 7));
        assert!(l.open);

        // Exact multiple: 6 rows / 3 → 2 pages, page 2 is full and last.
        let l = paginate(6, Some(2), 3, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.pages, l.first, l.last), (2, 4, 6));
        assert!(l.next_href.is_none());

        // A `_view?iri=…` self href already has a query string → `&page=`.
        let l = paginate(
            7,
            Some(1),
            3,
            "/d/_view?iri=https%3A%2F%2Fx%23C",
            "usages",
            fetch,
        );
        assert_eq!(
            l.next_href.as_deref(),
            Some("/d/_view?iri=https%3A%2F%2Fx%23C&page=2#usages")
        );

        // A zero page size cannot divide by zero: it is treated as 1.
        let l = paginate(2, None, 0, "/d/_entity/C", "instances", fetch);
        assert_eq!((l.pages, l.rows.len()), (2, 1));
    }

    /// Issue #4 end to end: the class view serves the instance list collapsed
    /// (no `open`), with the total in the summary; `?page=N` expands it and
    /// pages through the rows at `RESOURCE_LIST_PAGE_SIZE`; a page past the end
    /// clamps to the last page; an individual's `_entity` view is unaffected.
    #[tokio::test]
    async fn class_view_instances_collapsed_and_paginated() {
        use crate::routes::create_router;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("root/pub").unwrap();
        state
            .store_manager
            .insert_dataset_metadata("root/pub")
            .unwrap();
        let store = state.store_manager.get_dataset("root/pub").unwrap();
        let n = RESOURCE_LIST_PAGE_SIZE + 1;
        let mut ttl = String::from(
            "@prefix mlips: <https://w3id.org/mlips#> .\n\
             @prefix owl: <http://www.w3.org/2002/07/owl#> .\n\
             @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
             mlips:Method a owl:Class .\n\
             mlips:MLMethod a owl:Class ; rdfs:subClassOf mlips:Method .\n\
             mlips:Empty a owl:Class .\n\
             mlips:usesFramework a owl:ObjectProperty .\n\
             [] a mlips:Method ; rdfs:label \"Anon\" ; mlips:usesFramework <https://w3id.org/mlips/entity/tf> .\n",
        );
        for i in 0..n {
            // Zero-padded ids so IRI order == numeric order; the last one is an
            // instance via the subclass, to keep the count subclass-aware.
            let cls = if i == n - 1 {
                "mlips:MLMethod"
            } else {
                "mlips:Method"
            };
            ttl.push_str(&format!(
                "<https://w3id.org/mlips/entity/i{i:03}> a {cls} ; rdfs:label \"Inst {i:03}\" ; \
                 mlips:usesFramework <https://w3id.org/mlips/entity/tf> .\n"
            ));
        }
        store
            .load_from_reader(RdfFormat::Turtle, ttl.as_bytes())
            .unwrap();
        drop(store);

        let server = TestServer::new(create_router(state));
        let class_iri = "https://w3id.org/mlips#Method";
        let get = |page: Option<&str>, iri: &str| {
            let mut req = server.get("/_ds/pub/_view").add_query_param("iri", iri);
            if let Some(p) = page {
                req = req.add_query_param("page", p);
            }
            req
        };

        // Collapsed by default: a <details> without `open`, total in summary,
        // first page of rows present, next link but no previous. The blank-node
        // instance is neither counted nor listed. The "Referenced by" table no
        // longer repeats the instances (their rdf:type back-links), so the
        // labels of the instances appear only inside the list.
        let r = get(None, class_iri).await;
        r.assert_status_ok();
        let body = r.text();
        assert_eq!(
            body.matches("Inst 000").count(),
            1,
            "instance only in the list"
        );
        assert!(!body.contains("Anon"), "blank-node instance not rendered");
        assert!(
            body.contains("Referenced by (1)"),
            "only the subclass back-link remains"
        );
        let list = list_block(&body, "instances");
        assert!(
            list.starts_with(r#"<details id="instances" class="resource-list-box">"#),
            "collapsed (no `open`): {list}"
        );
        assert!(
            list.contains(&format!("Instances ({n})")),
            "total in summary"
        );
        assert!(
            list.contains("Inst 000") && list.contains("Inst 049"),
            "first page rows: {list}"
        );
        assert!(
            !list.contains("Inst 050"),
            "row beyond the page not on page 1"
        );
        assert!(
            list.contains(&format!("Showing 1–{} of {n} instances", n - 1)),
            "{list}"
        );
        assert!(list.contains(r#"rel="next""#) && !list.contains(r#"rel="prev""#));
        assert!(
            list.contains("page=2#instances"),
            "next link points at page 2"
        );

        // Page 2: expanded, the one remaining row, previous link only.
        let r = get(Some("2"), class_iri).await;
        r.assert_status_ok();
        let list = list_block(&r.text(), "instances");
        assert!(
            list.starts_with(r#"<details id="instances" class="resource-list-box" open="">"#),
            "expanded: {list}"
        );
        assert!(
            list.contains("Inst 050") && !list.contains("Inst 049"),
            "{list}"
        );
        assert!(
            list.contains(&format!("Showing {n}–{n} of {n} instances")),
            "{list}"
        );
        assert!(list.contains("Page 2 of 2"));
        assert!(list.contains(r#"rel="prev""#) && !list.contains(r#"rel="next""#));

        // Past the end clamps to the last page (expanded), including a number
        // beyond u32; garbage and `0` mean "no page" (page 1, collapsed).
        for huge in ["99", "99999999999", "18446744073709551615"] {
            let r = get(Some(huge), class_iri).await;
            r.assert_status_ok();
            let list = list_block(&r.text(), "instances");
            assert!(
                list.contains("Page 2 of 2") && list.contains(" open=\"\""),
                "{huge}: {list}"
            );
        }
        for junk in ["x", "0", "-1", "1.5", "99999999999999999999999"] {
            let r = get(Some(junk), class_iri).await;
            r.assert_status_ok();
            let list = list_block(&r.text(), "instances");
            assert!(
                list.contains("Inst 000") && !list.contains(r#"resource-list-box" open"#),
                "{junk}: {list}"
            );
        }

        // The property view gets the same treatment, under its own fragment id.
        let r = get(None, "https://w3id.org/mlips#usesFramework").await;
        r.assert_status_ok();
        let list = list_block(&r.text(), "usages");
        assert!(list.starts_with(r#"<details id="usages" class="resource-list-box">"#));
        assert!(
            list.contains(&format!("Used by ({n})")),
            "bnode subject not counted: {list}"
        );
        assert!(list.contains("page=2#usages"));
        let r = get(Some("2"), "https://w3id.org/mlips#usesFramework").await;
        let list = list_block(&r.text(), "usages");
        assert!(
            list.contains(&format!("Showing {n}–{n} of {n} subjects")),
            "{list}"
        );

        // A class without instances: a collapsed, empty list with a zero count.
        let r = get(None, "https://w3id.org/mlips#Empty").await;
        r.assert_status_ok();
        let list = list_block(&r.text(), "instances");
        assert!(list.starts_with(r#"<details id="instances" class="resource-list-box">"#));
        assert!(list.contains("Instances (0)"), "{list}");
        assert!(list.contains("No instances in this dataset."));
        assert!(!list.contains("pager"), "no pager on an empty list");

        // A single-page list (the subclass has one direct instance) shows its
        // range but no page position / links.
        let r = get(None, "https://w3id.org/mlips#MLMethod").await;
        r.assert_status_ok();
        let list = list_block(&r.text(), "instances");
        assert!(
            list.contains("Instances (1)") && list.contains("Inst 050"),
            "{list}"
        );
        assert!(list.contains("Showing 1–1 of 1 instances"));
        assert!(!list.contains("pager-pos") && !list.contains("rel="));

        // An individual's `_entity` view has neither list and still works.
        let r = server.get("/_ds/pub/_entity/i000").await;
        r.assert_status_ok();
        let body = r.text();
        assert!(
            !body.contains("<details id="),
            "no instance/usage list on an individual"
        );
        assert!(body.contains("Inst 000"));
    }
}
