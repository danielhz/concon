//! Ontology-document view with content negotiation (epic A2).
//!
//! Served at a dataset's base URL (`<dataset-base>/`, i.e. the `None` view):
//!
//! - `Accept: text/html` / `application/xhtml+xml` → the curated XHTML document
//!   (doc-as-file; stored via the ingest endpoint, served here). The document
//!   is the literate source of truth — concon serves it, it does **not**
//!   regenerate it from the triples. Serve-time augmentation with the Epic-B
//!   controls (per-concept "explore individuals" + the CQ section) hooks in
//!   here later; for now the document is served verbatim.
//! - `Accept: text/turtle` / `application/rdf+xml` → the ontology serialized
//!   from its schema + vocabulary named graphs.
//!
//! Companion assets referenced by the document (e.g. its stylesheet) are served
//! from the same doc store at `<dataset-base>/{file}`.
//!
//! When a dataset has no stored document, the caller falls back to the YASGUI
//! editor (preserving the platform-generic default for ordinary datasets).

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use oxigraph::io::RdfSerializer;
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use super::entity;
use crate::state::AppState;
use crate::store::{DOC_INDEX_FILE, sparql_query, sparql_query_union};

/// Named graphs whose union is "the ontology" serialized at the base URL —
/// the extracted schema and the controlled vocabulary (the `mlips#` terms the
/// document documents), but NOT the per-paper instance KG. These graph names
/// match the ingest contract; hardcoded to the MLIPs resource for now (the
/// driving published dataset), consistent with the entity-base scoping choice.
const ONTOLOGY_GRAPHS: [&str; 2] = [
    "https://w3id.org/mlips/graph/schema",
    "https://w3id.org/mlips/graph/vocab",
];

/// Serve the curated ontology document for `dataset_name`. `url_prefix` is the
/// dataset base, threaded through for the Epic-B serve-time augmentation that
/// will inject per-concept controls; the document is currently served verbatim.
pub fn serve_doc(state: &AppState, dataset_name: &str, url_prefix: &str) -> Response {
    let Some(bytes) = state.store_manager.read_doc_file(dataset_name, DOC_INDEX_FILE) else {
        return (StatusCode::NOT_FOUND, "No document for this dataset").into_response();
    };
    // External terms (used-not-defined) are derived live from the dataset, so
    // the doc's "External terms" section stays current as the KG grows.
    let external = state
        .store_manager
        .get_dataset(dataset_name)
        .map(|store| external_terms(&store, url_prefix))
        .unwrap_or_default();
    let html = augment_doc(
        String::from_utf8_lossy(&bytes).into_owned(),
        url_prefix,
        &external,
    );
    // Served as application/xhtml+xml: the curated document is authored as XHTML
    // (XML declaration, xmlns, self-closed tags, and CDATA in the owl-xml axiom
    // blocks). The HTML5 parser mangles CDATA, so the document must be parsed as
    // XML — everything augment_doc injects is well-formed XML to satisfy this.
    (
        [(header::CONTENT_TYPE, "application/xhtml+xml; charset=utf-8")],
        html,
    )
        .into_response()
}

/// Serve-time augmentation of the curated ontology document. All injected
/// markup is well-formed XML (the document is served as application/xhtml+xml).
/// Injects:
///   - in `<head>`: the canonical doc theme + the explore-enhancer stylesheet;
///   - at the top of `<body>`: concon chrome (top bar + breadcrumb) and a
///     generated table of contents (the source lacks a TOC);
///   - before `</body>`: the explore-enhancer `<script>` (B2/B3 controls + CQ
///     section; it builds its DOM via createElement, i.e. well-formed nodes).
///
/// It also wraps each per-term OWL/XML axiom block in a collapsed native
/// `<details>` (`collapse_owl_xml`); the curated document body is otherwise
/// untouched (no regeneration).
fn augment_doc(doc: String, url_prefix: &str, external: &[ExternalTerm]) -> String {
    // Stylesheets plus `rel="alternate"` pointers so a tool that lands on the
    // document (no RDF `Accept` header) can discover the machine-readable RDF.
    // The alternates share the document's own (negotiated) base URL — the
    // `Accept` header selects the concrete serialization (see the base-URL
    // content negotiation in `content.rs` → `dump_ontology_rdf`).
    let base = xml_escape(url_prefix);
    let head = format!(
        concat!(
            "<link rel=\"stylesheet\" href=\"/static/ontology-doc.css\"/>",
            "<link rel=\"stylesheet\" href=\"/static/concon-explore.css\"/>",
            "<link rel=\"alternate\" type=\"text/turtle\" href=\"{base}\"/>",
            "<link rel=\"alternate\" type=\"application/rdf+xml\" href=\"{base}\"/>",
            "<link rel=\"alternate\" type=\"application/n-triples\" href=\"{base}\"/>",
            "<link rel=\"alternate\" type=\"application/ld+json\" href=\"{base}\"/>"
        ),
        base = base
    );
    let body_end = format!(
        concat!(
            "<script src=\"/static/concon-explore.js\" defer=\"defer\"",
            " data-base=\"{p}\" data-sparql=\"{p}/_sparql\" data-query=\"{p}/_query\"></script>"
        ),
        p = url_prefix
    );
    let doc = inject_view_links(doc, url_prefix);
    let doc = collapse_owl_xml(doc);
    let doc = insert_before(doc, "</head>", &head);
    // Chrome stays at the top of <body>; the generated table of contents moves
    // below the title block + visualization figure (before the first module).
    let doc = insert_after_body_open(doc, &chrome_fragment(url_prefix));
    let toc = build_toc(&doc, external);
    let doc = insert_before_first_module(doc, &toc);
    // "External terms" appendix (used-not-defined terms → their `_view`).
    let doc = insert_before(doc, "</body>", &external_terms_section(external));
    insert_before(doc, "</body>", &body_end)
}

/// The `mlips#` term namespace: a term section's `id` is the term's local name,
/// so its IRI is `MLIPS_TERM_NS + id`. Hardcoded to the MLIPs resource, like
/// `ONTOLOGY_GRAPHS` and the entity base.
const MLIPS_TERM_NS: &str = "https://w3id.org/mlips#";

/// Epic G4: next to each term name in the served document, add a "▷ view" link
/// to that term's database (resource) view — *in addition to* the existing
/// in-document `#anchor`, never replacing the canonical dereference. Keyed off
/// the term section's `id` (its local name), which maps to the term IRI
/// `MLIPS_TERM_NS + id`; the link is the term's native `_view?iri=…` URL,
/// inserted just after each section's `</h4>` so it sits beside the term name.
/// Well-formed XML (the doc is served xhtml+xml): a single self-contained `<a>`
/// with an XML-escaped href.
fn inject_view_links(doc: String, url_prefix: &str) -> String {
    let mut inserts: Vec<(usize, String)> = Vec::new();
    let mut from = 0;
    while let Some(rel) = doc[from..].find("<section") {
        let sec_start = from + rel;
        let Some(gt_rel) = doc[sec_start..].find('>') else { break };
        let tag_end = sec_start + gt_rel; // index of the '>' of the opening tag
        let tag = &doc[sec_start..tag_end];
        from = tag_end + 1;
        if !attr_value(tag, "class").unwrap_or("").contains("term") {
            continue;
        }
        let Some(id) = attr_value(tag, "id").filter(|id| is_safe_fragment(id)) else {
            continue;
        };
        // Insert right after this section's first </h4> (the term name).
        let Some(h4_rel) = doc[tag_end..].find("</h4>") else {
            continue;
        };
        let pos = tag_end + h4_rel + "</h4>".len();
        let iri = format!("{MLIPS_TERM_NS}{id}");
        let href = entity::native_href(&iri, url_prefix);
        inserts.push((
            pos,
            format!(
                " <a class=\"ccx-view-link\" href=\"{}\" title=\"Open this term's database view\">▷ view</a>",
                xml_escape(&href)
            ),
        ));
    }
    if inserts.is_empty() {
        return doc;
    }
    // Splice right-to-left so earlier byte offsets stay valid.
    let mut out = doc;
    for (pos, frag) in inserts.into_iter().rev() {
        out.insert_str(pos, &frag);
    }
    out
}

/// Epic O1: hide each verbatim OWL/XML axiom block (`<pre class="owl-xml">…`
/// `</pre>`) behind a native `<details>` disclosure, collapsed by default —
/// the axiom serialization is secondary content but visually dominates each
/// term section when inline. Native `<details>`/`<summary>` only (no JS), and
/// the wrapper is well-formed XML (the doc is served application/xhtml+xml);
/// the `<pre>` and its CDATA content are moved verbatim, never rewritten.
fn collapse_owl_xml(doc: String) -> String {
    const OPEN: &str = "<details class=\"ccx-owl-xml\"><summary>OWL/XML</summary>";
    const CLOSE: &str = "</details>";
    let mut inserts: Vec<(usize, &str)> = Vec::new();
    let mut from = 0;
    while let Some(rel) = doc[from..].find("<pre") {
        let pre_start = from + rel;
        let Some(gt_rel) = doc[pre_start..].find('>') else { break };
        let tag = &doc[pre_start..pre_start + gt_rel];
        from = pre_start + gt_rel + 1;
        if !attr_value(tag, "class").unwrap_or("").contains("owl-xml") {
            continue;
        }
        let Some(close_rel) = doc[from..].find("</pre>") else { break };
        let close_end = from + close_rel + "</pre>".len();
        inserts.push((pre_start, OPEN));
        inserts.push((close_end, CLOSE));
        from = close_end;
    }
    // Splice right-to-left so earlier byte offsets stay valid.
    let mut out = doc;
    for (pos, frag) in inserts.into_iter().rev() {
        out.insert_str(pos, frag);
    }
    out
}

/// Insert `frag` immediately before the first `marker`; append if absent.
fn insert_before(doc: String, marker: &str, frag: &str) -> String {
    match doc.find(marker) {
        Some(idx) => {
            let mut out = String::with_capacity(doc.len() + frag.len());
            out.push_str(&doc[..idx]);
            out.push_str(frag);
            out.push_str(&doc[idx..]);
            out
        }
        None => doc + frag,
    }
}

/// Insert `frag` just after the opening `<body …>` tag; prepend if absent.
fn insert_after_body_open(doc: String, frag: &str) -> String {
    if let Some(start) = doc.find("<body")
        && let Some(rel) = doc[start..].find('>')
    {
        let idx = start + rel + 1;
        let mut out = String::with_capacity(doc.len() + frag.len());
        out.push_str(&doc[..idx]);
        out.push_str(frag);
        out.push_str(&doc[idx..]);
        out
    } else {
        format!("{frag}{doc}")
    }
}

/// concon chrome for the top of the document body: a top bar linking home and a
/// breadcrumb (Home / <team> / <dataset>). Well-formed XHTML, styled by
/// `ontology-doc.css`.
fn chrome_fragment(url_prefix: &str) -> String {
    let (team_href, team_label, dataset_label) = breadcrumb_parts(url_prefix);
    format!(
        concat!(
            "<div class=\"ccx-chrome\">",
            "<div class=\"ccx-topbar\">",
            "<nav class=\"ccx-nav\">",
            "<a class=\"ccx-brand\" href=\"/\">Concon</a>",
            "<a href=\"/_teams\">Teams</a><a href=\"/_users\">Users</a>",
            "</nav>",
            "<nav class=\"ccx-nav\"><a href=\"/_login\">Login</a></nav>",
            "</div>",
            "<nav class=\"ccx-breadcrumb\" aria-label=\"Breadcrumb\">",
            "<a href=\"/\">Home</a> / <a href=\"{th}\">{tl}</a> / <span>{dl}</span>",
            "</nav></div>"
        ),
        th = xml_escape(&team_href),
        tl = xml_escape(&team_label),
        dl = xml_escape(&dataset_label),
    )
}

/// Parse `url_prefix` (e.g. `/mlips/_ds/mlips`) into (team href, team label,
/// dataset label) for the breadcrumb.
fn breadcrumb_parts(url_prefix: &str) -> (String, String, String) {
    let (team_path, dataset) = match url_prefix.split_once("/_ds/") {
        Some((t, d)) => (t.trim_matches('/'), d.trim_matches('/')),
        None => ("", url_prefix.trim_matches('/')),
    };
    if team_path.is_empty() {
        ("/".to_string(), "root".to_string(), dataset.to_string())
    } else {
        (
            format!("/{team_path}/"),
            team_path.to_string(),
            dataset.to_string(),
        )
    }
}

/// Build a table of contents from the document's term sections
/// (`<section id="X" class="term TYPE">`), grouped by term type. The section id
/// is the term's local name and its in-document anchor. Empty if no terms.
fn build_toc(doc: &str, external: &[ExternalTerm]) -> String {
    let (mut classes, mut object_props, mut datatype_props, mut individuals) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut rest = doc;
    while let Some(pos) = rest.find("<section") {
        rest = &rest[pos + "<section".len()..];
        let Some(end) = rest.find('>') else { break };
        let tag = &rest[..end];
        rest = &rest[end..];
        let class = attr_value(tag, "class").unwrap_or("");
        if !class.contains("term") {
            continue;
        }
        let Some(id) = attr_value(tag, "id").filter(|id| is_safe_fragment(id)) else {
            continue;
        };
        if class.contains("object-property") {
            object_props.push(id);
        } else if class.contains("datatype-property") {
            datatype_props.push(id);
        } else if class.contains("individual") {
            individuals.push(id);
        } else if class.contains("class") {
            classes.push(id);
        }
    }
    // (label, css-slug, ids) — the slug colour-codes the group's chips to match
    // the corresponding term-section palette in ontology-doc.css.
    let groups = [
        ("Classes", "class", classes),
        ("Object properties", "objprop", object_props),
        ("Datatype properties", "datprop", datatype_props),
        ("Individuals", "indiv", individuals),
    ];
    if groups.iter().all(|(_, _, v)| v.is_empty()) && external.is_empty() {
        return String::new();
    }
    let mut s = String::from(
        "<nav id=\"toc\" aria-label=\"Table of contents\">\
         <h2 class=\"toc-heading\">Contents</h2>",
    );
    for (label, slug, ids) in &groups {
        if ids.is_empty() {
            continue;
        }
        s.push_str(&format!(
            "<div class=\"toc-group {slug}\">\
             <h3><span class=\"dot\"></span>{label} <span class=\"count\">{n}</span></h3>\
             <ul class=\"toc-chips\">",
            n = ids.len(),
        ));
        for id in ids {
            s.push_str(&format!("<li><a href=\"#{id}\">{id}</a></li>"));
        }
        s.push_str("</ul></div>");
    }
    // External-terms group (Epic G gateway): each chip links to the term's
    // `_view`, so the element list itself reaches every individual of that type.
    if !external.is_empty() {
        s.push_str(&format!(
            "<div class=\"toc-group external\">\
             <h3><span class=\"dot\"></span>External terms <span class=\"count\">{n}</span></h3>\
             <ul class=\"toc-chips\">",
            n = external.len(),
        ));
        for t in external {
            s.push_str(&format!(
                "<li><a href=\"{href}\" title=\"{iri}\">{disp}</a></li>",
                href = xml_escape(&t.href),
                iri = xml_escape(&t.iri),
                disp = xml_escape(&t.display),
            ));
        }
        s.push_str("</ul></div>");
    }
    s.push_str("</nav>");
    s
}

/// An external vocabulary term the ontology uses but does not define, with its
/// concon resource-view href (Epic G).
struct ExternalTerm {
    iri: String,
    display: String,
    href: String,
}

/// External terms (used-not-defined), derived live from the dataset: IRIs that
/// appear as an `rdfs:domain`/`rdfs:range` of a property or as an `rdf:type` in
/// the data, restricted to the modelled external domain vocabularies
/// (`entity::earns_local_view`: schema/prov/qudt/mls/cmso/mdo) and excluding our
/// own `mlips#` terms (which ARE defined here) and the built-ins. Each gets its
/// `_view` href so the doc becomes a gateway to the individuals of that type.
fn external_terms(store: &Store, url_prefix: &str) -> Vec<ExternalTerm> {
    let q = r#"SELECT DISTINCT ?t WHERE {
        { ?p <http://www.w3.org/2000/01/rdf-schema#domain> ?t }
        UNION { ?p <http://www.w3.org/2000/01/rdf-schema#range> ?t }
        UNION { ?s <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?t }
        FILTER(isIRI(?t))
    }"#;
    let mut out = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union(store, q) {
        for sol in sols.flatten() {
            let Some(term) = sol.get("t") else { continue };
            let iri = term.to_string();
            let iri = iri.trim_matches(|c| c == '<' || c == '>').to_string();
            if entity::earns_local_view(&iri) && !iri.starts_with(MLIPS_TERM_NS) {
                out.push(ExternalTerm {
                    display: entity::short_form(&iri),
                    href: entity::native_href(&iri, url_prefix),
                    iri,
                });
            }
        }
    }
    out.sort_by(|a, b| a.display.cmp(&b.display));
    out
}

/// The "External terms" appendix section (Epic G gateway): each term links to
/// its `_view`. Well-formed XML; empty string when there are none.
fn external_terms_section(external: &[ExternalTerm]) -> String {
    if external.is_empty() {
        return String::new();
    }
    let mut s = String::from(
        "<section id=\"external-terms\" class=\"ccx-external\">\
         <h2>External terms <span class=\"ccx-external-note\">— used, not defined here</span></h2>\
         <p>Vocabulary terms this ontology references (in property domains/ranges and as instance types) but does not itself define. Each links to its concon resource view, which lists the individuals of that type in this dataset.</p>\
         <ul class=\"ccx-external-list\">",
    );
    for t in external {
        s.push_str(&format!(
            "<li><a href=\"{href}\" title=\"{iri}\">{disp}</a></li>",
            href = xml_escape(&t.href),
            iri = xml_escape(&t.iri),
            disp = xml_escape(&t.display),
        ));
    }
    s.push_str("</ul></section>");
    s
}

/// Insert `frag` just before the first module section (`<section id="…-module">`),
/// so the table of contents sits below the title block + visualization figure.
/// Falls back to the top of `<body>` if the document has no module sections.
fn insert_before_first_module(doc: String, frag: &str) -> String {
    let mut from = 0;
    while let Some(rel) = doc[from..].find("<section") {
        let start = from + rel;
        let Some(gt) = doc[start..].find('>') else { break };
        let tag = &doc[start..start + gt];
        if attr_value(tag, "id").is_some_and(|id| id.ends_with("-module")) {
            let mut out = String::with_capacity(doc.len() + frag.len());
            out.push_str(&doc[..start]);
            out.push_str(frag);
            out.push_str(&doc[start..]);
            return out;
        }
        from = start + gt + 1;
    }
    insert_after_body_open(doc, frag)
}

/// Value of attribute `name` within an element's attribute string `tag`.
fn attr_value<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Conservative: an id safe as both a URL fragment and XML text.
fn is_safe_fragment(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Minimal XML text/attribute escaping.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Serve a companion asset of the document (e.g. its stylesheet) from the
/// dataset's doc store. The file name is a single path segment; it is
/// sanitised to block traversal before touching the store.
pub fn serve_doc_asset(state: &AppState, dataset_name: &str, filename: &str) -> Response {
    if !is_safe_asset_name(filename) {
        return (StatusCode::BAD_REQUEST, "Invalid asset name").into_response();
    }
    match state.store_manager.read_doc_file(dataset_name, filename) {
        Some(bytes) => (
            [(header::CONTENT_TYPE, asset_content_type(filename))],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Asset not found").into_response(),
    }
}

/// Serialize the ontology (schema + vocabulary graphs) of `dataset_name` in the
/// negotiated RDF `format` (`"ttl"`, `"owl"`, `"nt"`, or `"jsonld"`; see
/// `entity::rdf_format_for`).
pub fn dump_ontology_rdf(state: &AppState, dataset_name: &str, format: &str) -> Response {
    let Some(store) = state.store_manager.get_dataset(dataset_name) else {
        return (
            StatusCode::NOT_FOUND,
            format!("Dataset '{dataset_name}' not found"),
        )
            .into_response();
    };
    let values = ONTOLOGY_GRAPHS
        .iter()
        .map(|g| format!("<{g}>"))
        .collect::<Vec<_>>()
        .join(" ");
    let q = format!(
        "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH ?g {{ ?s ?p ?o }} VALUES ?g {{ {values} }} }}"
    );
    let triples = match sparql_query(&store, &q) {
        Ok(QueryResults::Graph(t)) => t,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "Query error").into_response(),
    };
    let Some(rdf_format) = entity::rdf_format_for(format) else {
        return (StatusCode::NOT_ACCEPTABLE, "Unsupported RDF format").into_response();
    };
    let mut serializer = RdfSerializer::from_format(rdf_format).for_writer(Vec::new());
    for t in triples.flatten() {
        if serializer.serialize_triple(t.as_ref()).is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Serialize error").into_response();
        }
    }
    match serializer.finish() {
        Ok(buf) => (
            [(header::CONTENT_TYPE, entity::content_type_for(format))],
            buf,
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Finish error").into_response(),
    }
}

/// Accept only simple, single-segment asset names — alphanumerics plus
/// `. _ -`, no `..`, no path separators. Defends the doc store against
/// traversal even though the router already passes a single path segment.
pub(crate) fn is_safe_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn asset_content_type(filename: &str) -> &'static str {
    if filename.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if filename.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if filename.ends_with(".svg") {
        "image/svg+xml"
    } else if filename.ends_with(".png") {
        "image/png"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_asset_name() {
        assert!(is_safe_asset_name("mlips.css"));
        assert!(is_safe_asset_name("style-1_v2.css"));
        assert!(!is_safe_asset_name("../secret"));
        assert!(!is_safe_asset_name("a/b"));
        assert!(!is_safe_asset_name(""));
        assert!(!is_safe_asset_name("with space.css"));
    }

    #[test]
    fn test_asset_content_type() {
        assert_eq!(asset_content_type("mlips.css"), "text/css; charset=utf-8");
        assert_eq!(asset_content_type("x.png"), "image/png");
        assert_eq!(asset_content_type("x.bin"), "application/octet-stream");
    }

    #[test]
    fn test_augment_doc_injects_assets_chrome_toc() {
        let out = augment_doc(
            "<html><head></head><body>\
             <section id=\"Foo\" class=\"term class\"><h4>Foo</h4>\
             <pre class=\"owl-xml\"><![CDATA[<owl:Class/>]]></pre></section>\
             </body></html>"
                .to_string(),
            "/mlips/_ds/mlips",
            &[],
        );
        // Stylesheets in <head>.
        assert!(out.find("/static/ontology-doc.css").unwrap() < out.find("</head>").unwrap());
        assert!(out.contains("/static/concon-explore.css"));
        // Explore script before </body>.
        assert!(out.find("/static/concon-explore.js").unwrap() < out.find("</body>").unwrap());
        assert!(out.contains("data-sparql=\"/mlips/_ds/mlips/_sparql\""));
        // Chrome + breadcrumb after <body>, generated TOC links the term section.
        assert!(out.contains("ccx-breadcrumb") && out.contains(">Home</a>"));
        assert!(out.contains("<nav id=\"toc\"") && out.contains("href=\"#Foo\""));
        // RDF alternates advertised in <head> (discovery for tools/agents),
        // each pointing at the negotiated base URL, all before </head>.
        let head_end = out.find("</head>").unwrap();
        for media in [
            "text/turtle",
            "application/rdf+xml",
            "application/n-triples",
            "application/ld+json",
        ] {
            let link =
                format!("<link rel=\"alternate\" type=\"{media}\" href=\"/mlips/_ds/mlips\"/>");
            // The asserted form is self-closed (`/>`), so this also pins that
            // the augmented <head> stays well-formed XML (served xhtml+xml).
            assert!(out.contains(&link), "missing alternate link for {media}");
            assert!(out.find(&link).unwrap() < head_end, "{media} link not in <head>");
        }
        // Original content preserved; the OWL/XML axiom block is collapsed
        // behind a closed <details> (Epic O1).
        assert!(out.contains("<h4>Foo</h4>"));
        assert!(out.contains(
            "<details class=\"ccx-owl-xml\"><summary>OWL/XML</summary>\
             <pre class=\"owl-xml\"><![CDATA[<owl:Class/>]]></pre></details>"
        ));
    }

    #[test]
    fn inject_view_links_adds_per_term_view_link() {
        let doc = "<html><body>\
             <section id=\"Hyperparameter\" class=\"term class\" about=\"mlips:Hyperparameter\">\
               <h4><span property=\"rdfs:label\">Hyperparameter</span></h4><p>d</p>\
             </section>\
             <section id=\"mod\" class=\"module\"><h4>x</h4></section>\
             </body></html>"
            .to_string();
        let out = inject_view_links(doc, "/mlips/_ds/mlips");
        // The term section gets a view link to its native _view URL (keyed off
        // id → mlips# IRI), placed after the term name's </h4>.
        assert!(out.contains("class=\"ccx-view-link\""));
        assert!(out.contains(
            "/mlips/_ds/mlips/_view?iri=https%3A%2F%2Fw3id.org%2Fmlips%23Hyperparameter"
        ));
        assert!(out.find("ccx-view-link").unwrap() > out.find("</h4>").unwrap());
        // The in-document anchor is untouched (id preserved, canonical deref
        // unchanged) and the non-term section gets no link.
        assert!(out.contains("id=\"Hyperparameter\""));
        assert_eq!(out.matches("ccx-view-link").count(), 1);
    }

    #[test]
    fn collapse_owl_xml_wraps_axiom_blocks_in_closed_details() {
        let doc = "<body>\
             <section id=\"A\" class=\"term class\"><h4>A</h4>\
               <pre class=\"owl-xml\"><![CDATA[<owl:Class rdf:about=\"#A\"/>]]></pre>\
             </section>\
             <section id=\"B\" class=\"term class\"><h4>B</h4>\
               <pre class=\"owl-xml\"><![CDATA[<owl:Class rdf:about=\"#B\"/>]]></pre>\
             </section>\
             <pre class=\"ccx-cq-sparql\">SELECT * WHERE { ?s ?p ?o }</pre>\
             </body>"
            .to_string();
        let out = collapse_owl_xml(doc);
        // Every owl-xml block is wrapped — and only those (the SPARQL pre is
        // untouched), each in its own balanced, closed-by-default disclosure.
        assert_eq!(out.matches("<details class=\"ccx-owl-xml\">").count(), 2);
        assert_eq!(out.matches("<summary>OWL/XML</summary>").count(), 2);
        assert_eq!(out.matches("</details>").count(), 2);
        assert!(!out.contains("<details open"), "collapsed by default");
        assert!(out.contains(
            "<details class=\"ccx-owl-xml\"><summary>OWL/XML</summary>\
             <pre class=\"owl-xml\"><![CDATA[<owl:Class rdf:about=\"#A\"/>]]></pre></details>"
        ), "pre + CDATA moved verbatim inside the disclosure");
        assert!(out.contains("<pre class=\"ccx-cq-sparql\">SELECT * WHERE { ?s ?p ?o }</pre>"));
        // No owl-xml blocks → identity.
        let plain = "<body><pre class=\"other\">x</pre></body>".to_string();
        assert_eq!(collapse_owl_xml(plain.clone()), plain);
    }

    #[test]
    fn test_build_toc_groups_by_type_and_skips_non_terms() {
        let doc = "<section id=\"C\" class=\"term class\"></section>\
                   <section id=\"op\" class=\"term object-property\"></section>\
                   <section id=\"mod\" class=\"module\"></section>";
        let toc = build_toc(doc, &[]);
        assert!(toc.contains("href=\"#C\"") && toc.contains("Classes"));
        assert!(toc.contains("href=\"#op\"") && toc.contains("Object properties"));
        assert!(!toc.contains("#mod"), "non-term sections excluded");
        // No terms and no external → empty.
        assert_eq!(build_toc("<section id=\"x\" class=\"module\"></section>", &[]), "");
    }

    #[test]
    fn toc_repositions_below_figure_and_lists_external_terms() {
        let external = vec![ExternalTerm {
            iri: "https://schema.org/ScholarlyArticle".into(),
            display: "schema:ScholarlyArticle".into(),
            href: "/mlips/_ds/mlips/_view?iri=https%3A%2F%2Fschema.org%2FScholarlyArticle".into(),
        }];
        let doc = "<html><head></head><body>\
             <section id=\"ontology-metadata\"><h1>T</h1></section>\
             <section id=\"visualization\"><h2>Viz</h2></section>\
             <section id=\"algorithm-module\"><h2>Algorithm</h2>\
               <section id=\"Foo\" class=\"term class\"><h4>Foo</h4></section>\
             </section>\
             </body></html>"
            .to_string();
        let out = augment_doc(doc, "/mlips/_ds/mlips", &external);

        // TOC sits AFTER the visualization figure and BEFORE the first module.
        let toc = out.find("<nav id=\"toc\"").unwrap();
        assert!(out.find("id=\"visualization\"").unwrap() < toc, "TOC after figure");
        assert!(toc < out.find("id=\"algorithm-module\"").unwrap(), "TOC before first module");

        // External-terms TOC group + appendix section, each linking to the _view.
        assert!(out.contains("External terms"));
        assert!(out.contains("id=\"external-terms\""));
        assert_eq!(
            out.matches("/_view?iri=https%3A%2F%2Fschema.org%2FScholarlyArticle").count(),
            2,
            "external term linked from both the TOC chip and the appendix"
        );
        // The appendix comes after the module content, before </body>.
        assert!(out.find("id=\"algorithm-module\"").unwrap() < out.find("id=\"external-terms\"").unwrap());
    }

    #[test]
    fn test_breadcrumb_parts() {
        let (h, t, d) = breadcrumb_parts("/mlips/_ds/mlips");
        assert_eq!((h.as_str(), t.as_str(), d.as_str()), ("/mlips/", "mlips", "mlips"));
        let (h, t, _) = breadcrumb_parts("/_ds/foo");
        assert_eq!((h.as_str(), t.as_str()), ("/", "root"));
    }

    #[test]
    fn test_attr_value() {
        let tag = "id=\"X\" class=\"term class\"";
        assert_eq!(attr_value(tag, "id"), Some("X"));
        assert_eq!(attr_value(tag, "class"), Some("term class"));
        assert_eq!(attr_value(tag, "missing"), None);
    }

    #[tokio::test]
    async fn test_base_view_negotiation() {
        use crate::routes::create_router;
        use crate::store::sparql_update;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("root/onto-test").unwrap();
        // Public so the anonymous-read gate admits these requests.
        state
            .store_manager
            .insert_dataset_metadata("root/onto-test")
            .unwrap();
        state
            .store_manager
            .write_doc_file(
                "root/onto-test",
                DOC_INDEX_FILE,
                b"<html>THE CURATED DOC</html>".to_vec(),
            )
            .unwrap();
        state
            .store_manager
            .write_doc_file("root/onto-test", "mlips.css", b"body { color: teal; }".to_vec())
            .unwrap();
        let ds = state.store_manager.get_dataset("root/onto-test").unwrap();
        sparql_update(
            &ds,
            "INSERT DATA { GRAPH <https://w3id.org/mlips/graph/schema> \
             { <urn:s> <urn:p> <urn:o> } }",
        )
        .unwrap();

        let server = TestServer::new(create_router(state));

        // HTML → the curated document, served publicly (no login).
        let resp = server.get("/_ds/onto-test/").add_header("accept", "text/html").await;
        resp.assert_status_ok();
        // Served as application/xhtml+xml so the browser parses the document
        // (incl. the owl-xml CDATA axiom blocks) as XML rather than HTML.
        assert!(
            resp.header(header::CONTENT_TYPE)
                .to_str()
                .unwrap()
                .starts_with("application/xhtml+xml"),
            "the document must be served as application/xhtml+xml"
        );
        let body = resp.text();
        assert!(body.contains("THE CURATED DOC"));
        // Augmented at serve-time: theme stylesheet + concon chrome.
        assert!(body.contains("/static/ontology-doc.css"));
        assert!(body.contains("ccx-breadcrumb"));

        // Turtle → the ontology graph serialization.
        let resp = server
            .get("/_ds/onto-test/")
            .add_header("accept", "text/turtle")
            .await;
        resp.assert_status_ok();
        assert!(resp.text().contains("urn:s"));

        // Companion asset resolves under the base.
        let resp = server.get("/_ds/onto-test/mlips.css").await;
        resp.assert_status_ok();
        assert!(resp.text().contains("teal"));
        // (Asset-name traversal rejection is covered by `test_is_safe_asset_name`;
        // it can't be exercised over HTTP because the client normalises `..`.)
    }

    #[tokio::test]
    async fn test_base_view_no_doc_redirects_to_login() {
        use crate::routes::create_router;
        use axum_test::TestServer;

        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("root/no-doc").unwrap();
        // Public, so the gate admits the request; the editor fallback still
        // redirects an anonymous visitor to login.
        state
            .store_manager
            .insert_dataset_metadata("root/no-doc")
            .unwrap();
        let server = TestServer::new(create_router(state));

        // No document and not logged in → editor fallback redirects to login.
        let resp = server
            .get("/_ds/no-doc/")
            .add_header("accept", "text/html")
            .await;
        resp.assert_status(StatusCode::SEE_OTHER);
    }
}
