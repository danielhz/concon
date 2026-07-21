//! Native per-dataset MCP endpoint (`…/_ds/{ds}/_mcp`) — Epic N.
//!
//! A thin, hand-rolled JSON-RPC 2.0 handler over the MCP *streamable-HTTP*
//! transport: an MCP client POSTs a JSON-RPC request and the server answers
//! with a single JSON response (notifications get `202 Accepted`, no body).
//! There is deliberately **no second SPARQL surface and no write tool** —
//! `run-sparql` routes through the *same* capped, union-graph query path as the
//! public `_sparql` endpoint (`store::sparql_query_union_timeout`, 30 s / 10 000
//! rows via `sparql::format_results`). Query-only is enforced structurally:
//! `parse_query` rejects UPDATE syntax exactly as `_sparql` does.
//!
//! Visibility is enforced by the caller (`content.rs`): `_mcp` sits in the same
//! public-read gate as `_sparql`, so a public dataset is open and a private one
//! is login/404 to anonymous callers — this module never sees a request it is
//! not allowed to answer.
//!
//! Everything the tools expose is derived **generically** from the dataset's
//! own named graphs via union-graph SPARQL — no per-dataset (e.g. MLIPs)
//! hardcoding. `get-schema` lists whatever classes/properties/CQs the dataset
//! actually declares; an empty dataset yields an empty-but-valid schema.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use oxigraph::io::RdfFormat;
use oxigraph::model::Term;
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;
use serde::Deserialize;
use serde_json::{Value, json};

use super::sparql;
use crate::state::AppState;
use crate::store::{QUERY_TIMEOUT, sparql_query_union_timeout};

/// MCP protocol revision advertised when the client does not request one. The
/// `initialize` handshake echoes the client's requested version when present
/// (maximising interop), falling back to this.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// A parsed JSON-RPC 2.0 request. A request without `id` is a *notification*
/// (no response is sent). `params` defaults to null when absent.
#[derive(Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Handle one MCP JSON-RPC message POSTed to `…/_ds/{ds}/_mcp`. The caller has
/// already enforced visibility (public dataset, or authenticated).
pub fn handle(state: &AppState, dataset_name: &str, body: &str) -> Response {
    let req: JsonRpcRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            // Batched (array) requests also land here — not supported.
            return json_response(rpc_error(Value::Null, -32700, &format!("Parse error: {e}")));
        }
    };

    let is_notification = req.id.is_none();
    let id = req.id.clone().unwrap_or(Value::Null);

    let response = match req.method.as_str() {
        "initialize" => Some(rpc_result(id, initialize_result(&req.params))),
        "ping" => Some(rpc_result(id, json!({}))),
        "tools/list" => Some(rpc_result(id, json!({ "tools": tools_list() }))),
        "tools/call" => Some(handle_tools_call(state, dataset_name, id, &req.params)),
        // Unknown *notifications* (e.g. `notifications/initialized`) are ignored.
        _ if is_notification => None,
        other => Some(rpc_error(id, -32601, &format!("Method not found: {other}"))),
    };

    match response {
        Some(v) => json_response(v),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// `GET …/_mcp`: this endpoint offers no server-initiated (SSE) stream — it is
/// stateless and request/response only — so a stream open is declined. The
/// visibility gate still applies (private datasets 404 to anonymous callers
/// before reaching here), so returning 405 does not leak dataset existence.
pub fn handle_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "The MCP endpoint accepts JSON-RPC over POST; it offers no GET event stream.",
    )
        .into_response()
}

fn initialize_result(params: &Value) -> Value {
    let protocol_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_PROTOCOL_VERSION);
    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "concon", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "A concon knowledge-graph dataset. Call get-schema first to \
            learn the dataset's classes, properties and example queries, then use \
            run-sparql to answer questions. All access is read-only."
    })
}

fn tools_list() -> Value {
    json!([
        {
            "name": "get-schema",
            "description": "Return a compact, LLM-grounding schema view of this dataset: a \
                prefix header, the classes (curie · label · comment), the properties \
                (curie · label · domain→range · comment), and competency-question \
                question→SPARQL example pairs. Everything is derived from the dataset's own \
                graphs. Call this FIRST to learn the vocabulary before writing SPARQL.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "run-sparql",
            "description": "Execute a read-only SPARQL 1.1 query (SELECT/ASK return \
                SPARQL-results JSON; CONSTRUCT/DESCRIBE return Turtle) against this dataset's \
                union graph. Query-only: UPDATE requests are rejected. Bounded at 30 seconds \
                and 10000 result rows (truncation is flagged in the output).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "A SPARQL 1.1 query string." }
                },
                "required": ["query"],
                "additionalProperties": false
            }
        }
    ])
}

fn handle_tools_call(state: &AppState, dataset_name: &str, id: Value, params: &Value) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    let Some(store) = state.store_manager.get_dataset(dataset_name) else {
        return rpc_error(id, -32602, &format!("Dataset '{dataset_name}' not found"));
    };

    match name {
        "get-schema" => tool_text(id, get_schema(&store)),
        "run-sparql" => {
            let Some(query) = arguments.get("query").and_then(|v| v.as_str()) else {
                return tool_error(id, "Missing required 'query' argument");
            };
            match run_sparql(&store, query) {
                Ok(text) => tool_text(id, text),
                Err(msg) => tool_error(id, &msg),
            }
        }
        other => rpc_error(id, -32602, &format!("Unknown tool: {other}")),
    }
}

/// Execute a query through the shared capped/union path and serialize with the
/// same row-cap logic as `_sparql`. Reuses `sparql::format_results` so there is
/// exactly one hardened serialization surface. UPDATE strings fail to parse as
/// a query and surface as a tool error.
fn run_sparql(store: &Store, query: &str) -> Result<String, String> {
    let results =
        sparql_query_union_timeout(store, query, QUERY_TIMEOUT).map_err(|e| e.to_string())?;
    let (headers, body) =
        sparql::format_results(results, RdfFormat::Turtle).map_err(|(_, msg)| msg)?;
    let mut text = body;
    if headers.contains_key("x-concon-results-truncated") {
        text.push_str("\n\n[results truncated at 10000 rows]");
    }
    Ok(text)
}

// ---------------------------------------------------------------------------
// get-schema: generic, per-dataset schema extraction over the union graph.
// ---------------------------------------------------------------------------

fn get_schema(store: &Store) -> String {
    let mut curies = Curies::new();
    let classes = collect_classes(store, &mut curies);
    let properties = collect_properties(store, &mut curies);
    // CQs carry their own verbatim SPARQL (own PREFIX lines), so they are not
    // run through the curie machinery.
    let cqs = collect_cqs(store);

    let mut out = String::new();
    let header = curies.header();
    if !header.is_empty() {
        out.push_str("# Prefixes\n");
        out.push_str(&header);
    }

    out.push_str(&format!("\n# Classes ({})\n", classes.len()));
    if classes.is_empty() {
        out.push_str("(none declared in this dataset)\n");
    }
    for line in &classes {
        out.push_str(line);
        out.push('\n');
    }

    out.push_str(&format!("\n# Properties ({})\n", properties.len()));
    if properties.is_empty() {
        out.push_str("(none declared in this dataset)\n");
    }
    for line in &properties {
        out.push_str(line);
        out.push('\n');
    }

    if !cqs.is_empty() {
        out.push_str(&format!(
            "\n# Competency questions ({}) — example question→SPARQL pairs\n",
            cqs.len()
        ));
        for cq in &cqs {
            out.push_str(cq);
            out.push_str("\n\n");
        }
    }

    out
}

fn collect_classes(store: &Store, curies: &mut Curies) -> Vec<String> {
    const Q: &str = r#"
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
SELECT ?c (SAMPLE(?lab) AS ?label) (SAMPLE(?com) AS ?comment) WHERE {
  { ?c a owl:Class } UNION { ?c a rdfs:Class }
  FILTER(isIRI(?c))
  OPTIONAL { ?c rdfs:label ?lab }
  OPTIONAL { ?c rdfs:comment ?com }
} GROUP BY ?c ORDER BY ?c"#;

    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union_timeout(store, Q, QUERY_TIMEOUT) {
        for sol in sols.flatten() {
            let Some(Term::NamedNode(c)) = sol.get("c") else {
                continue;
            };
            let curie = curies.curie(c.as_str());
            rows.push(term_line(
                &curie,
                literal_value(sol.get("label")),
                literal_value(sol.get("comment")),
                None,
            ));
        }
    }
    rows
}

fn collect_properties(store: &Store, curies: &mut Curies) -> Vec<String> {
    const Q: &str = r#"
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
SELECT ?p (SAMPLE(?lab) AS ?label) (SAMPLE(?com) AS ?comment)
          (SAMPLE(?dom) AS ?domain) (SAMPLE(?rng) AS ?range) WHERE {
  { ?p a owl:ObjectProperty } UNION { ?p a owl:DatatypeProperty }
  UNION { ?p a owl:AnnotationProperty } UNION { ?p a rdf:Property }
  FILTER(isIRI(?p))
  OPTIONAL { ?p rdfs:label ?lab }
  OPTIONAL { ?p rdfs:comment ?com }
  OPTIONAL { ?p rdfs:domain ?dom }
  OPTIONAL { ?p rdfs:range ?rng }
} GROUP BY ?p ORDER BY ?p"#;

    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union_timeout(store, Q, QUERY_TIMEOUT) {
        for sol in sols.flatten() {
            let Some(Term::NamedNode(p)) = sol.get("p") else {
                continue;
            };
            let curie = curies.curie(p.as_str());
            let domain = named_curie(sol.get("domain"), curies);
            let range = named_curie(sol.get("range"), curies);
            let sig = match (domain, range) {
                (None, None) => None,
                (d, r) => Some(format!(
                    "{}→{}",
                    d.unwrap_or_else(|| "?".into()),
                    r.unwrap_or_else(|| "?".into())
                )),
            };
            rows.push(term_line(
                &curie,
                literal_value(sol.get("label")),
                literal_value(sol.get("comment")),
                sig,
            ));
        }
    }
    rows
}

fn collect_cqs(store: &Store) -> Vec<String> {
    // The `cq:` vocabulary is concon's de-facto competency-question contract
    // (the same predicates `static/concon-explore.js` renders). A dataset that
    // declares none simply yields no CQ section.
    const Q: &str = r#"
PREFIX cq: <https://w3id.org/mlips/cq#>
PREFIX dcterms: <http://purl.org/dc/terms/>
SELECT ?cq (SAMPLE(?ident) AS ?id) (SAMPLE(?q) AS ?question) (SAMPLE(?sq) AS ?query) WHERE {
  ?cq a cq:CompetencyQuestion ; cq:questionText ?q ; cq:sparqlQuery ?sq .
  OPTIONAL { ?cq dcterms:identifier ?ident }
} GROUP BY ?cq ORDER BY ?id"#;

    let mut rows = Vec::new();
    if let Ok(QueryResults::Solutions(sols)) = sparql_query_union_timeout(store, Q, QUERY_TIMEOUT) {
        for sol in sols.flatten() {
            let query = literal_value(sol.get("query")).unwrap_or_default();
            if query.trim().is_empty() {
                continue;
            }
            let question = oneline(&literal_value(sol.get("question")).unwrap_or_default());
            let id = literal_value(sol.get("id")).unwrap_or_else(|| "CQ".into());
            rows.push(format!("## {id}: {question}\n{}", query.trim()));
        }
    }
    rows
}

/// Format one class/property line: `- curie "label" (domain→range) — comment`,
/// omitting any absent part.
fn term_line(
    curie: &str,
    label: Option<String>,
    comment: Option<String>,
    signature: Option<String>,
) -> String {
    let mut line = format!("- {curie}");
    if let Some(l) = label {
        line.push_str(&format!(" \"{}\"", oneline(&l)));
    }
    if let Some(sig) = signature {
        line.push_str(&format!(" ({sig})"));
    }
    if let Some(c) = comment {
        line.push_str(&format!(" — {}", oneline(&c)));
    }
    line
}

/// Curie-fy a solution term when it is an IRI; `None` otherwise (e.g. a blank
/// node domain/range, which has no useful curie).
fn named_curie(term: Option<&Term>, curies: &mut Curies) -> Option<String> {
    match term {
        Some(Term::NamedNode(n)) => Some(curies.curie(n.as_str())),
        _ => None,
    }
}

fn literal_value(term: Option<&Term>) -> Option<String> {
    match term {
        Some(Term::Literal(lit)) => Some(lit.value().to_string()),
        _ => None,
    }
}

/// Collapse internal whitespace/newlines so a multi-line label or comment stays
/// on one line in the compact schema view.
fn oneline(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Namespace→prefix bookkeeping for the generated prefix header. Prefixes are
/// coined on first use (well-known names where the namespace is recognised,
/// otherwise `ns1`, `ns2`, …), so the emitted header lists exactly the
/// namespaces the schema view actually references.
struct Curies {
    /// `(prefix, namespace)` in first-use order; every entry is referenced.
    known: Vec<(String, String)>,
    generated: usize,
}

const WELL_KNOWN: &[(&str, &str)] = &[
    ("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
    ("rdfs", "http://www.w3.org/2000/01/rdf-schema#"),
    ("owl", "http://www.w3.org/2002/07/owl#"),
    ("xsd", "http://www.w3.org/2001/XMLSchema#"),
    ("skos", "http://www.w3.org/2004/02/skos/core#"),
    ("dcterms", "http://purl.org/dc/terms/"),
    ("dc", "http://purl.org/dc/elements/1.1/"),
    ("foaf", "http://xmlns.com/foaf/0.1/"),
    ("prov", "http://www.w3.org/ns/prov#"),
    ("schema", "https://schema.org/"),
];

impl Curies {
    fn new() -> Self {
        Self {
            known: Vec::new(),
            generated: 0,
        }
    }

    /// Return a curie for `iri`, coining a prefix on first use. Falls back to
    /// `<full-iri>` when no sensible local part can be split off.
    fn curie(&mut self, iri: &str) -> String {
        // Longest already-known namespace wins.
        if let Some((prefix, ns)) = self
            .known
            .iter()
            .filter(|(_, ns)| iri.starts_with(ns.as_str()))
            .max_by_key(|(_, ns)| ns.len())
            .map(|(p, n)| (p.clone(), n.clone()))
        {
            return format!("{prefix}:{}", &iri[ns.len()..]);
        }
        // Recognised well-known namespace: register and use.
        if let Some((p, ns)) = WELL_KNOWN
            .iter()
            .filter(|(_, ns)| iri.starts_with(ns))
            .max_by_key(|(_, ns)| ns.len())
        {
            self.known.push(((*p).to_string(), (*ns).to_string()));
            return format!("{p}:{}", &iri[ns.len()..]);
        }
        // Derive a namespace by splitting at the last '#' or '/'.
        let split = iri
            .rfind('#')
            .map(|i| i + 1)
            .or_else(|| iri.rfind('/').map(|i| i + 1));
        match split {
            Some(idx) if idx < iri.len() && !iri[idx..].contains('/') => {
                let ns = iri[..idx].to_string();
                let local = &iri[idx..];
                self.generated += 1;
                let prefix = format!("ns{}", self.generated);
                let out = format!("{prefix}:{local}");
                self.known.push((prefix, ns));
                out
            }
            _ => format!("<{iri}>"),
        }
    }

    fn header(&self) -> String {
        let mut h = String::new();
        for (p, ns) in &self.known {
            h.push_str(&format!("PREFIX {p}: <{ns}>\n"));
        }
        h
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 envelope helpers.
// ---------------------------------------------------------------------------

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// A successful `tools/call` result carrying a single text block. MCP tool
/// *execution* errors are reported here with `isError: true` (not as a JSON-RPC
/// error) so the calling agent can read the message.
fn tool_text(id: Value, text: String) -> Value {
    rpc_result(
        id,
        json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
    )
}

fn tool_error(id: Value, message: &str) -> Value {
    rpc_result(
        id,
        json!({ "content": [{ "type": "text", "text": message }], "isError": true }),
    )
}

fn json_response(v: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use serde_json::{Value, json};

    use crate::routes::create_router;
    use crate::state::AppState;
    use crate::store::sparql_update;

    /// A server with a Public dataset `pub` and a private (logged-users-only)
    /// dataset `secret`, mirroring the `_sparql` visibility gate tests. The
    /// returned `AppState` shares the stores (Arc), so tests can seed data.
    fn server_and_state() -> (TestServer, AppState) {
        let state = AppState::new().unwrap();
        state.store_manager.create_dataset("root/pub").unwrap();
        state.store_manager.insert_dataset_metadata("root/pub").unwrap();
        state.store_manager.create_dataset("root/secret").unwrap();
        state
            .store_manager
            .insert_dataset_metadata_with_visibility("root/secret", "LoggedUsersVisibility")
            .unwrap();
        let server = TestServer::new(create_router(state.clone()));
        (server, state)
    }

    /// Load a tiny, deliberately NON-mlips schema (example.org namespace) into a
    /// named graph of `pub` so union-graph extraction — and its genericity — is
    /// exercised. Inserted straight into the shared store (the HTTP ingest path
    /// needs write auth; these tests only cover the read-side MCP tools).
    fn load_example_schema(state: &AppState) {
        let store = state.store_manager.get_dataset("root/pub").unwrap();
        sparql_update(
            &store,
            r#"
            INSERT DATA {
              GRAPH <http://example.org/g> {
                <http://example.org/onto#Widget>
                    a <http://www.w3.org/2002/07/owl#Class> ;
                    <http://www.w3.org/2000/01/rdf-schema#label> "Widget" ;
                    <http://www.w3.org/2000/01/rdf-schema#comment> "A widget." .
                <http://example.org/onto#partOf>
                    a <http://www.w3.org/2002/07/owl#ObjectProperty> ;
                    <http://www.w3.org/2000/01/rdf-schema#label> "part of" ;
                    <http://www.w3.org/2000/01/rdf-schema#domain> <http://example.org/onto#Widget> ;
                    <http://www.w3.org/2000/01/rdf-schema#range> <http://example.org/onto#Gadget> .
                <http://example.org/cq/1>
                    a <https://w3id.org/mlips/cq#CompetencyQuestion> ;
                    <http://purl.org/dc/terms/identifier> "CQ1" ;
                    <https://w3id.org/mlips/cq#questionText> "What widgets exist?" ;
                    <https://w3id.org/mlips/cq#sparqlQuery> "SELECT ?w WHERE { ?w a <http://example.org/onto#Widget> }" .
              }
            }"#,
        )
        .unwrap();
    }

    /// POST a JSON-RPC message to a dataset's `_mcp` endpoint and return the
    /// parsed JSON response.
    async fn rpc(server: &TestServer, dataset: &str, msg: Value) -> Value {
        server
            .post(&format!("/_ds/{dataset}/_mcp"))
            .json(&msg)
            .await
            .json::<Value>()
    }

    #[tokio::test]
    async fn test_initialize_handshake() {
        let (server, _state) = server_and_state();
        let resp = rpc(
            &server,
            "pub",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                   "params":{"protocolVersion":"2025-06-18"}}),
        )
        .await;
        assert_eq!(resp["result"]["serverInfo"]["name"], "concon");
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
        assert!(resp["result"]["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn test_tools_list_is_read_only() {
        let (server, _state) = server_and_state();
        let resp = rpc(
            &server,
            "pub",
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await;
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["get-schema", "run-sparql"]);
        // No write/update tool is exposed anywhere in the surface.
        let blob = resp.to_string().to_lowercase();
        assert!(!blob.contains("\"name\":\"_update\""));
        assert!(!names.iter().any(|n| n.contains("update") || n.contains("insert")));
    }

    #[tokio::test]
    async fn test_notification_gets_202() {
        let (server, _state) = server_and_state();
        // A JSON-RPC notification (no `id`) must not get a response body.
        let r = server
            .post("/_ds/pub/_mcp")
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        r.assert_status(axum::http::StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_run_sparql_query() {
        let (server, _state) = server_and_state();
        let resp = rpc(
            &server,
            "pub",
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                   "params":{"name":"run-sparql","arguments":{"query":"ASK {}"}}}),
        )
        .await;
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("true"), "ASK {{}} should be true, got: {text}");
    }

    #[tokio::test]
    async fn test_run_sparql_rejects_update() {
        let (server, _state) = server_and_state();
        let resp = rpc(
            &server,
            "pub",
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                   "params":{"name":"run-sparql",
                             "arguments":{"query":"INSERT DATA { <urn:s> <urn:p> <urn:o> }"}}}),
        )
        .await;
        // An UPDATE fails to parse as a query → surfaced as a tool error, never
        // executed. (There is no write path at all.)
        assert_eq!(resp["result"]["isError"], true);
    }

    #[tokio::test]
    async fn test_private_dataset_denies_anonymous() {
        let (server, _state) = server_and_state();
        // Anonymous MCP POST to a non-Public dataset → 404 (no existence leak),
        // exactly like `_sparql`.
        let r = server
            .post("/_ds/secret/_mcp")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .await;
        r.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_is_405() {
        let (server, _state) = server_and_state();
        // Public dataset, but MCP is POST-only.
        server
            .get("/_ds/pub/_mcp")
            .await
            .assert_status(axum::http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_get_schema_is_generic() {
        let (server, state) = server_and_state();
        load_example_schema(&state);
        let resp = rpc(
            &server,
            "pub",
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
                   "params":{"name":"get-schema","arguments":{}}}),
        )
        .await;
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();

        // A non-mlips namespace is curie-fied with a generated prefix — proving
        // the extraction is not hardcoded to any dataset's vocabulary.
        assert!(
            text.contains("PREFIX ns1: <http://example.org/onto#>"),
            "expected a generated prefix header, got:\n{text}"
        );
        // Class, property (with domain→range), and CQ all surface.
        assert!(text.contains("ns1:Widget"), "class missing:\n{text}");
        assert!(text.contains("\"part of\""), "property label missing:\n{text}");
        assert!(
            text.contains("ns1:Widget→ns1:Gadget"),
            "domain→range missing:\n{text}"
        );
        assert!(
            text.contains("What widgets exist?"),
            "competency question missing:\n{text}"
        );
    }

    #[tokio::test]
    async fn test_get_schema_on_empty_dataset() {
        let (server, _state) = server_and_state();
        // No schema loaded: get-schema must still succeed with a valid,
        // empty-but-well-formed payload (graceful degradation).
        let resp = rpc(
            &server,
            "pub",
            json!({"jsonrpc":"2.0","id":10,"method":"tools/call",
                   "params":{"name":"get-schema","arguments":{}}}),
        )
        .await;
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("# Classes (0)"), "got:\n{text}");
    }
}
