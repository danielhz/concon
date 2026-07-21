//! Server-side inference (Epic M): materialize axiom-derivable triples into a
//! dataset's `…/graph/computed` named graph.
//!
//! Oxigraph has no reasoner, so "inference" here is a fixed set of SPARQL
//! `INSERT` rules run over a dataset's *source* graphs. The guiding principle
//! (decided 2026-07-21): **concon derives only what is expressible in the
//! axioms** — RDFS/OWL-RL entailments driven by the dataset's own schema
//! declarations. Anything domain-specific (e.g. templated human-readable
//! labels) stays the consumer's responsibility and is not produced here.
//!
//! The rules are **dataset-agnostic**: they key off each dataset's own
//! `rdfs:subClassOf` / `rdfs:domain` / `owl:inverseOf` / … declarations, never
//! off hardcoded vocabulary. The same code serves any concon dataset.
//!
//! ## Contract
//!
//! - The **computed graph** is `<prefix>computed`, where `<prefix>` is the
//!   dataset's own `…/graph/` namespace (derived from the graphs it already
//!   has). It is **concon-derived and read-only**: consumers upload source
//!   graphs only and must not PUT `computed` (rejected in `ingest`).
//! - A **recompute** clears `computed` once, then iterates the rule set to a
//!   **fixpoint**: each pass matches over the **union of the source graphs and
//!   `computed`-so-far**, appending only newly entailed triples, until the
//!   `computed` triple count stops growing. This yields the *full closure* over
//!   the scoped rule set — composed entailments (e.g. `domain` feeding a
//!   `subClassOf` step) are derived, not just single-rule ones. The rules are
//!   monotone and the vocabulary is finite, so the loop terminates; a hard
//!   `MAX_PASSES` cap backstops any surprise. Clearing first (never trusting a
//!   prior `computed`) keeps the result a deterministic function of the sources,
//!   independent of upload order.
//! - The WHERE side of each rule reads the union of the source graphs **plus
//!   `computed`** via `USING <g>` clauses; the INSERT side writes into
//!   `GRAPH <computed>`. Source = every named graph except the concon-internal
//!   `annotations` graph.

use oxigraph::model::{NamedNode, Term};
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;

use crate::store::{sparql_query_union, sparql_update};

/// SPARQL prefix block shared by every rule.
const PREFIXES: &str = r#"
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
"#;

/// Safety backstop on the fixpoint loop. The rules are monotone over a finite
/// vocabulary so the loop terminates well before this; hitting it signals a bug
/// (e.g. a rule that isn't actually guarded by NOT EXISTS) and is logged.
const MAX_PASSES: usize = 64;

/// The `…/graph/` slot name concon reserves for its derived graph.
const COMPUTED_SLOT: &str = "computed";
/// The `…/graph/` slot name concon uses for user annotations (Epic H); it is a
/// concon-internal graph, not consumer source data, so inference ignores it.
const ANNOTATIONS_SLOT: &str = "annotations";

/// Outcome of a recompute, for logging and the `_recompute` endpoint response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecomputeReport {
    /// The computed graph IRI, or `None` when the dataset has no `…/graph/`
    /// layout to derive one from (inference skipped).
    pub computed_graph: Option<String>,
    /// Source graphs the rules read from.
    pub sources: Vec<String>,
    /// Triples in the computed graph after the rebuild.
    pub inserted: usize,
}

/// The graph layout of a dataset: the computed target and its source graphs.
struct Layout {
    computed: NamedNode,
    sources: Vec<NamedNode>,
}

/// Whether `iri` addresses a reserved `…/graph/computed` graph. Used by the
/// ingest layer to reject consumer writes to the concon-derived graph (M3).
/// Dataset-agnostic: matches the slot after the `…/graph/` convention, so it
/// holds for any namespace (mlips or otherwise).
pub fn is_reserved_computed_graph(iri: &str) -> bool {
    graph_slot(iri).is_some_and(|slot| slot == COMPUTED_SLOT)
}

/// Split a graph IRI on the `…/graph/` convention into `(prefix, slot)` where
/// `prefix` ends in `graph/` and `slot` is the final segment (e.g. `schema`).
/// `None` if the IRI does not follow the convention.
fn split_graph_iri(iri: &str) -> Option<(&str, &str)> {
    let idx = iri.rfind("/graph/")?;
    let prefix = &iri[..idx + "/graph/".len()];
    let slot = &iri[idx + "/graph/".len()..];
    // A single trailing segment only (no further slashes / fragments).
    if slot.is_empty() || slot.contains('/') || slot.contains('#') {
        return None;
    }
    Some((prefix, slot))
}

/// The `…/graph/` slot of an IRI (e.g. `computed`), if it follows the convention.
fn graph_slot(iri: &str) -> Option<&str> {
    split_graph_iri(iri).map(|(_, slot)| slot)
}

/// Enumerate the distinct named graphs that currently hold triples.
fn named_graphs(store: &Store) -> Result<Vec<NamedNode>, String> {
    let q = "SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } }";
    let mut out = Vec::new();
    if let QueryResults::Solutions(solutions) =
        sparql_query_union(store, q).map_err(|e| e.to_string())?
    {
        for sol in solutions.flatten() {
            if let Some(Term::NamedNode(g)) = sol.get("g") {
                out.push(g.clone());
            }
        }
    }
    Ok(out)
}

/// Derive the computed target and source graphs from the dataset's existing
/// graphs, using the `…/graph/` convention. The computed graph is
/// `<prefix>computed` for the prefix shared by the most graphs; sources are all
/// convention-following graphs under that prefix except `computed` and
/// `annotations`. Returns `None` when no graph follows the convention (nothing
/// to infer for / into).
fn derive_layout(graphs: &[NamedNode]) -> Option<Layout> {
    use std::collections::BTreeMap;

    // Count graphs per `…/graph/` prefix; pick the most common (ties: the
    // lexicographically smallest prefix, for determinism).
    let mut by_prefix: BTreeMap<&str, usize> = BTreeMap::new();
    for g in graphs {
        if let Some((prefix, _)) = split_graph_iri(g.as_str()) {
            *by_prefix.entry(prefix).or_default() += 1;
        }
    }
    let prefix = by_prefix
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))
        .map(|(p, _)| p.to_string())?;

    let computed = NamedNode::new(format!("{prefix}{COMPUTED_SLOT}")).ok()?;
    let annotations_iri = format!("{prefix}{ANNOTATIONS_SLOT}");

    let sources: Vec<NamedNode> = graphs
        .iter()
        .filter(|g| {
            let s = g.as_str();
            // Only graphs under this prefix, excluding the derived/internal ones.
            split_graph_iri(s).is_some_and(|(p, _)| p == prefix)
                && s != computed.as_str()
                && s != annotations_iri
        })
        .cloned()
        .collect();

    Some(Layout { computed, sources })
}

/// Build the `USING <g> …` clause that makes the rule WHERE read the union of
/// the given graphs (the source graphs plus `computed`, so each fixpoint pass
/// sees the triples earlier passes derived).
fn using_clause(graphs: &[NamedNode]) -> String {
    graphs
        .iter()
        .map(|g| format!("USING <{}>", g.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the `FROM <g> …` clause scoping a SELECT's default graph to exactly
/// `graphs` (source + `computed`) — the query-side counterpart of
/// [`using_clause`], used to keep `transitive_properties` reading the same
/// union the rules do (not the whole store).
fn from_clause(graphs: &[NamedNode]) -> String {
    graphs
        .iter()
        .map(|g| format!("FROM <{}>", g.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The fixed axiom-driven rule set (RDFS + a common OWL-RL subset). Each entry
/// is an `INSERT { GRAPH <computed> { … } } USING … WHERE { … }` update. `c` is
/// the computed graph IRI; `using` is the source-union clause.
///
/// Every rule carries a `FILTER NOT EXISTS { <inferred triple> }` guard so that
/// each pass appends only triples not *already present* in the source-plus-
/// `computed` union — the `+` paths and closure rules would otherwise
/// re-materialize direct edges, and the fixpoint loop would never converge. The
/// guard reads the same `USING` union as the rest of the WHERE (source +
/// `computed`), which is what makes each pass strictly grow `computed` toward
/// its closure and then stop.
///
/// Transitive user-declared properties are handled separately (below) because
/// their predicate is a variable and a property path needs a fixed predicate.
fn fixed_rules(c: &str, using: &str) -> Vec<String> {
    let rule = |body: &str| format!("{PREFIXES}\n{body}");
    vec![
        // subClassOf transitive closure (IRI classes only; skip reflexive).
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?a rdfs:subClassOf ?b }} }} {using} \
             WHERE {{ ?a rdfs:subClassOf+ ?b . FILTER(?a != ?b) FILTER(isIRI(?a) && isIRI(?b)) \
             FILTER NOT EXISTS {{ ?a rdfs:subClassOf ?b }} }}"
        )),
        // subPropertyOf transitive closure.
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?a rdfs:subPropertyOf ?b }} }} {using} \
             WHERE {{ ?a rdfs:subPropertyOf+ ?b . FILTER(?a != ?b) FILTER(isIRI(?a) && isIRI(?b)) \
             FILTER NOT EXISTS {{ ?a rdfs:subPropertyOf ?b }} }}"
        )),
        // Type propagation along the subclass hierarchy.
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?s a ?d }} }} {using} \
             WHERE {{ ?s a ?c2 . ?c2 rdfs:subClassOf+ ?d . FILTER(?c2 != ?d) FILTER(isIRI(?d)) \
             FILTER NOT EXISTS {{ ?s a ?d }} }}"
        )),
        // Data propagation along the subproperty hierarchy.
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?s ?q ?o }} }} {using} \
             WHERE {{ ?s ?p ?o . ?p rdfs:subPropertyOf+ ?q . FILTER(?p != ?q) FILTER(isIRI(?q)) \
             FILTER NOT EXISTS {{ ?s ?q ?o }} }}"
        )),
        // rdfs:domain → rdf:type on the subject.
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?s a ?class }} }} {using} \
             WHERE {{ ?p rdfs:domain ?class . ?s ?p ?o . FILTER(isIRI(?class)) \
             FILTER NOT EXISTS {{ ?s a ?class }} }}"
        )),
        // rdfs:range → rdf:type on the object (non-literal objects only).
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?o a ?class }} }} {using} \
             WHERE {{ ?p rdfs:range ?class . ?s ?p ?o . \
             FILTER(isIRI(?class)) FILTER(isIRI(?o) || isBlank(?o)) \
             FILTER NOT EXISTS {{ ?o a ?class }} }}"
        )),
        // owl:inverseOf, both declaration directions. Guard on the object (the
        // inverse triple's subject): a literal there yields an invalid triple,
        // silently skipped anyway — the filter makes the intent explicit and
        // matches the symmetric rule below.
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?o ?q ?s }} }} {using} \
             WHERE {{ {{ ?p owl:inverseOf ?q }} UNION {{ ?q owl:inverseOf ?p }} \
             ?s ?p ?o . FILTER(isIRI(?q)) FILTER(isIRI(?o) || isBlank(?o)) \
             FILTER NOT EXISTS {{ ?o ?q ?s }} }}"
        )),
        // owl:SymmetricProperty (non-literal objects only, else invalid subject).
        rule(&format!(
            "INSERT {{ GRAPH <{c}> {{ ?o ?p ?s }} }} {using} \
             WHERE {{ ?p a owl:SymmetricProperty . ?s ?p ?o . \
             FILTER(isIRI(?o) || isBlank(?o)) FILTER NOT EXISTS {{ ?o ?p ?s }} }}"
        )),
    ]
}

/// Collect the IRIs declared `owl:TransitiveProperty` over `graphs` (source +
/// `computed`) — scoped with `FROM` so it reads the same union the rules do,
/// not the whole store (which would also pull in `annotations`).
fn transitive_properties(store: &Store, graphs: &[NamedNode]) -> Result<Vec<NamedNode>, String> {
    let from = from_clause(graphs);
    let q = format!(
        "{PREFIXES}\nSELECT DISTINCT ?p {from} \
         WHERE {{ ?p a owl:TransitiveProperty . FILTER(isIRI(?p)) }}"
    );
    let mut out = Vec::new();
    if let QueryResults::Solutions(solutions) =
        crate::store::sparql_query(store, &q).map_err(|e| e.to_string())?
    {
        for sol in solutions.flatten() {
            if let Some(Term::NamedNode(p)) = sol.get("p") {
                out.push(p.clone());
            }
        }
    }
    Ok(out)
}

/// Recompute a dataset's computed graph: clear it, then iterate the rule set to
/// a fixpoint over `source ∪ computed`. A full rebuild — idempotent and
/// order-independent, computing the closure of the scoped rules (composed
/// entailments included). Returns a report (with `computed_graph: None` when the
/// dataset has no `…/graph/` layout, in which case nothing is done).
pub fn recompute(store: &Store) -> Result<RecomputeReport, String> {
    let graphs = named_graphs(store)?;
    let Some(layout) = derive_layout(&graphs) else {
        return Ok(RecomputeReport {
            computed_graph: None,
            sources: Vec::new(),
            inserted: 0,
        });
    };
    let computed = layout.computed.as_str().to_string();

    // Clear the derived graph first so the result is a deterministic function of
    // the sources — the fixpoint below then reads `computed` back, but only ever
    // triples it derived this run, never a stale prior output.
    store
        .clear_graph(layout.computed.as_ref())
        .map_err(|e| format!("Failed to clear computed graph: {e}"))?;

    // With no source graphs there is nothing to derive; leave `computed` empty.
    if layout.sources.is_empty() {
        return Ok(RecomputeReport {
            computed_graph: Some(computed),
            sources: Vec::new(),
            inserted: 0,
        });
    }

    // Each pass reads the source graphs *and* `computed`, so a triple derived by
    // one rule can feed another (e.g. domain → type, then type → superclass).
    let mut union = layout.sources.clone();
    union.push(layout.computed.clone());
    let using = using_clause(&union);
    let rules = fixed_rules(&computed, &using);

    // Iterate to a fixpoint: run every rule, then stop once a full pass adds no
    // new triple. Monotone growth (each rule is NOT-EXISTS-guarded against the
    // same union) over a finite vocabulary guarantees convergence; MAX_PASSES is
    // only a bug backstop.
    let mut inserted = 0usize;
    for pass in 1..=MAX_PASSES {
        for update in &rules {
            sparql_update(store, update).map_err(|e| format!("Inference rule failed: {e}"))?;
        }
        // Transitive user-declared properties: one fixed-predicate property-path
        // rule per declared property (a variable predicate cannot carry a `+`
        // path). Re-read the declarations each pass so a type derived into
        // `computed` can introduce a new transitive property.
        for p in transitive_properties(store, &union)? {
            let update = format!(
                "{PREFIXES}\nINSERT {{ GRAPH <{computed}> {{ ?x <{p}> ?z }} }} {using} \
                 WHERE {{ ?x <{p}>+ ?z . FILTER(?x != ?z) \
                 FILTER NOT EXISTS {{ ?x <{p}> ?z }} }}",
                p = p.as_str(),
            );
            sparql_update(store, &update).map_err(|e| format!("Transitive rule failed: {e}"))?;
        }

        let count = graph_triple_count(store, &computed)?;
        if count == inserted {
            break; // fixpoint reached
        }
        inserted = count;
        if pass == MAX_PASSES {
            tracing::warn!(
                graph = computed.as_str(),
                "inference fixpoint did not converge within {MAX_PASSES} passes"
            );
        }
    }

    Ok(RecomputeReport {
        computed_graph: Some(computed),
        sources: layout.sources.iter().map(|g| g.as_str().to_string()).collect(),
        inserted,
    })
}

/// Count the triples in a named graph.
fn graph_triple_count(store: &Store, graph: &str) -> Result<usize, String> {
    let q = format!("SELECT (COUNT(*) AS ?n) WHERE {{ GRAPH <{graph}> {{ ?s ?p ?o }} }}");
    if let QueryResults::Solutions(solutions) = sparql_query_union(store, &q).map_err(|e| e.to_string())? {
        for sol in solutions.flatten() {
            if let Some(Term::Literal(l)) = sol.get("n") {
                return Ok(l.value().parse().unwrap_or(0));
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "https://ex.org/ds/graph/schema";
    const KG: &str = "https://ex.org/ds/graph/kg";
    const COMPUTED: &str = "https://ex.org/ds/graph/computed";

    fn load(store: &Store, graph: &str, turtle: &str) {
        sparql_update(
            store,
            &format!(
                "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n\
                 PREFIX owl: <http://www.w3.org/2002/07/owl#>\n\
                 PREFIX ex: <https://ex.org/t/>\n\
                 INSERT DATA {{ GRAPH <{graph}> {{ {turtle} }} }}"
            ),
        )
        .unwrap();
    }

    fn ask(store: &Store, pattern: &str) -> bool {
        let q = format!(
            "PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n\
             PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n\
             PREFIX owl: <http://www.w3.org/2002/07/owl#>\n\
             PREFIX ex: <https://ex.org/t/>\n\
             ASK {{ GRAPH <{COMPUTED}> {{ {pattern} }} }}"
        );
        matches!(
            sparql_query_union(store, &q).unwrap(),
            QueryResults::Boolean(true)
        )
    }

    #[test]
    fn test_split_graph_iri() {
        assert_eq!(split_graph_iri(COMPUTED), Some(("https://ex.org/ds/graph/", "computed")));
        assert_eq!(split_graph_iri(SCHEMA), Some(("https://ex.org/ds/graph/", "schema")));
        assert_eq!(split_graph_iri("https://ex.org/ds/schema"), None);
        assert_eq!(split_graph_iri("https://ex.org/ds/graph/a/b"), None);
    }

    #[test]
    fn test_is_reserved_computed_graph() {
        assert!(is_reserved_computed_graph(COMPUTED));
        assert!(is_reserved_computed_graph("https://w3id.org/mlips/graph/computed"));
        assert!(!is_reserved_computed_graph(SCHEMA));
        assert!(!is_reserved_computed_graph("https://ex.org/graph/other"));
    }

    #[test]
    fn test_derive_layout_picks_prefix_and_excludes_internal() {
        let g = |s: &str| NamedNode::new(s).unwrap();
        let graphs = vec![
            g(SCHEMA),
            g(KG),
            g(COMPUTED),
            g("https://ex.org/ds/graph/annotations"),
        ];
        let layout = derive_layout(&graphs).unwrap();
        assert_eq!(layout.computed.as_str(), COMPUTED);
        let mut sources: Vec<_> = layout.sources.iter().map(|g| g.as_str()).collect();
        sources.sort();
        assert_eq!(sources, vec![KG, SCHEMA]);
    }

    #[test]
    fn test_derive_layout_none_without_convention() {
        let g = |s: &str| NamedNode::new(s).unwrap();
        let graphs = vec![g("https://ex.org/ds/schema"), g("urn:x")];
        assert!(derive_layout(&graphs).is_none());
    }

    #[test]
    fn test_subclass_closure_and_type_propagation() {
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:A rdfs:subClassOf ex:B . ex:B rdfs:subClassOf ex:C .");
        load(&store, KG, "ex:x a ex:A .");
        recompute(&store).unwrap();
        // transitive subclass edge A ⊑ C
        assert!(ask(&store, "ex:A rdfs:subClassOf ex:C ."));
        // type propagation: x is A ⊑ B ⊑ C
        assert!(ask(&store, "ex:x a ex:B ."));
        assert!(ask(&store, "ex:x a ex:C ."));
    }

    #[test]
    fn test_domain_and_range() {
        let store = Store::new().unwrap();
        load(
            &store,
            SCHEMA,
            "ex:p rdfs:domain ex:D . ex:p rdfs:range ex:R .",
        );
        load(&store, KG, "ex:s ex:p ex:o .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:s a ex:D ."));
        assert!(ask(&store, "ex:o a ex:R ."));
    }

    #[test]
    fn test_range_skips_literal_objects() {
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:p rdfs:range ex:R .");
        load(&store, KG, "ex:s ex:p \"a literal\" .");
        // Must not crash and must not type a literal.
        recompute(&store).unwrap();
        assert!(!ask(&store, "?x a ex:R ."));
    }

    #[test]
    fn test_inverse_of_both_directions() {
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:hasResult owl:inverseOf ex:isResultOf .");
        load(&store, KG, "ex:study ex:hasResult ex:r .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:r ex:isResultOf ex:study ."));
    }

    #[test]
    fn test_symmetric_property() {
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:near a owl:SymmetricProperty .");
        load(&store, KG, "ex:a ex:near ex:b .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:b ex:near ex:a ."));
    }

    #[test]
    fn test_transitive_property() {
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:part a owl:TransitiveProperty .");
        load(&store, KG, "ex:a ex:part ex:b . ex:b ex:part ex:c .");
        recompute(&store).unwrap();
        // The derived edge is materialized …
        assert!(ask(&store, "ex:a ex:part ex:c ."));
        // … but the direct edges (already in the source) are NOT re-materialized
        // into computed — it holds only newly entailed triples.
        assert!(!ask(&store, "ex:a ex:part ex:b ."));
        assert!(!ask(&store, "ex:b ex:part ex:c ."));
    }

    #[test]
    fn test_recompute_is_full_rebuild() {
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:hasResult owl:inverseOf ex:isResultOf .");
        load(&store, KG, "ex:study ex:hasResult ex:r .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:r ex:isResultOf ex:study ."));

        // Remove the source fact and recompute: the derived triple must vanish
        // (clear-then-rederive, never fed back from computed).
        sparql_update(
            &store,
            &format!("PREFIX ex: <https://ex.org/t/> DELETE WHERE {{ GRAPH <{KG}> {{ ?s ?p ?o }} }}"),
        )
        .unwrap();
        recompute(&store).unwrap();
        assert!(!ask(&store, "ex:r ex:isResultOf ex:study ."));
    }

    /// Composed entailments — the fixpoint's reason for existing. Each needs one
    /// rule's output as another rule's input, so single-pass would miss the
    /// second triple.
    #[test]
    fn test_composed_entailments_fixpoint() {
        // domain ∘ subclass: s a D (domain), then D ⊑ E ⇒ s a E.
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:p rdfs:domain ex:D . ex:D rdfs:subClassOf ex:E .");
        load(&store, KG, "ex:s ex:p ex:o .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:s a ex:D ."));
        assert!(ask(&store, "ex:s a ex:E ."), "composed domain∘subclass");

        // subproperty ∘ domain: s sub o ⇒ s p o (subprop), then p domain D ⇒ s a D.
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:sub rdfs:subPropertyOf ex:p . ex:p rdfs:domain ex:D .");
        load(&store, KG, "ex:s ex:sub ex:o .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:s ex:p ex:o ."));
        assert!(ask(&store, "ex:s a ex:D ."), "composed subproperty∘domain");

        // inverse ∘ domain: x hasR y ⇒ y isR x (inverse), then isR domain D ⇒ y a D.
        let store = Store::new().unwrap();
        load(&store, SCHEMA, "ex:hasR owl:inverseOf ex:isR . ex:isR rdfs:domain ex:D .");
        load(&store, KG, "ex:x ex:hasR ex:y .");
        recompute(&store).unwrap();
        assert!(ask(&store, "ex:y ex:isR ex:x ."));
        assert!(ask(&store, "ex:y a ex:D ."), "composed inverse∘domain");
    }

    /// Golden test tying the generic `owl:inverseOf` rule to the concrete
    /// consumer expectation: the eight (forward, inverse) pairs the retired
    /// MLIPs `inverses.rq` hardcoded must all materialize from schema-declared
    /// `owl:inverseOf` alone — no MLIPs terms in concon's code. Graphs use the
    /// real `https://w3id.org/mlips/graph/{schema,kg}` layout.
    #[test]
    fn test_mlips_inverse_pairs_golden() {
        const PAIRS: [(&str, &str); 8] = [
            ("hasHyperparameter", "isHyperparameterOf"),
            ("hasImplementation", "isImplementationOf"),
            ("hasResult", "isResultOf"),
            ("hasAccuracyMetric", "isMetricOf"),
            ("hasHyperparameterSetting", "isSettingOf"),
            ("produces", "isProducedBy"),
            ("runsOn", "wasRunBy"),
            ("evaluatesModel", "isEvaluatedIn"),
        ];
        let schema_g = "https://w3id.org/mlips/graph/schema";
        let kg_g = "https://w3id.org/mlips/graph/kg";
        let computed_g = "https://w3id.org/mlips/graph/computed";
        let m = |t: &str| format!("<https://w3id.org/mlips#{t}>");

        let store = Store::new().unwrap();
        // Schema: the eight owl:inverseOf declarations.
        let decls = PAIRS
            .iter()
            .map(|(f, i)| {
                format!("{} <http://www.w3.org/2002/07/owl#inverseOf> {} .", m(f), m(i))
            })
            .collect::<Vec<_>>()
            .join("\n");
        sparql_update(
            &store,
            &format!("INSERT DATA {{ GRAPH <{schema_g}> {{ {decls} }} }}"),
        )
        .unwrap();
        // Data: one forward triple per pair, subject/object distinct per pair.
        let data = PAIRS
            .iter()
            .enumerate()
            .map(|(n, (f, _))| format!("{} {} {} .", m(&format!("s{n}")), m(f), m(&format!("o{n}"))))
            .collect::<Vec<_>>()
            .join("\n");
        sparql_update(&store, &format!("INSERT DATA {{ GRAPH <{kg_g}> {{ {data} }} }}")).unwrap();

        let report = recompute(&store).unwrap();
        assert_eq!(report.computed_graph.as_deref(), Some(computed_g));

        // Every inverse triple `o<n> <inverse> s<n>` must be in computed.
        for (n, (_, inv)) in PAIRS.iter().enumerate() {
            let q = format!(
                "ASK {{ GRAPH <{computed_g}> {{ {} {} {} }} }}",
                m(&format!("o{n}")),
                m(inv),
                m(&format!("s{n}")),
            );
            assert!(
                matches!(sparql_query_union(&store, &q).unwrap(), QueryResults::Boolean(true)),
                "inverse pair {inv} not materialized"
            );
        }
    }

    #[test]
    fn test_no_layout_is_noop() {
        let store = Store::new().unwrap();
        sparql_update(&store, "INSERT DATA { GRAPH <urn:g> { <urn:s> <urn:p> <urn:o> } }").unwrap();
        let report = recompute(&store).unwrap();
        assert!(report.computed_graph.is_none());
        assert_eq!(report.inserted, 0);
    }
}
