# Inference reference-oracle cross-check (dev-only)

A manual confidence check that concon's server-side inference (`src/inference.rs`)
agrees, on the fragment it implements, with an established OWL-RL/RDFS
materializer (`owlrl`, the RDFLib reference). **Not part of concon's build or
CI** — concon stays Python-free; this is a developer aid run by hand.

## What it checks

concon materializes a *subset* of OWL-RL, so a full reasoner derives a superset.
The check therefore asserts:

- **Soundness (hard):** every triple concon derives is in the reference closure —
  concon must never invent an unentailed triple.
- **Completeness (scoped):** every reference entailment that matches an
  implemented pattern (data triples from subPropertyOf/inverseOf/symmetric/
  transitive, plus type/subclass/subproperty structure) was also derived by
  concon. Tautological axioms and schema-meta statements the subset omits
  (reflexive `subClassOf`, `rdf:type rdfs:Resource`, `owl:inverseOf` symmetry, …)
  are filtered out.

## Run it

```sh
pip install rdflib owlrl            # one-time; not a concon dependency
python3 docs/inference-oracle/check_against_owlrl.py            # all fixtures
python3 docs/inference-oracle/check_against_owlrl.py docs/inference-oracle/fixtures/inverse.ttl
```

It shells out to the dev-only `infer` helper binary (`src/bin/infer.rs`) which
reads Turtle on stdin, runs `inference::recompute`, and prints the derived
`computed` graph as N-Triples. Exit 0 = agree; 1 = a discrepancy (printed as
`+ concon-only (UNSOUND)` / `- reference-only (missing)`).

## Fixtures

`fixtures/*.ttl` — one per rule (subclass, subproperty, domain/range, inverse,
symmetric, transitive). Add more to widen coverage; keep them small so the
reference closure is easy to reason about.
