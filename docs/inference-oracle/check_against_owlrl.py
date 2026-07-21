#!/usr/bin/env python3
"""Dev-only reference-oracle cross-check for concon's server-side inference.

This is NOT part of concon's build or CI (concon stays Python-free). It is a
manual confidence check that concon's hand-rolled SPARQL rules agree, on the
implemented fragment, with an established OWL-RL/RDFS materializer (`owlrl`,
the RDFLib reference implementation).

## How it works

  fixture.ttl ──► `cargo run --bin infer`  ──► concon-derived N-Triples
              └─► rdflib + owlrl closure    ──► reference entailments

concon materializes a *subset* of OWL-RL, so a full reasoner derives a superset.
We therefore compare only over the **implemented rule patterns** and drop the
tautological/axiomatic triples the subset deliberately omits (reflexive
subClassOf/subPropertyOf, `rdf:type rdfs:Resource`, `rdfs:Class`/`owl:*` meta,
etc.). The check asserts:
  * SOUNDNESS  — every triple concon derived is in the reference closure
                 (concon must never invent an unentailed triple);
  * COMPLETENESS (scoped) — every reference entailment matching an implemented
                 pattern was also derived by concon.

## Usage

    pip install rdflib owlrl
    python3 docs/inference-oracle/check_against_owlrl.py            # all fixtures
    python3 docs/inference-oracle/check_against_owlrl.py fixtures/inverse.ttl

Exit code 0 = agree; 1 = a discrepancy (printed as +concon-only / -reference-only).
"""

import subprocess
import sys
from pathlib import Path

try:
    import rdflib
    from rdflib import RDF, RDFS, OWL, XSD
    import owlrl
except ImportError:
    sys.exit("Install the oracle deps first:  pip install rdflib owlrl")

# Vocabulary namespaces. Modern owlrl (7.x) materializes a large axiomatic
# *vocabulary closure* (xsd datatypes ⊑ rdfs:Literal, owl:Class ⊑ rdfs:Class,
# owl:AnnotationProperty typings, …). Those triples relate only vocabulary terms
# to each other; concon does not (and need not) produce them, so a triple whose
# subject AND object are both vocabulary terms is dropped from the expectation.
_META_NS = (str(RDF), str(RDFS), str(OWL), str(XSD))


def _in_meta_ns(term) -> bool:
    return isinstance(term, rdflib.URIRef) and str(term).startswith(_META_NS)

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
FIXTURES = HERE / "fixtures"

# Schema-level statements a full reasoner also entails but that concon's scoped
# rule set intentionally does NOT materialize — excluded from the (scoped)
# completeness expectation. Soundness still requires concon never *invents* a
# triple outside the closure. Two groups:
#   - inverseOf symmetry, class/property equivalence: concon has no rule for them.
#   - domain/range propagation along the class/property hierarchy (RDFS entails
#     `p domain E` from `p domain D` + `D ⊑ E`): concon consumes domain/range to
#     derive instance `rdf:type` (the query-relevant consequence — `s a E` IS
#     produced), but never emits derived domain/range *axioms*. So a derived
#     rdfs:domain / rdfs:range triple is expected of owlrl, not of concon.
SCHEMA_META_PREDICATES = {
    OWL.inverseOf,
    OWL.equivalentClass,
    OWL.equivalentProperty,
    RDFS.domain,
    RDFS.range,
}


def run_concon(fixture: Path) -> set:
    """Run the `infer` helper: feed the fixture on stdin, parse the computed
    N-Triples it emits into a set of (s, p, o) triples."""
    out = subprocess.run(
        ["cargo", "run", "--quiet", "--bin", "infer"],
        cwd=REPO,
        stdin=fixture.open("rb"),
        capture_output=True,
        check=True,
    ).stdout.decode()
    g = rdflib.Graph()
    g.parse(data=out, format="nt")
    return set(g)


def reference_closure(fixture: Path) -> tuple[set, set]:
    """(base triples, all triples after owlrl RDFS+OWL-RL closure)."""
    base = rdflib.Graph()
    base.parse(fixture, format="turtle")
    base_triples = set(base)
    closed = rdflib.Graph()
    for t in base:
        closed.add(t)
    owlrl.DeductiveClosure(owlrl.RDFS_OWLRL_Semantics).expand(closed)
    return base_triples, set(closed)


_META_CLASSES = (RDFS.Resource, RDFS.Class, RDFS.Datatype, OWL.Class,
                 RDF.Property, OWL.ObjectProperty, OWL.DatatypeProperty,
                 OWL.Thing, OWL.NamedIndividual)


# Tautological / axiomatic triples the subset intentionally omits.
def is_tautology(t) -> bool:
    s, p, o = t
    if p in (RDFS.subClassOf, RDFS.subPropertyOf):
        # reflexivity, and "everything ⊑ Resource/Thing" axioms
        if s == o or o in (RDFS.Resource, OWL.Thing):
            return True
    if p == RDF.type and o in _META_CLASSES:
        return True
    if p == OWL.sameAs and s == o:
        return True
    return False


def is_implemented_triple(t, base: set) -> bool:
    """Whether a reference-derived triple is one concon is expected to derive:
    new (not in the base), not a tautology, and not a schema-meta statement
    concon deliberately skips. What remains — data triples (copied by
    subPropertyOf / inverseOf / symmetric / transitive rules) and
    type/subclass/subproperty structure — is concon's scoped responsibility."""
    s, p, o = t
    if t in base or is_tautology(t) or p in SCHEMA_META_PREDICATES:
        return False
    # Axiomatic vocabulary closure: both endpoints are vocabulary terms.
    if _in_meta_ns(s) and _in_meta_ns(o):
        return False
    return True


def check(fixture: Path) -> bool:
    concon = run_concon(fixture)
    base, closed = reference_closure(fixture)
    expected = {t for t in closed if is_implemented_triple(t, base)}
    concon_new = {t for t in concon if t not in base}

    unsound = concon_new - closed          # concon derived something unentailed
    missing = expected - concon_new        # reference entailment concon missed

    ok = not unsound and not missing
    status = "OK  " if ok else "FAIL"
    print(f"[{status}] {fixture.name}: "
          f"concon={len(concon_new)} expected≈{len(expected)}")
    for t in sorted(unsound, key=str):
        print(f"    + concon-only (UNSOUND): {t}")
    for t in sorted(missing, key=str):
        print(f"    - reference-only (missing): {t}")
    return ok


def main():
    args = sys.argv[1:]
    fixtures = [Path(a) for a in args] if args else sorted(FIXTURES.glob("*.ttl"))
    if not fixtures:
        sys.exit(f"No fixtures found in {FIXTURES}")
    # Evaluate every fixture (do not short-circuit) so all discrepancies show.
    results = [check(f) for f in fixtures]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
