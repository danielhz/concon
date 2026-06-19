/*
 * concon ontology-doc enhancer (epics B2 + B3).
 *
 * Injected into the served ontology document by the server (see
 * routes/ontology.rs `augment_doc`). Progressively enhances the curated,
 * static document — it is never required for the document to render.
 *
 *  - B2: for every owl:Class section, add an "Explore individuals" expander
 *        (subclass-aware results from the public SPARQL endpoint, JSON) plus an
 *        "open in editor" deep link. No full YASGUI per concept.
 *  - B3: append a competency-question section rendered generically from the
 *        cq: RDF (questionText + verbatim SPARQL, runnable inline + deep link).
 *
 * Endpoint URLs come from the script tag's data-* attributes; requests are
 * same-origin. Vanilla DOM + fetch, no dependencies.
 */
(function () {
  "use strict";

  var script = document.querySelector("script[data-sparql]");
  if (!script) return;
  var SPARQL = script.dataset.sparql; // e.g. /mlips/_ds/mlips/_sparql
  var QUERY = script.dataset.query; //  e.g. /mlips/_ds/mlips/_query
  var BASE = script.dataset.base; //   e.g. /mlips/_ds/mlips

  var MLIPS_NS = "https://w3id.org/mlips#";
  var ENTITY_NS = "https://w3id.org/mlips/entity/";

  var PREFIXES = [
    "PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>",
    "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>",
    "PREFIX owl: <http://www.w3.org/2002/07/owl#>",
    "PREFIX mlips: <https://w3id.org/mlips#>",
    "PREFIX cq: <https://w3id.org/mlips/cq#>",
    "PREFIX dcterms: <http://purl.org/dc/terms/>"
  ].join("\n");

  function runSelect(query) {
    return fetch(SPARQL + "?query=" + encodeURIComponent(query), {
      headers: { Accept: "application/sparql-results+json" }
    }).then(function (r) {
      if (!r.ok) throw new Error("SPARQL " + r.status);
      return r.json();
    });
  }

  function editorLink(query) {
    return QUERY + "?query=" + encodeURIComponent(query);
  }

  // entity IRIs → native dereference URL; mlips# terms → in-document anchor;
  // anything else → the IRI itself.
  function hrefFor(iri) {
    if (iri.indexOf(ENTITY_NS) === 0) return BASE + "/_entity/" + iri.slice(ENTITY_NS.length);
    if (iri.indexOf(MLIPS_NS) === 0) return "#" + iri.slice(MLIPS_NS.length);
    return iri;
  }

  function shortForm(iri) {
    if (iri.indexOf(ENTITY_NS) === 0) return "entity:" + iri.slice(ENTITY_NS.length);
    if (iri.indexOf(MLIPS_NS) === 0) return "mlips:" + iri.slice(MLIPS_NS.length);
    return iri;
  }

  function renderResults(json, container) {
    container.innerHTML = "";
    var vars = json.head.vars;
    var rows = json.results.bindings;
    if (!rows.length) {
      container.textContent = "No results.";
      return;
    }
    var table = document.createElement("table");
    table.className = "ccx-table";
    var thead = document.createElement("thead");
    var htr = document.createElement("tr");
    vars.forEach(function (v) {
      var th = document.createElement("th");
      th.textContent = v;
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");
    var shown = rows.slice(0, 500);
    shown.forEach(function (row) {
      var tr = document.createElement("tr");
      vars.forEach(function (v) {
        var td = document.createElement("td");
        var cell = row[v];
        if (!cell) {
          td.textContent = "";
        } else if (cell.type === "uri") {
          var a = document.createElement("a");
          a.href = hrefFor(cell.value);
          a.textContent = shortForm(cell.value);
          a.title = cell.value;
          td.appendChild(a);
        } else {
          td.textContent = cell.value;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
    var note = document.createElement("div");
    note.className = "ccx-count";
    note.textContent =
      rows.length + " result" + (rows.length === 1 ? "" : "s") + (rows.length > 500 ? " (showing first 500)" : "");
    container.appendChild(note);
  }

  // An expandable widget: a toggle that lazily runs `query` and renders the
  // results inline, plus an "open in editor" deep link. Shared by B2 and B3.
  function buildRunner(query, label) {
    var wrap = document.createElement("div");
    wrap.className = "ccx-runner";

    var bar = document.createElement("div");
    bar.className = "ccx-bar";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ccx-toggle";
    btn.textContent = label;
    var link = document.createElement("a");
    link.className = "ccx-editor-link";
    link.href = editorLink(query);
    link.textContent = "open in editor";
    bar.appendChild(btn);
    bar.appendChild(link);

    var results = document.createElement("div");
    results.className = "ccx-results";
    results.style.display = "none";

    var loaded = false;
    btn.addEventListener("click", function () {
      var isOpen = results.style.display !== "none";
      results.style.display = isOpen ? "none" : "block";
      btn.classList.toggle("ccx-open", !isOpen);
      if (!isOpen && !loaded) {
        loaded = true;
        results.textContent = "Loading…";
        runSelect(query)
          .then(function (json) {
            renderResults(json, results);
          })
          .catch(function (e) {
            results.textContent = "Error: " + e.message;
            loaded = false;
          });
      }
    });

    wrap.appendChild(bar);
    wrap.appendChild(results);
    return wrap;
  }

  // B2 — attach an "Explore individuals" widget to each owl:Class section.
  function exploreClasses() {
    var q =
      PREFIXES +
      '\nSELECT ?c WHERE { ?c a owl:Class . FILTER(STRSTARTS(STR(?c), "' +
      MLIPS_NS +
      '")) }';
    runSelect(q)
      .then(function (json) {
        json.results.bindings.forEach(function (b) {
          var iri = b.c.value;
          var local = iri.slice(MLIPS_NS.length);
          var anchor = document.getElementById(local);
          if (!anchor) return;
          // GROUP BY + SAMPLE the label so an individual carrying more than one
          // rdfs:label (e.g. a plain and an @en copy of the same text) yields a
          // single row, and LIMIT bounds *distinct* individuals.
          var query =
            PREFIXES +
            "\n# Individuals of " +
            shortForm(iri) +
            " (subclass-aware)\n" +
            "SELECT ?individual (SAMPLE(?label) AS ?label) WHERE {\n" +
            "  ?individual rdf:type/rdfs:subClassOf* <" +
            iri +
            "> .\n" +
            "  OPTIONAL { ?individual rdfs:label ?label }\n" +
            "} GROUP BY ?individual ORDER BY ?individual LIMIT 200";
          var widget = buildRunner(query, "Explore individuals");
          widget.classList.add("ccx-class");
          anchor.parentNode.insertBefore(widget, anchor.nextSibling);
        });
      })
      .catch(function () {
        /* no classes / endpoint unavailable: leave the document untouched */
      });
  }

  // B3 — render the competency-question section from the cq: RDF.
  function competencyQuestions() {
    var q =
      PREFIXES +
      // GROUP BY the CQ + SAMPLE the rest so a competency question with more
      // than one rdfs:label (same multi-label class as the individuals widget)
      // is listed once.
      "\nSELECT ?cq (SAMPLE(?id) AS ?id) (SAMPLE(?label) AS ?label)" +
      " (SAMPLE(?question) AS ?question) (SAMPLE(?query) AS ?query) WHERE {\n" +
      "  ?cq a cq:CompetencyQuestion ; dcterms:identifier ?id ;\n" +
      "      cq:questionText ?question ; cq:sparqlQuery ?query .\n" +
      "  OPTIONAL { ?cq rdfs:label ?label }\n" +
      "} GROUP BY ?cq ORDER BY ?id";
    runSelect(q)
      .then(function (json) {
        var rows = json.results.bindings;
        if (!rows.length) return;
        var section = document.createElement("section");
        section.id = "competency-questions";
        section.className = "ccx-cq-section";
        var h = document.createElement("h2");
        h.textContent = "Competency questions";
        section.appendChild(h);
        rows.forEach(function (b) {
          var item = document.createElement("div");
          item.className = "ccx-cq";
          var hd = document.createElement("h3");
          hd.textContent = b.id.value + (b.label ? " — " + b.label.value : "");
          item.appendChild(hd);
          var p = document.createElement("p");
          p.className = "ccx-cq-q";
          p.textContent = b.question.value;
          item.appendChild(p);
          var pre = document.createElement("pre");
          pre.className = "ccx-cq-sparql";
          pre.textContent = b.query.value;
          item.appendChild(pre);
          // The stored query is verbatim (its own PREFIXes); run it as-is.
          item.appendChild(buildRunner(b.query.value, "Run query"));
          section.appendChild(item);
        });
        document.body.appendChild(section);
      })
      .catch(function () {
        /* no cq graph: skip the section */
      });
  }

  exploreClasses();
  competencyQuestions();
})();
