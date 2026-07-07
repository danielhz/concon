/*
 * concon entity/resource graph explorer (Epic J).
 *
 * A client-side node-link neighbourhood graph on the resource view
 * (serve_resource → entity.html): centre node = the current resource, edges =
 * its incoming + outgoing entity↔entity relations (object properties; literals
 * excluded), neighbours labelled. Tapping a node shows its literal attributes
 * in the side panel and offers "open its view". Reads only, over the public
 * `_sparql` endpoint (same pattern as concon-explore.js). Cytoscape.js is
 * vendored (CSP-safe, no CDN); this script does nothing if it or the container
 * is absent, so the page degrades gracefully.
 */
(function () {
  "use strict";

  var script = document.querySelector("script[data-graph-iri]");
  if (!script || !window.cytoscape) return;
  var SPARQL = script.dataset.sparql; // e.g. /mlips/_ds/mlips/_sparql
  var BASE = script.dataset.base; //     e.g. /mlips/_ds/mlips
  var IRI = script.dataset.graphIri; //  the centre resource IRI
  var container = document.getElementById("cy");
  var panel = document.getElementById("cy-attrs");
  if (!container || !IRI) return;

  var MLIPS_NS = "https://w3id.org/mlips#";
  var ENTITY_NS = "https://w3id.org/mlips/entity/";
  // Namespaces that get a local resource view (mirrors the server's
  // earns_local_view policy) — for routing node links view→view.
  var VIEWABLE = [
    MLIPS_NS,
    "https://schema.org/",
    "http://www.w3.org/ns/prov#",
    "http://qudt.org/schema/qudt/",
    "http://qudt.org/vocab/unit/",
    "http://www.w3.org/ns/mls#",
    "https://purls.helmholtz-metadaten.de/cmso/",
    "https://w3id.org/mdo/core/",
    "https://w3id.org/mdo/calculation/"
  ];

  var PREFIXES = "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n";
  var NEIGHBOUR_CAP = 200;

  function startsWith(s, p) {
    return s.lastIndexOf(p, 0) === 0;
  }

  function hrefFor(iri) {
    if (startsWith(iri, ENTITY_NS)) return BASE + "/_entity/" + iri.slice(ENTITY_NS.length);
    for (var i = 0; i < VIEWABLE.length; i++) {
      if (startsWith(iri, VIEWABLE[i])) return BASE + "/_view?iri=" + encodeURIComponent(iri);
    }
    return iri;
  }

  function shortForm(iri) {
    if (startsWith(iri, ENTITY_NS)) return "entity:" + iri.slice(ENTITY_NS.length);
    if (startsWith(iri, MLIPS_NS)) return "mlips:" + iri.slice(MLIPS_NS.length);
    var hash = Math.max(iri.lastIndexOf("#"), iri.lastIndexOf("/"));
    return hash >= 0 && hash < iri.length - 1 ? iri.slice(hash + 1) : iri;
  }

  function runSelect(query) {
    return fetch(SPARQL + "?query=" + encodeURIComponent(query), {
      headers: { Accept: "application/sparql-results+json" }
    }).then(function (r) {
      if (!r.ok) throw new Error("SPARQL " + r.status);
      return r.json();
    });
  }

  // 1-hop neighbourhood: IRI-valued objects (outgoing) and IRI subjects
  // (incoming). Literals are excluded — they populate the attributes panel.
  function neighbourhoodQuery() {
    return (
      PREFIXES +
      "SELECT ?dir ?pred ?node ?nlabel WHERE {\n" +
      "  { <" + IRI + "> ?pred ?node . BIND('out' AS ?dir) FILTER(isIRI(?node)) }\n" +
      "  UNION\n" +
      "  { ?node ?pred <" + IRI + "> . BIND('in' AS ?dir) FILTER(isIRI(?node)) }\n" +
      "  OPTIONAL { ?node rdfs:label ?nlabel }\n" +
      "} LIMIT " + NEIGHBOUR_CAP
    );
  }

  function buildGraph(json) {
    var rows = json.results.bindings;
    if (!rows.length) {
      container.classList.add("cy-empty");
      container.textContent = "No entity relations to graph.";
      return;
    }
    var elements = [{ data: { id: IRI, label: shortForm(IRI), iri: IRI, centre: 1 } }];
    var seenNode = {};
    seenNode[IRI] = true;
    var seenEdge = {};
    rows.forEach(function (b) {
      var node = b.node.value,
        pred = b.pred.value,
        dir = b.dir.value;
      if (!seenNode[node]) {
        elements.push({
          data: {
            id: node,
            label: b.nlabel ? b.nlabel.value : shortForm(node),
            iri: node
          }
        });
        seenNode[node] = true;
      }
      var source = dir === "out" ? IRI : node;
      var target = dir === "out" ? node : IRI;
      var ekey = source + " " + pred + " " + target;
      if (seenEdge[ekey]) return;
      seenEdge[ekey] = true;
      elements.push({
        data: { id: "e" + elements.length, source: source, target: target, label: shortForm(pred) }
      });
    });

    var cy = cytoscape({
      container: container,
      elements: elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#5a8fc6",
            label: "data(label)",
            "font-size": "10px",
            color: "#0a0a0a",
            "text-valign": "bottom",
            "text-margin-y": 3,
            width: 26,
            height: 26
          }
        },
        {
          selector: "node[centre]",
          style: { "background-color": "#cc4b37", width: 38, height: 38, "font-weight": "bold" }
        },
        { selector: "node:selected", style: { "border-width": 3, "border-color": "#1779ba" } },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#b8c2cc",
            "target-arrow-color": "#b8c2cc",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "8px",
            color: "#767676",
            "text-rotation": "autorotate"
          }
        }
      ],
      layout: { name: "cose", animate: false, padding: 20 }
    });

    cy.on("tap", "node", function (evt) {
      showAttributes(evt.target.data());
    });
    // Show the centre node's attributes to start.
    showAttributes({ iri: IRI, label: shortForm(IRI) });
  }

  function showAttributes(d) {
    if (!panel) return;
    panel.innerHTML = "";
    var h = document.createElement("div");
    h.className = "cy-attrs-head";
    var strong = document.createElement("strong");
    strong.textContent = d.label || shortForm(d.iri);
    h.appendChild(strong);
    var open = document.createElement("a");
    open.href = hrefFor(d.iri);
    open.target = "_blank";
    open.rel = "noopener";
    open.className = "cy-open";
    open.textContent = "open view ↗";
    h.appendChild(open);
    panel.appendChild(h);

    var iriLine = document.createElement("div");
    iriLine.className = "cy-attrs-iri";
    iriLine.textContent = d.iri;
    panel.appendChild(iriLine);

    var loading = document.createElement("div");
    loading.className = "cy-attrs-loading";
    loading.textContent = "Loading attributes…";
    panel.appendChild(loading);

    var q =
      "SELECT ?p ?v WHERE { <" + d.iri + "> ?p ?v FILTER(isLiteral(?v)) } LIMIT 100";
    runSelect(q)
      .then(function (json) {
        loading.remove();
        var rows = json.results.bindings;
        if (!rows.length) {
          var none = document.createElement("div");
          none.className = "cy-attrs-none";
          none.textContent = "No literal attributes.";
          panel.appendChild(none);
          return;
        }
        var table = document.createElement("table");
        table.className = "cy-attrs-table";
        rows.forEach(function (b) {
          var tr = document.createElement("tr");
          var pth = document.createElement("th");
          pth.textContent = shortForm(b.p.value);
          pth.title = b.p.value;
          var vtd = document.createElement("td");
          vtd.textContent = b.v.value;
          tr.appendChild(pth);
          tr.appendChild(vtd);
          table.appendChild(tr);
        });
        panel.appendChild(table);
      })
      .catch(function (e) {
        loading.textContent = "Error loading attributes: " + e.message;
      });
  }

  runSelect(neighbourhoodQuery())
    .then(buildGraph)
    .catch(function () {
      container.classList.add("cy-empty");
      container.textContent = "Graph unavailable (endpoint error).";
    });
})();
