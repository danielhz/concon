//! SHACL shape parsing and form descriptor generation.
//!
//! Parses SHACL NodeShapes from an Oxigraph store using SPARQL queries
//! and generates form field descriptors for the entity editor UI.

use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;
use serde::Serialize;

use crate::auth::strip_literal;
use crate::store::sparql_query;

/// Describes the input type for a form field, derived from SHACL constraints.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type")]
pub enum InputType {
    Text,
    Number,
    Date,
    DateTime,
    Boolean,
    Url,
    Textarea,
    Select { options: Vec<String> },
    EntityAutocomplete { class_iri: String },
}

/// Describes a single property field in an entity form.
#[derive(Debug, Clone, Serialize)]
pub struct PropertyField {
    pub path: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub min_count: Option<u32>,
    pub max_count: Option<u32>,
    pub datatype: Option<String>,
    pub class: Option<String>,
    pub pattern: Option<String>,
    pub order: Option<f64>,
    pub group: Option<String>,
    pub input_type: InputType,
    pub required: bool,
}

/// Describes a complete entity form generated from a SHACL NodeShape.
#[derive(Debug, Clone, Serialize)]
pub struct FormDescriptor {
    pub shape_iri: String,
    pub target_class: String,
    pub label: Option<String>,
    pub iri_generator: Option<String>,
    pub properties: Vec<PropertyField>,
}

/// Parse all SHACL NodeShapes from a store into form descriptors.
pub fn parse_shapes_from_store(store: &Store) -> Vec<FormDescriptor> {
    let shapes_query = r#"
        PREFIX sh: <http://www.w3.org/ns/shacl#>
        PREFIX concon: <https://concon.2mia.org/ontology#>
        SELECT ?shape ?targetClass ?name ?iriGen WHERE {
            ?shape a sh:NodeShape ;
                   sh:targetClass ?targetClass .
            OPTIONAL { ?shape sh:name ?name }
            OPTIONAL { ?shape concon:iriGenerator ?iriGen }
        }
    "#;

    let mut descriptors = Vec::new();

    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, shapes_query) {
        for solution in solutions.flatten() {
            let shape_iri = solution
                .get("shape")
                .map(|v| strip_iri(&v.to_string()))
                .unwrap_or_default();
            let target_class = solution
                .get("targetClass")
                .map(|v| strip_iri(&v.to_string()))
                .unwrap_or_default();
            let label = solution.get("name").map(|v| strip_literal(&v.to_string()));
            let iri_generator = solution.get("iriGen").map(|v| strip_iri(&v.to_string()));

            let properties = parse_property_shapes(store, &shape_iri);

            descriptors.push(FormDescriptor {
                shape_iri,
                target_class,
                label,
                iri_generator,
                properties,
            });
        }
    }

    descriptors
}

/// Parse property shapes for a given NodeShape IRI.
fn parse_property_shapes(store: &Store, shape_iri: &str) -> Vec<PropertyField> {
    let query = format!(
        r#"
        PREFIX sh: <http://www.w3.org/ns/shacl#>
        SELECT ?prop ?path ?name ?desc ?minCount ?maxCount ?datatype ?class ?pattern ?order ?group
        WHERE {{
            <{shape_iri}> sh:property ?prop .
            ?prop sh:path ?path .
            OPTIONAL {{ ?prop sh:name ?name }}
            OPTIONAL {{ ?prop sh:description ?desc }}
            OPTIONAL {{ ?prop sh:minCount ?minCount }}
            OPTIONAL {{ ?prop sh:maxCount ?maxCount }}
            OPTIONAL {{ ?prop sh:datatype ?datatype }}
            OPTIONAL {{ ?prop sh:class ?class }}
            OPTIONAL {{ ?prop sh:pattern ?pattern }}
            OPTIONAL {{ ?prop sh:order ?order }}
            OPTIONAL {{ ?prop sh:group ?group }}
        }}
        ORDER BY ?order
        "#,
    );

    let mut fields = Vec::new();

    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            let prop_iri = solution
                .get("prop")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let path = solution
                .get("path")
                .map(|v| strip_iri(&v.to_string()))
                .unwrap_or_default();
            let name = solution.get("name").map(|v| strip_literal(&v.to_string()));
            let description = solution.get("desc").map(|v| strip_literal(&v.to_string()));
            let min_count = solution
                .get("minCount")
                .and_then(|v| strip_literal(&v.to_string()).parse::<u32>().ok());
            let max_count = solution
                .get("maxCount")
                .and_then(|v| strip_literal(&v.to_string()).parse::<u32>().ok());
            let datatype = solution.get("datatype").map(|v| strip_iri(&v.to_string()));
            let class = solution.get("class").map(|v| strip_iri(&v.to_string()));
            let pattern = solution
                .get("pattern")
                .map(|v| strip_literal(&v.to_string()));
            let order = solution
                .get("order")
                .and_then(|v| strip_literal(&v.to_string()).parse::<f64>().ok());
            let group = solution.get("group").map(|v| strip_literal(&v.to_string()));

            // Check for sh:in values
            let allowed_values = parse_sh_in(store, &prop_iri);

            let input_type = derive_input_type(&datatype, &class, &allowed_values);
            let required = min_count.unwrap_or(0) >= 1;

            fields.push(PropertyField {
                path,
                name,
                description,
                min_count,
                max_count,
                datatype,
                class,
                pattern,
                order,
                group,
                input_type,
                required,
            });
        }
    }

    fields
}

/// Parse sh:in values (RDF list) for a property shape.
fn parse_sh_in(store: &Store, prop_iri: &str) -> Vec<String> {
    let prop_clean = prop_iri.trim_matches(|c| c == '<' || c == '>');
    let query = format!(
        r#"
        PREFIX sh: <http://www.w3.org/ns/shacl#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?item WHERE {{
            <{prop_clean}> sh:in/rdf:rest*/rdf:first ?item .
        }}
        "#,
    );

    let mut values = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &query) {
        for solution in solutions.flatten() {
            if let Some(item) = solution.get("item") {
                let s = item.to_string();
                // Could be a literal or IRI
                if s.starts_with('"') {
                    values.push(strip_literal(&s));
                } else {
                    values.push(strip_iri(&s));
                }
            }
        }
    }
    values
}

/// Derive the form input type from SHACL constraints.
fn derive_input_type(
    datatype: &Option<String>,
    class: &Option<String>,
    allowed_values: &[String],
) -> InputType {
    if !allowed_values.is_empty() {
        return InputType::Select {
            options: allowed_values.to_vec(),
        };
    }

    if let Some(class_iri) = class {
        return InputType::EntityAutocomplete {
            class_iri: class_iri.clone(),
        };
    }

    match datatype.as_deref() {
        Some("http://www.w3.org/2001/XMLSchema#integer")
        | Some("http://www.w3.org/2001/XMLSchema#decimal")
        | Some("http://www.w3.org/2001/XMLSchema#float")
        | Some("http://www.w3.org/2001/XMLSchema#double") => InputType::Number,
        Some("http://www.w3.org/2001/XMLSchema#date") => InputType::Date,
        Some("http://www.w3.org/2001/XMLSchema#dateTime") => InputType::DateTime,
        Some("http://www.w3.org/2001/XMLSchema#boolean") => InputType::Boolean,
        Some("http://www.w3.org/2001/XMLSchema#anyURI") => InputType::Url,
        _ => InputType::Text,
    }
}

/// Serialize form descriptors to a JSON value for the template.
pub fn form_descriptors_to_json(descriptors: &[FormDescriptor]) -> serde_json::Value {
    serde_json::to_value(descriptors).unwrap_or(serde_json::json!([]))
}

/// Generate an entity IRI using a UUID.
pub fn generate_uuid_iri(base: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{}/{}", base, uuid::Uuid::new_v4())
}

/// Generate an entity IRI from a label (slug).
pub fn generate_slug_iri(base: &str, label: &str) -> String {
    let base = base.trim_end_matches('/');
    let slug: String = label
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let slug: String = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    format!("{}/{}", base, slug)
}

/// Strip angle brackets from an IRI string.
fn strip_iri(s: &str) -> String {
    s.trim().trim_matches(|c| c == '<' || c == '>').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sparql_update;

    fn load_shapes(store: &Store, turtle: &str) {
        sparql_update(store, &format!("INSERT DATA {{ {} }}", turtle)).unwrap();
    }

    #[test]
    fn test_parse_shacl_node_shape() {
        let store = Store::new().unwrap();
        load_shapes(
            &store,
            r#"
            <http://example.org/PersonShape> a <http://www.w3.org/ns/shacl#NodeShape> ;
                <http://www.w3.org/ns/shacl#targetClass> <http://example.org/Person> ;
                <http://www.w3.org/ns/shacl#name> "Person" ;
                <http://www.w3.org/ns/shacl#property> <http://example.org/nameShape> .
            <http://example.org/nameShape> a <http://www.w3.org/ns/shacl#PropertyShape> ;
                <http://www.w3.org/ns/shacl#path> <http://example.org/name> ;
                <http://www.w3.org/ns/shacl#name> "Name" ;
                <http://www.w3.org/ns/shacl#minCount> 1 ;
                <http://www.w3.org/ns/shacl#datatype> <http://www.w3.org/2001/XMLSchema#string> .
            "#,
        );

        let descriptors = parse_shapes_from_store(&store);
        assert_eq!(descriptors.len(), 1);
        let shape = &descriptors[0];
        assert_eq!(shape.target_class, "http://example.org/Person");
        assert_eq!(shape.label, Some("Person".to_string()));
        assert_eq!(shape.properties.len(), 1);

        let prop = &shape.properties[0];
        assert_eq!(prop.path, "http://example.org/name");
        assert_eq!(prop.name, Some("Name".to_string()));
        assert_eq!(prop.min_count, Some(1));
        assert!(prop.required);
        assert_eq!(prop.input_type, InputType::Text);
    }

    #[test]
    fn test_form_fields_from_shape() {
        let store = Store::new().unwrap();
        load_shapes(
            &store,
            r#"
            <http://example.org/MolShape> a <http://www.w3.org/ns/shacl#NodeShape> ;
                <http://www.w3.org/ns/shacl#targetClass> <http://example.org/Molecule> ;
                <http://www.w3.org/ns/shacl#property> <http://example.org/massShape> ,
                    <http://example.org/dateShape> ,
                    <http://example.org/typeShape> .
            <http://example.org/massShape> <http://www.w3.org/ns/shacl#path> <http://example.org/mass> ;
                <http://www.w3.org/ns/shacl#datatype> <http://www.w3.org/2001/XMLSchema#decimal> ;
                <http://www.w3.org/ns/shacl#minCount> 1 ;
                <http://www.w3.org/ns/shacl#order> 1 .
            <http://example.org/dateShape> <http://www.w3.org/ns/shacl#path> <http://example.org/created> ;
                <http://www.w3.org/ns/shacl#datatype> <http://www.w3.org/2001/XMLSchema#date> ;
                <http://www.w3.org/ns/shacl#order> 2 .
            <http://example.org/typeShape> <http://www.w3.org/ns/shacl#path> <http://example.org/relatedTo> ;
                <http://www.w3.org/ns/shacl#class> <http://example.org/Molecule> ;
                <http://www.w3.org/ns/shacl#order> 3 .
            "#,
        );

        let descriptors = parse_shapes_from_store(&store);
        assert_eq!(descriptors.len(), 1);
        let props = &descriptors[0].properties;
        assert_eq!(props.len(), 3);

        // Mass: decimal -> Number, required
        assert_eq!(props[0].input_type, InputType::Number);
        assert!(props[0].required);

        // Date: date -> Date, optional
        assert_eq!(props[1].input_type, InputType::Date);
        assert!(!props[1].required);

        // Related: class -> EntityAutocomplete, optional
        assert!(matches!(
            &props[2].input_type,
            InputType::EntityAutocomplete { .. }
        ));
        assert!(!props[2].required);
    }

    #[test]
    fn test_stated_triple_annotation() {
        use oxigraph::io::RdfFormat;

        let store = Store::new().unwrap();

        // Insert a stated triple with annotation via Turtle I/O
        let turtle = r#"
            @prefix concon: <https://concon.2mia.org/ontology#> .
            <urn:entity1> <urn:prop> "value" .
            << <urn:entity1> <urn:prop> "value" >> a concon:StatedTriple .
        "#;
        store
            .load_from_reader(RdfFormat::Turtle, turtle.as_bytes())
            .unwrap();

        // Verify the triple exists
        let results = sparql_query(&store, "ASK { <urn:entity1> <urn:prop> \"value\" }").unwrap();
        assert!(matches!(results, QueryResults::Boolean(true)));

        // Verify the annotation exists
        let results = sparql_query(
            &store,
            r#"
            PREFIX concon: <https://concon.2mia.org/ontology#>
            SELECT ?r WHERE { ?r a concon:StatedTriple }
            "#,
        )
        .unwrap();
        let mut count = 0;
        if let QueryResults::Solutions(solutions) = results {
            for solution in solutions {
                solution.unwrap();
                count += 1;
            }
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_non_stated_triple_annotation() {
        use oxigraph::io::RdfFormat;

        let store = Store::new().unwrap();

        // Insert only the annotation, NOT the triple
        let turtle = r#"
            @prefix concon: <https://concon.2mia.org/ontology#> .
            << <urn:entity2> <urn:prop> "draft-value" >> a concon:NonStatedTriple .
        "#;
        store
            .load_from_reader(RdfFormat::Turtle, turtle.as_bytes())
            .unwrap();

        // Verify the triple does NOT exist
        let results =
            sparql_query(&store, "ASK { <urn:entity2> <urn:prop> \"draft-value\" }").unwrap();
        assert!(matches!(results, QueryResults::Boolean(false)));

        // Verify the annotation exists
        let results = sparql_query(
            &store,
            r#"
            PREFIX concon: <https://concon.2mia.org/ontology#>
            SELECT ?r WHERE { ?r a concon:NonStatedTriple }
            "#,
        )
        .unwrap();
        let mut count = 0;
        if let QueryResults::Solutions(solutions) = results {
            for solution in solutions {
                solution.unwrap();
                count += 1;
            }
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_iri_generator_uuid() {
        let iri = generate_uuid_iri("http://example.org/entities");
        assert!(iri.starts_with("http://example.org/entities/"));
        // UUID part should be 36 chars (8-4-4-4-12)
        let uuid_part = iri.strip_prefix("http://example.org/entities/").unwrap();
        assert_eq!(uuid_part.len(), 36);
        assert_eq!(uuid_part.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_slug_iri_generation() {
        assert_eq!(
            generate_slug_iri("http://example.org/entities", "My Cool Entity"),
            "http://example.org/entities/my-cool-entity"
        );
        assert_eq!(
            generate_slug_iri("http://example.org/entities/", "  Hello  World!  "),
            "http://example.org/entities/hello-world"
        );
    }

    #[test]
    fn test_entity_search() {
        let store = Store::new().unwrap();
        sparql_update(
            &store,
            r#"
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX ex: <http://example.org/>
            INSERT DATA {
                ex:alice a ex:Person ; rdfs:label "Alice Smith" .
                ex:bob a ex:Person ; rdfs:label "Bob Jones" .
                ex:water a ex:Molecule ; rdfs:label "Water" .
            }
            "#,
        )
        .unwrap();

        // Search for "alice" among Person entities
        let results = search_entities(&store, "alice", Some("http://example.org/Person"));
        assert_eq!(results.len(), 1);
        assert!(results[0].label.contains("Alice"));

        // Search without class filter — "o" matches Bob Jones only
        let results = search_entities(&store, "o", None);
        assert_eq!(results.len(), 1);

        // Search all entities with empty-ish term — "a" matches Alice, Water
        let results = search_entities(&store, "a", None);
        assert_eq!(results.len(), 2);
    }
}

/// Result of an entity search.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub iri: String,
    pub label: String,
}

/// Search for entities in a dataset store by label substring.
pub fn search_entities(
    store: &Store,
    query_text: &str,
    class_filter: Option<&str>,
) -> Vec<SearchResult> {
    let escaped = query_text.replace('\\', "\\\\").replace('"', "\\\"");
    let class_clause = match class_filter {
        Some(class) => format!("?entity a <{}> .", class),
        None => String::new(),
    };

    let sparql = format!(
        r#"
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX dcterms: <http://purl.org/dc/terms/>
        SELECT DISTINCT ?entity ?label WHERE {{
            {class_clause}
            {{ ?entity rdfs:label ?label }}
            UNION
            {{ ?entity dcterms:title ?label }}
            FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{escaped}")))
        }}
        LIMIT 20
        "#,
    );

    let mut results = Vec::new();
    if let Ok(QueryResults::Solutions(solutions)) = sparql_query(store, &sparql) {
        for solution in solutions.flatten() {
            let iri = solution
                .get("entity")
                .map(|v| strip_iri(&v.to_string()))
                .unwrap_or_default();
            let label = solution
                .get("label")
                .map(|v| strip_literal(&v.to_string()))
                .unwrap_or_default();
            results.push(SearchResult { iri, label });
        }
    }
    results
}
