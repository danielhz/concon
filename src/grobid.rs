//! GROBID integration for extracting metadata from scientific PDFs.
//!
//! GROBID URL is configured via mlipe.toml [grobid] section.

/// Metadata extracted from a PDF.
#[derive(Debug, Default, Clone)]
pub struct PaperMetadata {
    pub title: String,
    pub authors: String,
    pub year: String,
    pub doi: String,
    pub abstract_text: String,
    pub journal: String,
    pub volume: String,
    pub issue: String,
    pub pages: String,
    pub publisher: String,
    pub issn: String,
    pub arxiv_id: String,
    pub keywords: String,
    pub affiliations: String,
    pub references: Vec<String>,
    pub tei_xml: String,
}

/// Extract metadata from a PDF file using GROBID.
/// Calls processHeaderDocument first, then processFulltextDocument.
pub async fn extract_metadata(pdf_path: &std::path::Path, base_url: &str) -> Result<PaperMetadata, String> {
    let file_bytes = tokio::fs::read(pdf_path)
        .await
        .map_err(|e| format!("Failed to read PDF: {}", e))?;

    let file_name = pdf_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let client = reqwest::Client::new();

    // 1. processHeaderDocument (fast, ~1-3s)
    let header_meta = {
        let part = reqwest::multipart::Part::bytes(file_bytes.clone())
            .file_name(file_name.clone())
            .mime_str("application/pdf")
            .map_err(|e| format!("Mime error: {}", e))?;
        let form = reqwest::multipart::Form::new().part("input", part);

        let resp = client
            .post(format!("{}/api/processHeaderDocument", base_url))
            .header("Accept", "application/xml")
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("GROBID header request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("GROBID header returned status {}", resp.status()));
        }

        let xml = resp.text().await
            .map_err(|e| format!("Failed to read header response: {}", e))?;
        parse_tei_header(&xml)
    };

    // 2. processFulltextDocument (slower, ~5-15s)
    let fulltext_meta = {
        let part = reqwest::multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("application/pdf")
            .map_err(|e| format!("Mime error: {}", e))?;
        let form = reqwest::multipart::Form::new().part("input", part);

        let resp = client
            .post(format!("{}/api/processFulltextDocument", base_url))
            .header("Accept", "application/xml")
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("GROBID fulltext request failed: {}", e))?;

        if resp.status().is_success() {
            let xml = resp.text().await
                .map_err(|e| format!("Failed to read fulltext response: {}", e))?;
            Some(parse_tei_fulltext(&xml))
        } else {
            tracing::warn!("GROBID fulltext returned status {}, using header only", resp.status());
            None
        }
    };

    // Merge: header is primary, fulltext adds references and TEI XML
    let mut meta = header_meta;
    if let Some(ft) = fulltext_meta {
        meta.references = ft.references;
        meta.tei_xml = ft.tei_xml;
        // Fill in any blanks from fulltext that header missed
        if meta.abstract_text.is_empty() && !ft.abstract_text.is_empty() {
            meta.abstract_text = ft.abstract_text;
        }
        if meta.keywords.is_empty() && !ft.keywords.is_empty() {
            meta.keywords = ft.keywords;
        }
    }

    Ok(meta)
}

/// Parse GROBID's TEI XML header response.
fn parse_tei_header(xml: &str) -> PaperMetadata {
    let mut meta = PaperMetadata::default();

    // Title
    meta.title = extract_tag_content(xml, "<title level=\"a\" type=\"main\">", "</title>");

    // Authors
    let analytic = extract_section(xml, "<analytic>", "</analytic>");
    meta.authors = extract_authors(&analytic);

    // Affiliations
    meta.affiliations = extract_affiliations(&analytic);

    // DOI
    meta.doi = extract_tag_content(xml, "<idno type=\"DOI\">", "</idno>");

    // arXiv ID
    meta.arxiv_id = extract_tag_content(xml, "<idno type=\"arXiv\">", "</idno>");

    // Year
    if let Some(start) = xml.find("<date type=\"published\" when=\"") {
        let start = start + "<date type=\"published\" when=\"".len();
        if let Some(end) = xml[start..].find('"') {
            meta.year = xml[start..start + end].chars().take(4).collect();
        }
    }

    // Journal title
    let monogr = extract_section(xml, "<monogr>", "</monogr>");
    meta.journal = extract_tag_content(&monogr, "<title level=\"j\">", "</title>");

    // Volume, issue, pages from monogr
    meta.volume = extract_attr_content(&monogr, "<biblScope unit=\"volume\">", "</biblScope>");
    meta.issue = extract_attr_content(&monogr, "<biblScope unit=\"issue\">", "</biblScope>");
    meta.pages = extract_attr_content(&monogr, "<biblScope unit=\"page\"", "</biblScope>");

    // Publisher
    meta.publisher = extract_tag_content(&monogr, "<publisher>", "</publisher>");

    // ISSN
    meta.issn = extract_tag_content(&monogr, "<idno type=\"ISSN\">", "</idno>");

    // Abstract
    meta.abstract_text = extract_abstract(xml);

    // Keywords
    meta.keywords = extract_keywords(xml);

    // Clean HTML entities
    clean_entities(&mut meta);

    meta
}

/// Parse GROBID's TEI fulltext response for references and raw XML.
fn parse_tei_fulltext(xml: &str) -> PaperMetadata {
    let mut meta = PaperMetadata::default();

    // Store raw TEI XML
    meta.tei_xml = xml.to_string();

    // Extract abstract if present
    meta.abstract_text = extract_abstract(xml);

    // Extract keywords if present
    meta.keywords = extract_keywords(xml);

    // Extract references (DOIs of cited works)
    let mut refs = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find("<idno type=\"DOI\">") {
        let abs_pos = search_from + pos;
        // Check if this DOI is within a <listBibl> (references section)
        let before = &xml[..abs_pos];
        if before.rfind("<listBibl>").is_some() {
            let start = abs_pos + "<idno type=\"DOI\">".len();
            if let Some(end) = xml[start..].find("</idno>") {
                let doi = xml[start..start + end].trim().to_string();
                if !doi.is_empty() && !refs.contains(&doi) {
                    refs.push(doi);
                }
            }
            search_from = abs_pos + 1;
        } else {
            search_from = abs_pos + 1;
        }
    }
    meta.references = refs;

    meta
}

// ─── Helper functions ───────────────────────────────────────────────

fn extract_tag_content(xml: &str, open: &str, close: &str) -> String {
    if let Some(start) = xml.find(open) {
        let start = start + open.len();
        if let Some(end) = xml[start..].find(close) {
            return xml[start..start + end].trim().to_string();
        }
    }
    String::new()
}

fn extract_attr_content(xml: &str, open_prefix: &str, close: &str) -> String {
    if let Some(start) = xml.find(open_prefix) {
        // Find the closing > of the opening tag
        if let Some(gt) = xml[start..].find('>') {
            let content_start = start + gt + 1;
            if let Some(end) = xml[content_start..].find(close) {
                return xml[content_start..content_start + end].trim().to_string();
            }
        }
    }
    String::new()
}

fn extract_section(xml: &str, open: &str, close: &str) -> String {
    if let Some(start) = xml.find(open) {
        if let Some(end) = xml[start..].find(close) {
            return xml[start..start + end + close.len()].to_string();
        }
    }
    String::new()
}

fn extract_authors(analytic: &str) -> String {
    let mut authors = Vec::new();
    let mut search_from = 0;
    while let Some(start) = analytic[search_from..].find("<persName") {
        let abs_start = search_from + start;
        if let Some(end) = analytic[abs_start..].find("</persName>") {
            let person = &analytic[abs_start..abs_start + end + "</persName>".len()];

            let mut forenames = Vec::new();
            let mut surname = String::new();

            // Extract all forenames
            let mut fn_search = 0;
            while let Some(fs) = person[fn_search..].find("<forename") {
                let fs_abs = fn_search + fs;
                if let Some(fe) = person[fs_abs..].find('>') {
                    let after = fs_abs + fe + 1;
                    if let Some(fend) = person[after..].find("</forename>") {
                        let name = person[after..after + fend].trim().to_string();
                        if !name.is_empty() {
                            forenames.push(name);
                        }
                    }
                    fn_search = after;
                } else {
                    break;
                }
            }

            // Extract surname
            if let Some(ss) = person.find("<surname>") {
                let after = ss + "<surname>".len();
                if let Some(send) = person[after..].find("</surname>") {
                    surname = person[after..after + send].trim().to_string();
                }
            }

            if !surname.is_empty() {
                if forenames.is_empty() {
                    authors.push(surname);
                } else {
                    authors.push(format!("{}, {}", surname, forenames.join(" ")));
                }
            }

            search_from = abs_start + end + "</persName>".len();
        } else {
            break;
        }
    }
    authors.join("; ")
}

fn extract_affiliations(analytic: &str) -> String {
    let mut affiliations = Vec::new();
    let mut search_from = 0;
    while let Some(start) = analytic[search_from..].find("<affiliation") {
        let abs_start = search_from + start;
        if let Some(end) = analytic[abs_start..].find("</affiliation>") {
            let aff = &analytic[abs_start..abs_start + end + "</affiliation>".len()];

            // Extract orgName elements
            let mut org_parts = Vec::new();
            let mut org_search = 0;
            while let Some(os) = aff[org_search..].find("<orgName") {
                let os_abs = org_search + os;
                if let Some(gt) = aff[os_abs..].find('>') {
                    let after = os_abs + gt + 1;
                    if let Some(oend) = aff[after..].find("</orgName>") {
                        let name = aff[after..after + oend].trim().to_string();
                        if !name.is_empty() && !org_parts.contains(&name) {
                            org_parts.push(name);
                        }
                    }
                    org_search = after;
                } else {
                    break;
                }
            }

            if !org_parts.is_empty() {
                let aff_str = org_parts.join(", ");
                if !affiliations.contains(&aff_str) {
                    affiliations.push(aff_str);
                }
            }

            search_from = abs_start + end + "</affiliation>".len();
        } else {
            break;
        }
    }
    affiliations.join("; ")
}

fn extract_abstract(xml: &str) -> String {
    // <abstract> may contain <p> elements
    let section = extract_section(xml, "<abstract>", "</abstract>");
    if section.is_empty() {
        return String::new();
    }

    // Collect text from <p> elements
    let mut parts = Vec::new();
    let mut search_from = 0;
    while let Some(start) = section[search_from..].find("<p>") {
        let abs_start = search_from + start + "<p>".len();
        if let Some(end) = section[abs_start..].find("</p>") {
            let text = strip_xml_tags(&section[abs_start..abs_start + end]).trim().to_string();
            if !text.is_empty() {
                parts.push(text);
            }
            search_from = abs_start + end;
        } else {
            break;
        }
    }

    // If no <p> elements, try raw text content
    if parts.is_empty() {
        let inner = extract_tag_content(xml, "<abstract>", "</abstract>");
        let text = strip_xml_tags(&inner).trim().to_string();
        if !text.is_empty() {
            parts.push(text);
        }
    }

    parts.join("\n\n")
}

fn extract_keywords(xml: &str) -> String {
    let section = extract_section(xml, "<keywords>", "</keywords>");
    if section.is_empty() {
        return String::new();
    }

    let mut keywords = Vec::new();
    let mut search_from = 0;
    while let Some(start) = section[search_from..].find("<term>") {
        let abs_start = search_from + start + "<term>".len();
        if let Some(end) = section[abs_start..].find("</term>") {
            let kw = section[abs_start..abs_start + end].trim().to_string();
            if !kw.is_empty() {
                keywords.push(kw);
            }
            search_from = abs_start + end;
        } else {
            break;
        }
    }

    keywords.join("; ")
}

/// Remove XML tags from a string, keeping only text content.
fn strip_xml_tags(s: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for ch in s.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }
    result
}

fn clean_entities(meta: &mut PaperMetadata) {
    let clean = |s: &mut String| {
        *s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"");
    };
    clean(&mut meta.title);
    clean(&mut meta.authors);
    clean(&mut meta.abstract_text);
    clean(&mut meta.journal);
    clean(&mut meta.publisher);
    clean(&mut meta.keywords);
    clean(&mut meta.affiliations);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tei_header_basic() {
        let xml = r#"
        <TEI>
        <teiHeader>
        <fileDesc>
        <titleStmt>
        <title level="a" type="main">Machine learning interatomic potentials</title>
        </titleStmt>
        <sourceDesc>
        <biblStruct>
        <analytic>
        <author>
        <persName><forename type="first">John</forename><surname>Smith</surname></persName>
        <affiliation><orgName type="institution">MIT</orgName></affiliation>
        </author>
        <author>
        <persName><forename type="first">Jane</forename><surname>Doe</surname></persName>
        <affiliation><orgName type="institution">Stanford</orgName></affiliation>
        </author>
        <idno type="DOI">10.1234/example.2023</idno>
        </analytic>
        <monogr>
        <title level="j">Physical Review B</title>
        <idno type="ISSN">1098-0121</idno>
        <imprint>
        <publisher>APS</publisher>
        <biblScope unit="volume">107</biblScope>
        <biblScope unit="issue">3</biblScope>
        <biblScope unit="page" from="1" to="15">1-15</biblScope>
        <date type="published" when="2023-01-15"/>
        </imprint>
        </monogr>
        </biblStruct>
        </sourceDesc>
        </fileDesc>
        <profileDesc>
        <abstract><p>We present a review of machine learning potentials.</p></abstract>
        <keywords><term>machine learning</term><term>interatomic potentials</term></keywords>
        </profileDesc>
        </teiHeader>
        </TEI>
        "#;

        let meta = parse_tei_header(xml);
        assert_eq!(meta.title, "Machine learning interatomic potentials");
        assert_eq!(meta.authors, "Smith, John; Doe, Jane");
        assert_eq!(meta.doi, "10.1234/example.2023");
        assert_eq!(meta.year, "2023");
        assert_eq!(meta.journal, "Physical Review B");
        assert_eq!(meta.volume, "107");
        assert_eq!(meta.issue, "3");
        assert_eq!(meta.pages, "1-15");
        assert_eq!(meta.publisher, "APS");
        assert_eq!(meta.issn, "1098-0121");
        assert_eq!(meta.abstract_text, "We present a review of machine learning potentials.");
        assert_eq!(meta.keywords, "machine learning; interatomic potentials");
        assert_eq!(meta.affiliations, "MIT; Stanford");
    }

    #[test]
    fn test_parse_tei_fulltext_references() {
        let xml = r#"
        <TEI>
        <text>
        <body><p>Some text</p></body>
        <back>
        <listBibl>
        <biblStruct>
        <analytic><title>Ref 1</title></analytic>
        <idno type="DOI">10.1000/ref1</idno>
        </biblStruct>
        <biblStruct>
        <analytic><title>Ref 2</title></analytic>
        <idno type="DOI">10.1000/ref2</idno>
        </biblStruct>
        </listBibl>
        </back>
        </text>
        </TEI>
        "#;

        let meta = parse_tei_fulltext(xml);
        assert_eq!(meta.references, vec!["10.1000/ref1", "10.1000/ref2"]);
        assert!(!meta.tei_xml.is_empty());
    }
}
