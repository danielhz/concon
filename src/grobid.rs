//! GROBID integration for extracting metadata from scientific PDFs.
//!
//! GROBID runs as a Docker container on-demand: started before processing,
//! stopped after. This saves RAM when idle.

use std::process::Command;
use std::time::Duration;

const GROBID_IMAGE: &str = "lfoppiano/grobid:0.8.1";
const GROBID_CONTAINER: &str = "mlipe-grobid";
const GROBID_PORT: u16 = 8070;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);
const STARTUP_POLL: Duration = Duration::from_secs(2);

/// Metadata extracted from a PDF.
#[derive(Debug, Default)]
pub struct PaperMetadata {
    pub title: String,
    pub authors: String,
    pub year: String,
    pub doi: String,
}

/// Start the GROBID container if not already running.
pub fn ensure_running() -> Result<(), String> {
    // Check if already running
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", GROBID_CONTAINER])
        .output()
        .map_err(|e| format!("Failed to run docker: {}", e))?;

    if output.status.success() {
        let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if state == "true" {
            tracing::info!("GROBID container already running");
            return Ok(());
        }
    }

    // Remove old stopped container if it exists
    let _ = Command::new("docker")
        .args(["rm", "-f", GROBID_CONTAINER])
        .output();

    // Start new container
    tracing::info!("Starting GROBID container...");
    let output = Command::new("docker")
        .args([
            "run", "-d",
            "--name", GROBID_CONTAINER,
            "-p", &format!("{}:8070", GROBID_PORT),
            "--memory", "4g",
            GROBID_IMAGE,
        ])
        .output()
        .map_err(|e| format!("Failed to start GROBID: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to start GROBID: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Wait for GROBID to be ready
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > STARTUP_TIMEOUT {
            return Err("GROBID startup timed out".into());
        }

        if let Ok(resp) = reqwest::blocking::get(format!("http://localhost:{}/api/isalive", GROBID_PORT)) {
            if resp.status().is_success() {
                tracing::info!("GROBID is ready");
                return Ok(());
            }
        }

        std::thread::sleep(STARTUP_POLL);
    }
}

/// Stop the GROBID container.
pub fn stop() {
    tracing::info!("Stopping GROBID container...");
    let _ = Command::new("docker")
        .args(["stop", GROBID_CONTAINER])
        .output();
    let _ = Command::new("docker")
        .args(["rm", GROBID_CONTAINER])
        .output();
}

/// Extract metadata from a PDF file using GROBID.
pub async fn extract_metadata(pdf_path: &std::path::Path) -> Result<PaperMetadata, String> {
    // Start GROBID if needed (blocking, runs in spawn_blocking)
    let path = pdf_path.to_path_buf();
    tokio::task::spawn_blocking(|| ensure_running())
        .await
        .map_err(|e| format!("Task join error: {}", e))??;

    // Send PDF to GROBID
    let file_bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("Failed to read PDF: {}", e))?;

    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(file_name)
        .mime_str("application/pdf")
        .map_err(|e| format!("Mime error: {}", e))?;

    let form = reqwest::multipart::Form::new().part("input", part);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://localhost:{}/api/processHeaderDocument", GROBID_PORT))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("GROBID request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("GROBID returned status {}", resp.status()));
    }

    let tei_xml = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read GROBID response: {}", e))?;

    Ok(parse_tei_header(&tei_xml))
}

/// Parse GROBID's TEI XML response to extract metadata.
/// Uses simple string parsing to avoid adding an XML dependency.
fn parse_tei_header(xml: &str) -> PaperMetadata {
    let mut meta = PaperMetadata::default();

    // Title: <title level="a" type="main">...</title>
    if let Some(start) = xml.find("<title level=\"a\" type=\"main\">") {
        let start = start + "<title level=\"a\" type=\"main\">".len();
        if let Some(end) = xml[start..].find("</title>") {
            meta.title = xml[start..start + end].trim().to_string();
        }
    }

    // Authors: <persName> elements within <analytic>
    let mut authors = Vec::new();
    let analytic_section = if let Some(start) = xml.find("<analytic>") {
        if let Some(end) = xml.find("</analytic>") {
            &xml[start..end]
        } else {
            ""
        }
    } else {
        ""
    };

    let mut search_from = 0;
    while let Some(start) = analytic_section[search_from..].find("<persName") {
        let abs_start = search_from + start;
        if let Some(end) = analytic_section[abs_start..].find("</persName>") {
            let person = &analytic_section[abs_start..abs_start + end + "</persName>".len()];

            let mut forename = String::new();
            let mut surname = String::new();

            // Extract forename
            if let Some(fs) = person.find("<forename") {
                if let Some(fe) = person[fs..].find('>') {
                    let after = fs + fe + 1;
                    if let Some(fend) = person[after..].find("</forename>") {
                        forename = person[after..after + fend].trim().to_string();
                    }
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
                if forename.is_empty() {
                    authors.push(surname);
                } else {
                    authors.push(format!("{}, {}", surname, forename));
                }
            }

            search_from = abs_start + end + "</persName>".len();
        } else {
            break;
        }
    }
    meta.authors = authors.join("; ");

    // DOI: <idno type="DOI">...</idno>
    if let Some(start) = xml.find("<idno type=\"DOI\">") {
        let start = start + "<idno type=\"DOI\">".len();
        if let Some(end) = xml[start..].find("</idno>") {
            meta.doi = xml[start..start + end].trim().to_string();
        }
    }

    // Year: <date type="published" when="2023"> or when="2023-01-15"
    if let Some(start) = xml.find("<date type=\"published\" when=\"") {
        let start = start + "<date type=\"published\" when=\"".len();
        if let Some(end) = xml[start..].find('"') {
            let date = &xml[start..start + end];
            // Extract just the year (first 4 chars)
            meta.year = date.chars().take(4).collect();
        }
    }

    // Clean up HTML entities
    meta.title = meta.title.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">");
    meta.authors = meta.authors.replace("&amp;", "&");

    meta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tei_header() {
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
        </author>
        <author>
        <persName><forename type="first">Jane</forename><surname>Doe</surname></persName>
        </author>
        <idno type="DOI">10.1234/example.2023</idno>
        </analytic>
        </biblStruct>
        </sourceDesc>
        </fileDesc>
        <profileDesc>
        <abstract/>
        </profileDesc>
        </teiHeader>
        </TEI>
        "#;

        let meta = parse_tei_header(xml);
        assert_eq!(meta.title, "Machine learning interatomic potentials");
        assert_eq!(meta.authors, "Smith, John; Doe, Jane");
        assert_eq!(meta.doi, "10.1234/example.2023");
    }
}
