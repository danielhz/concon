//! Test GROBID extraction against a local PDF file.
//! Usage: cargo run --bin test_grobid -- /path/to/paper.pdf [grobid_url]

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pdf_path = args.get(1).expect("Usage: test_grobid <pdf_path> [grobid_url]");
    let grobid_url = args.get(2).map(|s| s.as_str()).unwrap_or("http://localhost:8070");

    let path = std::path::Path::new(pdf_path);
    if !path.exists() {
        eprintln!("File not found: {}", pdf_path);
        std::process::exit(1);
    }

    println!("Extracting metadata from: {}", pdf_path);
    println!("GROBID URL: {}", grobid_url);
    println!();

    match concon::grobid::extract_metadata(path, grobid_url).await {
        Ok(meta) => {
            println!("Title:        {}", meta.title);
            println!("Authors:      {}", meta.authors);
            println!("Year:         {}", meta.year);
            println!("DOI:          {}", meta.doi);
            println!("Journal:      {}", meta.journal);
            println!("Volume:       {}", meta.volume);
            println!("Issue:        {}", meta.issue);
            println!("Pages:        {}", meta.pages);
            println!("Publisher:    {}", meta.publisher);
            println!("ISSN:         {}", meta.issn);
            println!("arXiv ID:     {}", meta.arxiv_id);
            println!("Keywords:     {}", meta.keywords);
            println!("Affiliations: {}", meta.affiliations);
            println!("Abstract:     {}...", &meta.abstract_text[..meta.abstract_text.len().min(200)]);
            println!("References:   {} DOIs", meta.references.len());
            for r in &meta.references {
                println!("  - {}", r);
            }
            println!("TEI XML:      {} bytes", meta.tei_xml.len());
        }
        Err(e) => {
            eprintln!("Extraction failed: {}", e);
            std::process::exit(1);
        }
    }
}
