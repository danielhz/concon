//! Markdown rendering for user-written text (discussion notes), with the
//! output sanitised before it reaches a template.
//!
//! Notes are stored as the raw Markdown the author typed (`oa:hasBody` is a
//! plain literal); this module is the only place that turns such text into
//! HTML. Two layers keep user content from becoming script:
//!
//! 1. `pulldown-cmark` parses CommonMark (+ tables, strikethrough). Raw HTML
//!    written in a note passes through the parser untouched, so it is **not**
//!    trusted on its own.
//! 2. `ammonia` sanitises the resulting HTML with an allow-list: no `script`,
//!    no event handlers, no `style`, link targets restricted to `http`,
//!    `https` and `mailto` (and same-site relative URLs), and every link gets
//!    `rel="noopener noreferrer nofollow"`. Images are stripped: a remote
//!    image in a note would let an author track who reads the page.
//!
//! The rendered string is marked `| safe` in the template, so **do not**
//! bypass this function to put note text into HTML.

use pulldown_cmark::{Event, Options, Parser, html};

/// Render one note's Markdown to sanitised HTML.
///
/// Single newlines become `<br>` (as in GitHub comments), so notes written
/// before Markdown support — short plain-text lines — keep their line breaks.
pub fn render_note_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(markdown, options).map(|ev| match ev {
        Event::SoftBreak => Event::HardBreak,
        other => other,
    });
    let mut raw = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut raw, parser);
    sanitize(&raw)
}

/// The allow-list pass. Kept separate so a test can feed it hand-written HTML
/// that the Markdown parser would never emit.
fn sanitize(raw_html: &str) -> String {
    ammonia::Builder::default()
        .rm_tags(["img"])
        .url_schemes(["http", "https", "mailto"].into_iter().collect())
        .link_rel(Some("noopener noreferrer nofollow"))
        .clean(raw_html)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_becomes_a_paragraph() {
        assert_eq!(render_note_html("hello world"), "<p>hello world</p>\n");
    }

    #[test]
    fn single_newlines_are_line_breaks() {
        // A pre-Markdown note with two short lines keeps its break.
        let html = render_note_html("line one\nline two");
        assert_eq!(html, "<p>line one<br>\nline two</p>\n");
    }

    #[test]
    fn links_code_and_emphasis_render() {
        let html = render_note_html(
            "See [AtomicConfiguration](https://example.org/_view?iri=x) and `foo()` — **bold**.",
        );
        assert!(html.contains(r#"<a href="https://example.org/_view?iri=x" rel="noopener noreferrer nofollow">AtomicConfiguration</a>"#), "{html}");
        assert!(html.contains("<code>foo()</code>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn fenced_code_blocks_render_escaped() {
        let html = render_note_html("```sparql\nSELECT * WHERE { ?s ?p <x> }\n```");
        assert!(html.starts_with("<pre><code>"), "{html}");
        assert!(
            html.contains("SELECT * WHERE { ?s ?p &lt;x&gt; }"),
            "{html}"
        );
        // The language class is dropped by the sanitiser; no `class` leaks.
        assert!(!html.contains("class="), "{html}");
    }

    #[test]
    fn relative_links_to_other_notes_survive() {
        let html =
            render_note_html("as [noted above](#note-abc) and [this term](/t/_ds/d/_view?iri=y)");
        assert!(html.contains(r##"href="#note-abc""##), "{html}");
        assert!(html.contains(r#"href="/t/_ds/d/_view?iri=y""#), "{html}");
    }

    #[test]
    fn script_and_event_handlers_are_stripped() {
        let html = render_note_html(
            "<script>alert(1)</script>hi <b onclick=\"evil()\">there</b> <a href=\"javascript:alert(1)\">x</a>",
        );
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("alert"), "{html}");
        assert!(!html.contains("onclick"), "{html}");
        assert!(!html.contains("javascript:"), "{html}");
        assert!(html.contains("<b>there</b>"), "{html}");
    }

    #[test]
    fn markdown_links_with_bad_schemes_are_neutralised() {
        let html = render_note_html("[x](javascript:alert(1)) [y](data:text/html,evil)");
        assert!(!html.contains("javascript:"), "{html}");
        assert!(!html.contains("data:"), "{html}");
    }

    #[test]
    fn images_and_inline_styles_are_stripped() {
        let html = render_note_html(
            "![tracker](https://evil.example/px.gif) <p style=\"color:red\">t</p>",
        );
        assert!(!html.contains("<img"), "{html}");
        assert!(!html.contains("style="), "{html}");
    }

    #[test]
    fn angle_brackets_in_prose_are_escaped() {
        let html = render_note_html("a < b and <notatag> x");
        assert!(html.contains("a &lt; b"), "{html}");
        assert!(!html.contains("<notatag>"), "{html}");
    }
}
