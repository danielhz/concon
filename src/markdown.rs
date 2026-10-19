//! Markdown rendering for user-written text (discussion notes), producing
//! HTML that is safe to emit with `| safe` in a template.
//!
//! Notes are stored as the raw Markdown the author typed (`oa:hasBody` is a
//! plain literal); this module is the only place that turns such text into
//! HTML. The output is built from a single pass over the `pulldown-cmark`
//! event stream, and safety comes from what that stream is allowed to carry:
//!
//! 1. **Raw HTML is demoted to text.** Any `<tag>` the author types is shown
//!    escaped, as typed. The feature needs links, code and citations, not
//!    hand-written markup, and this removes the whole raw-HTML surface: no
//!    `script`, no event handlers, no `style`, no forms, nothing to sanitise.
//! 2. **Links are allow-listed and written by this module.** A link survives
//!    only if its destination has no control characters and its scheme is
//!    `http`, `https` or `mailto` (or it is relative, so `#note-…` citations
//!    and `_view?iri=` links work); otherwise only the link text remains.
//!    Every surviving link is written as `<a href="…" rel="noopener
//!    noreferrer nofollow">` with the destination percent-escaped.
//! 3. **Images are dropped** (their alt text stays as plain text): a remote
//!    image in a note would let an author track who reads the page.
//! 4. **Nesting is capped** at [`MAX_NESTING`]: deeper container tags are
//!    dropped and their content rendered flat, so a `> > > …` note cannot
//!    build an arbitrarily deep DOM.
//!
//! Everything else the HTML writer emits is either escaped text or a fixed
//! tag from the parser (paragraphs, emphasis, code, lists, quotes, tables
//! with an enum-derived `text-align`), with no author-controlled attribute
//! other than the escaped `class="language-…"` on fenced code.
//!
//! **Why no HTML-sanitiser library.** An earlier revision passed the output
//! through `ammonia`. Its html5ever front end costs ~9–14 µs per entity or
//! element and is superlinear on `&`: 5k / 10k / 20k `&amp;` took 118 ms /
//! 327 ms / 1.07 s, so a note of ampersands at the 32 KiB cap would cost
//! ~2.5 s on **every** view of its resource. The parser pass is ~0.1 µs per
//! byte. Since (1) keeps raw markup out of the stream, a second parse of the
//! generated HTML added only that cost, not safety.
//!
//! The rendered string is marked `| safe` in the template, so **do not**
//! bypass this function to put note text into HTML. The POST side caps note
//! length at [`MAX_NOTE_BYTES`] so the per-view cost stays bounded for
//! inputs this module did not anticipate.

use pulldown_cmark::{CowStr, Event, LinkType, Options, Parser, Tag, TagEnd, html};
use pulldown_cmark_escape::{escape_href, escape_html};

/// Deepest container nesting that is rendered as nested HTML. Beyond this,
/// container start/end tags are dropped and only their content is emitted.
/// Sixteen levels is far more than any real note uses.
pub const MAX_NESTING: usize = 16;

/// Longest note accepted by the add-note POST, in bytes (32 KiB). Rendering
/// costs time on every view of the note's resource, so the input is bounded
/// independently of what the renderer guards against.
pub const MAX_NOTE_BYTES: usize = 32 * 1024;

/// `rel` written on every link: no `window.opener`, no referrer leak, and no
/// search-engine credit for whatever a note links to.
const LINK_REL: &str = "noopener noreferrer nofollow";

/// Render one note's Markdown to HTML that is safe to emit unescaped.
///
/// Single newlines become `<br>` (as in GitHub comments), so notes written
/// before Markdown support — short plain-text lines — keep their line breaks.
pub fn render_note_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let mut state = RenderState::default();
    let events = Parser::new_ext(markdown, options).filter_map(move |ev| state.map(ev));
    let mut out = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut out, events);
    out
}

/// Per-render state of the event filter: the current container depth (for
/// the nesting cap) and how many enclosing links/images were dropped (so
/// their `End` events are dropped too).
#[derive(Default)]
struct RenderState {
    depth: usize,
    dropped_links: usize,
    dropped_images: usize,
}

impl RenderState {
    fn map<'a>(&mut self, ev: Event<'a>) -> Option<Event<'a>> {
        if self.dropped_images > 0 {
            // Inside a dropped image only its alt text survives, as plain
            // text — the same flattening pulldown applies to an `alt`.
            return match ev {
                Event::Start(Tag::Image { .. }) => {
                    self.dropped_images += 1;
                    None
                }
                Event::End(TagEnd::Image) => {
                    self.dropped_images -= 1;
                    None
                }
                Event::Text(t) | Event::Code(t) | Event::Html(t) | Event::InlineHtml(t) => {
                    Some(Event::Text(t))
                }
                Event::SoftBreak | Event::HardBreak | Event::Rule => {
                    Some(Event::Text(CowStr::Borrowed(" ")))
                }
                _ => None,
            };
        }
        match ev {
            Event::SoftBreak => Some(Event::HardBreak),
            // (1) Raw HTML is plain text; an HTML block becomes a paragraph
            // so the escaped text still sits in a `<p>`.
            Event::Html(s) | Event::InlineHtml(s) => Some(Event::Text(s)),
            Event::Start(Tag::HtmlBlock) => self.depth_capped(Event::Start(Tag::Paragraph)),
            Event::End(TagEnd::HtmlBlock) => self.depth_capped(Event::End(TagEnd::Paragraph)),
            // (2) Links: allow-listed scheme, written here with the fixed rel.
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                ..
            }) => match link_html(link_type, &dest_url, &title) {
                Some(open) => self.depth_capped(Event::Html(CowStr::from(open))),
                None => {
                    self.dropped_links += 1;
                    None
                }
            },
            Event::End(TagEnd::Link) => {
                if self.dropped_links > 0 {
                    self.dropped_links -= 1;
                    None
                } else {
                    self.depth_capped(Event::Html(CowStr::from("</a>")))
                }
            }
            // (3) Images are dropped; the alt-text events render as text.
            Event::Start(Tag::Image { .. }) => {
                self.dropped_images += 1;
                None
            }
            Event::End(TagEnd::Image) => {
                self.dropped_images = self.dropped_images.saturating_sub(1);
                None
            }
            // (4) Every other Start/End pair counts toward the depth cap.
            ev @ (Event::Start(_) | Event::End(_)) => self.depth_capped(ev),
            other => Some(other),
        }
    }

    /// Track nesting depth and drop the event when it opens (or closes) a
    /// container deeper than [`MAX_NESTING`]. Start/End events are balanced,
    /// so the same counter tells an `End` whether its `Start` was dropped.
    /// A synthetic `Html` event stands in for a link's Start/End.
    fn depth_capped<'a>(&mut self, ev: Event<'a>) -> Option<Event<'a>> {
        let is_end = matches!(ev, Event::End(_) | Event::Html(CowStr::Borrowed("</a>")));
        if is_end {
            let keep = self.depth <= MAX_NESTING;
            self.depth = self.depth.saturating_sub(1);
            keep.then_some(ev)
        } else {
            self.depth += 1;
            (self.depth <= MAX_NESTING).then_some(ev)
        }
    }
}

/// The opening `<a …>` for a link, or `None` when the destination is not
/// allowed (the link text is then rendered without a link).
fn link_html(link_type: LinkType, dest: &str, title: &str) -> Option<String> {
    let href: CowStr = if link_type == LinkType::Email {
        // `<user@example.org>` autolinks carry the bare address.
        format!("mailto:{dest}").into()
    } else {
        dest.into()
    };
    if !link_allowed(&href) {
        return None;
    }
    let mut open = String::with_capacity(href.len() + 64);
    open.push_str("<a href=\"");
    escape_href(&mut open, &href).ok()?;
    open.push_str("\" rel=\"");
    open.push_str(LINK_REL);
    if !title.is_empty() {
        open.push_str("\" title=\"");
        escape_html(&mut open, title).ok()?;
    }
    open.push_str("\">");
    Some(open)
}

/// Whether a link destination may be emitted: no ASCII control characters
/// (browsers strip tabs/newlines, so `java\tscript:` would run), and — after
/// trimming spaces — either no scheme (a relative URL) or one of `http`,
/// `https`, `mailto`.
fn link_allowed(dest: &str) -> bool {
    if dest.chars().any(|c| c.is_ascii_control()) {
        return false;
    }
    // Browsers strip leading/trailing space before parsing, so check the
    // scheme of what they would actually see.
    match url_scheme(dest.trim_matches(' ')) {
        None => true,
        Some(scheme) => {
            let s = scheme.to_ascii_lowercase();
            s == "http" || s == "https" || s == "mailto"
        }
    }
}

/// The scheme of `dest` (`[A-Za-z][A-Za-z0-9+.-]*` before the first `:`), or
/// `None` when the string does not start with one — a relative reference.
fn url_scheme(dest: &str) -> Option<&str> {
    let mut chars = dest.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    for (i, c) in chars {
        match c {
            ':' => return Some(&dest[..i]),
            c if c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-') => {}
            _ => return None,
        }
    }
    None
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
        assert_eq!(html, "<p>line one<br />\nline two</p>\n");
    }

    #[test]
    fn links_code_and_emphasis_render() {
        let html = render_note_html(
            "See [AtomicConfiguration](https://example.org/_view?iri=x \"a title\") and `foo()` — **bold**.",
        );
        assert!(
            html.contains(
                r#"<a href="https://example.org/_view?iri=x" rel="noopener noreferrer nofollow" title="a title">AtomicConfiguration</a>"#
            ),
            "{html}"
        );
        assert!(html.contains("<code>foo()</code>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn autolinks_and_email_autolinks() {
        let html = render_note_html("<https://example.org/a?b=c&d=e> <alice@example.org>");
        assert!(
            html.contains(r#"<a href="https://example.org/a?b=c&amp;d=e" rel="#),
            "{html}"
        );
        assert!(
            html.contains(r#"<a href="mailto:alice@example.org" rel="#),
            "{html}"
        );
        let html = render_note_html("<javascript:alert(1)>");
        assert!(!html.contains("<a "), "{html}");
        assert!(html.contains("javascript:alert(1)"), "{html}");
    }

    #[test]
    fn fenced_code_blocks_render_escaped() {
        let html = render_note_html("```sparql\nSELECT * WHERE { ?s ?p <x> }\n```");
        assert!(
            html.starts_with("<pre><code class=\"language-sparql\">"),
            "{html}"
        );
        assert!(
            html.contains("SELECT * WHERE { ?s ?p &lt;x&gt; }"),
            "{html}"
        );
        // The language class is escaped text from the fence info string.
        let html = render_note_html("```x\"onclick=\"evil()\nbody\n```");
        assert!(!html.contains("onclick=\"evil"), "{html}");
        assert!(
            html.contains("class=\"language-x&quot;onclick=&quot;evil()\""),
            "{html}"
        );
    }

    #[test]
    fn relative_links_to_other_notes_survive() {
        let html =
            render_note_html("as [noted above](#note-abc) and [this term](/t/_ds/d/_view?iri=y)");
        assert!(html.contains(r##"href="#note-abc""##), "{html}");
        assert!(html.contains(r#"href="/t/_ds/d/_view?iri=y""#), "{html}");
    }

    #[test]
    fn link_text_with_bad_schemes_keeps_text_only() {
        let html = render_note_html(
            "[x](javascript:alert(1)) [y](data:text/html,evil) [z](JaVaScRiPt:alert(2)) [w](vbscript:x) [v](file:///etc/passwd)",
        );
        assert!(!html.contains("<a "), "{html}");
        assert!(!html.to_ascii_lowercase().contains("javascript:"), "{html}");
        assert!(!html.contains("data:"), "{html}");
        assert_eq!(html, "<p>x y z w v</p>\n");
    }

    #[test]
    fn link_destinations_with_control_chars_or_entities_are_rejected() {
        // Entity-encoded scheme: the parser decodes it, then it is checked.
        let html = render_note_html("[a](&#106;avascript:alert(1)) [b](javascript&#58;alert(1))");
        assert!(!html.contains("<a "), "{html}");
        // Tab/newline inside the scheme (browsers strip them): `<…>` form
        // permits spaces but the control char must still be refused.
        let html = render_note_html("[c](<java\tscript:alert(1)>) [d](<jav&#x09;ascript:x>)");
        assert!(!html.contains("<a "), "{html}");
        // Leading whitespace before the scheme.
        let html = render_note_html("[e](<  javascript:alert(1)>)");
        assert!(!html.contains("<a "), "{html}");
    }

    #[test]
    fn link_title_and_href_cannot_break_out_of_the_attribute() {
        let html = render_note_html("[t](<https://e.org/x\"onclick=\"evil()> \"ti\\\"tle\")");
        assert!(!html.contains("onclick=\"evil"), "{html}");
        assert!(
            html.contains("href=\"https://e.org/x%22onclick=%22evil()\""),
            "{html}"
        );
        assert!(html.contains("title=\"ti&quot;tle\""), "{html}");
    }

    #[test]
    fn raw_html_is_shown_as_escaped_text() {
        let html = render_note_html(
            "<script>alert(1)</script>hi <b onclick=\"evil()\">there</b> <a href=\"javascript:alert(1)\">x</a>",
        );
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("<b"), "{html}");
        assert!(!html.contains("<a "), "{html}");
        // The author's tags are visible as typed, escaped.
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;hi"),
            "{html}"
        );
        assert!(html.contains("&lt;b onclick="), "{html}");
    }

    #[test]
    fn html_blocks_become_escaped_paragraphs() {
        let html = render_note_html("<div class=\"x\">\nblock\n</div>\n\nafter");
        assert!(html.starts_with("<p>&lt;div class="), "{html}");
        assert!(!html.contains("<div"), "{html}");
        assert!(html.contains("<p>after</p>"), "{html}");
        // Container breakout attempt stays text.
        let html = render_note_html("</div></li></ul><script>x</script>");
        assert!(!html.contains("</li>"), "{html}");
        assert!(!html.contains("<script"), "{html}");
    }

    #[test]
    fn images_are_dropped_keeping_alt_text() {
        let html = render_note_html(
            "![tracker](https://evil.example/px.gif) <p style=\"color:red\">t</p>",
        );
        assert!(!html.contains("<img"), "{html}");
        assert!(!html.contains("evil.example"), "{html}");
        assert!(html.contains("tracker"), "{html}");
        // The raw `<p style>` is shown escaped, never as a styled element.
        assert!(!html.contains("<p style"), "{html}");
        assert!(html.contains("&lt;p style="), "{html}");
        // Image with a link inside its alt text: both dropped cleanly.
        let html = render_note_html("![see [x](https://a.org)](https://b.org/i.png) after");
        assert!(!html.contains("<img"), "{html}");
        assert_eq!(html, "<p>see x after</p>\n");
    }

    #[test]
    fn angle_brackets_in_prose_are_escaped() {
        let html = render_note_html("a < b and <notatag> x");
        assert!(html.contains("a &lt; b"), "{html}");
        assert!(!html.contains("<notatag>"), "{html}");
    }

    #[test]
    fn tables_keep_enum_alignment_only() {
        let html = render_note_html("| a | b |\n|:--|--:|\n| 1 | 2 |");
        assert!(
            html.contains("<th style=\"text-align: left\">a</th>"),
            "{html}"
        );
        assert!(
            html.contains("<td style=\"text-align: right\">2</td>"),
            "{html}"
        );
    }

    #[test]
    fn deep_blockquote_nesting_is_capped_and_fast() {
        let note = format!("{}deep", "> ".repeat(10_000));
        let started = std::time::Instant::now();
        let html = render_note_html(&note);
        let elapsed = started.elapsed();
        assert!(html.contains("deep"), "{html}");
        assert_eq!(html.matches("<blockquote>").count(), MAX_NESTING);
        assert_eq!(html.matches("</blockquote>").count(), MAX_NESTING);
        assert!(elapsed.as_millis() < 100, "render took {elapsed:?}");
    }

    #[test]
    fn nesting_within_the_cap_is_preserved() {
        let html = render_note_html("> a\n> > b\n> > > c");
        assert_eq!(html.matches("<blockquote>").count(), 3, "{html}");
        let html = render_note_html("- a\n  - b\n    - c");
        assert_eq!(html.matches("<ul>").count(), 3, "{html}");
    }

    #[test]
    fn links_beyond_the_cap_are_dropped_in_balance() {
        // 20 nested quotes, then a link: the link's open/close are both
        // dropped (depth > cap), the text stays, output is balanced.
        let note = format!("{}[t](https://e.org)", "> ".repeat(20));
        let html = render_note_html(&note);
        assert_eq!(html.matches("<a ").count(), html.matches("</a>").count());
        assert!(html.contains("t"), "{html}");
    }

    /// Worst-case inputs at the POST size cap must render in well under the
    /// time an HTML-sanitiser pass used to take (see the module doc).
    #[test]
    fn pathological_inputs_at_the_size_cap_are_fast() {
        let cap = MAX_NOTE_BYTES;
        let cases = [
            ("ampersands", "&".repeat(cap)),
            ("angle brackets", "<".repeat(cap)),
            ("div tags", "<div>".repeat(cap / 5)),
            ("quotes", "> ".repeat(cap / 2)),
            ("list items", "- a\n".repeat(cap / 4)),
            ("emphasis", "*a* ".repeat(cap / 4)),
            ("links", "[a](https://e.org) ".repeat(cap / 19)),
            ("bad links", "[a](javascript:x) ".repeat(cap / 18)),
            ("nested emphasis", "_*".repeat(cap / 2)),
        ];
        for (name, note) in cases {
            let started = std::time::Instant::now();
            let html = render_note_html(&note);
            let elapsed = started.elapsed();
            assert!(elapsed.as_millis() < 100, "{name}: render took {elapsed:?}");
            assert!(!html.contains("<div"), "{name}");
            assert!(!html.contains("javascript:"), "{name}");
        }
    }
}
