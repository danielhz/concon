//! Markdown rendering for user-written text (discussion notes), producing
//! HTML that is safe to emit with `| safe` in a template.
//!
//! Notes are stored as the raw Markdown the author typed (`oa:hasBody` is a
//! plain literal); this module is the only place that turns such text into
//! HTML. A note gets a small set of styling constructs, not a way to build
//! page structure. The scope was fixed by Daniel (2026-10-20):
//!
//! | rendered | as |
//! |---|---|
//! | paragraphs, single newlines | `<p>`, `<br>` |
//! | `**bold**`, `*italics*`, `` `code` `` | `<strong>`, `<em>`, `<code>` |
//! | `[text](url)`, `<url>` | `<a href rel="noopener noreferrer nofollow">` |
//! | `> quote` — one level, inner quotes flattened | `<blockquote>` |
//! | fenced / indented code — no language class | `<pre><code>` |
//! | `- item`, `1. item` — one level, nested items flattened | `<ul>`/`<ol start>`/`<li>` |
//!
//! Everything else keeps its **content as plain text**: headings become
//! ordinary paragraphs; horizontal rules, tables, `~~strikethrough~~`, raw
//! HTML and images show as typed (the alt text for an image).
//!
//! Safety follows from how the output is built, in a single pass over the
//! `pulldown-cmark` event stream ([`RenderState::map`]):
//!
//! 1. Every `Start`/`End` tag not on the allow-list above is dropped (its
//!    content is kept), so the writer can only ever emit the tags listed.
//! 2. Raw HTML events become text, so nothing the author types is emitted
//!    as markup.
//! 3. Links are allow-listed and written by this module: a destination must
//!    have no control characters (browsers strip tab/newline, so
//!    `java\tscript:` would run) and, after trimming spaces, either no scheme
//!    (relative — so `#note-…` citations and `_view?iri=` links work) or
//!    `http`/`https`/`mailto`. `href`/`title` are escaped with the helpers
//!    pulldown uses for its own attributes.
//! 4. No parser option is enabled. Every option adds syntax whose output
//!    carries tags or attributes outside the inventory (heading `id`s,
//!    footnote anchors, task-list `<input>`, math spans, alert classes), so
//!    enabling one means re-auditing [`ALLOWED_TAGS`] and its test.
//!
//! The attribute inventory of the output is therefore: `href`, `rel`,
//! `title` on `a`; `start` on `ol`; nothing else. The tests enforce this on
//! a kitchen-sink note, on a hostile battery and on generated inputs, and
//! additionally check that an HTML sanitiser (`ammonia`, dev-dependency
//! only) finds nothing to remove in the output.
//!
//! There is no sanitiser pass at runtime on purpose: html5ever costs ~9–14
//! µs per entity or element and is superlinear on `&` (5k / 10k / 20k
//! `&amp;` took 118 ms / 327 ms / 1.07 s), which would make a 32 KiB note
//! cost seconds on **every** view. This pass is ~0.1 µs per byte. The POST
//! side caps note length at [`MAX_NOTE_BYTES`] so the per-view cost stays
//! bounded for inputs this module did not anticipate.
//!
//! The rendered string is marked `| safe` in the template, so **do not**
//! bypass this function to put note text into HTML.

use pulldown_cmark::{CodeBlockKind, CowStr, Event, LinkType, Options, Parser, Tag, TagEnd, html};
use pulldown_cmark_escape::{escape_href, escape_html};

/// Longest note accepted by the add-note POST, in bytes (32 KiB). Rendering
/// costs time on every view of the note's resource, so the input is bounded
/// independently of what the renderer guards against.
pub const MAX_NOTE_BYTES: usize = 32 * 1024;

/// The only HTML element names this module can emit. Kept as data so the
/// tests can check the output against it.
pub const ALLOWED_TAGS: [&str; 11] = [
    "p",
    "br",
    "strong",
    "em",
    "code",
    "pre",
    "a",
    "blockquote",
    "ul",
    "ol",
    "li",
];

/// `rel` written on every link: no `window.opener`, no referrer leak, and no
/// search-engine credit for whatever a note links to.
const LINK_REL: &str = "noopener noreferrer nofollow";

/// Render one note's Markdown to HTML that is safe to emit unescaped.
///
/// Single newlines become `<br>` (as in GitHub comments), so notes written
/// before Markdown support — short plain-text lines — keep their line breaks.
pub fn render_note_html(markdown: &str) -> String {
    // No options — see item 4 of the module doc before adding one.
    let options = Options::empty();
    let mut state = RenderState::default();
    let events = Parser::new_ext(markdown, options)
        .into_offset_iter()
        .filter_map(move |(ev, range)| state.map(ev, &markdown[range]));
    let mut out = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut out, events);
    out
}

/// Per-render state of the event filter: how deep we are in quotes and
/// lists (only level 1 is emitted) and how many enclosing links/images were
/// dropped (so their `End` events are dropped too).
#[derive(Default)]
struct RenderState {
    quote_depth: usize,
    list_depth: usize,
    dropped_links: usize,
    dropped_images: usize,
}

impl RenderState {
    /// The allow-list, in one place. `src` is the source slice the event
    /// came from, used when a construct is shown as typed.
    fn map<'a>(&mut self, ev: Event<'a>, src: &'a str) -> Option<Event<'a>> {
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
            Event::Start(tag) => match tag {
                Tag::Paragraph | Tag::Emphasis | Tag::Strong => Some(Event::Start(tag)),
                // Fenced blocks lose their info string (no `class`).
                Tag::CodeBlock(_) => Some(Event::Start(Tag::CodeBlock(CodeBlockKind::Indented))),
                // Headings and HTML blocks: content as an ordinary paragraph.
                Tag::Heading { .. } | Tag::HtmlBlock => Some(Event::Start(Tag::Paragraph)),
                Tag::BlockQuote(_) => {
                    self.quote_depth += 1;
                    (self.quote_depth == 1).then_some(Event::Start(Tag::BlockQuote(None)))
                }
                Tag::List(start) => {
                    self.list_depth += 1;
                    (self.list_depth == 1).then_some(Event::Start(Tag::List(start)))
                }
                // A nested item becomes a further line of the enclosing item.
                Tag::Item => Some(if self.list_depth <= 1 {
                    Event::Start(Tag::Item)
                } else {
                    Event::HardBreak
                }),
                Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    ..
                } => match link_html(link_type, &dest_url, &title) {
                    Some(open) => Some(Event::Html(CowStr::from(open))),
                    None => {
                        self.dropped_links += 1;
                        None
                    }
                },
                Tag::Image { .. } => {
                    self.dropped_images += 1;
                    None
                }
                // Tables, strikethrough, footnotes, definition lists,
                // metadata, super/subscript: not rendered, content kept.
                _ => None,
            },
            Event::End(end) => match end {
                TagEnd::Paragraph | TagEnd::Emphasis | TagEnd::Strong | TagEnd::CodeBlock => {
                    Some(Event::End(end))
                }
                TagEnd::Heading(_) | TagEnd::HtmlBlock => Some(Event::End(TagEnd::Paragraph)),
                TagEnd::BlockQuote(_) => {
                    let keep = self.quote_depth == 1;
                    self.quote_depth = self.quote_depth.saturating_sub(1);
                    keep.then_some(Event::End(TagEnd::BlockQuote(None)))
                }
                TagEnd::List(ordered) => {
                    let keep = self.list_depth == 1;
                    self.list_depth = self.list_depth.saturating_sub(1);
                    keep.then_some(Event::End(TagEnd::List(ordered)))
                }
                TagEnd::Item => (self.list_depth <= 1).then_some(Event::End(TagEnd::Item)),
                TagEnd::Link => {
                    if self.dropped_links > 0 {
                        self.dropped_links -= 1;
                        None
                    } else {
                        Some(Event::Html(CowStr::Borrowed("</a>")))
                    }
                }
                TagEnd::Image => {
                    self.dropped_images = self.dropped_images.saturating_sub(1);
                    None
                }
                _ => None,
            },
            Event::Text(_) | Event::Code(_) | Event::HardBreak => Some(ev),
            Event::SoftBreak => Some(Event::HardBreak),
            // Raw HTML is plain text.
            Event::Html(s) | Event::InlineHtml(s) => Some(Event::Text(s)),
            // A horizontal rule is shown as typed, in its own paragraph.
            Event::Rule => Some(Event::Html(CowStr::from(as_typed_paragraph(src)))),
            // Anything else (footnote references, task-list markers, math —
            // all behind options that are off) is shown as typed.
            _ => Some(Event::Text(CowStr::Borrowed(src))),
        }
    }
}

/// `<p>…</p>` holding the escaped source text of a block construct.
fn as_typed_paragraph(src: &str) -> String {
    let mut p = String::with_capacity(src.len() + 9);
    p.push_str("<p>");
    // Infallible for String; the helper's error type is for io writers.
    let _ = escape_html(&mut p, src.trim());
    p.push_str("</p>\n");
    p
}

/// The opening `<a …>` for a link, or `None` when the destination is not
/// allowed (the link text is then rendered without a link).
fn link_html(link_type: LinkType, dest: &str, title: &str) -> Option<String> {
    // Browsers strip leading/trailing space before parsing; check and emit
    // what they would actually see.
    let dest = dest.trim_matches(' ');
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
    if !title.is_empty() {
        open.push_str("\" title=\"");
        escape_html(&mut open, title).ok()?;
    }
    open.push_str("\" rel=\"");
    open.push_str(LINK_REL);
    open.push_str("\">");
    Some(open)
}

/// Whether a link destination may be emitted: no ASCII control characters,
/// and either no scheme (a relative URL) or one of `http`, `https`,
/// `mailto`.
fn link_allowed(dest: &str) -> bool {
    if dest.chars().any(|c| c.is_ascii_control()) {
        return false;
    }
    match url_scheme(dest) {
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

    /// A note exercising every construct the renderer knows about, allowed
    /// or not.
    const KITCHEN_SINK: &str = "# Heading\n\n\
        Para with **bold**, *em*, `code`, [a link](https://e.org/x?a=1&b=2 \"ti\\\"tle\"), \
        <https://auto.example>, <alice@example.org>, [rel](#note-1), [cite](/t/_ds/d/_view?iri=y).\n\
        Second line after a soft break.  \nHard break above.\n\n\
        > quoted\n> > nested quote\n> back\n\n\
        - one\n- two\n  - nested item\n    - deeper\n- three\n\n\
        3. a\n4. b\n\n\
        ```rust\nfn main() {}\n```\n\n\
        \x20\x20\x20\x20indented code\n\n\
        ---\n\n\
        | t | u |\n|---|---|\n| 1 | 2 |\n\n\
        ~~struck~~ text, ![img alt](https://evil.example/p.png) and <b onclick=\"x()\">raw</b>.\n\n\
        [bad](javascript:alert(1)) [data](data:text/html,x)";

    /// Every `<tag attr…>` in `html`: (name, attribute names), end tags
    /// excluded. The renderer never emits a raw `<` or `>` outside a tag
    /// (text and attributes are escaped), so a plain scan is exact.
    fn tag_inventory(html: &str) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for piece in html.split('<').skip(1) {
            let tag = piece.split('>').next().expect("tag closed");
            if tag.starts_with('/') {
                continue;
            }
            let name_end = tag.find(char::is_whitespace).unwrap_or(tag.len());
            let name = tag[..name_end].trim_end_matches('/').to_string();
            // Attributes are always `name="value"` with `"` escaped inside
            // the value, so walk them by quote pairs (a value may contain
            // spaces). Anything not in that shape is reported as an
            // attribute name so the allow-list check rejects it.
            let mut attrs = Vec::new();
            let mut rest = tag[name_end..].trim();
            while !rest.is_empty() && rest != "/" {
                let Some(eq) = rest.find('=') else {
                    attrs.push(rest.to_string());
                    break;
                };
                attrs.push(rest[..eq].trim().to_string());
                let value = &rest[eq + 1..];
                let close = value
                    .strip_prefix('"')
                    .and_then(|v| v.find('"'))
                    .expect("quoted attribute value");
                rest = value[close + 2..].trim();
            }
            out.push((name, attrs));
        }
        out
    }

    /// Every `href="…"` value in `html`.
    fn hrefs(html: &str) -> Vec<String> {
        html.split("href=\"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap_or("").to_string())
            .collect()
    }

    /// Assert the output uses only the allowed tags and attributes, and
    /// that every link destination passes the scheme allow-list.
    fn assert_inventory_ok(html: &str) {
        for href in hrefs(html) {
            assert!(link_allowed(&href), "href {href:?} in {html}");
        }
        for (name, attrs) in tag_inventory(html) {
            assert!(
                ALLOWED_TAGS.contains(&name.as_str()),
                "tag <{name}> in {html}"
            );
            let allowed: &[&str] = match name.as_str() {
                "a" => &["href", "rel", "title"],
                "ol" => &["start"],
                _ => &[],
            };
            for a in &attrs {
                assert!(
                    allowed.contains(&a.as_str()),
                    "attribute {a} on <{name}> in {html}"
                );
            }
        }
    }

    /// Assert an HTML sanitiser finds nothing to remove: `ammonia(html)` is
    /// `html` up to serialisation differences (`<br>` form, quote entities,
    /// nbsp), which are normalised on both sides.
    fn assert_sanitizer_fixed_point(html: &str) {
        let cleaned = ammonia::Builder::default()
            .link_rel(Some(LINK_REL))
            .clean(html)
            .to_string();
        let norm = |s: &str| {
            s.replace("<br />", "<br>")
                .replace("&quot;", "\"")
                .replace("&#x27;", "'")
                .replace("&#39;", "'")
                .replace("&nbsp;", "\u{a0}")
        };
        assert_eq!(
            norm(&cleaned),
            norm(html),
            "sanitiser changed the output.\n--- rendered:\n{html}\n--- sanitised:\n{cleaned}"
        );
    }

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
    fn kitchen_sink_uses_only_allowed_tags_and_attributes() {
        let html = render_note_html(KITCHEN_SINK);
        assert_inventory_ok(&html);
        assert_sanitizer_fixed_point(&html);
        // Every construct's content is still there.
        for text in [
            "Heading",
            "bold",
            "em",
            "code",
            "a link",
            "quoted",
            "nested quote",
            "back",
            "one",
            "nested item",
            "deeper",
            "three",
            "fn main() {}",
            "indented code",
            "---",
            "| t | u |",
            "~~struck~~",
            "img alt",
            "&lt;b onclick=",
            "bad",
            "data",
        ] {
            assert!(html.contains(text), "missing {text:?} in {html}");
        }
    }

    #[test]
    fn inline_styles_and_links_render() {
        let html = render_note_html(
            "See [AtomicConfiguration](https://example.org/_view?iri=x \"a title\") and `foo()` — **bold** *em*.",
        );
        assert!(
            html.contains(
                r#"<a href="https://example.org/_view?iri=x" title="a title" rel="noopener noreferrer nofollow">AtomicConfiguration</a>"#
            ),
            "{html}"
        );
        assert!(html.contains("<code>foo()</code>"));
        assert!(html.contains("<strong>bold</strong> <em>em</em>"));
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
    fn code_blocks_render_without_a_language_class() {
        let html = render_note_html("```sparql\nSELECT * WHERE { ?s ?p <x> }\n```");
        assert_eq!(
            html,
            "<pre><code>SELECT * WHERE { ?s ?p &lt;x&gt; }\n</code></pre>\n"
        );
        let html = render_note_html("```x\"onclick=\"evil()\nbody\n```");
        assert_eq!(html, "<pre><code>body\n</code></pre>\n");
        let html = render_note_html("    indented <b>\n");
        assert_eq!(html, "<pre><code>indented &lt;b&gt;\n</code></pre>\n");
    }

    #[test]
    fn quotes_are_one_level_flat() {
        let html = render_note_html("> a\n>\n> > b\n>\n> > > c\n>\n> d");
        assert_eq!(
            html,
            "<blockquote>\n<p>a</p>\n<p>b</p>\n<p>c</p>\n<p>d</p>\n</blockquote>\n"
        );
    }

    #[test]
    fn lists_are_one_level_flat() {
        let html = render_note_html("- a\n  - b\n    - c\n- d");
        assert_eq!(html.matches("<ul>").count(), 1, "{html}");
        assert_eq!(html.matches("</ul>").count(), 1, "{html}");
        // Nested items become further lines of the enclosing item.
        assert_eq!(
            html,
            "<ul>\n<li>a<br />\nb<br />\nc</li>\n<li>d</li>\n</ul>\n"
        );
        let html = render_note_html("3. a\n4. b");
        assert!(html.starts_with("<ol start=\"3\">"), "{html}");
        assert_inventory_ok(&html);
    }

    #[test]
    fn headings_rules_tables_strikethrough_are_text() {
        let html = render_note_html("# Title\n\nbody");
        assert_eq!(html, "<p>Title</p>\n<p>body</p>\n");
        let html = render_note_html("a\n\n---\n\nb\n\n* * *\n");
        assert_eq!(html, "<p>a</p>\n<p>---</p>\n<p>b</p>\n<p>* * *</p>\n");
        let html = render_note_html("| a | b |\n|---|---|\n| 1 | 2 |");
        assert!(!html.contains("<table"), "{html}");
        assert!(html.contains("| a | b |"), "{html}");
        let html = render_note_html("~~gone~~");
        assert_eq!(html, "<p>~~gone~~</p>\n");
    }

    /// Syntaxes behind parser options must stay literal; enabling an option
    /// would hand authors tags/attributes outside the inventory.
    #[test]
    fn option_gated_syntaxes_stay_literal() {
        let html = render_note_html(
            "# h {#note-abc .cls}\n\nref[^1]\n\n[^1]: foot\n\n- [ ] task\n\n$x$ and $$y$$\n\n> [!NOTE]\n> alert\n\nterm\n: definition\n\n---\ntitle: x\n---\n",
        );
        assert_inventory_ok(&html);
        assert!(!html.contains("id="), "{html}");
        assert!(!html.contains("<input"), "{html}");
        assert!(!html.contains("footnote"), "{html}");
        assert!(!html.contains("math"), "{html}");
        assert!(!html.contains("class="), "{html}");
        assert!(!html.contains("<sup"), "{html}");
        assert!(html.contains("{#note-abc .cls}"), "{html}");
        // `[^1]: foot` is an ordinary reference definition in CommonMark, so
        // `ref[^1]` is a plain (relative) link — no footnote markup.
        assert!(html.contains("<a href=\"foot\""), "{html}");
        assert!(html.contains("[ ] task"), "{html}");
        assert!(html.contains("[!NOTE]"), "{html}");
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
        assert_eq!(html, "<p>x y z w v</p>\n");
    }

    #[test]
    fn link_destinations_with_control_chars_entities_or_spaces() {
        // Entity-encoded scheme: the parser decodes it, then it is checked.
        let html = render_note_html("[a](&#106;avascript:alert(1)) [b](javascript&#58;alert(1))");
        assert!(!html.contains("<a "), "{html}");
        // Tab inside the scheme (browsers strip it) is refused outright.
        let html = render_note_html("[c](<java\tscript:alert(1)>) [d](<jav&#x09;ascript:x>)");
        assert!(!html.contains("<a "), "{html}");
        // Leading spaces: trimmed before the check and before emitting.
        let html = render_note_html("[e](<  javascript:alert(1)>) [f](<  https://ok.example>)");
        assert!(!html.contains("javascript"), "{html}");
        assert!(html.contains("href=\"https://ok.example\""), "{html}");
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
        assert_inventory_ok(&html);
    }

    #[test]
    fn raw_html_is_shown_as_escaped_text() {
        let html = render_note_html(
            "<script>alert(1)</script>hi <b onclick=\"evil()\">there</b> <a href=\"javascript:alert(1)\">x</a>",
        );
        assert_eq!(
            html,
            "<p>&lt;script&gt;alert(1)&lt;/script&gt;hi &lt;b onclick=\"evil()\"&gt;there&lt;/b&gt; &lt;a href=\"javascript:alert(1)\"&gt;x&lt;/a&gt;</p>\n"
        );
        let html = render_note_html("<div class=\"x\">\nblock\n</div>\n\nafter");
        assert!(html.starts_with("<p>&lt;div class="), "{html}");
        assert!(html.contains("<p>after</p>"), "{html}");
        // Container breakout attempt stays text.
        let html = render_note_html("</div></li></ul><script>x</script>");
        assert!(!html.contains("</li>"), "{html}");
        assert!(!html.contains("<script"), "{html}");
    }

    #[test]
    fn images_are_dropped_keeping_alt_text() {
        let html = render_note_html("![tracker](https://evil.example/px.gif) end");
        assert_eq!(html, "<p>tracker end</p>\n");
        // Image with a link inside its alt text: both dropped cleanly.
        let html = render_note_html("![see [x](https://a.org)](https://b.org/i.png) after");
        assert_eq!(html, "<p>see x after</p>\n");
    }

    #[test]
    fn angle_brackets_in_prose_are_escaped() {
        let html = render_note_html("a < b and <notatag> x");
        assert_eq!(html, "<p>a &lt; b and &lt;notatag&gt; x</p>\n");
    }

    /// Hostile battery: every output uses only the inventory and is a fixed
    /// point of the sanitiser oracle.
    #[test]
    fn hostile_battery_is_inventory_clean_and_sanitizer_fixed() {
        let battery = [
            KITCHEN_SINK,
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)><a xlink:href='javascript:x'>",
            "<iframe src=//evil.example></iframe><object data=x><embed src=y>",
            "<form action=/_update method=post><input autofocus onfocus=alert(1)><button>go</button></form>",
            "<style>body{display:none}</style><base href=//evil.example><meta http-equiv=refresh content=0>",
            "<!-- c --><?pi?><![CDATA[x]]><!DOCTYPE html>",
            "</div></li></ul></blockquote><script>x</script>",
            "[x](javascript:alert(1)) [y](JAVASCRIPT:x) [z](java\tscript:x) [w]( javascript:x) [v](&#106;avascript:x)",
            "[x](data:text/html;base64,PHNjcmlwdD4=) [y](vbscript:x) [z](file:///etc/passwd) [w](ftp://x)",
            "[x](https://e.org \"a\\\" onclick=\\\"x\") [y](<https://e.org/\"onclick=\"x>)",
            "<javascript:alert(1)> <JAVASCRIPT@x.y> <https://ok.example/?a=1&b=<x>>",
            "![a](javascript:alert(1)) ![b](https://x/i.png \"t\\\"\") [![c](https://x/i.png)](https://ok.example) ![[d](javascript:x)](https://x)",
            "[ref]: javascript:alert(1)\n\n[text][ref] [ref]",
            "[text][ref]\n\n[ref]: <java\tscript:x> \"t\"",
            "| a | <script>x</script> | [l](javascript:x) |\n|---|---|---|\n| 1 | 2 | 3 |",
            "# h {#note-abc .cls}\n\n- [x] task\n\n[^1]\n\n[^1]: f\n\n$x$\n\n> [!WARNING]\n> w",
            "```x\"><script>alert(1)</script>\nbody\n```",
            "~~~html\n<b>x</b>\n~~~",
            "> > > > > deep\n\n- - - - - deep\n\n1. 1. 1. deep",
            "- a\n  > q\n  - b\n    ```\n    c\n    ```\n- d",
            "> - a\n>   - b\n> > - c",
            "\\<script>x\\</script> &lt;script&gt; &#60;script&#62; &amp;lt;",
            "a\u{a0}b \u{200b} \u{ff1a} [x](java\u{a0}script:x) [y](\u{ff0a}javascript:x)",
            "**bold *nested em `code [link](https://x)`* **",
            "<a href=\"https://ok.example\" target=_blank ping=//evil.example rel=opener>x</a>",
            "<blockquote cite=\"javascript:x\">q</blockquote><q cite=\"javascript:y\">r</q>",
            "<details open ontoggle=alert(1)><summary>s</summary>d</details>",
            "<textarea><script>x</script></textarea><noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            "\"'`<>&/\\",
        ];
        for note in battery {
            let html = render_note_html(note);
            assert_inventory_ok(&html);
            assert_sanitizer_fixed_point(&html);
            // Tag-level checks; `javascript:` may still appear as escaped
            // text (that is "shown as typed"), never in an href (checked
            // by assert_inventory_ok).
            let lower = html.to_ascii_lowercase();
            assert!(!lower.contains("<script"), "{html}");
            assert!(!lower.contains("<img"), "{html}");
        }
    }

    /// Generated inputs: random concatenations of Markdown and hostile
    /// fragments (deterministic LCG, no extra dependency).
    #[test]
    fn generated_inputs_are_inventory_clean_and_sanitizer_fixed() {
        const FRAGMENTS: [&str; 40] = [
            "word ",
            "**b** ",
            "*i* ",
            "`c` ",
            "``c`d`` ",
            "[t](https://e.org) ",
            "[t](javascript:x) ",
            "[t](#note-1 \"ti\\\"tle\") ",
            "<https://a.example> ",
            "<x@y.z> ",
            "![a](https://x) ",
            "> ",
            "- ",
            "1. ",
            "  ",
            "\n",
            "\n\n",
            "<script>x</script>",
            "<b onclick=x>",
            "</li></ul>",
            "&amp;",
            "&",
            "<",
            ">",
            "\"",
            "'",
            "\\",
            "```\ncode\n```\n",
            "    indented\n",
            "---\n",
            "# h\n",
            "| a | b |\n",
            "~~s~~ ",
            "[ref]\n\n[ref]: javascript:x\n",
            "*",
            "_",
            "[",
            "](",
            "\t",
            "\u{a0}",
        ];
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        for _ in 0..400 {
            let n = 1 + next() % 40;
            let note: String = (0..n)
                .map(|_| FRAGMENTS[next() % FRAGMENTS.len()])
                .collect();
            let html = render_note_html(&note);
            assert_inventory_ok(&html);
            assert_sanitizer_fixed_point(&html);
        }
    }

    /// Worst-case inputs at the POST size cap must stay far below the
    /// seconds-scale cost an HTML-sanitiser pass used to have (module doc).
    /// The bound is generous: this is a debug-build regression guard that
    /// runs alongside the whole suite, not a benchmark.
    #[test]
    fn pathological_inputs_at_the_size_cap_are_fast() {
        let cap = MAX_NOTE_BYTES;
        let cases = [
            ("ampersands", "&".repeat(cap)),
            ("angle brackets", "<".repeat(cap)),
            ("div tags", "<div>".repeat(cap / 5)),
            ("quotes", "> ".repeat(cap / 2)),
            ("list items", "- a\n".repeat(cap / 4)),
            ("nested lists", "- ".repeat(cap / 2)),
            ("emphasis", "*a* ".repeat(cap / 4)),
            ("links", "[a](https://e.org) ".repeat(cap / 19)),
            ("bad links", "[a](javascript:x) ".repeat(cap / 18)),
            ("nested emphasis", "_*".repeat(cap / 2)),
            ("rules", "---\n\n".repeat(cap / 5)),
            ("brackets", "[".repeat(cap)),
        ];
        for (name, note) in cases {
            let started = std::time::Instant::now();
            let html = render_note_html(&note);
            let elapsed = started.elapsed();
            assert!(
                elapsed.as_millis() < 1000,
                "{name}: render took {elapsed:?}"
            );
            assert_inventory_ok(&html);
        }
    }
}
