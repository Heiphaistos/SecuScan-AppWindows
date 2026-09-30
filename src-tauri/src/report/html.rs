//! Rendu HTML autonome (un seul fichier, sans script) d'un `Doc`.
//!
//! Aucune ressource externe, aucun JavaScript : le rapport s'ouvre hors-ligne,
//! s'imprime proprement et ne peut rien exécuter même si une chaîne issue du
//! fichier analysé contient du HTML (tout est échappé).

use super::{Block, Cell, Doc, Tone};

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const CSS: &str = r#"
:root{--bg:#f4f6fb;--card:#fff;--text:#1d2330;--muted:#5b6474;--border:#dfe3ec;--code:#f1f3f8;--head:#0f172a;
--neutral:#64748b;--good:#16a34a;--info:#2563eb;--warn:#ca8a04;--danger:#ea580c;--critical:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b24;--text:#e6e9ef;--muted:#9aa3b2;--border:#2a3140;--code:#1e2430;--head:#05080f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:0 16px 40px}
header.top{background:var(--head);color:#fff;padding:22px 0 18px;margin-bottom:22px}
header.top .wrap{padding-bottom:0}
header.top .app{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#7dd3fc;font-weight:700}
header.top h1{margin:4px 0 2px;font-size:22px;line-height:1.3;word-break:break-word}
header.top .sub{color:#cbd5e1;font-size:13px;word-break:break-word}
h2{font-size:18px;margin:30px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--border)}
h3{font-size:15px;margin:20px 0 8px}
p{margin:0 0 10px}
.note{color:var(--muted);font-size:12.5px}
ul{margin:0 0 12px;padding-left:22px}li{margin:2px 0}
.kv{display:grid;grid-template-columns:minmax(120px,max-content) 1fr;gap:4px 16px;margin:0 0 14px;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.kv dt{color:var(--muted);font-weight:600}.kv dd{margin:0;word-break:break-word}
.mono,.kv.mono dd,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.callout{border:1px solid var(--border);border-left:6px solid var(--c);background:var(--card);border-radius:10px;padding:12px 16px;margin:0 0 16px}
.callout .t{font-weight:700;font-size:16px;color:var(--c);margin-bottom:4px}
.callout p{margin:4px 0}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 16px}
.stat{flex:1 1 130px;background:var(--card);border:1px solid var(--border);border-top:4px solid var(--c);border-radius:10px;padding:10px 14px}
.stat .v{font-size:24px;font-weight:800;color:var(--c)}.stat .l{color:var(--muted);font-size:12px}
.meter{margin:0 0 12px}.meter .lbl{display:flex;justify-content:space-between;font-weight:600;font-size:13px;margin-bottom:4px}
.meter .lbl b{color:var(--c)}
.track{height:10px;border-radius:99px;background:var(--border);overflow:hidden}.fill{height:100%;background:var(--c);border-radius:99px}
.tbl{overflow-x:auto;margin:0 0 16px;border:1px solid var(--border);border-radius:10px;background:var(--card)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;background:var(--code);padding:8px 10px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td{padding:8px 10px;border-top:1px solid var(--border);vertical-align:top;word-break:break-word}
td.t{font-weight:700;color:var(--c)}
pre{background:var(--code);border:1px solid var(--border);border-radius:8px;padding:10px 12px;overflow-x:auto;font-size:12px;line-height:1.45;margin:0 0 12px;white-space:pre-wrap;word-break:break-all}
.card{background:var(--card);border:1px solid var(--border);border-left:6px solid var(--c);border-radius:12px;padding:14px 16px 6px;margin:0 0 14px;break-inside:avoid}
.card>.h{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.card>.h .ti{font-weight:700;font-size:15px;flex:1 1 260px;word-break:break-word}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11.5px;font-weight:700;color:#fff;background:var(--c);white-space:nowrap}
.card h3{font-size:13px;margin:10px 0 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.neutral{--c:var(--neutral)}.good{--c:var(--good)}.info{--c:var(--info)}.warn{--c:var(--warn)}.danger{--c:var(--danger)}.critical{--c:var(--critical)}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:30px}
@media print{body{background:#fff}header.top{-webkit-print-color-adjust:exact;print-color-adjust:exact}.card,.callout,.stat,.fill,.badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}.tbl{overflow:visible}}
@media (max-width:600px){.kv{grid-template-columns:1fr}.kv dt{margin-top:6px}}
"#;

fn cell_html(c: &Cell) -> String {
    let body = if c.mono { format!("<code>{}</code>", esc(&c.text)) } else { esc(&c.text) };
    let body = body.replace('\n', "<br>");
    match c.tone {
        Some(t) => format!("<td class=\"t {}\">{body}</td>", t.css_class()),
        None => format!("<td>{body}</td>"),
    }
}

fn render_blocks(out: &mut String, blocks: &[Block], in_card: bool) {
    for b in blocks {
        render_block(out, b, in_card);
    }
}

fn render_block(out: &mut String, b: &Block, in_card: bool) {
    match b {
        Block::Heading(level, t) => {
            let tag = if *level <= 1 && !in_card { "h2" } else { "h3" };
            out.push_str(&format!("<{tag}>{}</{tag}>\n", esc(t)));
        }
        Block::Para(t) => out.push_str(&format!("<p>{}</p>\n", esc(t).replace('\n', "<br>"))),
        Block::Note(t) => out.push_str(&format!("<p class=\"note\">{}</p>\n", esc(t))),
        Block::Bullets(items) => {
            out.push_str("<ul>");
            for i in items {
                out.push_str(&format!("<li>{}</li>", esc(i).replace('\n', "<br>")));
            }
            out.push_str("</ul>\n");
        }
        Block::KeyValues { items, mono } => {
            out.push_str(&format!("<dl class=\"kv{}\">", if *mono { " mono" } else { "" }));
            for (k, v) in items {
                out.push_str(&format!("<dt>{}</dt><dd>{}</dd>", esc(k), esc(v).replace('\n', "<br>")));
            }
            out.push_str("</dl>\n");
        }
        Block::Callout { tone, title, lines } => {
            out.push_str(&format!(
                "<div class=\"callout {}\"><div class=\"t\">{}</div>",
                tone.css_class(),
                esc(title)
            ));
            for l in lines {
                out.push_str(&format!("<p>{}</p>", esc(l)));
            }
            out.push_str("</div>\n");
        }
        Block::Stats(items) => {
            out.push_str("<div class=\"stats\">");
            for (v, l, t) in items {
                out.push_str(&format!(
                    "<div class=\"stat {}\"><div class=\"v\">{}</div><div class=\"l\">{}</div></div>",
                    t.css_class(),
                    esc(v),
                    esc(l)
                ));
            }
            out.push_str("</div>\n");
        }
        Block::Meter { label, percent, tone } => {
            out.push_str(&format!(
                "<div class=\"meter {}\"><div class=\"lbl\"><span>{}</span><b>{} %</b></div>\
                 <div class=\"track\"><div class=\"fill\" style=\"width:{}%\"></div></div></div>\n",
                tone.css_class(),
                esc(label),
                percent,
                (*percent).min(100)
            ));
        }
        Block::Table { headers, rows, widths } => {
            let total: f32 = widths.iter().sum::<f32>().max(0.001);
            out.push_str("<div class=\"tbl\"><table><colgroup>");
            for i in 0..headers.len() {
                let w = widths.get(i).copied().unwrap_or(1.0) / total * 100.0;
                out.push_str(&format!("<col style=\"width:{w:.1}%\">"));
            }
            out.push_str("</colgroup><thead><tr>");
            for h in headers {
                out.push_str(&format!("<th>{}</th>", esc(h)));
            }
            out.push_str("</tr></thead><tbody>");
            for r in rows {
                out.push_str("<tr>");
                for c in r {
                    out.push_str(&cell_html(c));
                }
                out.push_str("</tr>");
            }
            out.push_str("</tbody></table></div>\n");
        }
        Block::Code(code) => out.push_str(&format!("<pre>{}</pre>\n", esc(code))),
        Block::Card { tone, title, badges, body } => {
            out.push_str(&format!(
                "<section class=\"card {}\"><div class=\"h\"><span class=\"ti\">{}</span>",
                tone.css_class(),
                esc(title)
            ));
            for b in badges {
                out.push_str(&format!("<span class=\"badge {}\">{}</span>", b.tone.css_class(), esc(&b.text)));
            }
            out.push_str("</div>\n");
            render_blocks(out, body, true);
            out.push_str("</section>\n");
        }
    }
}

pub fn render(doc: &Doc) -> String {
    let mut out = String::with_capacity(32 * 1024);
    out.push_str("<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    out.push_str("<meta name=\"color-scheme\" content=\"light dark\">\n");
    out.push_str(&format!("<title>{} — {}</title>\n<style>{CSS}</style>\n</head>\n<body>\n", esc(&doc.app), esc(&doc.title)));
    out.push_str(&format!(
        "<header class=\"top\"><div class=\"wrap\"><div class=\"app\">{}</div><h1>{}</h1><div class=\"sub\">{} · généré le {}</div></div></header>\n<main class=\"wrap\">\n",
        esc(&doc.app),
        esc(&doc.title),
        esc(&doc.subtitle),
        esc(&doc.generated_at)
    ));
    render_blocks(&mut out, &doc.blocks, false);
    out.push_str(&format!(
        "<footer>Rapport généré par {} — {}</footer>\n</main>\n</body>\n</html>\n",
        esc(&doc.app),
        esc(&doc.generated_at)
    ));
    out
}

/// Utilisé par les tests : une tonalité a bien sa classe CSS.
#[allow(dead_code)]
fn tone_has_css(t: Tone) -> bool {
    CSS.contains(&format!(".{}{{", t.css_class()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_doc;

    #[test]
    fn tout_est_echappe_et_sans_script() {
        let html = render(&sample_doc());
        assert!(!html.contains("<script"), "balise script présente");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<b>html</b>"));
        assert!(html.trim_end().ends_with("</html>"));
    }

    #[test]
    fn chaque_tonalite_a_son_style() {
        for t in [Tone::Neutral, Tone::Good, Tone::Info, Tone::Warn, Tone::Danger, Tone::Critical] {
            assert!(tone_has_css(t), "{t:?}");
        }
    }

    #[test]
    fn balises_equilibrees() {
        let html = render(&sample_doc());
        for tag in ["section", "table", "div", "dl", "ul", "pre", "p"] {
            let open = html.matches(&format!("<{tag}>")).count() + html.matches(&format!("<{tag} ")).count();
            let close = html.matches(&format!("</{tag}>")).count();
            assert_eq!(open, close, "balise <{tag}> déséquilibrée");
        }
    }
}
