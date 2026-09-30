//! Rendu texte brut (UTF-8, 100 colonnes) d'un `Doc`.

use super::{strip_emoji, text_bar, Block, Doc, Tone};

const WIDTH: usize = 100;

fn tag(t: Tone) -> &'static str {
    match t {
        Tone::Neutral => "",
        Tone::Good => "[OK] ",
        Tone::Info => "[INFO] ",
        Tone::Warn => "[!] ",
        Tone::Danger => "[!!] ",
        Tone::Critical => "[!!!] ",
    }
}

/// Découpe `s` en lignes de `width` caractères max (coupe les mots trop longs).
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines = Vec::new();
    for para in s.split('\n') {
        let mut cur = String::new();
        let mut cur_len = 0usize;
        for word in para.split_whitespace() {
            let mut word: Vec<char> = word.chars().collect();
            // Mot plus long que la ligne (hash, URL) : coupe dure.
            while word.len() > width {
                if cur_len > 0 {
                    lines.push(std::mem::take(&mut cur));
                    cur_len = 0;
                }
                lines.push(word[..width].iter().collect());
                word = word[width..].to_vec();
            }
            let wl = word.len();
            if cur_len > 0 && cur_len + 1 + wl > width {
                lines.push(std::mem::take(&mut cur));
                cur_len = 0;
            }
            if cur_len > 0 {
                cur.push(' ');
                cur_len += 1;
            }
            cur.extend(word.iter());
            cur_len += wl;
        }
        lines.push(cur);
    }
    lines
}

fn push_wrapped(out: &mut String, s: &str, indent: &str, width: usize) {
    let avail = width.saturating_sub(indent.chars().count());
    for l in wrap(s, avail) {
        out.push_str(indent);
        out.push_str(&l);
        out.push('\n');
    }
}

fn pad(s: &str, n: usize) -> String {
    let len = s.chars().count();
    if len >= n {
        s.chars().take(n).collect()
    } else {
        format!("{s}{}", " ".repeat(n - len))
    }
}

fn render_blocks(out: &mut String, blocks: &[Block], indent: &str) {
    for b in blocks {
        render_block(out, b, indent);
    }
}

fn render_block(out: &mut String, b: &Block, indent: &str) {
    let width = WIDTH;
    match b {
        Block::Heading(1, t) => {
            let t = strip_emoji(t).to_uppercase();
            out.push('\n');
            out.push_str(&format!("{indent}{t}\n{indent}{}\n\n", "=".repeat(t.chars().count().min(width))));
        }
        Block::Heading(_, t) => {
            let t = strip_emoji(t);
            out.push_str(&format!("{indent}{t}\n{indent}{}\n", "-".repeat(t.chars().count().min(width))));
        }
        Block::Para(t) => {
            push_wrapped(out, t, indent, width);
            out.push('\n');
        }
        Block::Note(t) => {
            push_wrapped(out, &format!("Note : {t}"), indent, width);
            out.push('\n');
        }
        Block::Bullets(items) => {
            for i in items {
                let lines = wrap(i, width.saturating_sub(indent.len() + 4));
                for (n, l) in lines.iter().enumerate() {
                    out.push_str(&format!("{indent}{}{l}\n", if n == 0 { "  - " } else { "    " }));
                }
            }
            out.push('\n');
        }
        Block::KeyValues { items, .. } => {
            let kw = items.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0).min(28);
            for (k, v) in items {
                let lines = wrap(v, width.saturating_sub(indent.len() + kw + 3));
                for (n, l) in lines.iter().enumerate() {
                    let key = if n == 0 { pad(k, kw) } else { " ".repeat(kw) };
                    let sep = if n == 0 { " : " } else { "   " };
                    out.push_str(&format!("{indent}{key}{sep}{l}\n"));
                }
            }
            out.push('\n');
        }
        Block::Callout { tone, title, lines } => {
            let bar = "#".repeat(width.saturating_sub(indent.len()));
            out.push_str(&format!("{indent}{bar}\n"));
            push_wrapped(out, &format!("{}{}", tag(*tone), strip_emoji(title)), &format!("{indent}# "), width);
            for l in lines {
                push_wrapped(out, l, &format!("{indent}#   "), width);
            }
            out.push_str(&format!("{indent}{bar}\n\n"));
        }
        Block::Stats(items) => {
            for (v, l, t) in items {
                out.push_str(&format!("{indent}  {}{} : {}\n", tag(*t), l, v));
            }
            out.push('\n');
        }
        Block::Meter { label, percent, tone } => {
            // « libellé : NN % [barre] » ; le libellé passe à la ligne si besoin.
            let tail = format!(" : {:>3} % [{}]", percent, text_bar(*percent, 30, '#', '-'));
            let head = format!("{}{}", tag(*tone), label);
            let room = width.saturating_sub(indent.chars().count() + tail.chars().count());
            let mut lines = wrap(&head, room.max(20));
            let last = lines.pop().unwrap_or_default();
            for l in lines {
                out.push_str(&format!("{indent}{l}\n"));
            }
            out.push_str(&format!("{indent}{last}{tail}\n\n"));
        }
        Block::Table { headers, rows, widths } => {
            let avail = width.saturating_sub(indent.len() + 1 + 3 * headers.len());
            let total: f32 = widths.iter().sum::<f32>().max(0.001);
            let cols: Vec<usize> = (0..headers.len())
                .map(|i| ((widths.get(i).copied().unwrap_or(1.0) / total) * avail as f32).floor().max(4.0) as usize)
                .collect();
            let sep: String = format!(
                "{indent}+{}\n",
                cols.iter().map(|w| format!("{}+", "-".repeat(w + 2))).collect::<String>()
            );
            let render_row = |out: &mut String, cells: Vec<String>| {
                let wrapped: Vec<Vec<String>> =
                    cells.iter().enumerate().map(|(i, c)| wrap(c, cols[i])).collect();
                let h = wrapped.iter().map(Vec::len).max().unwrap_or(1);
                for line in 0..h {
                    out.push_str(indent);
                    out.push('|');
                    for (i, w) in wrapped.iter().enumerate() {
                        let txt = w.get(line).map(String::as_str).unwrap_or("");
                        out.push_str(&format!(" {} |", pad(txt, cols[i])));
                    }
                    out.push('\n');
                }
            };
            out.push_str(&sep);
            render_row(out, headers.clone());
            out.push_str(&sep.replace('-', "="));
            for r in rows {
                render_row(out, r.iter().map(|c| c.text.clone()).collect());
                out.push_str(&sep);
            }
            out.push('\n');
        }
        Block::Code(code) => {
            for l in code.lines() {
                let l = l.replace('\t', "    ");
                push_wrapped_raw(out, &l, &format!("{indent}  | "), width);
            }
            out.push('\n');
        }
        Block::Card { tone, title, badges, body } => {
            let badges: Vec<String> = badges.iter().map(|b| format!("[{}]", b.text)).collect();
            let head = format!("{}{} {}", tag(*tone), strip_emoji(title), badges.join(" "));
            out.push_str(&format!("{indent}{}\n", "-".repeat(width.saturating_sub(indent.len()))));
            push_wrapped(out, &head, &format!("{indent}>> "), width);
            out.push('\n');
            render_blocks(out, body, &format!("{indent}   "));
        }
    }
}

/// Coupe une ligne de code sans toucher aux espaces (indentation conservée).
fn push_wrapped_raw(out: &mut String, s: &str, indent: &str, width: usize) {
    let avail = width.saturating_sub(indent.chars().count()).max(8);
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        out.push_str(indent.trim_end());
        out.push('\n');
        return;
    }
    for chunk in chars.chunks(avail) {
        out.push_str(indent);
        out.extend(chunk.iter());
        out.push('\n');
    }
}

pub fn render(doc: &Doc) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let rule = "=".repeat(WIDTH);
    out.push_str(&rule);
    out.push('\n');
    push_wrapped(&mut out, &format!("{} — {}", doc.app.to_uppercase(), doc.title), "", WIDTH);
    push_wrapped(&mut out, &doc.subtitle, "", WIDTH);
    out.push_str(&format!("Généré le {}\n", doc.generated_at));
    out.push_str(&rule);
    out.push_str("\n\n");
    render_blocks(&mut out, &doc.blocks, "");
    out.push_str(&rule);
    out.push_str(&format!("\nRapport généré par {} — {}\n", doc.app, doc.generated_at));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_doc;

    #[test]
    fn aucune_ligne_ne_depasse_la_largeur() {
        let txt = render(&sample_doc());
        for l in txt.lines() {
            assert!(l.chars().count() <= WIDTH, "ligne trop longue ({}) : {l}", l.chars().count());
        }
        assert!(txt.contains("éàçù"));
    }

    #[test]
    fn wrap_coupe_les_mots_longs() {
        let w = wrap(&"x".repeat(25), 10);
        assert_eq!(w, vec!["x".repeat(10), "x".repeat(10), "x".repeat(5)]);
    }
}
