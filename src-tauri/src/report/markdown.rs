//! Rendu Markdown (CommonMark / GitHub) d'un `Doc`.
//!
//! Tout texte issu du fichier analysé est échappé : un nom de règle ou une URL
//! piégée ne doit ni casser un tableau (`|`), ni injecter du HTML brut (`<`).

use super::{text_bar, Block, Cell, Doc, Tone};

/// Échappe les caractères qui ont un sens en Markdown inline.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '~' => {
                out.push('\\');
                out.push(c);
            }
            '\r' => {}
            '\n' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Texte d'une cellule de tableau : une seule ligne Markdown, sauts de ligne en `<br>`.
fn cell_text(c: &Cell) -> String {
    let body = multiline(&c.text, c.mono);
    match c.tone {
        Some(Tone::Critical | Tone::Danger) => format!("**{body}**"),
        _ => body,
    }
}

/// Valeur multi-ligne dans une cellule : chaque ligne échappée, jointes par `<br>`
/// (seule balise HTML émise, reconnue par GitHub/GitLab dans les tableaux).
fn multiline(s: &str, mono: bool) -> String {
    s.split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .map(|l| if mono { code_span(l) } else { esc(l) })
        .collect::<Vec<_>>()
        .join("<br>")
}

/// Code inline sûr : la clôture est plus longue que toute suite de backticks du texte.
fn code_span(s: &str) -> String {
    let longest = longest_run(s, '`');
    let fence = "`".repeat(longest + 1);
    // Dans un tableau GFM, `|` coupe la cellule même dans du code.
    let s = s.replace('|', "\\|");
    if longest > 0 || s.starts_with('`') || s.ends_with('`') {
        format!("{fence} {s} {fence}")
    } else {
        format!("{fence}{s}{fence}")
    }
}

fn longest_run(s: &str, ch: char) -> usize {
    let (mut best, mut cur) = (0, 0);
    for c in s.chars() {
        if c == ch {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn render_blocks(out: &mut String, blocks: &[Block], depth: usize) {
    for b in blocks {
        render_block(out, b, depth);
    }
}

fn render_block(out: &mut String, b: &Block, depth: usize) {
    match b {
        Block::Heading(level, t) => {
            let lvl = (*level as usize + 1 + depth).min(6);
            out.push_str(&format!("{} {}\n\n", "#".repeat(lvl), esc(t)));
        }
        Block::Para(t) => out.push_str(&format!("{}\n\n", esc(t))),
        Block::Note(t) => out.push_str(&format!("*{}*\n\n", esc(t))),
        Block::Bullets(items) => {
            for i in items {
                out.push_str(&format!("- {}\n", esc(i)));
            }
            out.push('\n');
        }
        Block::KeyValues { items, mono } => {
            out.push_str("| | |\n|---|---|\n");
            for (k, v) in items {
                let v = multiline(v, *mono);
                out.push_str(&format!("| **{}** | {} |\n", esc(k), v));
            }
            out.push('\n');
        }
        Block::Callout { tone, title, lines } => {
            out.push_str(&format!("> {} **{}**\n", tone.marker(), esc(&super::strip_emoji(title))));
            for l in lines {
                out.push_str(&format!(">\n> {}\n", esc(l)));
            }
            out.push('\n');
        }
        Block::Stats(items) => {
            let head: Vec<String> = items.iter().map(|(_, l, _)| esc(l)).collect();
            let vals: Vec<String> = items.iter().map(|(v, _, t)| format!("{} **{}**", t.marker(), esc(v))).collect();
            out.push_str(&format!("| {} |\n", head.join(" | ")));
            out.push_str(&format!("|{}\n", "---|".repeat(items.len())));
            out.push_str(&format!("| {} |\n\n", vals.join(" | ")));
        }
        Block::Meter { label, percent, tone } => {
            out.push_str(&format!(
                "{} **{} : {} %** `{}`\n\n",
                tone.marker(),
                esc(label),
                percent,
                text_bar(*percent, 20, '█', '░')
            ));
        }
        Block::Table { headers, rows, .. } => {
            let head: Vec<String> = headers.iter().map(|h| esc(h)).collect();
            out.push_str(&format!("| {} |\n", head.join(" | ")));
            out.push_str(&format!("|{}\n", "---|".repeat(headers.len())));
            for r in rows {
                let cells: Vec<String> = r.iter().map(cell_text).collect();
                out.push_str(&format!("| {} |\n", cells.join(" | ")));
            }
            out.push('\n');
        }
        Block::Code(code) => {
            let fence = "`".repeat(longest_run(code, '`').max(2) + 1);
            out.push_str(&format!("{fence}text\n{}\n{fence}\n\n", code.trim_end_matches('\n')));
        }
        Block::Card { tone, title, badges, body } => {
            let lvl = (3 + depth).min(6);
            let badge_txt: Vec<String> = badges.iter().map(|b| format!("`{}`", b.text.replace('`', "'"))).collect();
            out.push_str(&format!(
                "{} {} {} {}\n\n",
                "#".repeat(lvl),
                tone.marker(),
                esc(&super::strip_emoji(title)),
                badge_txt.join(" ")
            ));
            render_blocks(out, body, depth + 1);
            out.push_str("---\n\n");
        }
    }
}

pub fn render(doc: &Doc) -> String {
    let mut out = String::with_capacity(16 * 1024);
    out.push_str(&format!("# {}\n\n", esc(&doc.title)));
    out.push_str(&format!(
        "**{}** — {}  \n*Généré le {}*\n\n",
        esc(&doc.app),
        esc(&doc.subtitle),
        esc(&doc.generated_at)
    ));
    render_blocks(&mut out, &doc.blocks, 0);
    out.push_str(&format!("\n---\n*Rapport généré par {} — {}*\n", esc(&doc.app), esc(&doc.generated_at)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_doc;

    #[test]
    fn echappe_html_et_tableaux() {
        let md = render(&sample_doc());
        assert!(!md.contains("<script>"), "HTML brut non échappé");
        assert!(md.contains("\\<script\\>"));
        // Chaque ligne de tableau garde le même nombre de séparateurs non échappés.
        for line in md.lines().filter(|l| l.starts_with("| Col A")) {
            assert_eq!(line.matches(" | ").count(), 1, "{line}");
        }
        assert!(md.contains("`x\\|y`<br>`z`"), "cellule mono : {md}");
    }

    #[test]
    fn bloc_de_code_non_cassable() {
        let md = render(&sample_doc());
        // Le code contient ``` : la clôture doit être plus longue.
        assert!(md.contains("````text\n```fence```"));
    }
}
