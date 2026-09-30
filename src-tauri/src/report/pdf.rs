//! Rendu PDF d'un `Doc`, sans dépendance : PDF 1.4 écrit à la main.
//!
//! Polices standard (Helvetica, Helvetica-Bold, Helvetica-Oblique, Courier) en
//! encodage WinAnsi : tous les accents français passent, les emojis sont retirés
//! et quelques symboles (→, ✓, ≥…) sont translittérés. La mise en page mesure le
//! texte avec les vraies largeurs de glyphes (retour à la ligne exact), gère les
//! sauts de page (en-têtes de tableau répétés, cartes découpées proprement) et
//! numérote les pages « Page n / total ».

use super::pdf_metrics::{HELVETICA, HELVETICA_BOLD};
use super::{strip_emoji, Badge, Block, Cell, Doc, Tone};

const PAGE_W: f32 = 595.28;
const PAGE_H: f32 = 841.89;
const MARGIN_X: f32 = 46.0;
const MARGIN_TOP: f32 = 58.0;
const MARGIN_BOTTOM: f32 = 52.0;

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Reg,
    Bold,
    Ital,
    Mono,
}

impl Font {
    fn res(self) -> &'static str {
        match self {
            Font::Reg => "F1",
            Font::Bold => "F2",
            Font::Ital => "F4",
            Font::Mono => "F3",
        }
    }
}

type Rgb = (u8, u8, u8);

const TEXT: Rgb = (29, 35, 48);
const MUTED: Rgb = (91, 100, 116);
const RULE: Rgb = (223, 227, 236);
const ACCENT: Rgb = (37, 99, 235);
const CODE_BG: Rgb = (243, 244, 248);

// ─── Encodage WinAnsi ─────────────────────────────────────────────────────────

fn winansi(c: char) -> Option<u8> {
    let cp = c as u32;
    if (0x20..=0x7E).contains(&cp) || (0xA0..=0xFF).contains(&cp) {
        return Some(cp as u8);
    }
    let b = match c {
        '€' => 0x80, '‚' => 0x82, 'ƒ' => 0x83, '„' => 0x84, '…' => 0x85, '†' => 0x86,
        '‡' => 0x87, 'ˆ' => 0x88, '‰' => 0x89, 'Š' => 0x8A, '‹' => 0x8B, 'Œ' => 0x8C,
        'Ž' => 0x8E, '‘' => 0x91, '’' => 0x92, '“' => 0x93, '”' => 0x94, '•' => 0x95,
        '–' => 0x96, '—' => 0x97, '˜' => 0x98, '™' => 0x99, 'š' => 0x9A, '›' => 0x9B,
        'œ' => 0x9C, 'ž' => 0x9E, 'Ÿ' => 0x9F,
        _ => return None,
    };
    Some(b)
}

/// Convertit une chaîne Unicode en octets WinAnsi (translittération sinon `?`).
fn encode(s: &str) -> Vec<u8> {
    let s = strip_emoji(s);
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        if let Some(b) = winansi(c) {
            out.push(b);
            continue;
        }
        let rep: &str = match c {
            '\t' => "    ",
            '\n' | '\r' => " ",
            '→' | '⇒' | '➜' => "->",
            '←' => "<-",
            '↔' => "<->",
            '✓' | '✔' => "OK",
            '✗' | '✘' => "x",
            '≥' => ">=",
            '≤' => "<=",
            '≠' => "!=",
            '≈' => "~",
            '█' | '▓' | '▒' | '░' | '■' | '□' | '▪' => "",
            '\u{2009}' | '\u{202F}' | '\u{2002}' | '\u{2003}' => " ",
            '\u{2011}' | '\u{2010}' | '−' => "-",
            c if (c as u32) < 0x20 => " ",
            _ => "?",
        };
        for ch in rep.chars() {
            if let Some(b) = winansi(ch) {
                out.push(b);
            }
        }
    }
    out
}

fn char_w(font: Font, b: u8) -> f32 {
    match font {
        Font::Mono => 600.0,
        Font::Bold => HELVETICA_BOLD[b as usize] as f32,
        Font::Reg | Font::Ital => HELVETICA[b as usize] as f32,
    }
}

fn width(bytes: &[u8], font: Font, size: f32) -> f32 {
    bytes.iter().map(|&b| char_w(font, b)).sum::<f32>() * size / 1000.0
}

/// Retour à la ligne exact selon les métriques ; coupe les mots trop longs.
fn wrap(s: &str, font: Font, size: f32, max_w: f32) -> Vec<Vec<u8>> {
    let max_w = max_w.max(size * 2.0);
    let space = char_w(font, b' ') * size / 1000.0;
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for para in s.split('\n') {
        let mut cur: Vec<u8> = Vec::new();
        let mut cur_w = 0.0f32;
        for word in para.split_whitespace() {
            let mut w = encode(word);
            if w.is_empty() {
                continue;
            }
            let mut ww = width(&w, font, size);
            while ww > max_w {
                // Coupe dure : le plus long préfixe qui tient sur une ligne vide.
                if !cur.is_empty() {
                    lines.push(std::mem::take(&mut cur));
                    cur_w = 0.0;
                }
                let mut acc = 0.0;
                let mut cut = 0;
                for (i, &b) in w.iter().enumerate() {
                    let cw = char_w(font, b) * size / 1000.0;
                    if acc + cw > max_w && i > 0 {
                        break;
                    }
                    acc += cw;
                    cut = i + 1;
                }
                lines.push(w[..cut].to_vec());
                w = w[cut..].to_vec();
                ww = width(&w, font, size);
            }
            if w.is_empty() {
                continue;
            }
            if !cur.is_empty() && cur_w + space + ww > max_w {
                lines.push(std::mem::take(&mut cur));
                cur_w = 0.0;
            }
            if !cur.is_empty() {
                cur.push(b' ');
                cur_w += space;
            }
            cur.extend_from_slice(&w);
            cur_w += ww;
        }
        lines.push(cur);
    }
    lines
}

/// Chaîne littérale PDF : échappe `( ) \` et encode en octal tout octet non ASCII.
fn pdf_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 8);
    s.push('(');
    for &b in bytes {
        match b {
            b'(' | b')' | b'\\' => {
                s.push('\\');
                s.push(b as char);
            }
            0x20..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03o}")),
        }
    }
    s.push(')');
    s
}

fn tint(c: Rgb, amount: f32) -> Rgb {
    let m = |v: u8| (255.0 - (255.0 - v as f32) * amount).round() as u8;
    (m(c.0), m(c.1), m(c.2))
}

fn rgb_op(c: Rgb, stroke: bool) -> String {
    format!(
        "{:.3} {:.3} {:.3} {}",
        c.0 as f32 / 255.0,
        c.1 as f32 / 255.0,
        c.2 as f32 / 255.0,
        if stroke { "RG" } else { "rg" }
    )
}

// ─── Moteur de mise en page ───────────────────────────────────────────────────

#[derive(Default)]
struct Page {
    bg: String,
    fg: String,
}

/// Décoration (fond + barre) d'un bloc qui peut s'étendre sur plusieurs pages.
struct Deco {
    x: f32,
    w: f32,
    y_start: f32,
    fill: Rgb,
    bar: Option<Rgb>,
}

struct Layout {
    pages: Vec<Page>,
    y: f32,
    decos: Vec<Deco>,
}

impl Layout {
    fn new() -> Self {
        Layout { pages: vec![Page::default()], y: MARGIN_TOP, decos: Vec::new() }
    }

    fn page(&mut self) -> &mut Page {
        if self.pages.is_empty() {
            self.pages.push(Page::default());
        }
        let last = self.pages.len() - 1;
        &mut self.pages[last]
    }

    fn bottom() -> f32 {
        PAGE_H - MARGIN_BOTTOM
    }

    /// Passe à la page suivante si `h` ne tient pas.
    fn ensure(&mut self, h: f32) {
        if self.y + h > Self::bottom() && self.y > MARGIN_TOP + 0.5 {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        // Ferme sur cette page les décorations ouvertes, puis les rouvre en haut.
        let segs: Vec<(f32, f32, f32, f32, Rgb, Option<Rgb>)> = self
            .decos
            .iter()
            .map(|d| (d.x, d.y_start, d.w, Self::bottom() + 4.0 - d.y_start, d.fill, d.bar))
            .collect();
        for (x, y, w, h, fill, bar) in segs {
            self.deco_rect(x, y, w, h, fill, bar);
        }
        self.pages.push(Page::default());
        self.y = MARGIN_TOP;
        for d in &mut self.decos {
            d.y_start = MARGIN_TOP - 4.0;
        }
    }

    fn deco_rect(&mut self, x: f32, y: f32, w: f32, h: f32, fill: Rgb, bar: Option<Rgb>) {
        if h <= 0.5 {
            return;
        }
        let pdf_y = PAGE_H - y - h;
        let mut ops = format!("{} {x:.2} {pdf_y:.2} {w:.2} {h:.2} re f\n", rgb_op(fill, false));
        if let Some(bar) = bar {
            ops.push_str(&format!("{} {x:.2} {pdf_y:.2} 3.5 {h:.2} re f\n", rgb_op(bar, false)));
        }
        self.page().bg.push_str(&ops);
    }

    fn open_deco(&mut self, x: f32, w: f32, fill: Rgb, bar: Option<Rgb>) {
        let y_start = self.y;
        self.decos.push(Deco { x, w, y_start, fill, bar });
    }

    fn close_deco(&mut self, pad_bottom: f32) {
        self.y += pad_bottom;
        if let Some(d) = self.decos.pop() {
            let h = self.y - d.y_start;
            self.deco_rect(d.x, d.y_start, d.w, h, d.fill, d.bar);
        }
    }

    fn text(&mut self, x: f32, baseline: f32, font: Font, size: f32, color: Rgb, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let op = format!(
            "BT /{} {size:.2} Tf {} {x:.2} {:.2} Td {} Tj ET\n",
            font.res(),
            rgb_op(color, false),
            PAGE_H - baseline,
            pdf_str(bytes)
        );
        self.page().fg.push_str(&op);
    }

    fn rect_fg(&mut self, x: f32, y: f32, w: f32, h: f32, color: Rgb) {
        let op = format!("{} {x:.2} {:.2} {w:.2} {h:.2} re f\n", rgb_op(color, false), PAGE_H - y - h);
        self.page().fg.push_str(&op);
    }

    fn round_rect_fg(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32, color: Rgb) {
        let r = r.min(h / 2.0).min(w / 2.0);
        let (x0, y0) = (x, PAGE_H - y - h);
        let (x1, y1) = (x + w, PAGE_H - y);
        let k = 0.5523 * r;
        let op = format!(
            "{c} {a:.2} {y0:.2} m {b:.2} {y0:.2} l {b2:.2} {y0:.2} {x1:.2} {c1:.2} {x1:.2} {d:.2} c \
             {x1:.2} {e:.2} l {x1:.2} {e2:.2} {b2:.2} {y1:.2} {b:.2} {y1:.2} c {a:.2} {y1:.2} l \
             {a2:.2} {y1:.2} {x0:.2} {e2:.2} {x0:.2} {e:.2} c {x0:.2} {d:.2} l {x0:.2} {c1:.2} {a2:.2} {y0:.2} {a:.2} {y0:.2} c f\n",
            c = rgb_op(color, false),
            a = x0 + r,
            b = x1 - r,
            b2 = x1 - r + k,
            a2 = x0 + r - k,
            c1 = y0 + r - k,
            d = y0 + r,
            e = y1 - r,
            e2 = y1 - r + k,
        );
        self.page().fg.push_str(&op);
    }

    fn hline(&mut self, x: f32, y: f32, w: f32, color: Rgb, thick: f32) {
        let op = format!(
            "{} {thick:.2} w {x:.2} {py:.2} m {:.2} {py:.2} l S\n",
            rgb_op(color, true),
            x + w,
            py = PAGE_H - y
        );
        self.page().fg.push_str(&op);
    }

    /// Paragraphe multi-ligne à partir de la position courante.
    fn para(&mut self, x: f32, w: f32, s: &str, font: Font, size: f32, color: Rgb) {
        let leading = size * 1.42;
        for line in wrap(s, font, size, w) {
            self.ensure(leading);
            self.text(x, self.y + size, font, size, color, &line);
            self.y += leading;
        }
    }
}

// ─── Rendu des blocs ──────────────────────────────────────────────────────────

fn render_blocks(l: &mut Layout, blocks: &[Block], x: f32, w: f32, in_card: bool) {
    for b in blocks {
        render_block(l, b, x, w, in_card);
    }
}

fn render_block(l: &mut Layout, b: &Block, x: f32, w: f32, in_card: bool) {
    match b {
        Block::Heading(level, t) => {
            if *level <= 1 && !in_card {
                l.y += 10.0;
                l.ensure(60.0); // pas de titre orphelin en bas de page
                l.para(x, w, t, Font::Bold, 14.5, TEXT);
                l.y += 1.0;
                l.hline(x, l.y, w, ACCENT, 1.2);
                l.y += 9.0;
            } else {
                l.y += 5.0;
                l.ensure(40.0);
                l.para(x, w, t, Font::Bold, if in_card { 8.8 } else { 11.0 }, if in_card { MUTED } else { TEXT });
                l.y += 3.0;
            }
        }
        Block::Para(t) => {
            l.para(x, w, t, Font::Reg, 9.4, TEXT);
            l.y += 4.0;
        }
        Block::Note(t) => {
            l.para(x, w, t, Font::Ital, 8.4, MUTED);
            l.y += 4.0;
        }
        Block::Bullets(items) => {
            let size = 9.2;
            let leading = size * 1.42;
            for i in items {
                let lines = wrap(i, Font::Reg, size, w - 12.0);
                for (n, line) in lines.iter().enumerate() {
                    l.ensure(leading);
                    if n == 0 {
                        l.text(x + 2.0, l.y + size, Font::Bold, size, ACCENT, &[0x95]);
                    }
                    l.text(x + 12.0, l.y + size, Font::Reg, size, TEXT, line);
                    l.y += leading;
                }
            }
            l.y += 4.0;
        }
        Block::KeyValues { items, mono } => {
            let size = 8.8;
            let key_w = items
                .iter()
                .map(|(k, _)| width(&encode(k), Font::Bold, size))
                .fold(0.0f32, f32::max)
                .min(w * 0.34)
                + 12.0;
            let (vfont, vsize) = if *mono { (Font::Mono, 8.2) } else { (Font::Reg, size) };
            let leading = size * 1.45;
            for (k, v) in items {
                let klines = wrap(k, Font::Bold, size, key_w - 11.0);
                let vlines = wrap(v, vfont, vsize, w - key_w);
                let n = klines.len().max(vlines.len());
                for i in 0..n {
                    l.ensure(leading);
                    if let Some(kl) = klines.get(i) {
                        l.text(x, l.y + size, Font::Bold, size, MUTED, kl);
                    }
                    if let Some(vl) = vlines.get(i) {
                        l.text(x + key_w, l.y + size, vfont, vsize, TEXT, vl);
                    }
                    l.y += leading;
                }
                l.y += 1.5;
            }
            l.y += 5.0;
        }
        Block::Callout { tone, title, lines } => {
            let c = tone.rgb();
            l.ensure(40.0);
            l.open_deco(x, w, tint(c, 0.09), Some(c));
            l.y += 9.0;
            l.para(x + 14.0, w - 24.0, title, Font::Bold, 11.5, c);
            l.y += 2.0;
            for line in lines {
                l.para(x + 14.0, w - 24.0, line, Font::Reg, 9.2, TEXT);
                l.y += 1.5;
            }
            l.close_deco(7.0);
            l.y += 10.0;
        }
        Block::Stats(items) => {
            let per_row = items.len().clamp(1, 4);
            let gap = 8.0;
            let tile_w = (w - gap * (per_row as f32 - 1.0)) / per_row as f32;
            for row in items.chunks(per_row) {
                // Libellés sur 2 lignes max : la tuile prend la hauteur du plus long.
                let labels: Vec<Vec<Vec<u8>>> = row
                    .iter()
                    .map(|(_, lab, _)| {
                        let mut l = wrap(lab, Font::Reg, 8.3, tile_w - 16.0);
                        if l.len() > 2 {
                            let rest = l[1..].join(&b' ');
                            l.truncate(1);
                            l.push(fit(&rest, Font::Reg, 8.3, tile_w - 16.0));
                        }
                        l
                    })
                    .collect();
                let nl = labels.iter().map(Vec::len).max().unwrap_or(1) as f32;
                let tile_h = 36.0 + nl * 11.0;
                l.ensure(tile_h + 8.0);
                let y = l.y;
                for (i, (v, _, t)) in row.iter().enumerate() {
                    let tx = x + i as f32 * (tile_w + gap);
                    let c = t.rgb();
                    l.rect_fg(tx, y, tile_w, tile_h, tint(c, 0.08));
                    l.rect_fg(tx, y, tile_w, 3.0, c);
                    let vb = fit(&encode(v), Font::Bold, 17.0, tile_w - 16.0);
                    l.text(tx + 9.0, y + 24.0, Font::Bold, 17.0, c, &vb);
                    for (k, lb) in labels[i].iter().enumerate() {
                        l.text(tx + 9.0, y + 39.0 + k as f32 * 11.0, Font::Reg, 8.3, MUTED, lb);
                    }
                }
                l.y += tile_h + gap;
            }
            l.y += 6.0;
        }
        Block::Meter { label, percent, tone } => {
            let c = tone.rgb();
            let size = 9.0;
            let pct = format!("{} %", percent);
            let pw = width(&encode(&pct), Font::Bold, size + 1.0);
            let lines = wrap(label, Font::Bold, size, w - pw - 10.0);
            l.ensure(lines.len() as f32 * size * 1.4 + 14.0);
            let first_y = l.y;
            for line in &lines {
                l.text(x, l.y + size, Font::Bold, size, TEXT, line);
                l.y += size * 1.4;
            }
            l.text(x + w - pw, first_y + size, Font::Bold, size + 1.0, c, &encode(&pct));
            l.y += 1.0;
            l.round_rect_fg(x, l.y, w, 6.5, 3.2, RULE);
            let fw = w * (*percent).min(100) as f32 / 100.0;
            if fw > 0.5 {
                l.round_rect_fg(x, l.y, fw.max(6.5), 6.5, 3.2, c);
            }
            l.y += 15.0;
        }
        Block::Table { headers, rows, widths } => render_table(l, headers, rows, widths, x, w),
        Block::Code(code) => {
            let size = 7.6;
            let leading = size * 1.35;
            let pad = 7.0;
            let max_chars = (((w - 2.0 * pad) / (0.6 * size)).floor() as usize).max(10);
            l.ensure(leading * 2.0 + 2.0 * pad);
            l.open_deco(x, w, CODE_BG, None);
            l.y += pad;
            for raw in code.lines() {
                let bytes = encode(&raw.replace('\t', "    "));
                let chunks: Vec<&[u8]> = if bytes.is_empty() { vec![&[][..]] } else { bytes.chunks(max_chars).collect() };
                for ch in chunks {
                    l.ensure(leading);
                    l.text(x + pad, l.y + size, Font::Mono, size, TEXT, ch);
                    l.y += leading;
                }
            }
            l.close_deco(pad - 2.0);
            l.y += 8.0;
        }
        Block::Card { tone, title, badges, body } => {
            let c = tone.rgb();
            let pad = 12.0;
            l.ensure(140.0); // titre + premières lignes sur la même page
            l.y += 2.0;
            l.open_deco(x, w, tint(c, 0.05), Some(c));
            l.y += 10.0;
            let inner_x = x + pad + 3.0;
            let inner_w = w - 2.0 * pad - 3.0;
            // Badges à droite du titre.
            let bsize = 7.6;
            let bwidths: Vec<f32> = badges.iter().map(|b| width(&encode(&b.text), Font::Bold, bsize) + 12.0).collect();
            let badges_w: f32 = bwidths.iter().sum::<f32>() + 5.0 * badges.len() as f32;
            let title_w = (inner_w - badges_w).max(inner_w * 0.45);
            let tlines = wrap(title, Font::Bold, 10.8, title_w);
            let top = l.y;
            for line in &tlines {
                l.ensure(15.0);
                l.text(inner_x, l.y + 10.8, Font::Bold, 10.8, TEXT, line);
                l.y += 15.0;
            }
            draw_badges(l, badges, &bwidths, inner_x + inner_w, top, bsize);
            l.y += 4.0;
            render_blocks(l, body, inner_x, inner_w, true);
            l.close_deco(4.0);
            l.y += 10.0;
        }
    }
}

fn draw_badges(l: &mut Layout, badges: &[Badge], widths: &[f32], right: f32, top: f32, size: f32) {
    let mut bx = right;
    for (b, bw) in badges.iter().zip(widths).rev() {
        bx -= bw;
        l.round_rect_fg(bx, top, *bw, 14.0, 7.0, b.tone.rgb());
        l.text(bx + 6.0, top + 10.0, Font::Bold, size, (255, 255, 255), &encode(&b.text));
        bx -= 5.0;
    }
}

/// Tronque avec « … » pour tenir dans `max_w` (tuiles, cellules très hautes).
fn fit(bytes: &[u8], font: Font, size: f32, max_w: f32) -> Vec<u8> {
    if width(bytes, font, size) <= max_w {
        return bytes.to_vec();
    }
    let ell = char_w(font, 0x85) * size / 1000.0;
    let mut acc = 0.0;
    let mut out = Vec::new();
    for &b in bytes {
        let cw = char_w(font, b) * size / 1000.0;
        if acc + cw + ell > max_w {
            break;
        }
        acc += cw;
        out.push(b);
    }
    out.push(0x85);
    out
}

fn render_table(l: &mut Layout, headers: &[String], rows: &[Vec<Cell>], widths: &[f32], x: f32, w: f32) {
    let n = headers.len().max(1);
    let total: f32 = (0..n).map(|i| widths.get(i).copied().unwrap_or(1.0)).sum::<f32>().max(0.001);
    let cols: Vec<f32> = (0..n).map(|i| widths.get(i).copied().unwrap_or(1.0) / total * w).collect();
    let pad_x = 5.0;
    let pad_y = 4.0;
    let size = 8.3;
    let leading = size * 1.36;
    let max_row_h = PAGE_H - MARGIN_TOP - MARGIN_BOTTOM - 40.0;

    let draw_header = |l: &mut Layout| {
        let hsize = 7.4;
        let hl: Vec<Vec<Vec<u8>>> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| wrap(&h.to_uppercase(), Font::Bold, hsize, cols[i] - 2.0 * pad_x))
            .collect();
        let lines = hl.iter().map(Vec::len).max().unwrap_or(1);
        let h = lines as f32 * hsize * 1.3 + 2.0 * pad_y;
        l.ensure(h + leading + 2.0 * pad_y);
        let y = l.y;
        l.rect_fg(x, y, w, h, CODE_BG);
        let mut cx = x;
        for (i, lines) in hl.iter().enumerate() {
            for (k, line) in lines.iter().enumerate() {
                l.text(cx + pad_x, y + pad_y + hsize + k as f32 * hsize * 1.3, Font::Bold, hsize, MUTED, line);
            }
            cx += cols[i];
        }
        l.y += h;
    };

    draw_header(l);
    for row in rows {
        let wrapped: Vec<(Vec<Vec<u8>>, Font, f32, Rgb)> = (0..n)
            .map(|i| {
                let cell = row.get(i).cloned().unwrap_or_else(|| Cell::new(""));
                let (font, sz) = if cell.mono {
                    (Font::Mono, size - 0.6)
                } else if cell.tone.is_some() {
                    (Font::Bold, size)
                } else {
                    (Font::Reg, size)
                };
                let color = cell.tone.map(Tone::rgb).unwrap_or(TEXT);
                (wrap(&cell.text, font, sz, cols[i] - 2.0 * pad_x), font, sz, color)
            })
            .collect();
        let mut lines = wrapped.iter().map(|c| c.0.len()).max().unwrap_or(1).max(1);
        // Une ligne plus haute qu'une page entière est tronquée proprement.
        let max_lines = ((max_row_h - 2.0 * pad_y) / leading).floor() as usize;
        let truncated = lines > max_lines;
        if truncated {
            lines = max_lines;
        }
        let h = lines as f32 * leading + 2.0 * pad_y;
        if l.y + h > Layout::bottom() {
            l.new_page();
            draw_header(l);
        }
        let y = l.y;
        let mut cx = x;
        for (i, (cl, font, sz, color)) in wrapped.iter().enumerate() {
            for (k, line) in cl.iter().take(lines).enumerate() {
                let mut line = line.clone();
                if truncated && k + 1 == lines && cl.len() > lines {
                    line = fit(&[line.as_slice(), &b" \x85"[..]].concat(), *font, *sz, cols[i] - 2.0 * pad_x);
                }
                l.text(cx + pad_x, y + pad_y + sz + k as f32 * leading, *font, *sz, *color, &line);
            }
            cx += cols[i];
        }
        l.y += h;
        l.hline(x, l.y, w, RULE, 0.6);
    }
    l.y += 12.0;
}

// ─── Assemblage du fichier PDF ────────────────────────────────────────────────

fn utf16_hex(s: &str) -> String {
    let mut out = String::from("<FEFF");
    for u in s.encode_utf16() {
        out.push_str(&format!("{u:04X}"));
    }
    out.push('>');
    out
}

fn title_banner(l: &mut Layout, doc: &Doc) {
    let x = MARGIN_X;
    let w = PAGE_W - 2.0 * MARGIN_X;
    let tlines = wrap(&doc.title, Font::Bold, 17.0, w - 28.0);
    let slines = wrap(&format!("{} · généré le {}", doc.subtitle, doc.generated_at), Font::Reg, 9.0, w - 28.0);
    let h = 16.0 + 12.0 + tlines.len() as f32 * 22.0 + slines.len() as f32 * 12.5 + 12.0;
    let y = MARGIN_TOP - 20.0;
    l.rect_fg(x, y, w, h, (15, 23, 42));
    l.rect_fg(x, y, 5.0, h, (56, 189, 248));
    let mut ty = y + 18.0;
    l.text(x + 16.0, ty, Font::Bold, 8.5, (125, 211, 252), &encode(&doc.app.to_uppercase()));
    ty += 7.0;
    for line in &tlines {
        ty += 20.0;
        l.text(x + 16.0, ty, Font::Bold, 17.0, (255, 255, 255), line);
    }
    ty += 4.0;
    for line in &slines {
        ty += 12.5;
        l.text(x + 16.0, ty, Font::Reg, 9.0, (203, 213, 225), line);
    }
    l.y = y + h + 18.0;
}

pub fn render(doc: &Doc) -> Vec<u8> {
    let mut l = Layout::new();
    title_banner(&mut l, doc);
    let w = PAGE_W - 2.0 * MARGIN_X;
    render_blocks(&mut l, &doc.blocks, MARGIN_X, w, false);

    // En-tête et pied de page (le total de pages n'est connu qu'ici).
    let total = l.pages.len();
    let head = fit(&encode(&format!("{} — {}", doc.app, doc.title)), Font::Reg, 7.5, w * 0.7);
    for (i, page) in l.pages.iter_mut().enumerate() {
        let mut ops = String::new();
        if i > 0 {
            ops.push_str(&format!(
                "BT /F1 7.5 Tf {} {MARGIN_X:.2} {:.2} Td {} Tj ET\n",
                rgb_op(MUTED, false),
                PAGE_H - 32.0,
                pdf_str(&head)
            ));
            ops.push_str(&format!(
                "{} 0.6 w {MARGIN_X:.2} {y:.2} m {:.2} {y:.2} l S\n",
                rgb_op(RULE, true),
                PAGE_W - MARGIN_X,
                y = PAGE_H - 38.0
            ));
        }
        let footer = encode(&format!("Page {} / {}", i + 1, total));
        let fw = width(&footer, Font::Reg, 7.5);
        let left = fit(&encode(&format!("{} · {}", doc.app, doc.generated_at)), Font::Reg, 7.5, w * 0.7);
        ops.push_str(&format!(
            "{} 0.6 w {MARGIN_X:.2} 34.00 m {:.2} 34.00 l S\n",
            rgb_op(RULE, true),
            PAGE_W - MARGIN_X
        ));
        ops.push_str(&format!("BT /F1 7.5 Tf {} {MARGIN_X:.2} 22.00 Td {} Tj ET\n", rgb_op(MUTED, false), pdf_str(&left)));
        ops.push_str(&format!(
            "BT /F1 7.5 Tf {} {:.2} 22.00 Td {} Tj ET\n",
            rgb_op(MUTED, false),
            PAGE_W - MARGIN_X - fw,
            pdf_str(&footer)
        ));
        page.fg.push_str(&ops);
    }

    // Objets : 1 catalogue, 2 pages, 3-6 polices, 7 info, puis (page, contenu)*.
    let mut objs: Vec<Vec<u8>> = Vec::new();
    let first_page_obj = 8;
    let kids: Vec<String> = (0..total).map(|i| format!("{} 0 R", first_page_obj + 2 * i)).collect();
    objs.push(b"<< /Type /Catalog /Pages 2 0 R /Lang (fr-FR) >>".to_vec());
    objs.push(format!("<< /Type /Pages /Kids [{}] /Count {total} >>", kids.join(" ")).into_bytes());
    for base in ["Helvetica", "Helvetica-Bold", "Courier", "Helvetica-Oblique"] {
        objs.push(
            format!("<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>").into_bytes(),
        );
    }
    let now = chrono::Utc::now().format("D:%Y%m%d%H%M%SZ").to_string();
    objs.push(
        format!(
            "<< /Title {} /Producer {} /Creator {} /CreationDate ({now}) >>",
            utf16_hex(&doc.title),
            utf16_hex(&format!("{} (rapport PDF intégré)", doc.app)),
            utf16_hex(&doc.app)
        )
        .into_bytes(),
    );
    for (i, page) in l.pages.iter().enumerate() {
        let content_obj = first_page_obj + 2 * i + 1;
        objs.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] \
                 /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> /Contents {content_obj} 0 R >>"
            )
            .into_bytes(),
        );
        let stream = format!("{}{}", page.bg, page.fg);
        let mut o = format!("<< /Length {} >>\nstream\n", stream.len()).into_bytes();
        o.extend_from_slice(stream.as_bytes());
        o.extend_from_slice(b"\nendstream");
        objs.push(o);
    }

    let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::with_capacity(objs.len());
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R /Info 7 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1)
            .as_bytes(),
    );
    out
}

#[cfg(test)]
#[path = "pdf_tests.rs"]
mod tests;
