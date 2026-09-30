//! report — Modèle de document de rapport + rendus Markdown, texte, HTML et PDF.
//!
//! Chaque application construit UN `Doc` à partir de son résultat de scan ; les
//! quatre formats sont rendus depuis ce même modèle, ce qui garantit qu'ils
//! contiennent exactement les mêmes informations (pas de format « oublié »).
//! Module autonome, sans dépendance externe : identique dans FileScanner et SecuScan.

pub mod html;
pub mod markdown;
pub mod pdf;
mod pdf_metrics;
pub mod text;

/// Tonalité d'un élément : pilote couleurs (HTML/PDF) et pictos (MD/TXT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Good,
    Info,
    Warn,
    Danger,
    Critical,
}

impl Tone {
    /// Couleur RVB (0-255) utilisée par les rendus graphiques.
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Tone::Neutral => (100, 116, 139),
            Tone::Good => (22, 163, 74),
            Tone::Info => (37, 99, 235),
            Tone::Warn => (202, 138, 4),
            Tone::Danger => (234, 88, 12),
            Tone::Critical => (220, 38, 38),
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Tone::Neutral => "neutral",
            Tone::Good => "good",
            Tone::Info => "info",
            Tone::Warn => "warn",
            Tone::Danger => "danger",
            Tone::Critical => "critical",
        }
    }

    /// Marqueur texte pour les formats sans couleur.
    pub fn marker(self) -> &'static str {
        match self {
            Tone::Neutral => "•",
            Tone::Good => "✅",
            Tone::Info => "ℹ️",
            Tone::Warn => "⚠️",
            Tone::Danger => "🟠",
            Tone::Critical => "⛔",
        }
    }

    /// Tonalité d'une probabilité de menace réelle (0-100).
    pub fn for_threat(percent: u8) -> Tone {
        match percent {
            0..=14 => Tone::Good,
            15..=39 => Tone::Warn,
            40..=69 => Tone::Danger,
            _ => Tone::Critical,
        }
    }
}

/// Cellule de tableau : texte + tonalité optionnelle (mise en couleur / gras).
#[derive(Debug, Clone)]
pub struct Cell {
    pub text: String,
    pub tone: Option<Tone>,
    pub mono: bool,
}

impl Cell {
    pub fn new(text: impl Into<String>) -> Self {
        Cell { text: text.into(), tone: None, mono: false }
    }
    pub fn toned(text: impl Into<String>, tone: Tone) -> Self {
        Cell { text: text.into(), tone: Some(tone), mono: false }
    }
    pub fn mono(text: impl Into<String>) -> Self {
        Cell { text: text.into(), tone: None, mono: true }
    }
}

impl<T: Into<String>> From<T> for Cell {
    fn from(t: T) -> Self {
        Cell::new(t)
    }
}

/// Badge court affiché dans l'en-tête d'une carte (« CRITIQUE », « 87 % »…).
#[derive(Debug, Clone)]
pub struct Badge {
    pub text: String,
    pub tone: Tone,
}

#[derive(Debug, Clone)]
pub enum Block {
    /// Titre de section (niveau 1 = section principale, 2 = sous-section).
    Heading(u8, String),
    Para(String),
    /// Paragraphe discret (notes, méthodologie).
    Note(String),
    Bullets(Vec<String>),
    /// Paires clé / valeur ; `mono` = valeurs techniques (hash, chemin…).
    KeyValues { items: Vec<(String, String)>, mono: bool },
    /// Encadré coloré (verdict, avertissement…).
    Callout { tone: Tone, title: String, lines: Vec<String> },
    /// Tuiles de chiffres clés.
    Stats(Vec<(String, String, Tone)>),
    /// Barre de pourcentage.
    Meter { label: String, percent: u8, tone: Tone },
    /// Tableau ; `widths` = proportions relatives des colonnes.
    Table { headers: Vec<String>, rows: Vec<Vec<Cell>>, widths: Vec<f32> },
    /// Extrait de code / lignes brutes (police à chasse fixe).
    Code(String),
    /// Carte de détection : titre, badges, contenu imbriqué (un niveau).
    Card { tone: Tone, title: String, badges: Vec<Badge>, body: Vec<Block> },
}

#[derive(Debug, Clone)]
pub struct Doc {
    /// Nom de l'application (« FileScanner », « SecuScan »).
    pub app: String,
    pub title: String,
    pub subtitle: String,
    pub generated_at: String,
    pub blocks: Vec<Block>,
}

/// Barre de progression textuelle « ██████░░░░ » (MD / TXT).
pub fn text_bar(percent: u8, width: usize, full: char, empty: char) -> String {
    let p = percent.min(100) as usize;
    let filled = (p * width + 50) / 100;
    let mut s = String::with_capacity(width * 3);
    for i in 0..width {
        s.push(if i < filled { full } else { empty });
    }
    s
}

/// Retire les pictogrammes hors plan multilingue de base et les sélecteurs de
/// variante : les formats texte gardent les accents, le PDF n'a pas d'emoji.
pub fn strip_emoji(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        let is_pictograph = (0x1F000..=0x1FAFF).contains(&cp)
            || (0x2600..=0x27BF).contains(&cp)
            || (0x2B00..=0x2BFF).contains(&cp)
            || cp == 0xFE0F
            || cp == 0x200D
            || (0xE0000..=0xE007F).contains(&cp);
        if !is_pictograph {
            out.push(c);
        }
    }
    // Un emoji en tête laisse une espace orpheline.
    out.trim_start().to_string()
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// Document couvrant tous les types de blocs, avec des chaînes hostiles
    /// (HTML, Markdown, emoji, caractères hors WinAnsi, mots très longs).
    pub fn sample_doc() -> Doc {
        let long = "a".repeat(180);
        Doc {
            app: "TestApp".into(),
            title: "Rapport <script>alert(1)</script>".into(),
            subtitle: "fichier | test *gras* `code`".into(),
            generated_at: "2026-09-28 12:00 UTC".into(),
            blocks: vec![
                Block::Callout {
                    tone: Tone::Critical,
                    title: "⛔ Verdict : MALVEILLANT".into(),
                    lines: vec!["Ligne 1 — accentuée éàçù œ €".into(), "→ flèche ✓ coche".into()],
                },
                Block::Stats(vec![
                    ("87 %".into(), "Menace réelle".into(), Tone::Critical),
                    ("13 %".into(), "Faux positif".into(), Tone::Good),
                ]),
                Block::Meter { label: "Probabilité".into(), percent: 87, tone: Tone::Critical },
                Block::Meter {
                    label: "Probabilité que le fichier soit réellement malveillant selon toutes les sources".into(),
                    percent: 99,
                    tone: Tone::Critical,
                },
                Block::Heading(1, "Section".into()),
                Block::Heading(2, "Sous-section".into()),
                Block::Para(format!("Paragraphe avec un mot très long {long} et <b>html</b>.")),
                Block::Note("Note discrète.".into()),
                Block::Bullets(vec!["Puce 1".into(), "Puce | 2".into()]),
                Block::KeyValues {
                    items: vec![("SHA-256".into(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into())],
                    mono: true,
                },
                Block::Table {
                    headers: vec!["Col A".into(), "Col | B".into()],
                    rows: vec![
                        vec![Cell::toned("CRITIQUE", Tone::Critical), Cell::mono("x|y\nz")],
                        vec![Cell::new("n"), Cell::new(long.clone())],
                    ],
                    widths: vec![1.0, 3.0],
                },
                Block::Code("```fence``` \n\tindent\nline <tag>".into()),
                Block::Card {
                    tone: Tone::Warn,
                    title: "Détection `IEX`".into(),
                    badges: vec![Badge { text: "42 %".into(), tone: Tone::Danger }],
                    body: vec![
                        Block::Meter { label: "Menace".into(), percent: 42, tone: Tone::Danger },
                        Block::Para("Corps de carte.".into()),
                    ],
                },
            ],
        }
    }
}
