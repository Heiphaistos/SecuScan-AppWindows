//! Export des rapports — JSON, CSV, Markdown, texte, HTML et PDF.
//!
//! Markdown, texte, HTML et PDF sont rendus depuis UN même document (`report::Doc`) :
//! ils contiennent exactement les mêmes informations — synthèse chiffrée, réputation
//! en ligne, et pour chaque résultat sa probabilité d'être réel ou faux positif,
//! ce que fait le code, les arguments pour et contre, le calcul et la correction.

use crate::engine::confidence::severity_fr;
use crate::engine::intel::IntelStatus;
use crate::models::{ScanResult, Severity, VulnCategory, Vulnerability};
use crate::report::{self, Badge, Block, Cell, Doc, Tone};

/// Au-delà, le rapport resterait lisible mais ferait des centaines de pages.
const MAX_CARDS: usize = 300;
const MAX_TABLE_ROWS: usize = 1000;

// ─── JSON ──────────────────────────────────────────────────────────────────────

pub fn to_json(result: &ScanResult) -> Result<String, String> {
    serde_json::to_string_pretty(result).map_err(|e| e.to_string())
}

// ─── CSV ───────────────────────────────────────────────────────────────────────

pub fn to_csv(result: &ScanResult) -> String {
    let mut out = String::from(
        "ID,Gravité,Catégorie,Titre,Fichier,Ligne,CWE,% réel,% faux positif,Verdict,Description,Correction\n",
    );

    for v in &result.vulnerabilities {
        let row = format!(
            "{},{:?},{:?},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&v.id),
            v.severity,
            v.category,
            csv_escape(&v.title),
            csv_escape(&v.file_path),
            v.line_number.map(|n| n.to_string()).unwrap_or_default(),
            csv_escape(v.cwe_id.as_deref().unwrap_or("")),
            v.confidence,
            v.false_positive,
            csv_escape(&v.confidence_label),
            csv_escape(&v.description),
            csv_escape(&v.remediation),
        );
        out.push_str(&row);
    }

    out
}

fn csv_escape(s: &str) -> String {
    // Injection de formule : Excel et LibreOffice exécutent une cellule qui
    // commence par = + - @ ou une tabulation. Préfixer par une apostrophe la
    // neutralise sans changer le texte affiché.
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };

    if guarded.contains(',') || guarded.contains('"') || guarded.contains('\n') {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

// ─── Document commun ──────────────────────────────────────────────────────────

fn severity_tone(s: &Severity) -> Tone {
    match s {
        Severity::Critical => Tone::Critical,
        Severity::High => Tone::Danger,
        Severity::Medium => Tone::Warn,
        Severity::Low => Tone::Info,
        Severity::Info => Tone::Neutral,
    }
}

/// Tonalité d'une probabilité d'être un VRAI problème.
fn real_tone(p: u8) -> Tone {
    Tone::for_threat(p)
}

pub fn category_fr(c: &VulnCategory) -> &'static str {
    use VulnCategory::*;
    match c {
        SqlInjection => "Injection SQL",
        Xss => "XSS",
        InsecureDeserialization => "Désérialisation non sûre",
        WeakCrypto => "Cryptographie faible",
        CorsMisconfiguration => "CORS mal configuré",
        HardcodedSecret => "Secret en dur",
        OpenRedirect => "Redirection ouverte",
        PathTraversal => "Traversée de répertoire",
        CommandInjection => "Injection de commande",
        PrivilegeEscalation => "Élévation de privilèges",
        ObfuscatedCommand => "Commande obfusquée",
        AntivirusDisabled => "Antivirus désactivé",
        PayloadDownload => "Téléchargement de charge",
        ArbitraryCodeExecution => "Exécution de code",
        ApiKeyLeak => "Fuite de clé API",
        PasswordLeak => "Fuite de mot de passe",
        JwtExposed => "JWT exposé",
        ConnectionStringLeak => "Chaîne de connexion exposée",
        HighEntropyString => "Chaîne à haute entropie",
        MissingAslr => "ASLR absent",
        MissingDep => "DEP absent",
        InvalidSignature => "Signature invalide",
        MalwareIndicator => "Indicateur de malware",
        DllInjection => "Injection DLL",
        SuspiciousPersistence => "Persistance suspecte",
        RansomwareIndicator => "Indicateur de rançongiciel",
        SensitiveDataExposure => "Exposition de données",
        InsecureConfiguration => "Configuration non sûre",
    }
}

fn intel_label(s: IntelStatus) -> (&'static str, Tone) {
    match s {
        IntelStatus::Malicious => ("MALVEILLANT", Tone::Critical),
        IntelStatus::Suspicious => ("SUSPECT", Tone::Warn),
        IntelStatus::Clean => ("RIEN TROUVÉ", Tone::Good),
        IntelStatus::KnownGood => ("LÉGITIME CONNU", Tone::Good),
        IntelStatus::NotFound => ("INCONNU", Tone::Neutral),
        IntelStatus::Error => ("INDISPONIBLE", Tone::Neutral),
        IntelStatus::NotConfigured => ("NON CONFIGURÉ", Tone::Neutral),
    }
}

fn location(v: &Vulnerability) -> String {
    match v.line_number {
        Some(l) => format!("{}:{l}", v.file_path),
        None => v.file_path.clone(),
    }
}

fn finding_card(i: usize, v: &Vulnerability) -> Block {
    let tone = real_tone(v.confidence);
    let mut calc = vec![format!("Probabilité de départ pour cette règle : {} %", v.base_confidence)];
    for f in &v.confidence_factors {
        if f.delta == 0 {
            calc.push(f.label.clone());
        } else {
            calc.push(format!("{:+} points : {}", f.delta, f.label));
        }
    }
    calc.push(format!(
        "Résultat : {} % de probabilité que ce soit un vrai problème → {} % de faux positif",
        v.confidence, v.false_positive
    ));

    let mut kv = vec![
        ("Conclusion".to_string(), v.confidence_label.clone()),
        ("Emplacement".to_string(), location(v)),
        ("Catégorie".to_string(), category_fr(&v.category).to_string()),
        ("Gravité si réel".to_string(), severity_fr(&v.severity).to_string()),
    ];
    if let Some(c) = &v.cwe_id {
        kv.push(("Référence".into(), c.clone()));
    }
    if let Some(m) = &v.matched_pattern {
        if !m.is_empty() {
            kv.push(("Élément détecté".into(), m.clone()));
        }
    }

    let mut body = vec![
        Block::Meter { label: "Probabilité que ce soit un vrai problème".into(), percent: v.confidence, tone },
        Block::Meter { label: "Probabilité de faux positif".into(), percent: v.false_positive, tone: Tone::Good },
        Block::KeyValues { items: kv, mono: false },
        Block::Heading(2, "Ce que fait ce code".into()),
        Block::Para(v.what_it_does.clone()),
        Block::Heading(2, "Détail technique de la règle".into()),
        Block::Para(v.description.clone()),
        Block::Heading(2, "Pourquoi c'est probablement un vrai problème".into()),
        Block::Para(v.why_real.clone()),
        Block::Heading(2, "Pourquoi ça peut être un faux positif".into()),
        Block::Para(v.why_false_positive.clone()),
    ];
    if let Some(expl) = &v.ai_explanation {
        body.push(Block::Heading(2, "Impact en clair".into()));
        body.push(Block::Para(expl.clone()));
    }
    body.push(Block::Heading(2, "Calcul du pourcentage".into()));
    body.push(Block::Bullets(calc));
    body.push(Block::Heading(2, "Correction recommandée".into()));
    body.push(Block::Para(v.remediation.clone()));
    if let Some(fix) = &v.ai_fix {
        body.push(Block::Para(fix.clone()));
    }
    if let Some(snip) = &v.code_snippet {
        body.push(Block::Heading(2, "Extrait".into()));
        body.push(Block::Code(snip.clone()));
    }

    Block::Card {
        tone,
        title: format!("{}. {}", i + 1, v.title),
        badges: vec![
            Badge { text: severity_fr(&v.severity).to_string(), tone: severity_tone(&v.severity) },
            Badge { text: format!("Réel {} %", v.confidence), tone },
            Badge { text: format!("Faux positif {} %", v.false_positive), tone: Tone::Good },
        ],
        body,
    }
}

pub fn build(r: &ScanResult) -> Doc {
    let a = &r.assessment;
    let s = &r.stats;
    let mut b: Vec<Block> = Vec::new();
    let total = r.vulnerabilities.len();

    // ── Synthèse ──
    let malware = a.malware_probability;
    let (tone, title) = if malware >= 65 {
        (Tone::Critical, "Code malveillant probable dans le projet")
    } else if a.likely_real > 0 && (s.critical > 0 || s.high > 0) {
        (Tone::Danger, "Problèmes de sécurité probablement réels à corriger")
    } else if a.likely_real > 0 || a.to_review > 0 {
        (Tone::Warn, "Quelques points à vérifier")
    } else if total > 0 {
        (Tone::Good, "Résultats majoritairement des faux positifs probables")
    } else {
        (Tone::Good, "Aucun problème détecté")
    };
    b.push(Block::Callout {
        tone,
        title: title.into(),
        lines: vec![if a.summary.is_empty() { format!("{total} résultat(s).") } else { a.summary.clone() }],
    });
    b.push(Block::Stats(vec![
        (a.likely_real.to_string(), "Probablement réels (≥ 55 %)".into(), if a.likely_real > 0 { Tone::Danger } else { Tone::Good }),
        (a.to_review.to_string(), "À vérifier (30–54 %)".into(), Tone::Warn),
        (a.likely_false_positive.to_string(), "Faux positifs probables (< 30 %)".into(), Tone::Good),
        (format!("{malware} %"), "Probabilité de code malveillant".into(), Tone::for_threat(malware)),
    ]));
    b.push(Block::Meter {
        label: "Probabilité qu'un code malveillant (virus, script d'attaque) soit présent".into(),
        percent: malware,
        tone: Tone::for_threat(malware),
    });
    b.push(Block::Table {
        headers: vec!["Critique".into(), "Élevée".into(), "Moyenne".into(), "Faible".into(), "Info".into(), "Total".into()],
        rows: vec![vec![
            Cell::toned(s.critical.to_string(), Tone::Critical),
            Cell::toned(s.high.to_string(), Tone::Danger),
            Cell::toned(s.medium.to_string(), Tone::Warn),
            Cell::new(s.low.to_string()),
            Cell::new(s.info.to_string()),
            Cell::new(s.total().to_string()),
        ]],
        widths: vec![1.0; 6],
    });
    b.push(Block::Note(
        "« Gravité » = impact SI le problème est réel. « Réel % » = probabilité que ce soit un vrai problème ; \
         « Faux positif % » = probabilité que ce soit une fausse alerte. Les deux sont indépendants : \
         un résultat critique peut être un faux positif très probable (clé d'exemple dans un test…)."
            .into(),
    ));

    // ── Projet ──
    b.push(Block::Heading(1, "Projet analysé".into()));
    let mut kv = vec![
        ("Cible".to_string(), r.target_path.clone()),
        ("Date".to_string(), r.started_at.format("%d/%m/%Y à %H:%M:%S UTC").to_string()),
    ];
    if let Some(end) = r.completed_at {
        kv.push(("Durée".into(), format!("{} s", (end - r.started_at).num_seconds().max(0))));
    }
    kv.push(("Fichiers analysés".into(), format!("{} / {}", r.scanned_files, r.total_files)));
    kv.push(("Identifiant du scan".into(), r.scan_id.clone()));
    b.push(Block::KeyValues { items: kv, mono: false });

    // ── Réputation en ligne ──
    if !r.reputation.is_empty() {
        b.push(Block::Heading(1, format!("Réputation en ligne ({} fichier(s) vérifié(s))", r.reputation.len())));
        b.push(Block::Note(
            "Exécutables et scripts du projet : seule leur empreinte SHA-256 / MD5 est envoyée aux bases \
             (VirusTotal, MetaDefender, MalwareBazaar…), jamais le fichier."
                .into(),
        ));
        for fr in &r.reputation {
            b.push(Block::Heading(2, fr.file_path.clone()));
            b.push(Block::Para(fr.summary.clone()));
            if !fr.sources.is_empty() {
                b.push(Block::Table {
                    headers: vec!["Source".into(), "Résultat".into(), "Détails".into()],
                    rows: fr
                        .sources
                        .iter()
                        .map(|src| {
                            let (lab, t) = intel_label(src.status);
                            let mut det = src.summary.clone();
                            if !src.threat_names.is_empty() {
                                det.push_str(&format!("\nNoms : {}", src.threat_names.join(", ")));
                            }
                            for d in src.details.iter().take(3) {
                                det.push('\n');
                                det.push_str(d);
                            }
                            if let Some(l) = &src.link {
                                det.push('\n');
                                det.push_str(l);
                            }
                            vec![Cell::new(format!("{}\n{}", src.source, src.kind)), Cell::toned(lab, t), Cell::new(det)]
                        })
                        .collect(),
                    widths: vec![2.2, 1.4, 5.4],
                });
            }
            b.push(Block::KeyValues { items: vec![("SHA-256".into(), fr.sha256.clone())], mono: true });
        }
    }

    // ── Résultats ──
    b.push(Block::Heading(1, format!("Résultats ({total})")));
    if total == 0 {
        b.push(Block::Para("Aucune vulnérabilité, aucun secret et aucun comportement suspect détecté.".into()));
    } else {
        b.push(Block::Table {
            headers: vec!["#".into(), "Gravité".into(), "Résultat".into(), "Emplacement".into(), "Réel".into(), "Faux positif".into()],
            rows: r
                .vulnerabilities
                .iter()
                .take(MAX_TABLE_ROWS)
                .enumerate()
                .map(|(i, v)| {
                    vec![
                        Cell::new((i + 1).to_string()),
                        Cell::toned(severity_fr(&v.severity), severity_tone(&v.severity)),
                        Cell::new(v.title.clone()),
                        Cell::mono(location(v)),
                        Cell::toned(format!("{} %", v.confidence), real_tone(v.confidence)),
                        Cell::new(format!("{} %", v.false_positive)),
                    ]
                })
                .collect(),
            widths: vec![0.5, 1.1, 3.6, 3.0, 0.9, 1.1],
        });
        if total > MAX_TABLE_ROWS {
            b.push(Block::Note(format!("{} résultat(s) supplémentaire(s) non listé(s) (export JSON/CSV pour la liste complète).", total - MAX_TABLE_ROWS)));
        }
        b.push(Block::Heading(1, "Détail de chaque résultat".into()));
        for (i, v) in r.vulnerabilities.iter().take(MAX_CARDS).enumerate() {
            b.push(finding_card(i, v));
        }
        if total > MAX_CARDS {
            b.push(Block::Note(format!(
                "Les {} résultat(s) suivants ne sont pas détaillés ici pour garder un rapport lisible : exportez en JSON ou CSV pour la liste complète.",
                total - MAX_CARDS
            )));
        }
    }

    if !r.errors.is_empty() {
        b.push(Block::Heading(1, format!("Erreurs d'analyse ({})", r.errors.len())));
        b.push(Block::Table {
            headers: vec!["Fichier".into(), "Erreur".into()],
            rows: r.errors.iter().map(|e| vec![Cell::mono(e.file_path.clone()), Cell::new(e.error.clone())]).collect(),
            widths: vec![1.0, 1.5],
        });
    }

    b.push(Block::Heading(1, "Méthode et limites".into()));
    if !a.method.is_empty() {
        b.push(Block::Para(a.method.clone()));
    }
    b.push(Block::Note(
        "Analyse statique : les pourcentages sont des estimations calibrées et justifiées (voir « Calcul du pourcentage »), \
         pas une certitude. Un scan propre ne garantit pas l'absence totale de faille."
            .into(),
    ));

    Doc {
        app: "SecuScan".into(),
        title: format!("Rapport de sécurité — {}", r.target_path),
        subtitle: format!(
            "{total} résultat(s) · {} probablement réel(s) · code malveillant {malware} %",
            a.likely_real
        ),
        generated_at: chrono::Utc::now().format("%d/%m/%Y %H:%M UTC").to_string(),
        blocks: b,
    }
}

pub fn to_markdown(result: &ScanResult) -> String {
    report::markdown::render(&build(result))
}

pub fn to_txt(result: &ScanResult) -> String {
    report::text::render(&build(result))
}

pub fn to_html(result: &ScanResult) -> String {
    report::html::render(&build(result))
}

pub fn to_pdf(result: &ScanResult) -> Vec<u8> {
    report::pdf::render(&build(result))
}
