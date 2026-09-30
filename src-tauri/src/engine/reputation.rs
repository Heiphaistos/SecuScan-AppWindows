//! reputation.rs — Soumet l'empreinte des exécutables et scripts du projet aux bases
//! de menaces en ligne (voir `intel`), puis transforme les verdicts en résultats.
//!
//! Seules les empreintes quittent le serveur. Le nombre de fichiers interrogés est
//! plafonné (quotas gratuits : VirusTotal = 4 requêtes / minute).

use crate::engine::intel::{self, IntelConfig, IntelResult, IntelStatus};
use crate::models::{Factor, FileReputation, ScanResult, Severity, VulnCategory, Vulnerability};

/// Fichiers interrogés au maximum par scan (binaires d'abord).
const MAX_FILES: usize = 5;

/// Probabilité qu'un verdict de source soit un vrai positif.
fn source_confidence(s: &IntelResult) -> Option<u8> {
    let name = s.source.as_str();
    Some(match s.status {
        IntelStatus::Malicious if name.starts_with("MalwareBazaar") => 98,
        IntelStatus::Malicious if name.starts_with("ThreatFox") => 95,
        IntelStatus::Malicious if name == "VirusTotal" || name.starts_with("MetaDefender") => {
            if s.detections.unwrap_or(0) >= 10 { 97 } else { 82 }
        }
        IntelStatus::Malicious if name.starts_with("Kaspersky") => 90,
        IntelStatus::Malicious if name.starts_with("Team Cymru") => 88,
        IntelStatus::Malicious if name.starts_with("Hybrid") => 85,
        IntelStatus::Malicious => 72,
        IntelStatus::Suspicious if name == "VirusTotal" || name.starts_with("MetaDefender") => 28,
        IntelStatus::Suspicious => 40,
        _ => return None,
    })
}

fn summarize(sources: &[IntelResult]) -> String {
    let count = |st: IntelStatus| sources.iter().filter(|s| s.status == st).count();
    let (mal, susp, good, clean) = (
        count(IntelStatus::Malicious),
        count(IntelStatus::Suspicious),
        count(IntelStatus::KnownGood),
        count(IntelStatus::Clean),
    );
    if mal > 0 {
        format!("{mal} base(s) classent ce fichier comme malveillant.")
    } else if susp > 0 {
        format!("{susp} base(s) émettent un signal faible (souvent un faux positif isolé).")
    } else if good > 0 {
        "Référencé comme fichier légitime connu.".into()
    } else if clean > 0 {
        "Analysé par des antivirus en ligne, aucune détection.".into()
    } else if sources.iter().any(|s| matches!(s.status, IntelStatus::NotFound)) {
        "Inconnu des bases consultées (normal pour un fichier propre au projet).".into()
    } else {
        "Aucune base en ligne n'a pu être consultée.".into()
    }
}

/// Interroge les bases en ligne et ajoute les résultats au scan.
pub async fn enrich(result: &mut ScanResult, cfg: &IntelConfig) {
    if cfg.enabled_sources().is_empty() {
        return;
    }
    let mut candidates = std::mem::take(&mut result.intel_candidates);
    candidates.sort_by_key(|c| !c.is_binary);
    candidates.dedup_by(|a, b| a.sha256 == b.sha256);

    for c in candidates.into_iter().take(MAX_FILES) {
        let report = intel::lookup_all(&c.sha256, &c.md5, cfg).await;
        let sources: Vec<IntelResult> = report
            .sources
            .into_iter()
            .filter(|s| s.status != IntelStatus::NotConfigured)
            .collect();

        let hits: Vec<(&IntelResult, u8)> =
            sources.iter().filter_map(|s| source_confidence(s).map(|c| (s, c))).collect();
        if let Some(best) = hits.iter().map(|(_, c)| *c).max() {
            let names: Vec<String> = hits
                .iter()
                .map(|(s, _)| {
                    let detail = match (s.detections, s.total) {
                        (Some(d), Some(t)) => format!(" ({d}/{t})"),
                        _ => String::new(),
                    };
                    format!("{}{detail}", s.source)
                })
                .collect();
            let threats: Vec<String> = hits.iter().flat_map(|(s, _)| s.threat_names.iter().cloned()).take(6).collect();
            let mut v = Vulnerability::new(
                c.file_path.clone(),
                if best >= 80 { Severity::Critical } else if best >= 40 { Severity::High } else { Severity::Medium },
                VulnCategory::MalwareIndicator,
                "Réputation en ligne — fichier signalé par des bases de menaces",
                format!(
                    "L'empreinte exacte de ce fichier est connue : {}.{}",
                    names.join(", "),
                    if threats.is_empty() { String::new() } else { format!(" Noms de détection : {}.", threats.join(", ")) }
                ),
                "Ne pas exécuter ce fichier. Le supprimer du projet ou le remplacer par une version officielle, \
                 puis vérifier sa provenance (dépendance compromise, commit suspect).",
            )
            .with_snippet(format!("SHA-256 : {}", c.sha256));
            v.base_confidence = best;
            v.confidence_factors = hits
                .iter()
                .map(|(s, conf)| Factor { label: format!("{} : {} (fiabilité {} %)", s.source, s.summary, conf), delta: 0 })
                .collect();
            result.vulnerabilities.push(v);
        }

        result.reputation.push(FileReputation {
            file_path: c.file_path,
            sha256: c.sha256,
            summary: summarize(&sources),
            sources,
        });
    }
}
