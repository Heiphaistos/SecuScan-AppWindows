//! intel — Réputation d'un fichier auprès de bases de menaces en ligne.
//!
//! Seule l'EMPREINTE (SHA-256 / MD5) quitte la machine, jamais le fichier.
//! Toutes les sources sont interrogées en parallèle, chacune avec son délai :
//! une source lente, en panne ou sans clé ne bloque ni ne fait échouer le scan.
//!
//! | Source                | Type                         | Clé (écran Réglages) |
//! |-----------------------|------------------------------|----------------------|
//! | VirusTotal            | ~70 antivirus                | `vt`                 |
//! | MetaDefender (OPSWAT) | ~20 antivirus                | `metadefender`       |
//! | Hybrid Analysis       | Sandbox (exécution observée) | `hybrid`             |
//! | Kaspersky OpenTIP     | Réputation Kaspersky         | `opentip`            |
//! | AlienVault OTX        | Rapports de menaces          | `otx`                |
//! | MalwareBazaar         | Base d'échantillons malware  | `abusech`            |
//! | ThreatFox             | IOC de campagnes actives     | `abusech`            |
//! | YARAify               | Règles YARA communautaires   | `abusech`            |
//! | Team Cymru MHR        | Agrégat antivirus            | aucune (DoH)         |
//! | CIRCL hashlookup      | Fichiers LÉGITIMES connus    | aucune               |
//!
//! Les clés sont saisies par l'utilisateur et stockées localement (`security::keystore`),
//! jamais dans le binaire. Les deux sources sans clé sont actives par défaut ; une
//! option des Réglages les coupe. Porté du module `intel` de SecuScan-Web.

mod sources;
#[cfg(test)]
mod tests;

use sources::*;

use std::sync::OnceLock;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const USER_AGENT: &str = concat!("heiphaistos-scanner/", env!("CARGO_PKG_VERSION"));
const SOURCE_TIMEOUT: Duration = Duration::from_secs(12);

// ─── Types publics ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntelStatus {
    /// La source classe le fichier comme malveillant.
    Malicious,
    /// Signal faible / partiel (peu de moteurs, règle générique, rapport de menace).
    Suspicious,
    /// Analysé par la source, rien trouvé.
    Clean,
    /// Référencé comme fichier légitime connu (éditeur, NSRL…).
    KnownGood,
    /// Empreinte inconnue de la source.
    NotFound,
    /// Source injoignable, quota atteint, réponse invalide.
    Error,
    /// Pas de clé API configurée sur le serveur.
    NotConfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelResult {
    pub source: String,
    /// Nature de la source (« 70 antivirus », « sandbox »…).
    pub kind: String,
    pub status: IntelStatus,
    pub detections: Option<u32>,
    pub total: Option<u32>,
    #[serde(default)]
    pub threat_names: Vec<String>,
    /// Phrase de synthèse en français.
    pub summary: String,
    #[serde(default)]
    pub details: Vec<String>,
    pub link: Option<String>,
}

impl IntelResult {
    fn new(src: &Source, status: IntelStatus, summary: impl Into<String>) -> Self {
        IntelResult {
            source: src.name.to_string(),
            kind: src.kind.to_string(),
            status,
            detections: None,
            total: None,
            threat_names: Vec::new(),
            summary: summary.into(),
            details: Vec::new(),
            link: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtEngine {
    pub engine: String,
    pub category: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtSignature {
    pub verified: String,
    pub signers: String,
    pub product: String,
    pub description: String,
    pub copyright: String,
}

/// Résultat VirusTotal détaillé (les 5 premiers champs sont historiques).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtResult {
    pub positives: u32,
    pub total: u32,
    pub permalink: String,
    pub scan_date: String,
    pub detection_names: Vec<String>,
    #[serde(default)]
    pub suspicious: u32,
    #[serde(default)]
    pub harmless: u32,
    #[serde(default)]
    pub undetected: u32,
    /// Moteurs ayant signalé le fichier (malicious / suspicious), avec leur nom de détection.
    #[serde(default)]
    pub engines: Vec<VtEngine>,
    #[serde(default)]
    pub popular_threat_label: Option<String>,
    #[serde(default)]
    pub reputation: i64,
    #[serde(default)]
    pub type_description: Option<String>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub first_submission: Option<String>,
    #[serde(default)]
    pub times_submitted: u32,
    #[serde(default)]
    pub signature: Option<VtSignature>,
    /// Verdict « de confiance » de VirusTotal (ex. goodware attesté par un éditeur).
    #[serde(default)]
    pub trusted_verdict: Option<String>,
    #[serde(default)]
    pub sandbox_verdicts: Vec<String>,
    #[serde(default)]
    pub crowdsourced_yara: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IntelConfig {
    pub vt_key: String,
    pub metadefender_key: String,
    pub hybrid_key: String,
    pub opentip_key: String,
    pub otx_key: String,
    pub abusech_key: String,
    pub free_lookups: bool,
}

impl IntelConfig {
    /// Clés saisies dans l'écran Réglages (stockage local chiffré, voir `keystore`).
    pub fn load() -> Self {
        use crate::security::keystore;
        let get = |k: &str| {
            keystore::load_key(k)
                .map_err(|e| log::warn!("intel: clé {k} illisible : {e}"))
                .ok()
                .flatten()
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        IntelConfig {
            vt_key: get("vt"),
            metadefender_key: get("metadefender"),
            hybrid_key: get("hybrid"),
            opentip_key: get("opentip"),
            otx_key: get("otx"),
            abusech_key: get("abusech"),
            free_lookups: keystore::intel_free_lookups(),
        }
    }

    /// Noms des sources actives (journal de démarrage).
    pub fn enabled_sources(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        let on = |k: &str| !k.is_empty();
        if on(&self.vt_key) { v.push("VirusTotal"); }
        if on(&self.metadefender_key) { v.push("MetaDefender"); }
        if on(&self.hybrid_key) { v.push("Hybrid Analysis"); }
        if on(&self.opentip_key) { v.push("Kaspersky OpenTIP"); }
        if on(&self.otx_key) { v.push("AlienVault OTX"); }
        if on(&self.abusech_key) { v.extend(["MalwareBazaar", "ThreatFox", "YARAify"]); }
        if self.free_lookups { v.extend(["Team Cymru MHR", "CIRCL hashlookup"]); }
        v
    }
}

#[derive(Debug, Clone, Default)]
pub struct IntelReport {
    pub sources: Vec<IntelResult>,
}

// ─── Description des sources ──────────────────────────────────────────────────

struct Source {
    name: &'static str,
    kind: &'static str,
    /// Nom de la clé dans l'écran Réglages.
    setting: &'static str,
}

const VT: Source = Source { name: "VirusTotal", kind: "≈70 moteurs antivirus", setting: "VirusTotal" };
const MD: Source = Source { name: "MetaDefender (OPSWAT)", kind: "≈20 moteurs antivirus", setting: "MetaDefender" };
const HA: Source = Source { name: "Hybrid Analysis", kind: "Sandbox (exécution observée)", setting: "Hybrid Analysis" };
const KL: Source = Source { name: "Kaspersky OpenTIP", kind: "Réputation Kaspersky", setting: "Kaspersky OpenTIP" };
const OTX: Source = Source { name: "AlienVault OTX", kind: "Rapports de menaces communautaires", setting: "AlienVault OTX" };
const MB: Source = Source { name: "MalwareBazaar (abuse.ch)", kind: "Base d'échantillons malveillants", setting: "abuse.ch" };
const TF: Source = Source { name: "ThreatFox (abuse.ch)", kind: "Indicateurs de campagnes actives", setting: "abuse.ch" };
const YF: Source = Source { name: "YARAify (abuse.ch)", kind: "Règles YARA communautaires", setting: "abuse.ch" };
const CY: Source = Source { name: "Team Cymru MHR", kind: "Agrégat de détections antivirus", setting: "sources gratuites" };
const CI: Source = Source { name: "CIRCL hashlookup", kind: "Base de fichiers légitimes (NSRL…)", setting: "sources gratuites" };

// ─── HTTP ─────────────────────────────────────────────────────────────────────

static CLIENT: OnceLock<Option<Client>> = OnceLock::new();

fn client() -> Option<&'static Client> {
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .timeout(SOURCE_TIMEOUT)
                .user_agent(USER_AGENT)
                .build()
                .map_err(|e| log::warn!("intel: client HTTP indisponible : {e}"))
                .ok()
        })
        .as_ref()
}

/// Réponse HTTP brute (statut + corps) ou message d'erreur réseau.
async fn send(req: reqwest::RequestBuilder) -> Result<(u16, String), String> {
    let resp = req.send().await.map_err(|e| {
        if e.is_timeout() {
            "délai dépassé".to_string()
        } else {
            "source injoignable".to_string()
        }
    })?;
    let status = resp.status().as_u16();
    // Plafond : aucune source n'a besoin de plus de 4 Mo pour un lookup.
    let bytes = resp.bytes().await.map_err(|_| "réponse interrompue".to_string())?;
    let body = String::from_utf8_lossy(&bytes[..bytes.len().min(4 * 1024 * 1024)]).into_owned();
    Ok((status, body))
}

fn http_error(src: &Source, status: u16) -> IntelResult {
    let msg = match status {
        401 | 403 => "clé API refusée par la source".to_string(),
        429 => "quota de requêtes atteint".to_string(),
        s => format!("erreur HTTP {s}"),
    };
    IntelResult::new(src, IntelStatus::Error, format!("Non disponible : {msg}."))
}

fn net_error(src: &Source, msg: String) -> IntelResult {
    IntelResult::new(src, IntelStatus::Error, format!("Non disponible : {msg}."))
}

fn not_configured(src: &Source) -> IntelResult {
    IntelResult::new(
        src,
        IntelStatus::NotConfigured,
        format!("Non configurée : clé {} absente (à saisir dans Réglages).", src.setting),
    )
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ─── Utilitaires JSON ─────────────────────────────────────────────────────────

fn s(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    match cur {
        Value::String(x) if !x.trim().is_empty() => Some(x.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn n(v: &Value, path: &[&str]) -> Option<i64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_i64().or_else(|| cur.as_str().and_then(|x| x.parse().ok()))
}

fn str_list(v: Option<&Value>, max: usize) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::trim).filter(|x| !x.is_empty()).map(String::from))
                .take(max)
                .collect()
        })
        .unwrap_or_default()
}

fn ts_to_date(ts: i64) -> Option<String> {
    use chrono::TimeZone;
    chrono::Utc.timestamp_opt(ts, 0).single().map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
}

fn push_unique(v: &mut Vec<String>, x: String) {
    if !x.is_empty() && !v.iter().any(|y| y.eq_ignore_ascii_case(&x)) {
        v.push(x);
    }
}

// ─── Orchestration ────────────────────────────────────────────────────────────

/// Interroge toutes les sources en parallèle. N'échoue jamais : chaque source
/// renvoie un statut (y compris « non configurée » / « non disponible »).
pub async fn lookup_all(sha256: &str, md5: &str, cfg: &IntelConfig) -> IntelReport {
    let sha256 = sha256.to_ascii_lowercase();
    let md5 = md5.to_ascii_lowercase();
    // Défense en profondeur : l'empreinte est injectée dans des URL.
    if !is_hex(&sha256, 64) || !is_hex(&md5, 32) {
        return IntelReport::default();
    }

    let sh = sha256.as_str();
    let ((vt_res, _vt), md, ha, kl, ox, mb, tf, yf, cy, ci) = tokio::join!(
        virustotal(sh, &cfg.vt_key),
        metadefender(sh, &cfg.metadefender_key),
        hybrid(sh, &cfg.hybrid_key),
        opentip(sh, &cfg.opentip_key),
        otx(sh, &cfg.otx_key),
        malwarebazaar(sh, &cfg.abusech_key),
        threatfox(sh, &cfg.abusech_key),
        yaraify(sh, &cfg.abusech_key),
        async {
            if cfg.free_lookups { Some(cymru(&md5).await) } else { None }
        },
        async {
            if cfg.free_lookups { Some(circl(sh).await) } else { None }
        },
    );

    let mut sources = vec![vt_res, md, ha, kl, ox, mb, tf, yf];
    sources.extend(cy);
    sources.extend(ci);
    // Ordre d'affichage : verdicts utiles d'abord, sources muettes à la fin.
    sources.sort_by_key(|r| match r.status {
        IntelStatus::Malicious => 0,
        IntelStatus::Suspicious => 1,
        IntelStatus::KnownGood => 2,
        IntelStatus::Clean => 3,
        IntelStatus::NotFound => 4,
        IntelStatus::Error => 5,
        IntelStatus::NotConfigured => 6,
    });
    IntelReport { sources }
}
