use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Severity ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 10,
            Severity::High     => 7,
            Severity::Medium   => 5,
            Severity::Low      => 2,
            Severity::Info     => 0,
        }
    }
}

// ─── Vulnerability category ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnCategory {
    // SAST — source code
    SqlInjection,
    Xss,
    InsecureDeserialization,
    WeakCrypto,
    CorsMisconfiguration,
    HardcodedSecret,
    OpenRedirect,
    PathTraversal,
    CommandInjection,
    // Scripts
    PrivilegeEscalation,
    ObfuscatedCommand,
    AntivirusDisabled,
    PayloadDownload,
    ArbitraryCodeExecution,
    // Config / secrets
    ApiKeyLeak,
    PasswordLeak,
    JwtExposed,
    ConnectionStringLeak,
    HighEntropyString,
    // Binary
    MissingAslr,
    MissingDep,
    InvalidSignature,
    MalwareIndicator,
    DllInjection,
    SuspiciousPersistence,
    RansomwareIndicator,
    // General
    SensitiveDataExposure,
    InsecureConfiguration,
}

impl VulnCategory {
    pub fn cwe(&self) -> Option<&'static str> {
        match self {
            VulnCategory::SqlInjection            => Some("CWE-89"),
            VulnCategory::Xss                     => Some("CWE-79"),
            VulnCategory::InsecureDeserialization => Some("CWE-502"),
            VulnCategory::WeakCrypto              => Some("CWE-327"),
            VulnCategory::CorsMisconfiguration    => Some("CWE-346"),
            VulnCategory::HardcodedSecret         => Some("CWE-798"),
            VulnCategory::OpenRedirect            => Some("CWE-601"),
            VulnCategory::PathTraversal           => Some("CWE-22"),
            VulnCategory::CommandInjection        => Some("CWE-78"),
            VulnCategory::PrivilegeEscalation     => Some("CWE-269"),
            VulnCategory::PasswordLeak            => Some("CWE-256"),
            VulnCategory::ApiKeyLeak              => Some("CWE-312"),
            VulnCategory::JwtExposed              => Some("CWE-522"),
            VulnCategory::ConnectionStringLeak    => Some("CWE-312"),
            VulnCategory::MissingAslr             => Some("CWE-119"),
            VulnCategory::MissingDep              => Some("CWE-693"),
            VulnCategory::DllInjection            => Some("CWE-114"),
            _                                     => None,
        }
    }
}

// ─── Core vulnerability struct ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id:              String,
    pub file_path:       String,
    pub line_number:     Option<usize>,
    pub column:          Option<usize>,
    pub severity:        Severity,
    pub category:        VulnCategory,
    pub title:           String,
    pub description:     String,
    pub code_snippet:    Option<String>,
    pub matched_pattern: Option<String>,
    pub remediation:     String,
    pub cwe_id:          Option<String>,
    pub ai_explanation:  Option<String>,
    pub ai_fix:          Option<String>,
    /// Probabilité (%) que le problème soit réel (vrai positif).
    #[serde(default)]
    pub confidence:      u8,
    /// Probabilité (%) de faux positif (= 100 − confidence).
    #[serde(default)]
    pub false_positive:  u8,
    #[serde(default)]
    pub confidence_label: String,
    /// Ce que fait concrètement le code / la commande détectée.
    #[serde(default)]
    pub what_it_does:    String,
    /// Pourquoi c'est probablement un vrai problème.
    #[serde(default)]
    pub why_real:        String,
    /// Pourquoi ça peut être un faux positif.
    #[serde(default)]
    pub why_false_positive: String,
    #[serde(default)]
    pub base_confidence: u8,
    #[serde(default)]
    pub confidence_factors: Vec<Factor>,
}

/// Ajustement appliqué à une probabilité, avec sa justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    pub label: String,
    pub delta: i16,
}

impl Vulnerability {
    pub fn new(
        file_path:   impl Into<String>,
        severity:    Severity,
        category:    VulnCategory,
        title:       impl Into<String>,
        description: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let cwe = category.cwe().map(str::to_string);
        Self {
            id:              Uuid::new_v4().to_string(),
            file_path:       file_path.into(),
            line_number:     None,
            column:          None,
            severity,
            category,
            title:           title.into(),
            description:     description.into(),
            code_snippet:    None,
            matched_pattern: None,
            remediation:     remediation.into(),
            cwe_id:          cwe,
            ai_explanation:  None,
            ai_fix:          None,
            confidence:      0,
            false_positive:  0,
            confidence_label: String::new(),
            what_it_does:    String::new(),
            why_real:        String::new(),
            why_false_positive: String::new(),
            base_confidence: 0,
            confidence_factors: Vec::new(),
        }
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.code_snippet = Some(snippet.into());
        self
    }

    pub fn with_match(mut self, m: impl Into<String>) -> Self {
        self.matched_pattern = Some(m.into());
        self
    }
}

// ─── Scan config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_file_size_mb:  f64,
    pub skip_git_dirs:     bool,
    pub skip_node_modules: bool,
    pub scan_executables:  bool,
    pub include_info:      bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb:  50.0,
            skip_git_dirs:     true,
            skip_node_modules: true,
            scan_executables:  true,
            include_info:      false,
        }
    }
}

// ─── Scan result ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub file_path: String,
    pub error:     String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanStats {
    pub critical: usize,
    pub high:     usize,
    pub medium:   usize,
    pub low:      usize,
    pub info:     usize,
}

impl ScanStats {
    pub fn from_vulns(vulns: &[Vulnerability]) -> Self {
        let mut s = Self::default();
        for v in vulns {
            match v.severity {
                Severity::Critical => s.critical += 1,
                Severity::High     => s.high += 1,
                Severity::Medium   => s.medium += 1,
                Severity::Low      => s.low += 1,
                Severity::Info     => s.info += 1,
            }
        }
        s
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned:        usize,
    pub total:          usize,
    pub current_file:   String,
    pub findings_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id:       String,
    pub target_path:   String,
    pub started_at:    DateTime<Utc>,
    pub completed_at:  Option<DateTime<Utc>>,
    pub total_files:   usize,
    pub scanned_files: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub errors:        Vec<ScanError>,
    pub stats:         ScanStats,
    /// Réputation en ligne des binaires / scripts du projet.
    #[serde(default)]
    pub reputation:    Vec<FileReputation>,
    #[serde(default)]
    pub assessment:    ScanAssessment,
    /// Fichiers exécutables / scripts à soumettre aux bases en ligne (usage interne).
    #[serde(skip)]
    pub intel_candidates: Vec<IntelCandidate>,
}

#[derive(Debug, Clone)]
pub struct IntelCandidate {
    pub file_path: String,
    pub sha256:    String,
    pub md5:       String,
    pub is_binary: bool,
}

/// Réputation d'un fichier du projet auprès des bases en ligne.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReputation {
    pub file_path: String,
    pub sha256:    String,
    pub sources:   Vec<crate::engine::intel::IntelResult>,
    pub summary:   String,
}

/// Synthèse chiffrée du scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanAssessment {
    /// Résultats probablement réels (≥ 55 %).
    pub likely_real:     usize,
    /// Résultats à vérifier (30–54 %).
    pub to_review:       usize,
    /// Faux positifs probables (< 30 %).
    pub likely_false_positive: usize,
    /// Probabilité qu'un code MALVEILLANT (virus, script d'attaque) soit présent.
    pub malware_probability: u8,
    pub summary:         String,
    pub method:          String,
}

impl ScanResult {
    pub fn new(target_path: String, total_files: usize) -> Self {
        Self {
            scan_id:         Uuid::new_v4().to_string(),
            target_path,
            started_at:      Utc::now(),
            completed_at:    None,
            total_files,
            scanned_files:   0,
            vulnerabilities: Vec::new(),
            errors:          Vec::new(),
            stats:           ScanStats::default(),
            reputation:      Vec::new(),
            assessment:      ScanAssessment::default(),
            intel_candidates: Vec::new(),
        }
    }

    pub fn finalize(&mut self) {
        self.completed_at = Some(Utc::now());
        self.stats = ScanStats::from_vulns(&self.vulnerabilities);
    }
}

// ─── LLM ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    Claude,
    Gemini,
    Antigravity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFixRequest {
    pub vulnerability_id: String,
    pub provider:         LlmProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFixResult {
    pub vulnerability_id: String,
    pub explanation:      String,
    pub fixed_code:       String,
    pub provider:         LlmProvider,
}

/// One corrected file produced by the batch AI fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePatch {
    pub file_path:        String,
    pub original_content: String,
    pub patched_content:  String,
    pub summary:          String,
    /// IDs of vulnerabilities targeted by this patch
    pub vuln_ids:         Vec<String>,
    /// True = patch was successfully applied to disk
    pub applied:          bool,
}

/// Progress event emitted during batch fix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFixProgress {
    pub file_idx:     usize,
    pub total_files:  usize,
    pub current_file: String,
    pub status:       String, // "processing" | "done" | "error"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeys {
    pub claude_key:             Option<String>,
    pub gemini_key:             Option<String>,
    pub antigravity_key:        Option<String>,
    pub antigravity_endpoint:   Option<String>,
}
