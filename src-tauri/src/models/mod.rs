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
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        }
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeys {
    pub claude_key:             Option<String>,
    pub gemini_key:             Option<String>,
    pub antigravity_key:        Option<String>,
    pub antigravity_endpoint:   Option<String>,
}
