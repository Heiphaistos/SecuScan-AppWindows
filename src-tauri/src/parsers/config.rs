//! Config / Secret parser — .env, .json, .yaml, .xml, .ini, .bak, .config
//! Detects: hardcoded API keys, passwords, JWTs, connection strings, high-entropy secrets.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

use crate::models::{Severity, VulnCategory, Vulnerability};
use super::context_snippet;

struct Rule {
    pattern:     Regex,
    severity:    Severity,
    category:    VulnCategory,
    title:       &'static str,
    description: &'static str,
    remediation: &'static str,
}

fn get_rules() -> &'static Vec<Rule> {
    static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
        macro_rules! r {
            ($rx:expr, $sev:expr, $cat:expr, $t:expr, $d:expr, $f:expr) => {
                Rule {
                    pattern:     Regex::new($rx).expect("bad config regex"),
                    severity:    $sev,
                    category:    $cat,
                    title:       $t,
                    description: $d,
                    remediation: $f,
                }
            };
        }
        vec![
            // ── AWS ──────────────────────────────────────────────────────
            r!(
                r"AKIA[0-9A-Z]{16}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "AWS Access Key ID",
                "AWS IAM Access Key found in config/source. Full account compromise if exposed.",
                "Rotate key immediately via AWS IAM console. Store in AWS Secrets Manager or env var."
            ),
            r!(
                r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?"#,
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "AWS Secret Access Key",
                "AWS Secret Access Key found. Combined with key ID gives full API access.",
                "Rotate immediately. Use IAM roles / instance profiles instead of static keys."
            ),
            // ── OpenAI ───────────────────────────────────────────────────
            r!(
                r"sk-[A-Za-z0-9]{48,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "OpenAI API Key",
                "OpenAI secret key found. Allows billing abuse and model access.",
                "Rotate at platform.openai.com. Store in environment variable."
            ),
            // ── Google ───────────────────────────────────────────────────
            r!(
                r"AIza[0-9A-Za-z_\-]{35}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Google API Key",
                "Google Cloud / Firebase API key found.",
                "Restrict key in GCP console. Rotate and store in Secret Manager."
            ),
            // ── Anthropic ────────────────────────────────────────────────
            r!(
                r"sk-ant-api[0-9A-Za-z_\-]{20,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Anthropic API Key",
                "Anthropic Claude API key found in file.",
                "Rotate at console.anthropic.com. Use environment variable ANTHROPIC_API_KEY."
            ),
            // ── Stripe ───────────────────────────────────────────────────
            r!(
                r"(sk|pk)_(test|live)_[A-Za-z0-9]{24,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Stripe Secret/Publishable Key",
                "Stripe API key found. sk_live → full account takeover.",
                "Rotate at dashboard.stripe.com. sk_live keys must stay server-side only."
            ),
            // ── GitHub ───────────────────────────────────────────────────
            r!(
                r"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9]{20,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "GitHub Personal Access Token",
                "GitHub PAT found. Allows repo access at the PAT's permission level.",
                "Revoke at github.com/settings/tokens. Use GitHub Actions secrets for CI."
            ),
            // ── Slack ────────────────────────────────────────────────────
            r!(
                r"https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[A-Za-z0-9]{24,}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Slack Webhook URL",
                "Slack incoming webhook URL exposed. Allows sending messages to the channel.",
                "Rotate webhook in Slack app settings. Remove from version-controlled files."
            ),
            // ── JWT ──────────────────────────────────────────────────────
            r!(
                r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                Severity::High, VulnCategory::JwtExposed,
                "JWT Token Exposed",
                "JSON Web Token found in config/backup. If valid, attacker can impersonate the user.",
                "Invalidate the token server-side. Never commit tokens. Ensure short expiry."
            ),
            // ── Passwords ────────────────────────────────────────────────
            r!(
                r#"(?i)(password|passwd|pwd|db_pass|database_password|secret_key)\s*[=:]\s*["']?[^\s"']{8,}["']?"#,
                Severity::High, VulnCategory::PasswordLeak,
                "Hardcoded Password in Config",
                "Plain-text password assignment found in configuration file.",
                "Move to environment variable or secrets manager. Ensure .env is in .gitignore."
            ),
            // ── DB connection strings ─────────────────────────────────────
            r!(
                r#"(?i)(mongodb(\+srv)?|mysql|postgresql|postgres|mssql|redis|amqp)://[^:]+:[^@]+@[^\s"']+"#,
                Severity::Critical, VulnCategory::ConnectionStringLeak,
                "Database Connection String with Credentials",
                "Connection string including username and password found. Direct DB access possible.",
                "Remove credentials from connection string. Use environment variables or secrets manager."
            ),
            r!(
                r#"(?i)(Data\s+Source|Server|Initial\s+Catalog)=[^;]+;\s*(User\s+(Id|ID)|uid)=[^;]+;\s*(Password|Pwd)=[^;]+"#,
                Severity::Critical, VulnCategory::ConnectionStringLeak,
                "ADO.NET Connection String with Credentials",
                ".NET/ADO.NET connection string containing username and password.",
                "Use Windows Authentication or store credentials in Azure Key Vault / environment."
            ),
            // ── Private keys ──────────────────────────────────────────────
            r!(
                r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) (PRIVATE )?KEY-----",
                Severity::Critical, VulnCategory::HardcodedSecret,
                "Private Key Material",
                "SSH or TLS private key found in file. Critical if version-controlled.",
                "Remove immediately. Rotate all associated keys/certificates."
            ),
            // ── Generic signing keys ───────────────────────────────────────
            r!(
                r#"(?i)(SECRET|PRIVATE|SIGNING)[_-]?KEY\s*[=:]\s*["'][a-zA-Z0-9+/=_\-]{20,}["']"#,
                Severity::High, VulnCategory::HardcodedSecret,
                "Hardcoded Signing / Secret Key",
                "Application-level signing or secret key hardcoded in config.",
                "Rotate key. Store in environment variable or secrets manager."
            ),
            // ── Slack bot / app token ─────────────────────────────────────
            r!(
                r"xox[baprs]-[0-9A-Za-z-]{10,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Slack Bot / App Token",
                "Slack token (xoxb/xoxa/xoxp/xoxr/xoxs) exposed. Grants workspace API access.",
                "Revoke in Slack app settings. Store in a secrets manager."
            ),
            // ── GitLab PAT ────────────────────────────────────────────────
            r!(
                r"glpat-[0-9A-Za-z_\-]{20,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "GitLab Personal Access Token",
                "GitLab PAT exposed. Grants repo/API access at the token's scope.",
                "Revoke at gitlab.com/-/profile/personal_access_tokens. Use CI/CD variables."
            ),
            // ── Telegram bot token ────────────────────────────────────────
            r!(
                r"[0-9]{8,10}:AA[0-9A-Za-z_\-]{32,}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Telegram Bot Token",
                "Telegram bot API token exposed. Allows full control of the bot.",
                "Revoke via @BotFather (/revoke). Store token in environment variable."
            ),
            // ── SendGrid ──────────────────────────────────────────────────
            r!(
                r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "SendGrid API Key",
                "SendGrid API key exposed. Allows sending email as the account (phishing risk).",
                "Revoke at app.sendgrid.com. Store in secrets manager."
            ),
            // ── Twilio ────────────────────────────────────────────────────
            r!(
                r"SK[0-9a-fA-F]{32}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Twilio API Key SID",
                "Twilio API key SID exposed. Combined with secret, allows SMS/voice billing abuse.",
                "Rotate at console.twilio.com. Store credentials server-side only."
            ),
            // ── npm token ─────────────────────────────────────────────────
            r!(
                r"npm_[0-9A-Za-z]{36}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "npm Access Token",
                "npm automation/publish token exposed. Allows package publish (supply-chain risk).",
                "Revoke at npmjs.com/settings/tokens. Use CI secrets."
            ),
            // ── Google OAuth client secret ────────────────────────────────
            r!(
                r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Google OAuth Client ID",
                "Google OAuth client identifier exposed; if paired with client secret, enables token issuance.",
                "Restrict the client in GCP console. Keep client secret server-side."
            ),
            // ── Hardcoded HS256 JWT secret ────────────────────────────────
            r!(
                r#"(?i)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*["'][^"']{8,}["']"#,
                Severity::High, VulnCategory::HardcodedSecret,
                "Hardcoded JWT Signing Secret",
                "JWT signing secret hardcoded. Anyone with it can forge valid tokens for any user.",
                "Move to environment variable. Rotate the secret and invalidate existing tokens."
            ),
            // ── Azure Storage account key ─────────────────────────────────
            r!(
                r"AccountKey=[A-Za-z0-9+/]{86}==",
                Severity::Critical, VulnCategory::ConnectionStringLeak,
                "Azure Storage Account Key",
                "Azure Storage account key found in a connection string. Grants full blob/queue/table access.",
                "Rotate the key in the Azure portal. Use SAS tokens or Managed Identity instead."
            ),
            // ── DigitalOcean PAT ──────────────────────────────────────────
            r!(
                r"dop_v1_[a-f0-9]{64}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "DigitalOcean Personal Access Token",
                "DigitalOcean API token exposed. Allows full control of droplets and resources.",
                "Revoke at cloud.digitalocean.com/account/api. Store in a secrets manager."
            ),
            // ── Mailgun API key ───────────────────────────────────────────
            r!(
                r"key-[0-9a-zA-Z]{32}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Mailgun API Key",
                "Mailgun API key exposed. Allows sending email as the account (phishing risk).",
                "Rotate at app.mailgun.com. Store server-side only."
            ),
            // ── Datadog API key ───────────────────────────────────────────
            r!(
                r#"(?i)(datadog|dd[_-]?api[_-]?key)["'\s:=]{1,6}[a-f0-9]{32}"#,
                Severity::High, VulnCategory::ApiKeyLeak,
                "Datadog API Key",
                "Datadog API key exposed. Allows metric/log ingestion and account data access.",
                "Rotate at app.datadoghq.com/organization-settings/api-keys. Store in a secrets manager."
            ),
            // ── Heroku API key ────────────────────────────────────────────
            r!(
                r#"(?i)heroku[a-z0-9_ \-]{0,15}["'\s:=]{1,4}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Heroku API Key",
                "Heroku API key (UUID) exposed. Grants control of apps and add-ons.",
                "Revoke via `heroku authorizations`. Store in config vars, not source."
            ),
            // ── Cloudflare API token ──────────────────────────────────────
            r!(
                r#"(?i)(cloudflare|cf[_-]?api[_-]?token)["'\s:=]{1,6}[A-Za-z0-9_\-]{40}"#,
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Cloudflare API Token",
                "Cloudflare API token exposed. Allows DNS/zone/security changes at the token's scope.",
                "Revoke at dash.cloudflare.com/profile/api-tokens. Use least-privilege scoped tokens."
            ),
        ]
    });
    &RULES
}

// ─── Shannon entropy ──────────────────────────────────────────────────────────

fn shannon_entropy(s: &str) -> f64 {
    if s.len() < 10 { return 0.0; }
    let len = s.len() as f64;
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for b in s.bytes() { *freq.entry(b).or_insert(0) += 1; }
    freq.values().fold(0.0_f64, |acc, &f| {
        let p = f as f64 / len;
        acc - p * p.log2()
    })
}

fn detect_high_entropy(path: &str, text: &str, lines: &[&str]) -> Vec<Vulnerability> {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"["']([A-Za-z0-9+/=_\-@#$%^&*!]{20,80})["']"#).unwrap()
    });

    let mut findings = Vec::new();
    for m in RE.captures_iter(text) {
        if findings.len() >= 10 { break; }
        let candidate = &m[1];
        let entropy   = shannon_entropy(candidate);
        if entropy > 4.5 {
            let line_idx = text[..m.get(0).unwrap().start()]
                .chars().filter(|&c| c == '\n').count();
            let snippet = context_snippet(lines, line_idx, 1);
            findings.push(
                Vulnerability::new(
                    path,
                    Severity::Medium,
                    VulnCategory::HighEntropyString,
                    "High-Entropy String — Potential Secret",
                    &format!("String with entropy {:.2} (>4.5) found. Possible API key, token, or password.", entropy),
                    "Verify if this is a secret. If so, move to environment variables or secrets manager.",
                )
                .with_line(line_idx + 1)
                .with_snippet(snippet)
                .with_match(candidate.chars().take(40).collect::<String>() + "…"),
            );
        }
    }
    findings
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

pub fn scan_config(path: &Path, content: &[u8]) -> Vec<Vulnerability> {
    let raw = match std::str::from_utf8(content) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };

    // Drop lines >4 KB — anti-backtracking protection (same as sast/script)
    let scratch: String;
    let text: &str = match super::filter_long_lines(raw, 4096) {
        Some(s) => { scratch = s; &scratch }
        None    => raw,
    };

    let lines: Vec<&str> = text.lines().collect();
    let path_str = path.to_string_lossy().to_string();
    let mut findings: Vec<Vulnerability> = Vec::new();

    for rule in get_rules() {
        // FIX VULN 10 — Limite de 20 matches par règle (cohérent avec sast/script)
        let mut matches_for_rule = 0usize;
        for m in rule.pattern.find_iter(text) {
            if matches_for_rule >= 20 { break; }
            let line_idx = text[..m.start()].chars().filter(|&c| c == '\n').count();
            let snippet  = context_snippet(&lines, line_idx, 1);
            let matched  = m.as_str().chars().take(100).collect::<String>();
            findings.push(
                Vulnerability::new(
                    &path_str,
                    rule.severity.clone(),
                    rule.category.clone(),
                    rule.title,
                    rule.description,
                    rule.remediation,
                )
                .with_line(line_idx + 1)
                .with_snippet(snippet)
                .with_match(matched),
            );
            matches_for_rule += 1;
        }
    }

    if findings.len() < 20 {
        findings.extend(detect_high_entropy(&path_str, text, &lines));
    }

    findings
}

pub fn handles_extension(ext: &str) -> bool {
    matches!(ext.to_lowercase().as_str(),
        "env"  | "bak" | "backup" | "json" | "yaml" | "yml" |
        "xml"  | "ini" | "cfg"    | "conf" | "config" | "toml" |
        "properties" | "plist" | "htpasswd" | "netrc" | "npmrc" |
        "dockerignore" | "gitconfig"
    )
}
