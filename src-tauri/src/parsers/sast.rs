//! SAST parser — Source code security analysis.

use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use crate::models::{Severity, VulnCategory, Vulnerability};
use super::context_snippet;

// ─── Compiled rule ────────────────────────────────────────────────────────────

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
                    pattern:     Regex::new($rx).expect("bad sast regex"),
                    severity:    $sev,
                    category:    $cat,
                    title:       $t,
                    description: $d,
                    remediation: $f,
                }
            };
        }
        vec![
            // ── SQL Injection ──────────────────────────────────────────────
            r!(
                r#"(?i)(execute|exec)\s*\(\s*["']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)"#,
                Severity::Critical, VulnCategory::SqlInjection,
                "SQL Injection — Direct execute()",
                "Raw SQL string passed directly to execute(). Attacker controls query structure.",
                "Use parameterized queries / prepared statements. Never concatenate user input into SQL."
            ),
            r!(
                r#"(?i)["']\s*\+\s*(username|user_?id|email|password|id|input|param|req\.(body|query|params))"#,
                Severity::High, VulnCategory::SqlInjection,
                "SQL Injection — String concatenation in query",
                "User-controlled value concatenated directly into query string.",
                "Replace concatenation with bound parameters (?, $1, @p1…)."
            ),
            r!(
                r#"(?i)f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{[^}]+\}"#,
                Severity::Critical, VulnCategory::SqlInjection,
                "SQL Injection — f-string with user input",
                "Python f-string or format-string used to build SQL.",
                "Use parameterized queries with cursor.execute(sql, params)."
            ),
            // ── XSS ─────────────────────────────────────────────────────
            r!(
                r#"\.innerHTML\s*[+]?=\s*(?!["'`][^"'`]*["'`]\s*[;,])"#,
                Severity::High, VulnCategory::Xss,
                "XSS — Unsafe innerHTML assignment",
                "Dynamic content written to innerHTML without sanitization.",
                "Use textContent, or sanitize with DOMPurify before innerHTML assignment."
            ),
            r!(
                r#"document\.write\s*\([^"'`]"#,
                Severity::High, VulnCategory::Xss,
                "XSS — document.write() with dynamic content",
                "document.write() can inject attacker-controlled HTML.",
                "Avoid document.write(). Use DOM manipulation APIs instead."
            ),
            r!(
                r#"(?i)eval\s*\(\s*(?!["'`])[^)]+\)"#,
                Severity::Critical, VulnCategory::Xss,
                "XSS / RCE — eval() with dynamic expression",
                "eval() executes arbitrary JS. If input is attacker-controlled → RCE in browser.",
                "Replace eval() with JSON.parse() for data, or refactor to remove dynamic code evaluation."
            ),
            r!(
                r#"(?i)(echo|print)\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)"#,
                Severity::Critical, VulnCategory::Xss,
                "XSS — PHP superglobal echoed unescaped",
                "User input from $_GET/$_POST/etc directly printed without encoding.",
                "Use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before echoing user input."
            ),
            r!(
                r#"(?i)dangerouslySetInnerHTML\s*=\s*\{\s*\{"#,
                Severity::Medium, VulnCategory::Xss,
                "XSS — React dangerouslySetInnerHTML",
                "dangerouslySetInnerHTML bypasses React's XSS protection. Verify source is trusted.",
                "Sanitize content with DOMPurify before passing to dangerouslySetInnerHTML."
            ),
            // ── Command Injection ────────────────────────────────────────
            r!(
                r#"(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|shell_exec\(|passthru\(|system\()\s*[^"'`\n]*\+"#,
                Severity::Critical, VulnCategory::CommandInjection,
                "Command Injection — Shell call with string concatenation",
                "User-controlled string concatenated into shell command.",
                "Use shell=False with argument list in subprocess. Validate/whitelist all inputs."
            ),
            // ── Path Traversal ───────────────────────────────────────────
            r!(
                r#"(?i)(open|read_file|include|require|fopen)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"#,
                Severity::High, VulnCategory::PathTraversal,
                "Path Traversal — User input in file open",
                "File path constructed from user input allows directory traversal (../../etc/passwd).",
                "Validate file paths against a whitelist or use realpath() and assert it starts with allowed base."
            ),
            // ── Weak Crypto ───────────────────────────────────────────────
            r!(
                r#"(?i)\b(md5|sha1|des|rc4|3des|blowfish)\s*\("#,
                Severity::Medium, VulnCategory::WeakCrypto,
                "Weak Cryptographic Function",
                "MD5/SHA1/DES/RC4 are cryptographically broken.",
                "Replace with SHA-256+/AES-256-GCM/ChaCha20-Poly1305. For passwords: bcrypt/argon2."
            ),
            r!(
                r#"(?i)(ECB)\s*mode|AES.*ECB"#,
                Severity::High, VulnCategory::WeakCrypto,
                "Insecure Cipher Mode — ECB",
                "ECB mode leaks patterns. Never use for security-sensitive data.",
                "Use AES-GCM or ChaCha20-Poly1305 (authenticated encryption)."
            ),
            r!(
                r#"(?i)random\.(random|randint|randrange|choice)\s*\("#,
                Severity::High, VulnCategory::WeakCrypto,
                "CSPRNG Missing — Non-cryptographic random",
                "Standard random() is not cryptographically secure.",
                "Use secrets.token_hex() (Python), crypto.randomBytes() (Node), rand::thread_rng() (Rust)."
            ),
            // ── CORS ──────────────────────────────────────────────────────
            r!(
                r#"(?i)Access-Control-Allow-Origin[^:]*:\s*\*"#,
                Severity::Medium, VulnCategory::CorsMisconfiguration,
                "CORS — Wildcard origin (*)",
                "Access-Control-Allow-Origin: * allows any website cross-origin requests.",
                "Restrict allowed origins to an explicit whitelist."
            ),
            // ── Insecure Deserialization ──────────────────────────────────
            r!(
                r#"(?i)(pickle\.loads?|yaml\.load\s*\([^,)]+\)|marshal\.loads?|unserialize\()"#,
                Severity::Critical, VulnCategory::InsecureDeserialization,
                "Insecure Deserialization",
                "Deserializing untrusted data can lead to arbitrary code execution.",
                "Use yaml.safe_load(). Never pickle untrusted input. Use JSON for data exchange."
            ),
            // ── Hardcoded Secrets in code ─────────────────────────────────
            r!(
                r#"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"#,
                Severity::Critical, VulnCategory::HardcodedSecret,
                "Hardcoded Private Key",
                "Private key material embedded in source code.",
                "Remove key from code immediately. Rotate the key. Store in secrets manager or HSM."
            ),
            r!(
                r#"(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token)\s*[:=]\s*["'][a-zA-Z0-9_\-./+]{16,}["']"#,
                Severity::Critical, VulnCategory::HardcodedSecret,
                "Hardcoded API Key / Secret",
                "API key or secret token hardcoded in source. Leaked via version control.",
                "Move to environment variables (.env) or a secrets manager. Rotate the exposed key."
            ),
            r!(
                r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}["']"#,
                Severity::High, VulnCategory::HardcodedSecret,
                "Hardcoded Password",
                "Plain-text password found in source code.",
                "Remove from code. Use environment variables. Hash passwords with bcrypt/argon2 at rest."
            ),
            // ── Open Redirect ─────────────────────────────────────────────
            r!(
                r#"(?i)(redirect|location)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"#,
                Severity::Medium, VulnCategory::OpenRedirect,
                "Open Redirect",
                "Redirect destination derived from user input without validation.",
                "Validate redirect URL against a whitelist of allowed domains."
            ),
        ]
    });
    &RULES
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

pub fn scan_source(path: &Path, content: &[u8]) -> Vec<Vulnerability> {
    let text = match std::str::from_utf8(content) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };

    let lines: Vec<&str> = text.lines().collect();
    let mut findings: Vec<Vulnerability> = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    for rule in get_rules() {
        let mut matches_for_rule = 0usize;
        for m in rule.pattern.find_iter(text) {
            if matches_for_rule >= 20 { break; }
            let line_idx = text[..m.start()].chars().filter(|&c| c == '\n').count();
            let snippet  = context_snippet(&lines, line_idx, 2);
            let matched  = m.as_str().chars().take(120).collect::<String>();

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

    findings
}

pub fn handles_extension(ext: &str) -> bool {
    matches!(ext.to_lowercase().as_str(),
        "html" | "htm" | "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" |
        "py"   | "php" | "rb"  | "java" | "cs" | "go"  | "rs"  | "cpp" |
        "c"    | "h"   | "vue" | "svelte" | "kt" | "swift" | "scala" |
        "lua"  | "pl"  | "r"   | "ex" | "exs"
    )
}
