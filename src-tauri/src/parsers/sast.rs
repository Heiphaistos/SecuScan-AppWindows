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
            // ── SSRF ──────────────────────────────────────────────────────
            r!(
                r#"(?i)(requests\.(get|post|put)|urllib\.request\.urlopen|fetch|axios\.(get|post)|http\.get|httpclient\.get)\s*\(\s*[^)]{0,40}(req\.(query|params|body)|request\.(args|form|get|post)|\$_(GET|POST|REQUEST))"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "SSRF — Server-side request to user-controlled URL",
                "HTTP client fetches a URL derived from user input. Attacker can reach internal services (169.254.169.254, localhost, cloud metadata).",
                "Whitelist allowed hosts/schemes. Block private IP ranges (10/8, 172.16/12, 192.168/16, 169.254/16) and metadata endpoints."
            ),
            // ── SSTI ──────────────────────────────────────────────────────
            r!(
                r#"(?i)(render_template_string|env\.from_string|new\s+Function)\s*\(\s*[^)]{0,40}(\+|\$\{|%s|\{\{|f["'])"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "SSTI — Server-Side Template Injection",
                "User input concatenated into a template string. Leads to RCE in Jinja2/Twig/Handlebars/Freemarker.",
                "Never build templates from user input. Pass data as template variables, not as template source."
            ),
            // ── XXE ───────────────────────────────────────────────────────
            r!(
                r#"(?i)(libxml_disable_entity_loader\s*\(\s*false|resolve_entities\s*=\s*True|noent\s*=\s*True|XMLParser\([^)]*resolve_entities|DocumentBuilderFactory[^;]{0,80}(?!.*disallow-doctype))"#,
                Severity::High, VulnCategory::InsecureDeserialization,
                "XXE — XML External Entity processing enabled",
                "XML parser resolves external entities, enabling local file disclosure and SSRF via crafted DTD.",
                "Disable DTD/external entities: setFeature('disallow-doctype-decl', true) or defusedxml (Python)."
            ),
            // ── NoSQL Injection ───────────────────────────────────────────
            r!(
                r#"(?i)(find|findone|update|deleteone|deletemany)\s*\(\s*\{[^}]{0,60}(req\.(body|query|params)|\$where)"#,
                Severity::High, VulnCategory::SqlInjection,
                "NoSQL Injection — User input in query object",
                "Raw user input placed into a MongoDB query object. Operators like $ne/$gt/$where bypass authentication.",
                "Cast/validate input types. Reject query operators from user input. Enforce an ODM schema."
            ),
            // ── LDAP Injection ────────────────────────────────────────────
            r!(
                r#"(?i)(search|bind)\s*\([^)]{0,60}(\(uid=|\(cn=|\(&)[^)]{0,40}(\+|\$\{|%s|f["'])"#,
                Severity::High, VulnCategory::CommandInjection,
                "LDAP Injection — Filter built from user input",
                "LDAP filter concatenated with user input allows authentication bypass and directory data extraction.",
                "Escape LDAP special characters (RFC 4515) or use parameterized filters."
            ),
            // ── JWT misconfig ─────────────────────────────────────────────
            r!(
                r#"(?i)(algorithms\s*[:=]\s*\[?\s*["']none["']|verify_signature\s*[:=]\s*False|jwt\.decode\([^)]{0,80}verify\s*=\s*False)"#,
                Severity::Critical, VulnCategory::InsecureConfiguration,
                "JWT — Signature verification disabled / alg:none",
                "JWT accepted without verifying the signature (alg:none or verify=false). Attacker forges arbitrary tokens.",
                "Always verify the signature with a fixed algorithm allowlist (HS256/RS256). Never accept 'none'."
            ),
            // ── Prototype Pollution ───────────────────────────────────────
            r!(
                r#"(?i)(object\.assign|_\.merge|\bmerge|deepmerge|extend)\s*\(\s*[^)]{0,40}(req\.(body|query|params)|JSON\.parse)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Prototype Pollution — Unsafe merge of user input",
                "Deep-merging attacker-controlled objects can pollute Object.prototype via __proto__/constructor.",
                "Reject __proto__/constructor keys. Use Map or a hardened merge (lodash >= 4.17.21)."
            ),
            // ── Debug mode in production ───────────────────────────────────
            r!(
                r#"(?i)(app\.run\([^)]{0,60}debug\s*=\s*True|\bDEBUG\s*[:=]\s*True|FLASK_DEBUG\s*=\s*1|django\.conf.*DEBUG\s*=\s*True)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Debug Mode Enabled",
                "Framework debug mode exposes stack traces and an interactive console (Werkzeug RCE).",
                "Disable debug in production. Set DEBUG=False / NODE_ENV=production."
            ),
            // ── Disabled TLS verification ──────────────────────────────────
            r!(
                r#"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "TLS Certificate Verification Disabled",
                "TLS/SSL certificate validation turned off. Enables man-in-the-middle attacks.",
                "Never disable certificate verification. Fix the trust store / CA bundle instead."
            ),
            // ── Zip Slip ───────────────────────────────────────────────────
            r!(
                r#"(?i)(extractall\s*\(|\.getNextEntry\s*\(|tarfile\.extract)"#,
                Severity::Medium, VulnCategory::PathTraversal,
                "Zip Slip — Archive extraction without path validation",
                "Extracting archive entries without validating names allows writing outside the target dir (../).",
                "Validate each entry path resolves inside the destination before writing."
            ),
            // ── Weak crypto parameters ─────────────────────────────────────
            r!(
                r#"(?i)(createCipher\s*\(|IV\s*=\s*["'][0]{8,}|iv\s*=\s*bytes\(\s*\d+\s*\))"#,
                Severity::Medium, VulnCategory::WeakCrypto,
                "Static/Weak Crypto Parameters",
                "Hardcoded/zero IV or deprecated createCipher (no IV). Weakens or breaks encryption.",
                "Use a random IV per message (crypto.randomBytes / os.urandom). Prefer createCipheriv + AES-GCM."
            ),
            // ── XSS via disabled escaping ──────────────────────────────────
            r!(
                r#"(?i)(autoescape\s*=\s*False|\|\s*safe\b|mark_safe\s*\(|v-html\s*=)"#,
                Severity::Medium, VulnCategory::Xss,
                "XSS — Auto-escaping disabled / raw HTML binding",
                "Template auto-escaping disabled or raw HTML bound (|safe, mark_safe, v-html). Renders unescaped user input.",
                "Keep auto-escaping on. Sanitize with DOMPurify/bleach before marking content safe."
            ),
            // ── SQL Injection — ORM raw query with interpolation ──────────
            r!(
                r#"(?i)\.(raw|query)\s*\(\s*(`[^`]{0,80}\$\{|["'][^"']{0,80}["']\s*\+|f["'][^"']{0,80}\{)"#,
                Severity::High, VulnCategory::SqlInjection,
                "SQL Injection — ORM raw query with interpolation",
                "Raw SQL passed to an ORM (.raw()/.query() in Sequelize/Django/GORM/knex) built with string interpolation or concatenation.",
                "Use the ORM's parameter binding (replacements/params/$1) instead of interpolating user input."
            ),
            // ── Insecure temp file ────────────────────────────────────────
            r!(
                r#"(?i)(tempfile\.mktemp\s*\(|\bmktemp\s*\(|\btmpnam\s*\(|\btempnam\s*\(|\btmpfile\s*\()"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Insecure Temporary File Creation",
                "Predictable temp-file name (mktemp/tmpnam/tempfile.mktemp) — race condition / symlink attack (TOCTOU).",
                "Use atomic APIs: tempfile.NamedTemporaryFile / mkstemp() (Python), mkstemp(3) (C), fs.mkdtemp (Node)."
            ),
            // ── Insecure deserialization — Java ObjectInputStream ─────────
            r!(
                r#"(?i)new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|readUnshared\s*\(\s*\)|XMLDecoder\s*\("#,
                Severity::Critical, VulnCategory::InsecureDeserialization,
                "Insecure Deserialization — Java ObjectInputStream",
                "Java native deserialization (ObjectInputStream.readObject / XMLDecoder) of untrusted data enables RCE via gadget chains.",
                "Never deserialize untrusted input. Use a safe format (JSON) with a validating parser, or an allowlist ObjectInputFilter."
            ),
            // ── Go text/template used for HTML (XSS) ──────────────────────
            r!(
                r#""text/template""#,
                Severity::Medium, VulnCategory::Xss,
                "XSS — Go text/template used for web output",
                "text/template does not HTML-escape. Rendering it to a browser allows XSS.",
                "Use html/template for any HTML/web output; it escapes contextually."
            ),
            // ── GraphQL introspection enabled ─────────────────────────────
            r!(
                r#"(?i)(introspection\s*:\s*true|graphiql\s*:\s*true|__schema\s*\{)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "GraphQL Introspection / GraphiQL Enabled",
                "Introspection or GraphiQL exposed in production leaks the full schema to attackers.",
                "Disable introspection and GraphiQL in production."
            ),
            // ── Mass assignment ───────────────────────────────────────────
            r!(
                r#"(?i)(\.update_attributes\b|params\.permit!|\.save\(\s*strict:\s*false|new\s+\w+\(\s*req\.body\s*\))"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "Mass Assignment — Unfiltered Model Binding",
                "Binding the whole request body/params to a model lets attackers set unintended fields (is_admin, role).",
                "Whitelist assignable fields (strong params / DTO). Never bind raw request bodies to models."
            ),
            // ── XML entity expansion (billion laughs) ─────────────────────
            r!(
                r#"(?i)<!ENTITY\s+\w+\s+["'][^"']{0,40}&\w+;|<!DOCTYPE[^>]{0,80}<!ENTITY"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "XML Entity Expansion (Billion Laughs DoS)",
                "Nested internal DTD entities expand exponentially, exhausting memory/CPU (DoS).",
                "Disable DTD processing. Cap entity expansion. Prefer a hardened XML parser (defusedxml)."
            ),
            // ── ReDoS — user-controlled regex ─────────────────────────────
            r!(
                r#"(?i)new\s+RegExp\s*\(\s*[^)]{0,40}(req\.(query|params|body)|request\.|input)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "ReDoS — Regex Built from User Input",
                "Compiling a regex from user input allows catastrophic backtracking (denial of service).",
                "Do not build regexes from user input, or use a linear-time engine (RE2) and bound input length."
            ),
            // ── Path traversal via join(user input) ───────────────────────
            r!(
                r#"(?i)(path\.join|os\.path\.join)\s*\(\s*[^)]{0,40}(req\.(query|params|body)|request\.(args|form))"#,
                Severity::High, VulnCategory::PathTraversal,
                "Path Traversal — User Input in File Path Join",
                "Joining user input into a filesystem path allows escaping the base directory (../../etc/passwd).",
                "Resolve the final path and assert it stays within an allowed base; reject '..' segments."
            ),
            // ── Dangerous URL scheme in request (SSRF/LFI) ────────────────
            r!(
                r#"(?i)(fetch|requests\.(get|post)|urlopen|axios|curl_exec|file_get_contents|http\.get)\s*\(\s*[^)]{0,30}["'](gopher|dict|file|ftp)://"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "SSRF / LFI — Dangerous URL Scheme in Request",
                "A request uses gopher://, dict://, file:// or ftp:// — schemes abused for SSRF pivoting and local file read.",
                "Restrict outbound requests to http(s) and an allowlist of hosts. Reject non-http schemes."
            ),
            // ── CORS origin reflection ────────────────────────────────────
            r!(
                r#"(?i)(Access-Control-Allow-Origin[^\n]{0,40}(req\.headers\.origin|request\.headers\[.origin|origin\(\))|set_header\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*[^)]{0,20}origin)"#,
                Severity::High, VulnCategory::CorsMisconfiguration,
                "CORS — Origin Reflection",
                "The request Origin is echoed back into Access-Control-Allow-Origin. With credentials this is effectively `*`, letting any site make authenticated cross-origin requests.",
                "Reflect only origins from an explicit allowlist. Never echo the raw Origin header when credentials are allowed."
            ),
        ]
    });
    &RULES
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

pub fn scan_source(path: &Path, content: &[u8]) -> Vec<Vulnerability> {
    let raw = match std::str::from_utf8(content) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };

    // Drop lines >4 KB — generated/minified files have single lines of hundreds of KB
    // and cause catastrophic regex backtracking even within the total byte cap.
    let scratch: String;
    let text: &str = match super::filter_long_lines(raw, 4096) {
        Some(s) => { scratch = s; &scratch }
        None    => raw,
    };

    let lines: Vec<&str> = text.lines().collect();
    let mut findings: Vec<Vulnerability> = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    for rule in get_rules() {
        let mut matches_for_rule = 0usize;
        for m in rule.pattern.find_iter(text) {
            if matches_for_rule >= 20 { break; }
            let line_idx = text[..m.start()].chars().filter(|&c| c == '\n').count();
            if lines.get(line_idx).is_some_and(|l| super::is_comment_line(l)) { continue; }
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
