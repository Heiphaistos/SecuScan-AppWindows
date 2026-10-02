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
                "Identifiant de clé d'accès AWS",
                "Clé d'accès AWS IAM trouvée dans la configuration ou le code source. Compromission complète du compte en cas d'exposition.",
                "Faites tourner la clé immédiatement depuis la console AWS IAM. Stockez-la dans AWS Secrets Manager ou une variable d'environnement."
            ),
            r!(
                r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?"#,
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé d'accès secrète AWS",
                "Clé d'accès secrète AWS trouvée. Associée à l'identifiant de clé, elle donne un accès complet à l'API.",
                "Faites-la tourner immédiatement. Utilisez des rôles IAM ou des profils d'instance plutôt que des clés statiques."
            ),
            // ── OpenAI ───────────────────────────────────────────────────
            r!(
                r"sk-[A-Za-z0-9]{48,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé API OpenAI",
                "Clé secrète OpenAI trouvée. Permet d'abuser de la facturation et d'accéder aux modèles.",
                "Faites-la tourner sur platform.openai.com. Stockez-la dans une variable d'environnement."
            ),
            // ── Google ───────────────────────────────────────────────────
            r!(
                r"AIza[0-9A-Za-z_\-]{35}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé API Google",
                "Clé API Google Cloud / Firebase trouvée.",
                "Restreignez la clé dans la console GCP. Faites-la tourner et stockez-la dans Secret Manager."
            ),
            // ── Anthropic ────────────────────────────────────────────────
            r!(
                r"sk-ant-api[0-9A-Za-z_\-]{20,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé API Anthropic",
                "Clé API Anthropic Claude trouvée dans le fichier.",
                "Faites-la tourner sur console.anthropic.com. Utilisez la variable d'environnement ANTHROPIC_API_KEY."
            ),
            // ── Stripe ───────────────────────────────────────────────────
            r!(
                r"(sk|pk)_(test|live)_[A-Za-z0-9]{24,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé secrète/publiable Stripe",
                "Clé API Stripe trouvée. sk_live → prise de contrôle complète du compte.",
                "Faites-la tourner sur dashboard.stripe.com. Les clés sk_live doivent rester uniquement côté serveur."
            ),
            // ── GitHub ───────────────────────────────────────────────────
            r!(
                r"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9]{20,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton d'accès personnel GitHub",
                "PAT GitHub trouvé. Donne accès aux dépôts au niveau de permissions du PAT.",
                "Révoquez-le sur github.com/settings/tokens. Utilisez les secrets GitHub Actions pour la CI."
            ),
            // ── Slack ────────────────────────────────────────────────────
            r!(
                r"https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[A-Za-z0-9]{24,}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "URL de webhook Slack",
                "URL de webhook entrant Slack exposée. Permet d'envoyer des messages dans le salon.",
                "Faites tourner le webhook dans les paramètres de l'application Slack. Retirez-le des fichiers versionnés."
            ),
            // ── JWT ──────────────────────────────────────────────────────
            r!(
                r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                Severity::High, VulnCategory::JwtExposed,
                "Jeton JWT exposé",
                "JSON Web Token trouvé dans une configuration ou une sauvegarde. S'il est valide, un attaquant peut usurper l'identité de l'utilisateur.",
                "Invalidez le jeton côté serveur. Ne commitez jamais de jetons. Imposez une expiration courte."
            ),
            // ── Passwords ────────────────────────────────────────────────
            r!(
                r#"(?i)(password|passwd|pwd|db_pass|database_password|secret_key)\s*[=:]\s*["']?[^\s"']{8,}["']?"#,
                Severity::High, VulnCategory::PasswordLeak,
                "Mot de passe en dur dans la configuration",
                "Affectation de mot de passe en clair trouvée dans un fichier de configuration.",
                "Déplacez-le dans une variable d'environnement ou un gestionnaire de secrets. Vérifiez que .env figure dans .gitignore."
            ),
            // ── DB connection strings ─────────────────────────────────────
            r!(
                r#"(?i)(mongodb(\+srv)?|mysql|postgresql|postgres|mssql|redis|amqp)://[^:]+:[^@]+@[^\s"']+"#,
                Severity::Critical, VulnCategory::ConnectionStringLeak,
                "Chaîne de connexion à une base de données avec identifiants",
                "Chaîne de connexion contenant un nom d'utilisateur et un mot de passe trouvée. Accès direct à la base de données possible.",
                "Retirez les identifiants de la chaîne de connexion. Utilisez des variables d'environnement ou un gestionnaire de secrets."
            ),
            r!(
                r#"(?i)(Data\s+Source|Server|Initial\s+Catalog)=[^;]+;\s*(User\s+(Id|ID)|uid)=[^;]+;\s*(Password|Pwd)=[^;]+"#,
                Severity::Critical, VulnCategory::ConnectionStringLeak,
                "Chaîne de connexion ADO.NET avec identifiants",
                "Chaîne de connexion .NET/ADO.NET contenant un nom d'utilisateur et un mot de passe.",
                "Utilisez l'authentification Windows ou stockez les identifiants dans Azure Key Vault ou l'environnement."
            ),
            // ── Private keys ──────────────────────────────────────────────
            r!(
                r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) (PRIVATE )?KEY-----",
                Severity::Critical, VulnCategory::HardcodedSecret,
                "Clé privée",
                "Clé privée SSH ou TLS trouvée dans le fichier. Critique si elle est versionnée.",
                "Retirez-la immédiatement. Faites tourner toutes les clés et tous les certificats associés."
            ),
            // ── Generic signing keys ───────────────────────────────────────
            r!(
                r#"(?i)(SECRET|PRIVATE|SIGNING)[_-]?KEY\s*[=:]\s*["'][a-zA-Z0-9+/=_\-]{20,}["']"#,
                Severity::High, VulnCategory::HardcodedSecret,
                "Clé de signature / clé secrète en dur",
                "Clé de signature ou clé secrète applicative codée en dur dans la configuration.",
                "Faites tourner la clé. Stockez-la dans une variable d'environnement ou un gestionnaire de secrets."
            ),
            // ── Slack bot / app token ─────────────────────────────────────
            r!(
                r"xox[baprs]-[0-9A-Za-z-]{10,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton de bot / d'application Slack",
                "Jeton Slack (xoxb/xoxa/xoxp/xoxr/xoxs) exposé. Donne accès à l'API de l'espace de travail.",
                "Révoquez-le dans les paramètres de l'application Slack. Stockez-le dans un gestionnaire de secrets."
            ),
            // ── GitLab PAT ────────────────────────────────────────────────
            r!(
                r"glpat-[0-9A-Za-z_\-]{20,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton d'accès personnel GitLab",
                "PAT GitLab exposé. Donne accès aux dépôts et à l'API selon la portée du jeton.",
                "Révoquez-le sur gitlab.com/-/profile/personal_access_tokens. Utilisez les variables CI/CD."
            ),
            // ── Telegram bot token ────────────────────────────────────────
            r!(
                r"[0-9]{8,10}:AA[0-9A-Za-z_\-]{32,}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Jeton de bot Telegram",
                "Jeton d'API de bot Telegram exposé. Permet de contrôler entièrement le bot.",
                "Révoquez-le via @BotFather (/revoke). Stockez le jeton dans une variable d'environnement."
            ),
            // ── SendGrid ──────────────────────────────────────────────────
            r!(
                r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé API SendGrid",
                "Clé API SendGrid exposée. Permet d'envoyer des e-mails au nom du compte (risque d'hameçonnage).",
                "Révoquez-la sur app.sendgrid.com. Stockez-la dans un gestionnaire de secrets."
            ),
            // ── Twilio ────────────────────────────────────────────────────
            r!(
                r"SK[0-9a-fA-F]{32}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "SID de clé API Twilio",
                "SID de clé API Twilio exposé. Associé au secret, il permet d'abuser de la facturation SMS/voix.",
                "Faites-la tourner sur console.twilio.com. Stockez les identifiants uniquement côté serveur."
            ),
            // ── npm token ─────────────────────────────────────────────────
            r!(
                r"npm_[0-9A-Za-z]{36}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton d'accès npm",
                "Jeton npm d'automatisation/de publication exposé. Permet de publier des paquets (risque pour la chaîne d'approvisionnement).",
                "Révoquez-le sur npmjs.com/settings/tokens. Utilisez les secrets de la CI."
            ),
            // ── Google OAuth client secret ────────────────────────────────
            r!(
                r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Identifiant client OAuth Google",
                "Identifiant client OAuth Google exposé ; associé au secret client, il permet d'émettre des jetons.",
                "Restreignez le client dans la console GCP. Gardez le secret client côté serveur."
            ),
            // ── Hardcoded HS256 JWT secret ────────────────────────────────
            r!(
                r#"(?i)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*["'][^"']{8,}["']"#,
                Severity::High, VulnCategory::HardcodedSecret,
                "Secret de signature JWT en dur",
                "Secret de signature JWT codé en dur. Quiconque le possède peut forger des jetons valides pour n'importe quel utilisateur.",
                "Déplacez-le dans une variable d'environnement. Faites tourner le secret et invalidez les jetons existants."
            ),
            // ── Azure Storage account key ─────────────────────────────────
            r!(
                r"AccountKey=[A-Za-z0-9+/]{86}==",
                Severity::Critical, VulnCategory::ConnectionStringLeak,
                "Clé de compte de stockage Azure",
                "Clé de compte de stockage Azure trouvée dans une chaîne de connexion. Donne un accès complet aux blobs, files d'attente et tables.",
                "Faites tourner la clé dans le portail Azure. Utilisez plutôt des jetons SAS ou une identité managée."
            ),
            // ── DigitalOcean PAT ──────────────────────────────────────────
            r!(
                r"dop_v1_[a-f0-9]{64}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton d'accès personnel DigitalOcean",
                "Jeton d'API DigitalOcean exposé. Permet de contrôler entièrement les droplets et les ressources.",
                "Révoquez-le sur cloud.digitalocean.com/account/api. Stockez-le dans un gestionnaire de secrets."
            ),
            // ── Mailgun API key ───────────────────────────────────────────
            r!(
                r"key-[0-9a-zA-Z]{32}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Clé API Mailgun",
                "Clé API Mailgun exposée. Permet d'envoyer des e-mails au nom du compte (risque d'hameçonnage).",
                "Faites-la tourner sur app.mailgun.com. Stockez-la uniquement côté serveur."
            ),
            // ── Datadog API key ───────────────────────────────────────────
            r!(
                r#"(?i)(datadog|dd[_-]?api[_-]?key)["'\s:=]{1,6}[a-f0-9]{32}"#,
                Severity::High, VulnCategory::ApiKeyLeak,
                "Clé API Datadog",
                "Clé API Datadog exposée. Permet d'injecter des métriques et des journaux et d'accéder aux données du compte.",
                "Faites-la tourner sur app.datadoghq.com/organization-settings/api-keys. Stockez-la dans un gestionnaire de secrets."
            ),
            // ── Heroku API key ────────────────────────────────────────────
            r!(
                r#"(?i)heroku[a-z0-9_ \-]{0,15}["'\s:=]{1,4}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Clé API Heroku",
                "Clé API Heroku (UUID) exposée. Donne le contrôle des applications et des modules complémentaires.",
                "Révoquez-la via `heroku authorizations`. Stockez-la dans les config vars, pas dans le code source."
            ),
            // ── Cloudflare API token ──────────────────────────────────────
            r!(
                r#"(?i)(cloudflare|cf[_-]?api[_-]?token)["'\s:=]{1,6}[A-Za-z0-9_\-]{40}"#,
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton d'API Cloudflare",
                "Jeton d'API Cloudflare exposé. Permet de modifier DNS, zones et sécurité selon la portée du jeton.",
                "Révoquez-le sur dash.cloudflare.com/profile/api-tokens. Utilisez des jetons à portée minimale."
            ),
            // ── Discord bot token ─────────────────────────────────────────
            r!(
                r"[MNO][A-Za-z\d_-]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton de bot Discord",
                "Jeton de bot Discord exposé. Donne le contrôle complet du bot et de ses serveurs.",
                "Réinitialisez le jeton dans le portail développeur Discord. Stockez-le dans une variable d'environnement."
            ),
            // ── Shopify access token ──────────────────────────────────────
            r!(
                r"shpat_[a-fA-F0-9]{32}",
                Severity::Critical, VulnCategory::ApiKeyLeak,
                "Jeton d'accès Shopify",
                "Jeton d'accès à l'API privée/admin Shopify exposé. Permet d'accéder aux données de la boutique et aux commandes.",
                "Révoquez-le dans l'administration Shopify (Applications). Stockez-le uniquement côté serveur."
            ),
            // ── Square access token ───────────────────────────────────────
            r!(
                r"sq0atp-[0-9A-Za-z_\-]{22}",
                Severity::High, VulnCategory::ApiKeyLeak,
                "Jeton d'accès Square",
                "Jeton d'accès OAuth/production Square exposé. Permet des opérations de paiement et sur le compte.",
                "Faites-le tourner sur developer.squareup.com. Gardez les jetons côté serveur."
            ),
            // ── Firebase database URL ─────────────────────────────────────
            r!(
                r"https://[a-z0-9-]+\.firebaseio\.com",
                Severity::Medium, VulnCategory::SensitiveDataExposure,
                "URL de base de données Firebase exposée",
                "Une URL Firebase Realtime DB est exposée ; avec des règles laxistes, elle permet de lire et d'écrire directement les données.",
                "Vérifiez que les règles de sécurité Firebase refusent l'accès public. Dans la mesure du possible, ne mettez pas l'URL dans la configuration client distribuée."
            ),
            // ── Algolia admin key ─────────────────────────────────────────
            r!(
                r#"(?i)algolia[a-z0-9_ -]{0,15}["'\s:=]{1,6}[a-f0-9]{32}"#,
                Severity::High, VulnCategory::ApiKeyLeak,
                "Clé API admin Algolia",
                "Clé admin Algolia exposée — permet de lire, écrire et supprimer entièrement les index.",
                "Utilisez une clé de recherche seule côté client. Faites tourner la clé admin ; gardez-la côté serveur."
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
                    "Chaîne à forte entropie — secret potentiel",
                    &format!("Chaîne d'entropie {:.2} (>4,5) trouvée. Possible clé API, jeton ou mot de passe.", entropy),
                    "Vérifiez s'il s'agit d'un secret. Si oui, déplacez-le dans des variables d'environnement ou un gestionnaire de secrets.",
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
