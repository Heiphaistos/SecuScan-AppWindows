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
                "Injection SQL — execute() direct",
                "Chaîne SQL brute passée directement à execute(). L'attaquant contrôle la structure de la requête.",
                "Utilisez des requêtes paramétrées / requêtes préparées. Ne concaténez jamais d'entrée utilisateur dans du SQL."
            ),
            r!(
                r#"(?i)["']\s*\+\s*(username|user_?id|email|password|id|input|param|req\.(body|query|params))"#,
                Severity::High, VulnCategory::SqlInjection,
                "Injection SQL — concaténation de chaîne dans une requête",
                "Valeur contrôlée par l'utilisateur concaténée directement dans la chaîne de requête.",
                "Remplacez la concaténation par des paramètres liés (?, $1, @p1…)."
            ),
            r!(
                r#"(?i)f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{[^}]+\}"#,
                Severity::Critical, VulnCategory::SqlInjection,
                "Injection SQL — f-string avec entrée utilisateur",
                "f-string ou chaîne de formatage Python utilisée pour construire du SQL.",
                "Utilisez des requêtes paramétrées avec cursor.execute(sql, params)."
            ),
            // ── XSS ─────────────────────────────────────────────────────
            r!(
                // Le crate `regex` ne connait pas le look-ahead : formuler en
                // positif ce que `(?!…)` exprimait en negatif. Est dangereuse une
                // affectation dont la valeur ne commence pas par un guillemet
                // (variable, appel, concatenation), ou un gabarit interpole.
                r#"\.innerHTML\s*[+]?=\s*(?:[^"'`\s;]|`[^`]*\$\{)"#,
                Severity::High, VulnCategory::Xss,
                "XSS — affectation innerHTML non sécurisée",
                "Contenu dynamique écrit dans innerHTML sans assainissement.",
                "Utilisez textContent, ou assainissez avec DOMPurify avant l'affectation à innerHTML."
            ),
            r!(
                r#"document\.write\s*\([^"'`]"#,
                Severity::High, VulnCategory::Xss,
                "XSS — document.write() avec contenu dynamique",
                "document.write() peut injecter du HTML contrôlé par un attaquant.",
                "Évitez document.write(). Utilisez plutôt les API de manipulation du DOM."
            ),
            r!(
                // Sans look-ahead : est dangereuse une evaluation dont
                // l'argument ne commence pas par un guillemet, donc une
                // expression construite plutot qu'une chaine litterale.
                r#"(?i)eval\s*\(\s*[^"'`\s)][^)]*\)"#,
                Severity::Critical, VulnCategory::Xss,
                "XSS / RCE — eval() avec expression dynamique",
                "eval() exécute du JavaScript arbitraire. Si l'entrée est contrôlée par un attaquant → exécution de code (RCE) dans le navigateur.",
                "Remplacez eval() par JSON.parse() pour les données, ou refactorisez pour supprimer l'évaluation de code dynamique."
            ),
            r!(
                r#"(?i)(echo|print)\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)"#,
                Severity::Critical, VulnCategory::Xss,
                "XSS — superglobale PHP affichée sans échappement",
                "Entrée utilisateur issue de $_GET/$_POST/etc. affichée directement sans encodage.",
                "Utilisez htmlspecialchars($var, ENT_QUOTES, 'UTF-8') avant d'afficher une entrée utilisateur."
            ),
            r!(
                r#"(?i)dangerouslySetInnerHTML\s*=\s*\{\s*\{"#,
                Severity::Medium, VulnCategory::Xss,
                "XSS — dangerouslySetInnerHTML (React)",
                "dangerouslySetInnerHTML contourne la protection XSS de React. Vérifiez que la source est fiable.",
                "Assainissez le contenu avec DOMPurify avant de le passer à dangerouslySetInnerHTML."
            ),
            // ── Command Injection ────────────────────────────────────────
            r!(
                r#"(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|shell_exec\(|passthru\(|system\()\s*[^"'`\n]*\+"#,
                Severity::Critical, VulnCategory::CommandInjection,
                "Injection de commande — appel shell avec concaténation de chaîne",
                "Chaîne contrôlée par l'utilisateur concaténée dans une commande shell.",
                "Utilisez shell=False avec une liste d'arguments dans subprocess. Validez / filtrez par liste blanche toutes les entrées."
            ),
            // ── Path Traversal ───────────────────────────────────────────
            r!(
                r#"(?i)(open|read_file|include|require|fopen)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"#,
                Severity::High, VulnCategory::PathTraversal,
                "Traversée de répertoire — entrée utilisateur dans l'ouverture d'un fichier",
                "Un chemin de fichier construit à partir d'une entrée utilisateur permet la traversée de répertoire (../../etc/passwd).",
                "Validez les chemins de fichier par rapport à une liste blanche, ou utilisez realpath() et vérifiez qu'ils commencent par la base autorisée."
            ),
            // ── Weak Crypto ───────────────────────────────────────────────
            r!(
                r#"(?i)\b(md5|sha1|des|rc4|3des|blowfish)\s*\("#,
                Severity::Medium, VulnCategory::WeakCrypto,
                "Fonction cryptographique faible",
                "MD5/SHA1/DES/RC4 sont cassés sur le plan cryptographique.",
                "Remplacez par SHA-256+/AES-256-GCM/ChaCha20-Poly1305. Pour les mots de passe : bcrypt/argon2."
            ),
            r!(
                r#"(?i)(ECB)\s*mode|AES.*ECB"#,
                Severity::High, VulnCategory::WeakCrypto,
                "Mode de chiffrement non sécurisé — ECB",
                "Le mode ECB laisse fuiter des motifs. Ne jamais l'utiliser pour des données sensibles.",
                "Utilisez AES-GCM ou ChaCha20-Poly1305 (chiffrement authentifié)."
            ),
            r!(
                r#"(?i)random\.(random|randint|randrange|choice)\s*\("#,
                Severity::High, VulnCategory::WeakCrypto,
                "CSPRNG absent — aléatoire non cryptographique",
                "La fonction random() standard n'est pas sûre sur le plan cryptographique.",
                "Utilisez secrets.token_hex() (Python), crypto.randomBytes() (Node), rand::thread_rng() (Rust)."
            ),
            // ── CORS ──────────────────────────────────────────────────────
            r!(
                r#"(?i)Access-Control-Allow-Origin[^:]*:\s*\*"#,
                Severity::Medium, VulnCategory::CorsMisconfiguration,
                "CORS — origine générique (*)",
                "Access-Control-Allow-Origin: * autorise n'importe quel site à faire des requêtes cross-origin.",
                "Limitez les origines autorisées à une liste blanche explicite."
            ),
            // ── Insecure Deserialization ──────────────────────────────────
            r!(
                r#"(?i)(pickle\.loads?|yaml\.load\s*\([^,)]+\)|marshal\.loads?|unserialize\()"#,
                Severity::Critical, VulnCategory::InsecureDeserialization,
                "Désérialisation non sécurisée",
                "Désérialiser des données non fiables peut mener à l'exécution de code arbitraire.",
                "Utilisez yaml.safe_load(). N'utilisez jamais pickle sur une entrée non fiable. Utilisez JSON pour l'échange de données."
            ),
            // ── Hardcoded Secrets in code ─────────────────────────────────
            r!(
                r#"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"#,
                Severity::Critical, VulnCategory::HardcodedSecret,
                "Clé privée en dur",
                "Clé privée intégrée dans le code source.",
                "Retirez immédiatement la clé du code. Faites-la tourner. Stockez-la dans un gestionnaire de secrets ou un HSM."
            ),
            r!(
                r#"(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token)\s*[:=]\s*["'][a-zA-Z0-9_\-./+]{16,}["']"#,
                Severity::Critical, VulnCategory::HardcodedSecret,
                "Clé API / secret en dur",
                "Clé API ou jeton secret en dur dans le code source. Il fuit via le gestionnaire de versions.",
                "Déplacez-le dans des variables d'environnement (.env) ou un gestionnaire de secrets. Faites tourner la clé exposée."
            ),
            r!(
                r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}["']"#,
                Severity::High, VulnCategory::HardcodedSecret,
                "Mot de passe en dur",
                "Mot de passe en clair trouvé dans le code source.",
                "Retirez-le du code. Utilisez des variables d'environnement. Stockez les mots de passe hachés avec bcrypt/argon2."
            ),
            // ── Open Redirect ─────────────────────────────────────────────
            r!(
                r#"(?i)(redirect|location)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"#,
                Severity::Medium, VulnCategory::OpenRedirect,
                "Redirection ouverte",
                "Destination de redirection dérivée d'une entrée utilisateur sans validation.",
                "Validez l'URL de redirection par rapport à une liste blanche de domaines autorisés."
            ),
            // ── SSRF ──────────────────────────────────────────────────────
            r!(
                r#"(?i)(requests\.(get|post|put)|urllib\.request\.urlopen|fetch|axios\.(get|post)|http\.get|httpclient\.get)\s*\(\s*[^)]{0,40}(req\.(query|params|body)|request\.(args|form|get|post)|\$_(GET|POST|REQUEST))"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "SSRF — requête côté serveur vers une URL contrôlée par l'utilisateur",
                "Le client HTTP récupère une URL dérivée d'une entrée utilisateur. L'attaquant peut atteindre des services internes (169.254.169.254, localhost, métadonnées cloud).",
                "Filtrez par liste blanche les hôtes / schémas autorisés. Bloquez les plages d'IP privées (10/8, 172.16/12, 192.168/16, 169.254/16) et les points d'accès de métadonnées."
            ),
            // ── SSTI ──────────────────────────────────────────────────────
            r!(
                r#"(?i)(render_template_string|env\.from_string|new\s+Function)\s*\(\s*[^)]{0,40}(\+|\$\{|%s|\{\{|f["'])"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "SSTI — injection de template côté serveur",
                "Entrée utilisateur concaténée dans une chaîne de template. Mène à une RCE dans Jinja2/Twig/Handlebars/Freemarker.",
                "Ne construisez jamais de templates à partir d'une entrée utilisateur. Passez les données comme variables de template, pas comme source du template."
            ),
            // ── XXE ───────────────────────────────────────────────────────
            r!(
                r#"(?i)(libxml_disable_entity_loader\s*\(\s*false|resolve_entities\s*=\s*True|noent\s*=\s*True|XMLParser\([^)]*resolve_entities|DocumentBuilderFactory\.newInstance\s*\()"#,
                Severity::High, VulnCategory::InsecureDeserialization,
                "XXE — traitement des entités externes XML activé",
                "Le parseur XML résout les entités externes, ce qui permet la divulgation de fichiers locaux et une SSRF via une DTD forgée.",
                "Désactivez la DTD / les entités externes : setFeature('disallow-doctype-decl', true) ou defusedxml (Python)."
            ),
            // ── NoSQL Injection ───────────────────────────────────────────
            r!(
                r#"(?i)(find|findone|update|deleteone|deletemany)\s*\(\s*\{[^}]{0,60}(req\.(body|query|params)|\$where)"#,
                Severity::High, VulnCategory::SqlInjection,
                "Injection NoSQL — entrée utilisateur dans un objet de requête",
                "Entrée utilisateur brute placée dans un objet de requête MongoDB. Des opérateurs comme $ne/$gt/$where contournent l'authentification.",
                "Convertissez / validez les types des entrées. Rejetez les opérateurs de requête venant de l'utilisateur. Imposez un schéma ODM."
            ),
            // ── LDAP Injection ────────────────────────────────────────────
            r!(
                r#"(?i)(search|bind)\s*\([^)]{0,60}(\(uid=|\(cn=|\(&)[^)]{0,40}(\+|\$\{|%s|f["'])"#,
                Severity::High, VulnCategory::CommandInjection,
                "Injection LDAP — filtre construit à partir d'une entrée utilisateur",
                "Un filtre LDAP concaténé avec une entrée utilisateur permet de contourner l'authentification et d'extraire des données de l'annuaire.",
                "Échappez les caractères spéciaux LDAP (RFC 4515) ou utilisez des filtres paramétrés."
            ),
            // ── JWT misconfig ─────────────────────────────────────────────
            r!(
                r#"(?i)(algorithms\s*[:=]\s*\[?\s*["']none["']|verify_signature\s*[:=]\s*False|jwt\.decode\([^)]{0,80}verify\s*=\s*False)"#,
                Severity::Critical, VulnCategory::InsecureConfiguration,
                "JWT — vérification de signature désactivée / alg:none",
                "JWT accepté sans vérification de la signature (alg:none ou verify=false). L'attaquant peut forger des jetons arbitraires.",
                "Vérifiez toujours la signature avec une liste fixe d'algorithmes autorisés (HS256/RS256). N'acceptez jamais 'none'."
            ),
            // ── Prototype Pollution ───────────────────────────────────────
            r!(
                r#"(?i)(object\.assign|_\.merge|\bmerge|deepmerge|extend)\s*\(\s*[^)]{0,40}(req\.(body|query|params)|JSON\.parse)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Pollution de prototype — fusion non sécurisée d'une entrée utilisateur",
                "La fusion profonde d'objets contrôlés par un attaquant peut polluer Object.prototype via __proto__/constructor.",
                "Rejetez les clés __proto__/constructor. Utilisez Map ou une fusion renforcée (lodash >= 4.17.21)."
            ),
            // ── Debug mode in production ───────────────────────────────────
            r!(
                r#"(?i)(app\.run\([^)]{0,60}debug\s*=\s*True|\bDEBUG\s*[:=]\s*True|FLASK_DEBUG\s*=\s*1|django\.conf.*DEBUG\s*=\s*True)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Mode débogage activé",
                "Le mode débogage du framework expose les traces d'appels et une console interactive (RCE via Werkzeug).",
                "Désactivez le débogage en production. Définissez DEBUG=False / NODE_ENV=production."
            ),
            // ── Disabled TLS verification ──────────────────────────────────
            r!(
                r#"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "Vérification des certificats TLS désactivée",
                "Validation des certificats TLS/SSL désactivée. Permet les attaques de l'homme du milieu.",
                "Ne désactivez jamais la vérification des certificats. Corrigez plutôt le magasin de confiance / le bundle d'AC."
            ),
            // ── Zip Slip ───────────────────────────────────────────────────
            r!(
                r#"(?i)(extractall\s*\(|\.getNextEntry\s*\(|tarfile\.extract)"#,
                Severity::Medium, VulnCategory::PathTraversal,
                "Zip Slip — extraction d'archive sans validation des chemins",
                "Extraire les entrées d'une archive sans valider leurs noms permet d'écrire hors du répertoire cible (../).",
                "Vérifiez que le chemin de chaque entrée se résout à l'intérieur de la destination avant d'écrire."
            ),
            // ── Weak crypto parameters ─────────────────────────────────────
            r!(
                r#"(?i)(createCipher\s*\(|IV\s*=\s*["'][0]{8,}|iv\s*=\s*bytes\(\s*\d+\s*\))"#,
                Severity::Medium, VulnCategory::WeakCrypto,
                "Paramètres cryptographiques statiques / faibles",
                "IV en dur / nul ou createCipher obsolète (sans IV). Affaiblit ou casse le chiffrement.",
                "Utilisez un IV aléatoire par message (crypto.randomBytes / os.urandom). Préférez createCipheriv + AES-GCM."
            ),
            // ── XSS via disabled escaping ──────────────────────────────────
            r!(
                r#"(?i)(autoescape\s*=\s*False|\|\s*safe\b|mark_safe\s*\(|v-html\s*=)"#,
                Severity::Medium, VulnCategory::Xss,
                "XSS — échappement automatique désactivé / liaison HTML brute",
                "Échappement automatique des templates désactivé ou HTML brut lié (|safe, mark_safe, v-html). Affiche une entrée utilisateur non échappée.",
                "Gardez l'échappement automatique actif. Assainissez avec DOMPurify/bleach avant de marquer un contenu comme sûr."
            ),
            // ── SQL Injection — ORM raw query with interpolation ──────────
            r!(
                r#"(?i)\.(raw|query)\s*\(\s*(`[^`]{0,80}\$\{|["'][^"']{0,80}["']\s*\+|f["'][^"']{0,80}\{)"#,
                Severity::High, VulnCategory::SqlInjection,
                "Injection SQL — requête brute ORM avec interpolation",
                "SQL brut passé à un ORM (.raw()/.query() dans Sequelize/Django/GORM/knex) construit par interpolation ou concaténation de chaînes.",
                "Utilisez la liaison de paramètres de l'ORM (replacements/params/$1) au lieu d'interpoler l'entrée utilisateur."
            ),
            // ── Insecure temp file ────────────────────────────────────────
            r!(
                r#"(?i)(tempfile\.mktemp\s*\(|\bmktemp\s*\(|\btmpnam\s*\(|\btempnam\s*\(|\btmpfile\s*\()"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Création de fichier temporaire non sécurisée",
                "Nom de fichier temporaire prévisible (mktemp/tmpnam/tempfile.mktemp) — situation de concurrence / attaque par lien symbolique (TOCTOU).",
                "Utilisez des API atomiques : tempfile.NamedTemporaryFile / mkstemp() (Python), mkstemp(3) (C), fs.mkdtemp (Node)."
            ),
            // ── Insecure deserialization — Java ObjectInputStream ─────────
            r!(
                r#"(?i)new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|readUnshared\s*\(\s*\)|XMLDecoder\s*\("#,
                Severity::Critical, VulnCategory::InsecureDeserialization,
                "Désérialisation non sécurisée — ObjectInputStream Java",
                "La désérialisation native Java (ObjectInputStream.readObject / XMLDecoder) de données non fiables permet une RCE via des chaînes de gadgets.",
                "Ne désérialisez jamais d'entrée non fiable. Utilisez un format sûr (JSON) avec un parseur qui valide, ou un ObjectInputFilter à liste blanche."
            ),
            // ── Go text/template used for HTML (XSS) ──────────────────────
            r!(
                r#""text/template""#,
                Severity::Medium, VulnCategory::Xss,
                "XSS — text/template Go utilisé pour une sortie web",
                "text/template n'échappe pas le HTML. L'afficher dans un navigateur permet une XSS.",
                "Utilisez html/template pour toute sortie HTML/web ; il échappe selon le contexte."
            ),
            // ── GraphQL introspection enabled ─────────────────────────────
            r!(
                r#"(?i)(introspection\s*:\s*true|graphiql\s*:\s*true|__schema\s*\{)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Introspection GraphQL / GraphiQL activé",
                "L'introspection ou GraphiQL exposé en production révèle le schéma complet aux attaquants.",
                "Désactivez l'introspection et GraphiQL en production."
            ),
            // ── Mass assignment ───────────────────────────────────────────
            r!(
                r#"(?i)(\.update_attributes\b|params\.permit!|\.save\(\s*strict:\s*false|new\s+\w+\(\s*req\.body\s*\))"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "Affectation de masse — liaison de modèle non filtrée",
                "Lier tout le corps / les paramètres de la requête à un modèle permet aux attaquants de définir des champs non prévus (is_admin, role).",
                "Listez explicitement les champs affectables (strong params / DTO). Ne liez jamais le corps brut d'une requête à un modèle."
            ),
            // ── XML entity expansion (billion laughs) ─────────────────────
            r!(
                r#"(?i)<!ENTITY\s+\w+\s+["'][^"']{0,40}&\w+;|<!DOCTYPE[^>]{0,80}<!ENTITY"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "Expansion d'entités XML (DoS Billion Laughs)",
                "Des entités DTD internes imbriquées s'étendent de façon exponentielle et épuisent la mémoire / le CPU (DoS).",
                "Désactivez le traitement des DTD. Limitez l'expansion des entités. Préférez un parseur XML renforcé (defusedxml)."
            ),
            // ── ReDoS — user-controlled regex ─────────────────────────────
            r!(
                r#"(?i)new\s+RegExp\s*\(\s*[^)]{0,40}(req\.(query|params|body)|request\.|input)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "ReDoS — expression régulière construite à partir d'une entrée utilisateur",
                "Compiler une expression régulière à partir d'une entrée utilisateur permet un retour arrière catastrophique (déni de service).",
                "Ne construisez pas d'expressions régulières à partir d'une entrée utilisateur, ou utilisez un moteur en temps linéaire (RE2) et limitez la longueur de l'entrée."
            ),
            // ── Path traversal via join(user input) ───────────────────────
            r!(
                r#"(?i)(path\.join|os\.path\.join)\s*\(\s*[^)]{0,40}(req\.(query|params|body)|request\.(args|form))"#,
                Severity::High, VulnCategory::PathTraversal,
                "Traversée de répertoire — entrée utilisateur dans la jonction d'un chemin",
                "Joindre une entrée utilisateur à un chemin du système de fichiers permet de sortir du répertoire de base (../../etc/passwd).",
                "Résolvez le chemin final et vérifiez qu'il reste dans une base autorisée ; rejetez les segments '..'."
            ),
            // ── Dangerous URL scheme in request (SSRF/LFI) ────────────────
            r!(
                r#"(?i)(fetch|requests\.(get|post)|urlopen|axios|curl_exec|file_get_contents|http\.get)\s*\(\s*[^)]{0,30}["'](gopher|dict|file|ftp)://"#,
                Severity::High, VulnCategory::InsecureConfiguration,
                "SSRF / LFI — schéma d'URL dangereux dans une requête",
                "Une requête utilise gopher://, dict://, file:// ou ftp:// — des schémas détournés pour pivoter via SSRF et lire des fichiers locaux.",
                "Limitez les requêtes sortantes à http(s) et à une liste blanche d'hôtes. Rejetez les schémas autres que http."
            ),
            // ── CORS origin reflection ────────────────────────────────────
            r!(
                r#"(?i)(Access-Control-Allow-Origin[^\n]{0,40}(req\.headers\.origin|request\.headers\[.origin|origin\(\))|set_header\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*[^)]{0,20}origin)"#,
                Severity::High, VulnCategory::CorsMisconfiguration,
                "CORS — réflexion de l'origine",
                "L'en-tête Origin de la requête est renvoyé tel quel dans Access-Control-Allow-Origin. Avec les identifiants, cela équivaut à `*` : n'importe quel site peut faire des requêtes cross-origin authentifiées.",
                "Ne renvoyez que les origines d'une liste blanche explicite. Ne renvoyez jamais l'en-tête Origin brut quand les identifiants sont autorisés."
            ),
            // ── Sensitive data in URL query string ────────────────────────
            r!(
                r#"(?i)(https?://[^\s"'`]{0,120}[?&](password|passwd|pwd|token|api[_-]?key|secret|access[_-]?token|session)=)"#,
                Severity::Medium, VulnCategory::SensitiveDataExposure,
                "Donnée sensible dans la chaîne de requête de l'URL",
                "Un identifiant / jeton est passé dans la chaîne de requête d'une URL. Les URL sont journalisées (journaux serveur, proxys, historique du navigateur, en-tête Referer) — le secret fuit dans chacun d'eux.",
                "Envoyez les secrets dans le corps de la requête ou un en-tête Authorization, jamais dans la chaîne de requête."
            ),
            // ── Cloud metadata endpoint access ────────────────────────────
            r!(
                r#"(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata/instance|/latest/meta-data/|/computeMetadata/)"#,
                Severity::Medium, VulnCategory::InsecureConfiguration,
                "Accès au point de métadonnées cloud",
                "Accès au service de métadonnées de l'instance cloud (169.254.169.254 / metadata.google.internal). S'il est joignable via une SSRF, il laisse fuiter des identifiants cloud temporaires et des jetons IAM.",
                "Exigez IMDSv2 (limite de sauts + jeton de session). Ne relayez jamais d'URL contrôlée par l'utilisateur vers l'IP des métadonnées ; bloquez la sortie vers 169.254.169.254 depuis le code applicatif."
            ),
            // ── Weak randomness for security value ────────────────────────
            r!(
                r#"(?i)(Math\.random\(\)|new\s+Random\(\))[^;\n]{0,40}(token|secret|otp|nonce|session|reset|salt|password|api[_-]?key)"#,
                Severity::High, VulnCategory::WeakCrypto,
                "Aléa faible pour une valeur de sécurité",
                "Une valeur sensible (jeton, OTP, identifiant de session, sel…) est dérivée d'un générateur aléatoire non cryptographique (Math.random / java.util.Random). Le résultat est prévisible et peut être deviné par force brute.",
                "Utilisez un CSPRNG : crypto.randomBytes / crypto.getRandomValues (JS), secrets (Python), SecureRandom (Java), rand::rngs::OsRng (Rust)."
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Un fichier Python aux failles evidentes doit produire des findings.
    /// Un scan qui ne trouve rien sur ce cas signale un moteur muet, pas un
    /// projet sain.
    #[test]
    fn un_python_vulnerable_produit_des_findings() {
        let source = concat!(
            "import hashlib\n",
            "import sqlite3\n",
            "\n",
            "AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n",
            "\n",
            "def chercher(nom):\n",
            "    conn = sqlite3.connect(\"app.db\")\n",
            "    conn.execute(\"SELECT * FROM users WHERE name = '\" + nom + \"'\")\n",
            "    return conn.fetchall()\n",
            "\n",
            "def empreinte(mdp):\n",
            "    return hashlib.md5(mdp.encode()).hexdigest()\n",
        );

        let trouves = scan_source(Path::new("app.py"), source.as_bytes());
        let titres: Vec<&str> = trouves.iter().map(|v| v.title.as_str()).collect();
        assert!(
            !trouves.is_empty(),
            "aucune faille detectee sur un fichier qui en contient plusieurs"
        );
        println!("findings : {titres:?}");
    }
}
