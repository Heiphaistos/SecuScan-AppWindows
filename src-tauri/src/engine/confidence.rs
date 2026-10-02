//! confidence.rs — Probabilité qu'un résultat soit un VRAI problème ou un faux positif.
//!
//! Méthode (chaque ajustement est conservé et affiché à l'utilisateur) :
//! 1. Probabilité de base selon la règle : un format de clé propre à un fournisseur
//!    (AKIA…, ghp_…) est presque toujours une vraie clé ; une « chaîne à haute entropie »
//!    est souvent un hash ou un identifiant anodin.
//! 2. Ajustements selon le contexte réel : dossier de test/exemple, valeur de
//!    remplacement (« changeme », « your_key »), fichier de documentation, code tiers
//!    minifié, clé publique par conception, réputation en ligne du fichier…
//!
//! Estimation calibrée et justifiée, pas une statistique mesurée.

use crate::engine::intel::IntelStatus;
use crate::models::{Factor, ScanResult, Severity, VulnCategory, Vulnerability};

struct Kb {
    what: &'static str,
    why_real: &'static str,
    why_fp: &'static str,
    base: u8,
}

const fn kb(what: &'static str, why_real: &'static str, why_fp: &'static str, base: u8) -> Kb {
    Kb { what, why_real, why_fp, base }
}

/// Connaissance d'une règle, d'après son titre puis sa catégorie.
fn knowledge(v: &Vulnerability) -> Kb {
    let t = v.title.as_str();
    let has = |k: &str| t.contains(k);

    if matches!(v.category, VulnCategory::ConnectionStringLeak) {
        return kb(
            "Une adresse de connexion à une base de données ou à un stockage cloud contient l'identifiant et le mot de passe en clair.",
            "Toute personne ayant accès au code peut se connecter directement à la base et lire, modifier ou supprimer les données.",
            "Identifiants d'une base locale de développement (localhost, docker) ou valeurs d'exemple.",
            75,
        );
    }
    // ── Secrets au format propre à un fournisseur : très spécifiques ──
    if matches!(v.category, VulnCategory::ApiKeyLeak)
        && !has("Identifiant client OAuth Google")
        && !has("Firebase")
        && !has("webhook Slack")
        && !has("SID de clé API Twilio")
    {
        return kb(
            "Une clé d'accès à un service en ligne est écrite en clair dans le fichier.",
            "Le format correspond exactement à celui des vraies clés de ce fournisseur : toute personne ayant accès au code (ou à l'historique git) peut l'utiliser et agir à votre nom ou à vos frais.",
            "Ce peut être une clé d'exemple, de test, déjà révoquée, ou volontairement publique (clé « publishable » côté navigateur).",
            82,
        );
    }
    if has("Identifiant client OAuth Google") {
        return kb(
            "Un identifiant de client OAuth Google est présent.",
            "Combiné au secret client, il permettrait d'usurper l'application.",
            "Un client ID OAuth est PUBLIC par conception (il est visible dans toute page de connexion Google). Seul le client secret est sensible.",
            18,
        );
    }
    if has("Firebase") {
        return kb(
            "L'URL d'une base de données Firebase est présente.",
            "Si les règles de sécurité Firebase sont ouvertes, n'importe qui peut lire ou écrire la base.",
            "L'URL Firebase est publique par conception ; le risque dépend uniquement des règles d'accès configurées côté Firebase.",
            22,
        );
    }
    if has("webhook Slack") || has("SID de clé API Twilio") {
        return kb(
            "Un identifiant d'intégration (webhook Slack, SID Twilio) est présent.",
            "Un webhook permet à quiconque de publier des messages dans le canal ; un SID aide à cibler le compte.",
            "Un SID seul ne suffit pas à s'authentifier ; un webhook peut avoir été révoqué.",
            55,
        );
    }
    if has("Clé privée") || has("Clé privée") {
        return kb(
            "Une clé privée (RSA, EC, SSH, PGP…) est écrite dans le fichier.",
            "Une clé privée permet de déchiffrer des communications, signer au nom du propriétaire ou se connecter à des serveurs.",
            "Clés de test générées pour les tests unitaires, certificats d'exemple de documentation.",
            78,
        );
    }
    if has("Jeton JWT exposé") {
        return kb(
            "Un jeton d'authentification JWT complet est présent.",
            "S'il n'a pas expiré, il permet de se faire passer pour l'utilisateur concerné.",
            "Jetons d'exemple (jwt.io), jetons de test expirés ou sans privilège.",
            50,
        );
    }
    if matches!(v.category, VulnCategory::HighEntropyString) {
        return kb(
            "Une chaîne aléatoire longue a été trouvée (entropie élevée).",
            "Les clés et jetons secrets ont exactement cette apparence.",
            "Hashes d'intégrité, identifiants, données encodées (images, polices) ou empreintes de commit ont aussi une forte entropie.",
            22,
        );
    }
    if matches!(v.category, VulnCategory::PasswordLeak | VulnCategory::HardcodedSecret) {
        return kb(
            "Un mot de passe ou secret semble écrit en dur dans le fichier.",
            "Un secret dans le code finit dans l'historique git, les sauvegardes et les images Docker : il faut le considérer comme compromis.",
            "La valeur peut être vide, un exemple (« changeme », « password »), un nom de variable ou une valeur de test.",
            48,
        );
    }

    // ── Binaires ──
    if has("YARA: SuspiciousShellcode") {
        return kb(
            "Le binaire contient une longue suite d'octets 0x90 (NOP) ou 0xCC (INT3).",
            "Les exploits utilisent des « toboggans » de NOP pour atteindre leur shellcode.",
            "Le compilateur Microsoft remplit l'espace entre les fonctions avec des 0xCC : on trouve ce motif dans presque TOUS les programmes Windows légitimes.",
            5,
        );
    }
    if has("YARA: DLLInjectionAPIs") {
        return kb(
            "Le binaire référence les fonctions permettant d'injecter du code dans un autre programme.",
            "Technique classique pour cacher un malware dans un processus de confiance.",
            "Débogueurs, anti-triche, outils d'accessibilité et lanceurs de jeux les utilisent aussi.",
            30,
        );
    }
    if has("YARA: ProcessHollowing") {
        return kb(
            "Le binaire référence les fonctions du « process hollowing » (vider un programme pour y loger un autre code).",
            "Technique de camouflage avancée typique des malwares.",
            "Quelques protections logicielles et outils de sécurité l'emploient.",
            45,
        );
    }
    if has("YARA: PersistenceRunKeys") {
        return kb(
            "Le binaire référence les clés de registre de démarrage automatique.",
            "Un malware s'y inscrit pour se relancer à chaque démarrage.",
            "Énormément de logiciels légitimes se lancent au démarrage (messageries, synchronisation…).",
            15,
        );
    }
    if has("YARA: RansomwareIndicators") {
        return kb(
            "Le binaire contient des marqueurs de rançongiciel (suppression des sauvegardes, extension .encrypted, « DECRYPT »).",
            "Combinaison typique d'un programme qui chiffre les fichiers puis réclame une rançon.",
            "Logiciels de chiffrement ou de sauvegarde légitimes peuvent contenir « DECRYPT » et « .encrypted ».",
            50,
        );
    }
    if has("YARA: PackerUPX") {
        return kb(
            "Le programme est compressé avec UPX.",
            "La compression masque le code à l'antivirus.",
            "UPX est très utilisé par des outils légitimes pour réduire leur taille.",
            12,
        );
    }
    if matches!(v.category, VulnCategory::MissingAslr | VulnCategory::MissingDep) || has("Control Flow Guard") {
        return kb(
            "Le programme n'active pas une protection mémoire de Windows (ASLR, DEP ou CFG). Le pourcentage indique que l'option manque vraiment, PAS un risque de virus.",
            "Si une faille existe dans ce programme, elle sera plus facile à exploiter.",
            "Ce n'est PAS un virus : c'est une option de compilation. Les anciens programmes et certains compilateurs ne l'activent pas par défaut.",
            90,
        );
    }
    if has("Réputation en ligne") {
        return kb(
            "Des bases de menaces en ligne connaissent l'empreinte exacte de ce fichier.",
            "Le fichier identique a déjà été analysé et classé dangereux.",
            "Une détection isolée (1-2 moteurs sur des dizaines) est souvent un faux positif d'heuristique.",
            80,
        );
    }

    // ── Scripts (comportements) ──
    let script_kb: Option<Kb> = match t {
        _ if has("PowerShell encodée") => Some(kb(
            "Lance PowerShell avec une commande encodée en Base64, donc illisible.",
            "Masquer la commande exécutée est une technique d'évasion typique des malwares.",
            "Des outils d'administration (SCCM, Intune) encodent leurs commandes pour éviter les problèmes de guillemets.",
            55,
        )),
        _ if has("Invoke-Expression") => Some(kb(
            "Exécute comme du code une chaîne de texte construite pendant l'exécution (IEX).",
            "Brique des « download cradles » : exécuter un script téléchargé sans l'écrire sur le disque.",
            "Certains installeurs officiels l'utilisent pour exécuter un script de leur propre domaine.",
            40,
        )),
        _ if has("téléchargement d'une charge utile distante") || has("Transfert BITS") => Some(kb(
            "Télécharge un fichier ou un script depuis Internet.",
            "Un « dropper » récupère ainsi la charge malveillante.",
            "Les scripts d'installation et de mise à jour téléchargent légitimement des outils officiels.",
            30,
        )),
        _ if has("CertUtil") => Some(kb(
            "Utilise certutil.exe pour télécharger, encoder ou décoder un fichier.",
            "Outil Windows de confiance détourné pour faire entrer une charge sans éveiller les soupçons.",
            "Usage légitime pour convertir des certificats ou calculer une empreinte.",
            45,
        )),
        _ if has("MSHTA") => Some(kb(
            "Exécute un script distant via mshta.exe.",
            "Technique d'infection courante, sans usage légitime moderne.",
            "Très rare : vieux outils internes d'entreprise.",
            65,
        )),
        _ if has("Set-MpPreference") || has("Service de sécurité arrêté") || has("registre de l'antivirus") => Some(kb(
            "Désactive ou affaiblit l'antivirus Windows Defender ou un service de sécurité.",
            "Un malware coupe la protection avant d'agir.",
            "Scripts « d'optimisation » ou de laboratoire (déconseillés mais pas malveillants).",
            62,
        )),
        _ if has("Exclusion Windows Defender") => Some(kb(
            "Ajoute un dossier ou une extension aux exclusions de Windows Defender.",
            "Le malware exclut son propre dossier pour ne jamais être analysé.",
            "Développeurs et serveurs excluent des dossiers de compilation pour la performance.",
            48,
        )),
        _ if has("contournement de l'UAC") => Some(kb(
            "Demande ou contourne l'élévation en administrateur.",
            "Un contournement d'UAC donne les droits admin sans confirmation de l'utilisateur.",
            "« Exécuter en tant qu'administrateur » est normal dans un script d'installation.",
            30,
        )),
        _ if has("Privilège Windows sensible") => Some(kb(
            "Référence un privilège Windows sensible (débogage, prise de possession…).",
            "Ces privilèges permettent de lire la mémoire d'autres programmes (vol d'identifiants).",
            "Outils d'administration et de diagnostic.",
            20,
        )),
        _ if has("utilisateur local / du groupe Administrateurs") => Some(kb(
            "Crée un compte ou modifie le groupe Administrateurs.",
            "Un attaquant ajoute un compte caché pour garder l'accès.",
            "Scripts de provisionnement de postes par un administrateur.",
            42,
        )),
        _ if has("options d'exécution masquée") => Some(kb(
            "Lance PowerShell sans fenêtre et/ou sans politique d'exécution.",
            "Cache l'exécution à l'utilisateur.",
            "Tâches planifiées et scripts de fond l'utilisent pour ne pas déranger.",
            28,
        )),
        _ if has("Tâche planifiée créée en SYSTEM") => Some(kb(
            "Crée une tâche planifiée qui s'exécute avec le compte SYSTEM.",
            "Persistance avec les droits maximum.",
            "Agents de mise à jour, antivirus et outils de gestion de parc font de même.",
            32,
        )),
        _ if has("clé de registre Run") => Some(kb(
            "Inscrit un programme au démarrage automatique via le registre.",
            "Persistance : le malware se relance à chaque démarrage.",
            "Très courant pour les logiciels légitimes qui démarrent avec Windows.",
            22,
        )),
        _ if has("Création de processus via WMI") => Some(kb(
            "Crée un processus via WMI.",
            "Exécution discrète ou à distance, utilisée pour le déplacement latéral.",
            "Outils d'administration et d'inventaire.",
            25,
        )),
        _ if has("rundll32 / regsvr32") => Some(kb(
            "Exécute du code via rundll32.exe ou regsvr32.exe.",
            "Outils Windows de confiance détournés pour lancer une DLL ou un script malveillant.",
            "Enregistrement légitime de composants par un installeur.",
            40,
        )),
        _ if has("Windows Script Host") => Some(kb(
            "Lance un script VBScript/JScript via wscript/cscript.",
            "Vecteur fréquent des pièces jointes malveillantes.",
            "Scripts d'administration anciens mais légitimes.",
            15,
        )),
        _ if has("Effacement des journaux d'événements") => Some(kb(
            "Efface les journaux d'événements Windows.",
            "Un attaquant efface ses traces.",
            "Nettoyage de machines de test.",
            60,
        )),
        _ if has("curl | bash") => Some(kb(
            "Télécharge un script et l'exécute immédiatement (curl … | bash).",
            "Exécute un code distant sans aucune vérification.",
            "C'est la méthode d'installation officielle de nombreux outils (rustup, Homebrew, nvm…).",
            22,
        )),
        _ if has("Accès au presse-papiers") => Some(kb(
            "Lit ou modifie le presse-papiers.",
            "Les « clippers » remplacent une adresse de portefeuille copiée.",
            "Copier-coller automatisé : très courant.",
            18,
        )),
        _ if has("Follina") => Some(kb(
            "Utilise le protocole ms-msdt (faille Follina, CVE-2022-30190).",
            "Exploitation connue permettant d'exécuter du code à l'ouverture d'un document.",
            "Uniquement dans du matériel de recherche en sécurité.",
            88,
        )),
        _ if has("chargement réflectif d'assembly") => Some(kb(
            "Charge un programme .NET directement en mémoire.",
            "Exécution « sans fichier » d'outils offensifs.",
            "Plugins et outils d'administration chargent des bibliothèques dynamiquement.",
            40,
        )),
        _ if has("Décodage Base64") => Some(kb(
            "Décode des données Base64.",
            "Peut dissimuler une charge.",
            "Très courant : certificats, images, configuration.",
            12,
        )),
        _ if has("marqueurs d'obfuscation") => Some(kb(
            "Le script contient des marqueurs d'obfuscation (caractères d'échappement, concaténations).",
            "Rend le code illisible pour échapper aux antivirus.",
            "Scripts générés automatiquement ou minifiés.",
            50,
        )),
        _ if has("Copie du magasin d'identifiants") => Some(kb(
            "Copie la base des comptes Windows (NTDS.dit / SAM).",
            "Vol de tous les mots de passe du domaine ou de la machine.",
            "Sauvegardes d'annuaire par un administrateur (rare).",
            78,
        )),
        _ if has("stockage des clichés VSS") => Some(kb(
            "Réduit l'espace des clichés instantanés, ce qui les supprime.",
            "Technique de rançongiciel pour empêcher la restauration.",
            "Maintenance disque (rare).",
            75,
        )),
        _ if has("flux de données alternatifs") => Some(kb(
            "Utilise un flux de données alternatif NTFS (fichier caché dans un autre).",
            "Dissimulation de charge.",
            "Windows marque les fichiers téléchargés avec un ADS (Zone.Identifier) : très courant.",
            25,
        )),
        _ => None,
    };
    if let Some(k) = script_kb {
        return k;
    }

    // ── Code source (SAST) : par catégorie, ajusté par règle ──
    let base = match t {
        _ if has("execute() direct") || has("f-string") || has("requête brute ORM") => 55,
        _ if has("concaténation de chaîne dans une requête") => 42,
        _ if has("superglobale PHP affichée") => 75,
        _ if has("dangerouslySetInnerHTML") || has("text/template Go") => 30,
        _ if has("innerHTML") || has("document.write") => 40,
        _ if has("eval()") => 40,
        _ if has("Fonction cryptographique faible") => 28,
        _ if has("ECB") => 70,
        _ if has("CSPRNG absent") => 25,
        _ if has("Aléa faible pour une valeur de sécurité") => 60,
        _ if has("origine générique") => 45,
        _ if has("réflexion de l'origine") => 62,
        _ if has("alg:none") => 80,
        _ if has("Vérification des certificats TLS désactivée") => 70,
        _ if has("Mode débogage") => 50,
        _ if has("métadonnées cloud") => 35,
        _ if has("Donnée sensible dans la chaîne de requête") => 40,
        _ if has("fichier temporaire non sécurisée") => 35,
        _ if has("Introspection GraphQL") => 40,
        _ if has("Pollution de prototype") => 35,
        _ if has("XXE") => 45,
        _ => match v.category {
            VulnCategory::InsecureDeserialization => 52,
            VulnCategory::CommandInjection => 50,
            VulnCategory::PathTraversal => 48,
            VulnCategory::OpenRedirect => 40,
            VulnCategory::ArbitraryCodeExecution => 50,
            _ => 42,
        },
    };
    let (what, why_real, why_fp) = match v.category {
        VulnCategory::SqlInjection => (
            "Une requête de base de données est construite en collant du texte, potentiellement fourni par l'utilisateur.",
            "Un attaquant peut modifier la requête pour lire, modifier ou supprimer des données.",
            "Si la valeur insérée est une constante ou déjà validée (nombre, liste blanche), il n'y a pas d'injection possible.",
        ),
        VulnCategory::Xss => (
            "Du contenu est inséré dans la page web sans être échappé.",
            "Un attaquant peut injecter du JavaScript qui s'exécute chez vos utilisateurs (vol de session).",
            "Si le contenu inséré est une constante ou déjà assaini (DOMPurify, échappement), il n'y a pas de risque.",
        ),
        VulnCategory::CommandInjection => (
            "Une commande système ou une requête (shell, LDAP) est construite avec du texte variable.",
            "Un attaquant qui contrôle ce texte peut exécuter ses propres commandes sur le serveur.",
            "Si les valeurs viennent uniquement du programme (pas de l'utilisateur), l'injection est impossible.",
        ),
        VulnCategory::PathTraversal => (
            "Un chemin de fichier est construit à partir d'une valeur variable.",
            "Avec « ../ », un attaquant peut lire ou écrire des fichiers hors du dossier prévu.",
            "Si le chemin est validé ou provient d'une source de confiance, il n'y a pas de risque.",
        ),
        VulnCategory::WeakCrypto => (
            "Un algorithme cryptographique faible ou un générateur aléatoire non sûr est utilisé.",
            "Les données protégées peuvent être déchiffrées, falsifiées ou devinées.",
            "MD5/SHA-1 et random() sont légitimes pour des usages NON sécuritaires (somme de contrôle, cache, jeu, tri).",
        ),
        VulnCategory::CorsMisconfiguration => (
            "La politique CORS autorise des sites tiers à interroger ce serveur.",
            "Un site malveillant peut faire des requêtes au nom de vos utilisateurs connectés.",
            "Pour des ressources publiques sans authentification (CDN, API ouverte), c'est voulu.",
        ),
        VulnCategory::InsecureDeserialization => (
            "Des données externes sont désérialisées (reconstruites en objets) sans contrôle.",
            "Des données piégées peuvent exécuter du code sur le serveur.",
            "Si les données viennent d'une source de confiance (fichier local signé), le risque est faible.",
        ),
        VulnCategory::OpenRedirect => (
            "Une redirection utilise une URL fournie par l'utilisateur.",
            "Un attaquant peut rediriger vers un site d'hameçonnage en utilisant votre domaine.",
            "Si l'URL est validée contre une liste de domaines autorisés, il n'y a pas de risque.",
        ),
        VulnCategory::SensitiveDataExposure => (
            "Des données sensibles circulent là où elles peuvent fuiter (URL, logs, presse-papiers).",
            "Elles se retrouvent dans l'historique du navigateur, les journaux des proxys, etc.",
            "Si la valeur n'est pas réellement secrète, ce n'est pas un problème.",
        ),
        _ => (
            "Une configuration ou un usage de code affaiblit la sécurité.",
            "Cela peut ouvrir la porte à une attaque si le code est exposé.",
            "Le contexte (environnement de développement, code non exposé) peut rendre ce point sans conséquence.",
        ),
    };
    kb(what, why_real, why_fp, base)
}

fn factor(label: impl Into<String>, delta: i16) -> Factor {
    Factor { label: label.into(), delta }
}

const PLACEHOLDERS: &[&str] = &[
    "placeholder", "your_api", "your-api", "your_key", "your-key", "yourkey", "changeme", "change_me",
    "replace_me", "replaceme", "insert_key", "insert_secret", "example", "fake_", "dummy", "sample_key",
    "demo_key", "test_key", "test_secret", "xxxx", "<your", "${", "{{", "process.env", "os.environ",
    "getenv", "env(", "1234567890abcdef", "abcdefghijklmnop", "password123", "secret123", "todo",
];

fn is_secret(cat: &VulnCategory) -> bool {
    matches!(
        cat,
        VulnCategory::ApiKeyLeak
            | VulnCategory::PasswordLeak
            | VulnCategory::HardcodedSecret
            | VulnCategory::ConnectionStringLeak
            | VulnCategory::JwtExposed
            | VulnCategory::HighEntropyString
    )
}

fn is_behaviour(cat: &VulnCategory) -> bool {
    matches!(
        cat,
        VulnCategory::ObfuscatedCommand
            | VulnCategory::AntivirusDisabled
            | VulnCategory::PayloadDownload
            | VulnCategory::PrivilegeEscalation
            | VulnCategory::SuspiciousPersistence
            | VulnCategory::MalwareIndicator
            | VulnCategory::DllInjection
            | VulnCategory::RansomwareIndicator
    ) || (matches!(cat, VulnCategory::ArbitraryCodeExecution))
}

/// Signal de CODE MALVEILLANT (et non de faille) : comportement détecté dans un script
/// ou un binaire, ou réputation en ligne. Une injection SSTI dans une appli web est une
/// faille, pas un virus.
fn is_malware_signal(v: &Vulnerability) -> bool {
    if v.title.starts_with("YARA:") || v.title.starts_with("Réputation en ligne") {
        return true;
    }
    let ext = v.file_path.rsplit('.').next().unwrap_or("").to_lowercase();
    let script_or_bin = matches!(
        ext.as_str(),
        "bat" | "cmd" | "ps1" | "psm1" | "psd1" | "sh" | "bash" | "zsh" | "fish" | "vbs" | "vbe" | "wsf" | "wsh"
            | "exe" | "dll" | "sys" | "ocx" | "scr" | "com" | "drv"
    );
    script_or_bin && is_behaviour(&v.category)
}

/// Ligne signalée (au centre de l'extrait « nnnn | code »).
fn flagged_line(v: &Vulnerability) -> String {
    let Some(snip) = &v.code_snippet else { return String::new() };
    if let Some(n) = v.line_number {
        let prefix = format!("{n:>4} | ");
        if let Some(l) = snip.lines().find(|l| l.starts_with(&prefix)) {
            return l[prefix.len()..].to_string();
        }
    }
    snip.clone()
}

/// Chemin relatif à la racine du scan, en « / » : sur le bureau les chemins sont
/// absolus, et un dossier parent de la cible (« …/examples/mon-projet ») ne doit
/// pas faire passer tout le projet pour du code d'exemple.
fn relative_path(file: &str, root: &str) -> String {
    let norm = |p: &str| p.replace('\\', "/").to_lowercase();
    let (file, root) = (norm(file), norm(root));
    let root = root.trim_end_matches('/');
    match file.strip_prefix(root) {
        Some(rest) if !root.is_empty() => rest.trim_start_matches('/').to_string(),
        _ => file,
    }
}

fn context_factors(v: &Vulnerability, path: &str, rep: Option<(IntelStatus, &str)>) -> Vec<Factor> {
    let mut f = Vec::new();
    let base_name = path.rsplit('/').next().unwrap_or(path);
    let line = flagged_line(v).to_lowercase();
    let matched = v.matched_pattern.as_deref().unwrap_or("").to_lowercase();

    // Contexte de test / exemple (repris des heuristiques fp_hint).
    let segs: Vec<&str> = path.split('/').collect();
    let test_dirs = [
        "test", "tests", "spec", "specs", "mock", "mocks", "fixture", "fixtures", "example", "examples",
        "sample", "samples", "demo", "__tests__", "testdata",
    ];
    let in_test_dir = segs[..segs.len().saturating_sub(1)]
        .iter()
        .any(|s| test_dirs.iter().any(|t| s == t || s.starts_with(&format!("{t}_")) || s.ends_with(&format!("_{t}"))));
    let test_file = [
        "_test.", ".test.", ".spec.", "_spec.", "test_",
    ]
    .iter()
    .any(|k| base_name.contains(k));
    if in_test_dir || test_file {
        f.push(factor("fichier de test / d'exemple : ce code n'est généralement pas exécuté en production", -35));
    }

    // Modèles de configuration.
    if base_name.contains(".example") || base_name.contains(".sample") || base_name.contains(".template") || base_name.ends_with(".dist") {
        f.push(factor("fichier modèle (.example / .sample) : contient normalement des valeurs factices", -40));
    }

    // Documentation.
    if [".md", ".rst", ".txt", ".adoc", ".html"].iter().any(|e| base_name.ends_with(e)) && !is_behaviour(&v.category) {
        f.push(factor("fichier de documentation : le code cité n'est pas exécuté", -30));
    }

    // Code tiers / généré.
    if base_name.contains(".min.") || path.contains("/vendor/") || path.contains("third_party") || path.contains("/static/js/") {
        f.push(factor("code tiers ou minifié : vous ne l'avez probablement pas écrit, et il est souvent sans risque dans ce contexte", -15));
    }

    if is_secret(&v.category) {
        if matches!(v.category, VulnCategory::ConnectionStringLeak)
            && ["localhost", "127.0.0.1", "@db:", "@postgres:", "@mysql:"].iter().any(|k| line.contains(k))
        {
            f.push(factor("base de données locale / de développement", -25));
        }
        if let Some(p) = PLACEHOLDERS.iter().find(|p| line.contains(*p) || matched.contains(*p)) {
            f.push(factor(format!("la valeur ressemble à un exemple ou à une référence de variable (« {p} »)"), -45));
        }
        if v.title.contains("Stripe") && (line.contains("pk_live") || line.contains("pk_test")) && !line.contains("sk_") {
            f.push(factor("clé Stripe « publishable » (pk_…) : conçue pour être publique", -55));
        } else if line.contains("sk_test") || line.contains("_test_") {
            f.push(factor("clé de TEST (mode bac à sable) : pas d'accès aux vraies données", -25));
        }
        if matches!(v.category, VulnCategory::HighEntropyString)
            && (base_name.ends_with(".lock") || base_name.contains("lock.json") || base_name.ends_with(".sum"))
        {
            f.push(factor("fichier de verrouillage de dépendances : ce sont des empreintes d'intégrité, pas des secrets", -20));
        }
        if matches!(v.category, VulnCategory::HighEntropyString) {
            let raw = matched.trim_end_matches('…');
            if raw.len() >= 32 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
                f.push(factor("chaîne purement hexadécimale : typiquement un hash ou un identifiant", -12));
            }
        }
    }

    if matches!(v.category, VulnCategory::WeakCrypto) {
        if line.contains("md5") || line.contains("sha1") || line.contains("sha-1") {
            let security = ["password", "passwd", "pwd", "token", "secret", "sign", "auth"].iter().any(|k| line.contains(k));
            if security {
                f.push(factor("utilisé sur un mot de passe / jeton : usage de sécurité réel", 30));
            } else {
                f.push(factor("aucun mot de passe ni jeton sur la ligne : probablement une somme de contrôle", -12));
            }
        }
        if line.contains("random") && ["token", "password", "secret", "key", "otp", "nonce", "salt"].iter().any(|k| line.contains(k)) {
            f.push(factor("le hasard sert à générer un secret (jeton, mot de passe, sel)", 35));
        }
    }

    if matches!(v.category, VulnCategory::SqlInjection | VulnCategory::Xss | VulnCategory::CommandInjection | VulnCategory::PathTraversal) {
        let user_input = ["req.", "request", "$_get", "$_post", "$_request", "params", "query", "input(", "argv", "form", "body"]
            .iter()
            .any(|k| line.contains(k));
        if user_input {
            f.push(factor("la ligne manipule directement une entrée utilisateur (requête, formulaire, paramètre)", 20));
        }
    }

    if matches!(v.category, VulnCategory::CommandInjection) {
        let ext = base_name.rsplit('.').next().unwrap_or("");
        if matches!(ext, "rs" | "go" | "c" | "cpp" | "cs") {
            f.push(factor("outil système compilé : l'exécution de processus y est un usage normal", -10));
        }
    }

    if v.title.contains("XXE") && line.contains("documentbuilderfactory") {
        f.push(factor(
            "création d'un parseur XML Java : sûr si « disallow-doctype-decl » est activé juste après (non vérifiable sur une seule ligne)",
            -20,
        ));
    }

    if matches!(v.category, VulnCategory::CorsMisconfiguration)
        && ["nginx", "static", "cdn", "assets", "public"].iter().any(|k| path.contains(k))
    {
        f.push(factor("ressources statiques publiques : un CORS ouvert est acceptable", -25));
    }

    // Réputation en ligne du fichier concerné.
    if let Some((status, src)) = rep {
        if is_behaviour(&v.category) || matches!(v.category, VulnCategory::MissingAslr | VulnCategory::MissingDep) {
            match status {
                IntelStatus::Malicious if is_behaviour(&v.category) => {
                    f.push(factor(format!("fichier classé malveillant par une base en ligne ({src})"), 30))
                }
                IntelStatus::KnownGood if is_behaviour(&v.category) => {
                    f.push(factor(format!("fichier référencé comme légitime ({src})"), -40))
                }
                IntelStatus::Clean if is_behaviour(&v.category) => {
                    f.push(factor(format!("aucune détection antivirus en ligne ({src})"), -15))
                }
                _ => {}
            }
        }
    }
    f
}

pub fn label_for(p: u8) -> &'static str {
    match p {
        80..=100 => "Très probablement réel",
        55..=79 => "Probablement réel",
        30..=54 => "Douteux — à vérifier",
        12..=29 => "Probablement un faux positif",
        _ => "Faux positif très probable",
    }
}

/// Calcule la confiance de chaque résultat et la synthèse du scan.
pub fn apply(result: &mut ScanResult) {
    // Réputation par fichier : statut le plus significatif.
    let rep_of = |path: &str| -> Option<(IntelStatus, String)> {
        let fr = result.reputation.iter().find(|r| r.file_path == path)?;
        let pick = |st: IntelStatus| fr.sources.iter().find(|s| s.status == st).map(|s| (st, s.source.clone()));
        pick(IntelStatus::Malicious)
            .or_else(|| pick(IntelStatus::KnownGood))
            .or_else(|| {
                let vt_clean = fr.sources.iter().find(|s| s.source == "VirusTotal" && s.status == IntelStatus::Clean);
                vt_clean.map(|s| (IntelStatus::Clean, s.source.clone()))
            })
    };
    let reps: Vec<Option<(IntelStatus, String)>> = result.vulnerabilities.iter().map(|v| rep_of(&v.file_path)).collect();
    let root = result.target_path.clone();

    for (v, rep) in result.vulnerabilities.iter_mut().zip(reps) {
        let k = knowledge(v);
        let factors = if v.base_confidence > 0 && !v.confidence_factors.is_empty() && v.title.starts_with("Réputation en ligne") {
            v.confidence_factors.clone()
        } else {
            context_factors(v, &relative_path(&v.file_path, &root), rep.as_ref().map(|(s, n)| (*s, n.as_str())))
        };
        let base = if v.title.starts_with("Réputation en ligne") && v.base_confidence > 0 { v.base_confidence } else { k.base };
        let sum: i16 = factors.iter().map(|f| f.delta).sum();
        let p = (base as i16 + sum).clamp(1, 99) as u8;
        v.base_confidence = base;
        v.confidence = p;
        v.false_positive = 100 - p;
        v.confidence_label = label_for(p).to_string();
        v.what_it_does = k.what.to_string();
        v.why_real = k.why_real.to_string();
        v.why_false_positive = k.why_fp.to_string();
        v.confidence_factors = factors;
    }

    // Tri : sévérité puis confiance (le plus grave et le plus sûr d'abord).
    result.vulnerabilities.sort_by(|a, b| {
        b.severity.score().cmp(&a.severity.score()).then(b.confidence.cmp(&a.confidence))
    });

    let likely_real = result.vulnerabilities.iter().filter(|v| v.confidence >= 55).count();
    let to_review = result.vulnerabilities.iter().filter(|v| (30..55).contains(&v.confidence)).count();
    let likely_fp = result.vulnerabilities.iter().filter(|v| v.confidence < 30).count();

    // Probabilité de code malveillant : comportements (scripts/binaires) + réputation,
    // combinés comme des indices indépendants, par fichier puis sur le projet.
    let mut p_clean = 1.0f64;
    let mut files: Vec<&str> = result.vulnerabilities.iter().map(|v| v.file_path.as_str()).collect();
    files.sort();
    files.dedup();
    for file in files {
        let confs: Vec<f64> = result
            .vulnerabilities
            .iter()
            .filter(|v| v.file_path == file && is_malware_signal(v))
            .map(|v| v.confidence as f64)
            .collect();
        if confs.is_empty() {
            continue;
        }
        let max = confs.iter().cloned().fold(0.0, f64::max);
        let rest: f64 = confs.iter().sum::<f64>() - max;
        let g = (max + (rest * 0.15).min(15.0)).min(99.0) / 100.0;
        p_clean *= 1.0 - g;
    }
    let malware = (((1.0 - p_clean) * 100.0).round() as i32).clamp(0, 99) as u8;

    let total = result.vulnerabilities.len();
    let summary = if total == 0 {
        "Aucun problème détecté.".to_string()
    } else {
        format!(
            "{total} résultat(s) : {likely_real} probablement réel(s), {to_review} à vérifier, {likely_fp} faux positif(s) probable(s). \
             Probabilité qu'un code malveillant (virus, script d'attaque) soit présent : {malware} %."
        )
    };
    result.assessment = crate::models::ScanAssessment {
        likely_real,
        to_review,
        likely_false_positive: likely_fp,
        malware_probability: malware,
        summary,
        method: "Chaque résultat part d'une probabilité de base propre à la règle (un format de clé spécifique à un fournisseur \
                 est presque toujours une vraie clé ; une chaîne « à haute entropie » est souvent un hash), puis est ajusté selon \
                 le contexte : dossier de test ou d'exemple, valeur factice, documentation, code tiers, clé publique par conception, \
                 usage réel d'une entrée utilisateur, réputation en ligne du fichier. Chaque ajustement est affiché."
            .into(),
    };
}

/// Sévérité affichée → libellé français (rapports).
pub fn severity_fr(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITIQUE",
        Severity::High => "ÉLEVÉE",
        Severity::Medium => "MOYENNE",
        Severity::Low => "FAIBLE",
        Severity::Info => "INFO",
    }
}

#[cfg(test)]
#[path = "confidence_tests.rs"]
mod tests;
