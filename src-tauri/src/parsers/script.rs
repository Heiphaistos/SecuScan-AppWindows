//! Script parser — Batch, PowerShell, Shell, VBScript analysis.

use once_cell::sync::Lazy;
use regex::Regex;
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
                    pattern:     Regex::new($rx).expect("bad script regex"),
                    severity:    $sev,
                    category:    $cat,
                    title:       $t,
                    description: $d,
                    remediation: $f,
                }
            };
        }
        vec![
            // ── Encoded commands ──────────────────────────────────────────
            r!(
                r#"(?i)-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/]{20,}={0,2}"#,
                Severity::Critical, VulnCategory::ObfuscatedCommand,
                "Commande PowerShell encodée (-EncodedCommand)",
                "Charge utile PowerShell encodée en Base64 détectée. Technique d'obfuscation courante des logiciels malveillants.",
                "Examinez la charge utile décodée. Bloquez l'exécution de -EncodedCommand via AppLocker/WDAC."
            ),
            r!(
                r#"(?i)(IEX|Invoke-Expression)\s*\([^)]*\)"#,
                Severity::High, VulnCategory::ArbitraryCodeExecution,
                "PowerShell Invoke-Expression (IEX)",
                "IEX évalue une chaîne arbitraire comme du code. Si l'entrée n'est pas fiable → RCE.",
                "Supprimez IEX. Activez la journalisation des blocs de script PowerShell (Event ID 4104)."
            ),
            // ── Payload download ──────────────────────────────────────────
            r!(
                r#"(?i)(Invoke-WebRequest|iwr|DownloadString|DownloadFile|DownloadData)\s+['""]?(https?|ftp)://"#,
                Severity::High, VulnCategory::PayloadDownload,
                "PowerShell — téléchargement d'une charge utile distante",
                "Le script télécharge du contenu depuis une URL distante. Il pourrait récupérer une charge utile malveillante.",
                "Mettez sur liste blanche les destinations de téléchargement autorisées. Bloquez les URL externes non fiables via proxy/pare-feu."
            ),
            r!(
                r#"(?i)bitsadmin\s+/transfer\s+\S+\s+https?://"#,
                Severity::High, VulnCategory::PayloadDownload,
                "Transfert BITS — téléchargement de fichier distant",
                "BITSAdmin utilisé pour télécharger des fichiers depuis un serveur distant. Souvent employé dans les attaques LOLBin.",
                "Surveillez les tâches BITS. Restreignez l'exécution de bitsadmin.exe via AppLocker."
            ),
            r!(
                r#"(?i)(certutil|certutil\.exe)\s+(-urlcache|-decode|-encode)"#,
                Severity::High, VulnCategory::PayloadDownload,
                "Détournement de CertUtil (LOLBin)",
                "certutil.exe utilisé comme LOLBin pour télécharger ou décoder des fichiers en contournant les contrôles de sécurité.",
                "Empêchez certutil.exe de télécharger des URL via AppLocker ou des règles réseau."
            ),
            r!(
                r#"(?i)mshta\s+(https?://|javascript:|vbscript:)"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "Exécution de script distant par MSHTA",
                "mshta.exe exécute une URL distante ou un script en ligne — technique de dropper de malware courante.",
                "Bloquez mshta.exe via AppLocker."
            ),
            // ── Antivirus disable ─────────────────────────────────────────
            r!(
                r#"(?i)Set-MpPreference\s+-(Disable|ExclusionPath|ExclusionExtension)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Windows Defender désactivé/affaibli via Set-MpPreference",
                "Commande PowerShell qui désactive Windows Defender ou ajoute des exclusions.",
                "Supprimez cette configuration. Surveillez l'Event ID 5001. Protégez avec la protection contre les falsifications."
            ),
            r!(
                r#"(?i)(Stop-Service|sc\s+stop|net\s+stop)\s+.*(windefend|mpssvc|wscsvc|MsMpEng)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Service de sécurité arrêté",
                "Arrêt du service Windows Defender ou du pare-feu.",
                "Déclenchez une alerte sur ce motif. Imposez la protection contre les falsifications pour les services de sécurité."
            ),
            r!(
                r#"(?i)reg\s+(add|delete)\s+.*\\(windefend|Defender|AntiVirus)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Manipulation du registre de l'antivirus",
                "Modification du registre visant la configuration d'un produit de sécurité.",
                "Surveillez les écritures de registre dans HKLM\\SOFTWARE\\Microsoft\\Windows Defender."
            ),
            // ── Privilege escalation ──────────────────────────────────────
            r!(
                r#"(?i)(runas|Start-Process\s+.*-Verb\s+RunAs)"#,
                Severity::High, VulnCategory::PrivilegeEscalation,
                "Élévation de privilèges — Exécuter en tant que / contournement de l'UAC",
                "Le script demande des privilèges élevés ou lance un processus en tant qu'administrateur.",
                "Vérifiez que l'élévation est nécessaire."
            ),
            r!(
                r#"(?i)(SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege)"#,
                Severity::High, VulnCategory::PrivilegeEscalation,
                "Privilège Windows sensible référencé",
                "Le script fait référence à des droits de jeton à haut privilège souvent détournés pour une élévation de privilèges.",
                "Vérifiez pourquoi ce privilège est nécessaire. Exécutez sous un compte de service à privilèges minimaux."
            ),
            r!(
                r#"(?i)net\s+(user|localgroup\s+administrators)\s+\S+\s+(/add|/del)"#,
                Severity::Critical, VulnCategory::PrivilegeEscalation,
                "Modification d'utilisateur local / du groupe Administrateurs",
                "Le script ajoute/supprime un utilisateur local ou modifie le groupe Administrateurs.",
                "Bloquez net.exe dans les scripts via AppLocker. Déclenchez une alerte sur les Event ID 4720/4732."
            ),
            // ── Hidden execution ──────────────────────────────────────────
            r!(
                r#"(?i)powershell\s+(-nop|noprofile|-w\s+hidden|-windowstyle\s+hidden|-exec\s+bypass)"#,
                Severity::High, VulnCategory::ObfuscatedCommand,
                "PowerShell — options d'exécution masquée",
                "PowerShell lancé avec -NoProfile, -Hidden ou -ExecutionPolicy Bypass.",
                "Auditez cet appel. Bloquez -ExecutionPolicy Bypass via une stratégie de groupe."
            ),
            // ── Persistence ───────────────────────────────────────────────
            r!(
                r#"(?i)schtasks\s+/create\s+.*\/ru\s+(system|administrator)"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Tâche planifiée créée en SYSTEM",
                "Tâche planifiée exécutée en SYSTEM — mécanisme de persistance.",
                "Auditez les tâches planifiées. Surveillez l'Event ID 4698 (tâche créée)."
            ),
            r!(
                r#"(?i)reg\s+add.*\\(Run|RunOnce|RunServices|Winlogon)"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Persistance par clé de registre Run",
                "Ajout d'une valeur dans une clé de registre de démarrage automatique — mécanisme de persistance classique.",
                "Vérifiez la nécessité. Surveillez HKCU/HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run."
            ),
            // ── WMI process creation ──────────────────────────────────────
            r!(
                r#"(?i)(wmic\s+process\s+call\s+create|Invoke-WmiMethod\s+.*-Name\s+Create|Get-WmiObject\s+.*Win32_Process)"#,
                Severity::High, VulnCategory::ArbitraryCodeExecution,
                "Création de processus via WMI",
                "WMI utilisé pour lancer un processus — technique courante de mouvement latéral / d'exécution sans fichier.",
                "Auditez l'activité WMI. Surveillez l'Event ID 4688 et le journal opérationnel WMI-Activity."
            ),
            // ── rundll32 / regsvr32 LOLBin ────────────────────────────────
            r!(
                r#"(?i)(rundll32\s+.*javascript:|regsvr32\s+(/s\s+)?/(i|u):https?://|regsvr32\s+.*scrobj\.dll)"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "Exécution LOLBin via rundll32 / regsvr32",
                "rundll32/regsvr32 détourné pour exécuter des scriptlets distants (Squiblydoo) — contourne la liste blanche d'applications.",
                "Bloquez l'exécution de scriptlets via WDAC/AppLocker. Surveillez les accès réseau de regsvr32."
            ),
            // ── wscript / cscript ─────────────────────────────────────────
            r!(
                r#"(?i)(wscript|cscript)\s+.*\.(vbs|js|wsf|jse|vbe)"#,
                Severity::Medium, VulnCategory::ArbitraryCodeExecution,
                "Exécution via Windows Script Host",
                "wscript/cscript exécute un fichier script — vecteur courant de diffusion de malware par pièces jointes d'e-mail.",
                "Désactivez Windows Script Host s'il n'est pas utilisé (HKLM\\...\\Windows Script Host\\Settings\\Enabled=0)."
            ),
            // ── Defender exclusion added ──────────────────────────────────
            r!(
                r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Exclusion Windows Defender ajoutée",
                "L'attaquant ajoute une exclusion Defender pour soustraire une charge utile à l'analyse.",
                "Déclenchez une alerte sur les exclusions Add-MpPreference. Activez la protection contre les falsifications."
            ),
            // ── Event log clearing ────────────────────────────────────────
            r!(
                r#"(?i)(wevtutil\s+cl|Clear-EventLog|Remove-EventLog|wevtutil\s+clear-log)"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Effacement des journaux d'événements — anti-forensique",
                "Le script efface les journaux d'événements Windows pour supprimer les traces d'intrusion.",
                "Déclenchez une alerte sur l'Event ID 1102 (journal d'audit effacé). Transférez les journaux vers un SIEM distant."
            ),
            // ── curl|bash remote exec ─────────────────────────────────────
            r!(
                r#"(?i)(curl|wget)\s+[^|]*https?://[^|]*\|\s*(sudo\s+)?(bash|sh|python|perl)"#,
                Severity::High, VulnCategory::PayloadDownload,
                "Script distant redirigé vers un shell (curl | bash)",
                "Télécharge et exécute directement un script distant — aucune vérification d'intégrité, confiance totale dans le serveur.",
                "Téléchargez, inspectez et vérifiez la somme de contrôle avant d'exécuter. Évitez les installateurs du type pipe-to-shell."
            ),
            // ── Clipboard theft ───────────────────────────────────────────
            r!(
                r#"(?i)(Get-Clipboard|Set-Clipboard\s+.*[13][a-km-zA-HJ-NP-Z1-9]{25,})"#,
                Severity::Medium, VulnCategory::SensitiveDataExposure,
                "Accès au presse-papiers — détournement / vol possible",
                "Le script lit ou écrase le presse-papiers — technique des « clippers » pour substituer des adresses de portefeuille crypto.",
                "Auditez l'accès au presse-papiers. Déclenchez une alerte s'il est associé à des motifs d'adresse de portefeuille."
            ),
            // ── Follina (CVE-2022-30190) ──────────────────────────────────
            r!(
                r#"(?i)(ms-msdt:|msdt\.exe\s+.{0,40}IT_BrowseForFile|msdt\.exe\s+/id\s+PCWDiagnostic)"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "Follina — détournement du protocole MSDT (CVE-2022-30190)",
                "Appel du protocole ms-msdt: / de msdt.exe utilisé pour obtenir une exécution de code depuis un document.",
                "Désactivez le gestionnaire de protocole URL ms-msdt. Appliquez le correctif (CVE-2022-30190). Bloquez msdt.exe via les règles ASR."
            ),
            // ── Reflective assembly load ──────────────────────────────────
            r!(
                r#"(?i)\[?(System\.)?Reflection\.Assembly\]?::Load(WithPartialName|File|From)?\s*\("#,
                Severity::High, VulnCategory::ArbitraryCodeExecution,
                "PowerShell — chargement réflectif d'assembly",
                "Assembly .NET chargé en mémoire via [Reflection.Assembly]::Load — exécution sans fichier de charges utiles managées.",
                "Vérifiez pourquoi un assembly est chargé à l'exécution. Activez Script Block Logging + AMSI."
            ),
            // ── Base64 deobfuscation marker ───────────────────────────────
            r!(
                r#"(?i)\[Convert\]::FromBase64String\s*\("#,
                Severity::Medium, VulnCategory::ObfuscatedCommand,
                "Décodage Base64 dans un script",
                "[Convert]::FromBase64String décode souvent une charge utile obfusquée avant son exécution.",
                "Inspectez le contenu décodé. Signalez-le s'il est suivi de IEX/Assembly.Load/Invoke."
            ),
            // ── Obfuscation markers ───────────────────────────────────────
            r!(
                r#"(?i)(invoke-obfuscation|-bxor\s|-join\s*\(\s*\[char\]|\[char\]\s*0x[0-9a-f]{2}\s*\+)"#,
                Severity::High, VulnCategory::ObfuscatedCommand,
                "PowerShell — marqueurs d'obfuscation",
                "Obfuscation par tableau de caractères / -bxor / -join ou sortie d'Invoke-Obfuscation — utilisée pour masquer des commandes malveillantes.",
                "Désobfusquez et inspectez. Activez Script Block Logging (Event ID 4104) pour capturer la commande décodée."
            ),
            // ── Credential store copy (NTDS/SAM) ──────────────────────────
            r!(
                r#"(?i)(esentutl\s+/y|esentutl\s+.{0,40}\.dmp|copy\s+.{0,40}\\ntds\.dit|reg\s+save\s+hklm\\sam)"#,
                Severity::Critical, VulnCategory::SensitiveDataExposure,
                "Copie du magasin d'identifiants (NTDS / SAM)",
                "Copier ntds.dit ou la ruche SAM (via esentutl, VSS ou reg save) est une technique de vol d'identifiants.",
                "Déclenchez une alerte sur l'accès à NTDS/SAM. Restreignez les privilèges de sauvegarde. Surveillez l'usage d'esentutl."
            ),
            // ── Shadow storage resize (ransomware prep) ───────────────────
            r!(
                r#"(?i)vssadmin\s+resize\s+shadowstorage"#,
                Severity::Critical, VulnCategory::RansomwareIndicator,
                "Redimensionnement du stockage des clichés VSS",
                "Réduire le stockage des clichés instantanés à une taille minuscule supprime silencieusement les clichés — étape courante d'un ransomware avant chiffrement.",
                "Déclenchez une alerte sur vssadmin resize. Protégez le stockage des clichés. Conservez des sauvegardes hors ligne."
            ),
            // ── NTFS alternate data stream ────────────────────────────────
            r!(
                r#"(?i)(Add-Content|Set-Content)\s+[^\n]{0,60}-Stream\s|:\$DATA\b"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Utilisation de flux de données alternatifs NTFS",
                "Écrire dans un flux de données alternatif NTFS (:$DATA / -Stream) masque une charge utile du listage normal des fichiers.",
                "Recherchez les ADS (dir /r, Get-Item -Stream). Bloquez l'exécution depuis les ADS via WDAC."
            ),
        ]
    });
    &RULES
}

pub fn scan_script(path: &Path, content: &[u8]) -> Vec<Vulnerability> {
    let raw = match std::str::from_utf8(content) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };

    // Drop lines >4 KB — same protection as sast scanner
    let scratch: String;
    let text: &str = match super::filter_long_lines(raw, 4096) {
        Some(s) => { scratch = s; &scratch }
        None    => raw,
    };

    let lines: Vec<&str> = text.lines().collect();
    let mut findings: Vec<Vulnerability> = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    for rule in get_rules() {
        let mut cnt = 0usize;
        for m in rule.pattern.find_iter(text) {
            if cnt >= 15 { break; }
            let line_idx = text[..m.start()].chars().filter(|&c| c == '\n').count();
            if lines.get(line_idx).is_some_and(|l| super::is_comment_line(l)) { continue; }
            let snippet  = context_snippet(&lines, line_idx, 2);
            let matched  = m.as_str().chars().take(150).collect::<String>();

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
            cnt += 1;
        }
    }

    findings
}

pub fn handles_extension(ext: &str) -> bool {
    matches!(ext.to_lowercase().as_str(),
        "bat" | "cmd" | "ps1" | "psm1" | "psd1" | "sh" | "bash" |
        "zsh" | "fish" | "vbs" | "vbe" | "wsf" | "wsh"
    )
}
