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
                "PowerShell Encoded Command (-EncodedCommand)",
                "Base64-encoded PowerShell payload found. Common malware obfuscation technique.",
                "Investigate the decoded payload. Block -EncodedCommand execution via AppLocker/WDAC."
            ),
            r!(
                r#"(?i)(IEX|Invoke-Expression)\s*\([^)]*\)"#,
                Severity::High, VulnCategory::ArbitraryCodeExecution,
                "PowerShell Invoke-Expression (IEX)",
                "IEX evaluates arbitrary string as code. If input is not trusted → RCE.",
                "Remove IEX. Enable PowerShell Script Block Logging (Event ID 4104)."
            ),
            // ── Payload download ──────────────────────────────────────────
            r!(
                r#"(?i)(Invoke-WebRequest|iwr|DownloadString|DownloadFile|DownloadData)\s+['""]?(https?|ftp)://"#,
                Severity::High, VulnCategory::PayloadDownload,
                "PowerShell Remote Payload Download",
                "Script downloads content from remote URL. Could fetch malware payload.",
                "Whitelist allowed download destinations. Block untrusted external URLs via proxy/firewall."
            ),
            r!(
                r#"(?i)bitsadmin\s+/transfer\s+\S+\s+https?://"#,
                Severity::High, VulnCategory::PayloadDownload,
                "BITS Transfer — Remote File Download",
                "BITSAdmin used to download files from remote server. Often used in LOLBin attacks.",
                "Monitor BITS jobs. Restrict bitsadmin.exe execution via AppLocker."
            ),
            r!(
                r#"(?i)(certutil|certutil\.exe)\s+(-urlcache|-decode|-encode)"#,
                Severity::High, VulnCategory::PayloadDownload,
                "CertUtil LOLBin Abuse",
                "certutil.exe used as LOLBin to download or decode files, bypassing security controls.",
                "Block certutil.exe from downloading URLs via AppLocker/network rules."
            ),
            r!(
                r#"(?i)mshta\s+(https?://|javascript:|vbscript:)"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "MSHTA Remote Script Execution",
                "mshta.exe executing remote URL or inline script — common malware dropper technique.",
                "Block mshta.exe via AppLocker."
            ),
            // ── Antivirus disable ─────────────────────────────────────────
            r!(
                r#"(?i)Set-MpPreference\s+-(Disable|ExclusionPath|ExclusionExtension)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Windows Defender Disabled/Weakened via Set-MpPreference",
                "PowerShell command disabling Windows Defender or adding exclusions.",
                "Remove this configuration. Monitor via Event ID 5001. Protect with tamper protection."
            ),
            r!(
                r#"(?i)(Stop-Service|sc\s+stop|net\s+stop)\s+.*(windefend|mpssvc|wscsvc|MsMpEng)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Security Service Stopped",
                "Windows Defender or Firewall service being stopped.",
                "Alert on this pattern. Enforce tamper protection for security services."
            ),
            r!(
                r#"(?i)reg\s+(add|delete)\s+.*\\(windefend|Defender|AntiVirus)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Antivirus Registry Manipulation",
                "Registry modification targeting security product configuration.",
                "Monitor registry writes to HKLM\\SOFTWARE\\Microsoft\\Windows Defender."
            ),
            // ── Privilege escalation ──────────────────────────────────────
            r!(
                r#"(?i)(runas|Start-Process\s+.*-Verb\s+RunAs)"#,
                Severity::High, VulnCategory::PrivilegeEscalation,
                "Privilege Escalation — Run As / UAC Bypass",
                "Script requesting elevated privileges or running process as admin.",
                "Verify elevation is necessary."
            ),
            r!(
                r#"(?i)(SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege)"#,
                Severity::High, VulnCategory::PrivilegeEscalation,
                "Sensitive Windows Privilege Referenced",
                "Script references high-privilege token rights often abused for privilege escalation.",
                "Audit why this privilege is needed. Run under least-privilege service account."
            ),
            r!(
                r#"(?i)net\s+(user|localgroup\s+administrators)\s+\S+\s+(/add|/del)"#,
                Severity::Critical, VulnCategory::PrivilegeEscalation,
                "Local User / Admin Group Modification",
                "Script adding/removing local user or modifying Administrators group.",
                "Block net.exe from scripts via AppLocker. Alert on Event ID 4720/4732."
            ),
            // ── Hidden execution ──────────────────────────────────────────
            r!(
                r#"(?i)powershell\s+(-nop|noprofile|-w\s+hidden|-windowstyle\s+hidden|-exec\s+bypass)"#,
                Severity::High, VulnCategory::ObfuscatedCommand,
                "PowerShell Hidden Execution Flags",
                "PowerShell launched with -NoProfile, -Hidden, or -ExecutionPolicy Bypass.",
                "Audit this call. Block -ExecutionPolicy Bypass via Group Policy."
            ),
            // ── Persistence ───────────────────────────────────────────────
            r!(
                r#"(?i)schtasks\s+/create\s+.*\/ru\s+(system|administrator)"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Scheduled Task Created as SYSTEM",
                "Scheduled task running as SYSTEM — persistence mechanism.",
                "Audit scheduled tasks. Monitor Event ID 4698 (task created)."
            ),
            r!(
                r#"(?i)reg\s+add.*\\(Run|RunOnce|RunServices|Winlogon)"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Registry Run Key Persistence",
                "Adding value to autorun registry key — classic persistence mechanism.",
                "Review necessity. Monitor HKCU/HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run."
            ),
        ]
    });
    &RULES
}

pub fn scan_script(path: &Path, content: &[u8]) -> Vec<Vulnerability> {
    let text = match std::str::from_utf8(content) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };

    let lines: Vec<&str> = text.lines().collect();
    let mut findings: Vec<Vulnerability> = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    for rule in get_rules() {
        let mut cnt = 0usize;
        for m in rule.pattern.find_iter(text) {
            if cnt >= 15 { break; }
            let line_idx = text[..m.start()].chars().filter(|&c| c == '\n').count();
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
