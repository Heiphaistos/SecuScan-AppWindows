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
            // ── WMI process creation ──────────────────────────────────────
            r!(
                r#"(?i)(wmic\s+process\s+call\s+create|Invoke-WmiMethod\s+.*-Name\s+Create|Get-WmiObject\s+.*Win32_Process)"#,
                Severity::High, VulnCategory::ArbitraryCodeExecution,
                "WMI Process Creation",
                "WMI used to spawn a process — common lateral-movement / fileless execution technique.",
                "Audit WMI activity. Monitor Event ID 4688 and WMI-Activity operational log."
            ),
            // ── rundll32 / regsvr32 LOLBin ────────────────────────────────
            r!(
                r#"(?i)(rundll32\s+.*javascript:|regsvr32\s+(/s\s+)?/(i|u):https?://|regsvr32\s+.*scrobj\.dll)"#,
                Severity::Critical, VulnCategory::ArbitraryCodeExecution,
                "rundll32 / regsvr32 LOLBin Execution",
                "rundll32/regsvr32 abused to run remote scriptlets (Squiblydoo) — bypasses application whitelisting.",
                "Block scriptlet execution via WDAC/AppLocker. Monitor regsvr32 network access."
            ),
            // ── wscript / cscript ─────────────────────────────────────────
            r!(
                r#"(?i)(wscript|cscript)\s+.*\.(vbs|js|wsf|jse|vbe)"#,
                Severity::Medium, VulnCategory::ArbitraryCodeExecution,
                "Windows Script Host Execution",
                "wscript/cscript running a script file — common malware delivery vector via email attachments.",
                "Disable Windows Script Host if unused (HKLM\\...\\Windows Script Host\\Settings\\Enabled=0)."
            ),
            // ── Defender exclusion added ──────────────────────────────────
            r!(
                r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)"#,
                Severity::Critical, VulnCategory::AntivirusDisabled,
                "Windows Defender Exclusion Added",
                "Attacker adds a Defender exclusion to shield a payload from scanning.",
                "Alert on Add-MpPreference exclusions. Enable tamper protection."
            ),
            // ── Event log clearing ────────────────────────────────────────
            r!(
                r#"(?i)(wevtutil\s+cl|Clear-EventLog|Remove-EventLog|wevtutil\s+clear-log)"#,
                Severity::High, VulnCategory::SuspiciousPersistence,
                "Event Log Clearing — Anti-Forensics",
                "Script clears Windows event logs to erase traces of intrusion.",
                "Alert on Event ID 1102 (audit log cleared). Forward logs to a remote SIEM."
            ),
            // ── curl|bash remote exec ─────────────────────────────────────
            r!(
                r#"(?i)(curl|wget)\s+[^|]*https?://[^|]*\|\s*(sudo\s+)?(bash|sh|python|perl)"#,
                Severity::High, VulnCategory::PayloadDownload,
                "Remote Script Piped to Shell (curl | bash)",
                "Downloads and directly executes a remote script — no integrity check, full trust of the server.",
                "Download, inspect, and verify checksum before executing. Avoid pipe-to-shell installers."
            ),
            // ── Clipboard theft ───────────────────────────────────────────
            r!(
                r#"(?i)(Get-Clipboard|Set-Clipboard\s+.*[13][a-km-zA-HJ-NP-Z1-9]{25,})"#,
                Severity::Medium, VulnCategory::SensitiveDataExposure,
                "Clipboard Access — Possible Hijack / Theft",
                "Script reads or overwrites the clipboard — used by clippers to swap crypto wallet addresses.",
                "Audit clipboard access. Alert if paired with wallet-address patterns."
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
