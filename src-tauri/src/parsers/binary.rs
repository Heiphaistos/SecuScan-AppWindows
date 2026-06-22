//! Binary parser — PE header analysis, hash computation, YARA scanning.

use goblin::pe::PE;
use sha2::{Sha256, Digest};
use std::path::Path;

use crate::models::{Severity, VulnCategory, Vulnerability};

// ─── PE DLL Characteristics flags ────────────────────────────────────────────
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040; // ASLR
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT:    u16 = 0x0100; // DEP / NX
const IMAGE_DLLCHARACTERISTICS_GUARD_CF:     u16 = 0x4000; // CFG

// ─── Embedded YARA rules ──────────────────────────────────────────────────────
const YARA_RULES: &str = r#"
rule SuspiciousShellcode {
    meta:
        description = "NOP sled or INT3 chain — shellcode indicator"
        severity    = "critical"
    strings:
        $nop  = { 90 90 90 90 90 90 90 90 }
        $int3 = { CC CC CC CC CC CC CC CC }
    condition:
        any of them
}
rule DLLInjectionAPIs {
    meta:
        description = "Classic DLL injection API trio"
        severity    = "high"
    strings:
        $alloc  = "VirtualAllocEx"   ascii wide
        $write  = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
    condition:
        2 of ($alloc, $write, $thread)
}
rule ProcessHollowing {
    meta:
        description = "Process hollowing API set"
        severity    = "critical"
    strings:
        $cr = "CreateProcessW"        ascii wide
        $nt = "NtUnmapViewOfSection"  ascii wide
        $wx = "WriteProcessMemory"    ascii wide
        $rr = "ResumeThread"          ascii wide
    condition:
        3 of them
}
rule PersistenceRunKeys {
    meta:
        description = "Registry Run key persistence"
        severity    = "high"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
    condition:
        any of them
}
rule RansomwareIndicators {
    meta:
        description = "Shadow copy deletion and encrypt patterns"
        severity    = "critical"
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "wmic shadowcopy delete"  ascii wide nocase
        $ext1 = ".encrypted"              ascii wide
        $note = "DECRYPT"                 ascii wide
    condition:
        2 of them
}
rule PackerUPX {
    meta:
        description = "UPX packer signature"
        severity    = "low"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        2 of them
}
"#;

// ─── Hash helpers ──────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}

// ─── PE analysis ──────────────────────────────────────────────────────────────

fn check_pe_protections(path_str: &str, pe: &PE, data: &[u8]) -> Vec<Vulnerability> {
    let mut findings = Vec::new();

    let dll_chars = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    let has_aslr = (dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    let has_dep  = (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    let has_cfg  = (dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    let snippet = format!(
        "SHA-256: {}\nMD5:     {}\nDllCharacteristics: 0x{:04X}",
        sha256_hex(data), md5_hex(data), dll_chars
    );

    if !has_aslr {
        findings.push(
            Vulnerability::new(
                path_str, Severity::Medium, VulnCategory::MissingAslr,
                "Missing ASLR (Address Space Layout Randomization)",
                "Binary not compiled with /DYNAMICBASE. Predictable memory layout aids exploitation.",
                "Recompile with /DYNAMICBASE linker flag (MSVC) or -pie (GCC/Clang).",
            ).with_snippet(snippet.clone()),
        );
    }

    if !has_dep {
        findings.push(
            Vulnerability::new(
                path_str, Severity::Medium, VulnCategory::MissingDep,
                "Missing DEP/NX (Data Execution Prevention)",
                "Binary not compiled with /NXCOMPAT. Stack/heap data can be executed as code.",
                "Recompile with /NXCOMPAT linker flag.",
            ).with_snippet(snippet.clone()),
        );
    }

    if !has_cfg {
        findings.push(
            Vulnerability::new(
                path_str, Severity::Low, VulnCategory::InsecureConfiguration,
                "Control Flow Guard (CFG) not enabled",
                "Binary lacks CFG protection. Indirect call targets are not validated.",
                "Recompile with /guard:cf (MSVC) for modern Windows CFG protection.",
            ).with_snippet(snippet),
        );
    }

    findings
}

// ─── YARA scanning ────────────────────────────────────────────────────────────

fn run_yara(path_str: &str, data: &[u8]) -> Vec<Vulnerability> {
    use yara_x::Compiler;

    let mut compiler = Compiler::new();
    if let Err(e) = compiler.add_source(YARA_RULES) {
        log::warn!("YARA compile error: {e}");
        return vec![];
    }
    let rules   = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);

    let results = match scanner.scan(data) {
        Ok(r)  => r,
        Err(e) => {
            log::warn!("YARA scan error on {path_str}: {e}");
            return vec![];
        }
    };

    let mut findings = Vec::new();

    for rule in results.matching_rules() {
        let rule_id = rule.identifier();

        // Extract metadata safely
        let mut description = rule_id.to_string();
        let mut severity_str = "medium";

        for (key, value) in rule.metadata() {
            match key {
                "description" => {
                    if let yara_x::MetaValue::String(s) = value {
                        description = s.to_string();
                    }
                }
                "severity" => {
                    if let yara_x::MetaValue::String(s) = value {
                        severity_str = match s {
                            "critical" => "critical",
                            "high"     => "high",
                            "low"      => "low",
                            _          => "medium",
                        };
                    }
                }
                _ => {}
            }
        }

        let severity = match severity_str {
            "critical" => Severity::Critical,
            "high"     => Severity::High,
            "low"      => Severity::Low,
            _          => Severity::Medium,
        };

        let (category, remediation): (VulnCategory, &str) = match rule_id {
            "DLLInjectionAPIs" | "ProcessHollowing" => (
                VulnCategory::DllInjection,
                "Investigate binary origin. Run in sandbox. Block execution via AppLocker.",
            ),
            "PersistenceRunKeys" => (
                VulnCategory::SuspiciousPersistence,
                "Audit binary behavior. Remove if unauthorized. Monitor registry writes.",
            ),
            "RansomwareIndicators" => (
                VulnCategory::RansomwareIndicator,
                "Do NOT execute. Isolate system. Analyze in air-gapped sandbox.",
            ),
            "SuspiciousShellcode" => (
                VulnCategory::MalwareIndicator,
                "Binary likely contains shellcode. Quarantine immediately.",
            ),
            _ => (
                VulnCategory::MalwareIndicator,
                "Suspicious patterns detected. Analyze in a sandbox before execution.",
            ),
        };

        // Collect matched string locations
        let matched_strings: Vec<String> = rule
            .patterns()
            .flat_map(|p| -> Vec<String> {
                let id = p.identifier().to_string();
                p.matches()
                    .map(|m| format!("{}@{:#x}", id, m.range().start))
                    .collect()
            })
            .take(5)
            .collect();

        findings.push(
            Vulnerability::new(
                path_str,
                severity,
                category,
                &format!("YARA: {rule_id}"),
                &description,
                remediation,
            )
            .with_match(matched_strings.join(", ")),
        );
    }

    findings
}

// ─── Public entry ─────────────────────────────────────────────────────────────

pub fn scan_binary(path: &Path, data: &[u8]) -> Vec<Vulnerability> {
    let path_str = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    findings.extend(run_yara(&path_str, data));

    if data.len() > 2 && &data[..2] == b"MZ" {
        match PE::parse(data) {
            Ok(pe)  => findings.extend(check_pe_protections(&path_str, &pe, data)),
            Err(e)  => log::debug!("PE parse failed for {path_str}: {e}"),
        }
    }

    findings
}

pub fn handles_extension(ext: &str) -> bool {
    matches!(ext.to_lowercase().as_str(),
        "exe" | "dll" | "sys" | "ocx" | "scr" | "com" | "drv"
    )
}
