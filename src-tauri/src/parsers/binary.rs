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
                "ASLR absent (randomisation de l'espace d'adressage)",
                "Binaire non compilé avec /DYNAMICBASE. Une disposition mémoire prévisible facilite l'exploitation.",
                "Recompilez avec l'option d'éditeur de liens /DYNAMICBASE (MSVC) ou -pie (GCC/Clang).",
            ).with_snippet(snippet.clone()),
        );
    }

    if !has_dep {
        findings.push(
            Vulnerability::new(
                path_str, Severity::Medium, VulnCategory::MissingDep,
                "DEP/NX absent (prévention de l'exécution des données)",
                "Binaire non compilé avec /NXCOMPAT. Les données de la pile et du tas peuvent être exécutées comme du code.",
                "Recompilez avec l'option d'éditeur de liens /NXCOMPAT.",
            ).with_snippet(snippet.clone()),
        );
    }

    if !has_cfg {
        findings.push(
            Vulnerability::new(
                path_str, Severity::Low, VulnCategory::InsecureConfiguration,
                "Control Flow Guard (CFG) non activé",
                "Le binaire n'a pas la protection CFG. Les cibles des appels indirects ne sont pas validées.",
                "Recompilez avec /guard:cf (MSVC) pour bénéficier de la protection CFG des Windows récents.",
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

        // Description affichée en français ; la méta `description` (anglais) du
        // source YARA ne sert que de repli pour une règle ajoutée sans traduction.
        let (category, description_fr, remediation): (VulnCategory, Option<&str>, &str) = match rule_id {
            "DLLInjectionAPIs" => (
                VulnCategory::DllInjection,
                Some("Trio classique d'API d'injection de DLL (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)."),
                "Recherchez l'origine du binaire. Exécutez-le dans un bac à sable. Bloquez son exécution via AppLocker.",
            ),
            "ProcessHollowing" => (
                VulnCategory::DllInjection,
                Some("Ensemble d'API du « process hollowing » (vider un processus pour y loger un autre code)."),
                "Recherchez l'origine du binaire. Exécutez-le dans un bac à sable. Bloquez son exécution via AppLocker.",
            ),
            "PersistenceRunKeys" => (
                VulnCategory::SuspiciousPersistence,
                Some("Persistance par clé de registre Run (démarrage automatique)."),
                "Auditez le comportement du binaire. Supprimez-le s'il n'est pas autorisé. Surveillez les écritures dans le registre.",
            ),
            "RansomwareIndicators" => (
                VulnCategory::RansomwareIndicator,
                Some("Suppression des clichés instantanés et motifs de chiffrement (rançongiciel)."),
                "NE PAS exécuter. Isolez le système. Analysez-le dans un bac à sable isolé du réseau.",
            ),
            "SuspiciousShellcode" => (
                VulnCategory::MalwareIndicator,
                Some("Suite de NOP ou d'INT3 — indice de shellcode."),
                "Le binaire contient probablement du shellcode. Mettez-le en quarantaine immédiatement.",
            ),
            "PackerUPX" => (
                VulnCategory::MalwareIndicator,
                Some("Signature du compresseur d'exécutables UPX."),
                "Motifs suspects détectés. Analysez-le dans un bac à sable avant toute exécution.",
            ),
            _ => (
                VulnCategory::MalwareIndicator,
                None,
                "Motifs suspects détectés. Analysez-le dans un bac à sable avant toute exécution.",
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
                description_fr.unwrap_or(&description),
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
