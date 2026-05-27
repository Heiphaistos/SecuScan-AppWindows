//! Main scan orchestrator.
//! Walks directory tree, dispatches files to parsers, emits progress events.

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use rayon::prelude::*;
use tauri::{AppHandle, Emitter};
use walkdir::{DirEntry, WalkDir};

use crate::models::{ScanConfig, ScanProgress, ScanResult, Vulnerability};
use crate::parsers::{binary, config, sast, script};

const MAX_CHUNK_BYTES: usize = 10 * 1024 * 1024; // 10 MB streaming chunks for large files

// ─── Skip rules ───────────────────────────────────────────────────────────────

fn should_skip(entry: &DirEntry, cfg: &ScanConfig) -> bool {
    let name = entry.file_name().to_string_lossy();
    if cfg.skip_git_dirs && (name == ".git" || name == ".svn") {
        return true;
    }
    if cfg.skip_node_modules && name == "node_modules" {
        return true;
    }
    // Always skip: build artifacts + IDE + dependency vendors
    if matches!(name.as_ref(), "target" | "dist" | "build" | ".idea" | ".vs" | "__pycache__" |
                               "vendor"  | ".cargo" | "Pods"  | "Carthage" | "Packages" |
                               ".gradle" | ".m2"    | "bower_components" | "jspm_packages") {
        return true;
    }
    false
}

fn file_extension(path: &Path) -> &str {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
}

// ─── File reader with size guard ──────────────────────────────────────────────

fn read_file_capped(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::with_capacity(max_bytes.min(4096));
    reader.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

// ─── Max bytes fed to regex scanners (prevent hang on huge text files) ────────
/// 2 MB cap for any regex-based scanner. Secrets/vulns are almost always
/// in the first kilobytes of a file; capping avoids catastrophic backtracking
/// on multi-megabyte .txt, .log, .csv, etc.
const MAX_REGEX_BYTES: usize = 512 * 1024; // 512 KB — combined with per-line filter keeps regex fast

#[inline]
fn cap(data: &[u8]) -> &[u8] {
    if data.len() > MAX_REGEX_BYTES { &data[..MAX_REGEX_BYTES] } else { data }
}

// ─── Dispatch to appropriate parser ──────────────────────────────────────────

fn dispatch(path: &Path, data: &[u8], cfg: &ScanConfig) -> Vec<Vulnerability> {
    let ext = file_extension(path).to_lowercase();
    let ext = ext.as_str();

    if sast::handles_extension(ext) {
        return sast::scan_source(path, cap(data));
    }
    if script::handles_extension(ext) {
        return script::scan_script(path, cap(data));
    }
    if config::handles_extension(ext) {
        return config::scan_config(path, cap(data));
    }
    if cfg.scan_executables && binary::handles_extension(ext) {
        return binary::scan_binary(path, data); // binary scanner handles its own limits
    }

    // Fallback: secret scan on unknown text files, but:
    //   1. Skip .txt, .log, .csv, .md (too generic, low signal, high false-positive)
    //   2. Cap at 512 KB
    //   3. Only if < 5% null bytes (is text)
    let skip_fallback = matches!(ext, "txt" | "log" | "csv" | "md" | "rst" | "nfo" |
                                       "rtf" | "out" | "tmp" | "dat" | "cache" |
                                       "lock" | "sum" | "manifest");
    if !skip_fallback && data.iter().filter(|&&b| b == 0).count() < data.len() / 20 {
        const FALLBACK_CAP: usize = 512 * 1024;
        let slice = if data.len() > FALLBACK_CAP { &data[..FALLBACK_CAP] } else { data };
        return config::scan_config(path, slice);
    }

    vec![]
}

// ─── Dispatch with 10-second hard timeout ────────────────────────────────────
// If a parser hangs (regex catastrophic backtracking, YARA infinite loop, etc.)
// the file is skipped after 10 s so the overall scan can continue.
// The spawned thread may keep running until process exit — acceptable for a
// desktop tool where stuck threads are cleaned up on close.

fn dispatch_timed(path: PathBuf, data: Vec<u8>, cfg: ScanConfig) -> Vec<Vulnerability> {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel::<Vec<Vulnerability>>();
    std::thread::spawn(move || {
        let result = dispatch(&path, &data, &cfg);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(vulns) => vulns,
        Err(_) => {
            log::warn!("File scan timed out — skipped");
            vec![]
        }
    }
}

// ─── Public entry ─────────────────────────────────────────────────────────────

pub async fn run_scan(
    target: String,
    cfg: ScanConfig,
    app: AppHandle,
    cancelled: Arc<AtomicBool>,
) -> Result<ScanResult, String> {
    let root = PathBuf::from(&target);
    if !root.exists() {
        return Err(format!("Path does not exist: {target}"));
    }

    // Collect file list first (for accurate progress)
    let entries: Vec<PathBuf> = WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip(e, &cfg))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let total = entries.len();
    let mut result = ScanResult::new(target.clone(), total);

    // Track scan position atomically for rayon parallel scan
    let counter    = Arc::new(AtomicUsize::new(0));
    let app_clone  = app.clone();
    let cfg_clone  = cfg.clone();
    let cancel_ref = cancelled.clone();
    let max_bytes  = (cfg.max_file_size_mb * 1024.0 * 1024.0) as usize;

    // Parallel scan with rayon
    let scan_results: Vec<(Vec<Vulnerability>, Option<String>)> = entries
        .par_iter()
        .map(|path| {
            if cancel_ref.load(Ordering::Relaxed) {
                return (vec![], None);
            }

            let cnt = counter.fetch_add(1, Ordering::Relaxed) + 1;
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            // Emit progress (best-effort — ignore error if window closed)
            let _ = app_clone.emit("scan:progress", ScanProgress {
                scanned:        cnt,
                total,
                current_file:   file_name,
                findings_count: 0, // updated in final aggregation
            });

            // Read file
            match read_file_capped(path, max_bytes) {
                Ok(data) => {
                    // dispatch_timed: 10 s hard timeout per file — skips stuck parsers
                    let vulns = dispatch_timed(path.clone(), data, cfg_clone.clone());
                    (vulns, None)
                }
                Err(e) => {
                    let err_msg = format!("{}: {}", path.display(), e);
                    log::warn!("Scan IO error: {err_msg}");
                    // Log to file
                    let _ = log_scan_error(&target, &err_msg);
                    (vec![], Some(format!("{}|{}", path.display(), e)))
                }
            }
        })
        .collect();

    // Aggregate results
    for (vulns, err) in scan_results {
        result.vulnerabilities.extend(vulns);
        result.scanned_files += 1;
        if let Some(e) = err {
            let parts: Vec<&str> = e.splitn(2, '|').collect();
            result.errors.push(crate::models::ScanError {
                file_path: parts.first().copied().unwrap_or("").to_string(),
                error:     parts.get(1).copied().unwrap_or("").to_string(),
            });
        }
    }

    // Sort by severity (Critical first)
    result.vulnerabilities.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));

    // Apply false-positive hints (heuristics)
    apply_fp_hints(&mut result.vulnerabilities);

    result.finalize();

    // Emit completion
    let _ = app.emit("scan:complete", &result.stats);

    Ok(result)
}

// ─── False-positive heuristics ───────────────────────────────────────────────

fn apply_fp_hints(vulns: &mut Vec<crate::models::Vulnerability>) {
    for v in vulns.iter_mut() {
        v.fp_hint = detect_fp(&v.file_path, v.matched_pattern.as_deref(), &v.category);
    }
}

fn detect_fp(
    path:     &str,
    matched:  Option<&str>,
    category: &crate::models::VulnCategory,
) -> Option<String> {
    use crate::models::VulnCategory::*;

    let path_l    = path.to_lowercase();
    let matched_l = matched.unwrap_or("").to_lowercase();

    // ── 1. Test / example / mock paths ──────────────────────────────────────
    let path_segs: Vec<&str> = path.split(['/', '\\']).collect();
    let test_dirs = ["test", "tests", "spec", "specs", "mock", "mocks",
                     "fixture", "fixtures", "example", "examples",
                     "sample", "samples", "demo", "__tests__"];
    for seg in &path_segs {
        let s = seg.to_lowercase();
        if test_dirs.iter().any(|t| s == *t || s.starts_with(&format!("{}_", t)) || s.ends_with(&format!("_{}", t))) {
            return Some(format!(
                "Possible faux positif — fichier dans un contexte test/exemple (dossier «{}»). \
                 Vérifier si ce code est exécuté en production.",
                seg
            ));
        }
    }
    // file name patterns
    if path_l.ends_with("_test.rs") || path_l.ends_with("_test.go") ||
       path_l.ends_with(".test.js") || path_l.ends_with(".spec.ts") ||
       path_l.ends_with(".spec.js") {
        return Some(
            "Possible faux positif — fichier de test (nom contient _test/.test/.spec). \
             Vérifier si ce code est exécuté en production.".to_string()
        );
    }

    // ── 2. Placeholder / exemple values ─────────────────────────────────────
    let placeholders = ["placeholder", "your_api", "your-api", "your_key", "your-key",
                        "changeme", "replace_me", "insert_key", "insert_secret",
                        "example.com", "example_", "_example", "fake_", "dummy_",
                        "sample_key", "demo_key", "test_key", "test_secret",
                        "xxxx", "1234567890abcdef", "abcdefghijklmnop"];
    for p in &placeholders {
        if matched_l.contains(p) {
            return Some(format!(
                "Possible faux positif — valeur détectée ressemble à un placeholder/exemple (\"{}\"). \
                 Peu probable que ce soit une vraie fuite.",
                &matched_l[..matched_l.len().min(40)]
            ));
        }
    }

    // ── 3. WeakCrypto — checksums vs passwords ───────────────────────────────
    if matches!(category, WeakCrypto) {
        if matched_l.contains("md5") || matched_l.contains("sha1") || matched_l.contains("sha-1") {
            return Some(
                "Possible faux positif — MD5/SHA-1 fréquemment utilisés pour \
                 checksums de fichiers ou déduplication (usage non-sécuritaire légitime). \
                 Vérifier que ce n'est pas utilisé pour hacher des mots de passe.".to_string()
            );
        }
        if matched_l.contains("random") {
            return Some(
                "Possible faux positif — random() peut être utilisé à des fins \
                 non-sécuritaires (simulation, jeux, tri aléatoire). \
                 Problème uniquement si une valeur imprévisible est requise (token, clé).".to_string()
            );
        }
    }

    // ── 4. CommandInjection en Rust/Go/C (outils système) ───────────────────
    if matches!(category, CommandInjection) {
        let ext = path_l.rsplit('.').next().unwrap_or("");
        if matches!(ext, "rs" | "go" | "c" | "cpp" | "cs") {
            return Some(
                "Possible faux positif — les outils système en Rust/Go/C# utilisent \
                 légitimement l'exécution de processus. Vérifier si les paramètres \
                 passés à la commande peuvent être contrôlés par un attaquant.".to_string()
            );
        }
    }

    // ── 5. CORS wildcard sur ressources statiques ────────────────────────────
    if matches!(category, CorsMisconfiguration) {
        if path_l.contains("nginx") || path_l.contains("static") ||
           path_l.contains("cdn")   || path_l.contains("assets") {
            return Some(
                "Possible faux positif — CORS wildcard (*) acceptable pour les ressources \
                 statiques publiques (fonts, images, JS/CSS). \
                 Problématique uniquement pour les endpoints API authentifiés.".to_string()
            );
        }
    }

    // ── 6. HighEntropyString — hashes d'assets / fingerprints de build ──────
    if matches!(category, HighEntropyString) {
        if path_l.ends_with(".lock") || path_l.ends_with(".sum") ||
           path_l.contains("package-lock") || path_l.contains("yarn.lock") ||
           path_l.contains("cargo.lock") {
            return Some(
                "Possible faux positif — fichier de lock contenant des hashes \
                 d'intégrité de dépendances (non-secrets).".to_string()
            );
        }
        // All-hex string of 40+ chars = SHA1 commit hash or asset fingerprint
        let hex_only: bool = matched_l.chars().all(|c| c.is_ascii_hexdigit() || c == '"' || c == '\'');
        if hex_only && matched_l.len() >= 40 {
            return Some(
                "Possible faux positif — chaîne hexadécimale longue pouvant être \
                 un hash de commit, fingerprint d'asset ou checksum (non-secret).".to_string()
            );
        }
    }

    None
}

// ─── Append to log file ───────────────────────────────────────────────────────

fn log_scan_error(target: &str, error: &str) -> std::io::Result<()> {
    use std::io::Write;
    let log_path = std::path::Path::new(target)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("secuscan.log");
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    writeln!(f, "[{ts}] [ERROR] {error}")
}
