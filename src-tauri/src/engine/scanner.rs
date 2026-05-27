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
    matches!(name.as_ref(), "target" | "dist" | "build" | ".idea" | ".vs" | "__pycache__")
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

// ─── Dispatch to appropriate parser ──────────────────────────────────────────

fn dispatch(path: &Path, data: &[u8], cfg: &ScanConfig) -> Vec<Vulnerability> {
    let ext = file_extension(path);

    if sast::handles_extension(ext) {
        return sast::scan_source(path, data);
    }
    if script::handles_extension(ext) {
        return script::scan_script(path, data);
    }
    if config::handles_extension(ext) {
        return config::scan_config(path, data);
    }
    if cfg.scan_executables && binary::handles_extension(ext) {
        return binary::scan_binary(path, data);
    }

    // Fallback: apply config scanner to any unknown text file
    if data.iter().filter(|&&b| b == 0).count() < data.len() / 20 {
        // Probably text (< 5% null bytes)
        return config::scan_config(path, data);
    }

    vec![]
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
                    let vulns = dispatch(path, &data, &cfg_clone);
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

    result.finalize();

    // Emit completion
    let _ = app.emit("scan:complete", &result.stats);

    Ok(result)
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
