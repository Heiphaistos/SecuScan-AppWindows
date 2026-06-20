//! Tauri commands — bridge between frontend and Rust engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tauri::State;

use crate::api::llm;
use crate::export;
use crate::models::{AiFixRequest, AiFixResult, BatchFixProgress, FilePatch, LlmProvider, ScanConfig, ScanResult};
use crate::security::keystore;

// ─── App state ────────────────────────────────────────────────────────────────

pub struct AppState {
    pub current_scan:   Mutex<Option<ScanResult>>,
    pub scan_cancelled: Arc<AtomicBool>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            current_scan:   Mutex::new(None),
            scan_cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

// ─── Scan commands ────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn start_scan(
    path:   String,
    config: Option<ScanConfig>,
    state:  State<'_, AppState>,
    app:    tauri::AppHandle,
) -> Result<ScanResult, String> {
    // Reset cancel flag
    state.scan_cancelled.store(false, Ordering::Relaxed);

    let cfg       = config.unwrap_or_default();
    let cancelled = state.scan_cancelled.clone();

    let result = crate::engine::scanner::run_scan(path, cfg, app, cancelled).await?;

    // Cache result for export
    *state.current_scan.lock().unwrap() = Some(result.clone());

    Ok(result)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    state.scan_cancelled.store(true, Ordering::Relaxed);
    log::info!("Scan cancellation requested");
}

// ─── AI fix commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn request_ai_fix(
    req:   AiFixRequest,
    state: State<'_, AppState>,
) -> Result<AiFixResult, String> {
    // Clone vulnerability BEFORE any await so MutexGuard is not held across await points.
    let vuln = {
        let scan = state.current_scan.lock().unwrap();
        let scan_result = scan.as_ref().ok_or("No active scan result")?;
        scan_result
            .vulnerabilities
            .iter()
            .find(|v| v.id == req.vulnerability_id)
            .cloned()
            .ok_or_else(|| format!("Vulnerability {} not found", req.vulnerability_id))?
    }; // MutexGuard dropped here

    let key_name = match &req.provider {
        LlmProvider::Claude      => "claude",
        LlmProvider::Gemini      => "gemini",
        LlmProvider::Antigravity => "antigravity",
    };

    let api_key = keystore::load_key(key_name)?
        .ok_or_else(|| format!("No API key configured for {key_name}"))?;

    let endpoint = if matches!(req.provider, LlmProvider::Antigravity) {
        keystore::load_antigravity_endpoint()
    } else {
        None
    };

    llm::request_fix(&vuln, &req.provider, &api_key, endpoint.as_deref()).await
}

#[tauri::command]
pub fn build_clipboard_prompt(
    vuln_id: String,
    state:   State<'_, AppState>,
) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap();
    let scan_result = scan.as_ref().ok_or("No active scan result")?;

    let vuln = scan_result
        .vulnerabilities
        .iter()
        .find(|v| v.id == vuln_id)
        .ok_or_else(|| format!("Vulnerability {vuln_id} not found"))?;

    Ok(llm::build_clipboard_prompt(vuln))
}

// ─── Export commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn export_json(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap();
    let result = scan.as_ref().ok_or("No scan result to export")?;
    export::to_json(result)
}

#[tauri::command]
pub fn export_csv(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap();
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_csv(result))
}

#[tauri::command]
pub fn export_markdown(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap();
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_markdown(result))
}

#[tauri::command]
pub fn export_txt(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap();
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_txt(result))
}

#[tauri::command]
pub fn export_html(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap();
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_html(result))
}

/// Save report directly to disk (called after user picks path via save dialog).
#[tauri::command]
pub fn save_report_to_file(format: String, path: String, state: State<'_, AppState>) -> Result<(), String> {
    // FIX H2 — Path traversal: restrict export to user home directory
    let dest = std::path::PathBuf::from(&path);
    let canonical_dest = dest.canonicalize()
        .or_else(|_| {
            // File may not exist yet — canonicalize parent directory instead
            dest.parent()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir"))
                .and_then(|p| p.canonicalize())
        })
        .map_err(|e| format!("Chemin de destination invalide: {e}"))?;

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(std::path::PathBuf::from)
        .map_err(|_| "Impossible de déterminer le répertoire home".to_string())?;

    if !canonical_dest.starts_with(&home) {
        return Err("Le chemin d'export doit être dans le répertoire utilisateur".to_string());
    }

    let scan = state.current_scan.lock().unwrap();
    let result = scan.as_ref().ok_or("No scan result to export")?;
    let content = match format.as_str() {
        "json" => export::to_json(result)?,
        "csv"  => export::to_csv(result),
        "md"   => export::to_markdown(result),
        "txt"  => export::to_txt(result),
        "html" => export::to_html(result),
        _      => return Err(format!("Unknown format: {format}")),
    };
    std::fs::write(&path, content.as_bytes()).map_err(|e| e.to_string())
}

// ─── Key management commands ──────────────────────────────────────────────────

#[tauri::command]
pub fn save_api_key(provider: String, key: String) -> Result<(), String> {
    if key.trim().is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    keystore::save_key(&provider, &key)
}

#[tauri::command]
pub fn delete_api_key(provider: String) -> Result<(), String> {
    keystore::delete_key(&provider)
}

#[tauri::command]
pub fn get_key_status() -> serde_json::Value {
    keystore::key_status()
}

#[tauri::command]
pub fn save_antigravity_endpoint(endpoint: String) -> Result<(), String> {
    // FIX M7 — SSRF: enforce HTTPS and block private/local addresses
    if !endpoint.starts_with("https://") {
        return Err("L'endpoint doit utiliser HTTPS (https://)".to_string());
    }

    let url = url::Url::parse(&endpoint)
        .map_err(|e| format!("URL invalide: {e}"))?;

    let host = url.host_str().unwrap_or("");
    let blocked_prefixes = ["localhost", "127.", "0.0.0.0", "10.", "192.168.", "172.16.", "::1", "169.254."];
    if blocked_prefixes.iter().any(|b| host.starts_with(b) || host == b.trim_end_matches('.')) {
        return Err("Les adresses locales/privées ne sont pas autorisées".to_string());
    }

    keystore::save_antigravity_endpoint(&endpoint)
}

// ─── Batch AI Fix ─────────────────────────────────────────────────────────────

/// Fix ALL vulnerabilities across ALL affected files in one batch.
/// Emits "batch:progress" events. Returns list of FilePatch (one per file).
#[tauri::command]
pub async fn batch_ai_fix(
    provider: LlmProvider,
    app:      tauri::AppHandle,
    state:    State<'_, AppState>,
) -> Result<Vec<FilePatch>, String> {
    use tauri::Emitter;

    // Collect vulnerabilities from current scan
    let vulns = {
        let scan = state.current_scan.lock().unwrap();
        scan.as_ref()
            .ok_or("No active scan result")?
            .vulnerabilities
            .clone()
    };

    // API key
    let key_name = match &provider {
        LlmProvider::Claude      => "claude",
        LlmProvider::Gemini      => "gemini",
        LlmProvider::Antigravity => "antigravity",
    };
    let api_key = keystore::load_key(key_name)?
        .ok_or_else(|| format!("No API key configured for {key_name}"))?;
    let ag_endpoint = if matches!(provider, LlmProvider::Antigravity) {
        keystore::load_antigravity_endpoint()
    } else {
        None
    };

    // Group vulns by file path
    let mut by_file: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
    for (i, v) in vulns.iter().enumerate() {
        by_file.entry(v.file_path.clone()).or_default().push(i);
    }

    let total_files = by_file.len();
    let mut patches: Vec<FilePatch> = Vec::new();

    for (file_idx, (file_path, vuln_indices)) in by_file.iter().enumerate() {
        // Emit progress
        let _ = app.emit("batch:progress", BatchFixProgress {
            file_idx:     file_idx + 1,
            total_files,
            current_file: file_path.split(['/', '\\']).last().unwrap_or(file_path).to_string(),
            status:       "processing".to_string(),
        });

        // Read file from disk
        let original_content = match std::fs::read_to_string(file_path) {
            Ok(c)  => c,
            Err(e) => {
                let _ = app.emit("batch:progress", BatchFixProgress {
                    file_idx: file_idx + 1, total_files,
                    current_file: file_path.split(['/', '\\']).last().unwrap_or(file_path).to_string(),
                    status: format!("error: {e}"),
                });
                continue;
            }
        };

        let file_vulns: Vec<&crate::models::Vulnerability> =
            vuln_indices.iter().map(|&i| &vulns[i]).collect();
        let vuln_ids: Vec<String> = file_vulns.iter().map(|v| v.id.clone()).collect();

        match llm::batch_fix_file(
            file_path,
            &original_content,
            &file_vulns,
            &provider,
            &api_key,
            ag_endpoint.as_deref(),
        ).await {
            Ok((patched_content, summary)) => {
                let _ = app.emit("batch:progress", BatchFixProgress {
                    file_idx: file_idx + 1, total_files,
                    current_file: file_path.split(['/', '\\']).last().unwrap_or(file_path).to_string(),
                    status: "done".to_string(),
                });
                patches.push(FilePatch {
                    file_path:        file_path.clone(),
                    original_content,
                    patched_content,
                    summary,
                    vuln_ids,
                    applied: false,
                });
            }
            Err(e) => {
                let _ = app.emit("batch:progress", BatchFixProgress {
                    file_idx: file_idx + 1, total_files,
                    current_file: file_path.split(['/', '\\']).last().unwrap_or(file_path).to_string(),
                    status: format!("error: {e}"),
                });
            }
        }
    }

    Ok(patches)
}

/// Apply a single patch to disk (overwrite file with patched content).
#[tauri::command]
pub fn apply_patch(file_path: String, patched_content: String) -> Result<(), String> {
    // FIX C1 — Path traversal: validate path before writing
    let path = std::path::PathBuf::from(&file_path);

    // Must be absolute path
    if !path.is_absolute() {
        return Err("Chemin absolu requis".to_string());
    }

    // Canonicalize to resolve symlinks and ..
    let canonical = path.canonicalize()
        .map_err(|e| format!("Chemin invalide: {e}"))?;

    // Must be within user home directory
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(std::path::PathBuf::from)
        .map_err(|_| "Impossible de déterminer le répertoire home".to_string())?;

    if !canonical.starts_with(&home) {
        return Err(format!(
            "Accès refusé: {} hors du répertoire utilisateur",
            canonical.display()
        ));
    }

    // Whitelist source code extensions
    let allowed_exts = [
        "py", "js", "ts", "tsx", "jsx", "rs", "go", "c", "cpp", "h", "hpp",
        "java", "cs", "rb", "php", "swift", "kt", "lua", "sh", "bash", "zsh",
        "yaml", "yml", "toml", "json", "xml", "html", "css",
    ];
    let ext = canonical.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !allowed_exts.contains(&ext) {
        return Err(format!("Extension .{} non autorisée pour les patches", ext));
    }

    std::fs::write(&canonical, patched_content.as_bytes())
        .map_err(|e| format!("Échec écriture {}: {e}", canonical.display()))
}

// ─── App info ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
