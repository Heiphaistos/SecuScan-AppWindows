//! Tauri commands — bridge between frontend and Rust engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tauri::State;

use crate::api::llm;
use crate::export;
use crate::models::{AiFixRequest, AiFixResult, LlmProvider, ScanConfig, ScanResult};
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
    if !endpoint.starts_with("http") {
        return Err("Endpoint must start with http:// or https://".to_string());
    }
    keystore::save_antigravity_endpoint(&endpoint)
}

// ─── App info ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
