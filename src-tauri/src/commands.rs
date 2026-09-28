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
    *state.current_scan.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());

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
        let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
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
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
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
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
    let result = scan.as_ref().ok_or("No scan result to export")?;
    export::to_json(result)
}

#[tauri::command]
pub fn export_csv(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_csv(result))
}

#[tauri::command]
pub fn export_markdown(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_markdown(result))
}

#[tauri::command]
pub fn export_txt(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_txt(result))
}

#[tauri::command]
pub fn export_html(state: State<'_, AppState>) -> Result<String, String> {
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
    let result = scan.as_ref().ok_or("No scan result to export")?;
    Ok(export::to_html(result))
}

/// Canonicalise un chemin et vérifie qu'il reste sous le répertoire utilisateur.
///
/// `must_exist = false` : le fichier peut ne pas exister encore. On canonicalise
/// alors le dossier parent puis on rattache le nom de fichier — renvoyer le parent
/// seul ferait échouer le contrôle d'extension et écrirait sur un dossier.
///
/// Le home est canonicalisé lui aussi : sous Windows `canonicalize` renvoie un
/// chemin verbatim (préfixe `\\?\`) que `USERPROFILE` n'a pas, et `starts_with`
/// compare les préfixes tels quels — sans ça la comparaison est toujours fausse.
fn canonical_under_home(
    path: &std::path::Path,
    must_exist: bool,
) -> Result<std::path::PathBuf, String> {
    let canonical = if must_exist {
        path.canonicalize().map_err(|e| format!("Chemin invalide: {e}"))?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| "Chemin sans dossier parent".to_string())?
            .canonicalize()
            .map_err(|e| format!("Dossier de destination invalide: {e}"))?;
        let name = path
            .file_name()
            .ok_or_else(|| "Nom de fichier manquant".to_string())?;
        parent.join(name)
    };

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(std::path::PathBuf::from)
        .map_err(|_| "Impossible de déterminer le répertoire home".to_string())?
        .canonicalize()
        .map_err(|e| format!("Répertoire home invalide: {e}"))?;

    if !canonical.starts_with(&home) {
        return Err(format!(
            "Accès refusé: {} hors du répertoire utilisateur",
            canonical.display()
        ));
    }

    Ok(canonical)
}

/// Save report directly to disk (called after user picks path via save dialog).
#[tauri::command]
pub fn save_report_to_file(format: String, path: String, state: State<'_, AppState>) -> Result<(), String> {
    // FIX H2 — Path traversal: restrict export to user home directory
    let dest = canonical_under_home(std::path::Path::new(&path), false)?;

    // FIX VULN 2 — Whitelist extensions export (évite d'écrire dans un .exe/.bat/etc.)
    let allowed_export_exts = ["json", "csv", "md", "txt", "html"];
    let dest_ext = dest.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !allowed_export_exts.contains(&dest_ext) {
        return Err(format!("Extension .{dest_ext} non autorisée pour l'export de rapport"));
    }

    let content = {
        let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
        let result = scan.as_ref().ok_or("No scan result to export")?;
        match format.as_str() {
            "json" => export::to_json(result)?,
            "csv"  => export::to_csv(result),
            "md"   => export::to_markdown(result),
            "txt"  => export::to_txt(result),
            "html" => export::to_html(result),
            _      => return Err(format!("Unknown format: {format}")),
        }
    };
    // FIX TOCTOU — écrire sur le chemin canonicalisé, pas sur &path (chemin original)
    std::fs::write(&dest, content.as_bytes()).map_err(|e| e.to_string())
}

// ─── Key management commands ──────────────────────────────────────────────────

#[tauri::command]
pub fn save_api_key(provider: String, key: String) -> Result<(), String> {
    if key.trim().is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    // FIX VULN 5 — Cap longueur clé (limite raisonnable pour toute clé API)
    if key.len() > 4096 {
        return Err("API key trop longue (max 4096 caractères)".to_string());
    }
    // Whitelist providers autorisés
    if !matches!(provider.as_str(), "claude" | "gemini" | "antigravity") {
        return Err(format!("Provider inconnu: {provider}"));
    }
    keystore::save_key(&provider, &key)
}

#[tauri::command]
pub fn delete_api_key(provider: String) -> Result<(), String> {
    // FIX VULN 6 — Whitelist providers avant d'appeler le keystore
    if !matches!(provider.as_str(), "claude" | "gemini" | "antigravity") {
        return Err("Provider inconnu".to_string());
    }
    keystore::delete_key(&provider)
}

#[tauri::command]
pub fn get_key_status() -> serde_json::Value {
    keystore::key_status()
}

#[tauri::command]
pub fn save_antigravity_endpoint(endpoint: String) -> Result<(), String> {
    // FIX VULN 7 — Cap longueur URL
    if endpoint.len() > 2048 {
        return Err("URL trop longue (max 2048 caractères)".to_string());
    }
    // FIX M7 — SSRF: enforce HTTPS and block private/local addresses
    if !endpoint.starts_with("https://") {
        return Err("L'endpoint doit utiliser HTTPS (https://)".to_string());
    }

    let url = url::Url::parse(&endpoint)
        .map_err(|e| format!("URL invalide: {e}"))?;

    if url.host().map_or(true, is_blocked_host) {
        return Err("Les adresses locales/privées ne sont pas autorisées".to_string());
    }

    keystore::save_antigravity_endpoint(&endpoint)
}

/// Hôte interdit pour un endpoint sortant (anti-SSRF). `url` normalise déjà les IP
/// (décimales, octales, crochets IPv6) en `Host::Ipv4/Ipv6`.
fn is_blocked_host(host: url::Host<&str>) -> bool {
    use std::net::Ipv4Addr;
    fn v4(ip: Ipv4Addr) -> bool {
        ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
            || ip.is_broadcast() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64) // 100.64/10 CGNAT
    }
    match host {
        url::Host::Domain(d) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        url::Host::Ipv4(ip) => v4(ip),
        url::Host::Ipv6(ip) => {
            let s0 = ip.segments()[0];
            ip.is_loopback() || ip.is_unspecified()
                || s0 & 0xfe00 == 0xfc00 // fc00::/7 ULA
                || s0 & 0xffc0 == 0xfe80 // fe80::/10 link-local
                || ip.to_ipv4_mapped().is_some_and(v4)
        }
    }
}

/// Racine canonique du dernier scan (None si aucun scan ou racine introuvable).
fn scan_root(state: &AppState) -> Option<std::path::PathBuf> {
    let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
    scan.as_ref()
        .map(|r| std::path::PathBuf::from(&r.target_path))
        .and_then(|p| p.canonicalize().ok())
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
        let scan = state.current_scan.lock().unwrap_or_else(|e| e.into_inner());
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

    // Chemin racine du scan — tous les fichiers doivent être dedans
    let scan_root = scan_root(&state);

    for (file_idx, (file_path, vuln_indices)) in by_file.iter().enumerate() {
        // FIX VULN 3 — Valider que le fichier est bien dans le répertoire scanné
        if let Some(ref root) = scan_root {
            let canonical_fp = match std::path::PathBuf::from(file_path).canonicalize() {
                Ok(p) => p,
                Err(_) => {
                    let _ = app.emit("batch:progress", BatchFixProgress {
                        file_idx: file_idx + 1, total_files,
                        current_file: file_path.split(['/', '\\']).last().unwrap_or(file_path).to_string(),
                        status: "error: chemin invalide".to_string(),
                    });
                    continue;
                }
            };
            if !canonical_fp.starts_with(root) {
                let _ = app.emit("batch:progress", BatchFixProgress {
                    file_idx: file_idx + 1, total_files,
                    current_file: file_path.split(['/', '\\']).last().unwrap_or(file_path).to_string(),
                    status: "error: chemin hors du répertoire scanné".to_string(),
                });
                continue;
            }
        }

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
pub fn apply_patch(file_path: String, patched_content: String, state: State<'_, AppState>) -> Result<(), String> {
    write_patch(&file_path, &patched_content, scan_root(&state).as_deref())
}

fn write_patch(file_path: &str, patched_content: &str, scan_root: Option<&std::path::Path>) -> Result<(), String> {
    // FIX C1 — Path traversal: validate path before writing
    let path = std::path::PathBuf::from(file_path);

    // Must be absolute path
    if !path.is_absolute() {
        return Err("Chemin absolu requis".to_string());
    }

    // Canonicalize to resolve symlinks and .., and keep the file under $HOME
    let canonical = canonical_under_home(&path, true)?;

    // Confiné à la racine du dernier scan, comme batch_ai_fix
    let root = scan_root.ok_or("Aucun scan en cours : patch refusé")?;
    if !canonical.starts_with(root) {
        return Err("Chemin hors du répertoire scanné : patch refusé".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Régression : sous Windows `canonicalize` renvoie `\?\C:\...` alors que
    /// `USERPROFILE` vaut `C:\Users\...`. Comparer les deux sans canonicaliser
    /// le home rendait `starts_with` toujours faux et bloquait tout export.
    /// Le chemin rendu doit aussi garder le nom de fichier, pas juste le dossier.
    #[test]
    fn dest_inexistante_sous_home_est_acceptee_avec_son_nom() {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .expect("home introuvable");
        let dir = std::path::PathBuf::from(&home).join("secuscan_test_export");
        std::fs::create_dir_all(&dir).unwrap();

        let dest = dir.join("rapport.html");
        assert!(!dest.exists(), "le fichier ne doit pas exister avant le test");

        let out = canonical_under_home(&dest, false).expect("doit être accepté");
        assert_eq!(out.file_name().unwrap(), "rapport.html");
        assert_eq!(out.extension().and_then(|e| e.to_str()), Some("html"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Le chemin rendu porte le prefixe verbatim. Tout l'export repose sur
    /// l'hypothese que `std::fs::write` l'accepte : la verifier plutot que la
    /// supposer, et verifier aussi que le fichier est relisible par son chemin
    /// ordinaire.
    #[test]
    fn ecriture_sur_le_chemin_verbatim_rendu() {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .expect("home introuvable");
        let dir = std::path::PathBuf::from(&home).join("secuscan_test_ecriture");
        std::fs::create_dir_all(&dir).unwrap();

        let dest = dir.join("rapport.html");
        let resolu = canonical_under_home(&dest, false).expect("doit etre accepte");

        std::fs::write(&resolu, b"<html>ok</html>").expect("ecriture sur chemin verbatim");
        assert_eq!(std::fs::read(&dest).unwrap(), b"<html>ok</html>");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dest_hors_du_home_est_refusee() {
        let dest = std::path::PathBuf::from(r"C:\Windows\System32\rapport.html");
        assert!(canonical_under_home(&dest, false).is_err());
    }

    #[test]
    fn ssrf_blocks_private_and_ipv6_local() {
        let blocked = |u: &str| is_blocked_host(url::Url::parse(u).unwrap().host().unwrap());
        for u in ["https://localhost/", "https://127.0.0.1/", "https://2130706433/", "https://10.1.2.3/",
                  "https://172.20.0.1/", "https://172.31.255.1/", "https://192.168.1.1/", "https://169.254.169.254/",
                  "https://0.0.0.0/", "https://[::1]/", "https://[fd00::1]/", "https://[fe80::1]/",
                  "https://[::ffff:127.0.0.1]/", "https://a.localhost/"] {
            assert!(blocked(u), "{u} doit être bloqué");
        }
        for u in ["https://api.example.com/", "https://172.32.0.1/", "https://8.8.8.8/", "https://[2606:4700::1]/"] {
            assert!(!blocked(u), "{u} doit passer");
        }
    }

    #[test]
    fn patch_confined_to_scan_root() {
        let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap();
        let base = std::path::PathBuf::from(&home).join("secuscan_test_patch");
        let root = base.join("scan");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let inside_f = root.join("a.js");
        let outside_f = outside.join("b.js");
        std::fs::write(&inside_f, "x").unwrap();
        std::fs::write(&outside_f, "x").unwrap();
        let croot = root.canonicalize().unwrap();

        assert!(write_patch(outside_f.to_str().unwrap(), "evil", Some(&croot)).is_err());
        assert!(write_patch(inside_f.to_str().unwrap(), "ok", None).is_err());
        write_patch(inside_f.to_str().unwrap(), "ok", Some(&croot)).unwrap();
        assert_eq!(std::fs::read_to_string(&outside_f).unwrap(), "x");
        assert_eq!(std::fs::read_to_string(&inside_f).unwrap(), "ok");
        std::fs::remove_dir_all(&base).ok();
    }
}
