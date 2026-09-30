//! Stockage local des clés API (LLM et bases de réputation).
//! Windows : chiffrées par DPAPI pour l'utilisateur courant.
//! Linux / macOS : fichier lisible par le seul utilisateur (0600) dans son
//! dossier de configuration. Aucune clé n'est jamais intégrée au binaire.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StoredKeys {
    pub claude_enc:          Option<String>, // DPAPI-encrypted → base64
    pub gemini_enc:          Option<String>,
    pub antigravity_enc:     Option<String>,
    pub antigravity_endpoint: Option<String>,
    // Bases de réputation en ligne (même chiffrement)
    #[serde(default)]
    pub vt_enc:              Option<String>,
    #[serde(default)]
    pub metadefender_enc:    Option<String>,
    #[serde(default)]
    pub hybrid_enc:          Option<String>,
    #[serde(default)]
    pub opentip_enc:         Option<String>,
    #[serde(default)]
    pub otx_enc:             Option<String>,
    #[serde(default)]
    pub abusech_enc:         Option<String>,
    /// `Some(false)` = sources gratuites sans clé (Team Cymru, CIRCL) coupées.
    #[serde(default)]
    pub intel_free_lookups:  Option<bool>,
}

/// Noms de clés acceptés (liste blanche partagée avec les commandes).
pub const KEY_NAMES: [&str; 9] = [
    "claude", "gemini", "antigravity",
    "vt", "metadefender", "hybrid", "opentip", "otx", "abusech",
];

fn slot<'a>(stored: &'a mut StoredKeys, key_name: &str) -> Result<&'a mut Option<String>, String> {
    Ok(match key_name {
        "claude"       => &mut stored.claude_enc,
        "gemini"       => &mut stored.gemini_enc,
        "antigravity"  => &mut stored.antigravity_enc,
        "vt"           => &mut stored.vt_enc,
        "metadefender" => &mut stored.metadefender_enc,
        "hybrid"       => &mut stored.hybrid_enc,
        "opentip"      => &mut stored.opentip_enc,
        "otx"          => &mut stored.otx_enc,
        "abusech"      => &mut stored.abusech_enc,
        other          => return Err(format!("Unknown key name: {other}")),
    })
}

// ─── Dossier de configuration de l'app ────────────────────────────────────────

/// Windows : `%APPDATA%\SecuScanAI` (emplacement historique, conservé).
/// Ailleurs : `$XDG_CONFIG_HOME/SecuScanAI`, sinon `~/.config/SecuScanAI`.
pub fn config_dir() -> std::io::Result<PathBuf> {
    let missing = |v: &str| std::io::Error::new(std::io::ErrorKind::NotFound, format!("{v} non défini"));
    #[cfg(windows)]
    let base = std::env::var("APPDATA").map(PathBuf::from).map_err(|_| missing("APPDATA"))?;
    #[cfg(not(windows))]
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.trim().is_empty() => PathBuf::from(x),
        _ => std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")).map_err(|_| missing("HOME"))?,
    };
    Ok(base.join("SecuScanAI"))
}

fn keys_path() -> Result<PathBuf, String> {
    config_dir().map(|d| d.join("keys.json")).map_err(|e| e.to_string())
}

// ─── Windows DPAPI ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod dpapi {
    pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
        use winapi::um::dpapi::CryptProtectData;
        use winapi::um::wincrypt::CRYPTOAPI_BLOB;
        use winapi::um::winbase::LocalFree;

        unsafe {
            let mut input = CRYPTOAPI_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut output = CRYPTOAPI_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            let ok = CryptProtectData(
                &mut input,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut output,
            );

            if ok == 0 {
                return Err(format!("CryptProtectData failed: {}", std::io::Error::last_os_error()));
            }

            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as winapi::shared::minwindef::HLOCAL);
            Ok(result)
        }
    }

    pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
        use winapi::um::dpapi::CryptUnprotectData;
        use winapi::um::wincrypt::CRYPTOAPI_BLOB;
        use winapi::um::winbase::LocalFree;

        unsafe {
            let mut input = CRYPTOAPI_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut output = CRYPTOAPI_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            let ok = CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut output,
            );

            if ok == 0 {
                return Err(format!("CryptUnprotectData failed: {}", std::io::Error::last_os_error()));
            }

            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as winapi::shared::minwindef::HLOCAL);
            Ok(result)
        }
    }
}

// ─── Hors Windows : pas de coffre système commun ─────────────────────────────
// La protection repose sur les droits du fichier (0600, voir `write_raw`) :
// un XOR « d'obfuscation » ne protégerait rien de plus.

#[cfg(not(target_os = "windows"))]
mod dpapi {
    pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
    pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub fn save_key(key_name: &str, plaintext: &str) -> Result<(), String> {
    let mut stored = load_raw()?;
    let encrypted  = dpapi::encrypt(plaintext.as_bytes())?;
    *slot(&mut stored, key_name)? = Some(B64.encode(&encrypted));
    write_raw(&stored)
}

pub fn save_antigravity_endpoint(endpoint: &str) -> Result<(), String> {
    let mut stored = load_raw()?;
    stored.antigravity_endpoint = Some(endpoint.to_string());
    write_raw(&stored)
}

pub fn load_key(key_name: &str) -> Result<Option<String>, String> {
    let mut stored = load_raw()?;
    match slot(&mut stored, key_name)?.take() {
        None => Ok(None),
        Some(enc) => {
            let bytes     = B64.decode(&enc).map_err(|e| e.to_string())?;
            let decrypted = dpapi::decrypt(&bytes)?;
            let plaintext = String::from_utf8(decrypted).map_err(|e| e.to_string())?;
            Ok(Some(plaintext))
        }
    }
}

pub fn load_antigravity_endpoint() -> Option<String> {
    load_raw().ok()?.antigravity_endpoint
}

pub fn delete_key(key_name: &str) -> Result<(), String> {
    let mut stored = load_raw()?;
    *slot(&mut stored, key_name)? = None;
    write_raw(&stored)
}

/// Sources gratuites sans clé (Team Cymru, CIRCL) : actives par défaut.
pub fn intel_free_lookups() -> bool {
    load_raw().ok().and_then(|s| s.intel_free_lookups).unwrap_or(true)
}

pub fn set_intel_free_lookups(enabled: bool) -> Result<(), String> {
    let mut stored = load_raw()?;
    stored.intel_free_lookups = Some(enabled);
    write_raw(&stored)
}

/// Présence de chaque clé (jamais leur valeur).
pub fn key_status() -> serde_json::Value {
    let mut stored = load_raw().unwrap_or_default();
    let mut m = serde_json::Map::new();
    for name in KEY_NAMES {
        let present = slot(&mut stored, name).map(|s| s.is_some()).unwrap_or(false);
        m.insert(name.to_string(), serde_json::Value::Bool(present));
    }
    m.insert("antigravity_endpoint".into(), serde_json::json!(stored.antigravity_endpoint));
    m.insert("intel_free_lookups".into(), serde_json::Value::Bool(stored.intel_free_lookups.unwrap_or(true)));
    serde_json::Value::Object(m)
}

fn load_raw() -> Result<StoredKeys, String> {
    let path = keys_path()?;
    if !path.exists() {
        return Ok(StoredKeys::default());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

fn write_raw(stored: &StoredKeys) -> Result<(), String> {
    let path = keys_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(stored).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
