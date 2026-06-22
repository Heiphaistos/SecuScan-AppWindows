//! Secure key storage using Windows DPAPI.
//! Keys are encrypted per-user with the OS credential store.
//! Plain-text API keys NEVER touch disk.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StoredKeys {
    pub claude_enc:          Option<String>, // DPAPI-encrypted → base64
    pub gemini_enc:          Option<String>,
    pub antigravity_enc:     Option<String>,
    pub antigravity_endpoint: Option<String>,
}

// ─── Storage path (AppData\Roaming\SecuScanAI) ────────────────────────────────

fn keys_path() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("SecuScanAI").join("keys.json")
}

fn ensure_dir(path: &PathBuf) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

// ─── Windows DPAPI ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod dpapi {
    use super::*;

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

// ─── Fallback (non-Windows dev builds) ───────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod dpapi {
    pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
        // Non-Windows: store obfuscated (NOT secure — dev only)
        Ok(data.iter().map(|b| b ^ 0x5A).collect())
    }
    pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.iter().map(|b| b ^ 0x5A).collect())
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub fn save_key(key_name: &str, plaintext: &str) -> Result<(), String> {
    let path = keys_path();
    ensure_dir(&path).map_err(|e| e.to_string())?;

    let mut stored = load_raw().unwrap_or_default();
    let encrypted  = dpapi::encrypt(plaintext.as_bytes())?;
    let encoded    = B64.encode(&encrypted);

    match key_name {
        "claude"      => stored.claude_enc      = Some(encoded),
        "gemini"      => stored.gemini_enc      = Some(encoded),
        "antigravity" => stored.antigravity_enc = Some(encoded),
        other         => return Err(format!("Unknown key name: {other}")),
    }

    let json = serde_json::to_string_pretty(&stored).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn save_antigravity_endpoint(endpoint: &str) -> Result<(), String> {
    let path = keys_path();
    ensure_dir(&path).map_err(|e| e.to_string())?;
    let mut stored = load_raw().unwrap_or_default();
    stored.antigravity_endpoint = Some(endpoint.to_string());
    let json = serde_json::to_string_pretty(&stored).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn load_key(key_name: &str) -> Result<Option<String>, String> {
    let stored = load_raw().unwrap_or_default();
    let encoded = match key_name {
        "claude"      => stored.claude_enc,
        "gemini"      => stored.gemini_enc,
        "antigravity" => stored.antigravity_enc,
        other         => return Err(format!("Unknown key name: {other}")),
    };

    match encoded {
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
    let path = keys_path();
    let mut stored = load_raw().unwrap_or_default();
    match key_name {
        "claude"      => stored.claude_enc      = None,
        "gemini"      => stored.gemini_enc      = None,
        "antigravity" => stored.antigravity_enc = None,
        other         => return Err(format!("Unknown key name: {other}")),
    }
    let json = serde_json::to_string_pretty(&stored).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn key_status() -> serde_json::Value {
    let stored = load_raw().unwrap_or_default();
    serde_json::json!({
        "claude":      stored.claude_enc.is_some(),
        "gemini":      stored.gemini_enc.is_some(),
        "antigravity": stored.antigravity_enc.is_some(),
        "antigravity_endpoint": stored.antigravity_endpoint,
    })
}

fn load_raw() -> Result<StoredKeys, String> {
    let path = keys_path();
    if !path.exists() {
        return Ok(StoredKeys::default());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}
