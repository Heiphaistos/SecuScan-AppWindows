use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecuScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("YARA error: {0}")]
    Yara(String),

    #[error("LLM API error: {0}")]
    LlmApi(String),

    #[error("DPAPI error: {0}")]
    Dpapi(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Scan cancelled")]
    Cancelled,

    #[error("Unknown error: {0}")]
    Other(String),
}

impl From<SecuScanError> for String {
    fn from(e: SecuScanError) -> Self {
        e.to_string()
    }
}

impl From<anyhow::Error> for SecuScanError {
    fn from(e: anyhow::Error) -> Self {
        SecuScanError::Other(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SecuScanError>;
