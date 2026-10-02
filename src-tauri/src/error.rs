use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecuScanError {
    #[error("Erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),

    #[error("Erreur d'analyse : {0}")]
    Parse(String),

    #[error("Erreur YARA : {0}")]
    Yara(String),

    #[error("Erreur de l'API d'IA : {0}")]
    LlmApi(String),

    #[error("Erreur DPAPI : {0}")]
    Dpapi(String),

    #[error("Erreur JSON : {0}")]
    Json(#[from] serde_json::Error),

    #[error("Erreur HTTP : {0}")]
    Http(#[from] reqwest::Error),

    #[error("Accès refusé : {0}")]
    AccessDenied(String),

    #[error("Chemin invalide : {0}")]
    InvalidPath(String),

    #[error("Analyse annulée")]
    Cancelled,

    #[error("Erreur inconnue : {0}")]
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
