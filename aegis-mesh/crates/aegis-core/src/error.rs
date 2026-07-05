//! Error types — redacted for safe logging (audit fix: error.rs leaked secrets).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("crypto error")]
    Crypto,
    #[error("invalid input")]
    Invalid,
    #[error("storage error")]
    Storage,
    #[error("transport error")]
    Transport,
    #[error("mesh error")]
    Mesh,
    #[error("encoding error")]
    Encoding,
    #[error("io error")]
    Io,
    #[error("json error")]
    Json,
    #[error("sqlite error")]
    Sqlite,
    #[error("signature verification failed")]
    Signature,
    #[error("message expired or replayed")]
    Stale,
    #[error("rate limited")]
    RateLimited,
    #[error("queue full")]
    QueueFull,
    #[error("other error")]
    Other,
}

// Internal-only rich error context — never serialized, never logged at Display.
// Use tracing::debug! for detailed diagnostics; Display stays redacted.
impl From<std::io::Error> for AegisError {
    fn from(_: std::io::Error) -> Self { Self::Io }
}
impl From<serde_json::Error> for AegisError {
    fn from(_: serde_json::Error) -> Self { Self::Json }
}
impl From<rusqlite::Error> for AegisError {
    fn from(_: rusqlite::Error) -> Self { Self::Sqlite }
}
impl From<aead::Error> for AegisError {
    fn from(_: aead::Error) -> Self { Self::Crypto }
}
impl From<ed25519_dalek::SignatureError> for AegisError {
    fn from(_: ed25519_dalek::SignatureError) -> Self { Self::Signature }
}
impl From<hex::FromHexError> for AegisError {
    fn from(_: hex::FromHexError) -> Self { Self::Encoding }
}
impl From<base64::DecodeError> for AegisError {
    fn from(_: base64::DecodeError) -> Self { Self::Encoding }
}

pub type Result<T> = std::result::Result<T, AegisError>;
