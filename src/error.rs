use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeySystemError {
    #[error("license token is malformed")]
    MalformedToken,
    #[error("license token exceeds the maximum supported length")]
    TokenTooLarge,
    #[error("license payload is invalid")]
    InvalidPayload,
    #[error("license public key is invalid")]
    InvalidPublicKey,
    #[error("license signature is invalid")]
    InvalidSignature,
    #[error("the token references an unknown signing key")]
    UnknownSigningKey,
    #[error("license does not target this software")]
    SoftwareTargetMismatch,
    #[error("license issue time is too far in the future")]
    IssuedInFuture,
    #[error("license has expired")]
    Expired,
    #[error("local clock moved backwards beyond the allowed drift")]
    ClockRollback,
    #[error("license was revoked")]
    Revoked,
    #[error("revocation response is malformed")]
    MalformedRevocationResponse,
    #[error("revocation response signature is invalid")]
    InvalidRevocationSignature,
    #[error("revocation response is not fresh")]
    StaleRevocationResponse,
    #[error("revocation response rolls back the persisted revocation state")]
    RevocationRollback,
    #[error("protected verifier state could not be persisted")]
    StateStorage,
    #[error("hardware identifier does not match the license")]
    HardwareMismatch,
    #[error("invalid verification policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("failed to decode base64url input: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("failed to parse license JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, KeySystemError>;
