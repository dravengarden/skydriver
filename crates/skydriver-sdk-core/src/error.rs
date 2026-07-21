//! Stable failures shared by portable core modules.

/// Portable SDK validation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An input or derived layout violates a protocol bound.
    #[error("invalid Skydriver SDK input: {0}")]
    InvalidInput(&'static str),
    /// Key derivation or authenticated encryption failed.
    #[error("Skydriver SDK cryptographic verification failed")]
    Crypto,
}
