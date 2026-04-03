// mofold-core/src/error.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BdpError {
    #[error("Argon2id key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed (bad key, tampered ciphertext, or wrong blob type)")]
    Decryption,

    #[error("Envelope too small: need at least {0} bytes, got {1}")]
    EnvelopeTooSmall(usize, usize),

    #[error("Envelope version unsupported: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid blob type byte: {0:#04x}")]
    InvalidBlobType(u8),

    #[error("HMAC verification failed")]
    HmacVerification,

    #[error("Voucher invalid: {0}")]
    InvalidVoucher(String),

    #[error("Voucher expired")]
    VoucherExpired,

    // WriteKeyRejectedForRead — reserved for future client-side role enforcement.
    // Role validation currently happens in the Gateway Worker (TypeScript).
    // Uncomment when/if a Rust proxy layer is added that validates role headers.

    #[error("Padding error in CBC layer")]
    PaddingError,

    #[error("Random number generation failed")]
    Rng,

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
