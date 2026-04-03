// mofold-core/src/lib.rs
//
// MofoldZiplog — Binary Desert Protocol (BDP) v2
// Rust reference implementation
//
// Security properties:
//   • PBKDF2-HMAC-SHA256 @ 600,000 iterations for key derivation (ring built-in)
//     — Upgrade path to Argon2id (memory-hard) documented in .cargo/config.toml;
//       requires Rust ≥ 1.85 due to argon2 0.5 transitive dep on base64ct ≥ 1.8
//   • AES-256-GCM (Layer 1, authenticated) + AES-256-CBC (Layer 2, diffusion)
//   • Independently derived keys per layer via PBKDF2 domain separation ("_layer2" suffix)
//   • zeroize::ZeroizeOnDrop on all key types — memory wiped on drop, not on explicit call
//   • Constant-time comparisons via XOR accumulator (own impl, no deprecated ring API)
//   • Hierarchical key system: PMK → RK / WK (offline PMK, online RK/WK only)
//   • 64-byte BDP envelope header (wire-compatible with original TypeScript BDP)

pub mod crypto;
pub mod envelope;
pub mod keys;
pub mod coordinate;
pub mod voucher;
pub mod error;

pub use error::BdpError;
pub use keys::{ProjectMasterKey, ReadKey, WriteKey, KeyHierarchy};
pub use envelope::{Envelope, BlobType, ENVELOPE_SIZE};
pub use coordinate::{Coordinate, CoordinateDerivation};
pub use voucher::{Voucher, VoucherTier, VoucherClaims};
