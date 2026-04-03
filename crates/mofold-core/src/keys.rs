// mofold-core/src/keys.rs — Hierarchical key system (PMK → RK / WK)
//
//  ProjectMasterKey (PMK)  — OFFLINE ONLY
//        │
//        ├─► ReadKey  (RK) = HMAC-SHA256(PMK, "BDP-READ-KEY-v2")
//        └─► WriteKey (WK) = HMAC-SHA256(PMK, "BDP-WRITE-KEY-v2")
//
//  All key types implement ZeroizeOnDrop — memory wiped on drop.

use ring::hmac;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::BdpError;

const DOMAIN_READ:  &[u8] = b"BDP-READ-KEY-v2";
const DOMAIN_WRITE: &[u8] = b"BDP-WRITE-KEY-v2";

// ─── ProjectMasterKey ─────────────────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProjectMasterKey { inner: [u8; 32] }

impl ProjectMasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self { inner: bytes } }
    pub fn as_bytes(&self) -> &[u8; 32]        { &self.inner }

    pub fn derive_read_key(&self)  -> ReadKey  { ReadKey  { inner: hmac_key(&self.inner, DOMAIN_READ)  } }
    pub fn derive_write_key(&self) -> WriteKey { WriteKey { inner: hmac_key(&self.inner, DOMAIN_WRITE) } }
}

// ─── ReadKey ──────────────────────────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReadKey { inner: [u8; 32] }

impl ReadKey {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.inner }
    pub fn to_hex(&self)   -> String    { hex::encode(self.inner) }

    pub fn from_hex(s: &str) -> Result<Self, BdpError> {
        let b = hex::decode(s)?;
        if b.len() != 32 { return Err(BdpError::KeyDerivation("ReadKey must be 32 bytes".into())); }
        let mut inner = [0u8; 32]; inner.copy_from_slice(&b);
        Ok(Self { inner })
    }
    pub const ROLE_TAG: &'static str = "RK";
}

// ─── WriteKey ─────────────────────────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WriteKey { inner: [u8; 32] }

impl WriteKey {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.inner }
    pub fn to_hex(&self)   -> String    { hex::encode(self.inner) }

    pub fn from_hex(s: &str) -> Result<Self, BdpError> {
        let b = hex::decode(s)?;
        if b.len() != 32 { return Err(BdpError::KeyDerivation("WriteKey must be 32 bytes".into())); }
        let mut inner = [0u8; 32]; inner.copy_from_slice(&b);
        Ok(Self { inner })
    }
    pub const ROLE_TAG: &'static str = "WK";
}

// ─── KeyHierarchy ─────────────────────────────────────────────────────────────
pub struct KeyHierarchy {
    pub read_key:  ReadKey,
    pub write_key: WriteKey,
}

impl KeyHierarchy {
    pub fn from_pmk(pmk: &ProjectMasterKey) -> Self {
        Self { read_key: pmk.derive_read_key(), write_key: pmk.derive_write_key() }
    }
}

// ─── Internal ─────────────────────────────────────────────────────────────────
fn hmac_key(master: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let k   = hmac::Key::new(hmac::HMAC_SHA256, master);
    let tag = hmac::sign(&k, domain);
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag.as_ref()[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn rk_wk_are_distinct() {
        let pmk = ProjectMasterKey::from_bytes([0xAB; 32]);
        assert_ne!(pmk.derive_read_key().inner, pmk.derive_write_key().inner);
    }
    #[test] fn rk_is_deterministic() {
        let pmk = ProjectMasterKey::from_bytes([0x42; 32]);
        assert_eq!(pmk.derive_read_key().inner, pmk.derive_read_key().inner);
    }
    #[test] fn hex_roundtrip() {
        let pmk = ProjectMasterKey::from_bytes([0x01; 32]);
        let rk  = pmk.derive_read_key();
        let hex = rk.to_hex();
        assert_eq!(ReadKey::from_hex(&hex).unwrap().inner, rk.inner);
    }
}
