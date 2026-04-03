// mofold-core/src/coordinate.rs — BDP coordinate derivation
use ring::hmac;
use zeroize::Zeroize;
use crate::crypto::ct_eq_32;
use crate::error::BdpError;

// Domain-separation labels — each coordinate type has a unique prefix
const DOMAIN_VAULT:    &[u8] = b"BDP:VAULT-COORD-v2";
const DOMAIN_FOLD:     &[u8] = b"BDP:FOLD-COORD-v2";
const DOMAIN_LOG:      &[u8] = b"BDP:LOG-COORD-v2";
const DOMAIN_MANIFEST: &[u8] = b"BDP:MANIFEST-COORD-v2";
const DOMAIN_INVITE:   &[u8] = b"BDP:INVITE-COORD-v2";

/// 32-byte BDP storage coordinate. Constant-time equality via ct_eq_32().
#[derive(Clone, Zeroize)]
pub struct Coordinate([u8; 32]);

impl Coordinate {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn to_hex(&self) -> String       { hex::encode(self.0) }

    pub fn from_hex(s: &str) -> Result<Self, BdpError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(BdpError::HexDecode(hex::FromHexError::InvalidStringLength));
        }
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&bytes);
        Ok(Self(inner))
    }

    /// Constant-time equality — prevents timing oracle on coordinate comparison.
    pub fn ct_eq(&self, other: &Coordinate) -> bool {
        ct_eq_32(&self.0, &other.0)
    }
}

impl std::fmt::Debug for Coordinate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Coordinate({}...)", &self.to_hex()[..8])
    }
}

pub struct CoordinateDerivation;

impl CoordinateDerivation {
    /// Vault coordinate — identifies a user's root vault.
    pub fn vault(write_key: &[u8; 32], project_id: &str) -> Coordinate {
        hmac_coord(write_key, &[DOMAIN_VAULT, b":", project_id.as_bytes()])
    }

    /// Fold coordinate — individual fold scoped to a vault.
    pub fn fold(write_key: &[u8; 32], fold_key: &str, vault_coord: &Coordinate) -> Coordinate {
        hmac_coord(write_key, &[DOMAIN_FOLD, b":", fold_key.as_bytes(),
                                b":", vault_coord.as_bytes()])
    }

    /// Log entry coordinate — derived from project + monotonic sequence number.
    pub fn log_entry(write_key: &[u8; 32], project_id: &str, sequence: u64) -> Coordinate {
        hmac_coord(write_key, &[DOMAIN_LOG, b":", project_id.as_bytes(),
                                b":", &sequence.to_be_bytes()])
    }

    /// Manifest coordinate for a channel or locker.
    pub fn manifest(write_key: &[u8; 32], channel_key: &str) -> Coordinate {
        hmac_coord(write_key, &[DOMAIN_MANIFEST, b":", channel_key.as_bytes()])
    }

    /// Invite coordinate. namespace = "ROOM" | "LOCKER"
    pub fn invite(
        write_key:   &[u8; 32],
        invite_key:  &str,
        channel_key: &str,
        namespace:   &str,
    ) -> Coordinate {
        hmac_coord(write_key, &[DOMAIN_INVITE, b":", invite_key.as_bytes(),
                                b":", channel_key.as_bytes(), b":", namespace.as_bytes()])
    }
}

// ── Internal: HMAC-SHA256(key=write_key, data=concat(parts)) → Coordinate ────
fn hmac_coord(key_bytes: &[u8; 32], parts: &[&[u8]]) -> Coordinate {
    let key    = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    let mut ctx = hmac::Context::with_key(&key);
    for part in parts { ctx.update(part); }
    let tag = ctx.sign();
    let mut inner = [0u8; 32];
    inner.copy_from_slice(&tag.as_ref()[..32]);
    Coordinate(inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ProjectMasterKey;

    fn test_wk() -> [u8; 32] {
        *ProjectMasterKey::from_bytes([0x42; 32]).derive_write_key().as_bytes()
    }

    #[test] fn vault_coords_differ_per_project() {
        let wk = test_wk();
        assert!(!CoordinateDerivation::vault(&wk, "alpha").ct_eq(
                &CoordinateDerivation::vault(&wk, "beta")));
    }
    #[test] fn fold_scoped_to_vault() {
        let wk  = test_wk();
        let vc1 = CoordinateDerivation::vault(&wk, "proj-a");
        let vc2 = CoordinateDerivation::vault(&wk, "proj-b");
        assert!(!CoordinateDerivation::fold(&wk, "same-key", &vc1)
                 .ct_eq(&CoordinateDerivation::fold(&wk, "same-key", &vc2)));
    }
    #[test] fn log_coords_differ_by_sequence() {
        let wk = test_wk();
        assert!(!CoordinateDerivation::log_entry(&wk, "proj", 0)
                 .ct_eq(&CoordinateDerivation::log_entry(&wk, "proj", 1)));
    }
    #[test] fn coord_hex_roundtrip() {
        let wk = test_wk();
        let c  = CoordinateDerivation::vault(&wk, "test");
        assert!(c.ct_eq(&Coordinate::from_hex(&c.to_hex()).unwrap()));
    }
}
