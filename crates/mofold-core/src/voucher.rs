// mofold-core/src/voucher.rs — Stateless HMAC-SHA256 voucher system
//
// Token format: <TIER>-<CLAIMS_B64>.<HMAC_HEX>
// Constant-time HMAC comparison via ct_eq_32 (no timing oracle).

use ring::hmac;
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::{crypto::ct_eq_32, error::BdpError};

const FREE_MAX_RPS:   u32 = 5;
const FREE_MAX_BYTES: u64 = 50 * 1024 * 1024;
const PAID_MAX_RPS:   u32 = 500;

// ─── Tier ─────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VoucherTier {
    Free,
    Paid,
}

impl VoucherTier {
    pub fn prefix(&self) -> &'static str {
        match self { VoucherTier::Free => "FREE", VoucherTier::Paid => "PAID" }
    }
    pub fn max_rps(&self)          -> u32        { match self { VoucherTier::Free => FREE_MAX_RPS, VoucherTier::Paid => PAID_MAX_RPS } }
    pub fn max_quota_bytes(&self)  -> Option<u64>{ match self { VoucherTier::Free => Some(FREE_MAX_BYTES), VoucherTier::Paid => None } }
    pub fn max_lifetime_secs(&self)-> u64        { match self { VoucherTier::Free => 30*24*3600, VoucherTier::Paid => 365*24*3600 } }
}

// ─── Claims ───────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherClaims {
    pub voucher_id:    String,
    pub tier:          VoucherTier,
    pub issued_at:     u64,
    pub expires_at:    u64,
    pub quota_bytes:   u64,
    pub rate_limit_rps: u32,
}

// ─── Voucher ──────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Voucher {
    pub claims: VoucherClaims,
    pub token:  String,
}

impl Voucher {
    pub fn issue(claims: VoucherClaims, server_secret: &[u8]) -> Result<Self, BdpError> {
        let max_quota = claims.tier.max_quota_bytes().unwrap_or(u64::MAX);
        if claims.quota_bytes > max_quota {
            return Err(BdpError::InvalidVoucher(
                format!("quota {} > tier max {}", claims.quota_bytes, max_quota)));
        }
        let lifetime = claims.expires_at.saturating_sub(claims.issued_at);
        if lifetime > claims.tier.max_lifetime_secs() {
            return Err(BdpError::InvalidVoucher("expires_at exceeds tier max lifetime".into()));
        }
        let claims_b64  = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?.as_bytes());
        let signing_in  = format!("{}-{}", claims.tier.prefix(), claims_b64);
        let hmac_hex    = sign_hex(server_secret, signing_in.as_bytes());
        Ok(Self { claims, token: format!("{}.{}", signing_in, hmac_hex) })
    }

    pub fn verify(token: &str, server_secret: &[u8], now_unix: u64) -> Result<Self, BdpError> {
        let dot       = token.rfind('.').ok_or_else(|| BdpError::InvalidVoucher("missing '.'".into()))?;
        let signing   = &token[..dot];
        let provided  = &token[dot+1..];
        let expected  = sign_hex(server_secret, signing.as_bytes());

        // Constant-time compare: pad both to 64 hex chars (SHA-256 output is always 64)
        let e_bytes = expected.as_bytes();
        let p_bytes = provided.as_bytes();
        if e_bytes.len() != 64 || p_bytes.len() != 64 {
            return Err(BdpError::HmacVerification);
        }
        let mut ea = [0u8; 32]; let mut pa = [0u8; 32];
        hex::decode_to_slice(e_bytes, &mut ea).map_err(|_| BdpError::HmacVerification)?;
        hex::decode_to_slice(p_bytes, &mut pa).map_err(|_| BdpError::HmacVerification)?;
        if !ct_eq_32(&ea, &pa) { return Err(BdpError::HmacVerification); }

        let dash        = signing.find('-').ok_or_else(|| BdpError::InvalidVoucher("no tier prefix".into()))?;
        let claims_b64  = &signing[dash+1..];
        let claims_json = URL_SAFE_NO_PAD.decode(claims_b64)?;
        let claims: VoucherClaims = serde_json::from_slice(&claims_json)?;

        if now_unix > claims.expires_at { return Err(BdpError::VoucherExpired); }

        let max_rps = claims.tier.max_rps();
        if claims.rate_limit_rps > max_rps {
            return Err(BdpError::InvalidVoucher(
                format!("rate_limit_rps {} > tier max {}", claims.rate_limit_rps, max_rps)));
        }

        Ok(Self { token: token.to_string(), claims })
    }

    pub fn effective_rps(&self)          -> u32  { self.claims.rate_limit_rps }
    pub fn effective_quota_bytes(&self)  -> u64  { self.claims.quota_bytes }
    pub fn is_free(&self)                -> bool { self.claims.tier == VoucherTier::Free }
}

fn sign_hex(secret: &[u8], data: &[u8]) -> String {
    let k   = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&k, data);
    hex::encode(tag.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SECRET: &[u8] = b"unit-test-secret";
    const NOW:    u64   = 1_700_000_000;

    fn free_claims() -> VoucherClaims {
        VoucherClaims { voucher_id: "v1".into(), tier: VoucherTier::Free,
            issued_at: NOW, expires_at: NOW + 7*24*3600,
            quota_bytes: 10*1024*1024, rate_limit_rps: 5 }
    }

    #[test] fn issue_and_verify_free_voucher() {
        let v  = Voucher::issue(free_claims(), SECRET).unwrap();
        let v2 = Voucher::verify(&v.token, SECRET, NOW + 100).unwrap();
        assert_eq!(v2.claims.voucher_id, "v1");
        assert!(v2.is_free());
    }
    #[test] fn expired_voucher_rejected() {
        let v = Voucher::issue(free_claims(), SECRET).unwrap();
        assert!(matches!(Voucher::verify(&v.token, SECRET, NOW + 999_999_999),
                         Err(BdpError::VoucherExpired)));
    }
    #[test] fn tampered_hmac_rejected() {
        let v   = Voucher::issue(free_claims(), SECRET).unwrap();
        let bad = v.token.replace('a', "b");
        assert!(Voucher::verify(&bad, SECRET, NOW + 100).is_err());
    }
    #[test] fn wrong_secret_rejected() {
        let v = Voucher::issue(free_claims(), SECRET).unwrap();
        assert!(Voucher::verify(&v.token, b"wrong", NOW + 100).is_err());
    }
    #[test] fn free_tier_rps_capped() {
        let mut c = free_claims(); c.rate_limit_rps = 1000;
        let v = Voucher::issue(c, SECRET).unwrap();
        assert!(Voucher::verify(&v.token, SECRET, NOW + 100).is_err());
    }
    #[test] fn paid_voucher_higher_limits() {
        let c = VoucherClaims { voucher_id: "p1".into(), tier: VoucherTier::Paid,
            issued_at: NOW, expires_at: NOW + 365*24*3600,
            quota_bytes: 0, rate_limit_rps: 500 };
        let v = Voucher::issue(c, SECRET).unwrap();
        let v2 = Voucher::verify(&v.token, SECRET, NOW + 100).unwrap();
        assert!(!v2.is_free()); assert_eq!(v2.effective_rps(), 500);
    }
}
