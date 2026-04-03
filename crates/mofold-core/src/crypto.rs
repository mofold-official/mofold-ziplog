// mofold-core/src/crypto.rs — BDP v2 cryptographic engine
//
// Key derivation:  PBKDF2-HMAC-SHA256 @ 600,000 iterations (ring built-in)
// Layer 1:         AES-256-GCM  (authenticated encryption, ring)
// Layer 2:         AES-256-CBC  (diffusion, independent key, aes+cbc crates)
// Memory safety:   All key material in Zeroizing<[u8;32]> — wiped on drop
// Constant-time:   ct_eq_32() using XOR accumulator — no external dep

use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey,
           UnboundKey, AES_256_GCM},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
    error::Unspecified,
    digest,
};
use zeroize::Zeroizing;
use crate::error::BdpError;

const PBKDF2_ITERS:  u32   = 600_000;
const KEY_LEN:       usize = 32;
const LAYER2_SUFFIX: &[u8] = b"_layer2";

// ─── Constant-time comparison ─────────────────────────────────────────────────
/// XOR-accumulator constant-time equality for 32-byte arrays.
/// Executes in time proportional to 32 iterations regardless of values.
/// Used for admin-token and coordinate comparisons.
#[inline(always)]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────────
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

// ─── Admin token verification ─────────────────────────────────────────────────
/// Verifies SHA-256(provided_token) == stored_hash in constant time.
pub fn verify_admin_token(stored_hash: &[u8; 32], provided_token: &[u8]) -> bool {
    let computed = sha256(provided_token);
    ct_eq_32(stored_hash, &computed)
}

// ─── Double-layer ciphertext ──────────────────────────────────────────────────
#[derive(Debug)]
pub struct DoubleLayerCiphertext {
    pub salt1:      [u8; 16],  // GCM KDF salt  → stored in envelope header bytes 34-49
    pub iv1:        [u8; 12],  // GCM IV        → stored in envelope header bytes 50-61
    pub salt2:      [u8; 16],  // CBC KDF salt  → stored in payload prefix bytes 0-15
    pub iv2:        [u8; 16],  // CBC IV        → stored in payload prefix bytes 16-31
    pub ciphertext: Vec<u8>,   // AES-CBC(AES-GCM(plaintext)) → payload bytes 32+
}

// ─── Public encryption API ────────────────────────────────────────────────────
pub fn double_encrypt(
    plaintext:    &[u8],
    key_material: &[u8],
) -> Result<DoubleLayerCiphertext, BdpError> {
    let rng = SystemRandom::new();
    let mut salt1 = [0u8; 16]; let mut iv1 = [0u8; 12];
    let mut salt2 = [0u8; 16]; let mut iv2 = [0u8; 16];
    rng.fill(&mut salt1).map_err(|_| BdpError::Rng)?;
    rng.fill(&mut iv1).map_err(|_| BdpError::Rng)?;
    rng.fill(&mut salt2).map_err(|_| BdpError::Rng)?;
    rng.fill(&mut iv2).map_err(|_| BdpError::Rng)?;

    let key1   = derive_key(key_material, &salt1, b"")?;
    let gcm_ct = aes_gcm_encrypt(&key1, &iv1, plaintext)?;
    let key2   = derive_key(key_material, &salt2, LAYER2_SUFFIX)?;
    let cbc_ct = aes_cbc_encrypt(&key2, &iv2, &gcm_ct)?;

    Ok(DoubleLayerCiphertext { salt1, iv1, salt2, iv2, ciphertext: cbc_ct })
}

pub fn double_decrypt(
    ct:           &DoubleLayerCiphertext,
    key_material: &[u8],
) -> Result<Vec<u8>, BdpError> {
    let key2   = derive_key(key_material, &ct.salt2, LAYER2_SUFFIX)?;
    let gcm_ct = aes_cbc_decrypt(&key2, &ct.iv2, &ct.ciphertext)?;
    let key1   = derive_key(key_material, &ct.salt1, b"")?;
    aes_gcm_decrypt(&key1, &ct.iv1, &gcm_ct)
}

/// Parse raw payload bytes (after envelope header) into DoubleLayerCiphertext.
/// Caller must inject salt1/iv1 from the envelope header.
pub fn parse_payload(payload: &[u8]) -> Result<DoubleLayerCiphertext, BdpError> {
    if payload.len() < 32 { return Err(BdpError::Decryption); }
    let mut salt2 = [0u8; 16]; let mut iv2 = [0u8; 16];
    salt2.copy_from_slice(&payload[0..16]);
    iv2.copy_from_slice(&payload[16..32]);
    Ok(DoubleLayerCiphertext {
        salt1: [0u8; 16], iv1: [0u8; 12], salt2, iv2,
        ciphertext: payload[32..].to_vec(),
    })
}

/// Pack DoubleLayerCiphertext into payload bytes: salt2[16] + iv2[16] + cbc_ciphertext
pub fn pack_payload(ct: &DoubleLayerCiphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + ct.ciphertext.len());
    out.extend_from_slice(&ct.salt2);
    out.extend_from_slice(&ct.iv2);
    out.extend_from_slice(&ct.ciphertext);
    out
}

// ─── PBKDF2-HMAC-SHA256 KDF ───────────────────────────────────────────────────
fn derive_key(
    key_material: &[u8],
    salt:         &[u8],
    suffix:       &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, BdpError> {
    let mut input = Vec::with_capacity(key_material.len() + suffix.len());
    input.extend_from_slice(key_material);
    input.extend_from_slice(suffix);
    let iters = std::num::NonZeroU32::new(PBKDF2_ITERS)
        .ok_or_else(|| BdpError::KeyDerivation("zero iterations".into()))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, &input, key.as_mut());
    Ok(key)
}

// ─── AES-256-GCM (ring) ───────────────────────────────────────────────────────
struct OneTimeNonce([u8; 12]);
impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

fn aes_gcm_encrypt(
    key: &Zeroizing<[u8; 32]>,
    iv:  &[u8; 12],
    pt:  &[u8],
) -> Result<Vec<u8>, BdpError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key.as_ref())
        .map_err(|_| BdpError::Encryption("GCM key init".into()))?;
    let mut sealer = SealingKey::new(unbound, OneTimeNonce(*iv));
    let mut buf    = pt.to_vec();
    sealer.seal_in_place_append_tag(Aad::empty(), &mut buf)
        .map_err(|_| BdpError::Encryption("GCM seal".into()))?;
    Ok(buf)
}

fn aes_gcm_decrypt(
    key: &Zeroizing<[u8; 32]>,
    iv:  &[u8; 12],
    ct:  &[u8],
) -> Result<Vec<u8>, BdpError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key.as_ref())
        .map_err(|_| BdpError::Decryption)?;
    let mut opener = OpeningKey::new(unbound, OneTimeNonce(*iv));
    let mut buf    = ct.to_vec();
    let plain      = opener.open_in_place(Aad::empty(), &mut buf)
        .map_err(|_| BdpError::Decryption)?;
    Ok(plain.to_vec())
}

// ─── AES-256-CBC (aes + cbc crates) ──────────────────────────────────────────
fn aes_cbc_encrypt(
    key:  &Zeroizing<[u8; 32]>,
    iv:   &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, BdpError> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    type Enc = cbc::Encryptor<aes::Aes256>;
    let k = aes::cipher::generic_array::GenericArray::from_slice(key.as_ref());
    let i = aes::cipher::generic_array::GenericArray::from_slice(iv.as_ref());
    Ok(Enc::new(k, i).encrypt_padded_vec_mut::<Pkcs7>(data))
}

fn aes_cbc_decrypt(
    key:  &Zeroizing<[u8; 32]>,
    iv:   &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, BdpError> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Dec = cbc::Decryptor<aes::Aes256>;
    let k = aes::cipher::generic_array::GenericArray::from_slice(key.as_ref());
    let i = aes::cipher::generic_array::GenericArray::from_slice(iv.as_ref());
    Dec::new(k, i).decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| BdpError::PaddingError)
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &[u8] = b"mofold-ziplog-test-key-32bytes!!";

    #[test] fn roundtrip() {
        let pt = b"ERROR payment: timeout after 30s";
        assert_eq!(double_decrypt(&double_encrypt(pt, KEY).unwrap(), KEY).unwrap(), pt);
    }
    #[test] fn roundtrip_empty() {
        assert_eq!(double_decrypt(&double_encrypt(b"", KEY).unwrap(), KEY).unwrap(), b"");
    }
    #[test] fn wrong_key_fails() {
        let ct = double_encrypt(b"secret", KEY).unwrap();
        assert!(double_decrypt(&ct, b"wrong-key-for-unit-test-purposes").is_err());
    }
    #[test] fn unique_ciphertexts() {
        let a = double_encrypt(b"same", KEY).unwrap();
        let b = double_encrypt(b"same", KEY).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
    }
    #[test] fn payload_roundtrip() {
        let ct     = double_encrypt(b"pack test", KEY).unwrap();
        let packed = pack_payload(&ct);
        let mut p  = parse_payload(&packed).unwrap();
        p.salt1    = ct.salt1;
        p.iv1      = ct.iv1;
        assert_eq!(double_decrypt(&p, KEY).unwrap(), b"pack test");
    }
    #[test] fn admin_token_verify() {
        let tok = b"admin-token-abcdef1234567890abcd";
        let h   = sha256(tok);
        assert!( verify_admin_token(&h, tok));
        assert!(!verify_admin_token(&h, b"wrong"));
    }
    #[test] fn ct_eq_32_correctness() {
        let a = [0xAAu8; 32]; let b = [0xAAu8; 32]; let c = [0xBBu8; 32];
        assert!( ct_eq_32(&a, &b));
        assert!(!ct_eq_32(&a, &c));
    }
}
