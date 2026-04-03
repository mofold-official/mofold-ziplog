// mofold-cli/src/pmk.rs — PMK lifecycle (Argon2id via ring PBKDF2)
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, OpeningKey, UnboundKey, AES_256_GCM},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
    error::Unspecified,
};
use zeroize::Zeroizing;
use mofold_core::keys::ProjectMasterKey;

const MAGIC: &[u8; 8] = b"ZIPLOGPM";
const PBKDF2_ITERS: u32 = 600_000;

struct OneShot([u8; 12]);
impl NonceSequence for OneShot {
    fn advance(&mut self) -> std::result::Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

pub fn generate_pmk() -> Result<ProjectMasterKey> {
    let rng = SystemRandom::new();
    let mut raw = [0u8; 32];
    rng.fill(&mut raw).map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(ProjectMasterKey::from_bytes(raw))
}

pub fn save_pmk(pmk: &ProjectMasterKey, passphrase: &str, path: &Path) -> Result<()> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16]; let mut iv = [0u8; 12];
    rng.fill(&mut salt).map_err(|_| anyhow::anyhow!("RNG"))?;
    rng.fill(&mut iv).map_err(|_| anyhow::anyhow!("RNG"))?;

    let wrap_key = pbkdf2_key(passphrase, &salt)?;
    let unbound  = UnboundKey::new(&AES_256_GCM, wrap_key.as_ref())
        .map_err(|_| anyhow::anyhow!("AES key init"))?;
    let mut sealing = SealingKey::new(unbound, OneShot(iv));
    let mut plaintext = pmk.as_bytes().to_vec();
    sealing.seal_in_place_append_tag(Aad::empty(), &mut plaintext)
        .map_err(|_| anyhow::anyhow!("GCM seal"))?;

    let mut out = Vec::with_capacity(8 + 16 + 12 + plaintext.len());
    out.extend_from_slice(MAGIC); out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);   out.extend_from_slice(&plaintext);
    std::fs::write(path, &out).with_context(|| format!("Writing PMK to {}", path.display()))
}

pub fn load_pmk(passphrase: &str, path: &Path) -> Result<ProjectMasterKey> {
    let data = std::fs::read(path)
        .with_context(|| format!("Reading PMK from {}", path.display()))?;
    if data.len() < 8 + 16 + 12 + 32 + 16 { bail!("PMK file too small"); }
    if &data[..8] != MAGIC { bail!("Not a valid PMK file"); }

    let salt: [u8; 16] = data[8..24].try_into().unwrap();
    let iv:   [u8; 12] = data[24..36].try_into().unwrap();
    let mut ct = data[36..].to_vec();

    let wrap_key = pbkdf2_key(passphrase, &salt)?;
    let unbound  = UnboundKey::new(&AES_256_GCM, wrap_key.as_ref())
        .map_err(|_| anyhow::anyhow!("AES key init"))?;
    let mut opening = OpeningKey::new(unbound, OneShot(iv));
    let plain = opening.open_in_place(Aad::empty(), &mut ct)
        .map_err(|_| anyhow::anyhow!("PMK decryption failed — wrong passphrase?"))?;

    let mut raw = [0u8; 32];
    raw.copy_from_slice(plain);
    Ok(ProjectMasterKey::from_bytes(raw))
}

pub fn default_pmk_path() -> PathBuf { PathBuf::from(".ziplog-pmk") }

fn pbkdf2_key(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let iters = std::num::NonZeroU32::new(PBKDF2_ITERS).unwrap();
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, passphrase.as_bytes(), key.as_mut());
    Ok(key)
}
