// mofold-cli/src/commands/decrypt.rs
//
// `ziplog decrypt` — Decrypt a base64-encoded BDP blob back to plaintext.
//
// F2 fix: clarifies why WK is required (it is the encryption key material,
//         not an authorization key). The help text explains the distinction
//         so readers who have only RK understand what to do.

use clap::Args;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::Read;
use mofold_core::{
    crypto::{double_decrypt, parse_payload},
    envelope::Envelope,
    keys::WriteKey,
};

#[derive(Args)]
pub struct DecryptArgs {
    /// Base64-encoded BDP blob to decrypt.
    /// Omit (or use '-') to read from stdin.
    #[arg(long, short = 'b')]
    pub blob: Option<String>,

    /// WriteKey hex (the ENCRYPTION key — not the ReadKey).
    ///
    /// MofoldZiplog uses the WriteKey as encryption key material so that
    /// read-path agents (dashboards) holding only the ReadKey cannot decrypt
    /// stored logs. Offline decryption always requires the WriteKey.
    ///
    /// To decrypt on a read-only machine: pipe the blob via a WK-holding
    /// host: ssh agent-host "ziplog decrypt --blob <blob>"
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,
}

pub async fn run(args: DecryptArgs) -> Result<()> {
    let wk = WriteKey::from_hex(&args.write_key).context("Parsing write key")?;
    let key_material = wk.as_bytes().to_vec();

    // Read blob: from --blob, from --blob -, or from stdin
    let blob_b64 = match args.blob.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Reading blob from stdin")?;
            buf.trim().to_string()
        }
        Some(b) => b.trim().to_string(),
    };

    let raw = STANDARD.decode(&blob_b64).context("Decoding base64 blob")?;
    let (header, payload_bytes) = Envelope::unpack(&raw).context("Unpacking envelope")?;

    let mut ct = parse_payload(payload_bytes).context("Parsing payload")?;
    ct.salt1   = header.salt1;
    ct.iv1     = header.iv1;

    let plaintext = double_decrypt(&ct, &key_material)
        .context("Decryption failed — ensure --write-key matches the encrypting agent's WK")?;
    let text = String::from_utf8(plaintext).context("UTF-8 decode")?;
    print!("{}", text);
    Ok(())
}
