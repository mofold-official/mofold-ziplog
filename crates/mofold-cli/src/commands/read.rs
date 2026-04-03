// mofold-cli/src/commands/read.rs
//
// `ziplog read`     — Retrieve and decrypt a single log entry / fold from the Gateway
// `ziplog get-burn` — Retrieve-and-delete (burn-on-read) a blob, then decrypt
//
// Both require the ReadKey (RK) for Gateway authorization and the WriteKey (WK)
// for decryption (WK is the encryption key material; RK cannot decrypt).
// This is explained in the command help text.

use clap::{Args};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use mofold_core::{
    crypto::{double_decrypt, parse_payload},
    coordinate::CoordinateDerivation,
    envelope::Envelope,
    keys::{ReadKey, WriteKey},
};
use crate::agent::GatewayClient;

// ─── `ziplog read` ────────────────────────────────────────────────────────────
#[derive(Args)]
pub struct ReadArgs {
    /// Project ID (used to derive the coordinate — never sent to Gateway)
    #[arg(long, short = 'p', env = "ZIPLOG_PROJECT_ID")]
    pub project_id: String,

    /// ReadKey hex for Gateway authorization (from `ziplog init`)
    #[arg(long, env = "ZIPLOG_READ_KEY")]
    pub read_key: String,

    /// WriteKey hex for decryption (required because WK is the encryption key material)
    /// Note: RK cannot decrypt — see docs/SECURITY.md §3.3
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,

    /// Signed voucher token
    #[arg(long, env = "ZIPLOG_VOUCHER")]
    pub voucher: String,

    /// Sequence number of the log entry to retrieve
    #[arg(long, short = 's')]
    pub sequence: u64,

    /// Output raw base64 blob instead of decrypted plaintext
    #[arg(long, default_value_t = false)]
    pub raw: bool,
}

pub async fn run_read(args: ReadArgs, gateway_url: Option<String>) -> Result<()> {
    let gateway_url = gateway_url
        .ok_or_else(|| anyhow::anyhow!("--gateway URL required (or set ZIPLOG_GATEWAY_URL)"))?;

    let rk = ReadKey::from_hex(&args.read_key).context("Parsing read key")?;
    let wk = WriteKey::from_hex(&args.write_key).context("Parsing write key")?;

    let coord = CoordinateDerivation::log_entry(wk.as_bytes(), &args.project_id, args.sequence);
    let coord_hex = coord.to_hex();

    let gateway = GatewayClient::new(&gateway_url)?;
    let blob = gateway
        .get(&rk.to_hex(), &args.voucher, &coord_hex)
        .await?;

    match blob {
        None => bail!("Entry not found (project={}, seq={})", args.project_id, args.sequence),
        Some(raw_bytes) => {
            if args.raw {
                println!("{}", STANDARD.encode(&raw_bytes));
                return Ok(());
            }
            print_decrypted(&raw_bytes, wk.as_bytes())
        }
    }
}

// ─── `ziplog get-burn` ────────────────────────────────────────────────────────
#[derive(Args)]
pub struct GetBurnArgs {
    /// Project ID
    #[arg(long, short = 'p', env = "ZIPLOG_PROJECT_ID")]
    pub project_id: String,

    /// ReadKey hex for Gateway authorization
    #[arg(long, env = "ZIPLOG_READ_KEY")]
    pub read_key: String,

    /// WriteKey hex for decryption
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,

    /// Signed voucher token
    #[arg(long, env = "ZIPLOG_VOUCHER")]
    pub voucher: String,

    /// Sequence number of the entry to retrieve-and-delete
    #[arg(long, short = 's')]
    pub sequence: u64,

    /// Output raw base64 blob instead of decrypted plaintext
    #[arg(long, default_value_t = false)]
    pub raw: bool,
}

pub async fn run_get_burn(args: GetBurnArgs, gateway_url: Option<String>) -> Result<()> {
    let gateway_url = gateway_url
        .ok_or_else(|| anyhow::anyhow!("--gateway URL required"))?;

    let rk = ReadKey::from_hex(&args.read_key).context("Parsing read key")?;
    let wk = WriteKey::from_hex(&args.write_key).context("Parsing write key")?;

    let coord = CoordinateDerivation::log_entry(wk.as_bytes(), &args.project_id, args.sequence);
    let coord_hex = coord.to_hex();

    let gateway = GatewayClient::new(&gateway_url)?;
    let blob = gateway
        .get_burn(&rk.to_hex(), &args.voucher, &coord_hex)
        .await?;

    match blob {
        None => bail!("Entry not found or already consumed (project={}, seq={})",
                      args.project_id, args.sequence),
        Some(raw_bytes) => {
            if args.raw {
                println!("{}", STANDARD.encode(&raw_bytes));
                return Ok(());
            }
            print_decrypted(&raw_bytes, wk.as_bytes())
        }
    }
}

// ─── Shared: decrypt blob and print plaintext ─────────────────────────────────
fn print_decrypted(raw_bytes: &[u8], key_material: &[u8]) -> Result<()> {
    let (header, payload_bytes) = Envelope::unpack(raw_bytes)
        .context("Unpacking BDP envelope")?;
    let mut ct = parse_payload(payload_bytes)
        .context("Parsing encrypted payload")?;
    ct.salt1 = header.salt1;
    ct.iv1   = header.iv1;
    let plaintext = double_decrypt(&ct, key_material)
        .context("Decrypting blob — ensure --write-key matches the encrypting agent")?;
    let text = String::from_utf8(plaintext)
        .context("UTF-8 decode of plaintext")?;
    print!("{}", text);
    Ok(())
}
