// mofold-cli/src/commands/batch_get.rs
//
// Gap 1 fix: `ziplog batch-get` — retrieve and decrypt a range of log entries
// in a single Gateway round trip (up to 50 per request, auto-chunked).
//
// Usage:
//   ziplog batch-get --project-id svc --from 100 --to 149 \
//     --read-key $RK --write-key $WK --voucher $VOUCHER
//
// Output: one decrypted line per entry to stdout; missing entries skipped with
//         a warning to stderr. Use --output-missing to emit empty lines instead.

use clap::Args;
use anyhow::{Context, Result};
use mofold_core::{
    coordinate::CoordinateDerivation,
    crypto::{double_decrypt, parse_payload},
    envelope::Envelope,
    keys::{ReadKey, WriteKey},
};
use crate::agent::GatewayClient;
use tracing::warn;

const BATCH_SIZE: usize = 50; // Gateway cap

#[derive(Args)]
pub struct BatchGetArgs {
    /// Project ID
    #[arg(long, short = 'p', env = "ZIPLOG_PROJECT_ID")]
    pub project_id: String,

    /// ReadKey hex for Gateway authorization
    #[arg(long, env = "ZIPLOG_READ_KEY")]
    pub read_key: String,

    /// WriteKey hex for decryption (WK is the encryption key material)
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,

    /// Signed voucher token
    #[arg(long, env = "ZIPLOG_VOUCHER")]
    pub voucher: String,

    /// First sequence number to retrieve (inclusive)
    #[arg(long)]
    pub from: u64,

    /// Last sequence number to retrieve (inclusive)
    #[arg(long)]
    pub to: u64,

    /// Print an empty line for each missing entry instead of skipping
    #[arg(long, default_value_t = false)]
    pub output_missing: bool,

    /// Output raw base64 blobs instead of decrypted plaintext
    #[arg(long, default_value_t = false)]
    pub raw: bool,
}

pub async fn run(args: BatchGetArgs, gateway_url: Option<String>) -> Result<()> {
    let gateway_url = gateway_url
        .ok_or_else(|| anyhow::anyhow!("--gateway URL required (or set ZIPLOG_GATEWAY_URL)"))?;

    if args.to < args.from {
        anyhow::bail!("--to ({}) must be >= --from ({})", args.to, args.from);
    }

    let rk = ReadKey::from_hex(&args.read_key).context("Parsing read key")?;
    let wk = WriteKey::from_hex(&args.write_key).context("Parsing write key")?;
    let key_material = wk.as_bytes().to_vec();

    let gateway = GatewayClient::new(&gateway_url)?;

    // Build all coordinates for the requested range
    let seqs: Vec<u64> = (args.from..=args.to).collect();
    let coords: Vec<String> = seqs.iter()
        .map(|&seq| CoordinateDerivation::log_entry(wk.as_bytes(), &args.project_id, seq).to_hex())
        .collect();

    // Process in chunks of BATCH_SIZE (Gateway cap = 50)
    let mut found  = 0usize;
    let mut missed = 0usize;

    for (chunk_coords, chunk_seqs) in coords.chunks(BATCH_SIZE).zip(seqs.chunks(BATCH_SIZE)) {
        let blobs = gateway
            .batch_get(&rk.to_hex(), &args.voucher, &chunk_coords.iter().cloned().collect::<Vec<_>>())
            .await
            .context("Gateway batch-get")?;

        for (i, maybe_blob) in blobs.into_iter().enumerate() {
            let seq = chunk_seqs[i];
            match maybe_blob {
                None => {
                    missed += 1;
                    warn!(seq, "entry not found");
                    if args.output_missing {
                        println!();
                    }
                }
                Some(raw_bytes) => {
                    found += 1;
                    if args.raw {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        println!("{}", STANDARD.encode(&raw_bytes));
                    } else {
                        let text = decrypt_blob(&raw_bytes, &key_material)
                            .with_context(|| format!("Decrypting seq={}", seq))?;
                        print!("{}", text);
                        // Ensure newline between entries if plaintext doesn't end with one
                        if !text.ends_with('\n') { println!(); }
                    }
                }
            }
        }
    }

    eprintln!(
        "batch-get: {} found, {} missing  (seq {}..={})",
        found, missed, args.from, args.to
    );
    Ok(())
}

fn decrypt_blob(raw_bytes: &[u8], key_material: &[u8]) -> Result<String> {
    let (header, payload_bytes) = Envelope::unpack(raw_bytes)
        .context("Unpacking envelope")?;
    let mut ct = parse_payload(payload_bytes).context("Parsing payload")?;
    ct.salt1   = header.salt1;
    ct.iv1     = header.iv1;
    let plaintext = double_decrypt(&ct, key_material)
        .context("Decryption failed — ensure --write-key matches encrypting agent")?;
    String::from_utf8(plaintext).context("UTF-8 decode")
}
