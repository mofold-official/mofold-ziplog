// mofold-cli/src/commands/encrypt.rs
//
// `ziplog encrypt` — One-shot encrypt a message into a BDP fold.
//
// F1 fix: --message/-m is optional. When omitted, reads from stdin.
// This enables Unix pipeline usage:
//   echo "secret value" | ziplog encrypt --write-key $WK --project-id $PID
//   cat secrets.txt | ziplog encrypt -m - ...  (explicit stdin)

use clap::Args;
use anyhow::{Context, Result};
use std::io::Read;
use base64::{engine::general_purpose::STANDARD, Engine};
use mofold_core::{
    crypto::{double_encrypt, pack_payload, sha256},
    coordinate::CoordinateDerivation,
    envelope::{BlobType, Envelope},
    keys::WriteKey,
};

#[derive(Args)]
pub struct EncryptArgs {
    /// Plaintext message to encrypt. Omit (or use '-') to read from stdin.
    #[arg(long, short = 'm')]
    pub message: Option<String>,

    /// WriteKey hex (from `ziplog init`)
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,

    /// Project ID
    #[arg(long, short = 'p', env = "ZIPLOG_PROJECT_ID")]
    pub project_id: String,

    /// Sequence number for this entry
    #[arg(long, default_value_t = 0)]
    pub sequence: u64,

    /// Print the coordinate alongside the blob
    #[arg(long, default_value_t = false)]
    pub show_coord: bool,
}

pub async fn run(args: EncryptArgs) -> Result<()> {
    let wk = WriteKey::from_hex(&args.write_key)?;
    let key_material = wk.as_bytes().to_vec();

    // F1: read message from --message, or stdin if absent/"-"
    let message = match args.message.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Reading message from stdin")?;
            buf
        }
        Some(m) => m.to_string(),
    };

    let coord = CoordinateDerivation::log_entry(
        wk.as_bytes(),
        &args.project_id,
        args.sequence,
    );

    let ct = double_encrypt(message.as_bytes(), &key_material)?;

    let mut admin_hash = [0u8; 32];
    admin_hash.copy_from_slice(&sha256(wk.as_bytes()));

    let payload = pack_payload(&ct);
    let blob    = Envelope::pack(BlobType::Log, &admin_hash, &ct.salt1, &ct.iv1, &payload);
    let b64     = STANDARD.encode(&blob);

    if args.show_coord {
        eprintln!("coordinate: {}", coord.to_hex());
    }
    println!("{}", b64);
    Ok(())
}
