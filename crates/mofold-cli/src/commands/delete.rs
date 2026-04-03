// mofold-cli/src/commands/delete.rs
//
// `ziplog delete` — Delete a stored blob from the Gateway.
//
// Requires:
//   • WriteKey (WK) for Gateway authorization
//   • The admin token embedded in the blob's envelope header must match
//     SHA-256(WK_bytes) — since ziplog agents set admin_hash = SHA-256(WK),
//     the WK acts as the admin token.

use clap::Args;
use anyhow::{Context, Result};
use mofold_core::{
    coordinate::CoordinateDerivation,
    keys::WriteKey,
};
use crate::agent::GatewayClient;

#[derive(Args)]
pub struct DeleteArgs {
    /// Project ID
    #[arg(long, short = 'p', env = "ZIPLOG_PROJECT_ID")]
    pub project_id: String,

    /// WriteKey hex — used for both Gateway authorization and as the admin token
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,

    /// Signed voucher token
    #[arg(long, env = "ZIPLOG_VOUCHER")]
    pub voucher: String,

    /// Sequence number of the entry to delete
    #[arg(long, short = 's')]
    pub sequence: u64,

    /// Skip confirmation prompt
    #[arg(long, short = 'y', default_value_t = false)]
    pub yes: bool,
}

pub async fn run(args: DeleteArgs, gateway_url: Option<String>) -> Result<()> {
    let gateway_url = gateway_url
        .ok_or_else(|| anyhow::anyhow!("--gateway URL required (or set ZIPLOG_GATEWAY_URL)"))?;

    let wk = WriteKey::from_hex(&args.write_key).context("Parsing write key")?;

    // Derive coordinate
    let coord     = CoordinateDerivation::log_entry(wk.as_bytes(), &args.project_id, args.sequence);
    let coord_hex = coord.to_hex();

    // The admin token is the WK itself (as hex) — the Gateway computes SHA-256(token)
    // and compares against the admin_hash stored in the blob envelope header.
    // Since agents write admin_hash = SHA-256(WK_bytes), only the WK holder can delete.
    let admin_token_hex = hex::encode(wk.as_bytes());

    // Confirmation prompt (unless -y)
    if !args.yes {
        eprint!(
            "Delete entry (project={}, seq={})? [y/N] ",
            args.project_id, args.sequence
        );
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let gateway = GatewayClient::new(&gateway_url)?;
    gateway
        .delete(&wk.to_hex(), &args.voucher, &coord_hex, &admin_token_hex)
        .await
        .context("Gateway delete")?;

    eprintln!("Deleted: project={} seq={}", args.project_id, args.sequence);
    Ok(())
}
