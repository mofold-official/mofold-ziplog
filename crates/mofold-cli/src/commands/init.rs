// mofold-cli/src/commands/init.rs
//
// `ziplog init` — Generate a new Project Master Key hierarchy.
//
// Outputs:
//   .ziplog-pmk          — AES-256-GCM encrypted PMK file (safe to store)
//   stdout               — ReadKey hex  (deploy to dashboards / read agents)
//   stdout               — WriteKey hex (deploy to log-shipping agents)
//
// The PMK itself is NEVER printed. It is stored only in the encrypted file.

use clap::Args;
use anyhow::Result;
use mofold_core::keys::KeyHierarchy;
use crate::pmk::{generate_pmk, save_pmk};

#[derive(Args)]
pub struct InitArgs {
    /// Human-readable project identifier (used in coordinate derivation)
    #[arg(long, short = 'p')]
    pub project_id: String,

    /// Passphrase to encrypt the PMK file with (min 16 chars recommended)
    #[arg(long, short = 'k', env = "ZIPLOG_PMK_PASSPHRASE")]
    pub passphrase: String,

    /// Output path for the encrypted PMK file
    #[arg(long, default_value = ".ziplog-pmk")]
    pub pmk_file: std::path::PathBuf,
}

pub async fn run(args: InitArgs) -> Result<()> {
    // Generate fresh PMK
    let pmk = generate_pmk()?;

    // Derive key hierarchy
    let hierarchy = KeyHierarchy::from_pmk(&pmk);
    let rk_hex = hierarchy.read_key.to_hex();
    let wk_hex = hierarchy.write_key.to_hex();

    // Save encrypted PMK file
    save_pmk(&pmk, &args.passphrase, &args.pmk_file)?;

    // Output key material to stdout
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           MofoldZiplog — Project Initialised                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Project ID  : {}", args.project_id);
    println!("  PMK File    : {}", args.pmk_file.display());
    println!();
    println!("  ┌─ READ KEY (RK) — deploy on dashboards / readers ──────────");
    println!("  │  {}", rk_hex);
    println!("  └────────────────────────────────────────────────────────────");
    println!();
    println!("  ┌─ WRITE KEY (WK) — deploy on log-shipping agents ──────────");
    println!("  │  {}", wk_hex);
    println!("  └────────────────────────────────────────────────────────────");
    println!();
    println!("  ⚠  The PMK is stored encrypted at: {}", args.pmk_file.display());
    println!("     Keep the passphrase offline. If lost, all keys are unrecoverable.");
    println!();
    println!("  Next steps:");
    println!("    1. Set ZIPLOG_WRITE_KEY={} in your log-shipping environment", &wk_hex[..16]);
    println!("       (truncated above for display — use the full hex)");
    println!("    2. Set ZIPLOG_READ_KEY in your dashboard environment");
    println!("    3. Deploy the Gateway Worker:");
    println!("         wrangler secret put PEPPER          # openssl rand -hex 32");
    println!("         wrangler secret put VOUCHER_SECRET  # shared with `ziplog voucher`");
    println!("         wrangler secret put ALLOWED_ORIGIN  # your app domain");
    println!("    4. Issue a voucher: ziplog voucher --tier free --project-id {}", args.project_id);
    println!();

    Ok(())
}
