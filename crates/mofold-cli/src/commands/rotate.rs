// mofold-cli/src/commands/rotate.rs
//
// `ziplog rotate` — Load an existing encrypted PMK file and re-print the
//                   key hierarchy (RK + WK). This is the primary use case
//                   for load_pmk(): recovering keys from the .ziplog-pmk
//                   file when environment variables have been lost.
//
// Also useful for:
//   • Onboarding a new agent machine (paste WK into env)
//   • Rotating to a new vault passphrase (re-encrypt PMK file)
//   • CI/CD bootstrap scripts

use clap::Args;
use anyhow::{Context, Result};
use std::path::PathBuf;
use mofold_core::keys::KeyHierarchy;
use crate::pmk::{default_pmk_path, load_pmk, save_pmk};

#[derive(Args)]
pub struct RotateArgs {
    /// Path to the existing encrypted PMK file
    #[arg(long, default_value = ".ziplog-pmk")]
    pub pmk_file: PathBuf,

    /// Current passphrase to decrypt the PMK file
    #[arg(long, env = "ZIPLOG_PMK_PASSPHRASE")]
    pub passphrase: String,

    /// If set, re-encrypt the PMK file with this new passphrase
    #[arg(long)]
    pub new_passphrase: Option<String>,

    /// Output path for re-encrypted PMK (defaults to overwriting --pmk-file)
    #[arg(long)]
    pub output: Option<PathBuf>,
}

pub async fn run(args: RotateArgs) -> Result<()> {
    // Use default_pmk_path() as the canonical default file name
    let pmk_file = if args.pmk_file == std::path::PathBuf::from(".ziplog-pmk") {
        default_pmk_path()
    } else {
        args.pmk_file.clone()
    };
    // C1 fix: load_pmk() is now called here
    let pmk = load_pmk(&args.passphrase, &pmk_file)
        .with_context(|| format!(
            "Failed to decrypt PMK file: {}\nCheck --passphrase or ZIPLOG_PMK_PASSPHRASE",
            pmk_file.display()
        ))?;

    let hierarchy = KeyHierarchy::from_pmk(&pmk);
    let rk_hex   = hierarchy.read_key.to_hex();
    let wk_hex   = hierarchy.write_key.to_hex();

    // If new passphrase supplied, re-encrypt
    if let Some(ref new_pass) = args.new_passphrase {
        let out_path = args.output.as_ref().unwrap_or(&pmk_file);
        save_pmk(&pmk, new_pass, out_path)
            .with_context(|| format!("Re-encrypting PMK to {}", out_path.display()))?;
        eprintln!("PMK re-encrypted → {}", out_path.display());
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           MofoldZiplog — Key Hierarchy Recovered            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  PMK File  : {}", pmk_file.display());
    println!();
    println!("  ┌─ READ KEY (RK) — deploy on dashboards / readers ──────────");
    println!("  │  {}", rk_hex);
    println!("  └────────────────────────────────────────────────────────────");
    println!();
    println!("  ┌─ WRITE KEY (WK) — deploy on log-shipping agents ──────────");
    println!("  │  {}", wk_hex);
    println!("  └────────────────────────────────────────────────────────────");
    println!();
    if args.new_passphrase.is_none() {
        println!("  Tip: use --new-passphrase to re-encrypt the PMK file");
    }
    println!();
    println!("  ⚠  The Project ID is NOT stored in the PMK file.");
    println!("     You must record it separately — it is required to derive");
    println!("     log-entry coordinates (used by `ziplog tail`, `read`, `batch-get`).");
    println!("     Example: store it in an env file alongside ZIPLOG_WRITE_KEY.");
    println!();

    Ok(())
}
