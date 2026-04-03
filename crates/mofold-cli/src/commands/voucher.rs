// mofold-cli/src/commands/voucher.rs
//
// `ziplog voucher` — Issue a signed voucher token.
//
// Vouchers are HMAC-signed claims that tell the Gateway:
//   • which tier (FREE / PAID) the caller is on
//   • the rate limit and storage quota
//   • the expiry time
//
// The Gateway verifies the HMAC using VOUCHER_SECRET (a shared server secret)
// without hitting any database — fully stateless verification.

use clap::Args;
use anyhow::{bail, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use mofold_core::voucher::{Voucher, VoucherClaims, VoucherTier};

#[derive(Args)]
pub struct VoucherArgs {
    /// Voucher tier: free or paid
    #[arg(long, value_parser = parse_tier)]
    pub tier: VoucherTier,

    /// Opaque voucher identifier (UUID recommended)
    #[arg(long, default_value = "")]
    pub voucher_id: String,

    /// Validity duration in hours (FREE max 720, PAID max 8760)
    #[arg(long, default_value_t = 168)]
    pub valid_hours: u64,

    /// Storage quota in MB (0 = unlimited for PAID; max 50 for FREE)
    #[arg(long, default_value_t = 0)]
    pub quota_mb: u64,

    /// Rate limit in requests per second (FREE max 5, PAID max 500)
    #[arg(long, default_value_t = 0)]
    pub rps: u32,

    /// Server secret used to sign the voucher (must match Gateway VOUCHER_SECRET)
    #[arg(long, env = "ZIPLOG_VOUCHER_SECRET")]
    pub server_secret: String,
}

fn parse_tier(s: &str) -> Result<VoucherTier, String> {
    match s.to_lowercase().as_str() {
        "free" => Ok(VoucherTier::Free),
        "paid" => Ok(VoucherTier::Paid),
        other  => Err(format!("Unknown tier '{}'; use 'free' or 'paid'", other)),
    }
}

pub async fn run(args: VoucherArgs) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Apply tier defaults if not specified
    let (quota_bytes, rps) = match args.tier {
        VoucherTier::Free => {
            let q = if args.quota_mb == 0 { 10 * 1024 * 1024 } else { args.quota_mb * 1024 * 1024 };
            let r = if args.rps == 0 { 5 } else { args.rps };
            if q > 50 * 1024 * 1024 { bail!("FREE tier quota max is 50 MB"); }
            if r > 5              { bail!("FREE tier RPS max is 5");       }
            (q, r)
        }
        VoucherTier::Paid => {
            let q = args.quota_mb * 1024 * 1024; // 0 = unlimited
            let r = if args.rps == 0 { 500 } else { args.rps };
            if r > 500 { bail!("PAID tier RPS max is 500"); }
            (q, r)
        }
    };

    let max_hours = match args.tier {
        VoucherTier::Free => 720u64,
        VoucherTier::Paid => 8760u64,
    };
    if args.valid_hours > max_hours {
        bail!("Validity exceeds tier maximum of {} hours", max_hours);
    }

    let voucher_id = if args.voucher_id.is_empty() {
        // Generate a pseudo-random ID using ring
        let rng = ring::rand::SystemRandom::new();
        let mut raw = [0u8; 16];
        ring::rand::SecureRandom::fill(&rng, &mut raw)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        hex::encode(raw)
    } else {
        args.voucher_id.clone()
    };

    let claims = VoucherClaims {
        voucher_id:     voucher_id.clone(),
        tier:           args.tier,
        issued_at:      now,
        expires_at:     now + args.valid_hours * 3600,
        quota_bytes,
        rate_limit_rps: rps,
    };

    let voucher = Voucher::issue(claims, args.server_secret.as_bytes())?;

    let tier_label = match args.tier {
        VoucherTier::Free => "FREE",
        VoucherTier::Paid => "PAID",
    };

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           MofoldZiplog — Voucher Issued                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Voucher ID   : {}", voucher_id);
    println!("  Tier         : {}", tier_label);
    println!("  Quota        : {} MB", if quota_bytes == 0 { "unlimited".to_string() } else { (quota_bytes / 1024 / 1024).to_string() });
    println!("  Rate limit   : {} req/sec", rps);
    println!("  Valid for    : {} hours", args.valid_hours);
    println!();
    println!("  ┌─ TOKEN (set as ZIPLOG_VOUCHER in agent env) ───────────────");
    println!("  │");
    // Print token in chunks for readability
    let token = &voucher.token;
    for chunk in token.as_bytes().chunks(72) {
        println!("  │  {}", std::str::from_utf8(chunk).unwrap());
    }
    println!("  │");
    println!("  └────────────────────────────────────────────────────────────");
    println!();
    println!("  Usage:  export ZIPLOG_VOUCHER=\"{}\"", &token[..20]);
    println!("          (truncated above — use full token)");
    println!();

    Ok(())
}
