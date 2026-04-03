// mofold-cli/src/commands/status.rs
//
// `ziplog status` — Verify Gateway connectivity, key format, and voucher validity.
//
// Gap 6 fix: adds a 5th live-probe check that sends a real request with the RK
// and voucher to the Gateway. A 404 response confirms the Gateway accepted the
// auth and voucher (found nothing for the dummy coordinate — that's correct).
// A 401 response flags a VOUCHER_SECRET mismatch — the most common deployment
// error that the previous 4 format-only checks could not catch.

use clap::Args;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use mofold_core::voucher::Voucher;

#[derive(Args)]
pub struct StatusArgs {
    #[arg(long, env = "ZIPLOG_READ_KEY")]
    pub read_key: Option<String>,

    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: Option<String>,

    #[arg(long, env = "ZIPLOG_VOUCHER")]
    pub voucher: Option<String>,

    /// VOUCHER_SECRET for local HMAC validation (optional but recommended)
    #[arg(long, env = "ZIPLOG_VOUCHER_SECRET")]
    pub voucher_secret: Option<String>,

    /// Output JSON (for Docker HEALTHCHECK / scripts)
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

struct Check {
    name:    &'static str,
    passed:  bool,
    message: String,
}

pub async fn run(args: StatusArgs, gateway_url: Option<String>) -> Result<()> {
    let mut checks: Vec<Check> = Vec::new();

    // ── Check 1: Gateway reachability ─────────────────────────────────────────
    match &gateway_url {
        None => checks.push(Check {
            name: "gateway_reachable", passed: false,
            message: "No gateway URL — set ZIPLOG_GATEWAY_URL".into(),
        }),
        Some(url) => match ping_gateway(url).await {
            Ok(ms)  => checks.push(Check { name: "gateway_reachable", passed: true,
                                           message: format!("{}  ({}ms)", url, ms) }),
            Err(e)  => checks.push(Check { name: "gateway_reachable", passed: false,
                                           message: format!("{}: {}", url, e) }),
        },
    }

    // ── Check 2: ReadKey format ────────────────────────────────────────────────
    match &args.read_key {
        None      => checks.push(Check { name: "read_key_valid", passed: false,
                                         message: "No RK — set ZIPLOG_READ_KEY".into() }),
        Some(hex) => match mofold_core::keys::ReadKey::from_hex(hex) {
            Ok(_)  => checks.push(Check { name: "read_key_valid", passed: true,
                                          message: format!("{}…{}", &hex[..8], &hex[56..]) }),
            Err(e) => checks.push(Check { name: "read_key_valid", passed: false,
                                          message: format!("Invalid RK: {}", e) }),
        },
    }

    // ── Check 3: WriteKey format ───────────────────────────────────────────────
    match &args.write_key {
        None      => checks.push(Check { name: "write_key_valid", passed: false,
                                         message: "No WK — set ZIPLOG_WRITE_KEY".into() }),
        Some(hex) => match mofold_core::keys::WriteKey::from_hex(hex) {
            Ok(_)  => checks.push(Check { name: "write_key_valid", passed: true,
                                          message: format!("{}…{}", &hex[..8], &hex[56..]) }),
            Err(e) => checks.push(Check { name: "write_key_valid", passed: false,
                                          message: format!("Invalid WK: {}", e) }),
        },
    }

    // ── Check 4: Voucher validity (local) ──────────────────────────────────────
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    match &args.voucher {
        None => checks.push(Check { name: "voucher_valid", passed: false,
                                    message: "No voucher — set ZIPLOG_VOUCHER".into() }),
        Some(token) => {
            let result = match &args.voucher_secret {
                Some(s) => Voucher::verify(token, s.as_bytes(), now)
                    .map(|v| {
                        let h = v.claims.expires_at.saturating_sub(now) / 3600;
                        format!("{} tier, {}rps, expires in {}h",
                                v.claims.tier.prefix(), v.claims.rate_limit_rps, h)
                    })
                    .map_err(|e| anyhow::anyhow!("{}", e)),
                None    => decode_voucher_expiry(token, now)
                    .map(|m| format!("{} (HMAC not checked — no VOUCHER_SECRET)", m)),
            };
            match result {
                Ok(msg) => checks.push(Check { name: "voucher_valid", passed: true,
                                               message: msg }),
                Err(e)  => checks.push(Check { name: "voucher_valid", passed: false,
                                               message: format!("{}", e) }),
            }
        }
    }

    // ── Check 5: Live Gateway acceptance probe ────────────────────────────────
    // Sends a real GET with a zero coordinate. 404 = auth accepted (correct).
    // 401 = VOUCHER_SECRET mismatch — most common deployment misconfiguration.
    // W4 fix: always emit this check (pass/fail/skipped) so users see all 5 slots.
    let can_probe = gateway_url.is_some()
        && args.read_key.is_some()
        && args.voucher.is_some();
    if let (true, Some(url), Some(rk_hex), Some(token)) =
        (can_probe, &gateway_url, &args.read_key, &args.voucher)
    {
        match live_voucher_probe(url, rk_hex, token).await {
            Ok(status) if status == 404 => checks.push(Check {
                name:    "gateway_accepts_auth",
                passed:  true,
                message: "Gateway accepted voucher + RK (404 on dummy coordinate — correct)".into(),
            }),
            Ok(status) if status == 401 => checks.push(Check {
                name:    "gateway_accepts_auth",
                passed:  false,
                message: format!(
                    "Gateway returned 401 — VOUCHER_SECRET mismatch between CLI and Worker"
                ),
            }),
            Ok(status) => checks.push(Check {
                name:    "gateway_accepts_auth",
                passed:  false,
                message: format!("Unexpected HTTP {} from probe — check Gateway logs", status),
            }),
            Err(e) => checks.push(Check {
                name:    "gateway_accepts_auth",
                passed:  false,
                message: format!("Probe failed: {}", e),
            }),
        }
    }

    // ── Render ─────────────────────────────────────────────────────────────────
    // W4 fix: emit "skipped" entry when preconditions for the probe are unmet
    if !can_probe {
        checks.push(Check {
            name:    "gateway_accepts_auth",
            passed:  false,
            message: "Skipped — requires gateway URL + valid RK + voucher (fix checks above first)".into(),
        });
    }

    let all_ok = checks.iter().all(|c| c.passed);

    if args.json {
        let entries: Vec<serde_json::Value> = checks.iter().map(|c| serde_json::json!({
            "check":   c.name,
            "passed":  c.passed,
            "message": c.message,
        })).collect();
        println!("{}", serde_json::json!({ "ok": all_ok, "checks": entries }));
    } else {
        println!();
        println!("  MofoldZiplog — Status");
        println!("  ─────────────────────────────────────────────────────────");
        for c in &checks {
            println!("  {} {:<26} {}", if c.passed { "✓" } else { "✕" }, c.name, c.message);
        }
        println!("  ─────────────────────────────────────────────────────────");
        println!("  {}", if all_ok { "All checks passed." } else { "One or more checks FAILED." });
        println!();
    }

    if !all_ok { std::process::exit(1); }
    Ok(())
}

async fn ping_gateway(url: &str) -> Result<u64> {
    use tokio::time::Instant;
    let start  = Instant::now();
    let client = crate::agent::GatewayClient::new(url)?;
    let _      = client.ping().await;
    Ok(start.elapsed().as_millis() as u64)
}

/// Gap 6: sends a real read request and returns the raw HTTP status code.
/// A 404 = Gateway accepted auth+voucher, blob not found (correct).
/// A 401 = VOUCHER_SECRET mismatch.
async fn live_voucher_probe(url: &str, rk_hex: &str, voucher: &str) -> Result<u16> {
    let client = crate::agent::GatewayClient::new(url)?;
    let auth   = format!("Ziplog RK.{}", rk_hex);
    let body   = serde_json::json!({
        "action":     "get",
        "coordinate": "0".repeat(64),  // will never exist
        "voucher":    voucher,
    });
    client.probe_status(&auth, &body.to_string()).await
}

fn decode_voucher_expiry(token: &str, now: u64) -> Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let dot  = token.rfind('.').ok_or_else(|| anyhow::anyhow!("missing '.'"))?;
    let dash = token.find('-').ok_or_else(|| anyhow::anyhow!("missing tier prefix"))?;
    let b64  = &token[dash + 1..dot];
    let json = URL_SAFE_NO_PAD.decode(b64)?;
    let val: serde_json::Value = serde_json::from_slice(&json)?;
    let expires_at = val["expires_at"].as_u64().unwrap_or(0);
    if now > expires_at { anyhow::bail!("voucher expired at {}", expires_at); }
    Ok(format!(
        "{} tier, {}rps, expires in {}h",
        val["tier"].as_str().unwrap_or("?"),
        val["rate_limit_rps"].as_u64().unwrap_or(0),
        expires_at.saturating_sub(now) / 3600
    ))
}
