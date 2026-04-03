// mofold-cli/src/commands/tail.rs
//
// Gap 2 fix: whole batch shipped as one batch-put round trip (was N serial PUTs).
// Gap 7 fix: log-rotation detection — position-vs-file-length check; reopen on truncation.
// B3 (prior): graceful SIGTERM/Ctrl-C shutdown retained.

use clap::Args;
use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use base64::{engine::general_purpose::STANDARD, Engine};
use mofold_core::{
    crypto::{double_encrypt, pack_payload, sha256},
    coordinate::CoordinateDerivation,
    envelope::{BlobType, Envelope},
    keys::WriteKey,
};
use crate::agent::GatewayClient;

const BATCH_MAX:        usize = 50;   // matches Gateway cap
const BATCH_TIMEOUT_MS: u64  = 200;
const POLL_INTERVAL_MS: u64  = 100;
const RETRY_BACKOFF_MS: u64  = 2_000;
const SEQ_FILE_SUFFIX:  &str = ".ziplog-seq";

#[derive(Args)]
pub struct TailArgs {
    /// Path to the log file to tail
    #[arg(long, short = 'f')]
    pub file: PathBuf,

    /// Project ID (used in coordinate derivation — never sent to Gateway)
    #[arg(long, short = 'p', env = "ZIPLOG_PROJECT_ID")]
    pub project_id: String,

    /// WriteKey hex string (from `ziplog init`)
    #[arg(long, env = "ZIPLOG_WRITE_KEY")]
    pub write_key: String,

    /// Signed voucher token (from `ziplog voucher`)
    #[arg(long, env = "ZIPLOG_VOUCHER")]
    pub voucher: String,

    /// Maximum number of retries on Gateway error (0 = infinite)
    #[arg(long, default_value_t = 0)]
    pub max_retries: u32,
}

pub async fn run(args: TailArgs, gateway_url: Option<String>) -> Result<()> {
    let gateway_url = gateway_url
        .ok_or_else(|| anyhow::anyhow!("--gateway URL required for tail command"))?;

    let wk           = WriteKey::from_hex(&args.write_key).context("Parsing write key")?;
    let wk_hex       = wk.to_hex();
    let key_material = wk.as_bytes().to_vec();

    let gateway  = GatewayClient::new(&gateway_url)?;
    let seq_path = seq_file_path(&args.file);
    let mut sequence = load_sequence(&seq_path);

    info!(file = %args.file.display(), project = %args.project_id, seq = sequence, "Starting tail");

    let mut reader = open_and_seek_to_end(&args.file)?;

    // Graceful shutdown flag (Ctrl-C + SIGTERM)
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sd2      = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = async {
                #[cfg(unix)] {
                    use tokio::signal::unix::{signal, SignalKind};
                    if let Ok(mut s) = signal(SignalKind::terminate()) { s.recv().await; }
                    else { std::future::pending::<()>().await; }
                }
                #[cfg(not(unix))] std::future::pending::<()>().await
            } => {}
        }
        warn!("Shutdown signal — draining and exiting");
        sd2.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let mut retries   = 0u32;
    let mut admin_hash = [0u8; 32];
    admin_hash.copy_from_slice(&sha256(wk.as_bytes()));

    'outer: loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) { break 'outer; }

        let mut batch: Vec<(u64, String)> = Vec::with_capacity(BATCH_MAX);
        let deadline = std::time::Instant::now() + Duration::from_millis(BATCH_TIMEOUT_MS);

        loop {
            if shutdown.load(std::sync::atomic::Ordering::SeqCst) && batch.is_empty() {
                break 'outer;
            }

            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // Gap 7: detect log rotation (truncation / file replacement)
                    let current_pos = reader.stream_position().unwrap_or(0);
                    let file_len    = std::fs::metadata(&args.file)
                        .map(|m| m.len())
                        .unwrap_or(current_pos);

                    if current_pos > file_len {
                        // File was truncated (e.g. logrotate copytruncate)
                        warn!(
                            pos = current_pos,
                            len = file_len,
                            "Log file truncated — reopening from start"
                        );
                        reader = reopen_from_start(&args.file)?;
                        continue;
                    }

                    if !batch.is_empty() && std::time::Instant::now() >= deadline { break; }
                    if shutdown.load(std::sync::atomic::Ordering::SeqCst) && batch.is_empty() {
                        break 'outer;
                    }
                    sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
                }
                Ok(_) => {
                    let trimmed = line.trim_end().to_string();
                    if !trimmed.is_empty() {
                        batch.push((sequence, trimmed));
                        sequence += 1;
                    }
                    if batch.len() >= BATCH_MAX { break; }
                }
                Err(e) => {
                    warn!("Read error: {}", e);
                    sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
                }
            }
        }

        if batch.is_empty() { continue; }

        // Encrypt all lines — any failure aborts the whole batch so no sequence
        // numbers are silently dropped. The batch vec is retained for retry.
        let mut entries: Vec<(String, String, Option<String>)> = Vec::with_capacity(batch.len());
        let mut encrypt_ok = true;
        for (seq, line) in &batch {
            match double_encrypt(line.as_bytes(), &key_material) {
                Ok(ct) => {
                    let coord    = CoordinateDerivation::log_entry(wk.as_bytes(), &args.project_id, *seq);
                    let payload  = pack_payload(&ct);
                    let blob     = Envelope::pack(BlobType::Log, &admin_hash, &ct.salt1, &ct.iv1, &payload);
                    entries.push((coord.to_hex(), STANDARD.encode(&blob), None));
                    debug!(seq, "encrypted");
                }
                Err(e) => {
                    error!(seq, "Encrypt failed — aborting batch for retry: {}", e);
                    encrypt_ok = false;
                    break;
                }
            }
        }

        if !encrypt_ok {
            retries += 1;
            if args.max_retries > 0 && retries >= args.max_retries {
                bail!("Max retries exceeded on encryption failure ({})", args.max_retries);
            }
            sleep(Duration::from_millis(RETRY_BACKOFF_MS)).await;
            continue;
        }

        if entries.is_empty() { continue; }

        match gateway.batch_put(&wk_hex, &args.voucher, &entries).await {
            Ok(()) => {
                info!(shipped = entries.len(), next_seq = sequence, "Batch shipped");
                retries = 0;
            }
            Err(e) => {
                error!("Gateway batch-PUT error: {}", e);
                retries += 1;
                if args.max_retries > 0 && retries >= args.max_retries {
                    bail!("Max retries exceeded ({})", args.max_retries);
                }
                sleep(Duration::from_millis(RETRY_BACKOFF_MS)).await;
                // Do NOT advance sequence — retry will re-ship the same batch
                continue;
            }
        }

        save_sequence(&seq_path, sequence);
    }

    save_sequence(&seq_path, sequence);
    info!("Tail exited cleanly at seq={}", sequence);
    Ok(())
}

// ── File helpers ──────────────────────────────────────────────────────────────

fn open_and_seek_to_end(path: &Path) -> Result<BufReader<std::fs::File>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Opening {}", path.display()))?;
    let mut r = BufReader::new(file);
    r.seek(SeekFrom::End(0)).context("Seeking to EOF")?;
    Ok(r)
}

fn reopen_from_start(path: &Path) -> Result<BufReader<std::fs::File>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Reopening {}", path.display()))?;
    Ok(BufReader::new(file))
}

fn seq_file_path(log_file: &Path) -> PathBuf {
    let name = log_file.file_name().unwrap_or_default().to_string_lossy().to_string();
    let mut p = log_file.to_path_buf();
    p.set_file_name(format!("{}{}", name, SEQ_FILE_SUFFIX));
    p
}

fn load_sequence(path: &Path) -> u64 {
    std::fs::read_to_string(path).ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_sequence(path: &Path, seq: u64) {
    if let Err(e) = std::fs::write(path, seq.to_string()) {
        warn!("Failed to persist sequence: {}", e);
    }
}
