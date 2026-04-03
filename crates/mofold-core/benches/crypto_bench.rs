// crates/mofold-core/benches/crypto_bench.rs
//
// MofoldZiplog BDP v2 — performance benchmarks
//
// harness = false: we provide our own main() and use std::time for timing.
// This works on stable Rust without the nightly `test` crate.
//
// Run:  cargo bench -p mofold-core
//
// For richer HTML reports add criterion to [dev-dependencies] and flip harness = true.

use std::time::Instant;
use mofold_core::{
    crypto::{ct_eq_32, double_decrypt, double_encrypt, pack_payload,
             parse_payload, sha256, verify_admin_token},
    coordinate::CoordinateDerivation,
    envelope::{BlobType, Envelope},
    keys::{KeyHierarchy, ProjectMasterKey},
    voucher::{Voucher, VoucherClaims, VoucherTier},
};

const KEY:    &[u8] = b"mofold-ziplog-bench-32-bytes!!!!";
const SECRET: &[u8] = b"bench-voucher-secret-32-bytes!!!";
const NOW:    u64   = 1_700_000_000;
const ITERS:  u32   = 3; // PBKDF2@600K is slow; 3 iterations is enough for timing

fn bench<F: FnMut()>(label: &str, mut f: F) {
    // Warmup
    for _ in 0..1 { f(); }
    // Measure
    let start = Instant::now();
    for _ in 0..ITERS { f(); }
    let elapsed = start.elapsed();
    let per_iter_ms = elapsed.as_secs_f64() * 1000.0 / ITERS as f64;
    println!("  {:<45} {:>8.2} ms/op", label, per_iter_ms);
}

fn bench_fast<F: FnMut()>(label: &str, iters: u32, mut f: F) {
    for _ in 0..10 { f(); } // warmup
    let start = Instant::now();
    for _ in 0..iters { f(); }
    let elapsed = start.elapsed();
    let per_iter_us = elapsed.as_secs_f64() * 1_000_000.0 / iters as f64;
    if per_iter_us < 1.0 {
        println!("  {:<45} {:>8.1} ns/op", label, per_iter_us * 1000.0);
    } else {
        println!("  {:<45} {:>8.2} µs/op", label, per_iter_us);
    }
}

fn main() {
    println!();
    println!("MofoldZiplog — BDP v2 Benchmarks");
    println!("  Build: {}", if cfg!(debug_assertions) { "debug (slow!)" } else { "release" });
    println!("  PBKDF2 iterations: 600,000 × 2 per encrypt/decrypt");
    println!();

    println!("── Encryption / Decryption (KDF-dominated) ──────────────────────────────");

    bench("double_encrypt(256 B)", || {
        let ct = double_encrypt(&vec![0x41u8; 256], KEY).unwrap();
        std::hint::black_box(ct.ciphertext.len());
    });

    bench("double_encrypt(4 KB)", || {
        let ct = double_encrypt(&vec![0x41u8; 4096], KEY).unwrap();
        std::hint::black_box(ct.ciphertext.len());
    });

    bench("double_encrypt(64 KB)", || {
        let ct = double_encrypt(&vec![0x41u8; 65536], KEY).unwrap();
        std::hint::black_box(ct.ciphertext.len());
    });

    bench("double_decrypt(256 B)", || {
        let ct  = double_encrypt(&vec![0x41u8; 256], KEY).unwrap();
        let out = double_decrypt(&ct, KEY).unwrap();
        std::hint::black_box(out.len());
    });

    println!();
    println!("── Full BDP pipeline (encrypt → pack → envelope → unpack → decrypt) ─────");

    let pmk  = ProjectMasterKey::from_bytes([0xDE; 32]);
    let h    = KeyHierarchy::from_pmk(&pmk);
    let wk   = h.write_key.as_bytes().to_vec();
    let mut admin_hash = [0u8; 32];
    admin_hash.copy_from_slice(&sha256(&wk));
    let plaintext = b"2024-01-15T10:23:44Z ERROR payment-svc: timeout [trace=abc]";

    bench("full pipeline — log entry (256 B)", || {
        let ct      = double_encrypt(plaintext, &wk).unwrap();
        let payload = pack_payload(&ct);
        let blob    = Envelope::pack(BlobType::Log, &admin_hash, &ct.salt1, &ct.iv1, &payload);
        let (hdr, raw) = Envelope::unpack(&blob).unwrap();
        let mut pct    = parse_payload(raw).unwrap();
        pct.salt1      = hdr.salt1;
        pct.iv1        = hdr.iv1;
        let out = double_decrypt(&pct, &wk).unwrap();
        std::hint::black_box(out.len());
    });

    println!();
    println!("── Fast primitives ──────────────────────────────────────────────────────");

    let pmk2 = ProjectMasterKey::from_bytes([0x42; 32]);
    let wk2  = pmk2.derive_write_key();

    bench_fast("coord — vault derivation", 10_000, || {
        let c = CoordinateDerivation::vault(wk2.as_bytes(), "bench-project");
        std::hint::black_box(c.as_bytes()[0]);
    });

    bench_fast("coord — log_entry derivation", 10_000, || {
        let c = CoordinateDerivation::log_entry(wk2.as_bytes(), "bench-project", 42);
        std::hint::black_box(c.as_bytes()[0]);
    });

    bench_fast("sha256(256 B)", 100_000, || {
        let h = sha256(KEY);
        std::hint::black_box(h[0]);
    });

    bench_fast("ct_eq_32 (match)", 1_000_000, || {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        std::hint::black_box(ct_eq_32(&a, &b));
    });

    bench_fast("verify_admin_token", 100_000, || {
        let h = sha256(KEY);
        std::hint::black_box(verify_admin_token(&h, KEY));
    });

    bench_fast("key_hierarchy_from_pmk", 10_000, || {
        let pmk = ProjectMasterKey::from_bytes([0x01; 32]);
        let h   = KeyHierarchy::from_pmk(&pmk);
        std::hint::black_box(h.write_key.as_bytes()[0]);
    });

    println!();
    println!("── Voucher ──────────────────────────────────────────────────────────────");

    let paid_claims = VoucherClaims {
        voucher_id:    "bench-paid".to_string(),
        tier:          VoucherTier::Paid,
        issued_at:     NOW,
        expires_at:    NOW + 365 * 24 * 3600,
        quota_bytes:   0,
        rate_limit_rps: 500,
    };

    bench_fast("voucher issue (PAID)", 10_000, || {
        let v = Voucher::issue(paid_claims.clone(), SECRET).unwrap();
        std::hint::black_box(v.token.len());
    });

    let token = Voucher::issue(paid_claims, SECRET).unwrap().token;
    bench_fast("voucher verify (PAID)", 10_000, || {
        let v = Voucher::verify(&token, SECRET, NOW + 100).unwrap();
        std::hint::black_box(v.effective_rps());
    });

    println!();
    println!("─────────────────────────────────────────────────────────────────────────");
    println!("  Note: encrypt/decrypt times are dominated by PBKDF2 @ 600K iterations.");
    println!("  This is intentional — it bounds offline brute-force to ~25 attempts/s.");
    if cfg!(debug_assertions) {
        println!("  WARNING: Run `cargo bench -p mofold-core` (release mode) for real numbers.");
    }
    println!();
}
