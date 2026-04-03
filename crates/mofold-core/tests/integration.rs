// crates/mofold-core/tests/integration.rs
//
// End-to-end integration tests for the Binary Desert Protocol v2 pipeline.
// These tests exercise the full path:
//   PMK generation → key hierarchy → coordinate derivation →
//   double-layer encrypt → BDP envelope pack →
//   envelope unpack → payload parse → double-layer decrypt
//
// They also verify cross-cutting security properties:
//   • Role separation (RK ≠ WK, coordinate domain isolation)
//   • Voucher lifecycle (issue → verify → expire → tamper)
//   • Admin token write-lock round-trip
//   • Envelope wire format stability

use mofold_core::{
    crypto::{double_decrypt, double_encrypt, pack_payload, parse_payload, sha256, verify_admin_token},
    coordinate::CoordinateDerivation,
    envelope::{BlobType, Envelope, ENVELOPE_SIZE},
    keys::{KeyHierarchy, ProjectMasterKey},
    voucher::{Voucher, VoucherClaims, VoucherTier},
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn test_pmk() -> ProjectMasterKey {
    ProjectMasterKey::from_bytes([0xDE; 32])
}

const SERVER_SECRET: &[u8] = b"integration-test-server-secret!!";
const NOW:           u64   = 1_700_000_000;

fn free_claims(voucher_id: &str) -> VoucherClaims {
    VoucherClaims {
        voucher_id:    voucher_id.to_string(),
        tier:          VoucherTier::Free,
        issued_at:     NOW,
        expires_at:    NOW + 7 * 24 * 3600,
        quota_bytes:   10 * 1024 * 1024,
        rate_limit_rps: 5,
    }
}

// ─── Key hierarchy ────────────────────────────────────────────────────────────

#[test]
fn key_hierarchy_rk_wk_are_distinct_and_deterministic() {
    let pmk = test_pmk();
    let h1  = KeyHierarchy::from_pmk(&pmk);
    let h2  = KeyHierarchy::from_pmk(&pmk);

    // Deterministic
    assert_eq!(h1.read_key.as_bytes(),  h2.read_key.as_bytes());
    assert_eq!(h1.write_key.as_bytes(), h2.write_key.as_bytes());

    // Distinct — a compromised WK does not reveal RK
    assert_ne!(h1.read_key.as_bytes(), h1.write_key.as_bytes());
}

#[test]
fn different_pmks_produce_different_hierarchies() {
    let pmk1 = ProjectMasterKey::from_bytes([0x01; 32]);
    let pmk2 = ProjectMasterKey::from_bytes([0x02; 32]);
    let h1   = KeyHierarchy::from_pmk(&pmk1);
    let h2   = KeyHierarchy::from_pmk(&pmk2);
    assert_ne!(h1.write_key.as_bytes(), h2.write_key.as_bytes());
    assert_ne!(h1.read_key.as_bytes(),  h2.read_key.as_bytes());
}

// ─── Full encrypt → pack → unpack → decrypt pipeline ─────────────────────────

#[test]
fn full_bdp_pipeline_log_entry() {
    let pmk       = test_pmk();
    let hierarchy = KeyHierarchy::from_pmk(&pmk);
    let wk_bytes  = hierarchy.write_key.as_bytes();
    let project   = "integration-test-project";
    let sequence  = 42u64;

    // Plaintext log line
    let plaintext = b"2024-01-15T10:23:44Z ERROR payment-svc: timeout after 30s [trace=abc123]";

    // Derive coordinate
    let coord = CoordinateDerivation::log_entry(wk_bytes, project, sequence);
    assert_eq!(coord.to_hex().len(), 64, "coordinate must be 64 hex chars");

    // Encrypt
    let key_material = wk_bytes.to_vec();
    let ct = double_encrypt(plaintext, &key_material)
        .expect("encryption must succeed");

    // Admin hash from WK
    let mut admin_hash = [0u8; 32];
    admin_hash.copy_from_slice(&sha256(wk_bytes));

    // Pack envelope
    let payload = pack_payload(&ct);
    let blob    = Envelope::pack(BlobType::Log, &admin_hash, &ct.salt1, &ct.iv1, &payload);

    // Blob must be > ENVELOPE_SIZE
    assert!(blob.len() > ENVELOPE_SIZE);
    // First byte must be protocol version 0x02
    assert_eq!(blob[0], 0x02);
    // Second byte must be BlobType::Log = 0x05
    assert_eq!(blob[1], 0x05);

    // Unpack envelope
    let (header, recovered_payload) = Envelope::unpack(&blob)
        .expect("unpack must succeed");

    assert_eq!(header.blob_type, BlobType::Log as u8);
    assert_eq!(header.salt1, ct.salt1);
    assert_eq!(header.iv1,   ct.iv1);

    // Parse payload
    let mut parsed_ct = parse_payload(recovered_payload)
        .expect("parse_payload must succeed");
    parsed_ct.salt1 = header.salt1;
    parsed_ct.iv1   = header.iv1;

    // Decrypt
    let decrypted = double_decrypt(&parsed_ct, &key_material)
        .expect("decryption must succeed");

    assert_eq!(&decrypted, plaintext, "decrypted must match original plaintext");
}

#[test]
fn full_pipeline_with_fold_blob_type() {
    let pmk       = test_pmk();
    let h         = KeyHierarchy::from_pmk(&pmk);
    let key       = h.write_key.as_bytes().to_vec();
    let plaintext = b"db_password=super-secret-value-here";

    let ct      = double_encrypt(plaintext, &key).unwrap();
    let payload = pack_payload(&ct);
    let blob    = Envelope::pack(BlobType::Fold, &[0u8; 32], &ct.salt1, &ct.iv1, &payload);

    let (hdr, raw_payload) = Envelope::unpack(&blob).unwrap();
    assert_eq!(hdr.typed_blob_type().unwrap(), BlobType::Fold);
    assert!(hdr.is_zero_admin_hash(), "zero admin hash must be detected");

    let mut pct = parse_payload(raw_payload).unwrap();
    pct.salt1   = hdr.salt1;
    pct.iv1     = hdr.iv1;

    let got = double_decrypt(&pct, &key).unwrap();
    assert_eq!(&got, plaintext);
}

// ─── Cross-project coordinate isolation ──────────────────────────────────────

#[test]
fn coordinates_isolated_across_projects() {
    let pmk = test_pmk();
    let wk  = pmk.derive_write_key();

    let c_alpha = CoordinateDerivation::log_entry(wk.as_bytes(), "project-alpha", 0);
    let c_beta  = CoordinateDerivation::log_entry(wk.as_bytes(), "project-beta",  0);

    assert!(!c_alpha.ct_eq(&c_beta),
        "same sequence under different project IDs must produce different coordinates");
}

#[test]
fn coordinates_isolated_across_sequences() {
    let pmk = test_pmk();
    let wk  = pmk.derive_write_key();

    let c0 = CoordinateDerivation::log_entry(wk.as_bytes(), "proj", 0);
    let c1 = CoordinateDerivation::log_entry(wk.as_bytes(), "proj", 1);
    assert!(!c0.ct_eq(&c1));
}

#[test]
fn rk_and_wk_produce_different_vault_coords() {
    // The Gateway uses WK-derived coordinates for storage authorization.
    // If someone had only RK, they could not compute valid write coordinates.
    let pmk  = test_pmk();
    let h    = KeyHierarchy::from_pmk(&pmk);

    let wk_coord = CoordinateDerivation::vault(h.write_key.as_bytes(), "proj");
    let rk_coord = CoordinateDerivation::vault(h.read_key.as_bytes(),  "proj");

    assert!(!wk_coord.ct_eq(&rk_coord),
        "RK-derived and WK-derived coordinates must differ — RK cannot forge write addresses");
}

// ─── Admin token write-lock ───────────────────────────────────────────────────

#[test]
fn admin_token_roundtrip() {
    let pmk   = test_pmk();
    let wk    = pmk.derive_write_key();
    let token = wk.as_bytes();          // WK bytes as admin token
    let hash  = sha256(token);

    assert!(verify_admin_token(&hash, token),   "correct token must pass");
    assert!(!verify_admin_token(&hash, b"bad"), "wrong token must fail");

    // Flip one bit — must fail
    let mut bad = token.to_vec();
    bad[0] ^= 0x01;
    assert!(!verify_admin_token(&hash, &bad), "bit-flipped token must fail");
}

#[test]
fn zero_admin_hash_is_open_write() {
    let ct      = double_encrypt(b"open manifest entry", b"key").unwrap();
    let payload = pack_payload(&ct);
    let blob    = Envelope::pack(BlobType::Room, &[0u8; 32], &ct.salt1, &ct.iv1, &payload);

    let (hdr, _) = Envelope::unpack(&blob).unwrap();
    assert!(hdr.is_zero_admin_hash(),
        "zero admin hash must be detected as open-write blob");
}

// ─── Voucher lifecycle ────────────────────────────────────────────────────────

#[test]
fn voucher_full_lifecycle() {
    // Issue
    let claims  = free_claims("e2e-test-voucher-001");
    let voucher = Voucher::issue(claims, SERVER_SECRET)
        .expect("voucher issue must succeed");

    // Token must start with FREE-
    assert!(voucher.token.starts_with("FREE-"),
        "free voucher token must start with FREE-");

    // Verify within validity window
    let v2 = Voucher::verify(&voucher.token, SERVER_SECRET, NOW + 3600)
        .expect("voucher verify must succeed");
    assert_eq!(v2.claims.voucher_id, "e2e-test-voucher-001");
    assert_eq!(v2.claims.rate_limit_rps, 5);
    assert!(v2.is_free());

    // Verify at expiry boundary (should pass)
    Voucher::verify(&voucher.token, SERVER_SECRET, NOW + 7 * 24 * 3600)
        .expect("verify at exact expiry must succeed");

    // Verify after expiry (must fail)
    let expired = Voucher::verify(&voucher.token, SERVER_SECRET, NOW + 7 * 24 * 3600 + 1);
    assert!(expired.is_err(), "expired voucher must be rejected");
}

#[test]
fn voucher_tamper_detection() {
    let v   = Voucher::issue(free_claims("tamper-test"), SERVER_SECRET).unwrap();
    let tok = &v.token;

    // Flip a character in the claims section (before the dot)
    let dot   = tok.rfind('.').unwrap();
    let mut bad_tok = tok.clone();
    let flip_pos    = dot / 2;          // somewhere in the claims b64
    let bytes       = unsafe { bad_tok.as_bytes_mut() };
    bytes[flip_pos] ^= 0x01;

    let result = Voucher::verify(&bad_tok, SERVER_SECRET, NOW + 100);
    assert!(result.is_err(), "tampered token must be rejected");
}

#[test]
fn paid_voucher_has_higher_limits() {
    let claims = VoucherClaims {
        voucher_id:    "paid-e2e-001".to_string(),
        tier:          VoucherTier::Paid,
        issued_at:     NOW,
        expires_at:    NOW + 365 * 24 * 3600,
        quota_bytes:   0,    // unlimited
        rate_limit_rps: 500,
    };
    let v  = Voucher::issue(claims, SERVER_SECRET).unwrap();
    let v2 = Voucher::verify(&v.token, SERVER_SECRET, NOW + 100).unwrap();

    assert!(!v2.is_free());
    assert_eq!(v2.effective_rps(), 500);
    assert_eq!(v2.effective_quota_bytes(), 0, "zero means unlimited for PAID");
    assert!(v2.token.starts_with("PAID-"));
}

// ─── Encryption security properties ──────────────────────────────────────────

#[test]
fn ciphertext_is_nondeterministic() {
    // Two encryptions of identical plaintext under identical keys must differ
    // because salts and IVs are random.
    let key = b"test-key-for-nondeterminism-32b!";
    let pt  = b"same plaintext every time";
    let c1  = double_encrypt(pt, key).unwrap();
    let c2  = double_encrypt(pt, key).unwrap();
    assert_ne!(c1.ciphertext, c2.ciphertext);
    assert_ne!(c1.salt1, c2.salt1);
}

#[test]
fn wrong_key_fails_authentication() {
    let ct = double_encrypt(b"confidential log entry", b"correct-key-for-test-32bytes!").unwrap();
    let result = double_decrypt(&ct, b"wrong---key-for-test-32bytes!--");
    assert!(result.is_err(),
        "GCM authentication tag must reject decryption with wrong key");
}

#[test]
fn bit_flip_in_ciphertext_fails_gcm() {
    let key = b"bit-flip-test-key-32-bytes-pad!!";
    let mut ct = double_encrypt(b"sensitive data", key).unwrap();
    // Flip a byte deep in the ciphertext (after CBC+GCM layers)
    if !ct.ciphertext.is_empty() {
        let mid = ct.ciphertext.len() / 2;
        ct.ciphertext[mid] ^= 0xFF;
    }
    assert!(double_decrypt(&ct, key).is_err(),
        "modified ciphertext must fail GCM authentication");
}

#[test]
fn large_payload_roundtrip() {
    // 64 KB — typical for a batch of log lines
    let pmk      = test_pmk();
    let wk       = pmk.derive_write_key();
    let key      = wk.as_bytes().to_vec();
    let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

    let ct      = double_encrypt(&plaintext, &key).unwrap();
    let payload = pack_payload(&ct);
    let blob    = Envelope::pack(BlobType::Log, &[0u8; 32], &ct.salt1, &ct.iv1, &payload);

    let (hdr, raw) = Envelope::unpack(&blob).unwrap();
    let mut pct    = parse_payload(raw).unwrap();
    pct.salt1      = hdr.salt1;
    pct.iv1        = hdr.iv1;

    let got = double_decrypt(&pct, &key).unwrap();
    assert_eq!(got, plaintext, "64 KB payload must decrypt correctly");
}

// ─── Envelope wire format ─────────────────────────────────────────────────────

#[test]
fn envelope_header_layout_is_stable() {
    // Verify byte offsets are exactly as documented in the BDP spec.
    let admin_hash = [0xAA; 32];
    let salt1      = [0xBB; 16];
    let iv1        = [0xCC; 12];
    let payload    = b"test payload";

    let blob = Envelope::pack(BlobType::Log, &admin_hash, &salt1, &iv1, payload);

    assert_eq!(blob[0], 0x02,  "byte 0: version must be 0x02");
    assert_eq!(blob[1], 0x05,  "byte 1: blob type LOG must be 0x05");
    assert_eq!(&blob[2..34],   &admin_hash, "bytes 2-33: admin hash");
    assert_eq!(&blob[34..50],  &salt1,      "bytes 34-49: salt1");
    assert_eq!(&blob[50..62],  &iv1,        "bytes 50-61: iv1");

    let payload_len = u16::from_be_bytes([blob[62], blob[63]]) as usize;
    assert_eq!(payload_len, payload.len(), "bytes 62-63: payload length");
    assert_eq!(&blob[64..64 + payload_len], payload, "bytes 64+: payload");
}

#[test]
fn blob_type_all_variants_round_trip() {
    use mofold_core::envelope::BlobType;

    for bt in [BlobType::Vault, BlobType::Fold, BlobType::Room, BlobType::Invite, BlobType::Log] {
        let blob    = Envelope::pack(bt, &[0u8; 32], &[0u8; 16], &[0u8; 12], b"x");
        let (hdr,_) = Envelope::unpack(&blob).unwrap();
        assert_eq!(hdr.typed_blob_type().unwrap(), bt);
    }
}
