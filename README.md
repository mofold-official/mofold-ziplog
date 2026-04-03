# MofoldZiplog

**Binary Desert Protocol v2 — Zero-Identity Encrypted Log Shipping & Secret Management**

MofoldZiplog is a developer infrastructure toolkit built on the [Binary Desert Protocol (BDP)](./docs/PROTOCOL.md). It provides production-ready blackbox logging and secret management with zero-knowledge guarantees, a hierarchical key system, and quantum-safe symmetric-only cryptography.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Developer machine (OFFLINE)                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Project Master Key (PMK)  — never leaves this machine      │   │
│  │  └── ReadKey  (RK) = HMAC-SHA256(PMK, "BDP-READ-KEY-v2")   │   │
│  │  └── WriteKey (WK) = HMAC-SHA256(PMK, "BDP-WRITE-KEY-v2")  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         │ WK (env var)              │ RK (env var)
         ▼                           ▼
┌──────────────────┐       ┌──────────────────┐
│  ziplog tail     │       │  Dashboard /     │
│  (log agent)     │       │  reader agent    │
└────────┬─────────┘       └────────┬─────────┘
         │  POST /ingest             │  POST /ingest
         │  Auth: Ziplog WK.<hex>    │  Auth: Ziplog RK.<hex>
         ▼                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Cloudflare Worker — Gateway (worker.ts)                           │
│  • Stateless HMAC voucher verification                             │
│  • Role enforcement: WK=write-only, RK=read-only                   │
│  • Server-side coordinate pepering: R2key=SHA256(coord+":"+PEPPER) │
│  • Write-lock via envelope AdminHash (constant-time compare)       │
│  • Durable Objects rate limiting (per-voucher + per-IP)            │
│  • Atomic get-burn via Durable Object lock                         │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
              ┌──────────────────────────┐
              │  Cloudflare R2           │
              │  Opaque encrypted blobs  │
              │  at peppered SHA-256 keys│
              │  No index. No metadata.  │
              └──────────────────────────┘
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| Content confidentiality | AES-256-GCM (Layer 1) + AES-256-CBC (Layer 2), independent keys |
| Key derivation | PBKDF2-HMAC-SHA256 @ 600,000 iterations (ring crate) |
| Memory safety | `zeroize::ZeroizeOnDrop` on all key types — wiped immediately after use |
| Timing attack prevention | `ring::constant_time::verify_slices_are_equal` for all token comparisons |
| Identity unlinkability | No user table, no account. Storage address = credential hash |
| Server opacity | Coordinate pepering: R2 key = SHA-256(coord + ":" + PEPPER) |
| Role separation | PMK offline only; RK for reads, WK for writes — Gateway enforces |
| Rate limiting | Cloudflare Durable Objects (survives cold starts, cross-instance consistent) |
| Atomic burn-on-read | Durable Object mutex prevents double-read race condition |
| Quantum readiness | Symmetric-only (AES-256, SHA-256, HMAC) — no asymmetric operations |
| Voucher verification | HMAC-SHA256 stateless tokens — no database hit per request |

### Whitepaper Mitigations Implemented (Section 8.3)

| Vulnerability | Fix |
|---|---|
| In-memory credential exposure | `ZeroizeOnDrop` on `ProjectMasterKey`, `ReadKey`, `WriteKey`; PBKDF2 key material in `Zeroizing<[u8;32]>` |
| Coordinate oracle / account enumeration | Constant-time HMAC comparison in voucher verify; pepered coordinates |
| In-memory rate limiting (single-instance) | Durable Objects — durable, cross-instance consistent sliding window |
| Ghost coordinate entropy gap | Coordinate derivation now uses HMAC-SHA256(WK, domain\|\|project\|\|seq) — full 256-bit security |
| Non-atomic burn-on-read | Durable Object burn-lock mutex serialises get+delete for each coordinate |
| CORS wildcard | Worker restricts `Access-Control-Allow-Origin` to production domain |
| Admin token = access key | Hierarchical keys: PMK→RK/WK; admin ops require WK, reads require RK |

---

## Project Structure

```
mofold-ziplog/
├── Cargo.toml                  # Workspace
├── crates/
│   ├── mofold-core/            # Core BDP crypto library
│   │   └── src/
│   │       ├── lib.rs          # Public API
│   │       ├── crypto.rs       # AES-GCM + AES-CBC + PBKDF2 engine
│   │       ├── envelope.rs     # 64-byte BDP binary header
│   │       ├── keys.rs         # PMK / RK / WK hierarchy
│   │       ├── coordinate.rs   # HMAC-based coordinate derivation
│   │       ├── voucher.rs      # Stateless HMAC voucher system
│   │       └── error.rs        # Unified error type
│   └── mofold-cli/             # `ziplog` binary
│       └── src/
│           ├── main.rs         # Clap command dispatch
│           ├── pmk.rs          # PMK file lifecycle (encrypted at rest)
│           ├── agent.rs        # Gateway HTTP client
│           └── commands/
│               ├── init.rs      # `ziplog init`
│               ├── rotate.rs    # `ziplog rotate`      ← recover RK/WK from PMK file
│               ├── voucher.rs   # `ziplog voucher`
│               ├── tail.rs      # `ziplog tail`        ← batch log shipping agent
│               ├── encrypt.rs   # `ziplog encrypt`     ← stdin or --message
│               ├── decrypt.rs   # `ziplog decrypt`
│               ├── read.rs      # `ziplog read`        ← single entry retrieval
│               ├── batch_get.rs # `ziplog batch-get`   ← bulk retrieval (one round trip)
│               ├── delete.rs    # `ziplog delete`
│               └── status.rs    # `ziplog status`      ← health check + live Gateway probe
└── gateway/
    ├── worker.ts               # Cloudflare Worker (full implementation)
    ├── wrangler.toml           # Deployment config
    ├── package.json
    └── tsconfig.json
```

---

## Quick Start

### 1. Build

```bash
# Requires Rust ≥ 1.85 (for argon2 0.5 transitive deps)
# This repo uses ring's PBKDF2 as interim, compatible with Rust ≥ 1.56
cargo build --release
cp target/release/ziplog /usr/local/bin/
```

### 2. Initialise a project

```bash
ziplog init \
  --project-id "my-service-prod" \
  --passphrase "$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 32)"

# Output:
#   .ziplog-pmk         ← encrypted PMK file (keep offline)
#   READ KEY  (RK): a3f8...   ← deploy to dashboards
#   WRITE KEY (WK): 9c12...   ← deploy to log agents
```

### 3. Issue a voucher

```bash
export ZIPLOG_VOUCHER_SECRET="your-server-secret-matches-worker-env"

# Free tier voucher (5 req/s, 50 MB)
ziplog voucher \
  --tier free \
  --valid-hours 168 \
  --quota-mb 10 \
  --rps 5

# Paid tier voucher (500 req/s, unlimited)
ziplog voucher \
  --tier paid \
  --valid-hours 8760 \
  --quota-mb 0 \
  --rps 500
```

### 4. Ship logs

```bash
export ZIPLOG_PROJECT_ID="my-service-prod"
export ZIPLOG_WRITE_KEY="9c12..."
export ZIPLOG_VOUCHER="PAID-eyJ..."

# Tail a file and ship encrypted entries
ziplog tail \
  --file /var/log/my-service/app.log \
  --gateway http://localhost:8787    # or https://your-worker.workers.dev
```

> **Sequence sidecar file:** `tail` creates a `.ziplog-seq` file next to the log
> file (e.g. `/var/log/my-service/app.log.ziplog-seq`) to persist the sequence
> counter across restarts. This file must be preserved during log rotation — if
> it is deleted, `tail` will restart the sequence from 0 and re-ship existing logs.

### 5. Encrypt / decrypt one-shot

```bash
# Encrypt
ziplog encrypt \
  --message "db_password=hunter2" \
  --write-key "$ZIPLOG_WRITE_KEY" \
  --project-id "$ZIPLOG_PROJECT_ID" \
  --sequence 0 \
  --show-coord > blob.b64

# Decrypt (same key, any machine)
ziplog decrypt \
  --blob "$(cat blob.b64)" \
  --write-key "$ZIPLOG_WRITE_KEY"
```

### 6. Retrieve logs in bulk

```bash
export ZIPLOG_READ_KEY="<RK hex>"

# Retrieve and decrypt entries 100–149 in a single Gateway round trip
ziplog batch-get \
  --project-id "$ZIPLOG_PROJECT_ID" \
  --read-key  "$ZIPLOG_READ_KEY" \
  --write-key "$ZIPLOG_WRITE_KEY" \
  --voucher   "$ZIPLOG_VOUCHER" \
  --from 100 --to 149 \
  --gateway "$ZIPLOG_GATEWAY_URL"
```

---

## Gateway Deployment

### Prerequisites

```bash
npm install -g wrangler
cd gateway && npm install
```

### Set secrets

```bash
# These are never in wrangler.toml — always set as secrets
wrangler secret put PEPPER          # 32+ random bytes hex, e.g. openssl rand -hex 32
wrangler secret put VOUCHER_SECRET  # shared with ziplog voucher CLI
```

### Create R2 bucket

```bash
wrangler r2 bucket create mofold-ziplog
wrangler r2 bucket create mofold-ziplog-dev  # for local dev
```

### Deploy

```bash
wrangler deploy          # production
wrangler dev --local     # local development (HTTP, no TLS)
```

### Expected execution time

The Worker is optimised to stay under 50ms per request:

| Operation | Typical time |
|---|---|
| Voucher HMAC verify | ~0.5ms |
| Coordinate pepper | ~0.2ms |
| R2 PUT (10 KB blob) | ~8–15ms |
| R2 GET | ~5–12ms |
| Rate limit DO check | ~2–5ms |
| **Total (PUT)** | **~15–25ms** |

---

## Voucher System

Vouchers are stateless HMAC-signed tokens. The Worker verifies them without
hitting any database — just one HMAC computation and a constant-time compare.

```
Token format:
  <TIER>-<BASE64_JSON_CLAIMS>.<HMAC_HEX>

  e.g. FREE-eyJ2b3VjaGVyX2lkIjoiYWJjMTIzIiwidGllciI6IkZSRUUi...}.a3f8c2...
```

### Tier comparison

| Property | FREE | PAID |
|---|---|---|
| Prefix | `FREE-` | `PAID-` |
| Max req/s | 5 | 500 |
| Max storage | 50 MB | Unlimited |
| Max lifetime | 30 days | 365 days |
| Payment required | No | Yes (your billing layer) |

The Worker applies **two layers** of rate limiting:
1. Per-voucher (from claims): enforces the purchased rate
2. Per-IP (2× voucher rate): defence against credential sharing

---

## Key Hierarchy

```
PMK (offline) ──HMAC-SHA256──► RK  →  used in: Authorization: Ziplog RK.<hex>
             └─HMAC-SHA256──► WK  →  used in: Authorization: Ziplog WK.<hex>
```

The Gateway enforces:
- `action: put`      → **WK required** (WK-signed; RK rejected with 403)
- `action: delete`   → **WK required**
- `action: get`      → **RK required** (RK-signed; WK rejected with 403)
- `action: get-burn` → **RK required**
- `action: batch-get`→ **RK required**
- `action: batch-put`→ **WK required** (parallel R2 writes, single rate-limit check per batch)

The PMK is encrypted with PBKDF2-AES-256-GCM and stored in `.ziplog-pmk`.
It is **never transmitted** and should be kept on an air-gapped machine or HSM.

---

## Envelope Format (64-byte BDP header)

Wire-compatible with the original TypeScript BDP implementation.

```
Byte  0      : Protocol version (0x02 for BDP v2)
Byte  1      : Blob type (0x01 VAULT | 0x02 FOLD | 0x03 ROOM | 0x04 INVITE | 0x05 LOG)
Bytes 2–33   : AdminHash — SHA-256(adminToken) [32 bytes]
Bytes 34–49  : Salt1     — random 16-byte Argon2id/PBKDF2 salt for GCM key
Bytes 50–61  : IV1       — random 12-byte IV for AES-256-GCM
Bytes 62–63  : PayloadLen — u16 big-endian (0 = total blob - 64)
Bytes 64+    : Payload: Salt2[16] + IV2[16] + AES-CBC(AES-GCM(plaintext))
```

---

## Upgrading to Argon2id

The current implementation uses PBKDF2-HMAC-SHA256 @ 600K iterations via
the `ring` crate, which is fully compatible with Rust ≥ 1.56 and has zero
additional transitive dependencies.

To upgrade to Argon2id (OWASP 2024 recommendation) once your toolchain is
Rust ≥ 1.85:

1. Add to `Cargo.toml`: `argon2 = { version = "0.5", features = ["alloc"] }`
2. In `crypto.rs`, replace `derive_key()` with:
   ```rust
   let params = Params::new(65536, 3, 4, Some(32)).unwrap();
   let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
   argon2.hash_password_into(&input, salt, key.as_mut()).unwrap();
   ```
3. The envelope format and all other code remain unchanged.

---

## Testing

```bash
# All 21 unit tests
cargo test -p mofold-core

# Specific suites
cargo test -p mofold-core crypto
cargo test -p mofold-core voucher
cargo test -p mofold-core coordinate

# Release build (verify optimizations don't break anything)
cargo test --release
```

Test coverage:
- `crypto`: encrypt/decrypt roundtrip, wrong-key rejection, GCM tamper detection, payload pack/parse
- `envelope`: pack/unpack roundtrip, small-blob error
- `keys`: RK/WK distinctness, determinism, hex roundtrip
- `coordinate`: per-project isolation, sequence differentiation, hex roundtrip
- `voucher`: issue+verify, expiry, HMAC tamper, wrong secret, tier limit enforcement

---

## License

MIT
