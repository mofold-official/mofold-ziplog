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
│  Cloudflare Worker — Gateway (managed service)                     │
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
| Content confidentiality | AES-256-GCM (Layer 1) + AES-256-CBC (Layer 2), independent keys per layer |
| Key derivation | PBKDF2-HMAC-SHA256 @ 600,000 iterations (ring crate) |
| Memory safety | `zeroize::ZeroizeOnDrop` on all key types — key material wiped from memory immediately after use |
| Timing attack prevention | Constant-time comparisons for all credential and token verification — no early-exit branches |
| Identity unlinkability | No user table, no account. Storage address is derived from credentials, never from identity |
| Server opacity | Coordinate pepering: R2 key = SHA-256(coord + ":" + PEPPER) — storage addresses are not reversible without PEPPER |
| Role separation | PMK stays offline only; RK for reads, WK for writes — Gateway enforces at request time |
| Credential isolation | In-memory keys are wrapped under a session KEK and wiped after use — not accessible in plaintext after login |
| Rate limiting | Durable Objects — durable across cold starts, consistent across all Worker instances |
| Atomic burn-on-read | Durable Object mutex serialises get+delete for each coordinate — prevents double-read race conditions |
| Quantum readiness | Symmetric-only primitives (AES-256, SHA-256, HMAC) — no asymmetric operations vulnerable to Shor's algorithm |
| Voucher verification | HMAC-SHA256 stateless tokens — Gateway verifies without hitting any database |
| Coordinate entropy | Coordinate derivation uses HMAC-SHA256(WK, domain\|\|project\|\|seq) — full 256-bit security, no entropy gap |
| CORS restriction | Gateway restricts `Access-Control-Allow-Origin` to the configured production domain |

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
│               ├── init.rs     # `ziplog init`
│               ├── rotate.rs   # `ziplog rotate`      ← recover RK/WK from PMK file
│               ├── voucher.rs  # `ziplog voucher`
│               ├── tail.rs     # `ziplog tail`        ← batch log shipping agent
│               ├── encrypt.rs  # `ziplog encrypt`     ← stdin or --message
│               ├── decrypt.rs  # `ziplog decrypt`
│               ├── read.rs     # `ziplog read`        ← single entry retrieval
│               ├── batch_get.rs# `ziplog batch-get`   ← bulk retrieval (one round trip)
│               ├── delete.rs   # `ziplog delete`
│               └── status.rs   # `ziplog status`      ← health check + live Gateway probe
└── docs/
    ├── PROTOCOL.md             # BDP v2 formal specification
    ├── DEPLOYMENT.md           # Production deployment guide
    └── SECURITY.md             # Threat model and security analysis
```

> **Gateway Worker:** The Cloudflare Worker that powers the gateway is maintained
> as a separate private repository and operated as a managed service.
> See the [Gateway](#gateway) section below for access options.

---

## Quick Start

### 1. Build

```bash
# Requires Rust ≥ 1.75
cargo build --release
cp target/release/ziplog /usr/local/bin/
```

### 2. Initialise a project

```bash
ziplog init \
  --project-id "my-service-prod" \
  --passphrase "$(openssl rand -base64 32)"

# Output:
#   .ziplog-pmk         ← encrypted PMK file (keep offline)
#   READ KEY  (RK): a3f8...   ← deploy to dashboards / readers
#   WRITE KEY (WK): 9c12...   ← deploy to log agents
```

### 3. Get a voucher token

Sign up at **https://mofold.com** to receive your voucher token.
The voucher authorises your requests to the managed gateway.

```bash
export ZIPLOG_VOUCHER="<token from your mofold.com dashboard>"
```

### 4. Ship logs

```bash
export ZIPLOG_PROJECT_ID="my-service-prod"
export ZIPLOG_WRITE_KEY="9c12..."
export ZIPLOG_VOUCHER="<token from your mofold.com dashboard>"
export ZIPLOG_GATEWAY_URL="https://mofold-ziplog-gateway.mofold-official.workers.dev"

# Tail a file and ship encrypted entries
ziplog tail \
  --file /var/log/my-service/app.log \
  --gateway "$ZIPLOG_GATEWAY_URL"
```

> **Sequence sidecar file:** `tail` creates a `.ziplog-seq` file next to the log
> file to persist the sequence counter across restarts. Preserve this file
> during log rotation. Add `*.ziplog-seq` to your `.gitignore`.

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

## Gateway

The MofoldZiplog Gateway is a Cloudflare Worker that handles voucher
verification, coordinate pepering, R2 storage, and Durable Object rate
limiting. It is stateless — no database is hit per request.

### Managed service (recommended)

Use the hosted gateway — no infrastructure setup required:

```
https://mofold-ziplog-gateway.mofold-official.workers.dev
```

Get your voucher token and manage your subscription at **https://mofold.com**.

### Enterprise self-hosting

The gateway source code is available to Enterprise plan subscribers.
Self-hosting gives you full data sovereignty — your own Cloudflare account,
your own R2 bucket, your own PEPPER. See **https://mofold.com/pricing** for details.

---

## TypeScript SDK

If you prefer TypeScript over the CLI, use the official SDK:

```bash
npm install @mofold/ziplog-sdk
```

```typescript
import { GatewayClient } from "@mofold/ziplog-sdk";

const client = new GatewayClient({
  gatewayUrl: "https://mofold-ziplog-gateway.mofold-official.workers.dev",
  writeKey:   process.env.ZIPLOG_WRITE_KEY,
  readKey:    process.env.ZIPLOG_READ_KEY,
  voucher:    process.env.ZIPLOG_VOUCHER,
});

await client.put("my-project", 1, new TextEncoder().encode("hello"));
const data = await client.get("my-project", 1);
```

Full SDK documentation: [github.com/mofold-official/mofold-ziplog-sdk](https://github.com/mofold-official/mofold-ziplog-sdk)

---

## Voucher System

Vouchers are stateless HMAC-signed tokens that authorise requests to the Gateway.
The Gateway verifies them without hitting any database — just one HMAC computation
and a constant-time compare.

For information on available plans, quotas, and how to obtain a voucher token,
visit **https://mofold.com**.

---

## Key Hierarchy

```
PMK (offline) ──HMAC-SHA256──► RK  →  used in: Authorization: Ziplog RK.<hex>
             └─HMAC-SHA256──► WK  →  used in: Authorization: Ziplog WK.<hex>
```

The Gateway enforces:
- `action: put`       → **WK required** (RK rejected with 403)
- `action: delete`    → **WK required**
- `action: get`       → **RK required** (WK rejected with 403)
- `action: get-burn`  → **RK required**
- `action: batch-get` → **RK required**
- `action: batch-put` → **WK required**

The PMK is encrypted with PBKDF2-AES-256-GCM and stored in `.ziplog-pmk`.
It is **never transmitted** and should be kept on an air-gapped machine or HSM.

---

## Envelope Format (64-byte BDP header)

Wire-compatible with the original TypeScript BDP implementation.

```
Byte  0      : Protocol version (0x02 for BDP v2)
Byte  1      : Blob type (0x01 VAULT | 0x02 FOLD | 0x03 ROOM | 0x04 INVITE | 0x05 LOG)
Bytes 2–33   : AdminHash — SHA-256(adminToken) [32 bytes]
Bytes 34–49  : Salt1     — random 16-byte PBKDF2 salt for GCM key
Bytes 50–61  : IV1       — random 12-byte IV for AES-256-GCM
Bytes 62–63  : PayloadLen — u16 big-endian (0 = total blob - 64)
Bytes 64+    : Payload: Salt2[16] + IV2[16] + AES-CBC(AES-GCM(plaintext))
```

---

## Upgrading to Argon2id

The current implementation uses PBKDF2-HMAC-SHA256 @ 600K iterations via
the `ring` crate, compatible with Rust ≥ 1.75.

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
# All unit tests
cargo test -p mofold-core

# Specific suites
cargo test -p mofold-core crypto
cargo test -p mofold-core voucher
cargo test -p mofold-core coordinate

# Release build
cargo test --release
```

Test coverage:
- `crypto`: encrypt/decrypt roundtrip, wrong-key rejection, GCM tamper detection
- `envelope`: pack/unpack roundtrip, small-blob error
- `keys`: RK/WK distinctness, determinism, hex roundtrip
- `coordinate`: per-project isolation, sequence differentiation, hex roundtrip
- `voucher`: issue+verify, expiry, HMAC tamper, wrong secret, tier limit enforcement

---

## License

MIT
