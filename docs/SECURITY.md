# MofoldZiplog — Security Model

## Threat Model

### Adversary Classes

| Adversary | Capabilities | What MofoldZiplog protects against |
|---|---|---|
| Passive server operator | Reads R2 bucket contents and Worker logs | Cannot link blobs to users; cannot read plaintext; cannot map R2 keys back to coordinates without PEPPER |
| Active server operator | Modifies Worker code | Cannot read already-stored encrypted data; cannot compute coordinates without PEPPER; can observe access timing |
| Network adversary | Intercepts HTTPS traffic | Transport is TLS; content is pre-encrypted before transmission — TLS breach reveals only ciphertext |
| Offline dictionary attacker | Obtains R2 bucket dump | Cannot brute-force without PEPPER; PBKDF2-SHA256 @ 600K iterations per key derivation attempt |
| Insider (WK holder) | Has the WriteKey | Can write/delete blobs; cannot read without RK; cannot compute PMK |
| Insider (RK holder) | Has the ReadKey | Can read blobs they know coordinates for; cannot write; cannot forge WK-signed requests |
| Quantum adversary | CRQC running Grover | AES-256 provides 128-bit post-quantum security; SHA-256 provides 128-bit post-quantum security; no asymmetric operations to attack with Shor |

---

## Security Properties

### Zero-Identity Architecture

The Gateway Worker has no concept of "user identity". The complete list of
information visible to the server per request:

- An opaque peppered SHA-256 hash (the R2 key) — not reversible without PEPPER
- An opaque base64 binary blob (the encrypted payload) — AES-256 encrypted
- A voucher token — reveals only tier/rate/quota claims, not user identity
- The Authorization header — reveals the role tag (RK or WK) and a 32-byte key hex
- The client IP address — used for secondary rate limiting only

The Worker **cannot** determine:
- Which project the blob belongs to
- What sequence number this entry has
- How many total blobs a given user has
- Whether two requests from different IPs are from the same user

### Cryptographic Guarantees

**Content confidentiality** — AES-256-GCM (Layer 1) provides authenticated
encryption. AES-256-CBC (Layer 2) with an independently derived key adds a
second confidentiality layer. Both keys are derived via PBKDF2-HMAC-SHA256
at 600,000 iterations with independent random 128-bit salts.

**Integrity protection** — The GCM authentication tag (128 bits) detects any
modification to the ciphertext. Tampered blobs are rejected during decryption
before any plaintext is produced.

**Key independence** — Layer-1 and Layer-2 keys are derived with a domain
separator (`_layer2` suffix on the KDF input). A weakness in one layer's
key cannot be leveraged to attack the other.

**Forward-secure key hierarchy** — The PMK is never transmitted. RK and WK
are derived via HMAC-SHA256 with distinct domain labels. Compromise of WK
does not reveal RK. Compromise of both RK and WK does not reveal PMK.

**Memory safety** — All key types (`ProjectMasterKey`, `ReadKey`, `WriteKey`)
implement `zeroize::ZeroizeOnDrop`. All intermediate key material in the
encryption path is held in `Zeroizing<[u8; 32]>` wrappers. Keys are wiped
immediately when they go out of scope, regardless of whether drop() is called
explicitly. This prevents sensitive material from remaining in heap memory
after use.

**Constant-time operations** — All security-sensitive comparisons use
`ct_eq_32()` — a custom XOR-accumulator function in `crypto.rs` — which
executes in time proportional to 32 iterations regardless of input values.
This prevents timing side channels that could reveal whether a guess was
"close" to the correct value. The implementation does not use the deprecated
`ring::constant_time::verify_slices_are_equal`.

### Rate Limiting

Rate limits are enforced by Cloudflare Durable Objects. Unlike the original
in-memory implementation (which was reset on every cold start and was not
consistent across multiple Worker instances), Durable Objects provide:

- **Durability** — state persists across cold starts
- **Consistency** — all Worker instances route to the same DO instance per key
- **Isolation** — each voucher has its own DO, so a flooded free-tier user
  cannot affect a paid-tier user's rate limit state

Two rate limit layers are applied per request:
1. Per-voucher sliding window (enforces the purchased rate)
2. Per-IP sliding window at 2× the voucher rate (defence against credential sharing)

### Atomic Burn-on-Read

The `get-burn` operation (retrieve + delete) is made atomic via a Durable
Object mutex lock. The sequence is:

1. Acquire burn-lock for the coordinate (DO `burn-lock` endpoint)
2. If lock not acquired → return 409 Conflict (another read in progress)
3. GET blob from R2
4. DELETE blob from R2
5. Release burn-lock (DO `burn-unlock` endpoint, called in `finally`)

The lock auto-expires after 10 seconds to handle Worker crashes between
steps 3 and 5. This is substantially stronger than the original non-atomic
two-step implementation described in whitepaper Section 8.3.5.

---

## Key Rotation

To rotate keys for a project:

1. Generate a new PMK: `ziplog init --project-id <id> --passphrase <new>`
2. Derive new RK and WK from the new PMK
3. Re-encrypt all existing blobs:
   - Read each blob using the old RK
   - Decrypt with old WK
   - Re-encrypt with new WK
   - Write at new coordinate (derived from new WK)
   - Delete from old coordinate using old WK (admin token)
4. Revoke old WK and RK from all agents
5. Deploy new WK to agents, new RK to dashboards

There is no server-side key rotation operation — the zero-identity design
means the server has no record of which blobs belong to which project.

---

## Voucher Security

Vouchers are HMAC-SHA256 signed tokens. The security properties are:

- **Unforgeability** — without the `VOUCHER_SECRET`, it is computationally
  infeasible to produce a valid voucher of any tier
- **Tamper detection** — any modification to the claims (tier, RPS, quota,
  expiry) invalidates the HMAC signature
- **Expiry enforcement** — the Worker checks `expires_at` against the current
  Unix timestamp on every request
- **Defence-in-depth tier limits** — even if a malicious issuer creates a
  token with claims exceeding the tier maximum, the Worker re-validates
  tier limits on every verify and rejects out-of-spec claims
- **Stateless** — no database lookup required; the Worker verifies the HMAC
  with the shared `VOUCHER_SECRET` in ~0.5ms

The `VOUCHER_SECRET` must be set as a Cloudflare Worker secret (not a plain
`[vars]` entry) and must be at least 32 bytes of high-entropy random data.

---

## Known Limitations

See whitepaper Section 11 for full discussion. The following remain as
acknowledged limitations in the current implementation:

1. **No Perfect Forward Secrecy for stored data** — if the WK is compromised,
   all past blobs encrypted under that WK are at risk. Mitigation: key rotation
   (see above).

2. **PBKDF2 instead of Argon2id** — the current KDF is PBKDF2-SHA256 at
   600K iterations, which provides computational hardness but not memory
   hardness. Argon2id is recommended for future upgrade (see README).

3. **Transport TLS is not post-quantum** — the ECDHE key exchange in TLS 1.3
   is vulnerable to Shor's algorithm. Content is AES-256 encrypted before
   transmission, so a TLS break reveals only ciphertext; but a HNDL attack
   that breaks TLS and then breaks the AES-256 (requiring 2^128 Grover
   operations) remains a theoretical future risk.

4. **Voucher ID is opaque but not anonymous** — the Worker cannot link a
   VoucherID to storage coordinates, but if the same VoucherID appears in
   multiple requests, those requests are linkable to each other. Use distinct
   vouchers per agent/project to prevent this.
