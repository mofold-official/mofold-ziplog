# Binary Desert Protocol v2 — Formal Specification

**Document status:** Normative reference  
**Version:** 2.0  
**Replaces:** BDP v1 (TypeScript implementation, PBKDF2 @ 600K, no key hierarchy)

---

## 1. Overview

The Binary Desert Protocol (BDP) defines a zero-identity encrypted data
storage system. Data is addressed by cryptographic coordinates derived from
access credentials rather than from user identifiers or content hashes.
The storage layer is designed to be indistinguishable from an unstructured
binary store ("desert") to any party that does not hold the correct credentials.

### 1.1 Design Goals

1. **Zero-identity** — the storage operator cannot link stored objects to user identities.
2. **Content confidentiality** — stored objects are AES-256 encrypted; the operator cannot read plaintext.
3. **Coordinate opacity** — storage addresses are computationally unlinkable to credentials without a server-side secret.
4. **Role separation** — read and write capabilities are cryptographically distinct.
5. **Memory safety** — key material is erased from memory immediately after use.
6. **Constant-time security** — all credential comparisons execute in time independent of value.
7. **Quantum resistance** — exclusively symmetric primitives; no asymmetric operations.

### 1.2 Scope

This specification covers:
- Key hierarchy derivation (§3)
- Coordinate derivation functions (§4)
- Binary envelope format (§5)
- Double-layer encryption pipeline (§6)
- Voucher token format (§7)
- Gateway protocol (§8)

---

## 2. Notation and Primitives

| Symbol | Definition |
|--------|-----------|
| `\|\|` | Byte concatenation |
| `HMAC(K, M)` | HMAC-SHA256 with key K over message M |
| `PBKDF2(P, S, c)` | PBKDF2-HMAC-SHA256, password P, salt S, c iterations, 32-byte output |
| `AES-GCM(K, IV, M)` | AES-256-GCM encryption, 12-byte IV, 128-bit tag appended |
| `AES-GCM⁻¹(K, IV, C)` | AES-256-GCM decryption + authentication; rejects if tag invalid |
| `AES-CBC(K, IV, M)` | AES-256-CBC encryption with PKCS#7 padding, 16-byte IV |
| `AES-CBC⁻¹(K, IV, C)` | AES-256-CBC decryption + PKCS#7 unpad |
| `SHA256(M)` | SHA-256 hash of M |
| `CSPRNG(n)` | n bytes from a cryptographically secure pseudo-random generator |
| `CT_EQ(A, B)` | Constant-time byte equality (XOR accumulator) |
| `hex(B)` | Lower-case hexadecimal encoding of byte array B |
| `b64url(B)` | URL-safe Base64 encoding of B, no padding |

---

## 3. Key Hierarchy

### 3.1 Project Master Key (PMK)

The PMK is a 32-byte secret generated offline. It MUST NOT be transmitted
over any network. It MAY be stored encrypted at rest (see §3.4).

```
PMK ∈ {0,1}^256
```

### 3.2 Derived Keys

Two operational keys are derived from the PMK via HMAC with distinct domain labels:

```
ReadKey  (RK) = HMAC(PMK, "BDP-READ-KEY-v2")     [32 bytes]
WriteKey (WK) = HMAC(PMK, "BDP-WRITE-KEY-v2")    [32 bytes]
```

**Properties:**
- RK ≠ WK with overwhelming probability.
- Knowing RK does not reveal WK or PMK (HMAC preimage resistance).
- Knowing WK does not reveal RK or PMK.
- Both RK and WK are deterministically derivable from PMK.

### 3.3 Key Roles

| Key | Permitted operations | Forbidden operations |
|-----|---------------------|---------------------|
| PMK | Derive RK and WK | Any network operation |
| WK  | PUT (write), DELETE | GET (read) |
| RK  | GET (read), batch-get | PUT (write), DELETE |

The Gateway MUST reject:
- GET requests presenting a WK-signed Authorization header
- PUT/DELETE requests presenting an RK-signed Authorization header

### 3.4 PMK Encryption at Rest

When persisted, the PMK is wrapped with AES-256-GCM under a key derived from
a user passphrase:

```
salt   = CSPRNG(16)
iv     = CSPRNG(12)
wrap_k = PBKDF2(passphrase, salt, 600_000)
ct     = AES-GCM(wrap_k, iv, PMK)

file   = "ZIPLOGPM" || salt || iv || ct
```

File size: 8 + 16 + 12 + 32 + 16 = **84 bytes**.

---

## 4. Coordinate Derivation

A **coordinate** is a 32-byte value that identifies a storage location.
Coordinates are derived using HMAC-SHA256 with domain separation.
All coordinate functions take WK as the HMAC key.

### 4.1 Coordinate Function Family

```
coord(WK, parts...) = HMAC(WK, domain || ":" || part₁ || ":" || part₂ || ...)
```

| Function | Domain | Parts |
|----------|--------|-------|
| vault_coord | `BDP:VAULT-COORD-v2` | project_id |
| fold_coord | `BDP:FOLD-COORD-v2` | fold_key, vault_coord |
| log_coord | `BDP:LOG-COORD-v2` | project_id, seq_be64 |
| manifest_coord | `BDP:MANIFEST-COORD-v2` | channel_key |
| invite_coord | `BDP:INVITE-COORD-v2` | invite_key, channel_key, namespace |

Where `seq_be64` is the sequence number encoded as 8-byte big-endian unsigned integer.

### 4.2 Namespace Isolation

Including `vault_coord` in `fold_coord` ensures that two different projects
using the same fold key derive different storage coordinates:

```
fold_coord(WK, "same-key", vault_A) ≠ fold_coord(WK, "same-key", vault_B)
```

The namespace string ("ROOM" or "LOCKER") in invite_coord prevents invite keys
from colliding across platform modules.

### 4.3 Server-Side Pepering

The Gateway transforms client-supplied coordinates before storage:

```
r2_key = hex(SHA256(coordinate_hex || ":" || PEPPER))
```

`PEPPER` is a server-side secret. An adversary who knows the coordinate
derivation algorithm and all user inputs cannot determine the R2 storage key
without knowledge of PEPPER.

### 4.4 Coordinate Comparison

All comparisons of coordinates MUST use the constant-time equality function:

```
CT_EQ(A, B) = (⊕ᵢ Aᵢ XOR Bᵢ) == 0
```

This prevents timing side channels that could reveal whether a coordinate
guess was "close" to a valid coordinate.

---

## 5. Binary Envelope Format

Every BDP object (a **Fold**) consists of a fixed 64-byte header followed by
a variable-length encrypted payload.

### 5.1 Header Layout

```
Offset  Length  Field
──────  ──────  ─────────────────────────────────────────────────────────────
0       1       Version        Protocol version byte (0x02 for BDP v2)
1       1       BlobType       Object type (see §5.2)
2       32      AdminHash      SHA256(admin_token); all-zero = open-write
34      16      Salt1          Random salt for GCM key derivation
50      12      IV1            Random IV for AES-256-GCM
62      2       PayloadLen     Big-endian u16; 0 = "read to end of blob"
64      ...     Payload        Encrypted payload (see §5.3)
```

### 5.2 Blob Types

| Value | Type | Description |
|-------|------|-------------|
| 0x01 | VAULT | Root encrypted vault manifest |
| 0x02 | FOLD | Individual encrypted data fold |
| 0x03 | ROOM | Shared room/channel manifest |
| 0x04 | INVITE | Channel invitation blob |
| 0x05 | LOG | Log entry (BDP v2 / MofoldZiplog) |

### 5.3 Payload Layout

```
Offset  Length  Field
──────  ──────  ────────────────────────────────────
0       16      Salt2       Random salt for CBC key derivation
16      16      IV2         Random IV for AES-256-CBC
32      ...     Ciphertext  AES-CBC(AES-GCM(plaintext))
```

The combined header + payload form the complete wire blob stored in R2.

### 5.4 PayloadLen Sentinel

When `PayloadLen == 0`, the receiver MUST use `blob.len() - 64` as the
payload length. This is required for payloads exceeding 65535 bytes
(the maximum representable in a u16).

### 5.5 AdminHash and Write-Lock

The `AdminHash` field enables write-lock enforcement without server-side
key knowledge:

- **Protected blob** (`AdminHash ≠ 0x00*32`): The Gateway verifies
  `CT_EQ(AdminHash, SHA256(provided_admin_token))` before allowing
  overwrite or deletion.
- **Open-write blob** (`AdminHash == 0x00*32`): Any authenticated
  request may overwrite. Used for shared room manifests.

---

## 6. Double-Layer Encryption Pipeline

### 6.1 Key Derivation Per Layer

```
Layer-1 key: K₁ = PBKDF2(key_material,          salt1, 600_000)
Layer-2 key: K₂ = PBKDF2(key_material||"_layer2", salt2, 600_000)
```

The `"_layer2"` suffix ensures K₁ and K₂ are cryptographically independent
even when derived from the same `key_material`. This is domain separation
per NIST SP 800-108.

### 6.2 Encryption

```
Input: plaintext M, key_material K

salt1, iv1 = CSPRNG(16), CSPRNG(12)
salt2, iv2 = CSPRNG(16), CSPRNG(16)

K₁ = PBKDF2(K, salt1, 600_000)
C₁ = AES-GCM(K₁, iv1, M)         # Layer 1: authenticated encryption

K₂ = PBKDF2(K||"_layer2", salt2, 600_000)
C₂ = AES-CBC(K₂, iv2, C₁)        # Layer 2: diffusion

payload = salt2 || iv2 || C₂
blob    = pack_envelope(BlobType, AdminHash, salt1, iv1, payload)
```

### 6.3 Decryption

```
Input: blob, key_material K

(header, payload) = unpack_envelope(blob)
salt2, iv2, C₂   = payload[0:16], payload[16:32], payload[32:]

K₂ = PBKDF2(K||"_layer2", salt2, 600_000)
C₁ = AES-CBC⁻¹(K₂, iv2, C₂)      # Layer 2: reverse diffusion

K₁ = PBKDF2(K, header.salt1, 600_000)
M  = AES-GCM⁻¹(K₁, header.iv1, C₁)  # Layer 1: authenticate + decrypt
                                       # Aborts if GCM tag invalid
```

### 6.4 Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256 (both layers) |
| Integrity | GCM authentication tag (Layer 1) |
| Non-malleability | GCM tag rejects any bit flip in C₁ |
| Key independence | PBKDF2 domain separation ("_layer2") |
| IV uniqueness | CSPRNG per encryption; collision probability < 2⁻⁶⁴ |
| Memory erasure | K₁, K₂ in Zeroizing wrappers; zeroed on drop |

### 6.5 Layer Interaction Security

Assume an adversary who can break AES-CBC with probability p_cbc and
AES-GCM with probability p_gcm. The probability of breaking both layers
under independent keys is at most p_cbc × p_gcm. This is substantially
stronger than either primitive alone.

---

## 7. Voucher Token Format

### 7.1 Structure

```
token = TIER "-" b64url(JSON(claims)) "." hex(HMAC(server_secret, signing_input))

where:
  signing_input = TIER "-" b64url(JSON(claims))
  TIER          = "FREE" | "PAID"
```

### 7.2 Claims JSON

```json
{
  "voucher_id":    "<opaque string>",
  "tier":          "FREE" | "PAID",
  "issued_at":     <unix timestamp>,
  "expires_at":    <unix timestamp>,
  "quota_bytes":   <u64, 0 = unlimited>,
  "rate_limit_rps": <u32>
}
```

### 7.3 Tier Constraints

| Parameter | FREE | PAID |
|-----------|------|------|
| Max `rate_limit_rps` | 5 | 500 |
| Max `quota_bytes` | 52,428,800 (50 MiB) | Unlimited (0) |
| Max `expires_at - issued_at` | 2,592,000 s (30 days) | 31,536,000 s (365 days) |

The Gateway MUST re-validate tier constraints on every request, regardless
of what the signed claims contain. This is defence-in-depth against a
compromised voucher issuer.

### 7.4 Verification Algorithm

```
1. Split token at last "."
2. signing_input = token[0 .. last_dot]
3. provided_hmac = token[last_dot+1 ..]
4. expected_hmac = HMAC(server_secret, signing_input)
5. Verify: CT_EQ(expected_hmac, provided_hmac)  [reject if false]
6. Decode claims = JSON(b64url_decode(signing_input after first "-"))
7. Verify: now_unix ≤ claims.expires_at         [reject if false]
8. Verify: claims.rate_limit_rps ≤ tier max_rps [reject if false]
```

Step 5 MUST use constant-time comparison.

---

## 8. Gateway HTTP Protocol

### 8.1 Endpoint

```
POST /ingest
Content-Type: application/json
Authorization: Ziplog <ROLE>.<KEY_HEX>
```

Where:
- `<ROLE>` = `RK` or `WK`
- `<KEY_HEX>` = 64 lower-case hex characters (32 bytes)

### 8.2 Request Actions

#### PUT

```json
{
  "action":      "put",
  "coordinate":  "<64 hex chars>",
  "data":        "<base64 blob>",
  "admin_token": "<hex admin token, optional>",
  "voucher":     "<voucher token>"
}
```

**Pre-conditions:**
- Authorization role MUST be `WK`
- Blob MUST be ≥ 64 bytes (envelope minimum)
- Blob MUST be ≤ 10 MiB
- Rate limit check (per-voucher sliding window) MUST pass
- If `coordinate` exists in R2 with non-zero AdminHash:
  `CT_EQ(stored.AdminHash, SHA256(admin_token))` MUST be true

**Effect:** Store blob at `r2_key = hex(SHA256(coordinate || ":" || PEPPER))`

#### GET

```json
{
  "action":     "get",
  "coordinate": "<64 hex chars>",
  "voucher":    "<voucher token>"
}
```

**Pre-conditions:**
- Authorization role MUST be `RK`
- Rate limit check MUST pass

**Response on success:**
```json
{ "success": true, "data": "<base64 blob>" }
```

#### GET-BURN (atomic retrieve + delete)

Same as GET but:
1. Acquires a Durable Object lock on the coordinate
2. Returns 409 if lock cannot be acquired (concurrent burn in progress)
3. Deletes the blob after successful retrieval
4. Releases lock unconditionally (even on error)

#### DELETE

```json
{
  "action":      "delete",
  "coordinate":  "<64 hex chars>",
  "admin_token": "<hex admin token>",
  "voucher":     "<voucher token>"
}
```

**Pre-conditions:**
- Authorization role MUST be `WK`
- `admin_token` MUST satisfy write-lock check

#### BATCH-GET

```json
{
  "action":      "batch-get",
  "coordinates": ["<hex>", ...],
  "voucher":     "<voucher token>"
}
```

Up to 50 coordinates per request. Role MUST be `RK`.
Response: `{ "success": true, "results": { "<coord>": "<base64>", ... } }` — missing coordinates are absent from the map.

#### BATCH-PUT

```json
{
  "action":  "batch-put",
  "entries": [
    { "coordinate": "<64 hex>", "data": "<base64 blob>", "admin_token": "<optional hex>" },
    ...
  ],
  "voucher": "<voucher token>"
}
```

Up to 50 entries per request. Role MUST be `WK`.
All R2 writes execute in parallel via `Promise.all`. Rate limiting is charged once for the whole batch.
Response: `{ "success": true, "written": N }`.

### 8.3 Response Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success |
| 400 | Malformed request |
| 401 | Missing or invalid Authorization or voucher |
| 403 | Role violation or AdminHash mismatch |
| 404 | Coordinate not found |
| 409 | Burn-lock contention |
| 413 | Blob exceeds size limit |
| 429 | Rate limit exceeded |

### 8.4 Execution Time Budget

Target: **≤ 50ms** per request (Cloudflare Worker CPU limit).

| Step | Budget |
|------|--------|
| Voucher HMAC verify | ≤ 1ms |
| Coordinate pepper hash | ≤ 1ms |
| Durable Object rate check | ≤ 5ms |
| R2 PUT (10 KB) | ≤ 20ms |
| R2 GET | ≤ 15ms |
| Response serialisation | ≤ 1ms |
| **Total (worst case)** | **≤ 43ms** |

---

## 9. Security Considerations

### 9.1 Coordinate Oracle

An implementation that distinguishes "coordinate exists" from "coordinate does
not exist" via different response timing or error messages creates an oracle
that enables account enumeration. The Gateway MUST:

- Return identical HTTP status (404) for "not found" regardless of whether
  the coordinate derivation is valid
- Apply rate limiting before checking coordinate existence
- Use constant-time HMAC verification for voucher tokens

### 9.2 Key Material Lifetime

All key material (K₁, K₂, WK bytes used in encryption) MUST be:
1. Held in memory structures that implement `ZeroizeOnDrop` (Rust) or equivalent
2. Erased immediately after the cryptographic operation completes
3. Never written to disk, swap, or logged

### 9.3 PEPPER Confidentiality

The PEPPER is the only secret that prevents an adversary with full R2 bucket
access from mounting offline dictionary attacks on coordinates. It MUST be:
- ≥ 256 bits (32 bytes) of CSPRNG output
- Stored only in the Worker's secret environment (not in wrangler.toml)
- Never rotated after first deployment (rotation requires blob migration)

### 9.4 Quantum Security Analysis

| Primitive | Quantum attack | Effective security |
|-----------|---------------|-------------------|
| AES-256-GCM | Grover (search) | 2¹²⁸ operations |
| AES-256-CBC | Grover (search) | 2¹²⁸ operations |
| PBKDF2-SHA256 | Grover (search) | 2¹²⁸ operations |
| HMAC-SHA256 | Grover (collision) | 2¹²⁸ operations |
| TLS 1.3 ECDHE | Shor | **BROKEN** (transport only) |

The content encryption is quantum-safe. The transport layer (ECDHE in TLS 1.3)
is vulnerable to Shor's algorithm. Since content is pre-encrypted before
transmission, breaking TLS reveals only ciphertext. Harvest-now-decrypt-later
(HNDL) attacks on the transport layer yield AES-256 ciphertext, which remains
secure against Grover's algorithm.

---

## 10. Changes from BDP v1

| Feature | v1 (TypeScript) | v2 (Rust/MofoldZiplog) |
|---------|-----------------|----------------------|
| Key hierarchy | Single access key | PMK → RK / WK |
| Coordinate hash | SHA-256(key) | HMAC-SHA256(WK, domain\|\|parts) |
| Rate limiting | In-memory (per Worker instance) | Durable Objects (durable, consistent) |
| Admin token compare | `ring::constant_time::verify_slices_are_equal` (now deprecated) | `ct_eq_32()` — inline XOR accumulator in `crypto.rs` (no external dep) |
| Burn-on-read atomicity | Non-atomic GET + DELETE | DO-locked atomic sequence |
| Memory safety | Manual `.fill(0)` (not always called) | `ZeroizeOnDrop` on all key types |
| Blob type | 4 types | 5 types (added LOG = 0x05) |
| PayloadLen sentinel | Not defined | 0 = "read to end" for large payloads |
| Voucher system | None | HMAC-signed stateless tokens |
