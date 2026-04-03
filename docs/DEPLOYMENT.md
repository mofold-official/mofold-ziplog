# MofoldZiplog — Production Deployment Guide

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust | ≥ 1.75 (1.85+ for Argon2id upgrade) | Build `ziplog` binary |
| Node.js | ≥ 18 | Wrangler CLI for Worker deployment |
| Wrangler | ≥ 3.95 | Cloudflare Worker deploy tool |
| Cloudflare account | — | Workers + R2 + Durable Objects |

---

## Step 1 — Build the CLI

```bash
git clone https://github.com/your-org/mofold-ziplog
cd mofold-ziplog
cargo build --release
sudo cp target/release/ziplog /usr/local/bin/ziplog
ziplog --version
```

---

## Step 2 — Initialise a project (air-gapped machine recommended)

```bash
# Generate a secure passphrase and store it in your password manager
PASSPHRASE=$(openssl rand -base64 32)

ziplog init \
  --project-id "my-service-prod" \
  --passphrase "$PASSPHRASE" \
  --pmk-file /secure/path/my-service.ziplog-pmk

# The command outputs:
#   READ KEY  (RK): <64 hex chars>  → add to ZIPLOG_READ_KEY env
#   WRITE KEY (WK): <64 hex chars>  → add to ZIPLOG_WRITE_KEY env
```

**Keep the PMK file and passphrase offline.** The PMK file is encrypted with
AES-256-GCM, but it should still be stored on air-gapped media or in an HSM.
The RK and WK hex strings are the only values that need to be online.

---

## Step 3 — Deploy the Gateway Worker

```bash
cd gateway
npm install

# Create the R2 bucket
wrangler r2 bucket create mofold-ziplog

# Set secrets (never put these in wrangler.toml)
wrangler secret put PEPPER
# Paste: $(openssl rand -hex 32)   e.g. a3f8c2d1...

wrangler secret put VOUCHER_SECRET
# Paste: $(openssl rand -base64 32)  — must match what ziplog voucher uses

# Verify secrets are set
wrangler secret list

# Deploy
wrangler deploy

# Output: https://mofold-ziplog-gateway.<your-subdomain>.workers.dev
```

### Restrict CORS (required for production)

The Worker reads `ALLOWED_ORIGIN` from its environment at runtime —
**do not hardcode the domain in `worker.ts`**. Set it as a secret:

```bash
wrangler secret put ALLOWED_ORIGIN
# Paste: https://app.your-company.com
```

The secret is applied immediately after the Worker is redeployed or
the secret is updated. No source file changes are needed.

---

## Step 4 — Issue vouchers

```bash
export ZIPLOG_VOUCHER_SECRET="<same value as VOUCHER_SECRET set in Worker>"

# Free tier — for development/staging
ziplog voucher \
  --tier free \
  --valid-hours 168 \
  --quota-mb 50 \
  --rps 5

# Paid tier — for production log agents
ziplog voucher \
  --tier paid \
  --valid-hours 8760 \
  --quota-mb 0 \
  --rps 100

# Copy the output token — it starts with FREE- or PAID-
```

---

## Step 5 — Deploy log shipping agent

On each server that ships logs:

```bash
# Create environment file (never commit to git)
cat > /etc/ziplog/env << EOF
ZIPLOG_PROJECT_ID=my-service-prod
ZIPLOG_WRITE_KEY=<WK hex from Step 2>
ZIPLOG_VOUCHER=<PAID- token from Step 4>
ZIPLOG_GATEWAY_URL=https://mofold-ziplog-gateway.<subdomain>.workers.dev
EOF
chmod 600 /etc/ziplog/env

# Systemd service
cat > /etc/systemd/system/ziplog-tail.service << EOF
[Unit]
Description=MofoldZiplog log shipping agent
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/ziplog/env
ExecStart=/usr/local/bin/ziplog tail \
  --file /var/log/my-service/app.log \
  --project-id \${ZIPLOG_PROJECT_ID} \
  --write-key \${ZIPLOG_WRITE_KEY} \
  --voucher \${ZIPLOG_VOUCHER} \
  --gateway \${ZIPLOG_GATEWAY_URL}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now ziplog-tail
journalctl -u ziplog-tail -f
```

---

## Step 6 — Verify end-to-end

```bash
# Encrypt and ship a test message
export ZIPLOG_WRITE_KEY="<WK hex>"
export ZIPLOG_PROJECT_ID="my-service-prod"
export ZIPLOG_VOUCHER="<PAID- token>"

BLOB=$(ziplog encrypt \
  --message "test log entry $(date)" \
  --write-key "$ZIPLOG_WRITE_KEY" \
  --project-id "$ZIPLOG_PROJECT_ID" \
  --sequence 999999 \
  --show-coord)

echo "$BLOB"

# Decrypt it back
ziplog decrypt \
  --blob "$(echo "$BLOB" | tail -1)" \
  --write-key "$ZIPLOG_WRITE_KEY"
```

---

## Environment Variables Reference

### Agent (`ziplog tail`)

| Variable | Required | Description |
|---|---|---|
| `ZIPLOG_PROJECT_ID` | Yes | Project identifier (used in coordinate derivation) |
| `ZIPLOG_WRITE_KEY` | Yes | WriteKey hex from `ziplog init` |
| `ZIPLOG_VOUCHER` | Yes | Signed voucher token from `ziplog voucher` |
| `ZIPLOG_GATEWAY_URL` | Yes | Worker URL (also via `--gateway` flag) |
| `ZIPLOG_PMK_PASSPHRASE` | No | PMK file passphrase (for `ziplog init` only) |

### Worker (Cloudflare secrets)

| Secret | Required | Description |
|---|---|---|
| `PEPPER` | Yes | 32+ random hex bytes. Never rotated (rotation invalidates all R2 keys) |
| `VOUCHER_SECRET` | Yes | Shared secret for HMAC voucher signing. Rotation invalidates all issued vouchers |

### CLI operator

| Variable | Used by | Description |
|---|---|---|
| `ZIPLOG_VOUCHER_SECRET` | `ziplog voucher` | Must match Worker `VOUCHER_SECRET` |

---

## Monitoring

### Worker metrics (Cloudflare Dashboard)

Navigate to Workers & Pages → mofold-ziplog-gateway → Metrics:

- **Request count** — total requests per minute
- **Error rate** — 4xx/5xx responses (spikes indicate auth failures or rate limiting)
- **CPU time** — should stay well under 50ms average
- **Durable Object requests** — rate limiter + burn-lock activity

### Key metrics to alert on

| Metric | Alert threshold | Likely cause |
|---|---|---|
| 401 errors > 1% | HMAC failures | Voucher secret mismatch or expired tokens |
| 403 errors > 0.1% | Role violations | Agent using wrong key type (WK for reads) |
| 429 errors > 5% | Rate limit hits | Agent too aggressive; increase tier or reduce rate |
| CPU time > 40ms | Worker near limit | Increase batch size in agent; reduce R2 call count |
| DO error rate > 0% | DO eviction | Check Cloudflare DO region health |

### Agent logs

```bash
journalctl -u ziplog-tail --since "1 hour ago" | grep -E "ERROR|WARN|Batch shipped"
```

Expected output every few seconds:
```
INFO ziplog_agent: Batch shipped shipped=15 next_seq=1234
```

---

## PEPPER Rotation

The PEPPER is applied to all coordinate→R2 key mappings. **Rotating the PEPPER
invalidates all existing R2 keys** — stored blobs become permanently unreachable.

If you must rotate PEPPER:
1. Export all blobs (using batch-get with old RK+PEPPER configuration)
2. Decrypt each blob
3. Set new PEPPER in Worker
4. Re-encrypt and re-upload all blobs
5. Delete old blobs

This is a maintenance window operation. Keep PEPPER rotation extremely rare —
ideally never after initial deployment.

## Sequence Sidecar File (.ziplog-seq)

The `ziplog tail` command creates a `.ziplog-seq` file alongside the tailed log
file (e.g. `app.log` → `app.log.ziplog-seq`). This file stores the next sequence
number and is read on startup for crash-recovery.

**Preserve this file during log rotation.** If your `logrotate` config uses
`create` (the default — rename old file, create new one), the sidecar will
survive alongside the old log file. If you use `copytruncate` (truncates in
place), the sidecar is preserved automatically.

**Do not delete the sidecar** unless you intend to restart the sequence from 0.
Restarting from 0 will re-ship any logs from before the sequence was reset —
they will be stored under new coordinates (different sequence → different
coordinate), so no data is overwritten, but auditors may see duplicate content.

Add to your `.gitignore`:
```
*.ziplog-seq
```

## VOUCHER_SECRET Rotation

1. Generate new secret: `openssl rand -base64 32`
2. Update Worker secret: `wrangler secret put VOUCHER_SECRET`
3. Re-issue all vouchers with new secret
4. Update all agents with new vouchers
5. Old vouchers will fail validation immediately after Worker redeploy

---

## Cloudflare Plan Requirements

| Feature | Required plan |
|---|---|
| Workers | Free (up to 100k requests/day) or Paid |
| R2 | Paid (R2 has 10 GB free storage/month) |
| Durable Objects | Workers Paid plan ($5/month) |
| Custom domain | Any paid plan |
