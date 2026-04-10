# MofoldZiplog — Production Deployment Guide

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust | ≥ 1.75 (1.85+ for Argon2id upgrade) | Build `ziplog` binary |
| Git | any | Clone the repository |

---

## Step 1 — Build the CLI

```bash
git clone https://github.com/mofold-official/mofold-ziplog
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
  --passphrase "$PASSPHRASE"

# The command outputs:
#   READ KEY  (RK): <64 hex chars>  → add to ZIPLOG_READ_KEY env
#   WRITE KEY (WK): <64 hex chars>  → add to ZIPLOG_WRITE_KEY env
#   .ziplog-pmk file created in current directory
```

**Keep the PMK file and passphrase offline.** The PMK file is encrypted with
AES-256-GCM, but it should still be stored on air-gapped media or in a
password manager. The RK and WK hex strings are the only values that need
to be online.

---

## Step 3 — Get your Gateway access

The MofoldZiplog Gateway is operated as a managed service.

**Managed (recommended)**

1. Sign up at **https://mofold.com** and choose your plan
2. Copy your voucher token from the dashboard
3. Set your environment:

```bash
export ZIPLOG_GATEWAY_URL="https://mofold-ziplog-gateway.mofold-official.workers.dev"
export ZIPLOG_VOUCHER="FREE-eyJ..."   # from your mofold.com dashboard
```

**Enterprise self-hosting**

Gateway source code access is available on the Enterprise plan,
allowing you to deploy on your own Cloudflare account with your own
R2 bucket and secrets. See **https://mofold.com/pricing** for details.

---

## Step 4 — Issue vouchers (self-hosted enterprise only)

If you are running your own gateway, you issue vouchers using the CLI
with your own `VOUCHER_SECRET`:

```bash
export ZIPLOG_VOUCHER_SECRET="<same value as VOUCHER_SECRET set in your Worker>"

ziplog voucher \
  --tier free \
  --server-secret "$ZIPLOG_VOUCHER_SECRET"

# Copy the output token — it starts with FREE- or PAID-
```

For available tiers, quota limits, and rate options, run:
```bash
ziplog voucher --help
```

For the managed service, vouchers are issued automatically by
mofold.com when you sign up or renew. Visit **https://mofold.com**
for plan details.

---

## Step 5 — Deploy log shipping agent

On each server that ships logs:

```bash
# Create environment file (never commit to git)
cat > /etc/ziplog/env << EOF
ZIPLOG_PROJECT_ID=my-service-prod
ZIPLOG_WRITE_KEY=<WK hex from Step 2>
ZIPLOG_VOUCHER=<token from Step 3 or Step 4>
ZIPLOG_GATEWAY_URL=https://mofold-ziplog-gateway.mofold-official.workers.dev
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
export ZIPLOG_WRITE_KEY="<WK hex>"
export ZIPLOG_PROJECT_ID="my-service-prod"
export ZIPLOG_VOUCHER="<token>"
export ZIPLOG_GATEWAY_URL="https://mofold-ziplog-gateway.mofold-official.workers.dev"

# Encrypt and ship a test message
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
| `ZIPLOG_VOUCHER` | Yes | Signed voucher token |
| `ZIPLOG_GATEWAY_URL` | Yes | Worker URL (also via `--gateway` flag) |

### CLI operator (self-hosted enterprise only)

| Variable | Used by | Description |
|---|---|---|
| `ZIPLOG_VOUCHER_SECRET` | `ziplog voucher` | Must match your Worker's `VOUCHER_SECRET` |

---

## Monitoring

### Gateway metrics (managed service)

Usage statistics including quota consumed, requests made, and expiry date
are visible in your **https://mofold.com** dashboard.

### Agent logs

```bash
journalctl -u ziplog-tail --since "1 hour ago" | grep -E "ERROR|WARN|Batch shipped"
```

Expected output every few seconds:
```
INFO ziplog_agent: Batch shipped shipped=15 next_seq=1234
```

### Key metrics to watch

| Metric | Alert threshold | Likely cause |
|---|---|---|
| 401 errors | any | Voucher secret mismatch or expired token |
| 403 errors | any | Agent using wrong key type (WK for reads) |
| 429 errors | sustained | Rate limit hit — contact mofold.com to review your plan |

---

## Sequence Sidecar File (.ziplog-seq)

The `ziplog tail` command creates a `.ziplog-seq` file alongside the tailed
log file (e.g. `app.log` → `app.log.ziplog-seq`). This file stores the next
sequence number for crash recovery.

**Preserve this file during log rotation.** If deleted, `tail` restarts the
sequence from 0 and re-ships existing logs under new coordinates.

Add to your `.gitignore`:
```
*.ziplog-seq
```

---

## Annual Token Renewal

Voucher tokens issued via the managed service are valid for one year.
When your subscription renews, a new token is available in your
**https://mofold.com** dashboard. Update your environment:

```bash
# Update the value in /etc/ziplog/env
ZIPLOG_VOUCHER=<new token from dashboard>

# Restart the agent to pick up the new token
systemctl restart ziplog-tail
```

The old token remains valid until its `expires_at` timestamp,
giving you a grace period to update all agents.

---

## PEPPER Rotation (Enterprise self-hosting only)

The PEPPER is applied to all coordinate→R2 key mappings. **Rotating the
PEPPER invalidates all existing R2 keys** — stored blobs become permanently
unreachable.

If you must rotate PEPPER:
1. Export all blobs via batch-get with the old configuration
2. Decrypt each blob
3. Set the new PEPPER in the Worker
4. Re-encrypt and re-upload all blobs
5. Delete the old blobs

Keep PEPPER rotation extremely rare — ideally never after initial deployment.

## VOUCHER_SECRET Rotation (Enterprise self-hosting only)

1. Generate a new secret: `openssl rand -hex 32`
2. Update the Worker secret: `wrangler secret put VOUCHER_SECRET`
3. Re-issue all vouchers with the new secret
4. Update all agents with the new vouchers

Old vouchers fail validation immediately after the Worker redeploys.
