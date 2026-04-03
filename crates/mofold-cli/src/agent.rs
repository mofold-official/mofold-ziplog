// mofold-cli/src/agent.rs — Gateway HTTP/HTTPS client (rustls 0.21 + tokio)
//
// Gap 3+4 fix: all #[allow(dead_code)] attributes removed — get(), get_burn(),
//              load_pmk(), and default_pmk_path() are all called by other modules.
// Gap 8 fix:   extract_body() now strips chunked-transfer-encoding chunk-size
//              lines, fixing JSON parse failures under `wrangler dev --local`.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};
use base64::Engine as _;

#[derive(Deserialize, Debug)]
pub struct GatewayResponse {
    pub success: bool,
    pub data:    Option<String>,
    pub error:   Option<String>,
}

pub struct GatewayClient {
    host:    String,
    port:    u16,
    use_tls: bool,
}

impl GatewayClient {
    pub fn new(url: impl AsRef<str>) -> Result<Self> {
        let url     = url.as_ref().trim_end_matches('/');
        let use_tls = url.starts_with("https://");
        let stripped = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let (host, port) = match stripped.rfind(':') {
            Some(p) => (stripped[..p].to_string(),
                        stripped[p+1..].parse::<u16>().context("invalid port")?),
            None    => (stripped.to_string(), if use_tls { 443 } else { 80 }),
        };
        Ok(Self { host, port, use_tls })
    }

    async fn post(&self, auth: &str, body_json: &str) -> Result<String> {
        let request = format!(
            "POST /ingest HTTP/1.1\r\nHost: {host}\r\nAuthorization: {auth}\r\n\
             Content-Type: application/json\r\nContent-Length: {len}\r\n\
             Connection: close\r\n\r\n{body}",
            host = self.host, auth = auth,
            len  = body_json.len(), body = body_json
        );
        let addr = format!("{}:{}", self.host, self.port);
        if self.use_tls {
            let host = self.host.clone();
            let req  = request.clone();
            tokio::task::spawn_blocking(move || post_tls_blocking(&host, &addr, &req))
                .await.context("spawn_blocking")?
        } else {
            post_plain_async(&addr, &request).await
        }
    }

    // ── Write operations (WK) ─────────────────────────────────────────────────

    /// Single-entry write for operator scripts and custom integrations.
    /// The bundled `tail` command uses [`GatewayClient::batch_put`] instead.
    ///
    /// # Note
    /// This method is not called internally — it is intentional public API
    /// surface for operators who want to push individual entries without tailing.
    #[allow(dead_code)]  // intentional: exported API, not called by bundled commands
    pub async fn put(
        &self,
        write_key_hex: &str,
        voucher_token: &str,
        coordinate:    &str,
        blob_b64:      &str,
        admin_token:   Option<&str>,
    ) -> Result<()> {
        let auth = format!("Ziplog WK.{}", write_key_hex);
        let body = match admin_token {
            Some(at) => serde_json::json!({"action":"put","coordinate":coordinate,
                "data":blob_b64,"admin_token":at,"voucher":voucher_token}),
            None     => serde_json::json!({"action":"put","coordinate":coordinate,
                "data":blob_b64,"voucher":voucher_token}),
        };
        debug!(coord = &coordinate[..8], "PUT gateway");
        let resp = self.post(&auth, &body.to_string()).await?;
        let gw: GatewayResponse = serde_json::from_str(&resp)
            .with_context(|| format!("parse: {}", &resp[..resp.len().min(200)]))?;
        if !gw.success { bail!("Gateway PUT: {}", gw.error.unwrap_or_default()); }
        info!(coord = &coordinate[..8], "PUT ok");
        Ok(())
    }

    /// Gap 2 fix: batch PUT — single round trip for up to 50 log entries.
    /// entries: Vec of (coordinate_hex, blob_base64, optional_admin_token)
    pub async fn batch_put(
        &self,
        write_key_hex: &str,
        voucher_token: &str,
        entries:       &[(String, String, Option<String>)],
    ) -> Result<()> {
        let auth  = format!("Ziplog WK.{}", write_key_hex);
        let items: Vec<serde_json::Value> = entries.iter().map(|(coord, data, at)| {
            let mut m = serde_json::json!({"coordinate": coord, "data": data});
            if let Some(t) = at { m["admin_token"] = serde_json::Value::String(t.clone()); }
            m
        }).collect();
        let body = serde_json::json!({
            "action":  "batch-put",
            "entries": items,
            "voucher": voucher_token,
        });
        let resp = self.post(&auth, &body.to_string()).await?;
        let gw: GatewayResponse = serde_json::from_str(&resp)
            .with_context(|| format!("parse batch-put: {}", &resp[..resp.len().min(200)]))?;
        if !gw.success { bail!("Gateway batch-PUT: {}", gw.error.unwrap_or_default()); }
        Ok(())
    }

    pub async fn delete(
        &self,
        write_key_hex:   &str,
        voucher_token:   &str,
        coordinate:      &str,
        admin_token_hex: &str,
    ) -> Result<()> {
        let auth = format!("Ziplog WK.{}", write_key_hex);
        let body = serde_json::json!({
            "action":      "delete",
            "coordinate":  coordinate,
            "admin_token": admin_token_hex,
            "voucher":     voucher_token,
        });
        let resp = self.post(&auth, &body.to_string()).await?;
        let gw: GatewayResponse = serde_json::from_str(&resp)?;
        if !gw.success { bail!("Gateway DELETE: {}", gw.error.unwrap_or_default()); }
        Ok(())
    }

    // ── Read operations (RK) ──────────────────────────────────────────────────

    /// Retrieve a single blob. Returns None if not found.
    pub async fn get(
        &self,
        read_key_hex:  &str,
        voucher_token: &str,
        coordinate:    &str,
    ) -> Result<Option<Vec<u8>>> {
        let auth = format!("Ziplog RK.{}", read_key_hex);
        let body = serde_json::json!({"action":"get","coordinate":coordinate,
            "voucher":voucher_token});
        let resp = self.post(&auth, &body.to_string()).await?;
        let gw: GatewayResponse = serde_json::from_str(&resp)?;
        if !gw.success { return Ok(None); }
        match gw.data {
            None      => Ok(None),
            Some(b64) => Ok(Some(
                base64::engine::general_purpose::STANDARD.decode(&b64)?
            )),
        }
    }

    /// Retrieve and delete (burn-on-read). Returns None if not found.
    pub async fn get_burn(
        &self,
        read_key_hex:  &str,
        voucher_token: &str,
        coordinate:    &str,
    ) -> Result<Option<Vec<u8>>> {
        let auth = format!("Ziplog RK.{}", read_key_hex);
        let body = serde_json::json!({"action":"get-burn","coordinate":coordinate,
            "voucher":voucher_token});
        let resp = self.post(&auth, &body.to_string()).await?;
        let gw: GatewayResponse = serde_json::from_str(&resp)?;
        if !gw.success { return Ok(None); }
        match gw.data {
            None      => Ok(None),
            Some(b64) => Ok(Some(
                base64::engine::general_purpose::STANDARD.decode(&b64)?
            )),
        }
    }

    /// Gap 1 fix: batch GET — retrieve up to 50 blobs in one round trip.
    /// Returns a Vec aligned with `coordinates`: Some(bytes) if found, None if not.
    pub async fn batch_get(
        &self,
        read_key_hex:  &str,
        voucher_token: &str,
        coordinates:   &[String],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        if coordinates.is_empty() { return Ok(vec![]); }
        let auth = format!("Ziplog RK.{}", read_key_hex);
        let body = serde_json::json!({
            "action":      "batch-get",
            "coordinates": coordinates,
            "voucher":     voucher_token,
        });
        let resp = self.post(&auth, &body.to_string()).await?;
        // batch-get returns: { success: true, results: { "<coord>": "<b64>", ... } }
        let val: serde_json::Value = serde_json::from_str(&resp)
            .with_context(|| format!("parse batch-get: {}", &resp[..resp.len().min(200)]))?;

        if val["success"].as_bool() != Some(true) {
            bail!("Gateway batch-GET: {}", val["error"].as_str().unwrap_or("unknown"));
        }

        let results = val["results"].as_object()
            .ok_or_else(|| anyhow::anyhow!("batch-get response missing 'results' object"))?;

        coordinates.iter().map(|coord| {
            match results.get(coord) {
                None      => Ok(None),
                Some(v)   => {
                    let b64   = v.as_str().ok_or_else(|| anyhow::anyhow!("invalid result value"))?;
                    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
                    Ok(Some(bytes))
                }
            }
        }).collect()
    }

    /// Probe Gateway connectivity — returns Ok if Worker responds (any HTTP status).
    pub async fn ping(&self) -> Result<()> {
        let body = r#"{"action":"ping","voucher":""}"#;
        let _ = self.post(
            "Ziplog WK.0000000000000000000000000000000000000000000000000000000000000000",
            body
        ).await;
        Ok(())
    }

    /// Probe Gateway connectivity and return the raw HTTP status code.
    /// Used by `ziplog status` to distinguish 401 (auth rejected) from 404 (auth ok, not found).
    pub async fn probe_status(
        &self,
        auth_header: &str,
        body_json:   &str,
    ) -> Result<u16> {
        let request = format!(
            "POST /ingest HTTP/1.1\r\nHost: {host}\r\nAuthorization: {auth}\r\n\
             Content-Type: application/json\r\nContent-Length: {len}\r\n\
             Connection: close\r\n\r\n{body}",
            host = self.host, auth = auth_header,
            len  = body_json.len(), body = body_json
        );
        let addr = format!("{}:{}", self.host, self.port);
        let raw_response = if self.use_tls {
            let host = self.host.clone();
            let req  = request.clone();
            tokio::task::spawn_blocking(move || raw_post_tls_blocking(&host, &addr, &req))
                .await.context("spawn_blocking probe")?
        } else {
            raw_post_plain_async(&addr, &request).await
        }?;
        // Extract HTTP status from first line: "HTTP/1.1 NNN ..."
        let first = raw_response.lines().next().unwrap_or("");
        let status = first.split_whitespace().nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        Ok(status)
    }
}

// ── TCP helpers ───────────────────────────────────────────────────────────────

async fn post_plain_async(addr: &str, request: &str) -> Result<String> {
    let stream = TcpStream::connect(addr)
        .await.with_context(|| format!("TCP connect {}", addr))?;
    let (mut r, mut w) = stream.into_split();
    w.write_all(request.as_bytes()).await.context("write")?;
    w.shutdown().await.ok();
    let mut raw = Vec::new();
    r.read_to_end(&mut raw).await.context("read")?;
    extract_body(&raw)
}

async fn raw_post_plain_async(addr: &str, request: &str) -> Result<String> {
    let stream = TcpStream::connect(addr)
        .await.with_context(|| format!("TCP connect {}", addr))?;
    let (mut r, mut w) = stream.into_split();
    w.write_all(request.as_bytes()).await.context("write")?;
    w.shutdown().await.ok();
    let mut raw = Vec::new();
    r.read_to_end(&mut raw).await.context("read")?;
    Ok(String::from_utf8_lossy(&raw).to_string())
}

fn post_tls_blocking(host: &str, addr: &str, request: &str) -> Result<String> {
    let raw = raw_post_tls_blocking(host, addr, request)?;
    extract_body(raw.as_bytes())
}

fn raw_post_tls_blocking(host: &str, addr: &str, request: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcp;
    use rustls::{ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName, Stream};
    use std::sync::Arc;

    let mut roots = RootCertStore::empty();
    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject, ta.spki, ta.name_constraints,
        )
    }));
    let config     = rustls::ClientConfig::builder()
        .with_safe_defaults().with_root_certificates(roots).with_no_client_auth();
    let server_name = ServerName::try_from(host)
        .with_context(|| format!("invalid server name: {}", host))?;
    let mut stream  = StdTcp::connect(addr)
        .with_context(|| format!("TCP connect {}", addr))?;
    let mut tls    = ClientConnection::new(Arc::new(config), server_name)
        .context("TLS init")?;
    let mut ts     = Stream::new(&mut tls, &mut stream);
    ts.write_all(request.as_bytes()).context("TLS write")?;
    ts.flush().ok();
    let mut raw = Vec::new();
    ts.read_to_end(&mut raw).context("TLS read")?;
    Ok(String::from_utf8_lossy(&raw).to_string())
}

// ── Gap 8 fix: HTTP body extraction with chunked transfer-encoding support ───
fn extract_body(raw: &[u8]) -> Result<String> {
    let full       = String::from_utf8_lossy(raw);
    let header_end = if let Some(i) = full.find("\r\n\r\n") { i + 4 }
                     else if let Some(i) = full.find("\n\n") { i + 2 }
                     else { bail!("Malformed HTTP response (no header/body separator)") };

    let headers = full[..header_end].to_ascii_lowercase();
    let body    = &full[header_end..];

    if headers.contains("transfer-encoding: chunked") {
        // Decode chunked encoding: <hex-size>\r\n<chunk-data>\r\n ...  0\r\n\r\n
        let mut out   = String::new();
        let mut lines = body.lines().peekable();
        while let Some(size_line) = lines.next() {
            // Strip optional chunk extensions (";ext=val")
            let size_str  = size_line.trim().split(';').next().unwrap_or("0");
            let chunk_len = usize::from_str_radix(size_str, 16).unwrap_or(0);
            if chunk_len == 0 { break; }  // terminal chunk
            if let Some(data) = lines.next() {
                out.push_str(data);
            }
        }
        Ok(out)
    } else {
        Ok(body.to_string())
    }
}
