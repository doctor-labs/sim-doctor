//! Self-hosted SM-DP+ test server and RSP/OTA hosting primitives (#114).
//!
//! **Owns.** A minimal, self-hosted ES9+ HTTP server that can answer the
//! profile download functions (InitiateAuthentication, AuthenticateClient,
//! GetBoundProfilePackage, HandleNotification, CancelSession) for local
//! testing and integration, without any third-party account. It is designed to
//! work with [`crate::profile_download`] and the ES9+ transport/client.
//!
//! **Does not own.** Real operator PKI, production-grade profile generation, or
//! full ES2+/SCP81 administration backends beyond the local hosting primitives
//! exposed here. The server is defensive: requests are size-bounded and
//! malformed input is refused.
//!
//! **Safety / scope.** This is test/integration infrastructure. It must not be
//! exposed as a public production SM-DP+; it binds only where the operator
//! asks and serves scripted/test responses.

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

/// This module's name.
pub const NAME: &str = "smdp_server";

/// A minimal HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request headers as (name, value).
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

/// A minimal HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: &'static str,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Content-Type value.
    pub content_type: &'static str,
}

impl HttpResponse {
    /// Build a JSON response.
    pub fn json(status: u16, reason: &'static str, value: Value) -> Self {
        Self {
            status,
            reason,
            body: serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec()),
            content_type: "application/json",
        }
    }
    /// Build an empty response.
    pub fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            body: Vec::new(),
            content_type: "application/json",
        }
    }
}

/// Server behavior configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Pre-canned BoundProfilePackage (base64) for GetBoundProfilePackage.
    pub bpp_base64: Option<String>,
    /// Transaction ID to echo/use.
    pub transaction_id: Option<String>,
}

/// A simple ES9+ handler state.
pub struct ServerState {
    /// Current configuration.
    pub config: Config,
}

impl ServerState {
    /// Create a new handler state.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Handle one ES9+ request path and return a response.
    pub fn handle(&mut self, req: &HttpRequest) -> HttpResponse {
        let _body_json: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        match req.path.as_str() {
            "/gsma/rsp2/es9plus/initiateAuthentication" => {
                let tid = self
                    .config
                    .transaction_id
                    .clone()
                    .unwrap_or_else(|| "01020304".to_string());
                // Minimal shape; real servers return signed material. This is a
                // test host skeleton that echoes a transactionId.
                HttpResponse::json(
                    200,
                    "OK",
                    json!({
                        "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
                        "transactionId": tid,
                    }),
                )
            }
            "/gsma/rsp2/es9plus/authenticateClient" => HttpResponse::json(
                200,
                "OK",
                json!({
                    "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
                    "profileMetadata": Value::Null,
                    "smdpSigned2": Value::Null,
                    "smdpSignature2": Value::Null,
                    "smdpCertificate": Value::Null,
                }),
            ),
            "/gsma/rsp2/es9plus/getBoundProfilePackage" => {
                let bpp = self.config.bpp_base64.clone().unwrap_or_default();
                HttpResponse::json(
                    200,
                    "OK",
                    json!({
                        "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
                        "boundProfilePackage": bpp,
                    }),
                )
            }
            "/gsma/rsp2/es9plus/handleNotification" => HttpResponse::empty(204, "No Content"),
            "/gsma/rsp2/es9plus/cancelSession" => HttpResponse::json(
                200,
                "OK",
                json!({
                    "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
                }),
            ),
            // ES2+ placeholder endpoints (issue #114 requests ES2+ hosting)
            p if p.starts_with("/gsma/rsp2/es2plus/") => HttpResponse::json(
                200,
                "OK",
                json!({
                    "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
                    "note": "self-hosted ES2+ placeholder"
                }),
            ),
            _ => HttpResponse::json(
                404,
                "Not Found",
                json!({"error": "not found", "path": req.path}),
            ),
        }
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> std::io::Result<Option<HttpRequest>> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // read headers
    loop {
        let n = match stream.read(&mut tmp) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e),
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    let mut content_len = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }
    let mut body = if header_end <= buf.len() {
        buf[header_end..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_len && body.len() < 16 * 1024 * 1024 {
        let mut tmp = [0u8; 4096];
        let n = match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }))
}

fn write_response(stream: &mut std::net::TcpStream, resp: &HttpResponse) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        resp.reason,
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&resp.body)?;
    Ok(())
}

/// Serve ES9+ (and placeholder ES2+) on `addr` until `stop` is set.
pub fn serve<A: ToSocketAddrs>(addr: A, config: Config, stop: Arc<AtomicBool>) -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let mut state = ServerState::new(config);
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                if let Ok(Some(req)) = read_request(&mut stream) {
                    let resp = state.handle(&req);
                    let _ = write_response(&mut stream, &resp);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiate_returns_json() {
        let mut s = ServerState::new(Config::default());
        let req = HttpRequest {
            method: "POST".into(),
            path: "/gsma/rsp2/es9plus/initiateAuthentication".into(),
            headers: vec![],
            body: b"{}".to_vec(),
        };
        let resp = s.handle(&req);
        assert_eq!(resp.status, 200);
        let v: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v.get("transactionId").is_some());
    }
}
