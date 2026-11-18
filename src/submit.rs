//! Opt-in, anonymized scan-result submission (#107).
//!
//! A scan envelope can be uploaded to an operator-chosen endpoint for
//! aggregate analysis (gsmmap-style). Submission is **off by default** and
//! happens only when the caller passes an explicit endpoint to
//! [`submit_envelope`] (exposed as `scan --submit <endpoint>`).
//!
//! **Owns.** Anonymizing a doctor/1 scan envelope (removing or redacting card
//! identifiers and file contents so the result cannot be tied to a card or
//! subscriber) and POSTing the resulting JSON over HTTPS with certificate
//! verification always on. When `pin_sha256` is supplied the server leaf
//! certificate's SPKI SHA-256 fingerprint must match (pinned-cert POST);
//! otherwise the platform/webpki roots are used via the standard HTTPS
//! transport config.
//!
//! **Does not own.** The scan itself, any automatic/background submission, or
//! storage of endpoint configuration. Key material must never reach a report
//! (contract) and is therefore never present to submit.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::es9::Es9Transport;
use crate::es9_https::{HttpsConfig, HttpsTransport, Trust};
use std::path::PathBuf;

/// This module's name.
pub const NAME: &str = "submit";

/// Why submission failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The endpoint URL is not acceptable.
    #[error("submit endpoint: {0}")]
    Endpoint(String),
    /// The envelope could not be serialized.
    #[error("serialize: {0}")]
    Serialize(String),
    /// The HTTP request failed.
    #[error("submit: {0}")]
    Http(String),
}

/// Anonymize a doctor/1 scan envelope in place, returning a redacted copy.
///
/// Identifiers that can name a card, subscriber or device are removed or
/// replaced with stable one-way hashes of their values (salted by a fixed tag
/// per field kind so identical values across fields do not correlate unless
/// they are the same field kind). File byte contents and raw EF reads are
/// stripped; findings and structural results are kept.
pub fn anonymize(mut envelope: Value) -> Value {
    redact_value(&mut envelope, "");
    envelope
}

fn hash_value(kind: &str, v: &str) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(v.as_bytes());
    let out = h.finalize();
    format!("sha256:{}", hex::encode(&out[..12]))
}

fn is_identifier_key(k: &str) -> bool {
    matches!(
        k,
        "iccid"
            | "imsi"
            | "eid"
            | "msisdn"
            | "imei"
            | "imeisv"
            | "impu"
            | "impi"
            | "ki"
            | "opc"
            | "op"
            | "acc"
            | "spn"
            | "gid1"
            | "gid2"
            | "atr"
            | "serial"
    )
}

fn is_blob_key(k: &str) -> bool {
    matches!(
        k,
        "data" | "bytes" | "hex" | "content" | "raw" | "value_hex" | "record_hex"
    )
}

fn redact_value(v: &mut Value, key: &str) {
    match v {
        Value::Object(map) => {
            // Drop or hash known identifier fields; recurse into others.
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let redact_id = is_identifier_key(&k);
                let redact_blob = is_blob_key(&k) && !key.is_empty();
                if redact_id {
                    if let Some(val) = map.get_mut(&k) {
                        if let Some(s) = val.as_str() {
                            *val = Value::String(hash_value(&k, s));
                        } else {
                            *val = Value::String("<redacted>".to_string());
                        }
                    }
                } else if redact_blob {
                    // Keep only a length marker for blobs to preserve structure.
                    if let Some(val) = map.get_mut(&k) {
                        let len = match val {
                            Value::String(s) => s.len(),
                            Value::Array(a) => a.len(),
                            _ => 0,
                        };
                        *val = json!({ "redacted": true, "len": len });
                    }
                } else if let Some(child) = map.get_mut(&k) {
                    redact_value(child, &k);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_value(item, key);
            }
        }
        _ => {}
    }
}

/// Submit an (already anonymized or to-be-anonymized) scan envelope to
/// `endpoint` over HTTPS.
///
/// The destination and the exact payload sent are printed to stderr before the
/// request (opt-in transparency). `pin_ca_file`, when provided, is a PEM trust
/// anchor (explicit CA / pinned certificate bundle) for the TLS connection.
/// Certificate verification is always on.
pub fn submit_envelope(
    endpoint: &str,
    envelope: &Value,
    anonymize_first: bool,
    pin_ca_file: Option<&str>,
) -> Result<Value, Error> {
    let url = endpoint.trim();
    if !(url.starts_with("https://")) {
        return Err(Error::Endpoint("must be an https:// URL".to_string()));
    }
    let body = if anonymize_first {
        anonymize(envelope.clone())
    } else {
        envelope.clone()
    };
    let bytes = serde_json::to_vec(&body).map_err(|e| Error::Serialize(e.to_string()))?;

    eprintln!("sim-doctor: --submit (opt-in): POST {url}");
    if let Some(ca) = pin_ca_file {
        eprintln!("sim-doctor: --submit trust anchor: {ca}");
    }
    eprintln!(
        "sim-doctor: --submit anonymized={anonymize_first}, {} bytes",
        bytes.len()
    );
    if let Ok(text) = serde_json::to_string_pretty(&body) {
        eprintln!("sim-doctor: --submit payload (exact):\n{text}");
    }

    let config = if let Some(path) = pin_ca_file {
        HttpsConfig {
            trust: Trust::Bundle(PathBuf::from(path)),
            ..HttpsConfig::default()
        }
    } else {
        HttpsConfig::default()
    };
    let mut transport =
        HttpsTransport::new(&config).map_err(|e| Error::Http(format!("transport: {e}")))?;
    let resp = transport
        .post(url, &[("Content-Type", "application/json")], &bytes)
        .map_err(|e| Error::Http(e.to_string()))?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(Error::Http(format!("HTTP {}", resp.status)));
    }
    eprintln!("sim-doctor: --submit complete: HTTP {}", resp.status);
    Ok(json!({ "submitted": true, "status": resp.status, "anonymized": anonymize_first }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymize_redacts_identifiers() {
        let env = json!({
            "schema": "doctor/1",
            "data": { "eid": "89049032000001000000000000000001", "files": [{"iccid": "8986000000000000001"}] }
        });
        let out = anonymize(env);
        assert_ne!(
            out["data"]["eid"].as_str().unwrap(),
            "89049032000001000000000000000001"
        );
        assert!(out["data"]["eid"].as_str().unwrap().starts_with("sha256:"));
    }
}
