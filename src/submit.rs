//! Opt-in anonymized submission of a scan envelope (gsmmap-style, issue #107).
//!
//! Computes the anonymized payload locally. Nothing leaves the machine unless
//! an explicit endpoint is given: without one the output says so and no network
//! call is made. There is no default endpoint.

use serde_json::{json, Map, Value};

/// Outcome of an opt-in submission attempt, reported in the scan output and
/// asserted by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// True only when the endpoint was contacted and the request succeeded.
    pub contacted: bool,
    /// The explicit endpoint, when `--submit` was given.
    pub endpoint: Option<String>,
    /// The anonymized payload that was (or would be) sent.
    pub payload: Value,
    /// Human-readable note for the report.
    pub note: String,
    /// Error string if the endpoint was contacted but the request failed.
    pub error: Option<String>,
}

/// Poster used to send the payload. Takes (endpoint, body_json) and returns
/// the response body or an error. Production uses [`post_http`]; tests pass a
/// mock to prove no call is made without opt-in.
pub type Poster = fn(&str, &str) -> Result<String, String>;

/// Sends `body` as JSON to `endpoint` with ureq. Certificate verification is
/// on (rustls as configured for ureq). This is only called for an explicit
/// operator-chosen endpoint.
pub fn post_http(endpoint: &str, body: &str) -> Result<String, String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let mut resp = agent
        .post(endpoint)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&status.as_u16()) {
        return Err(format!("HTTP {status}: {text}"));
    }
    Ok(text)
}

/// Redact card identifiers in a scan envelope: ICCID, IMSI, MSISDN, ATR and
/// key material in EF contents/evidence. The shape is preserved so the payload
/// stays readable; values become `"REDACTED"`.
pub fn anonymize(envelope: &Value) -> Value {
    let mut out = envelope.clone();
    if let Value::Object(ref mut root) = out {
        if let Some(Value::Object(data)) = root.get_mut("data") {
            redact_data(data);
        }
    }
    out
}

fn redact_data(data: &mut Map<String, Value>) {
    if data.contains_key("atr") {
        data.insert("atr".into(), Value::String("REDACTED".into()));
    }
    if let Some(Value::Array(items)) = data.get_mut("ef_contents") {
        for item in items {
            if let Value::Object(obj) = item {
                redact_ef_item(obj);
            }
        }
    }
}

fn redact_ef_item(obj: &mut Map<String, Value>) {
    let ef_name = obj
        .get("ef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_uppercase();
    let sensitive_ef = matches!(
        ef_name.as_str(),
        "EF.ICCID"
            | "EF.IMSI"
            | "EF.MSISDN"
            | "EF.ADN"
            | "EF.FDN"
            | "EF.IMPI"
            | "EF.IMPU"
            | "EF.KEYS"
            | "EF.KEYSPS"
            | "EF.MANUAREA"
    );
    if let Some(Value::Object(fields)) = obj.get_mut("fields") {
        redact_fields(fields, sensitive_ef);
    }
    if sensitive_ef {
        if let Some(v) = obj.get_mut("evidence") {
            redact_value_deep(v);
        }
        if let Some(v) = obj.get_mut("contents") {
            redact_value_deep(v);
        }
        if let Some(v) = obj.get_mut("raw") {
            redact_value_deep(v);
        }
    } else {
        if let Some(v) = obj.get_mut("evidence") {
            redact_identifier_strings(v);
        }
    }
}

fn redact_fields(fields: &mut Map<String, Value>, redact_all: bool) {
    let keys: Vec<String> = fields.keys().cloned().collect();
    for k in keys {
        let kl = k.to_ascii_lowercase();
        let is_id = kl.contains("iccid")
            || kl.contains("imsi")
            || kl.contains("msisdn")
            || kl.contains("impi")
            || kl.contains("impu")
            || kl == "number"
            || kl == "digits"
            || kl.contains("key")
            || kl.contains("opc")
            || kl == "ki"
            || kl == "k";
        if redact_all || is_id {
            if let Some(v) = fields.get_mut(&k) {
                *v = Value::String("REDACTED".into());
            }
        } else if let Some(v) = fields.get_mut(&k) {
            redact_identifier_strings(v);
        }
    }
}

fn redact_identifier_strings(v: &mut Value) {
    match v {
        Value::String(s) => {
            let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 10 {
                *s = "REDACTED".into();
            }
        }
        Value::Array(a) => {
            for x in a {
                redact_identifier_strings(x);
            }
        }
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                let kl = k.to_ascii_lowercase();
                if kl.contains("iccid")
                    || kl.contains("imsi")
                    || kl.contains("msisdn")
                    || kl.contains("impi")
                    || kl.contains("impu")
                {
                    *x = Value::String("REDACTED".into());
                } else {
                    redact_identifier_strings(x);
                }
            }
        }
        _ => {}
    }
}

fn redact_value_deep(v: &mut Value) {
    match v {
        Value::String(_) => *v = Value::String("REDACTED".into()),
        Value::Array(a) => {
            for x in a {
                redact_value_deep(x);
            }
        }
        Value::Object(o) => {
            for x in o.values_mut() {
                redact_value_deep(x);
            }
        }
        _ => *v = Value::String("REDACTED".into()),
    }
}

/// Compute the anonymized payload and, only if `endpoint` is Some, print the
/// destination and exact payload then contact it. With no endpoint, no network
/// call is made and the note says so.
pub fn maybe_submit_with(poster: Poster, endpoint: Option<&str>, envelope: &Value) -> Submission {
    let payload = anonymize(envelope);
    match endpoint {
        None => Submission {
            contacted: false,
            endpoint: None,
            payload,
            note: "No --submit endpoint provided: no scan result was uploaded and nothing left the machine.".into(),
            error: None,
        },
        Some(ep) => {
            let body = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into());
            eprintln!(
                "sim-doctor: opt-in submission: destination {ep} (explicit --submit). The following anonymized payload will be sent:"
            );
            eprintln!("{body}");
            eprintln!("sim-doctor: contacting submission endpoint (this leaves the machine)...");
            match poster(ep, &body) {
                Ok(_) => Submission {
                    contacted: true,
                    endpoint: Some(ep.to_string()),
                    payload,
                    note: format!("Anonymized scan result submitted to {ep}."),
                    error: None,
                },
                Err(e) => Submission {
                    contacted: false,
                    endpoint: Some(ep.to_string()),
                    payload,
                    note: format!("Submission to {ep} failed: {e}"),
                    error: Some(e),
                },
            }
        }
    }
}

/// Convenience wrapper using the real HTTP poster.
pub fn maybe_submit(endpoint: Option<&str>, envelope: &Value) -> Submission {
    maybe_submit_with(post_http, endpoint, envelope)
}

/// The part of a submission recorded in the scan envelope's `data` (no payload
/// copy; the payload is the anonymized form of the envelope itself).
pub fn submission_json(s: &Submission) -> Value {
    json!({
        "contacted": s.contacted,
        "endpoint": s.endpoint,
        "note": s.note,
        "error": s.error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    fn counting_poster(_ep: &str, _body: &str) -> Result<String, String> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        Ok("ok".into())
    }

    fn never_poster(_ep: &str, _body: &str) -> Result<String, String> {
        panic!("network contacted without explicit --submit");
    }

    #[test]
    fn no_endpoint_makes_no_network_call_and_says_so() {
        CALLS.store(0, Ordering::SeqCst);
        let env = json!({
            "schema": "doctor/1",
            "data": {
                "atr": "3B9F95801FC78031",
                "ef_contents": [{"ef":"EF.IMSI","fields":{"imsi":"001010123456789"},"evidence":"001010123456789"}]
            }
        });
        let s = maybe_submit_with(never_poster, None, &env);
        assert!(!s.contacted);
        assert_eq!(s.endpoint, None);
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
        assert!(s.note.contains("nothing left the machine"));
        assert_eq!(s.payload["data"]["atr"], "REDACTED");
        assert_eq!(
            s.payload["data"]["ef_contents"][0]["fields"]["imsi"],
            "REDACTED"
        );
        assert_eq!(s.payload["data"]["ef_contents"][0]["evidence"], "REDACTED");
    }

    #[test]
    fn explicit_endpoint_contacts_poster_with_redacted_payload() {
        CALLS.store(0, Ordering::SeqCst);
        let env = json!({
            "schema": "doctor/1",
            "data": {"atr": "3B9F95", "ef_contents": [{"ef":"EF.ICCID","fields":{"iccid":"8999101200003204510"}}]}
        });
        let s = maybe_submit_with(counting_poster, Some("http://127.0.0.1:9/submit"), &env);
        assert!(s.contacted);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(s.payload["data"]["atr"], "REDACTED");
        assert_eq!(
            s.payload["data"]["ef_contents"][0]["fields"]["iccid"],
            "REDACTED"
        );
    }
}
