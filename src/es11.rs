//! ES11, SM-DS discovery (SGP.22 v2.5): the LPA asks a root SM-DS for pending
//! events (profile download offers) for an eUICC.
//!
//! Library only. Nothing here opens a socket: a caller supplies an
//! [`crate::es9::Es9Transport`] (the same JSON-over-HTTPS transport shape as
//! ES9+). The CLI wires this only when explicitly asked.
//!
//! **Owns.** The ES11 request bodies, the response decoding for discovery
//! (InitiateAuthentication / AuthenticateClient against an SM-DS), and the
//! list of discovered events (SM-DP+ address + matching ID) an operator can
//! act on.
//!
//! **Does not own.** TLS or certificate policy (the transport's job), the
//! download that follows discovery, or ES9+ to the SM-DP+.
//!
//! Provenance note: section numbers and the exact JSON binding for ES11 are
//! taken from the SGP.22 structure as commonly implemented (lpac `profile
//! discovery`); this module is written to be tolerant and to surface the raw
//! response when it cannot be fully decoded.

use serde_json::Value;

use crate::es9::{Es9Transport, SmdpAddress, ADMIN_PROTOCOL, USER_AGENT, CONTENT_TYPE};

/// This module's name.
pub const NAME: &str = "es11";

/// An SM-DS event discovered for an eUICC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredEvent {
    /// The SM-DP+ address to download from, if present.
    pub smdp_address: Option<String>,
    /// The matching ID / activation code token, if present.
    pub matching_id: Option<String>,
    /// The raw event object for fields we do not model.
    pub raw: Value,
}

/// A discovery result.
#[derive(Debug, Clone, PartialEq)]
pub struct Discovery {
    /// Events returned by the SM-DS (may be empty).
    pub events: Vec<DiscoveredEvent>,
    /// The raw top-level response for auditability.
    pub raw: Value,
}

/// ES11-specific errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Transport or ES9-layer error.
    #[error("{0}")]
    Transport(String),
    /// The SM-DS address is not valid.
    #[error("SM-DS address: {0}")]
    Address(String),
    /// The response could not be decoded.
    #[error("SM-DS response: {0}")]
    Decode(String),
}

/// Build and send a minimal ES11 discovery request to `smds`.
///
/// This performs an InitiateAuthentication-style query against the SM-DS
/// endpoint used for discovery. The request carries the eUICC challenge and
/// info material when provided by the caller; callers that only have an EID/
/// address can pass empty/None values and the SM-DS may still respond.
///
/// Note: a full ES11 flow requires the eUICC's ES10b material (euiccChallenge,
/// euiccInfo1) similar to ES9+; this helper is shaped for the common "profile
/// discovery" case and returns whatever events the SM-DS reports.
pub fn discover(
    transport: &mut dyn Es9Transport,
    smds: &SmdpAddress,
    euicc_challenge_b64: Option<&str>,
    euicc_info1_b64: Option<&str>,
) -> Result<Discovery, Error> {
    // ES11 discovery is commonly exposed as the same function names under an
    // /gsma/rsp3/es11 or /gsma/rsp2/es11 path depending on version; we try the
    // SGP.22 v2.x style path first. The transport posts to the full URL.
    let mut body = serde_json::Map::new();
    if let Some(c) = euicc_challenge_b64 {
        body.insert("euiccChallenge".to_string(), Value::String(c.to_string()));
    }
    if let Some(i) = euicc_info1_b64 {
        body.insert("euiccInfo1".to_string(), Value::String(i.to_string()));
    }
    let payload = Value::Object(body).to_string();
    let url = format!("https://{}{}", smds.as_str(), "/gsma/rsp2/es11/initiateAuthentication");
    let headers = [
        ("User-Agent", USER_AGENT),
        ("X-Admin-Protocol", ADMIN_PROTOCOL),
        ("Content-Type", CONTENT_TYPE),
    ];
    let resp = transport
        .post(&url, &headers, payload.as_bytes())
        .map_err(|e| Error::Transport(e.to_string()))?;
    if resp.status != 200 {
        return Err(Error::Transport(format!("HTTP {}", resp.status)));
    }
    let raw: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Decode(e.to_string()))?;
    Ok(decode_discovery(raw))
}

fn decode_discovery(raw: Value) -> Discovery {
    // Be tolerant: look for common event list shapes.
    let mut events = Vec::new();
    let candidates = raw
        .get("eventEntries")
        .or_else(|| raw.get("events"))
        .or_else(|| raw.get("pendingEvents"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for ev in candidates {
        let smdp_address = ev
            .get("smdpAddress")
            .or_else(|| ev.get("rspServerAddress"))
            .or_else(|| ev.get("smdpPlusAddress"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let matching_id = ev
            .get("matchingId")
            .or_else(|| ev.get("acToken"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        events.push(DiscoveredEvent {
            smdp_address,
            matching_id,
            raw: ev,
        });
    }
    Discovery { events, raw }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es9::{Response, TransportError};

    struct Stub(Response);
    impl Es9Transport for Stub {
        fn post(&mut self, _u: &str, _h: &[(&str, &str)], _b: &[u8]) -> Result<Response, TransportError> {
            Ok(Response { status: self.0.status, headers: vec![], body: self.0.body.clone() })
        }
    }

    #[test]
    fn decodes_event_entries() {
        let body = br#"{"eventEntries":[{"smdpAddress":"smdp.example.com","matchingId":"ABC"}]}"#.to_vec();
        let smds = SmdpAddress::parse("smds.example.com").unwrap();
        let mut t = Stub(Response { status: 200, headers: vec![], body });
        let d = discover(&mut t, &smds, None, None).unwrap();
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].smdp_address.as_deref(), Some("smdp.example.com"));
        assert_eq!(d.events[0].matching_id.as_deref(), Some("ABC"));
    }
}
