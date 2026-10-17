//! The profile download sequence of SGP.22 v2.5: the ORDER of the ES10b and
//! ES9+ calls, the data that flows from each response into the next request,
//! and the classification of every failure. Library only. Nothing here opens a
//! socket or talks to a card: the caller brings an [`Es9Client`] (over the
//! HTTPS transport, or a scripted one in tests) and a card callback that sends
//! one ES10 request on the ISD-R and returns the response data.
//!
//! **Owns.** The order ([`STEPS`]), the transactionId checks, the hand-off of
//! each response to the next request, cutting the received BoundProfilePackage
//! into segments before the first write, the CancelSession chain, and
//! [`Error::kind`] and [`Error::retryable`].
//!
//! **Does not own.** TLS ([`crate::es9_https`]), the ES9+ and ES10 message
//! layers ([`crate::es9`], [`crate::es10`]), the card channel and STORE DATA
//! segmentation (the callback, see [`crate::euicc`]), or building a BPP. The
//! BPP is built on the SM-DP+ side and only cut here. There is no second BPP
//! builder in this file.
//!
//! # Order
//!
//! 1. ES10b GetEUICCChallenge (5.7.7), then GetEUICCInfo1 (5.7.8): the LPA reads the eUICC first.
//! 2. ES9+ InitiateAuthentication (5.6.1): the SM-DP+ allocates the transactionId.
//! 3. ES10b AuthenticateServer (5.7.13): serverSigned1, serverSignature1, euiccCiPKIdToBeUsed, serverCertificate and ctxParams1.
//! 4. ES9+ AuthenticateClient (5.6.3): the transactionId and the whole BF38 answer.
//! 5. ES10b PrepareDownload (5.7.5): smdpSigned2, smdpSignature2, smdpCertificate. hashCc is not sent (see Not built).
//! 6. ES9+ GetBoundProfilePackage (5.6.2): the transactionId and the whole BF21 answer.
//! 7. ES10 LoadBoundProfilePackage (5.7.6, 2.5.5): one STORE DATA sequence per segment, in order. This is the first write that installs anything.
//! 8. The Profile Installation Result (BF37) must come back with the last segment. Without it the download is not reported as installed.
//!
//! Steps 2 to 6 may fail. Once the eUICC has answered AuthenticateServer with
//! a session, a failure is closed with ES10b CancelSession (5.7.14) and ES9+
//! CancelSession (5.6.5), which carries the cancelSessionResponse. No cancel
//! is sent once step 7 has begun, because the card may then hold part of a
//! profile and this module does not claim it is clean.
//!
//! # Transaction identifier
//!
//! The SM-DP+ allocates it in InitiateAuthentication. It is carried in every
//! ES9+ request after that (AuthenticateClient, GetBoundProfilePackage,
//! CancelSession) and echoed by the eUICC in euiccSigned1 and euiccSigned2.
//! Each echo is compared with the SM-DP+ value, and a mismatch is terminal.
//!
//! # Retryable and terminal
//!
//! Retryable ([`Error::retryable`]): no HTTP response (`smdp-unreachable`), HTTP
//! 5xx (`smdp-unavailable`), and functionExecutionStatus Expired
//! (`smdp-session-expired`). All happen before step 7, so nothing was installed
//! and running the whole sequence again from step 1 is the right retry. This
//! module makes one attempt; deciding to retry belongs to the caller.
//!
//! Terminal: an SM-DP+ Failed status (`smdp-refused`), a 3xx, never followed
//! (`smdp-redirect`), any other fault in an SM-DP+ answer (`smdp-protocol`), an
//! eUICC error answer (`euicc-refused`), a card-side failure (`card-failed`), an
//! eUICC answer that does not decode (`euicc-protocol`), a transactionId
//! mismatch (`transaction-id-mismatch`), a package that is not the BF36 shape
//! (`bpp-malformed`), and a load that ends without a Profile Installation
//! Result (`installation-result-missing`).
//!
//! # Not built
//!
//! hashCc (the confirmation code): PrepareDownload is sent without it, so a
//! profile whose SM-DP+ requires one ends in an eUICC refusal. Also not built:
//! the ES11 path, HandleNotification after an install, the CLI command with
//! `--yes`, a live card channel (the callback is the seam), and decoding the
//! transactionId inside the Profile Installation Result.

use crate::es10::{self, AuthenticateServerResponse, CancelSessionReason, PrepareDownloadResponse};
use crate::es9::{self, Es9Client, Es9Transport};

/// This module name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "profile_download";

const GET_CHALLENGE: &str = "GetEUICCChallenge";
const GET_INFO1: &str = "GetEUICCInfo1";
const INITIATE: &str = "InitiateAuthentication";
const AUTHENTICATE_SERVER: &str = "AuthenticateServer";
const AUTHENTICATE_CLIENT: &str = "AuthenticateClient";
const PREPARE: &str = "PrepareDownload";
const GET_PACKAGE: &str = "GetBoundProfilePackage";
const LOAD: &str = "LoadBoundProfilePackage";
const CANCEL: &str = "CancelSession";

/// The operations of a download, in the order they run. The test pins this
/// order against what the scripted card and server actually see.
pub const STEPS: [&str; 8] = [
    GET_CHALLENGE,
    GET_INFO1,
    INITIATE,
    AUTHENTICATE_SERVER,
    AUTHENTICATE_CLIENT,
    PREPARE,
    GET_PACKAGE,
    LOAD,
];

/// What the caller asks for. `apply` false is the dry run: [`run`] returns
/// [`Outcome::Preview`] and sends nothing to the card or the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// `ctxParams1`, complete DER with its `A0` header (SGP.22 v2.5 5.7.13),
    /// supplied by the LPA and passed through unchanged.
    pub ctx_params1: Vec<u8>,
    /// Whether to send. The `--yes` gate belongs to the caller.
    pub apply: bool,
}

/// A completed install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The transactionId the SM-DP+ allocated, as carried through every request.
    pub transaction_id: Vec<u8>,
    /// The Profile Installation Result: the whole BF37 the eUICC sent with the last segment.
    pub installation_result: Vec<u8>,
}

/// What [`run`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Dry run: see [`STEPS`] for the order. Nothing was sent.
    Preview,
    /// The profile was bound, loaded and reported as installed.
    Installed(Installed),
}

/// A failed download: the cause, and the outcome of the cancel chain when it
/// ran (`None` when it was not needed, or when it succeeded).
#[derive(Debug)]
pub struct Failure {
    /// The first failure.
    pub error: Error,
    /// The error of the cancel chain, when it ran and failed.
    pub cancel_error: Option<String>,
}

/// Everything that stops a download, with its stable kind and retry class.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The SM-DP+ failed an ES9+ function, or the transport did.
    #[error("{step}: SM-DP+ {source}")]
    Smdp {
        /// The operation.
        step: String,
        /// What the ES9+ layer reported.
        source: Box<es9::Error>,
    },
    /// The eUICC answered with its own error code.
    #[error("{step}: the eUICC refused with {code}")]
    Refused {
        /// The operation.
        step: String,
        /// The eUICC error code, as named by the ES10 decoder.
        code: String,
    },
    /// The card callback failed (the card refused the command or the channel broke).
    #[error("{step}: the card did not carry the request: {message}")]
    Card {
        /// The operation.
        step: String,
        /// What the callback said.
        message: String,
    },
    /// The eUICC answered, but not with the structure its function defines.
    #[error("{step}: eUICC answer: {source}")]
    Euicc {
        /// The operation.
        step: String,
        /// What the ES10 decoder said.
        source: es10::DecodeError,
    },
    /// A request could not be encoded.
    #[error("{step}: request: {message}")]
    Request {
        /// The operation.
        step: String,
        /// What the encoder said.
        message: String,
    },
    /// A transactionId differs from the one the SM-DP+ allocated.
    #[error("{step}: transactionId {got:?}, expected {expected:?}")]
    TransactionId {
        /// The operation whose answer carried the other value.
        step: String,
        /// The SM-DP+ value.
        expected: Vec<u8>,
        /// The value found.
        got: Vec<u8>,
    },
    /// The received BoundProfilePackage is not the BF36 shape of 2.5.4.
    #[error("BoundProfilePackage: {0}")]
    Package(es10::DecodeError),
    /// The load finished without a Profile Installation Result.
    #[error("LoadBoundProfilePackage ended without a Profile Installation Result")]
    NoInstallationResult,
}

impl Error {
    /// A stable name for the failure, for machine-readable output.
    pub fn kind(&self) -> &str {
        match self {
            Self::Smdp { source, .. } => match source.as_ref() {
                es9::Error::Transport(_) => "smdp-unreachable",
                es9::Error::HttpStatus { got, .. } if *got >= 500 => "smdp-unavailable",
                es9::Error::Function { status, .. } if status == "Expired" => {
                    "smdp-session-expired"
                }
                es9::Error::Function { .. } => "smdp-refused",
                es9::Error::Redirect { .. } => "smdp-redirect",
                _ => "smdp-protocol",
            },
            Self::Refused { .. } => "euicc-refused",
            Self::Card { .. } => "card-failed",
            Self::Euicc { .. } => "euicc-protocol",
            Self::Request { .. } => "request-invalid",
            Self::TransactionId { .. } => "transaction-id-mismatch",
            Self::Package(_) => "bpp-malformed",
            Self::NoInstallationResult => "installation-result-missing",
        }
    }

    /// True when running the whole sequence again from step 1 may succeed.
    /// Every retryable failure happens before the first segment is loaded.
    pub fn retryable(&self) -> bool {
        matches!(
            self.kind(),
            "smdp-unreachable" | "smdp-unavailable" | "smdp-session-expired"
        )
    }

    /// True once the first segment of LoadBoundProfilePackage has been sent.
    /// From then on the card may hold part of a profile.
    pub fn load_started(&self) -> bool {
        match self {
            Self::Card { step, .. } | Self::Euicc { step, .. } => step == LOAD,
            Self::NoInstallationResult => true,
            _ => false,
        }
    }
}

/// Runs the download. `card` sends one ES10 request on the ISD-R and returns
/// the response data; the first argument is the step name.
///
/// # Errors
///
/// A [`Failure`] carrying the first [`Error`] and the outcome of the cancel
/// chain. Nothing is retried.
pub fn run<T: Es9Transport, C: FnMut(&str, Vec<u8>) -> Result<Vec<u8>, String>>(
    smdp: &mut Es9Client<T>,
    card: &mut C,
    plan: &Plan,
) -> Result<Outcome, Failure> {
    if !plan.apply {
        return Ok(Outcome::Preview);
    }
    let mut session = None;
    match download(smdp, card, plan, &mut session) {
        Ok(done) => Ok(Outcome::Installed(done)),
        Err(error) => {
            let cancel_error = session.and_then(|tid| cancel(smdp, card, &tid).err());
            Err(Failure {
                error,
                cancel_error,
            })
        }
    }
}

fn download<T: Es9Transport, C: FnMut(&str, Vec<u8>) -> Result<Vec<u8>, String>>(
    smdp: &mut Es9Client<T>,
    card: &mut C,
    plan: &Plan,
    session: &mut Option<Vec<u8>>,
) -> Result<Installed, Error> {
    let challenge = es10::decode_get_euicc_challenge(&ask(
        card,
        GET_CHALLENGE,
        es10::get_euicc_challenge_request(),
    )?)
    .map_err(|source| euicc_err(GET_CHALLENGE, source))?;
    let info1 = ask(card, GET_INFO1, es10::get_euicc_info1_request())?;

    let init = smdp
        .initiate_authentication(&challenge.challenge, &info1)
        .map_err(|source| smdp_err(INITIATE, source))?;
    let tid = init.transaction_id.clone();

    let request = init.authenticate_server_request(&plan.ctx_params1).encode();
    let auth_raw = ask(card, AUTHENTICATE_SERVER, request)?;
    let auth = match es10::decode_authenticate_server(&auth_raw)
        .map_err(|source| euicc_err(AUTHENTICATE_SERVER, source))?
    {
        AuthenticateServerResponse::Ok(ok) => ok,
        AuthenticateServerResponse::Error(err) => {
            return Err(refused(AUTHENTICATE_SERVER, err.code))
        }
    };
    *session = Some(tid.clone());
    check_tid(AUTHENTICATE_SERVER, &tid, &auth.transaction_id)?;

    let client = smdp
        .authenticate_client(&tid, &auth_raw)
        .map_err(|source| smdp_err(AUTHENTICATE_CLIENT, source))?;
    check_tid(AUTHENTICATE_CLIENT, &tid, &client.transaction_id)?;

    let request = client
        .prepare_download_request(None)
        .encode()
        .map_err(|e| Error::Request {
            step: PREPARE.to_string(),
            message: e.to_string(),
        })?;
    let prepare_raw = ask(card, PREPARE, request)?;
    match es10::decode_prepare_download(&prepare_raw)
        .map_err(|source| euicc_err(PREPARE, source))?
    {
        PrepareDownloadResponse::Ok(ok) => check_tid(PREPARE, &tid, &ok.transaction_id)?,
        PrepareDownloadResponse::Error(err) => return Err(refused(PREPARE, err.code)),
    }

    let package = smdp
        .get_bound_profile_package(&tid, &prepare_raw)
        .map_err(|source| smdp_err(GET_PACKAGE, source))?;
    check_tid(GET_PACKAGE, &tid, &package.transaction_id)?;
    // Every segment is cut before the first one is sent, so a bad package
    // writes nothing to the card.
    let segments = es10::bpp_segments(&package.bound_profile_package).map_err(Error::Package)?;

    // The first load is the first write that can install anything: from here
    // the cancel chain is not used.
    *session = None;
    let mut last = Vec::new();
    for segment in segments {
        last = ask(card, LOAD, segment)?;
    }
    if last.is_empty() {
        return Err(Error::NoInstallationResult);
    }
    es10::single_value(&last, 0xBF37).map_err(|source| euicc_err(LOAD, source))?;
    Ok(Installed {
        transaction_id: tid,
        installation_result: last,
    })
}

/// ES10b CancelSession, then ES9+ CancelSession with what the eUICC answered.
fn cancel<T: Es9Transport, C: FnMut(&str, Vec<u8>) -> Result<Vec<u8>, String>>(
    smdp: &mut Es9Client<T>,
    card: &mut C,
    transaction_id: &[u8],
) -> Result<(), String> {
    let request =
        es10::cancel_session_request(transaction_id, CancelSessionReason::UndefinedReason)
            .map_err(|e| e.to_string())?;
    let response = card(CANCEL, request)?;
    smdp.cancel_session(transaction_id, &response)
        .map_err(|e| e.to_string())
}

fn ask<C: FnMut(&str, Vec<u8>) -> Result<Vec<u8>, String>>(
    card: &mut C,
    step: &str,
    request: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    card(step, request).map_err(|message| Error::Card {
        step: step.to_string(),
        message,
    })
}

fn smdp_err(step: &str, source: es9::Error) -> Error {
    Error::Smdp {
        step: step.to_string(),
        source: Box::new(source),
    }
}

fn euicc_err(step: &str, source: es10::DecodeError) -> Error {
    Error::Euicc {
        step: step.to_string(),
        source,
    }
}

fn refused(step: &str, code: impl std::fmt::Debug) -> Error {
    Error::Refused {
        step: step.to_string(),
        code: format!("{code:?}"),
    }
}

fn check_tid(step: &str, expected: &[u8], got: &[u8]) -> Result<(), Error> {
    if expected == got {
        return Ok(());
    }
    Err(Error::TransactionId {
        step: step.to_string(),
        expected: expected.to_vec(),
        got: got.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpp::Bpp;
    use crate::es9::{Response, TransportError};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    type Log = Rc<RefCell<Vec<String>>>;
    const TID: [u8; 4] = [0x0A, 0x0B, 0x0C, 0x0D];
    const INFO2_V25: &str = "BF2281B781030201008203020500830304060084158101008204000628248304000019228504067F36C0850200FF86030300008703020301880204B0A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB8B0102990202C004030000010C0D47492D42412D55502D30343139AC1E80056C6162656C811568747470733A2F2F646C6F612E6578616D706C652F8D0205408E075452452D524546AF050403030200";
    const FAILED_BODY: &str = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Failed\",\"statusCodeData\":{\"subjectCode\":\"8.1\",\"reasonCode\":\"3.1\"}}}}";
    const EXPIRED_BODY: &str =
        "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Expired\"}}}";

    /// A TLV with a definite length of any size. The tag bytes are given whole.
    fn der(tag: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        match body.len() {
            n @ 0..=0x7F => out.push(n as u8),
            n @ 0x80..=0xFF => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(body);
        out
    }

    /// The body shape of 6.5.1.4 for an Executed-Success answer, with `members`.
    fn ok_with(members: &str) -> String {
        let head = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}}";
        if members.is_empty() {
            format!("{head}}}")
        } else {
            format!("{head},{members}}}")
        }
    }

    fn member(name: &str, tlv: &[u8]) -> String {
        format!("\"{name}\":\"{}\"", es9::b64_encode(tlv))
    }

    fn tid_member(tid: &[u8]) -> String {
        format!("\"transactionId\":\"{}\"", hex::encode_upper(tid))
    }

    fn json(status: u16, body: &str) -> Result<Response, TransportError> {
        Ok(Response {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        })
    }

    fn initiate_body() -> String {
        ok_with(&format!(
            "{},{},{},{},{}",
            tid_member(&TID),
            member("serverSigned1", &der(&[0x30], &[1, 2, 3])),
            member("serverSignature1", &der(&[0x5F, 0x37], &[9, 9])),
            member("euiccCiPKIdToBeUsed", &der(&[0x04], &[7; 20])),
            member("serverCertificate", &der(&[0x30], &[8, 8])),
        ))
    }

    fn client_body(tid: &[u8]) -> String {
        ok_with(&format!(
            "{},{},{},{},{}",
            tid_member(tid),
            member("profileMetadata", &der(&[0xBF, 0x25], &[1])),
            member("smdpSigned2", &der(&[0x30], &[1])),
            member("smdpSignature2", &der(&[0x5F, 0x37], &[2; 3])),
            member("smdpCertificate", &der(&[0x30], &[3])),
        ))
    }

    fn package(with_a3: bool) -> Vec<u8> {
        let mut inner = der(&[0xBF, 0x23], &[0x01]);
        inner.extend(der(&[0xA0], &der(&[0x87], &[0x02])));
        inner.extend(der(&[0xA1], &der(&[0x88], &[0x03])));
        if with_a3 {
            inner.extend(der(&[0xA3], &der(&[0x86], &[0x04])));
        }
        der(&[0xBF, 0x36], &inner)
    }

    fn package_body(with_a3: bool) -> String {
        ok_with(&format!(
            "{},{}",
            tid_member(&TID),
            member("boundProfilePackage", &package(with_a3))
        ))
    }

    fn auth_ok() -> Vec<u8> {
        let mut signed = der(&[0x80], &TID);
        signed.extend(der(&[0x83], b"smdp.example.com"));
        signed.extend(der(&[0x84], &[0x40; 16]));
        signed.extend(hex::decode(INFO2_V25).unwrap());
        signed.extend(der(&[0xA0], &[0x30, 0x00]));
        let mut inner = der(&[0x30], &signed);
        inner.extend(der(&[0x5F, 0x37], &[0x80; 4]));
        inner.extend(der(&[0x30], &[0x02, 0x01, 0x01]));
        inner.extend(der(&[0x30], &[0x02, 0x01, 0x02]));
        der(&[0xBF, 0x38], &der(&[0xA0], &inner))
    }

    fn prepare_ok() -> Vec<u8> {
        let mut signed = der(&[0x80], &TID);
        signed.extend(der(&[0x5F, 0x49], &[0x04; 65]));
        let mut inner = der(&[0x30], &signed);
        inner.extend(der(&[0x5F, 0x37], &[0x81; 4]));
        der(&[0xBF, 0x21], &der(&[0xA0], &inner))
    }

    struct Answers {
        auth: Vec<u8>,
        prepare: Vec<u8>,
        pir: Vec<u8>,
    }

    fn answers() -> Answers {
        Answers {
            auth: auth_ok(),
            prepare: prepare_ok(),
            pir: der(&[0xBF, 0x37], &[0x80, 0x01, 0x00]),
        }
    }

    /// The SM-DP+ side: records each request and answers from a script.
    struct Smdp {
        log: Log,
        bodies: Rc<RefCell<Vec<String>>>,
        replies: VecDeque<Result<Response, TransportError>>,
    }

    impl Es9Transport for Smdp {
        fn post(
            &mut self,
            url: &str,
            _headers: &[(&str, &str)],
            body: &[u8],
        ) -> Result<Response, TransportError> {
            let name = url.rsplit("/").next().unwrap_or_default();
            self.log.borrow_mut().push(format!("smdp {name}"));
            self.bodies
                .borrow_mut()
                .push(String::from_utf8_lossy(body).into_owned());
            self.replies
                .pop_front()
                .expect("one scripted reply per request")
        }
    }

    /// The eUICC side: answers each ES10 step from `answers`.
    fn card(log: Log, answers: Answers) -> impl FnMut(&str, Vec<u8>) -> Result<Vec<u8>, String> {
        move |step: &str, _request: Vec<u8>| {
            log.borrow_mut().push(format!("card {step}"));
            match step {
                GET_CHALLENGE => Ok(der(&[0xBF, 0x2E], &der(&[0x80], &[0x11; 16]))),
                GET_INFO1 => Ok(der(&[0xBF, 0x20], &[0x01])),
                AUTHENTICATE_SERVER => Ok(answers.auth.clone()),
                PREPARE => Ok(answers.prepare.clone()),
                LOAD => Ok(answers.pir.clone()),
                CANCEL => Ok(der(&[0xBF, 0x41], &der(&[0x80], &TID))),
                other => Err(format!("unexpected step {other}")),
            }
        }
    }

    struct Ran {
        outcome: Result<Outcome, Failure>,
        log: Vec<String>,
        bodies: Vec<String>,
    }

    fn drive(replies: Vec<Result<Response, TransportError>>, answers: Answers, apply: bool) -> Ran {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let bodies = Rc::new(RefCell::new(Vec::new()));
        let transport = Smdp {
            log: log.clone(),
            bodies: bodies.clone(),
            replies: VecDeque::from(replies),
        };
        let mut smdp = Es9Client::new(
            transport,
            es9::SmdpAddress::parse("smdp.example.com").unwrap(),
        );
        let mut card = card(log.clone(), answers);
        let plan = Plan {
            ctx_params1: vec![0xA0, 0x02, 0x30, 0x00],
            apply,
        };
        let outcome = run(&mut smdp, &mut card, &plan);
        let log = log.borrow().clone();
        let bodies = bodies.borrow().clone();
        Ran {
            outcome,
            log,
            bodies,
        }
    }

    fn lines(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// The log of a run that installs: 7 steps, then one load per segment (6).
    fn happy_log() -> Vec<String> {
        let mut log = lines(&[
            "card GetEUICCChallenge",
            "card GetEUICCInfo1",
            "smdp initiateAuthentication",
            "card AuthenticateServer",
            "smdp authenticateClient",
            "card PrepareDownload",
            "smdp getBoundProfilePackage",
        ]);
        log.extend((0..6).map(|_| "card LoadBoundProfilePackage".to_string()));
        log
    }

    /// The log of a run that fails after AuthenticateServer succeeded and
    /// before any load: the cancel chain follows.
    fn cancelled_log(steps: &[&str]) -> Vec<String> {
        let mut log = lines(&[
            "card GetEUICCChallenge",
            "card GetEUICCInfo1",
            "smdp initiateAuthentication",
            "card AuthenticateServer",
        ]);
        log.extend(steps.iter().map(|s| s.to_string()));
        log.extend(lines(&["card CancelSession", "smdp cancelSession"]));
        log
    }

    #[test]
    fn the_order_is_pinned_and_the_transaction_id_travels() {
        let ran = drive(
            vec![
                json(200, &initiate_body()),
                json(200, &client_body(&TID)),
                json(200, &package_body(true)),
            ],
            answers(),
            true,
        );
        assert_eq!(ran.log, happy_log());
        let installed = match ran.outcome {
            Ok(Outcome::Installed(done)) => done,
            other => panic!("expected an install, got {other:?}"),
        };
        assert_eq!(installed.transaction_id, TID);
        assert_eq!(installed.installation_result, answers().pir);
        assert!(ran.bodies[1].contains("\"transactionId\":\"0A0B0C0D\""));
        assert!(ran.bodies[2].contains("\"transactionId\":\"0A0B0C0D\""));
    }

    #[test]
    fn the_steps_constant_names_the_order_the_run_uses() {
        let mut names: Vec<String> = Vec::new();
        for entry in happy_log() {
            let name = entry.split(' ').nth(1).unwrap().to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        assert_eq!(
            names.join(" ").to_ascii_lowercase(),
            STEPS.join(" ").to_ascii_lowercase()
        );
    }

    #[test]
    fn an_smdp_refusal_cancels_and_loads_nothing() {
        let ran = drive(
            vec![
                json(200, &initiate_body()),
                json(200, FAILED_BODY),
                json(200, &ok_with("")),
            ],
            answers(),
            true,
        );
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "smdp-refused");
        assert!(!failure.error.retryable());
        assert!(!failure.error.load_started());
        assert_eq!(failure.cancel_error, None);
        assert_eq!(ran.log, cancelled_log(&["smdp authenticateClient"]));
    }

    #[test]
    fn no_http_response_is_retryable_and_leaves_no_session() {
        let ran = drive(
            vec![Err(TransportError("connection reset".to_string()))],
            answers(),
            true,
        );
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "smdp-unreachable");
        assert!(failure.error.retryable());
        assert_eq!(failure.cancel_error, None);
        assert_eq!(
            ran.log,
            lines(&[
                "card GetEUICCChallenge",
                "card GetEUICCInfo1",
                "smdp initiateAuthentication",
            ])
        );
    }

    #[test]
    fn an_expired_session_is_retryable_and_cancelled() {
        let ran = drive(
            vec![
                json(200, &initiate_body()),
                json(200, EXPIRED_BODY),
                json(200, &ok_with("")),
            ],
            answers(),
            true,
        );
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "smdp-session-expired");
        assert!(failure.error.retryable());
        assert_eq!(failure.cancel_error, None);
        assert_eq!(ran.log, cancelled_log(&["smdp authenticateClient"]));
    }

    #[test]
    fn a_redirect_is_terminal_and_not_followed() {
        let ran = drive(vec![json(302, "")], answers(), true);
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "smdp-redirect");
        assert!(!failure.error.retryable());
        assert_eq!(ran.log.len(), 3);
    }

    #[test]
    fn an_euicc_refusal_of_authenticate_server_opens_no_session() {
        let mut err = der(&[0x80], &TID);
        err.extend(der(&[0x02], &[0x01]));
        let refusing = Answers {
            auth: der(&[0xBF, 0x38], &der(&[0xA1], &err)),
            ..answers()
        };
        let ran = drive(vec![json(200, &initiate_body())], refusing, true);
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "euicc-refused");
        assert!(!failure.error.retryable());
        assert_eq!(failure.cancel_error, None);
        assert_eq!(ran.log.last().unwrap(), "card AuthenticateServer");
        assert_eq!(ran.log.len(), 4);
    }

    #[test]
    fn a_transaction_id_mismatch_is_terminal_and_cancelled() {
        let ran = drive(
            vec![
                json(200, &initiate_body()),
                json(200, &client_body(&[0x0B, 0x0B, 0x0C, 0x0D])),
                json(200, &ok_with("")),
            ],
            answers(),
            true,
        );
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "transaction-id-mismatch");
        assert_eq!(failure.cancel_error, None);
        assert_eq!(ran.log, cancelled_log(&["smdp authenticateClient"]));
    }

    #[test]
    fn a_malformed_package_writes_no_segment() {
        let ran = drive(
            vec![
                json(200, &initiate_body()),
                json(200, &client_body(&TID)),
                json(200, &package_body(false)),
                json(200, &ok_with("")),
            ],
            answers(),
            true,
        );
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "bpp-malformed");
        assert!(!failure.error.load_started());
        assert_eq!(failure.cancel_error, None);
        let mut expected = lines(&[
            "card GetEUICCChallenge",
            "card GetEUICCInfo1",
            "smdp initiateAuthentication",
            "card AuthenticateServer",
            "smdp authenticateClient",
            "card PrepareDownload",
            "smdp getBoundProfilePackage",
        ]);
        expected.extend(lines(&["card CancelSession", "smdp cancelSession"]));
        assert_eq!(ran.log, expected);
    }

    #[test]
    fn a_load_with_no_installation_result_is_reported_not_installed() {
        let no_result = Answers {
            pir: Vec::new(),
            ..answers()
        };
        let ran = drive(
            vec![
                json(200, &initiate_body()),
                json(200, &client_body(&TID)),
                json(200, &package_body(true)),
            ],
            no_result,
            true,
        );
        let failure = ran.outcome.unwrap_err();
        assert_eq!(failure.error.kind(), "installation-result-missing");
        assert!(failure.error.load_started());
        assert_eq!(failure.cancel_error, None);
        assert_eq!(ran.log, happy_log());
    }

    #[test]
    fn the_dry_run_touches_nothing() {
        let ran = drive(Vec::new(), answers(), false);
        assert_eq!(ran.outcome.unwrap(), Outcome::Preview);
        assert!(ran.log.is_empty());
        assert!(ran.bodies.is_empty());
    }

    #[test]
    fn the_received_package_is_cut_as_the_builder_cuts_it() {
        let built = Bpp {
            initialise_secure_channel: der(&[0xBF, 0x23], &[0x01; 3]),
            first_sequence_of_87: vec![der(&[0x87], &[0x02; 5]), der(&[0x87], &[0x03])],
            sequence_of_88: vec![der(&[0x88], &[0x04])],
            second_sequence_of_87: vec![der(&[0x87], &[0x05])],
            sequence_of_86: vec![der(&[0x86], &[0x06; 2]), der(&[0x86], &[0x07])],
        };
        assert_eq!(
            es10::bpp_segments(&built.to_bytes()).unwrap(),
            built.segments()
        );
    }
}
