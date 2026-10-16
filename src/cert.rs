//! eSIM certificate and CI chain verification, offline (GSMA SGP.22, issue #231).
//!
//! Given the certificates of a chain (DER, or PEM with one or more blocks) and the CI root the
//! caller trusts, this module checks each signature up to that root and reports validity and key
//! usage per certificate. It never touches a reader, a card or the network.
//!
//! **Owns.** X.509 parsing of the fields a chain check needs, ECDSA P-256 / SHA-256 signature
//! verification through the `p256` crate already in the tree, and the report shape.
//!
//! **Does not own.** Names are compared as raw DER, not parsed into CN/O strings. Certificates
//! that are not ecdsa-with-SHA256 over P-256 (brainpool, RSA) are reported as
//! [`SignatureCheck::Unsupported`], never as valid. Verifying them needs a new crypto dependency,
//! which is an owner decision.
//!
//! The structure is decoded with the strict DER decoder in [`crate::der`]: a certificate is DER
//! by definition, so a BER length in one is refused rather than tolerated.

use crate::der::Der;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The name this module answers to in `sim-doctor modules`.
pub const NAME: &str = "cert";

/// The largest chain or root file read: 1 MiB, far more than any real chain.
pub const MAX_CHAIN_BYTES: u64 = 1024 * 1024;

/// id-ecPublicKey, 1.2.840.10045.2.1 (RFC 5480 section 2.1.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// prime256v1 / secp256r1, 1.2.840.10045.3.1.7 (RFC 5480 section 2.1.1.1).
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// ecdsa-with-SHA256, 1.2.840.10045.4.3.2 (RFC 5758 section 3.2).
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// id-ce-keyUsage, 2.5.29.15 (RFC 5280 section 4.2.1.3).
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];

/// Named bits of the KeyUsage extension, in bit-number order (RFC 5280 section 4.2.1.3).
const KEY_USAGE_NAMES: [&str; 9] = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_VERSION: u8 = 0xA0;
const TAG_EXTENSIONS: u8 = 0xA3;

/// Why a certificate or chain could not be read at all. A readable certificate with a bad
/// signature is not an error: it is a [`SignatureCheck::Invalid`] in the report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not strict DER in the shape of an X.509 certificate.
    #[error("certificate is malformed: {0}")]
    Malformed(String),
    /// A PEM file had no `CERTIFICATE` block, or a block was not base64.
    #[error("PEM input has no readable CERTIFICATE block: {0}")]
    Pem(&'static str),
    /// A chain needs at least one certificate.
    #[error("the chain is empty")]
    EmptyChain,
}

impl From<crate::der::Error> for Error {
    fn from(e: crate::der::Error) -> Self {
        Error::Malformed(e.to_string())
    }
}

/// The result of checking one certificate's signature against one issuer key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheck {
    /// The signature verifies under the issuer's key.
    Valid,
    /// The signature does not verify, or the issuer key or signature bytes are not decodable.
    Invalid,
    /// The algorithm is outside what this module verifies. Not a failure of the chain, but
    /// not a pass either: [`ChainReport::verified`] is false.
    Unsupported(&'static str),
}

/// Where a certificate's validity period sits relative to the time it is checked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// `now` is before `notBefore`.
    NotYetValid,
    /// `notBefore <= now <= notAfter`.
    Valid,
    /// `now` is after `notAfter`.
    Expired,
}

/// One parsed X.509 certificate, with the pieces a chain check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The whole certificate, exactly as it was given.
    pub der: Vec<u8>,
    /// SHA-256 of [`Certificate::der`], lowercase hex: how a reader names this certificate.
    pub fingerprint: String,
    /// The serial number, lowercase hex, as the INTEGER's content octets.
    pub serial: String,
    /// `notBefore` as `YYYYMMDDHHMMSS` (UTCTime years are mapped as RFC 5280 section 4.1.2.5.1).
    pub not_before: String,
    /// `notAfter` as `YYYYMMDDHHMMSS`.
    pub not_after: String,
    /// The KeyUsage bits set, by RFC 5280 name, or `None` when the extension is absent.
    pub key_usage: Option<Vec<&'static str>>,
    /// The signature algorithm OID, dotted, for reports on unsupported algorithms.
    pub signature_algorithm: String,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    sig_oid: Vec<u8>,
    public_key: Option<Vec<u8>>,
    key_is_p256: bool,
}

impl Certificate {
    /// Parse one certificate from its DER encoding. The input must be exactly one certificate.
    pub fn parse(der: &[u8]) -> Result<Self, Error> {
        let cert = Der::decode(der)?;
        let parts = children(&cert, TAG_SEQUENCE, "certificate")?;
        if parts.len() != 3 {
            return Err(malformed(
                "certificate needs tbs, signatureAlgorithm, signatureValue",
            ));
        }
        let (tbs, outer_alg, sig_value) = (&parts[0], &parts[1], &parts[2]);
        let outer_oid = oid_of(outer_alg)?;

        let sig_bits = bit_string(sig_value)?;
        let fields = children(tbs, TAG_SEQUENCE, "tbsCertificate")?;
        let mut at = 0;
        if fields.first().map(Der::tag) == Some(TAG_VERSION) {
            at += 1;
        }
        let serial = fields.get(at).ok_or_else(|| malformed("no serialNumber"))?;
        expect_tag(serial, TAG_INTEGER, "serialNumber")?;
        at += 1;
        let inner_alg = fields.get(at).ok_or_else(|| malformed("no signature"))?;
        if oid_of(inner_alg)? != outer_oid {
            return Err(malformed("tbs and outer signature algorithms differ"));
        }
        at += 1;
        let issuer = fields.get(at).ok_or_else(|| malformed("no issuer"))?;
        at += 1;
        let validity = children(
            fields.get(at).ok_or_else(|| malformed("no validity"))?,
            TAG_SEQUENCE,
            "validity",
        )?;
        if validity.len() != 2 {
            return Err(malformed("validity needs notBefore and notAfter"));
        }
        let not_before = time_of(&validity[0])?;
        let not_after = time_of(&validity[1])?;
        at += 1;
        let subject = fields.get(at).ok_or_else(|| malformed("no subject"))?;
        at += 1;
        let spki = children(
            fields
                .get(at)
                .ok_or_else(|| malformed("no subjectPublicKeyInfo"))?,
            TAG_SEQUENCE,
            "subjectPublicKeyInfo",
        )?;
        if spki.len() != 2 {
            return Err(malformed("subjectPublicKeyInfo needs algorithm and key"));
        }
        let key_alg = children(&spki[0], TAG_SEQUENCE, "key algorithm")?;
        let key_oid = key_alg.first().map(oid_value).transpose()?;
        let curve_oid = key_alg.get(1).map(oid_value).transpose()?;
        let key_is_p256 = key_oid == Some(OID_EC_PUBLIC_KEY) && curve_oid == Some(OID_P256);
        let public_key = if key_is_p256 {
            let bits = bit_string(&spki[1])?;
            Some(bits.to_vec())
        } else {
            None
        };
        at += 1;

        let mut key_usage = None;
        if fields.get(at).map(Der::tag) == Some(TAG_EXTENSIONS) {
            let wrapped = children(&fields[at], TAG_EXTENSIONS, "extensions")?;
            let list = children(
                wrapped
                    .first()
                    .ok_or_else(|| malformed("empty extensions"))?,
                TAG_SEQUENCE,
                "extensions list",
            )?;
            for ext in list {
                let parts = children(&ext, TAG_SEQUENCE, "extension")?;
                let id = parts.first().map(oid_value).transpose()?;
                if id == Some(OID_KEY_USAGE) {
                    let octets = parts
                        .last()
                        .ok_or_else(|| malformed("extension has no value"))?;
                    expect_tag(octets, TAG_OCTET_STRING, "extnValue")?;
                    let bits = Der::decode(octets.value())?;
                    expect_tag(&bits, TAG_BIT_STRING, "KeyUsage")?;
                    key_usage = Some(named_bits(bits.value())?);
                }
            }
        }

        Ok(Certificate {
            der: der.to_vec(),
            fingerprint: hex(&Sha256::digest(der)),
            serial: hex(serial.value()),
            not_before,
            not_after,
            key_usage,
            signature_algorithm: dotted(outer_oid),
            issuer: issuer.encode(),
            subject: subject.encode(),
            tbs: tbs.encode(),
            signature: sig_bits.to_vec(),
            sig_oid: outer_oid.to_vec(),
            public_key,
            key_is_p256,
        })
    }

    /// Where `now` (a `YYYYMMDDHHMMSS` string, UTC) falls in this certificate's validity period.
    pub fn validity_at(&self, now: &str) -> Validity {
        if now < self.not_before.as_str() {
            Validity::NotYetValid
        } else if now > self.not_after.as_str() {
            Validity::Expired
        } else {
            Validity::Valid
        }
    }

    /// The one ECDSA signature check this crate performs: ecdsa-with-SHA256 over NIST P-256.
    ///
    /// Public so a caller outside X.509 - the GlobalPlatform card certificate in
    /// [`crate::gpcert`] - checks signatures here rather than opening a second verifier that
    /// could come to disagree with this one about the same octets.
    pub fn verify_ecdsa_p256(point: &[u8], message: &[u8], signature: &Signature) -> bool {
        let Ok(key) = VerifyingKey::from_sec1_bytes(point) else {
            return false;
        };
        key.verify(message, signature).is_ok()
    }

    /// Check this certificate's signature under `issuer`'s public key.
    pub fn verify_signed_by(&self, issuer: &Certificate) -> SignatureCheck {
        if self.sig_oid != OID_ECDSA_SHA256 {
            return SignatureCheck::Unsupported("signature algorithm is not ecdsa-with-SHA256");
        }
        if !issuer.key_is_p256 {
            return SignatureCheck::Unsupported("issuer key is not ECDSA P-256");
        }
        let Some(point) = issuer.public_key.as_deref() else {
            return SignatureCheck::Invalid;
        };
        let Ok(sig) = Signature::from_der(&self.signature) else {
            return SignatureCheck::Invalid;
        };
        if Self::verify_ecdsa_p256(point, &self.tbs, &sig) {
            SignatureCheck::Valid
        } else {
            SignatureCheck::Invalid
        }
    }

    /// Whether this certificate's issuer name is byte-for-byte the issuer's subject name.
    pub fn issued_by_name(&self, issuer: &Certificate) -> bool {
        self.issuer == issuer.subject
    }
}

/// One certificate's line in a chain report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertReport {
    /// Position in the chain as given, 0 is the leaf.
    pub index: usize,
    /// SHA-256 fingerprint of the certificate, lowercase hex.
    pub fingerprint: String,
    /// The serial number, lowercase hex.
    pub serial: String,
    /// `notBefore`, `YYYYMMDDHHMMSS`.
    pub not_before: String,
    /// `notAfter`, `YYYYMMDDHHMMSS`.
    pub not_after: String,
    /// Validity at the report's `now`.
    pub validity: Validity,
    /// KeyUsage bits by name, or `None` when absent.
    pub key_usage: Option<Vec<&'static str>>,
    /// Whether the issuer name matches the name of the certificate that signed it.
    pub issuer_name_matches: bool,
    /// The signature check against the issuer (the next certificate, or the CI root).
    pub signature: SignatureCheck,
}

/// The result of checking a whole chain against a CI root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// One entry per certificate, leaf first.
    pub certs: Vec<CertReport>,
    /// Whether the CI root is correctly self-signed. Its trust comes from the caller, not this check.
    pub root_self_signature: SignatureCheck,
    /// True only when every signature is `Valid`, every issuer name matches, and the root's
    /// self-signature is `Valid`. Validity periods do not decide this; read `validity` per entry.
    pub verified: bool,
}

/// Check `chain` (leaf first) against `ci_root`, at `now` (`YYYYMMDDHHMMSS`, UTC).
///
/// Each certificate is verified under the next certificate in `chain`, and the last one under
/// `ci_root`. If the chain file already ends with the root, that root is verified under itself
/// and the result is the same.
pub fn verify_chain(
    chain: &[Certificate],
    ci_root: &Certificate,
    now: &str,
) -> Result<ChainReport, Error> {
    if chain.is_empty() {
        return Err(Error::EmptyChain);
    }
    let certs = chain
        .iter()
        .enumerate()
        .map(|(index, cert)| {
            let issuer = chain.get(index + 1).unwrap_or(ci_root);
            CertReport {
                index,
                fingerprint: cert.fingerprint.clone(),
                serial: cert.serial.clone(),
                not_before: cert.not_before.clone(),
                not_after: cert.not_after.clone(),
                validity: cert.validity_at(now),
                key_usage: cert.key_usage.clone(),
                issuer_name_matches: cert.issued_by_name(issuer),
                signature: cert.verify_signed_by(issuer),
            }
        })
        .collect::<Vec<_>>();
    let root_self_signature = ci_root.verify_signed_by(ci_root);
    let verified = root_self_signature == SignatureCheck::Valid
        && certs
            .iter()
            .all(|c| c.signature == SignatureCheck::Valid && c.issuer_name_matches);
    Ok(ChainReport {
        certs,
        root_self_signature,
        verified,
    })
}

/// Read a chain file: PEM with one or more `CERTIFICATE` blocks, or concatenated DER.
pub fn parse_chain(bytes: &[u8]) -> Result<Vec<Certificate>, Error> {
    let blobs = if bytes.first() == Some(&TAG_SEQUENCE) {
        split_der(bytes)?
    } else {
        pem_blocks(bytes)?
    };
    blobs.iter().map(|b| Certificate::parse(b)).collect()
}

fn split_der(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (_, used) = Der::decode_first(bytes)?;
        out.push(bytes[..used].to_vec());
        bytes = &bytes[used..];
    }
    Ok(out)
}

fn pem_blocks(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Pem("not UTF-8 text"))?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after.find(END).ok_or(Error::Pem("BEGIN without END"))?;
        let body =
            crate::es9::b64_decode(&after[..end]).map_err(|_| Error::Pem("block is not base64"))?;
        out.push(body);
        rest = &after[end + END.len()..];
    }
    if out.is_empty() {
        return Err(Error::Pem("no BEGIN CERTIFICATE line"));
    }
    Ok(out)
}

fn malformed(what: &str) -> Error {
    Error::Malformed(what.to_string())
}

fn children<'a>(node: &Der<'a>, tag: u8, what: &str) -> Result<Vec<Der<'a>>, Error> {
    expect_tag(node, tag, what)?;
    Ok(node.children()?)
}

fn expect_tag(node: &Der<'_>, tag: u8, what: &str) -> Result<(), Error> {
    if node.tag() == tag {
        Ok(())
    } else {
        Err(Error::Malformed(format!(
            "{what}: tag {:02x}, expected {tag:02x}",
            node.tag()
        )))
    }
}

fn oid_value<'a>(node: &Der<'a>) -> Result<&'a [u8], Error> {
    expect_tag(node, TAG_OID, "object identifier")?;
    Ok(node.value())
}

/// The OID of an AlgorithmIdentifier SEQUENCE, as its content octets.
fn oid_of<'a>(alg: &Der<'a>) -> Result<&'a [u8], Error> {
    let parts = children(alg, TAG_SEQUENCE, "AlgorithmIdentifier")?;
    oid_value(
        parts
            .first()
            .ok_or_else(|| malformed("AlgorithmIdentifier is empty"))?,
    )
}

fn bit_string<'a>(node: &Der<'a>) -> Result<&'a [u8], Error> {
    expect_tag(node, TAG_BIT_STRING, "BIT STRING")?;
    match node.value() {
        [0, rest @ ..] => Ok(rest),
        _ => Err(malformed("BIT STRING has unused bits")),
    }
}

fn time_of(node: &Der<'_>) -> Result<String, Error> {
    let raw = node.value();
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let (year, rest) = match node.tag() {
        TAG_UTC_TIME if raw.len() == 13 && digits(&raw[..12]) && raw[12] == b'Z' => {
            let yy: u32 = std::str::from_utf8(&raw[..2])
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (year, &raw[2..12])
        }
        TAG_GENERALIZED_TIME if raw.len() == 15 && digits(&raw[..14]) && raw[14] == b'Z' => {
            let year: u32 = std::str::from_utf8(&raw[..4])
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            (year, &raw[4..14])
        }
        _ => return Err(malformed("time is not YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ")),
    };
    Ok(format!("{year:04}{}", String::from_utf8_lossy(rest)))
}

/// Named bits of a BIT STRING's content octets (first octet = unused bits in the last byte).
fn named_bits(content: &[u8]) -> Result<Vec<&'static str>, Error> {
    let (unused, bytes) = content
        .split_first()
        .ok_or_else(|| malformed("empty KeyUsage"))?;
    if *unused > 7 || (bytes.is_empty() && *unused != 0) {
        return Err(malformed("KeyUsage has bad unused-bit count"));
    }
    let total = bytes.len() * 8 - usize::from(*unused);
    Ok(KEY_USAGE_NAMES
        .iter()
        .enumerate()
        .filter(|(n, _)| *n < total && bytes[n / 8] & (0x80 >> (n % 8)) != 0)
        .map(|(_, name)| *name)
        .collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The dotted form of the OIDs this module names; other OIDs stay as hex, unparsed.
fn dotted(oid: &[u8]) -> String {
    if oid == OID_ECDSA_SHA256 {
        return "1.2.840.10045.4.3.2".into();
    }
    format!("oid-hex:{}", hex(oid))
}

/// Reads one input file. Refuses anything that is not a regular file and anything over
/// [`MAX_CHAIN_BYTES`]. The ceiling is enforced while reading, with a `take`, so a file that
/// grows after the size check still cannot exhaust memory.
pub fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown}: not a regular file"));
    }
    if meta.len() > MAX_CHAIN_BYTES {
        return Err(format!("{shown}: larger than {MAX_CHAIN_BYTES} bytes"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_CHAIN_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{shown}: {e}"))?;
    if bytes.len() as u64 > MAX_CHAIN_BYTES {
        return Err(format!("{shown}: larger than {MAX_CHAIN_BYTES} bytes"));
    }
    Ok(bytes)
}

/// The current UTC time as `YYYYMMDDHHMMSS`, the form [`Certificate::validity_at`] compares.
pub fn now_stamp() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%S").to_string()
}

/// The overall outcome of a chain check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every signature chains to the root and every certificate is inside its validity period.
    Verified,
    /// The signatures chain to the root, but at least one certificate is outside its period.
    /// Never reported as plainly verified.
    VerifiedOutOfValidity,
    /// At least one signature is invalid, unsupported, or a name link is broken.
    NotVerified,
}

impl Verdict {
    /// The stable word used in JSON and on the human line.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::VerifiedOutOfValidity => "verified-but-out-of-validity",
            Verdict::NotVerified => "not-verified",
        }
    }
}

/// Whether any certificate in the chain is outside its validity period at the report's time.
pub fn out_of_validity(report: &ChainReport) -> bool {
    report.certs.iter().any(|c| c.validity != Validity::Valid)
}

/// The overall verdict. `verified` alone is not enough: an expired chain is not plainly good.
pub fn verdict(report: &ChainReport) -> Verdict {
    match (report.verified, out_of_validity(report)) {
        (false, _) => Verdict::NotVerified,
        (true, true) => Verdict::VerifiedOutOfValidity,
        (true, false) => Verdict::Verified,
    }
}

fn validity_name(v: Validity) -> &'static str {
    match v {
        Validity::NotYetValid => "not-yet-valid",
        Validity::Valid => "valid",
        Validity::Expired => "expired",
    }
}

fn signature_name(s: SignatureCheck) -> &'static str {
    match s {
        SignatureCheck::Valid => "valid",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::Unsupported(_) => "unsupported",
    }
}

/// Findings for a chain report: one per failed check, with the certificate's position
/// (`null` for the CI root itself). Severity is `error` for anything that breaks the chain or
/// its validity, and `warning` for an algorithm this module cannot verify.
pub fn findings(report: &ChainReport) -> Vec<Value> {
    let mut out = Vec::new();
    let mut push = |code: &str, severity: &str, cert: Option<usize>, message: String| {
        out.push(json!({ "code": code, "severity": severity, "cert": cert, "message": message }));
    };
    for c in &report.certs {
        let at = Some(c.index);
        match c.signature {
            SignatureCheck::Valid => {}
            SignatureCheck::Invalid => push(
                "signature-invalid",
                "error",
                at,
                format!("certificate {} is not signed by its issuer", c.index),
            ),
            SignatureCheck::Unsupported(why) => push(
                "signature-unsupported",
                "warning",
                at,
                format!("certificate {} was not verified: {why}", c.index),
            ),
        }
        if !c.issuer_name_matches {
            push(
                "issuer-name-mismatch",
                "error",
                at,
                format!(
                    "certificate {} names an issuer that is not the next certificate",
                    c.index
                ),
            );
        }
        match c.validity {
            Validity::Valid => {}
            Validity::NotYetValid => push(
                "validity-not-yet-valid",
                "error",
                at,
                format!("certificate {} is not valid yet at the check time", c.index),
            ),
            Validity::Expired => push(
                "validity-expired",
                "error",
                at,
                format!("certificate {} has expired at the check time", c.index),
            ),
        }
    }
    match report.root_self_signature {
        SignatureCheck::Valid => {}
        SignatureCheck::Invalid => push(
            "root-self-signature-invalid",
            "error",
            None,
            "the CI root is not correctly self-signed".into(),
        ),
        SignatureCheck::Unsupported(why) => push(
            "root-self-signature-unsupported",
            "warning",
            None,
            format!("the CI root was not verified: {why}"),
        ),
    }
    out
}

/// The doctor/1 `data` object for a chain check: per-certificate rows, the overall verdict,
/// the top-level `expired_or_not_yet_valid` flag, and the findings.
pub fn to_json(report: &ChainReport, root: &Certificate, now: &str) -> Value {
    let certs: Vec<Value> = report
        .certs
        .iter()
        .map(|c| {
            json!({
                "index": c.index,
                "fingerprint": c.fingerprint,
                "serial": c.serial,
                "not_before": c.not_before,
                "not_after": c.not_after,
                "validity": validity_name(c.validity),
                "key_usage": c.key_usage,
                "issuer_name_matches": c.issuer_name_matches,
                "signature": signature_name(c.signature),
            })
        })
        .collect();
    json!({
        "card_touched": false,
        "now": now,
        "verdict": verdict(report).as_str(),
        "verified": report.verified,
        "expired_or_not_yet_valid": out_of_validity(report),
        "root": {
            "fingerprint": root.fingerprint,
            "serial": root.serial,
            "not_before": root.not_before,
            "not_after": root.not_after,
            "self_signature": signature_name(report.root_self_signature),
        },
        "certs": certs,
        "findings": findings(report),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway P-256 CI root and EUM leaf, made with openssl 3.6 for this test. Test PKI only,
    // not a GSMA certificate; the private keys were discarded.
    const ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkjCCATmgAwIBAgIUYOJljb54sgDgAxJF7YLH9c/A7hMwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBDSSBSb290MB4XDTI2MTAxNTA1MzQzOVoXDTM2MTAx
MjA1MzQzOVowFzEVMBMGA1UEAwwMVGVzdCBDSSBSb290MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE6sxZmeFk6VxyMpvRFn69OAY0bq8mhtYDgPOCd0LXEcQoBcPl
RGa5NKY42H+5siMzt+HBtV23rOvOfqhD1Z5JnqNjMGEwHQYDVR0OBBYEFEtxOYGG
CbfKG+ljqpTzGhixSiAPMB8GA1UdIwQYMBaAFEtxOYGGCbfKG+ljqpTzGhixSiAP
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cA
MEQCIEArb5gvOeNxaK10vR+uqcaT857Jt1VN08oJYkvmbZ52AiBFke8lNiB4yUlk
xi3beTBzlDkFIrUdA4ezDnczCU9wLg==
-----END CERTIFICATE-----
";
    const LEAF_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBeTCCASCgAwIBAgICBNIwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMVGVzdCBD
SSBSb290MB4XDTI2MTAxNTA1MzQzOVoXDTMxMTAxNDA1MzQzOVowEzERMA8GA1UE
AwwIVGVzdCBFVU0wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtocQAtt0ZCoGK
4/4xh0bNKm3qz1KE5/2p+ErZhhfISQb9SBd4Hgc7mtqTKt33sCnd2SUTSe+ix/MH
fVmC13SYo2AwXjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQUMb53FfElnqZslFWeBBAmKXzADbMwHwYDVR0jBBgwFoAUS3E5gYYJt8ob6WOq
lPMaGLFKIA8wCgYIKoZIzj0EAwIDRwAwRAIgG7r+idgeU1S2+aBdhNvkhuyTXy9C
M2IOIIskVvtMhvECICPDG2YKnGqzt5Sj6ulwq/ZLI2sH3yjElnCp9JVhudTz
-----END CERTIFICATE-----
";
    const NOW: &str = "20261015120000";

    fn chain() -> (Vec<Certificate>, Certificate) {
        let leaf = parse_chain(LEAF_PEM.as_bytes()).unwrap().remove(0);
        let root = parse_chain(ROOT_PEM.as_bytes()).unwrap().remove(0);
        (vec![leaf], root)
    }

    #[test]
    fn parses_fields_from_pem() {
        let (leaf, root) = chain();
        let leaf = &leaf[0];
        assert_eq!(leaf.serial, "04d2");
        assert_eq!(leaf.not_before, "20261015053439");
        assert_eq!(leaf.not_after, "20311014053439");
        assert_eq!(leaf.key_usage, Some(vec!["digitalSignature"]));
        assert_eq!(root.key_usage, Some(vec!["keyCertSign", "cRLSign"]));
        assert_eq!(leaf.signature_algorithm, "1.2.840.10045.4.3.2");
    }

    #[test]
    fn verifies_leaf_to_ci_root_and_reports_validity() {
        let (chain, root) = chain();
        let report = verify_chain(&chain, &root, NOW).unwrap();
        assert!(report.verified);
        assert_eq!(report.root_self_signature, SignatureCheck::Valid);
        assert_eq!(report.certs[0].signature, SignatureCheck::Valid);
        assert!(report.certs[0].issuer_name_matches);
        assert_eq!(report.certs[0].validity, Validity::Valid);
    }

    #[test]
    fn a_wrong_ci_root_fails_the_chain() {
        let (chain, _) = chain();
        // The leaf itself is not a CA for this chain: its key cannot have signed the leaf.
        let report = verify_chain(&chain, &chain[0], NOW).unwrap();
        assert!(!report.verified);
        assert_eq!(report.certs[0].signature, SignatureCheck::Invalid);
    }

    #[test]
    fn a_tampered_tbs_fails_the_signature() {
        let (_, root) = chain();
        let mut der = parse_chain(LEAF_PEM.as_bytes()).unwrap().remove(0).der;
        // Serial 04 d2 -> 04 d3: still valid DER, but the signed bytes changed.
        let at = der
            .windows(4)
            .position(|w| w == [0x02, 0x02, 0x04, 0xd2])
            .unwrap();
        der[at + 3] = 0xd3;
        let tampered = Certificate::parse(&der).unwrap();
        let report = verify_chain(&[tampered], &root, NOW).unwrap();
        assert!(!report.verified);
        assert_eq!(report.certs[0].signature, SignatureCheck::Invalid);
    }

    #[test]
    fn validity_reports_before_and_after_the_period() {
        let (chain, _) = chain();
        assert_eq!(
            chain[0].validity_at("20000101000000"),
            Validity::NotYetValid
        );
        assert_eq!(chain[0].validity_at("20400101000000"), Validity::Expired);
    }

    #[test]
    fn empty_and_non_certificate_inputs_are_errors() {
        let (_, root) = chain();
        assert_eq!(verify_chain(&[], &root, NOW), Err(Error::EmptyChain));
        assert!(matches!(parse_chain(b"hello"), Err(Error::Pem(_))));
    }
}
