//! GlobalPlatform card certificates (tag `7F21`) of SCP11: parse, construct and sign.
//!
//! **Owns.** The BER-TLV *writing* of a `7F21` body and the read-back of one, the field order and
//! the mandatory set of SCP11 (GP Amendment F v1.4 Table 6-1), and the offline ECDSA P-256
//! signature over the bytes to be signed. It never touches a reader, a card or the network.
//!
//! **Does not own.** X.509. A GP card certificate is BER-TLV inside `7F21`, not a DER certificate,
//! so it is not something [`crate::cert`] parses; what it borrows from there is the one signature
//! verifier, [`crate::cert::verify_ecdsa_p256`], so a chain check and a card-certificate check
//! cannot disagree about the same bytes. The BER-TLV *reading and writing* is [`crate::es10`],
//! the reader and writer this crate already carries for SGP.22 payloads, whose multi-octet tags
//! are the reason it exists; this module adds no parser of its own. The strict DER reader is
//! [`crate::der`], unused here because a `7F21` is BER-TLV and not DER.
//!
//! # What the reference does, and where
//!
//! GlobalPlatformPro `library/src/main/java/pro/javacard/gp/GPCertificate.java`:
//!
//! - line 21: the tag itself, "GlobalPlatform certificate (tag 7F21) of SCP11 (Amendment F v1.4
//!   Table 6-1)",
//! - lines 26-40: every field tag used below (`93` serial, `42` CA, `5F20` subject, `95` usage,
//!   `5F25` effective, `5F24` expires, `45` image number, `53` and `73` discretionary, `BF20`
//!   authorizations, `7F49` public key, `5F37` signature, `B0` point, `F0` curve reference),
//! - lines 44 and 48: [`ORDER`] and [`MANDATORY`], which are what make [`Builder::dtbs`]
//!   deterministic: the same fields in the same values produce the same octets whatever order the
//!   caller supplied them in,
//! - lines 51-60: the Key Usage of `95` (GPC v2.3.1 11.1.9), [`Usage::Verification`] and
//!   [`Usage::Agreement`], and the rule that a one-octet `95` is the high octet with `00` implied,
//! - lines 282-296: both dates are four octets of BCD `YYYYMMDD`; the hexadecimal reading of the
//!   four bytes *is* the date,
//! - lines 372-376: `7F49` holds `B0` (the point) then `F0` (the curve's key parameter
//!   reference),
//! - lines 386-392: [`Builder::dtbs`] is the sorted concatenation of the present fields,
//! - lines 394-398: signing appends `5F37` over exactly those bytes, with the plain `R||S` form
//!   `GPCrypto.ecdsa_plain` produces.
//!
//! `GPCurve.java` lines 27-28 give the key parameter reference of `secp256r1` as `00`, and line 91
//! requires an uncompressed point: `04 || X || Y`, 65 octets.
//!
//! `GPCommandLineInterface.java` lines 181-227 are the flag names this command mirrors
//! (`--cert-serial`, `--cert-ca`, `--cert-subject`, `--cert-usage`, `--cert-effective`,
//! `--cert-expires`, `--cert-discretionary`, `--cert-authorizations`, `--cert-pubkey`,
//! `--cert-out`), and line 181 is why nothing here touches a card except the read command.
//!
//! # No clock
//!
//! [`Builder`] has no notion of "now". Every date is supplied by the operator as `YYYYMMDD` and
//! stored as BCD, and a certificate with no `5F24` is refused rather than given an expiry this
//! tool invented. A certificate that silently grew a validity period while it was being signed
//! would not be the certificate the operator asked for, and a byte-exact output is worth more
//! than a convenient default.
//!
//! The date is stored as four octets of BCD and is not calendar-checked: `20279999` is a
//! well-formed BCD field and the card is where a real date is enforced. The format *is* checked.
//!
//! # Key material
//!
//! [`load_signing_key`] reads a file or an environment variable and nothing else. There is no
//! `KeySource` variant that takes a command-line value, and the rendered report never carries the
//! key, the scalar or its encoding.

use std::path::Path;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};

use crate::cert::SignatureCheck;

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "gpcert";

/// The card certificate itself, `7F21` (GPCertificate.java:26).
pub const TAG_CERTIFICATE: u16 = 0x7F21;
/// Certificate Serial Number, `93` (GPCertificate.java:27).
pub const TAG_SERIAL: u16 = 0x93;
/// The CA Identifier, `42` (GPCertificate.java:28).
pub const TAG_CA: u16 = 0x42;
/// The Subject Identifier, `5F20` (GPCertificate.java:29).
pub const TAG_SUBJECT: u16 = 0x5F20;
/// The Key Usage, `95` (GPCertificate.java:30).
pub const TAG_USAGE: u16 = 0x95;
/// The Effective Date, `5F25` (GPCertificate.java:31).
pub const TAG_EFFECTIVE: u16 = 0x5F25;
/// The Expiration Date, `5F24` (GPCertificate.java:32).
pub const TAG_EXPIRES: u16 = 0x5F24;
/// The Security Domain Image Number, `45` (GPCertificate.java:33).
pub const TAG_IMAGE_NUMBER: u16 = 0x45;
/// Discretionary Data, `53`, of unspecified format (GPCertificate.java:34).
pub const TAG_DISCRETIONARY: u16 = 0x53;
/// Discretionary Data, `73`, BER-TLV encoded (GPCertificate.java:35).
pub const TAG_DISCRETIONARY_TLV: u16 = 0x73;
/// The Authorization rules, `BF20` (GPCertificate.java:36).
pub const TAG_AUTHORIZATIONS: u16 = 0xBF20;
/// The Subject public key, `7F49` (GPCertificate.java:37).
pub const TAG_PUBLIC_KEY: u16 = 0x7F49;
/// The signature, `5F37` (GPCertificate.java:38).
pub const TAG_SIGNATURE: u16 = 0x5F37;
/// The public key point, `B0` (GPCertificate.java:39).
pub const TAG_POINT: u16 = 0xB0;
/// The curve's key parameter reference, `F0` (GPCertificate.java:40).
pub const TAG_CURVE: u16 = 0xF0;

/// The order fields are written in, which is what makes a constructed certificate byte-exact
/// (GPCertificate.java:44). Anything not named sorts after all of it.
pub const ORDER: [u16; 11] = [
    TAG_SERIAL,
    TAG_CA,
    TAG_SUBJECT,
    TAG_USAGE,
    TAG_EFFECTIVE,
    TAG_EXPIRES,
    TAG_IMAGE_NUMBER,
    TAG_DISCRETIONARY,
    TAG_DISCRETIONARY_TLV,
    TAG_AUTHORIZATIONS,
    TAG_PUBLIC_KEY,
];

/// The fields every profile of the format requires (GPCertificate.java:48).
pub const MANDATORY: [u16; 6] = [
    TAG_SERIAL,
    TAG_CA,
    TAG_SUBJECT,
    TAG_USAGE,
    TAG_EXPIRES,
    TAG_PUBLIC_KEY,
];

/// The key parameter reference of `secp256r1` (GPCurve.java:27): the byte `00`, which is why `F0`
/// carries a single octet rather than a two-octet reference.
pub const CURVE_P256: u8 = 0x00;

/// The length of an uncompressed P-256 point, `04 || X || Y` (GPCurve.java:91).
pub const POINT_P256_LEN: usize = 65;

/// The longest field value this encoder writes.
///
/// 255 octets, the widest a length octet in this encoding can describe.
pub const MAX_VALUE_LEN: usize = 0xFF;

/// Key Usage of tag `95` (GPCertificate.java:51-60, GPC v2.3.1 Tables 11-17 and 11-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// `82 00`: b8 verification and b2 digital signature.
    Verification,
    /// `00`: b8 key agreement.
    Agreement,
}

impl Usage {
    /// The octets `95` carries. Agreement is one octet because its low half is zero
    /// (GPCertificate.java:60-62).
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Verification => vec![0x82, 0x00],
            Self::Agreement => vec![0x00],
        }
    }

    /// Reads the usage back. A one-octet value is the high octet with `00` implied
    /// (GPCertificate.java:66-68); anything else is an error, not a guess.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        match value {
            [0x82, 0x00] | [0x82] => Ok(Self::Verification),
            [0x00] => Ok(Self::Agreement),
            _ => Err(Error::Usage),
        }
    }

    /// The name used in output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verification => "verification (82 00)",
            Self::Agreement => "agreement (00)",
        }
    }
}

/// Why a card certificate could not be built, read or signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A field value was longer than [`MAX_VALUE_LEN`], so it has no length octet here.
    #[error(
        "field {tag:04X} is {len} octets, longer than the {max} a GP length octet can describe"
    )]
    ValueTooLong {
        /// The field that was too long.
        tag: u16,
        /// Its length.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// The caller tried to set the signature as a field.
    #[error("5F37 is written by signing, not supplied as a field")]
    SignatureIsNotAField,

    /// A mandatory field was absent (GPCertificate.java:319-321).
    #[error("certificate is missing mandatory field {0:04X}")]
    MissingField(u16),

    /// The same field was given twice.
    #[error("field {0:04X} was given more than once")]
    DuplicateField(u16),

    /// The octets are not a `7F21` body, or are truncated.
    #[error("not a 7F21 card certificate: {0}")]
    Malformed(String),

    /// The `95` key usage is not one of the two the specification names.
    #[error("key usage 95 is not one of the two values GPC v2.3.1 11.1.9 defines")]
    Usage,

    /// A date was not eight digits of `YYYYMMDD`.
    #[error("date {0:?} is not eight digits of YYYYMMDD")]
    Date(String),

    /// A public key point was not an uncompressed P-256 point.
    #[error("public key point is {len} octets and does not start 04; an uncompressed P-256 point is 65 octets starting 04")]
    Point {
        /// Its length.
        len: usize,
    },

    /// The key file or variable did not hold a P-256 scalar.
    #[error("signing key: {0}")]
    Key(String),

    /// Reading the key file failed.
    #[error("cannot read the signing key: {0}")]
    KeyIo(String),
}

/// One GP card certificate: the `7F21` body, its fields in canonical order, and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    body: Vec<u8>,
    /// How much of `body` the signature covers: everything before `5F37`.
    signed_len: usize,
    fields: Vec<(u16, Vec<u8>)>,
    signature: Vec<u8>,
}

impl Certificate {
    /// The `7F21` TLV: the two-octet tag, the length in the form [`crate::es10::parse`] reads,
    /// and the body.
    ///
    /// Infallible. A body built here carries at most [`MAX_VALUE_LEN`] per field and there are a
    /// dozen fields; one read off a card is bounded by the card.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 5);
        crate::es10::push_tlv(&mut out, u32::from(TAG_CERTIFICATE), &self.body);
        out
    }

    /// The octets the signature was made over: the body up to, and not including, `5F37`
    /// (GPCertificate.java:264-265).
    ///
    /// The length is carried, not searched for, because a discretionary value is allowed to
    /// contain the octets `5F 37 40` without being the signature.
    pub fn signed_data(&self) -> &[u8] {
        &self.body[..self.signed_len]
    }

    /// The fields in canonical order.
    pub fn fields(&self) -> &[(u16, Vec<u8>)] {
        &self.fields
    }

    /// The value of `5F37`.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The value of one field.
    pub fn field(&self, tag: u16) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| v.as_slice())
    }

    /// The Certificate Serial Number, `93`.
    pub fn serial(&self) -> Option<&[u8]> {
        self.field(TAG_SERIAL)
    }

    /// The CA Identifier, `42`.
    pub fn ca(&self) -> Option<&[u8]> {
        self.field(TAG_CA)
    }

    /// The Subject Identifier, `5F20`.
    pub fn subject(&self) -> Option<&[u8]> {
        self.field(TAG_SUBJECT)
    }

    /// The Effective Date, `5F25`, as `YYYYMMDD`.
    pub fn effective(&self) -> Option<String> {
        self.field(TAG_EFFECTIVE).map(hex::encode_upper)
    }

    /// The Expiration Date, `5F24`, as `YYYYMMDD`.
    pub fn expires(&self) -> Option<String> {
        self.field(TAG_EXPIRES).map(hex::encode_upper)
    }

    /// The Key Usage of `95`.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`], or [`Error::MissingField`] when `95` is absent.
    pub fn usage(&self) -> Result<Usage, Error> {
        match self.field(TAG_USAGE) {
            Some(v) => Usage::parse(v),
            None => Err(Error::MissingField(TAG_USAGE)),
        }
    }

    /// The `B0` point inside `7F49`.
    pub fn public_key_point(&self) -> Option<&[u8]> {
        let key = self.field(TAG_PUBLIC_KEY)?;
        let parts = crate::es10::parse(key).ok()?;
        let point = parts.first()?;
        (point.tag == u32::from(TAG_POINT)).then_some(point.value)
    }

    /// The `F0` key parameter reference inside `7F49`.
    pub fn curve_reference(&self) -> Option<u8> {
        let key = self.field(TAG_PUBLIC_KEY)?;
        let parts = crate::es10::parse(key).ok()?;
        let curve = parts.get(1)?;
        (curve.tag == u32::from(TAG_CURVE))
            .then_some(curve.value.last().copied())
            .flatten()
    }

    /// Checks `5F37` against an issuer's public key point.
    ///
    /// Goes through [`crate::cert::verify_ecdsa_p256`], the same ECDSA P-256 / SHA-256 check the
    /// X.509 chain verifier uses, so the two cannot drift apart.
    pub fn verify_signature(&self, issuer_point: &[u8]) -> SignatureCheck {
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return SignatureCheck::Invalid;
        };
        if crate::cert::Certificate::verify_ecdsa_p256(issuer_point, self.signed_data(), &sig) {
            SignatureCheck::Valid
        } else {
            SignatureCheck::Invalid
        }
    }
}

/// The doctor/1 `data` object for a read or constructed certificate.
pub fn to_json(cert: &Certificate) -> Value {
    let fields: Vec<Value> = cert
        .fields()
        .iter()
        .map(|(tag, value)| {
            json!({ "tag": format!("{tag:04X}"), "value": hex::encode_upper(value) })
        })
        .collect();
    json!({
        "tag": "7F21",
        "fields": fields,
        "signed_data_len": cert.signed_data().len(),
        "signature": hex::encode_upper(cert.signature()),
        "usage": cert.usage().map(|u| u.as_str()).unwrap_or("unreadable"),
        "expires": cert.expires(),
        "effective": cert.effective(),
        "public_key_point": cert.public_key_point().map(hex::encode_upper),
    })
}

/// The plain text table for one certificate.
pub fn render(cert: &Certificate) -> String {
    let mut out = String::from("GP card certificate 7F21 (SCP11, GP Amendment F v1.4 Table 6-1)\n");
    for (tag, value) in cert.fields() {
        out.push_str(&format!("  {tag:04X}  {}\n", hex::encode_upper(value)));
    }
    out.push_str(&format!(
        "  5F37  {}  ({} octets)\n",
        hex::encode_upper(cert.signature()),
        cert.signature().len()
    ));
    out.push_str(&format!(
        "\nsigned over {} octets\n",
        cert.signed_data().len()
    ));
    out
}

/// Writes one BER-TLV value: the tag, then a length, then the value, in the form
/// [`crate::es10::parse`] reads back.
///
/// The writer is [`crate::es10::push_tlv`], the reader's own. That is the reason to use it: a
/// second hand-rolled length form inside one crate is how a certificate gets written with a
/// length octet no reader will accept, and the first version of this module did exactly that.
///
/// GP card data is BER-TLV, not DER, so this is not [`crate::der`] and does not try to be. The
/// two-octet tag form is ISO/IEC 7816-4, which is the same form the `7F21` body itself uses.
///
/// # Errors
///
/// [`Error::ValueTooLong`] past [`MAX_VALUE_LEN`]. A GP card certificate does not carry a single
/// field that long; a certificate that does is read, not written.
pub fn encode_tlv(tag: u16, value: &[u8]) -> Result<Vec<u8>, Error> {
    if value.len() > MAX_VALUE_LEN {
        return Err(Error::ValueTooLong {
            tag,
            len: value.len(),
            max: MAX_VALUE_LEN,
        });
    }
    let mut out = Vec::with_capacity(value.len() + 5);
    crate::es10::push_tlv(&mut out, u32::from(tag), value);
    Ok(out)
}

/// Writes a sequence of fields back to back, which is what a `7F21` body is
/// (GPCertificate.java:386-392, `TLV.encode`).
///
/// # Errors
///
/// Any [`Error::ValueTooLong`].
pub fn encode_all(items: &[(u16, Vec<u8>)]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for (tag, value) in items {
        out.extend_from_slice(&encode_tlv(*tag, value)?);
    }
    Ok(out)
}

/// Where a card-certificate signing key may come from.
///
/// Named here rather than reused from the SCP03 key source, because the two are not the same
/// thing: an SCP03 key is AES or 3DES and opens a secure channel, a card-certificate key is an
/// ECDSA P-256 scalar and signs a certificate. There is no variant that takes a value from the
/// command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource<'a> {
    /// A file holding the key.
    File(&'a Path),
    /// An environment variable holding the key.
    Env(&'a str),
}

/// How the key source is named in output. Never the key.
pub fn source_label(source: KeySource<'_>) -> String {
    match source {
        KeySource::File(p) => format!("file {}", p.display()),
        KeySource::Env(v) => format!("environment variable {v}"),
    }
}

/// Reads a signing key from a file or an environment variable.
///
/// The 32-octet P-256 scalar is written as 64 hex digits, as base64, or as 32 raw octets when the
/// input is not valid text (which is what a raw scalar dump looks like). Anything else is an
/// error.
///
/// There is deliberately no way to name a key on the command line: a key on `argv` is in the shell
/// history, in `/proc/*/cmdline` and in every process listing on the host.
///
/// # Errors
///
/// [`Error::KeyIo`] if the file cannot be read as a regular file, [`Error::Key`] if the content is
/// not a P-256 scalar.
pub fn load_signing_key(source: KeySource<'_>) -> Result<SigningKey, Error> {
    let raw: Vec<u8> = match source {
        KeySource::File(path) => crate::cert::read_regular_file(path).map_err(Error::KeyIo)?,
        KeySource::Env(name) => std::env::var(name)
            .map_err(|e| Error::Key(format!("{name}: {e}")))?
            .into_bytes(),
    };
    signing_key_from_bytes(&raw)
}

/// Reads a P-256 scalar out of `raw`; see [`load_signing_key`] for the accepted forms.
///
/// # Errors
///
/// [`Error::Key`] if the octets are not a scalar of the curve.
pub fn signing_key_from_bytes(raw: &[u8]) -> Result<SigningKey, Error> {
    let scalar = match std::str::from_utf8(raw) {
        Ok(text) => {
            let cleaned: String = text
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
                .collect();
            if cleaned.len() == 64 && cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
                hex::decode(&cleaned).map_err(|e| Error::Key(e.to_string()))?
            } else {
                crate::es9::b64_decode(&cleaned).map_err(Error::Key)?
            }
        }
        Err(_) => raw.to_vec(),
    };

    let bytes: [u8; 32] = scalar
        .as_slice()
        .try_into()
        .map_err(|_| Error::Key("a P-256 scalar is 32 octets".into()))?;
    SigningKey::from_bytes(&bytes.into()).map_err(|_| Error::Key("not a P-256 scalar".into()))
}

/// The uncompressed public point of a key, `04 || X || Y`.
pub fn public_point(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

/// Signs the bytes to be signed with a P-256 key and returns the plain `R || S` signature.
///
/// Plain, not DER: the reference's `GPCrypto.ecdsa_plain` (GPCertificate.java:398) produces the two
/// 32-octet integers side by side, and `GPCommandLineInterface.java:200` accepts "R||S or DER" on
/// the way in, so plain is what is written.
///
/// # Errors
///
/// Never, in practice; kept so the caller does not have to unwrap a panic path.
pub fn sign_plain(dtbs: &[u8], key: &SigningKey) -> Result<Vec<u8>, Error> {
    let sig: Signature = key.sign(dtbs);
    Ok(sig.to_bytes().to_vec())
}

/// Converts a DER ECDSA signature to the plain `R || S` form, for a signature supplied in DER.
///
/// # Errors
///
/// [`Error::Malformed`] if the octets are not a DER ECDSA signature.
pub fn plain_from_der(der: &[u8]) -> Result<Vec<u8>, Error> {
    let sig = Signature::from_der(der)
        .map_err(|_| Error::Malformed("not a DER ECDSA signature".into()))?;
    Ok(sig.to_bytes().to_vec())
}

/// The DER form of a plain `R || S` signature.
///
/// # Errors
///
/// [`Error::Malformed`] if the octets are not a plain `R || S` signature.
pub fn der_from_plain(plain: &[u8]) -> Result<Vec<u8>, Error> {
    plain_signature(plain)
        .map(|sig| sig.to_der().as_bytes().to_vec())
        .map_err(|_| Error::Malformed("not a plain R||S signature".into()))
}

fn plain_signature(plain: &[u8]) -> Result<Signature, ()> {
    Signature::from_slice(plain).map_err(|_| ())
}

/// A `7F21` body under construction.
///
/// Every setter takes a value the operator supplied. There is no default date and no serial from
/// the clock, so two runs with the same inputs produce the same octets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builder {
    fields: Vec<(u16, Vec<u8>)>,
}

impl Builder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a field, refusing `5F37` (GPCertificate.java:369-371: the signature is added by
    /// signing, never supplied).
    ///
    /// # Errors
    ///
    /// [`Error::SignatureIsNotAField`] or [`Error::DuplicateField`].
    pub fn field(&mut self, tag: u16, value: &[u8]) -> Result<(), Error> {
        if tag == TAG_SIGNATURE {
            return Err(Error::SignatureIsNotAField);
        }
        if self.fields.iter().any(|(t, _)| *t == tag) {
            return Err(Error::DuplicateField(tag));
        }
        self.fields.push((tag, value.to_vec()));
        Ok(())
    }

    /// The Certificate Serial Number, `93`.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn serial(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_SERIAL, value)
    }

    /// The CA Identifier, `42`.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn ca(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_CA, value)
    }

    /// The Subject Identifier, `5F20`.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn subject(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_SUBJECT, value)
    }

    /// The Key Usage, `95`.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn usage(&mut self, usage: Usage) -> Result<(), Error> {
        self.field(TAG_USAGE, &usage.encode())
    }

    /// The Effective Date, `5F25`, written from `YYYYMMDD` as four octets of BCD.
    ///
    /// # Errors
    ///
    /// [`Error::Date`] unless the date is eight decimal digits.
    pub fn effective(&mut self, yyyymmdd: &str) -> Result<(), Error> {
        self.field(TAG_EFFECTIVE, &bcd_date(yyyymmdd)?)
    }

    /// The Expiration Date, `5F24`, written from `YYYYMMDD` as four octets of BCD.
    ///
    /// # Errors
    ///
    /// [`Error::Date`] unless the date is eight decimal digits.
    pub fn expires(&mut self, yyyymmdd: &str) -> Result<(), Error> {
        self.field(TAG_EXPIRES, &bcd_date(yyyymmdd)?)
    }

    /// The Security Domain Image Number, `45`.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn image_number(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_IMAGE_NUMBER, value)
    }

    /// The Discretionary Data, `53`, of unspecified format.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn discretionary(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_DISCRETIONARY, value)
    }

    /// The Discretionary Data, `73`, already BER-TLV encoded.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn discretionary_tlv(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_DISCRETIONARY_TLV, value)
    }

    /// The Authorization rules, `BF20`.
    ///
    /// # Errors
    ///
    /// As [`Builder::field`].
    pub fn authorizations(&mut self, value: &[u8]) -> Result<(), Error> {
        self.field(TAG_AUTHORIZATIONS, value)
    }

    /// The Subject public key, `7F49`, holding `B0` (the uncompressed point) then `F0` (the key
    /// parameter reference), as GPCertificate.java:372-376 writes it.
    ///
    /// # Errors
    ///
    /// [`Error::Point`] unless the point is an uncompressed P-256 point.
    pub fn public_key(&mut self, point: &[u8]) -> Result<(), Error> {
        if point.len() != POINT_P256_LEN || point.first() != Some(&0x04) {
            return Err(Error::Point { len: point.len() });
        }
        let mut value = encode_tlv(TAG_POINT, point)?;
        value.extend_from_slice(&encode_tlv(TAG_CURVE, &[CURVE_P256])?);
        self.field(TAG_PUBLIC_KEY, &value)
    }

    /// The present fields, sorted into [`ORDER`].
    fn sorted(&self) -> Vec<(u16, Vec<u8>)> {
        let rank = |tag: u16| ORDER.iter().position(|t| *t == tag).unwrap_or(ORDER.len());
        let mut fields = self.fields.clone();
        fields.sort_by_key(|(tag, _)| rank(*tag));
        fields
    }

    /// The bytes to be signed: every present field, in [`ORDER`], back to back
    /// (GPCertificate.java:386-392).
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] for the first absent mandatory field, or [`Error::ValueTooLong`].
    pub fn dtbs(&self) -> Result<Vec<u8>, Error> {
        for tag in MANDATORY {
            if !self.fields.iter().any(|(t, _)| *t == tag) {
                return Err(Error::MissingField(tag));
            }
        }
        encode_all(&self.sorted())
    }

    /// The unsigned certificate: the bytes to be signed, with no `5F37`.
    ///
    /// # Errors
    ///
    /// As [`Builder::dtbs`].
    pub fn unsigned(&self) -> Result<Certificate, Error> {
        let body = self.dtbs()?;
        Ok(Certificate {
            signed_len: body.len(),
            body,
            fields: self.sorted(),
            signature: Vec::new(),
        })
    }

    /// Completes the certificate with a signature made over [`Builder::dtbs`]
    /// (GPCertificate.java:394-398).
    ///
    /// # Errors
    ///
    /// As [`Builder::dtbs`], plus [`Error::ValueTooLong`] for a signature that does not fit.
    pub fn sign(&self, plain: &[u8]) -> Result<Certificate, Error> {
        let body = self.dtbs()?;
        let signed_len = body.len();
        let mut complete = body;
        complete.extend_from_slice(&encode_tlv(TAG_SIGNATURE, plain)?);
        Ok(Certificate {
            body: complete,
            signed_len,
            fields: self.sorted(),
            signature: plain.to_vec(),
        })
    }
}

/// Reads a `7F21` TLV back into a [`Certificate`].
///
/// The BER-TLV reader is [`crate::tlv`]; there is no second one here. The signature must be the
/// last field (GPCertificate.java:132-134), because anything after it would be a field the
/// signature does not cover.
///
/// # Errors
///
/// [`Error::Malformed`] if the input is not one `7F21` TLV, is truncated, carries fields after the
/// signature, or is missing the signature or a mandatory field.
pub fn parse(tlv: &[u8]) -> Result<Certificate, Error> {
    let nodes = crate::es10::parse(tlv).map_err(|e| Error::Malformed(e.to_string()))?;
    let consumed: usize = nodes.iter().map(|n| n.raw.len()).sum();
    if consumed != tlv.len() {
        return Err(Error::Malformed(format!(
            "{} octets after the certificate",
            tlv.len() - consumed
        )));
    }
    let outer = nodes
        .first()
        .ok_or_else(|| Error::Malformed("the input is empty".into()))?;
    if outer.tag != u32::from(TAG_CERTIFICATE) {
        return Err(Error::Malformed(format!("tag {:04X}, not 7F21", outer.tag)));
    }
    parse_body(outer.value)
}

/// Reads the body of a `7F21` (its value, without the tag).
///
/// # Errors
///
/// As [`parse`].
pub fn parse_body(body: &[u8]) -> Result<Certificate, Error> {
    let mut fields: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut signature: Option<Vec<u8>> = None;
    let mut signed_len = 0usize;
    let mut at = 0usize;

    let nodes = crate::es10::parse(body).map_err(|e| Error::Malformed(e.to_string()))?;
    let consumed: usize = nodes.iter().map(|n| n.raw.len()).sum();
    if consumed != body.len() {
        return Err(Error::Malformed(format!(
            "{} octets after the last field",
            body.len() - consumed
        )));
    }
    for tlv in &nodes {
        let tag = u16::try_from(tlv.tag)
            .map_err(|_| Error::Malformed(format!("tag {} is too wide for 7F21", tlv.tag)))?;
        if signature.is_some() {
            return Err(Error::Malformed(format!(
                "field {tag:04X} follows the signature 5F37 and is not covered by it"
            )));
        }
        if tag == TAG_SIGNATURE {
            signed_len = at;
            signature = Some(tlv.value.to_vec());
        } else {
            fields.push((tag, tlv.value.to_vec()));
        }
        at += tlv.raw.len();
    }

    let Some(signature) = signature else {
        return Err(Error::Malformed("certificate has no signature 5F37".into()));
    };
    for tag in MANDATORY {
        if !fields.iter().any(|(t, _)| *t == tag) {
            return Err(Error::Malformed(format!(
                "mandatory field {tag:04X} is absent"
            )));
        }
    }

    Ok(Certificate {
        body: body.to_vec(),
        signed_len,
        fields,
        signature,
    })
}

/// Four octets of BCD from `YYYYMMDD`, which is what the hexadecimal reading of the four bytes is
/// (GPCertificate.java:282-296).
///
/// # Errors
///
/// [`Error::Date`] unless the date is exactly eight decimal digits.
fn bcd_date(yyyymmdd: &str) -> Result<[u8; 4], Error> {
    let bad = || Error::Date(yyyymmdd.to_string());
    if yyyymmdd.len() != 8 || !yyyymmdd.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let mut out = [0u8; 4];
    for (i, pair) in yyyymmdd.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| bad())?;
        out[i] = u8::from_str_radix(text, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact octets of one constructed certificate, written out by hand from the tags in
    /// GPCertificate.java and the tag and length rules of ISO/IEC 7816-4. Written here rather than
    /// produced by this module, so that a change in the encoder cannot quietly move it.
    ///
    /// Fields in [`ORDER`]: `93 01 01`, `42 03 11 22 33`, `5F 20 02 44 55`, `95 02 82 00`,
    /// `5F 25 04 20 26 01 15`, `5F 24 04 20 27 01 15`, `7F 49 46 B0 41 04 00..3F F0 01 00`.
    /// The `B0` point is the 65 octets `04` followed by `00 01 .. 3F`: it is a **synthetic** point,
    /// chosen so that the expected octets can be written down. Only tests that compare against
    /// this constant use it; the ones that check a signature use [`the_signed_builder`].
    /// Lower case, because it is compared against `hex::encode`, which is lower case. The octets
    /// are the ones written out above; only the spelling of the hex digits differs.
    ///
    /// 3 + 5 + 5 + 4 + 7 + 7 + 3 + 2 + 1 + 64 + 3 = 104 octets.
    const EXPECTED_DTBS: &str = concat!(
        "930101",
        "4203112233",
        "5f20024455",
        "95028200",
        "5f250420260115",
        "5f240420270115",
        "7f4946",
        "b041",
        "04",
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f",
        "303132333435363738393a3b3c3d3e3f",
        "f00100",
    );

    /// A scalar that is not valid UTF-8, so the raw-octet form of [`signing_key_from_bytes`] is
    /// the one under test.
    const TEST_SCALAR: [u8; 32] = [0xABu8; 32];

    fn synthetic_point() -> Vec<u8> {
        let mut point = vec![0x04];
        point.extend((0..64).map(|i| i as u8));
        point
    }

    fn builder_with(point: Vec<u8>) -> Builder {
        let mut b = Builder::new();
        b.serial(&[0x01]).unwrap();
        b.ca(&[0x11, 0x22, 0x33]).unwrap();
        b.subject(&[0x44, 0x55]).unwrap();
        b.usage(Usage::Verification).unwrap();
        b.effective("20260115").unwrap();
        b.expires("20270115").unwrap();
        b.public_key(&point).unwrap();
        b
    }

    fn the_builder() -> Builder {
        builder_with(synthetic_point())
    }

    /// The same fields, carrying the real public point of [`test_key`].
    ///
    /// A certificate whose signature is checked has to carry the key that made that signature,
    /// or it is a certificate about nothing. The synthetic point is there so [`EXPECTED_DTBS`]
    /// can be written out octet by octet, so only the tests comparing against that constant use
    /// [`the_builder`]; every test that signs uses this one.
    fn the_signed_builder() -> Builder {
        builder_with(public_point(&test_key()))
    }

    fn test_key() -> SigningKey {
        signing_key_from_bytes(&TEST_SCALAR).unwrap()
    }

    #[test]
    fn a_constructed_certificate_is_the_octets_written_down_by_hand() {
        let dtbs = the_builder().dtbs().unwrap();
        assert_eq!(hex::encode(&dtbs), EXPECTED_DTBS);

        // And the whole thing as `7F 21 68` then the body: 104 octets is under 128, so the
        // length takes the short form.
        let unsigned = the_builder().unsigned().unwrap();
        let tlv = unsigned.encode();
        assert_eq!(&tlv[..3], &[0x7F, 0x21, 0x68]);
        assert_eq!(&tlv[3..], &dtbs[..]);
        assert_eq!(tlv.len(), 107);
    }

    #[test]
    fn field_order_does_not_depend_on_the_order_the_fields_were_supplied() {
        let mut a = Builder::new();
        a.public_key(&synthetic_point()).unwrap();
        a.expires("20270115").unwrap();
        a.subject(&[0x44, 0x55]).unwrap();
        a.ca(&[0x11, 0x22, 0x33]).unwrap();
        a.usage(Usage::Verification).unwrap();
        a.effective("20260115").unwrap();
        a.serial(&[0x01]).unwrap();
        assert_eq!(hex::encode(a.dtbs().unwrap()), EXPECTED_DTBS);
    }

    #[test]
    fn a_missing_mandatory_field_is_refused_and_the_field_is_named() {
        let mut b = Builder::new();
        b.serial(&[0x01]).unwrap();
        assert_eq!(b.dtbs(), Err(Error::MissingField(TAG_CA)));
    }

    #[test]
    fn the_signature_is_not_a_field_and_a_field_is_not_supplied_twice() {
        let mut b = the_builder();
        assert_eq!(
            b.field(TAG_SIGNATURE, &[0x00]),
            Err(Error::SignatureIsNotAField)
        );
        assert_eq!(b.subject(&[0x01]), Err(Error::DuplicateField(TAG_SUBJECT)));
    }

    #[test]
    fn a_date_that_is_not_yyyymmdd_is_refused_rather_than_rounded() {
        let mut b = the_builder();
        assert_eq!(
            b.expires("2027-01-15"),
            Err(Error::Date("2027-01-15".into()))
        );
        assert_eq!(b.expires("2027011"), Err(Error::Date("2027011".into())));
        assert_eq!(b.expires("2027011a"), Err(Error::Date("2027011a".into())));
    }

    #[test]
    fn a_public_key_point_that_is_not_an_uncompressed_p256_point_is_refused() {
        let mut b = the_builder();
        assert_eq!(b.public_key(&[0x04; 64]), Err(Error::Point { len: 64 }));
        let mut wrong_tag = synthetic_point();
        wrong_tag[0] = 0x02;
        assert_eq!(b.public_key(&wrong_tag), Err(Error::Point { len: 65 }));
    }

    #[test]
    fn key_usage_is_two_named_values_and_nothing_else() {
        assert_eq!(Usage::Verification.encode(), vec![0x82, 0x00]);
        assert_eq!(Usage::Agreement.encode(), vec![0x00]);
        assert_eq!(Usage::parse(&[0x82, 0x00]), Ok(Usage::Verification));
        assert_eq!(Usage::parse(&[0x00]), Ok(Usage::Agreement));
        assert_eq!(Usage::parse(&[0x82, 0x01]), Err(Error::Usage));
        assert_eq!(Usage::parse(&[0x00, 0x00]), Err(Error::Usage));
    }

    #[test]
    fn a_signed_certificate_verifies_and_reads_back() {
        let key = test_key();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();
        assert_eq!(
            plain.len(),
            64,
            "a plain P-256 signature is R||S, 64 octets"
        );

        let cert = the_signed_builder().sign(&plain).unwrap();
        let round_trip = parse(&cert.encode()).unwrap();
        assert_eq!(round_trip, cert);
        assert_eq!(
            round_trip.signed_data(),
            the_signed_builder().dtbs().unwrap()
        );
        assert_eq!(round_trip.expires().as_deref(), Some("20270115"));
        assert_eq!(round_trip.effective().as_deref(), Some("20260115"));
        assert_eq!(round_trip.usage(), Ok(Usage::Verification));
        assert_eq!(round_trip.curve_reference(), Some(CURVE_P256));
        assert_eq!(
            round_trip.public_key_point(),
            Some(public_point(&key).as_slice())
        );

        assert_eq!(
            round_trip.verify_signature(&public_point(&key)),
            SignatureCheck::Valid
        );
    }

    #[test]
    fn the_der_form_of_the_signature_round_trips_to_the_plain_one() {
        let key = test_key();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();
        let der = der_from_plain(&plain).unwrap();
        assert_ne!(der, plain);
        assert_eq!(plain_from_der(&der).unwrap(), plain);
        assert!(plain_from_der(b"not a signature").is_err());
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let key = test_key();
        let mut plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();
        plain[63] ^= 0x01;
        let cert = the_signed_builder().sign(&plain).unwrap();
        assert_eq!(
            cert.verify_signature(&public_point(&key)),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn a_tampered_certificate_body_is_refused() {
        let key = test_key();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();
        let mut cert = the_signed_builder().sign(&plain).unwrap();
        // The serial `93 01 01` becomes `93 01 02`, inside the signed octets.
        let at = cert
            .body
            .windows(3)
            .position(|w| w == [0x93, 0x01, 0x01])
            .unwrap();
        cert.body[at + 2] = 0x02;
        assert_eq!(
            cert.verify_signature(&public_point(&key)),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn a_signature_made_with_another_key_is_refused() {
        let signer = test_key();
        let other = signing_key_from_bytes(&[0xCDu8; 32]).unwrap();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &signer).unwrap();
        let cert = the_signed_builder().sign(&plain).unwrap();
        assert_eq!(
            cert.verify_signature(&public_point(&other)),
            SignatureCheck::Invalid
        );
        assert_eq!(
            cert.verify_signature(&public_point(&signer)),
            SignatureCheck::Valid
        );
    }

    #[test]
    fn malformed_input_is_refused_rather_than_guessed() {
        // Not a 7F21 at all.
        assert!(matches!(
            parse(&[0x30, 0x03, 0x02, 0x01, 0x05]),
            Err(Error::Malformed(_))
        ));
        // Truncated mid-field.
        assert!(matches!(
            parse(&[0x7F, 0x21, 0x06, 0x93, 0x01]),
            Err(Error::Malformed(_))
        ));

        let key = test_key();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();

        // Trailing octets after the certificate.
        let mut bytes = the_signed_builder().sign(&plain).unwrap().encode();
        bytes.push(0x00);
        assert!(matches!(parse(&bytes), Err(Error::Malformed(_))));

        // No signature at all.
        let unsigned = the_signed_builder().unsigned().unwrap().encode();
        assert!(matches!(
            parse(&unsigned),
            Err(Error::Malformed(ref m)) if m.contains("no signature")
        ));

        // A field after the signature, which the signature would not cover.
        let mut after = the_signed_builder().sign(&plain).unwrap();
        after
            .body
            .extend_from_slice(&encode_tlv(TAG_SERIAL, &[0x09]).unwrap());
        assert!(matches!(
            parse(&encode_tlv(TAG_CERTIFICATE, &after.body).unwrap()),
            Err(Error::Malformed(ref m)) if m.contains("follows the signature")
        ));

        // A 5F37 that is not an R||S signature of the right length.
        let short = the_signed_builder().sign(&[0x00, 0x01]).unwrap().encode();
        assert_eq!(
            parse(&short).unwrap().verify_signature(&public_point(&key)),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn a_mandatory_field_missing_from_a_certificate_read_back_is_named() {
        let key = test_key();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();
        let cert = the_signed_builder().sign(&plain).unwrap();
        // The CA Identifier `42 03 11 22 33` is spliced out of the middle and the signature is
        // left in place, so it is the mandatory set that has to fail and name the tag. Dropping
        // the signature instead would only report that there is no signature.
        let mut body = cert.body.clone();
        let at = body
            .windows(5)
            .position(|w| w == [0x42, 0x03, 0x11, 0x22, 0x33])
            .unwrap();
        body.drain(at..at + 5);
        assert!(matches!(
            parse_body(&body),
            Err(Error::Malformed(ref m)) if m.contains("mandatory field 0042 is absent")
        ));
    }

    #[test]
    fn a_key_never_appears_in_the_rendered_output() {
        let key = test_key();
        let plain = sign_plain(&the_signed_builder().dtbs().unwrap(), &key).unwrap();
        let cert = the_signed_builder().sign(&plain).unwrap();
        let rendered = format!(
            "{}{}{}",
            render(&cert),
            serde_json::to_string(&to_json(&cert)).unwrap(),
            source_label(KeySource::Env("SIM_DOCTOR_GP_CERT_KEY")),
        );

        let secret_upper = hex::encode_upper(TEST_SCALAR);
        assert!(!rendered.contains(&secret_upper), "the raw key hex leaked");
        assert!(
            !rendered.contains(&secret_upper.to_lowercase()),
            "the raw key hex leaked in lower case"
        );
        assert!(rendered.contains("5F37"), "the signature must be shown");
        assert!(
            rendered.contains("SIM_DOCTOR_GP_CERT_KEY"),
            "the key source must be named"
        );
    }

    #[test]
    fn a_key_file_is_read_as_hex_or_base64_and_never_from_argv() {
        let key = test_key();
        assert_eq!(
            signing_key_from_bytes(&TEST_SCALAR).unwrap().to_bytes(),
            key.to_bytes()
        );
        for spelling in [
            hex::encode_upper(TEST_SCALAR),
            hex::encode(TEST_SCALAR),
            format!("{}\n", hex::encode_upper(TEST_SCALAR)),
            hex::encode_upper(TEST_SCALAR)
                .as_bytes()
                .chunks(2)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(":"),
        ] {
            assert_eq!(
                signing_key_from_bytes(spelling.as_bytes())
                    .unwrap()
                    .to_bytes(),
                key.to_bytes(),
                "{spelling:?} was not read as the key"
            );
        }
        assert_eq!(public_point(&key).len(), POINT_P256_LEN);

        // Not a scalar: refused, not clamped, and never a different key.
        assert!(signing_key_from_bytes(b"not a key").is_err());
        assert!(signing_key_from_bytes(&[0xFF; 31]).is_err());
        assert!(signing_key_from_bytes(&[0x00u8; 32]).is_err());
        assert!(signing_key_from_bytes(b"").is_err());
    }

    #[test]
    fn a_field_longer_than_a_length_octet_is_refused() {
        assert_eq!(
            encode_tlv(TAG_DISCRETIONARY, &[0xAA; 256]),
            Err(Error::ValueTooLong {
                tag: TAG_DISCRETIONARY,
                len: 256,
                max: MAX_VALUE_LEN
            })
        );
        assert!(encode_tlv(TAG_DISCRETIONARY, &[0xAA; 255]).is_ok());
    }

    #[test]
    fn tags_of_every_shape_in_the_7f21_family_encode_as_iso_7816_4_writes_them() {
        // Below 0x80: one octet. At and above: two, with bit 8 of the tag number clear.
        assert_eq!(encode_tlv(0x93, &[0x01]).unwrap()[..2], [0x93, 0x01]);
        assert_eq!(
            encode_tlv(TAG_SUBJECT, &[0x01]).unwrap()[..3],
            [0x5F, 0x20, 0x01]
        );
        assert_eq!(
            encode_tlv(TAG_CURVE, &[0x00]).unwrap()[..3],
            [0xF0, 0x01, 0x00]
        );
        assert_eq!(
            encode_tlv(TAG_CERTIFICATE, &[0x00]).unwrap()[..3],
            [0x7F, 0x21, 0x01]
        );
        assert_eq!(
            encode_tlv(TAG_AUTHORIZATIONS, &[0x00]).unwrap()[..3],
            [0xBF, 0x20, 0x01]
        );
    }
}
