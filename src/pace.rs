//! PACE, the Password Authenticated Connection Establishment of BSI
//! TR-03110, with the Card Application Number, and the AES secure messaging
//! channel that follows it.
//!
//! **Owns.** The PACE application selection, MSE:Set AT, the mutual
//! authentication steps and their cryptography (encrypted nonce, generic
//! mapping, ephemeral ECDH, authentication tokens), the key derivation
//! function, and the AES secure messaging that protects the APDUs afterwards.
//!
//! **Does not own.** Chip Authentication, which uses the same KDF with a
//! different counter, and everything after establishment: no profile is
//! installed or selected over the channel this module builds. PACE is an
//! authentication, not a write, so it is *not* behind `--yes`; the one write
//! it can lead to is the caller's, and that caller's own rules apply.
//!
//! # Spec map
//!
//! The reference implementation named by issue #260 is GlobalPlatformPro's
//! `pace` module, LGPL-3.0, read on 2026-10-16. Its own header cites BSI
//! TR-03110 Part 3 v2.2 and TR-03111 v2.0. Every wire shape below is taken
//! from that module and cited as `PACE.java:<line>` or
//! `AESSecureChannel.java:<line>`:
//!
//! - `PACE.java:57` - the OID `04 00 7F 00 07 02 02 04 02 04`,
//!   `0.4.0.127.0.7.2.2.4.2.4`, `id-PACE-ECDH-GM-AES-CBC-CMAC-256`.
//! - `PACE.java:59` - password reference `0x02`, the CAN.
//! - `PACE.java:62-66` - the four curves of TR-03110 A.2.1.1 Table 4.
//! - `PACE.java:78-79` - SELECT of the PACE application `00 A4 04 00 <AID>`.
//! - `PACE.java:82-83`, `:250-255` - MSE:Set AT `00 22 C1 A4` carrying tag
//!   `80` mechanism, `83` password, `84` curve.
//! - `PACE.java:86-87`, `:143-147` - GENERAL AUTHENTICATE `10 86 00 00`, and
//!   `00 86 00 00` for the last step.
//! - `PACE.java:90-95` - the encrypted nonce in tag `80`, decrypted under
//!   `KDF(CAN, counter 3)` with a zero IV.
//! - `PACE.java:101-102`, `:110` - host mapping public key in tag `81`, the
//!   card's in tag `82`.
//! - `PACE.java:117-118`, `:128` - host ephemeral public key in tag `83`, the
//!   card's in tag `84`.
//! - `PACE.java:133-139` - the session keys `KDF(k, 1)` for ENC and
//!   `KDF(k, 2)` for MAC, where `k` is the x coordinate of the ECDH point.
//! - `PACE.java:142-152` - the host token in tag `85`, checked against the
//!   card's tag `86`.
//! - `PACE.java:225-226` - the shared secret is the x coordinate, field
//!   width, big endian.
//! - `PACE.java:227-241` - the generic mapping `G' = s*G + h*d*Q_card`.
//! - `PACE.java:243-253` - the KDF, SHA-256 over `secret || nonce ||
//!   counter`, counter 4 big-endian bytes.
//! - `PACE.java:266-270` - `aes_mac8`: an AES-CMAC truncated to 8 bytes.
//! - `PACE.java:272-279` - the authentication token over the uncompressed
//!   public key, wrapped in `7F49 { 06 <OID>, 86 <key> }`.
//!
//! # The four curves, and which of them this module can reach
//!
//! TR-03110 A.2.1.1 Table 4 names four and the reference carries all four
//! (`PACE.java:62-66`): secp256r1 (code `12`), brainpoolP256r1 (`13`),
//! secp384r1 (`15`), brainpoolP384r1 (`16`). All four are in [`Curve`] with
//! their codes, and the codes are what goes on the wire.
//!
//! Only **secp256r1** is implemented, and the reason is a dependency
//! boundary, not a protocol one: this crate adds no package, and its ECC
//! stack is the `p256` crate alone (see the ECC section of `Cargo.toml`).
//! `p256` is P-256 and nothing else; P-384 and the Brainpool curves need the
//! `p384` and `brainpool` packages, which are not in `Cargo.lock`.
//! [`Curve::is_available`] and [`Error::CurveUnavailable`] report that at
//! runtime rather than agreeing to a curve this crate cannot compute on.
//! Everything around the curve - the KDF, the nonce, the tokens, the secure
//! messaging - is curve independent.
//!
//! # The CAN is a secret
//!
//! [`Can`] holds it, refuses to render it in `Debug`, and never appears in an
//! error message. It comes from a file or an environment variable
//! ([`CanSource`]), never from a command line, because a command line is shell
//! history and a process listing. The same rule [`crate::gp::Keys`] follows
//! for the SCP03 keys.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "pace";

use crate::apdu::{Command, Header, Le};
use crate::scp03::{cmac, BLOCK};
use crate::session::{self, Policy};
use crate::tlv::Length;
use crate::transport::CardSession;
use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes::Aes256;
use p256::elliptic_curve::{point::AffineCoordinates, sec1::ToSec1Point, FieldBytes, PrimeField};
use p256::{NistP256, ProjectivePoint, PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};

/// `id-PACE-ECDH-GM-AES-CBC-CMAC-256`, `0.4.0.127.0.7.2.2.4.2.4`
/// (`PACE.java:57`).
pub const OID: [u8; 10] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];

/// Password reference `0x02`, the CAN (`PACE.java:59`).
pub const PASSWORD_CAN: u8 = 0x02;

/// GENERAL AUTHENTICATE, ISO 7816-4 instruction `0x86` (`PACE.java:144`).
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x86;

/// MANAGE SECURITY ENVIRONMENT, ISO 7816-4 instruction `0x22`.
pub const INS_MSE: u8 = 0x22;

/// MSE:Set AT P1 for mutual authentication (`PACE.java:250`).
pub const P1_MUTUAL_AUTHENTICATE: u8 = 0xC1;

/// MSE:Set AT P2 for an authentication template (`PACE.java:250`).
pub const P2_AT: u8 = 0xA4;

/// The KDF counter for K-ENC (`PACE.java:246`).
pub const COUNTER_ENC: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
/// The KDF counter for K-MAC (`PACE.java:247`).
pub const COUNTER_MAC: [u8; 4] = [0x00, 0x00, 0x00, 0x02];
/// The KDF counter for the CAN-derived password key (`PACE.java:248`).
pub const COUNTER_PI: [u8; 4] = [0x00, 0x00, 0x00, 0x03];

/// Length of the nonce PACE decrypts in step 1, in bytes (A.3.3).
pub const NONCE_LEN: usize = 16;
/// Length of an authentication token: the AES-CMAC truncated to 8 bytes.
pub const TOKEN_LEN: usize = 8;
/// Length of a derived PACE session key. The KDF is SHA-256 and the reference
/// does not truncate it (`PACE.java:252`).
pub const KEY_LEN: usize = 32;
/// Largest CAN accepted, in bytes. A CAN is far shorter; this is a bound, not
/// a format rule.
pub const CAN_MAX: usize = 32;

/// One of the four standardised domain parameters of TR-03110 A.2.1.1
/// Table 4, as the reference enumerates them (`PACE.java:62-66`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256, code `12`. The one this crate can compute on.
    Secp256r1,
    /// ECC Brainpool P256r1, code `13`.
    BrainpoolP256r1,
    /// NIST P-384, code `15`.
    Secp384r1,
    /// ECC Brainpool P384r1, code `16`.
    BrainpoolP384r1,
}

/// All four, in the order the reference lists them.
pub const CURVES: [Curve; 4] = [
    Curve::Secp256r1,
    Curve::BrainpoolP256r1,
    Curve::Secp384r1,
    Curve::BrainpoolP384r1,
];

impl Curve {
    /// The one-byte curve code of MSE:Set AT tag `84`.
    pub const fn code(self) -> u8 {
        match self {
            Curve::Secp256r1 => 12,
            Curve::BrainpoolP256r1 => 13,
            Curve::Secp384r1 => 15,
            Curve::BrainpoolP384r1 => 16,
        }
    }

    /// The name BouncyCastle is given in the reference, kept so an operator can
    /// match a trace against it.
    pub const fn name(self) -> &'static str {
        match self {
            Curve::Secp256r1 => "secp256r1",
            Curve::BrainpoolP256r1 => "brainpoolp256r1",
            Curve::Secp384r1 => "secp384r1",
            Curve::BrainpoolP384r1 => "brainpoolp384r1",
        }
    }

    /// Whether this crate can run PACE on the curve.
    ///
    /// Only [`Curve::Secp256r1`] can: the other three need a P-384 or
    /// Brainpool package and this crate adds no package. The code and the name
    /// are still correct, so a refused curve is still reported correctly.
    pub const fn is_available(self) -> bool {
        matches!(self, Curve::Secp256r1)
    }

    /// The curve a code names.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            12 => Some(Curve::Secp256r1),
            13 => Some(Curve::BrainpoolP256r1),
            15 => Some(Curve::Secp384r1),
            16 => Some(Curve::BrainpoolP384r1),
            _ => None,
        }
    }
}

/// What went wrong reading the CAN, establishing the channel, or using it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The CAN text was empty.
    #[error("the CAN is empty")]
    CanEmpty,
    /// The CAN text was longer than [`CAN_MAX`] bytes.
    #[error("the CAN is {0} bytes, over the {CAN_MAX} byte limit")]
    CanTooLong(usize),
    /// The CAN file or variable could not be read. The name is given; the
    /// value never is.
    #[error("cannot read the CAN from {0}")]
    CanUnreadable(String),
    /// The curve is one of the four but not one this crate can compute on.
    #[error("{0:?} (code {1}) is a standardised PACE curve but this build cannot run it: only secp256r1 is implemented, because adding a P-384 or Brainpool package is outside this crate")]
    CurveUnavailable(Curve, u8),
    /// The card answered a step with a status word that is not `90 00`.
    #[error("the card refused {0}; the status word is in the trace")]
    Refused(&'static str),
    /// A response was not the template the step expects.
    #[error("malformed response to {0}")]
    Malformed(&'static str),
    /// A data object the step needs was not in the response.
    #[error("the response to {0} is missing data object {1:#04x}")]
    MissingTag(&'static str, u8),
    /// Host and card sent the same public key, which the reference treats as a
    /// security violation (`PACE.java:114`, `PACE.java:132`).
    #[error("{0}: host and card sent the same public key")]
    EqualKeys(&'static str),
    /// The card's authentication token did not verify.
    #[error("the card's authentication token did not verify, so it does not hold this CAN")]
    CardToken,
    /// A public point was not on the curve, or was the point at infinity.
    #[error("invalid {0} public point")]
    PublicPoint(&'static str),
    /// The decrypted nonce was not 16 bytes.
    #[error("the decrypted nonce is {0} bytes, expected {NONCE_LEN}")]
    NonceLen(usize),
    /// A value did not fit the field.
    #[error("{0} is not a value on the curve field")]
    FieldValue(&'static str),
    /// A response carried no ISO 7816-4 padding, so it was not one of ours.
    #[error("the payload is not padded the way secure messaging pads")]
    Padding,
    /// A secure messaging data object the direction requires was missing.
    #[error("the secure messaging response has no data object {0:#04x}")]
    MissingDataObject(u8),
    /// The card's response MAC did not match.
    #[error("the card's secure messaging MAC did not verify")]
    Mac,
    /// The card transport failed.
    #[error("card transport: {0}")]
    Transport(String),
}

/// Where the CAN comes from. Never a command line: that is shell history and a
/// process listing. The same rule [`crate::gp::KeySource`] follows.
#[derive(Debug, Clone, Copy)]
pub enum CanSource<'a> {
    /// A file holding the CAN.
    File(&'a std::path::Path),
    /// An environment variable holding the CAN.
    Env(&'a str),
}

/// The Card Application Number, held so that it cannot be logged.
///
/// Not `Clone`, not `Serialize`, and `Debug` prints none of it.
pub struct Can(Vec<u8>);

impl std::fmt::Debug for Can {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Can([redacted])")
    }
}

impl Can {
    /// Takes the CAN as bytes, which is what the KDF is fed after the
    /// reference's `can.getBytes(UTF_8)` (`PACE.java:93`).
    ///
    /// # Errors
    ///
    /// [`Error::CanEmpty`], [`Error::CanTooLong`]. Nothing else: the CAN is
    /// opaque here, so a wrong one is only detectable when the card's token
    /// does not verify.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::CanEmpty);
        }
        if bytes.len() > CAN_MAX {
            return Err(Error::CanTooLong(bytes.len()));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Reads and trims the CAN from `source`.
    ///
    /// # Errors
    ///
    /// [`Error::CanUnreadable`], then [`Error::CanEmpty`] or
    /// [`Error::CanTooLong`].
    pub fn load(source: CanSource<'_>) -> Result<Self, Error> {
        let text = match source {
            CanSource::Env(name) => std::env::var(name)
                .map_err(|_| Error::CanUnreadable(format!("environment variable {name}")))?,
            CanSource::File(path) => std::fs::read_to_string(path)
                .map_err(|_| Error::CanUnreadable(format!("file {}", path.display())))?,
        };
        let text = text
            .trim_matches(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'')
            .to_string();
        Self::from_bytes(text.as_bytes())
    }

    /// The CAN bytes, for a caller that has to pass them on.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// The key derivation function of A.2.3: SHA-256 over `secret || nonce ||
/// counter`, the counter being 4 big-endian bytes (`PACE.java:243-253`).
///
/// `nonce` is the Chip Authentication version 2 nonce and is always empty for
/// PACE, which is why every caller here passes `None`.
pub fn kdf(secret: &[u8], nonce: Option<&[u8]>, counter: &[u8; 4]) -> [u8; KEY_LEN] {
    let mut sha = Sha256::new();
    sha.update(secret);
    if let Some(nonce) = nonce {
        sha.update(nonce);
    }
    sha.update(counter);
    sha.finalize().into()
}

/// The two session keys one PACE run produces (`PACE.java:133-139`).
///
/// `Debug` is redacted: these are the keys the whole secure messaging channel
/// rests on.
pub struct SessionKeys {
    enc: [u8; KEY_LEN],
    mac: [u8; KEY_LEN],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

impl SessionKeys {
    /// The channel keys from the ECDH shared secret `k`, the x coordinate of
    /// the ephemeral point (A.2.3.4).
    pub fn derive(k: &[u8]) -> Self {
        Self {
            enc: kdf(k, None, &COUNTER_ENC),
            mac: kdf(k, None, &COUNTER_MAC),
        }
    }

    /// K-ENC, the AES key of the secure messaging channel.
    pub fn enc(&self) -> &[u8; KEY_LEN] {
        &self.enc
    }

    /// K-MAC, from which the authentication tokens and the channel MAC come.
    pub fn mac(&self) -> &[u8; KEY_LEN] {
        &self.mac
    }
}
// ---------------------------------------------------------------------------
// AES, as the reference builds it
// ---------------------------------------------------------------------------

/// AES-CBC encryption with no padding, the reference's
/// `Cipher.getInstance("AES/CBC/NoPadding")` fed a 32-byte
/// `SecretKeySpec(key, "AES")` (`AESSecureChannel.java:244-248`), which is
/// AES-256: the KDF output is not truncated.
fn aes_cbc_encrypt(key: &[u8; KEY_LEN], iv: &[u8; BLOCK], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let len = buf.len();
    cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded::<NoPadding>(&mut buf, len)
        .expect("caller pads to a whole number of blocks")
        .to_vec()
}

/// AES-CBC decryption with no padding (`AESSecureChannel.java:250-254`).
fn aes_cbc_decrypt(key: &[u8; KEY_LEN], iv: &[u8; BLOCK], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = data.to_vec();
    let len = buf.len();
    if len == 0 || len % BLOCK != 0 {
        return Err(Error::Padding);
    }
    let out = cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| Error::Padding)?;
    Ok(out.to_vec())
}

/// The 8-byte AES-CMAC of A.2.4.2 (`PACE.java:266-270`).
///
/// **The key is the leading 16 bytes of K-MAC, not all 32.** The reference
/// calls `new CMac(AESEngine.newInstance())`; BouncyCastle's `AESEngine` with
/// no arguments is AES-128, so it consumes 16 bytes and silently ignores the
/// rest, while the CBC direction above uses the full 32. That asymmetry is the
/// reference's and this tool's; a test pins it. TR-03110's own OID name says
/// CMAC-256, so if this is ever reconciled with a card the reference itself
/// would have to change, not this port of it.
pub fn mac8(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> [u8; TOKEN_LEN] {
    let aes: [u8; 16] = key[..16]
        .try_into()
        .expect("a 32-byte key has 16 leading bytes");
    let full = cmac(&crate::scp03::Key::from_aes128(&aes), parts);
    full[..TOKEN_LEN].try_into().expect("8 bytes")
}

/// Whether two 8-byte tokens are equal, without a data-dependent branch.
fn tokens_equal(a: &[u8; TOKEN_LEN], b: &[u8]) -> bool {
    if b.len() != TOKEN_LEN {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// TLV
// ---------------------------------------------------------------------------

/// One BER-TLV data object: its tag, the whole `tag || length || value` slice,
/// and its value.
#[derive(Debug, Clone, Copy)]
struct DataObject<'a> {
    raw: &'a [u8],
    value: &'a [u8],
}

/// Reads one data object off the front of `data`.
fn next_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, tail) = rest.split_first()?;
    let (len, head) = if first & 0x80 == 0 {
        (usize::from(first), 1)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 2 || tail.len() < n {
            return None;
        }
        (
            tail[..n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
            1 + n,
        )
    };
    let body = rest.get(head..)?.get(..len)?;
    Some((tag, &data[..1 + head + len], body))
}

/// Finds a data object, descending into a `7C` template the way the
/// reference's `TLVs.parse(response).find(0x7C, tag)` does (`PACE.java:71`).
fn find(data: &[u8], tag: u8) -> Option<DataObject<'_>> {
    let mut rest = data;
    while !rest.is_empty() {
        let (t, raw, body) = next_tlv(rest)?;
        if t == tag {
            return Some(DataObject { raw, value: body });
        }
        if t == 0x7C {
            if let Some(inner) = find(body, tag) {
                return Some(inner);
            }
        }
        rest = &rest[raw.len()..];
    }
    None
}

/// `tag || BER length || value`.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(Length::new(u16::try_from(value.len()).unwrap_or(u16::MAX)).encode());
    out.extend_from_slice(value);
    out
}

/// `7C { tag value }`, the Dynamic Authentication Data template every PACE
/// response is wrapped in.
fn dynamic(tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x7C, &tlv(tag, value))
}

// ---------------------------------------------------------------------------
// The elliptic curve side, on the one curve this crate has
// ---------------------------------------------------------------------------

/// The cofactor of all four TR-03110 curves is 1, so the reference's
/// `h*d*Q` in the generic mapping (`PACE.java:236`) is `d*Q`.
const COFACTOR: u8 = 1;

/// A field element from big-endian bytes, left-padded to the field width.
fn scalar_from(bytes: &[u8], what: &'static str) -> Result<Scalar, Error> {
    const W: usize = 32;
    if bytes.len() > W {
        return Err(Error::FieldValue(what));
    }
    let mut wide = [0u8; W];
    wide[W - bytes.len()..].copy_from_slice(bytes);
    if wide.iter().all(|b| *b == 0) {
        return Err(Error::FieldValue(what));
    }
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::<NistP256>::from(wide)))
        .ok_or(Error::FieldValue(what))
}

/// A valid public point from a SEC1 encoding. `p256` rejects a point off the
/// curve and the point at infinity, which is what TR-03110 Part 2 requires of
/// a received key and what the reference's `decodePublic` checks
/// (`PACE.java:161-171`).
fn point_from(sec1: &[u8], what: &'static str) -> Result<ProjectivePoint, Error> {
    PublicKey::from_sec1_bytes(sec1)
        .map(|pk| pk.to_projective())
        .map_err(|_| Error::PublicPoint(what))
}

/// The uncompressed encoding of a point, which is what every public key in
/// PACE goes on the wire as (`PACE.java:104`, `PACE.java:120`).
fn encode_point(point: &ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_sec1_point(false).as_bytes().to_vec()
}

/// The shared secret of an ephemeral ECDH: the x coordinate of the point,
/// field width, big endian (`PACE.java:225-226`).
pub fn shared_secret(
    secret: &[u8; 32],
    peer_sec1: &[u8],
    what: &'static str,
) -> Result<Vec<u8>, Error> {
    let sk = SecretKey::from_slice(secret).map_err(|_| Error::FieldValue(what))?;
    let peer = point_from(peer_sec1, what)?;
    let shared = (peer * *sk.to_nonzero_scalar()).to_affine();
    Ok(shared.x().into())
}

/// The ephemeral domain parameters of A.3.4.1, generic mapping: with `d` the
/// host mapping private key, `Q_card` the card's mapping public key and `s`
/// the nonce, the new generator is `s*G + h*d*Q_card`.
///
/// Both sides compute it from the same inputs and so agree; the host needs no
/// key of its own in the result, which is why a wrong CAN never reaches this
/// function and instead fails at the token.
#[derive(Clone)]
pub struct MappedParameters {
    point: ProjectivePoint,
}

impl std::fmt::Debug for MappedParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MappedParameters { .. }")
    }
}

impl MappedParameters {
    /// Runs the generic mapping.
    ///
    /// # Errors
    ///
    /// [`Error::PublicPoint`] for a card key that is not on the curve, and
    /// [`Error::FieldValue`] for a secret that is zero or not below the group
    /// order, or a nonce that is not below the order (a 16-byte nonce cannot
    /// reach the order of P-256 except with probability 2^-128, but the check
    /// is exact rather than assumed).
    pub fn map(
        host_map_secret: &[u8; 32],
        card_map_sec1: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, Error> {
        let d = scalar_from(host_map_secret, "mapping")?;
        let s = scalar_from(nonce, "nonce")?;
        let q_card = point_from(card_map_sec1, "mapping")?;
        let g = ProjectivePoint::GENERATOR;
        let mapped = g * s + q_card * (d * Scalar::from(u64::from(COFACTOR)));
        Ok(Self { point: mapped })
    }

    /// The new generator, uncompressed, for the record.
    pub fn generator_sec1(&self) -> Vec<u8> {
        encode_point(&self.point)
    }

    /// The public key of an ephemeral key pair on the new generator.
    ///
    /// # Errors
    ///
    /// [`Error::FieldValue`] for a zero or out-of-range secret.
    pub fn ephemeral_public(&self, secret: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let d = scalar_from(secret, "ephemeral")?;
        Ok(encode_point(&(self.point * d)))
    }

    /// The ECDH shared secret with the card's ephemeral public key.
    ///
    /// # Errors
    ///
    /// As [`shared_secret`].
    pub fn agree(&self, secret: &[u8; 32], card_ephemeral_sec1: &[u8]) -> Result<Vec<u8>, Error> {
        shared_secret(secret, card_ephemeral_sec1, "ephemeral")
    }
}

/// The authentication token over a public key: `7F49 { 06 <OID>, 86 <key> }`
/// under K-MAC (`PACE.java:272-279`).
pub fn auth_token(public_key_sec1: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x06, &OID);
    body.extend(tlv(0x86, public_key_sec1));
    let mut out = vec![0x7F, 0x49];
    out.extend(Length::new(u16::try_from(body.len()).unwrap_or(u16::MAX)).encode());
    out.extend(body);
    out
}
// ---------------------------------------------------------------------------
// The commands, as byte vectors. Nothing here sends anything.
// ---------------------------------------------------------------------------

/// SELECT the PACE application: `00 A4 04 00 <AID>`, Le 256 (`PACE.java:79`).
pub fn select(aid: &[u8]) -> Command {
    Command::case4(
        Header::new(0x00, 0xA4, 0x04, 0x00),
        aid.to_vec(),
        Le::Short(0),
    )
}

/// MSE:Set AT for mutual authentication with the CAN on `curve`: `00 22 C1 A4`
/// with tag `80` the mechanism OID, `83` the password reference and `84` the
/// curve code (`PACE.java:82-83`, `:250-255`).
pub fn set_at(curve: Curve) -> Command {
    let mut payload = tlv(0x80, &OID);
    payload.extend(tlv(0x83, &[PASSWORD_CAN]));
    payload.extend(tlv(0x84, &[curve.code()]));
    Command::case4(
        Header::new(0x00, INS_MSE, P1_MUTUAL_AUTHENTICATE, P2_AT),
        payload,
        Le::Short(0),
    )
}

/// GENERAL AUTHENTICATE asking for the encrypted nonce: `7C {}` in class `10`
/// (`PACE.java:86-88`).
pub fn step_1() -> Command {
    general_authenticate(tlv(0x7C, &[]))
}

/// GENERAL AUTHENTICATE with the host mapping public key in tag `81`
/// (`PACE.java:101-103`).
pub fn step_2(host_mapping_public: &[u8]) -> Command {
    general_authenticate(dynamic(0x81, host_mapping_public))
}

/// GENERAL AUTHENTICATE with the host ephemeral public key in tag `83`
/// (`PACE.java:117-119`).
pub fn step_3(host_ephemeral_public: &[u8]) -> Command {
    general_authenticate(dynamic(0x83, host_ephemeral_public))
}

/// The last GENERAL AUTHENTICATE, in class `00`, carrying the host
/// authentication token in tag `85` (`PACE.java:142-144`).
pub fn step_4(host_token: &[u8; TOKEN_LEN]) -> Command {
    general_authenticate_last(dynamic(0x85, host_token))
}

fn general_authenticate(payload: Vec<u8>) -> Command {
    Command::case4(
        Header::new(0x10, INS_GENERAL_AUTHENTICATE, 0x00, 0x00),
        payload,
        Le::Short(0),
    )
}

fn general_authenticate_last(payload: Vec<u8>) -> Command {
    Command::case4(
        Header::new(0x00, INS_GENERAL_AUTHENTICATE, 0x00, 0x00),
        payload,
        Le::Short(0),
    )
}

// ---------------------------------------------------------------------------
// Secure messaging
// ---------------------------------------------------------------------------

/// ISO 7816-4 padding: `0x80` then zeros, always at least one byte
/// (`AESSecureChannel.java:207-212`).
fn pad80(text: &[u8]) -> Vec<u8> {
    let total = (text.len() / BLOCK + 1) * BLOCK;
    let mut out = vec![0u8; total];
    out[..text.len()].copy_from_slice(text);
    out[text.len()] = 0x80;
    out
}

/// Reverses [`pad80`] (`AESSecureChannel.java:214-224`).
fn unpad80(buffer: &[u8]) -> Result<&[u8], Error> {
    if buffer.is_empty() {
        return Err(Error::Padding);
    }
    let mut offset = buffer.len();
    while offset > 0 && buffer[offset - 1] == 0 {
        offset -= 1;
    }
    if offset == 0 || buffer[offset - 1] != 0x80 {
        return Err(Error::Padding);
    }
    Ok(&buffer[..offset - 1])
}

/// The AES secure messaging channel PACE hands over (TR-03110 Part 3, section
/// "Secure Messaging"), the port of the reference's `AESSecureChannel`.
///
/// The send sequence counter starts at 16 zero bytes and is incremented once
/// per command and once per response, as a single 16-byte big-endian counter
/// (`AESSecureChannel.java:31-33`, `:38-40`, `:118-120`).
///
/// `Debug` is redacted: the two keys are inside.
#[derive(Clone)]
pub struct SecureMessaging {
    ssc: [u8; BLOCK],
    enc: [u8; KEY_LEN],
    mac: [u8; KEY_LEN],
}

impl std::fmt::Debug for SecureMessaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureMessaging { .. }")
    }
}

impl SecureMessaging {
    /// A channel over the keys PACE derived, with a zero send sequence
    /// counter.
    pub fn new(keys: &SessionKeys) -> Self {
        Self {
            ssc: [0u8; BLOCK],
            enc: *keys.enc(),
            mac: *keys.mac(),
        }
    }

    /// The current send sequence counter, for a report or a test. It is not a
    /// secret: it is on the wire inside the MAC input.
    pub fn ssc(&self) -> [u8; BLOCK] {
        self.ssc
    }

    fn increment_ssc(&mut self) {
        for byte in self.ssc.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Wraps a command: the class byte gains the secure messaging bits `0x0C`,
    /// the data is replaced by the encrypted `87`, the expected length `97`
    /// and the MAC `8E`, and the SSC advances
    /// (`AESSecureChannel.java:37-113`).
    ///
    /// # Errors
    ///
    /// Never in practice: the payload is bounded by the data the caller gave.
    pub fn wrap(&mut self, plain: &Command) -> Result<Command, Error> {
        self.increment_ssc();
        let iv = aes_cbc_encrypt(&self.enc, &[0u8; BLOCK], &self.ssc);
        let iv: [u8; BLOCK] = iv.try_into().map_err(|_| Error::Padding)?;

        let header = plain.header();
        let wrapped_header = Header::new(
            header.class() | 0x0C,
            header.instruction(),
            header.parameter_1(),
            header.parameter_2(),
        );

        let mut mac_input = self.ssc.to_vec();
        mac_input.extend(pad80(&wrapped_header.to_bytes()));

        let expected = match plain.le() {
            Some(Le::Short(value)) => value,
            // An extended Le has no single-byte data object form; the reference
            // masks it to zero as well.
            Some(Le::Extended(_)) | None => 0x00,
        };
        let le_do = tlv(0x97, &[expected]);

        let mut payload = Vec::new();
        let data = plain.data();
        if !data.is_empty() {
            let mut value = vec![0x01];
            value.extend(aes_cbc_encrypt(&self.enc, &iv, &pad80(data)));
            let do87 = tlv(0x87, &value);
            let mut both = do87.clone();
            both.extend(le_do.clone());
            mac_input.extend(pad80(&both));
            payload.extend(do87);
        }
        payload.extend(le_do);
        let mac = mac8(&self.mac, &[&mac_input]);
        payload.extend(tlv(0x8E, &mac));

        Ok(Command::case4(wrapped_header, payload, Le::Short(0)))
    }

    /// Unwraps a response and returns the plaintext data field followed by the
    /// status word the card put in tag `99`
    /// (`AESSecureChannel.java:115-166`).
    ///
    /// # Errors
    ///
    /// [`Error::MissingDataObject`] for a response without the mandatory `99`
    /// or `8E`, [`Error::Mac`] when the card's MAC does not verify, and
    /// [`Error::Padding`] when the decrypted payload is not padded as this
    /// channel pads.
    pub fn unwrap(&mut self, response: &[u8]) -> Result<Vec<u8>, Error> {
        self.increment_ssc();
        let mut mac_input = self.ssc.to_vec();
        let mut fresh = Vec::new();

        if let Some(encrypted) = find(response, 0x87) {
            let iv = aes_cbc_encrypt(&self.enc, &[0u8; BLOCK], &self.ssc);
            let iv: [u8; BLOCK] = iv.try_into().map_err(|_| Error::Padding)?;
            let cryptogram = encrypted.value.get(1..).ok_or(Error::Padding)?;
            let plain = aes_cbc_decrypt(&self.enc, &iv, cryptogram)?;
            fresh.extend_from_slice(unpad80(&plain)?);
            mac_input.extend(encrypted.raw);
        }

        let status = find(response, 0x99).ok_or(Error::MissingDataObject(0x99))?;
        mac_input.extend(status.raw);
        fresh.extend_from_slice(status.value);

        let card_mac = find(response, 0x8E).ok_or(Error::MissingDataObject(0x8E))?;
        let ours = mac8(&self.mac, &[&pad80(&mac_input)]);
        if !tokens_equal(&ours, card_mac.value) {
            return Err(Error::Mac);
        }
        Ok(fresh)
    }

    /// Wraps, sends and unwraps, the whole of what a secure messaging channel
    /// is for. Returns the plaintext data field followed by the status word.
    ///
    /// # Errors
    ///
    /// Whatever [`SecureMessaging::wrap`] and [`SecureMessaging::unwrap`]
    /// return, plus [`Error::Refused`] when the outer status word is not
    /// `90 00`.
    pub fn transmit<S: CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        plain: &Command,
    ) -> Result<Vec<u8>, Error> {
        let wrapped = self.wrap(plain)?;
        let response = exchange(session, &wrapped, "a secure messaging command")?;
        self.unwrap(&response)
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// Sends one command and hands back the response data field.
fn exchange<S: CardSession + ?Sized>(
    session: &mut S,
    command: &Command,
    step: &'static str,
) -> Result<Vec<u8>, Error> {
    let ex = session::send(session, command, &Policy::default())
        .map_err(|e| Error::Transport(e.to_string()))?;
    if !ex.is_success() {
        return Err(Error::Refused(step));
    }
    Ok(ex.data().to_vec())
}

/// The uncompressed public key of a secret.
fn public_of(secret: &[u8; 32], what: &'static str) -> Result<Vec<u8>, Error> {
    let sk = SecretKey::from_slice(secret).map_err(|_| Error::FieldValue(what))?;
    Ok(PublicKey::from_secret_scalar(&sk.to_nonzero_scalar())
        .to_sec1_point(false)
        .as_bytes()
        .to_vec())
}

/// Runs PACE on `session`: select the PACE application `aid`, set the
/// authentication template, and complete the mutual authentication. On
/// success the caller holds the secure messaging channel and the session keys
/// are inside it, never returned.
///
/// This is authentication, not a write: it changes no card state that an
/// operator would have to restore, so it is not behind `--yes`. It is one
/// attempt: a wrong CAN fails at the card's token and the channel is dropped.
///
/// # Errors
///
/// [`Error::CurveUnavailable`] for a curve this crate cannot run,
/// [`Error::Refused`] where the card answered no, [`Error::CardToken`] for a
/// CAN the card does not hold, and the rest for malformed traffic.
pub fn establish<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    can: &Can,
    curve: Curve,
) -> Result<SecureMessaging, Error> {
    if !curve.is_available() {
        return Err(Error::CurveUnavailable(curve, curve.code()));
    }

    exchange(session, &select(aid), "SELECT of the PACE application")?;
    exchange(session, &set_at(curve), "MSE:Set AT")?;

    // Step 1: the encrypted nonce. A wrong CAN decrypts to 16 bytes of noise
    // and fails at the token three steps later; nothing here can tell the
    // difference sooner, and the reference does not either.
    let response = exchange(session, &step_1(), "the encrypted nonce")?;
    let encrypted = find(&response, 0x80).ok_or(Error::MissingTag("the encrypted nonce", 0x80))?;
    let password_key = kdf(can.expose(), None, &COUNTER_PI);
    let nonce_bytes = aes_cbc_decrypt(&password_key, &[0u8; BLOCK], encrypted.value)?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::NonceLen(nonce_bytes.len()))?;

    // Step 2: mapping keys, then the generic mapping onto a new generator.
    let mut host_mapping = [0u8; 32];
    rand::fill(&mut host_mapping);
    let host_mapping_public = public_of(&host_mapping, "mapping")?;
    let response = exchange(
        session,
        &step_2(&host_mapping_public),
        "the card mapping public key",
    )?;
    let card_mapping =
        find(&response, 0x82).ok_or(Error::MissingTag("the card mapping public key", 0x82))?;
    if card_mapping.value == host_mapping_public.as_slice() {
        return Err(Error::EqualKeys("the mapping step"));
    }
    let mapped = MappedParameters::map(&host_mapping, card_mapping.value, &nonce)?;

    // Step 3: ephemeral key agreement on the new generator.
    let mut host_ephemeral = [0u8; 32];
    rand::fill(&mut host_ephemeral);
    let host_ephemeral_public = mapped.ephemeral_public(&host_ephemeral)?;
    let response = exchange(
        session,
        &step_3(&host_ephemeral_public),
        "the card ephemeral public key",
    )?;
    let card_ephemeral =
        find(&response, 0x84).ok_or(Error::MissingTag("the card ephemeral public key", 0x84))?;
    if card_ephemeral.value == host_ephemeral_public.as_slice() {
        return Err(Error::EqualKeys("the ephemeral step"));
    }
    let shared = mapped.agree(&host_ephemeral, card_ephemeral.value)?;
    let keys = SessionKeys::derive(&shared);

    // Step 4: each side proves it holds the CAN by MAC-ing the other side's
    // ephemeral public key.
    let card_public = encode_point(&point_from(card_ephemeral.value, "ephemeral")?);
    let host_public = encode_point(&point_from(&host_ephemeral_public, "ephemeral")?);
    let host_token = mac8(keys.mac(), &[&auth_token(&card_public)]);
    let response = exchange(
        session,
        &step_4(&host_token),
        "the host authentication token",
    )?;
    let card_token =
        find(&response, 0x86).ok_or(Error::MissingTag("the card authentication token", 0x86))?;
    let host_token_expected = mac8(keys.mac(), &[&auth_token(&host_public)]);
    if !tokens_equal(&host_token_expected, card_token.value) {
        return Err(Error::CardToken);
    }

    Ok(SecureMessaging::new(&keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Error as TransportError, ReaderName};
    use std::cell::RefCell;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }
    fn hx32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }
    fn hx16(s: &str) -> [u8; 16] {
        h(s).try_into().unwrap()
    }
    fn hexu(bytes: &[u8]) -> String {
        hex::encode_upper(bytes)
    }
    fn hexl(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    const D_HOST: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const D_CARD: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const NONCE: &str = "101112131415161718191a1b1c1d1e1f";
    const E_HOST: &str = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60";
    const E_CARD: &str = "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80";
    const QC_MAPPING: &str = "04c6559d416dfb56af714f146d917c24abf818b2fb121604129649848230a2d258b2a6d82dc6c6734cf092ffaa9fc012f10f7008d3952a08d5797e85feaba5d977";
    const NEW_G: &str = "04f4f3bcf723bd83dd2064f8b8aa4c57382b522c5583ba7cb113c5bf50184b0749b8cd6ac48e5e2a7ef445fe2d50ec4b8a546465964f21c78dc95e71ef0739d4aa";
    const Q_HOST: &str = "04f9aa1de00b1eaef3cc559abcf9541051e178b8534c33c67ee09cb08b426381fce4610626e19aee70488300ae93d0b5da99064f12a63494846d3e52615a6253cb";
    const Q_CARD: &str = "040313fc0cfee2aed2af003ff85bfd87f152060f75d95f5af76c65e3948ebc3215cd44a49e8ce286ee0131f1800b69650ddd20b9f91b0759d14a67ca113dc6d9de";
    const SHARED: &str = "b3a6f8764eddde8c71962a8e8ac9cbc7db59477d15c2922b5174e5759f2e5db8";
    const K_ENC: &str = "a33ed83d677ce3e9877adbeef5dab1fce5adae7de7cee9e689090a272aee60a5";
    const K_MAC: &str = "e9f65322b683c59afcd35fd9e3c941746af6bdb498289eb9f9c448d4e6869f27";
    const KDF_ENC: &str = "436a735f3c53a8ab58caa5578144c134b7fd0775b08bdf8f549de37459fd6e52";
    const KDF_MAC: &str = "e46d2a8b7bdbc2777fc685950be785bb24e09bc1a35930c8770cb2609a0455a0";
    const KDF_PI: &str = "90528a0f9b2f8a5459c00c33fc46bc3f8b3f726469f4951e3e6231df0c9ef53c";
    const PI_CAN: &str = "e70be9fd2035c5b78214d7c0204e76a57224f1d76802440344648b38e6976139";
    const AID: &str = "A000000063504B43532D50";

    #[test]
    fn the_oid_and_password_reference_are_the_reference_bytes() {
        assert_eq!(hexu(&OID), "04007F00070202040204");
        assert_eq!(PASSWORD_CAN, 0x02);
    }

    #[test]
    fn the_four_curves_are_the_ones_the_reference_lists() {
        let want = [
            ("secp256r1", 12u8),
            ("brainpoolp256r1", 13),
            ("secp384r1", 15),
            ("brainpoolp384r1", 16),
        ];
        for (curve, (name, code)) in CURVES.iter().zip(want) {
            assert_eq!(curve.name(), name);
            assert_eq!(curve.code(), code);
            assert_eq!(Curve::from_code(code), Some(*curve));
        }
        assert_eq!(Curve::from_code(14), None);
        assert_eq!(CURVES.iter().filter(|c| c.is_available()).count(), 1);
    }

    #[test]
    fn a_curve_this_crate_cannot_run_is_refused_before_anything_is_sent() {
        let can = Can::from_bytes(b"112233").unwrap();
        for curve in CURVES.iter().filter(|c| !c.is_available()) {
            let mut card = Card::new(b"112233");
            assert_eq!(
                establish(&mut card, &h(AID), &can, *curve).err(),
                Some(Error::CurveUnavailable(*curve, curve.code()))
            );
            assert!(card.sent.borrow().is_empty());
            let text = Error::CurveUnavailable(*curve, curve.code()).to_string();
            assert!(text.contains(&format!("{:?}", curve)));
            assert!(text.contains(&curve.code().to_string()));
        }
    }

    #[test]
    fn the_kdf_is_sha256_over_the_secret_and_a_four_byte_counter() {
        let secret = b"0123456789abcdef";
        assert_eq!(hexl(&kdf(secret, None, &COUNTER_ENC)), KDF_ENC);
        assert_eq!(hexl(&kdf(secret, None, &COUNTER_MAC)), KDF_MAC);
        assert_eq!(hexl(&kdf(secret, None, &COUNTER_PI)), KDF_PI);
        assert_ne!(
            kdf(secret, None, &COUNTER_ENC),
            kdf(secret, None, &COUNTER_MAC)
        );
        assert_eq!(hexl(&kdf(b"112233", None, &COUNTER_PI)), PI_CAN);
        assert_ne!(PI_CAN, KDF_PI);
    }

    #[test]
    fn the_generic_mapping_matches_an_independent_model_of_p256() {
        let mapped = MappedParameters::map(&hx32(D_HOST), &h(QC_MAPPING), &hx16(NONCE)).unwrap();
        assert_eq!(hexl(&mapped.generator_sec1()), NEW_G);
        assert_ne!(
            hexu(
                &MappedParameters::map(&hx32(D_CARD), &h(QC_MAPPING), &hx16(NONCE))
                    .unwrap()
                    .generator_sec1()
            ),
            NEW_G
        );
        assert_ne!(
            hexu(
                &MappedParameters::map(&hx32(D_HOST), &h(Q_HOST), &hx16(NONCE))
                    .unwrap()
                    .generator_sec1()
            ),
            NEW_G
        );
        assert_ne!(
            hexu(
                &MappedParameters::map(&hx32(D_HOST), &h(QC_MAPPING), &[0x11; 16])
                    .unwrap()
                    .generator_sec1()
            ),
            NEW_G
        );
        let mut off_curve = h(QC_MAPPING);
        off_curve[64] ^= 1;
        assert_eq!(
            MappedParameters::map(&hx32(D_HOST), &off_curve, &hx16(NONCE)).err(),
            Some(Error::PublicPoint("mapping"))
        );
        assert_eq!(
            MappedParameters::map(&[0; 32], &h(QC_MAPPING), &hx16(NONCE)).err(),
            Some(Error::FieldValue("mapping"))
        );
    }

    #[test]
    fn both_sides_of_the_mapping_derive_the_same_secret_and_keys() {
        let mapped = MappedParameters::map(&hx32(D_HOST), &h(QC_MAPPING), &hx16(NONCE)).unwrap();
        let host_public = mapped.ephemeral_public(&hx32(E_HOST)).unwrap();
        assert_eq!(hexl(&host_public), Q_HOST);
        let from_host = mapped.agree(&hx32(E_HOST), &h(Q_CARD)).unwrap();
        let from_card = mapped.agree(&hx32(E_CARD), &host_public).unwrap();
        assert_eq!(from_host, from_card);
        assert_eq!(hexl(&from_host), SHARED);
        assert_eq!(from_host.len(), 32);
        let keys = SessionKeys::derive(&from_host);
        assert_eq!(hexl(keys.enc()), K_ENC);
        assert_eq!(hexl(keys.mac()), K_MAC);
    }
    #[test]
    fn the_commands_are_the_reference_byte_vectors() {
        assert_eq!(
            hexu(&select(&h(AID)).encode().unwrap()),
            format!("00A40400{:02X}{}00", h(AID).len(), AID)
        );
        assert_eq!(
            hexu(&set_at(Curve::Secp256r1).encode().unwrap()),
            "0022C1A412800A04007F0007020204020483010284010C00"
        );
        assert_eq!(hexu(&step_1().encode().unwrap()), "10860000027C0000");
        assert_eq!(
            hexu(&step_2(&[1, 2, 3]).encode().unwrap()),
            "10860000077C05810301020300"
        );
        assert_eq!(
            hexu(&step_3(&[1, 2, 3]).encode().unwrap()),
            "10860000077C05830301020300"
        );
        assert_eq!(
            hexu(&step_4(&[0x11; TOKEN_LEN]).encode().unwrap()),
            "008600000C7C0A8508111111111111111100"
        );
        assert_eq!(
            hexu(&set_at(Curve::BrainpoolP384r1).encode().unwrap()),
            "0022C1A412800A04007F0007020204020483010284011000"
        );
    }

    #[test]
    fn the_authentication_token_is_7f49_with_the_oid_and_the_key() {
        let key = h(Q_CARD);
        let token = auth_token(&key);
        assert_eq!(&token[..2], &[0x7F, 0x49]);
        assert_eq!(token[2], 79);
        assert_eq!(hexu(&token[3..5]), "060A");
        assert_eq!(hexu(&token[5..15]), "04007F00070202040204");
        assert_eq!(token[15], 0x86);
        assert_eq!(token[16], 65);
        assert_eq!(&token[17..], key.as_slice());
    }

    #[test]
    fn the_mac_uses_the_leading_sixteen_bytes_of_k_mac() {
        let mut key = [0u8; KEY_LEN];
        key[..16].copy_from_slice(&[0x2b; 16]);
        let first = mac8(&key, &[b"PACE"]);
        key[16..].copy_from_slice(&[0x7e; 16]);
        assert_eq!(mac8(&key, &[b"PACE"]), first);
        assert_eq!(first.len(), TOKEN_LEN);
    }

    #[test]
    fn the_can_is_never_rendered() {
        let can = Can::from_bytes(b"123456").unwrap();
        assert_eq!(format!("{can:?}"), "Can([redacted])");
        assert!(!format!("{can:?}").contains("123456"));
        assert!(!Error::CanEmpty.to_string().contains("123456"));
        assert!(!Error::CanTooLong(9).to_string().contains("123456"));
        assert_eq!(Can::from_bytes(b"").err(), Some(Error::CanEmpty));
        assert_eq!(
            Can::from_bytes(&[b'a'; CAN_MAX + 1]).err(),
            Some(Error::CanTooLong(CAN_MAX + 1))
        );
        assert!(Can::from_bytes(&[b'a'; CAN_MAX]).is_ok());
    }

    fn increment(ssc: &mut [u8; BLOCK]) {
        for byte in ssc.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    fn card_response(keys: &SessionKeys, data: &[u8], sw: [u8; 2], commands: usize) -> Vec<u8> {
        let mut ssc = [0u8; BLOCK];
        for _ in 0..commands {
            increment(&mut ssc);
        }
        let iv: [u8; BLOCK] = aes_cbc_encrypt(keys.enc(), &[0u8; BLOCK], &ssc)
            .try_into()
            .expect("AES-CBC of one block");
        let mut mac_input = ssc.to_vec();
        let mut response = Vec::new();
        if !data.is_empty() {
            let mut value = vec![0x01];
            value.extend(aes_cbc_encrypt(keys.enc(), &iv, &pad80(data)));
            let do87 = tlv(0x87, &value);
            mac_input.extend(do87.clone());
            response.extend(do87);
        }
        let do99 = tlv(0x99, &sw);
        mac_input.extend(do99.clone());
        response.extend(do99);
        response.extend(tlv(0x8E, &mac8(keys.mac(), &[&pad80(&mac_input)])));
        response.extend(sw);
        response
    }

    #[test]
    fn secure_messaging_wraps_and_its_mac_covers_the_wire_form() {
        let keys = SessionKeys::derive(b"a shared secret for the channel");
        let mut host = SecureMessaging::new(&keys);
        let plain = Command::case3(Header::new(0x00, 0xA4, 0x02, 0x00), b"\x3f\x00".to_vec());
        let wrapped = host.wrap(&plain).unwrap();
        let wire = wrapped.encode().unwrap();
        assert_eq!(&wire[..4], &[0x0C, 0xA4, 0x02, 0x00]);
        assert_eq!(host.ssc()[15], 1);
        let payload = wrapped.data();
        let do87 = find(payload, 0x87).expect("87");
        let do97 = find(payload, 0x97).expect("97");
        let do8e = find(payload, 0x8E).expect("8E");
        assert_eq!(do87.value[0], 0x01);
        assert_eq!((do87.value.len() - 1) % BLOCK, 0);
        assert_eq!(do97.value, &[0x00]);
        let mut input = host.ssc().to_vec();
        input.extend(pad80(&wire[..4]));
        let mut both = do87.raw.to_vec();
        both.extend(do97.raw);
        input.extend(pad80(&both));
        assert_eq!(do8e.value, mac8(keys.mac(), &[&input]));
    }

    #[test]
    fn unwrap_returns_the_data_and_the_status_word_and_refuses_a_bad_mac() {
        let keys = SessionKeys::derive(b"another shared secret");
        let response = card_response(&keys, b"\x3f\x00", [0x90, 0x00], 1);
        let mut host = SecureMessaging::new(&keys);
        assert_eq!(
            host.unwrap(&response).unwrap(),
            b"\x3f\x00\x90\x00".to_vec()
        );
        let mut tampered = response.clone();
        let last = tampered.len() - 3;
        tampered[last] ^= 1;
        let mut other = SecureMessaging::new(&keys);
        assert_eq!(other.unwrap(&tampered), Err(Error::Mac));
        let mut headless = card_response(&keys, b"", [0x90, 0x00], 1);
        headless.retain(|b| *b != 0x99);
        let mut third = SecureMessaging::new(&keys);
        assert!(matches!(
            third.unwrap(&headless),
            Err(Error::MissingDataObject(0x99))
        ));
    }
    #[test]
    fn a_host_and_a_card_complete_pace() {
        let can = Can::from_bytes(b"112233").unwrap();
        let mut card = Card::new(b"112233");
        let channel = establish(&mut card, &h(AID), &can, Curve::Secp256r1).expect("PACE");
        assert_eq!(card.sent.borrow().len(), 6);
        assert_eq!(channel.ssc(), [0u8; BLOCK]);
    }

    #[test]
    fn a_wrong_can_is_refused_at_the_card_token() {
        let can = Can::from_bytes(b"112233").unwrap();
        let mut card = Card::new(b"999999");
        assert_eq!(
            establish(&mut card, &h(AID), &can, Curve::Secp256r1).err(),
            Some(Error::CardToken)
        );
    }

    #[test]
    fn a_card_that_answers_the_wrong_nonce_is_refused() {
        let can = Can::from_bytes(b"112233").unwrap();
        let mut card = Card::new(b"112233");
        card.sent_nonce = Some([0xAA; NONCE_LEN]);
        assert_eq!(
            establish(&mut card, &h(AID), &can, Curve::Secp256r1).err(),
            Some(Error::CardToken)
        );
    }

    #[test]
    fn a_card_that_refuses_a_step_says_which_one() {
        let can = Can::from_bytes(b"112233").unwrap();
        let mut card = Card::new(b"112233");
        card.refuse_at = 3;
        assert_eq!(
            establish(&mut card, &h(AID), &can, Curve::Secp256r1).err(),
            Some(Error::Refused("the encrypted nonce"))
        );
    }

    /// A card that speaks the host half of PACE, so the host side can be
    /// driven with no reader and no card. Its arithmetic is this crate's,
    /// which is why the mathematics is pinned by the independent-model tests
    /// above; what this fixture proves is the sequence and the refusals.
    struct Card {
        can: Vec<u8>,
        mapping: [u8; 32],
        ephemeral: [u8; 32],
        real_nonce: [u8; NONCE_LEN],
        sent_nonce: Option<[u8; NONCE_LEN]>,
        refuse_at: usize,
        reader: ReaderName,
        sent: RefCell<Vec<Vec<u8>>>,
        mapped: Option<MappedParameters>,
        shared: Option<Vec<u8>>,
        host_ephemeral: Vec<u8>,
    }

    impl Card {
        fn new(can: &[u8]) -> Self {
            let mut real_nonce = [0u8; NONCE_LEN];
            rand::fill(&mut real_nonce);
            Self {
                can: can.to_vec(),
                mapping: hx32(D_CARD),
                ephemeral: hx32(E_CARD),
                real_nonce,
                sent_nonce: None,
                refuse_at: 0,
                reader: ReaderName::new("sim-doctor PACE test card").expect("a reader name"),
                sent: RefCell::new(Vec::new()),
                mapped: None,
                shared: None,
                host_ephemeral: Vec::new(),
            }
        }

        fn handle(&mut self, apdu: &[u8]) -> Vec<u8> {
            self.sent.borrow_mut().push(apdu.to_vec());
            let index = self.sent.borrow().len();
            let class = apdu[0];
            let ins = apdu[1];
            let lc = usize::from(apdu[4]);
            let data = apdu[5..5 + lc].to_vec();
            if index == self.refuse_at {
                return vec![0x6D, 0x00];
            }
            let body = match (class, ins) {
                (_, 0xA4) | (_, 0x22) => Vec::new(),
                (0x10, _) if find(&data, 0x81).is_some() => {
                    let host = find(&data, 0x81).expect("host mapping key").value.to_vec();
                    let card = public_of(&self.mapping, "mapping").expect("card mapping key");
                    self.mapped = Some(
                        MappedParameters::map(&self.mapping, &host, &self.real_nonce)
                            .expect("the card maps its own nonce"),
                    );
                    dynamic(0x82, &card)
                }
                (0x10, _) if find(&data, 0x83).is_some() => {
                    let host = find(&data, 0x83)
                        .expect("host ephemeral key")
                        .value
                        .to_vec();
                    let mapped = self.mapped.clone().expect("mapped parameters");
                    let ours = mapped
                        .ephemeral_public(&self.ephemeral)
                        .expect("card ephemeral");
                    self.shared = Some(mapped.agree(&self.ephemeral, &host).expect("shared"));
                    self.host_ephemeral = host;
                    dynamic(0x84, &ours)
                }
                (0x10, _) => {
                    let key = kdf(&self.can, None, &COUNTER_PI);
                    let nonce = self.sent_nonce.unwrap_or(self.real_nonce);
                    dynamic(0x80, &aes_cbc_encrypt(&key, &[0u8; BLOCK], &nonce))
                }
                (_, _) if find(&data, 0x85).is_some() => {
                    let keys = SessionKeys::derive(&self.shared.take().expect("shared"));
                    let token = auth_token(&self.host_ephemeral);
                    dynamic(0x86, &mac8(keys.mac(), &[&token]))
                }
                _ => return vec![0x6D, 0x00],
            };
            let mut out = body;
            out.extend([0x90, 0x00]);
            out
        }
    }

    impl CardSession for Card {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            Ok(self.handle(command))
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }
}
