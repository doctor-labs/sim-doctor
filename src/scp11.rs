//! SCP11 a, b and c: the off-card entity (OCE) side of GlobalPlatform Card
//! Specification Amendment F, Secure Channel Protocol 11, Public Release v1.4.
//!
//! **Owns.** The four SCP11 APDUs (GET DATA 7.2/7.4, PERFORM SECURITY OPERATION
//! 7.5, MUTUAL AUTHENTICATE 7.6, INTERNAL AUTHENTICATE 7.7), the Control
//! Reference Template (7.6.2.3), the key agreement of 3.1.1, the X9.63 key
//! derivation and KeyData split of 7.6.2.3, the receipt of Table 7-17, and the
//! GP certificate chain of 6.1 and 7.2.2.
//!
//! **Does not own.** Any card or reader I/O - nothing here sends a byte.
//! Secure messaging after the session opens is SCP03 ([`crate::scp03`]), not
//! SCP11. The X.509 certificate format (6.2), the STORE DATA commands
//! (7.8 - 7.10) and the authorizations of Annex B are not here.
//!
//! # What the text defines
//!
//! Amendment F is the complete card-side wire protocol for all three variants,
//! not only key information: it fixes the APDUs, their P1 and P2 bits, their
//! data objects, the response tags, the key agreement and the receipt. The
//! sequence per variant (4.1, Figures 4-2 to 4-4) is:
//!
//! | variant | card commands | authentication |
//! |---|---|---|
//! | SCP11a | GET DATA, PERFORM SECURITY OPERATION, MUTUAL AUTHENTICATE | mutual, ephemeral both sides |
//! | SCP11b | GET DATA, INTERNAL AUTHENTICATE | card to OCE only, no PSO |
//! | SCP11c | GET DATA, PERFORM SECURITY OPERATION, MUTUAL AUTHENTICATE | mutual, static card keys |
//!
//! # Algorithms: no RSA anywhere in the amendment
//!
//! ECC on P-256 with ECDSA (6.1, Table 6-3), ECKA (3.1.1), SHA-256 X9.63 key
//! derivation (3.1.2) and AES-CMAC for the receipt (7.6.2.3, the MAC algorithm
//! used in the secure channel, which is Amendment D C-MAC). Every one is
//! already in this crate: p256 for the curve and the signatures,
//! [`crate::scp03t`] for ECDH and the X9.63 KDF, [`crate::sign`] for ECDSA
//! verification and [`crate::otacrypto`] for AES-CMAC. The word RSA does not
//! occur in Amendment F v1.4 at all.
//!
//! # Verified against the text, and what is not
//!
//! Every constant here is taken from a clause of Amendment F (cited per item)
//! or from GP Card Spec v2.3.1 B.2.3. Two things are inferences, and both are
//! marked where the code needs them:
//!
//! * **GP certificate signatures** are taken as the raw r || s (64 octets)
//!   P-256 ECDSA value that [`crate::sign`] verifies. Amendment F defers to
//!   Amendment A, which is not in this crate reference set, so the encoding of
//!   tag 5F37 is [U].
//! * **Receipt input padding.** 7.6.2.3 says only a MAC across the data
//!   described in Table 7-17, without repeating the padding rule the MAC
//!   algorithm implies. [`receipt`] applies GP Card Spec B.2.3 (80 then
//!   zeroes); [`receipt_input`] hands back the unpadded concatenation so a
//!   caller that reads it differently can say so.
//!
//! Amendment F has no test-vector annex: Annex A describes OCE authentication
//! for SCP11b, Annex B the authorization rules, Annex C the ID allocations. No
//! known-answer vector exists for its key agreement, key derivation or receipt,
//! so those byte values are [U] here. What the tests pin is the structure the
//! clauses prescribe - APDU bytes, concatenation order, field order, TLV
//! shapes - all of which the text states outright.

/// This module name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scp11";

use std::fmt;

use crate::otacrypto;
use crate::scp03t;
use crate::sign;

/// INS of GET DATA (7.2, 7.4).
pub const INS_GET_DATA: u8 = 0xCA;
/// INS of PERFORM SECURITY OPERATION (7.5.2, Table 7-8).
pub const INS_PSO: u8 = 0x2A;
/// INS of MUTUAL AUTHENTICATE (7.6.2, Table 7-14).
///
/// The same INS as SCP02 and SCP03 EXTERNAL AUTHENTICATE; only P2 differs, and
/// Amendment F says so at 7.6.2.
pub const INS_MUTUAL_AUTHENTICATE: u8 = 0x82;
/// INS of INTERNAL AUTHENTICATE (7.7.2, Table 7-20).
pub const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;

/// P1P2 of GET DATA (Certificate Store) (7.2).
pub const P1P2_CERTIFICATE_STORE: [u8; 2] = [0xBF, 0x21];
/// P1P2 of GET DATA (Supported CA Identifiers) for CA-KLOC (7.4).
pub const P1P2_CA_KLOC_IDENTIFIERS: [u8; 2] = [0xFF, 0x33];
/// P1P2 of GET DATA (Supported CA Identifiers) for CA-KLCC (7.4).
pub const P1P2_CA_KLCC_IDENTIFIERS: [u8; 2] = [0xFF, 0x34];

/// P1 bit 8 of PERFORM SECURITY OPERATION: more commands follow (7.5.2.1).
pub const PSO_MORE_COMMANDS: u8 = 0x80;
/// P2 bit 8 of PERFORM SECURITY OPERATION: more certificates follow (7.5.2.2).
pub const PSO_MORE_CERTIFICATES: u8 = 0x80;
/// A certificate longer than this is split across commands (7.5.2.1).
pub const PSO_BLOCK_MAX: usize = 255;

/// KID of PK.CA-KLOC.ECDSA (5.1).
pub const KID_CA_KLOC: u8 = 0x10;
/// KID of SK.SD.ECKA for SCP11a (5.1).
pub const KID_SD_A: u8 = 0x11;
/// KID of the optional static Key-DEK for SCP11a (5.1).
pub const KID_DEK_A: u8 = 0x12;
/// KID of SK.SD.ECKA for SCP11b (5.1).
pub const KID_SD_B: u8 = 0x13;
/// KID of the optional static Key-DEK for SCP11b (5.1).
pub const KID_DEK_B: u8 = 0x14;
/// KID of SK.SD.ECKA for SCP11c (5.1).
pub const KID_SD_C: u8 = 0x15;
/// KID of the optional static Key-DEK for SCP11c (5.1).
pub const KID_DEK_C: u8 = 0x16;
/// First KID of the range of additional PK.CA-KLOC.ECDSA (5.1).
pub const KID_CA_KLOC_RANGE_START: u8 = 0x20;
/// Last KID of the range of additional PK.CA-KLOC.ECDSA (5.1).
pub const KID_CA_KLOC_RANGE_END: u8 = 0x2F;

/// Key type AES (Table 7-15 tag 80, GPCS Table 11-16).
pub const KEY_TYPE_AES: u8 = 0x88;
/// Key usage C-MAC and R-MAC only (Table 7-15 tag 95).
pub const KEY_USAGE_CMAC_RMAC: u8 = 0x34;
/// Key usage C-MAC, C-ENC, R-MAC and R-ENC (Table 7-15 tag 95).
pub const KEY_USAGE_FULL: u8 = 0x3C;
/// Key usage C-MAC and C-ENC; SCP11c only (Table 7-15 tag 95).
pub const KEY_USAGE_CMAC_CENC: u8 = 0x1C;
/// Key usage C-ENC, C-MAC and R-MAC; SCP11c only (Table 7-15 tag 95).
pub const KEY_USAGE_CENC_CMAC_RMAC: u8 = 0x74;
/// Length of the receipt (Table 7-17, Table 7-18, Table 7-22).
pub const RECEIPT_LEN: usize = 16;
/// Length of an uncompressed P-256 point as the text sends it: 5.1 and TR 03111
/// 3.1.1 require the coding identifier byte 04 first.
pub const UNCOMPRESSED_POINT_LEN: usize = 65;

/// What this module refuses, and why.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum Error {
    /// A BER-TLV field claimed more octets than were there.
    #[error("a BER-TLV field runs past the end of the buffer")]
    Truncated,
    /// A BER-TLV length used a form this decoder does not accept.
    #[error("unsupported BER-TLV length form {0:#04x}")]
    Length(u8),
    /// A structure did not start with the tag the clause requires.
    #[error("expected {want}, found tag {found:#04x}")]
    BadTag {
        /// The object the clause requires, named.
        want: &'static str,
        /// The tag that was actually there.
        found: u16,
    },
    /// Octets remained after a complete structure.
    #[error("{0} octet(s) of trailing data")]
    Trailing(usize),
    /// A required object was absent.
    #[error("{0} is required here")]
    Missing(&'static str),
    /// The key usage qualifier is not allowed for this variant (7.6.2.3).
    #[error("key usage {usage:#04x} is defined for SCP11c only, not for this variant")]
    KeyUsageVariant {
        /// The offending qualifier.
        usage: u8,
    },
    /// The CRT did not agree with the SCP parameter bit (7.6.2.3).
    #[error("tag 84 (HostID) must be present exactly when SCP parameter b3 is set")]
    HostIdMismatch,
    /// Tag 42 was needed, or not allowed, for the key version given.
    #[error(
        "tag 42 (CA-KLCC Identifier) must be present exactly when the key version number is 0"
    )]
    CaKlccMismatch,
    /// The last certificate was not a key agreement certificate (7.2.2).
    #[error("the last certificate must carry key usage 0080 (key agreement), not {0:?}")]
    KeyUsageNotKeyAgreement(Vec<u8>),
    /// A public key was not an uncompressed P-256 point (5.1).
    #[error("a public key must be {UNCOMPRESSED_POINT_LEN} octets starting with 04")]
    PublicKey,
    /// A signature was not 64 octets of raw r || s ([U], see module docs).
    #[error("a P-256 signature is 64 octets of r||s, got {0}")]
    SignatureLen(usize),
    /// A certificate did not verify against the key it must be signed by (7.2.2).
    #[error("certificate {index} does not verify against the key it must be signed by")]
    Signature {
        /// Position in the store.
        index: usize,
    },
    /// A certificate was not valid on the requested date (Table 6-1).
    #[error("certificate {index} is not valid on {date}")]
    Validity {
        /// Position in the store.
        index: usize,
        /// The four BCD octets that were checked.
        date: String,
    },
    /// A receipt was not 16 octets (Table 7-18).
    #[error("a receipt is {RECEIPT_LEN} octets, got {0}")]
    ReceiptLen(usize),
    /// A key length this module does not accept.
    #[error("{0}")]
    KeyLength(usize),
}

/// One BER-TLV atom, borrowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Atom<'a> {
    tag: u16,
    value: &'a [u8],
    raw: &'a [u8],
}

/// Wraps value in a BER-TLV with a minimal length.
///
/// A tag is one octet unless it sits in the F range: 5F49, 7F21, BF21, 7F49
/// and BF20 are written with the low five bits of the first octet all set and
/// the tag number in the octet after it. Everything else Amendment F uses (90,
/// 95, 84, 42, 86, A6, 83, 93, 5F20, 5F24, 5F25, 53, B0, F0, 5F37) is one
/// octet.
fn ber(tag: u16, value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let mut out = Vec::with_capacity(len + 4);
    if tag <= 0xFF {
        out.push(tag as u8);
    } else {
        out.push((tag >> 8) as u8);
        out.push(tag as u8);
    }
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(value);
    out
}

/// A length-and-value pair, as SharedInfo carries the identifiers (7.6.2.3).
fn lv(value: &[u8]) -> Vec<u8> {
    ber(0, value)[1..].to_vec()
}

/// Reads the first atom in input.
fn ber_read(input: &[u8]) -> Result<Atom<'_>, Error> {
    let Some((&first_tag, after_tag)) = input.split_first() else {
        return Err(Error::Truncated);
    };
    let (tag, after_tag) = if first_tag & 0b0001_1111 == 0b0001_1111 {
        let Some((&second, rest)) = after_tag.split_first() else {
            return Err(Error::Truncated);
        };
        (u16::from(first_tag) << 8 | u16::from(second), rest)
    } else {
        (u16::from(first_tag), after_tag)
    };
    let Some((&first, after_len)) = after_tag.split_first() else {
        return Err(Error::Truncated);
    };
    let (len, rest) = if first < 0x80 {
        (usize::from(first), after_len)
    } else if first == 0x81 {
        let Some((&len, rest)) = after_len.split_first() else {
            return Err(Error::Truncated);
        };
        (usize::from(len), rest)
    } else if first == 0x82 {
        let Some((&hi, rest)) = after_len.split_first() else {
            return Err(Error::Truncated);
        };
        let Some((&lo, rest)) = rest.split_first() else {
            return Err(Error::Truncated);
        };
        ((usize::from(hi) << 8) | usize::from(lo), rest)
    } else {
        return Err(Error::Length(first));
    };
    if rest.len() < len {
        return Err(Error::Truncated);
    }
    let consumed = input.len() - rest.len() + len;
    Ok(Atom {
        tag,
        value: &rest[..len],
        raw: &input[..consumed],
    })
}

/// Every atom of a body, in wire order.
fn ber_walk(input: &[u8]) -> Result<Vec<Atom<'_>>, Error> {
    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let atom = ber_read(rest)?;
        rest = &rest[atom.raw.len()..];
        out.push(atom);
    }
    Ok(out)
}

/// The value of the one atom a template must start with.
fn expect_value<'a>(body: &'a [u8], tag: u16, want: &'static str) -> Result<&'a [u8], Error> {
    let atom = ber_read(body)?;
    if atom.tag != tag {
        return Err(Error::BadTag {
            want,
            found: atom.tag,
        });
    }
    Ok(atom.value)
}

/// The three variants of 2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// SCP11a: mutual authentication, ephemeral keys on both sides.
    A,
    /// SCP11b: the card authenticates to the OCE only.
    B,
    /// SCP11c: mutual authentication with static card keys.
    C,
}

impl Variant {
    /// The single letter the CLI and the JSON envelope use.
    pub const fn name(self) -> &'static str {
        match self {
            Variant::A => "a",
            Variant::B => "b",
            Variant::C => "c",
        }
    }

    /// Parses a, b or c.
    pub fn from_name(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "a" | "scp11a" => Some(Variant::A),
            "b" | "scp11b" => Some(Variant::B),
            "c" | "scp11c" => Some(Variant::C),
            _ => None,
        }
    }

    /// The INS that opens the secure channel (Table 7-1).
    pub const fn final_ins(self) -> u8 {
        match self {
            Variant::B => INS_INTERNAL_AUTHENTICATE,
            _ => INS_MUTUAL_AUTHENTICATE,
        }
    }

    /// Whether a PERFORM SECURITY OPERATION precedes it (Table 7-1).
    pub const fn uses_pso(self) -> bool {
        !matches!(self, Variant::B)
    }

    /// Whether the OCE has a static key pair (Table 5-1: SCP11b has none).
    pub const fn has_static_oce_key(self) -> bool {
        !matches!(self, Variant::B)
    }

    /// The KID of SK.SD.ECKA for this variant (5.1).
    pub const fn sd_key_identifier(self) -> u8 {
        match self {
            Variant::A => KID_SD_A,
            Variant::B => KID_SD_B,
            Variant::C => KID_SD_C,
        }
    }

    /// The KID of the optional static Key-DEK for this variant (5.1).
    pub const fn dek_key_identifier(self) -> u8 {
        match self {
            Variant::A => KID_DEK_A,
            Variant::B => KID_DEK_B,
            Variant::C => KID_DEK_C,
        }
    }

    /// The SCP parameters byte: b2-b1 for the variant, plus b3 (Table 7-2).
    ///
    /// 00 is SCP11b, 01 SCP11a, 11 SCP11c; b3 set means the host and card (or
    /// card group) identifiers take part in the key derivation.
    pub const fn scp_parameters(self, include_ids: bool) -> u8 {
        let variant_bits = match self {
            Variant::B => 0b00,
            Variant::A => 0b01,
            Variant::C => 0b11,
        };
        variant_bits | if include_ids { 0b1000 } else { 0 }
    }

    /// Whether a key usage qualifier may be used: 7.6.2.3 allows 1C and 74 for
    /// SCP11c only.
    pub const fn allows_key_usage(self, usage: u8) -> bool {
        match usage {
            KEY_USAGE_CMAC_CENC | KEY_USAGE_CENC_CMAC_RMAC => matches!(self, Variant::C),
            _ => true,
        }
    }
}

/// The SCP identifier, byte 1 of tag 90: set to 11 (Table 7-2).
pub const SCP_IDENTIFIER: u8 = 0x11;

/// A key identifier and key version number pair (tag 83).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRef {
    /// Key identifier, byte 1.
    pub key_identifier: u8,
    /// Key version number, byte 2.
    pub key_version: u8,
}

impl KeyRef {
    /// Builds a reference to one key at one version.
    pub const fn new(key_identifier: u8, key_version: u8) -> Self {
        Self {
            key_identifier,
            key_version,
        }
    }

    /// The reference as tag 83: byte 1 then byte 2 (Table 7-3).
    pub fn tag_83(self) -> Vec<u8> {
        ber(0x83, &[self.key_identifier, self.key_version])
    }
}

/// How the OCE names the SK.SD.ECKA whose certificate store it wants.
///
/// Tag 83 and tag 42 are mutually exclusive (Table 7-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertSelector {
    /// Tag 83: name the key directly.
    Key(KeyRef),
    /// Tag 42: name the CA-KLCC and let the SD infer KID and KVN (7.2, 7.10).
    CaKlccIdentifier(Vec<u8>),
}

impl CertSelector {
    /// The Control Reference Template this selector codes to (Table 7-3).
    pub fn crt(&self) -> Vec<u8> {
        let inner = match self {
            CertSelector::Key(key) => key.tag_83(),
            CertSelector::CaKlccIdentifier(id) => ber(0x42, id),
        };
        ber(0xA6, &inner)
    }
}

/// GET DATA (Certificate Store) (7.2, Table 7-3).
pub fn get_data_certificate_store(cla: u8, selector: &CertSelector) -> Vec<u8> {
    command(
        cla,
        INS_GET_DATA,
        P1P2_CERTIFICATE_STORE[0],
        P1P2_CERTIFICATE_STORE[1],
        selector.crt(),
    )
}

/// GET DATA (Supported CA Identifiers) (7.4): loc selects CA-KLOC (FF33) or
/// CA-KLCC (FF34). The data field is empty.
pub fn get_data_supported_ca_identifiers(cla: u8, loc: bool) -> Vec<u8> {
    let p1p2 = if loc {
        P1P2_CA_KLOC_IDENTIFIERS
    } else {
        P1P2_CA_KLCC_IDENTIFIERS
    };
    command(cla, INS_GET_DATA, p1p2[0], p1p2[1], Vec::new())
}

/// Splits a certificate chain into the PERFORM SECURITY OPERATION commands that
/// carry it (7.5.2.1 to 7.5.2.4, Table 7-11).
///
/// chain runs from the first certificate, the one signed by the
/// PK.CA-KLOC.ECDSA named in P1 and P2, to CERT.OCE.ECKA. P1 bit 8 is set on
/// every command but the last of a certificate; P2 bit 8 on every certificate
/// but the last.
pub fn perform_security_operation(
    cla: u8,
    chain: &[&[u8]],
    ca: KeyRef,
) -> Result<Vec<Vec<u8>>, Error> {
    if chain.is_empty() {
        return Err(Error::Missing("a certificate"));
    }
    let mut out = Vec::new();
    for (cert_index, certificate) in chain.iter().enumerate() {
        if certificate.is_empty() {
            return Err(Error::Missing("a certificate body"));
        }
        let blocks: Vec<&[u8]> = if certificate.len() <= PSO_BLOCK_MAX {
            vec![certificate]
        } else {
            certificate.chunks(PSO_BLOCK_MAX).collect()
        };
        for (block_index, block) in blocks.iter().enumerate() {
            let more_commands = block_index + 1 < blocks.len();
            let more_certificates = cert_index + 1 < chain.len();
            let p1 = ca.key_version | if more_commands { PSO_MORE_COMMANDS } else { 0 };
            let p2 = ca.key_identifier
                | if more_certificates {
                    PSO_MORE_CERTIFICATES
                } else {
                    0
                };
            out.push(command(cla, INS_PSO, p1, p2, block.to_vec()));
        }
    }
    Ok(out)
}

/// The identifiers that take part in the key derivation when SCP parameter b3
/// is set (7.6.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationIds<'a> {
    /// Tag 84, the HostID, 1 to 16 octets (Table 7-15).
    pub host_id: &'a [u8],
    /// SIN-LV: SCP11a and SCP11b only.
    pub sin: Option<&'a [u8]>,
    /// SDIN-LV: SCP11a and SCP11b only.
    pub sdin: Option<&'a [u8]>,
    /// Card Group ID-LV: SCP11c only.
    pub card_group_id: Option<&'a [u8]>,
}

/// The Control Reference Template (Key Agreement) of Table 7-15.
///
/// Tag 84 is present exactly when SCP parameter b3 is set, and tag 42 exactly
/// when the key version number in P1 is zero. 7.6.2.3 makes both mismatches an
/// error on the card, so [`ControlReferenceTemplate::encode`] refuses them
/// here instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlReferenceTemplate {
    /// Which variant is being opened.
    pub variant: Variant,
    /// Whether SCP parameter b3 is set.
    pub include_ids: bool,
    /// Key Usage Qualifier, tag 95.
    pub key_usage: u8,
    /// Key Type, tag 80.
    pub key_type: u8,
    /// Key length in octets, tag 81.
    pub key_length: u8,
    /// HostID, tag 84.
    pub host_id: Option<Vec<u8>>,
    /// CA-KLCC Identifier, tag 42.
    pub ca_klcc_identifier: Option<Vec<u8>>,
}

impl ControlReferenceTemplate {
    /// AES, key length 16, full security level, no identifiers: the defaults
    /// of Table 7-15.
    pub fn new(variant: Variant) -> Self {
        Self {
            variant,
            include_ids: false,
            key_usage: KEY_USAGE_FULL,
            key_type: KEY_TYPE_AES,
            key_length: 16,
            host_id: None,
            ca_klcc_identifier: None,
        }
    }

    /// The whole template, tag A6 included.
    ///
    /// key_version is the number the caller will put in P1; 7.6.2.3 makes it
    /// decide whether tag 42 may be there at all.
    pub fn encode(&self, key_version: u8) -> Result<Vec<u8>, Error> {
        if !self.variant.allows_key_usage(self.key_usage) {
            return Err(Error::KeyUsageVariant {
                usage: self.key_usage,
            });
        }
        if self.include_ids != self.host_id.is_some() {
            return Err(Error::HostIdMismatch);
        }
        if self.ca_klcc_identifier.is_some() != (key_version == 0) {
            return Err(Error::CaKlccMismatch);
        }
        let mut inner = Vec::new();
        inner.extend(ber(
            0x90,
            &[
                SCP_IDENTIFIER,
                self.variant.scp_parameters(self.include_ids),
            ],
        ));
        inner.extend(ber(0x95, &[self.key_usage]));
        inner.extend(ber(0x80, &[self.key_type]));
        inner.extend(ber(0x81, &[self.key_length]));
        if let Some(host_id) = &self.host_id {
            inner.extend(ber(0x84, host_id));
        }
        if let Some(identifier) = &self.ca_klcc_identifier {
            inner.extend(ber(0x42, identifier));
        }
        Ok(ber(0xA6, &inner))
    }
}

/// MUTUAL AUTHENTICATE (7.6, Table 7-14 and Table 7-15).
///
/// crt is an encoded [`ControlReferenceTemplate`] and e_pk_oce the OCE
/// ephemeral public key as tag 5F49. P1 carries the key version and P2 the key
/// identifier of SK.SD.ECKA (7.6.2.1, 7.6.2.2); bit 8 of both is zero.
pub fn mutual_authenticate(cla: u8, crt: &[u8], e_pk_oce: &[u8], sd: KeyRef) -> Vec<u8> {
    key_establishment(cla, INS_MUTUAL_AUTHENTICATE, crt, e_pk_oce, sd)
}

/// INTERNAL AUTHENTICATE (7.7, Table 7-20 and Table 7-21).
///
/// The same P1 and P2, and the same data field as [`mutual_authenticate`],
/// which is what 7.7.2.3 means by processing being done as for MUTUAL
/// AUTHENTICATE; only the INS and the key agreement differ.
pub fn internal_authenticate(cla: u8, crt: &[u8], e_pk_oce: &[u8], sd: KeyRef) -> Vec<u8> {
    key_establishment(cla, INS_INTERNAL_AUTHENTICATE, crt, e_pk_oce, sd)
}

fn key_establishment(cla: u8, ins: u8, crt: &[u8], e_pk_oce: &[u8], sd: KeyRef) -> Vec<u8> {
    let mut data = crt.to_vec();
    data.extend(ber(0x5F49, e_pk_oce));
    command(cla, ins, sd.key_version, sd.key_identifier, data)
}

/// The data field of a MUTUAL or INTERNAL AUTHENTICATE response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticateResponse<'a> {
    /// Tag 5F49: ePK.SD.ECKA for SCP11a and SCP11b, PK.SD.ECKA for SCP11c
    /// (Table 7-18, Table 7-22).
    pub card_public_key: &'a [u8],
    /// Tag 86: the 16 octet receipt (Table 7-17).
    pub receipt: &'a [u8],
}

/// Reads the response data field of 7.6.3.1 or 7.7.3.1.
///
/// Both tables fix the order: the card key first, then the receipt.
pub fn parse_authenticate_response(data: &[u8]) -> Result<AuthenticateResponse<'_>, Error> {
    let first = ber_read(data)?;
    if first.tag != 0x5F49 {
        return Err(Error::BadTag {
            want: "tag 5F49 (card public key)",
            found: first.tag,
        });
    }
    let second = ber_read(&data[first.raw.len()..])?;
    if second.tag != 0x86 {
        return Err(Error::BadTag {
            want: "tag 86 (receipt)",
            found: second.tag,
        });
    }
    if second.value.len() != RECEIPT_LEN {
        return Err(Error::ReceiptLen(second.value.len()));
    }
    let rest = &data[first.raw.len() + second.raw.len()..];
    if !rest.is_empty() {
        return Err(Error::Trailing(rest.len()));
    }
    Ok(AuthenticateResponse {
        card_public_key: first.value,
        receipt: second.value,
    })
}

/// Key usage of a signature-verification certificate, CERT.KA-KLOC.ECDSA or
/// CERT.KA-KLCC.ECDSA (Table 6-1).
pub const CERT_KEY_USAGE_SIGNATURE: [u8; 1] = [0x82];
/// Key usage of a key agreement certificate, CERT.OCE.ECKA or CERT.SD.ECKA
/// (Table 6-1).
pub const CERT_KEY_USAGE_KEY_AGREEMENT: [u8; 2] = [0x00, 0x80];

/// One GP certificate, tag 7F21 (Table 6-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The whole 7F21 TLV as it arrived.
    pub raw: &'a [u8],
    /// The body, without the 7F21 header.
    pub body: &'a [u8],
    /// Tag 93: Certificate Serial Number.
    pub serial: &'a [u8],
    /// Tag 42: CA Identifier.
    pub ca_identifier: &'a [u8],
    /// Tag 5F20: Subject Identifier.
    pub subject: &'a [u8],
    /// Tag 95: Key Usage.
    pub key_usage: &'a [u8],
    /// Tag 5F25: Effective Date, 4 octets of BCD YYYYMMDD.
    pub effective_date: Option<&'a [u8]>,
    /// Tag 5F24: Expiration Date, 4 octets of BCD YYYYMMDD.
    pub expiration_date: &'a [u8],
    /// Tag 53 or 73: Discretionary Data.
    pub discretionary: Option<&'a [u8]>,
    /// Tag BF20: authorizations under SCP11a or SCP11c.
    pub authorizations: Option<&'a [u8]>,
    /// Tag 7F49: the Public Key object.
    pub public_key: &'a [u8],
    /// Tag 5F37: the signature over [`Certificate::signed_bytes`].
    pub signature: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// Reads one 7F21 certificate.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        let body = expect_value(raw, 0x7F21, "tag 7F21 (certificate)")?;
        let atoms = ber_walk(body)?;
        let required = |tag: u16, want: &'static str| {
            atoms
                .iter()
                .find(|atom| atom.tag == tag)
                .map(|atom| atom.value)
                .ok_or(Error::Missing(want))
        };
        Ok(Self {
            raw,
            body,
            serial: required(0x93, "tag 93 (certificate serial number)")?,
            ca_identifier: required(0x42, "tag 42 (CA identifier)")?,
            subject: required(0x5F20, "tag 5F20 (subject identifier)")?,
            key_usage: required(0x95, "tag 95 (key usage)")?,
            effective_date: atoms
                .iter()
                .find(|atom| atom.tag == 0x5F25)
                .map(|atom| atom.value),
            expiration_date: required(0x5F24, "tag 5F24 (expiration date)")?,
            discretionary: atoms
                .iter()
                .find(|atom| atom.tag == 0x53 || atom.tag == 0x73)
                .map(|atom| atom.value),
            authorizations: atoms
                .iter()
                .find(|atom| atom.tag == 0xBF20)
                .map(|atom| atom.value),
            public_key: required(0x7F49, "tag 7F49 (public key)")?,
            signature: required(0x5F37, "tag 5F37 (signature)")?,
        })
    }

    /// The octets the signature covers, in the order Table 6-2 lists them.
    ///
    /// 6.1 signs the TLV-encoded data of Table 6-2: 93, 42, 5F20 and 95, then
    /// 5F25 when present, then 5F24, then 53 or 73 and BF20 when present, and
    /// finally 7F49. The order is the table order and not the wire order, so
    /// this rebuilds it rather than slicing the body.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let Ok(atoms) = ber_walk(self.body) else {
            return Vec::new();
        };
        let raw_of = |tag: u16| atoms.iter().find(|atom| atom.tag == tag).map(|a| a.raw);
        let mut out = Vec::new();
        let mut push = |tag: u16| {
            if let Some(raw) = raw_of(tag) {
                out.extend(raw);
            }
        };
        for tag in [0x93u16, 0x42, 0x5F20, 0x95] {
            push(tag);
        }
        push(0x5F25);
        push(0x5F24);
        for tag in [0x53u16, 0x73, 0xBF20] {
            push(tag);
        }
        push(0x7F49);
        out
    }

    /// The uncompressed EC point of the certificate: tag 7F49, then B0
    /// (Table 6-3).
    pub fn public_key_point(&self) -> Result<&[u8], Error> {
        let atoms = ber_walk(self.public_key)?;
        let point = atoms
            .iter()
            .find(|atom| atom.tag == 0xB0)
            .map(|atom| atom.value)
            .ok_or(Error::Missing("tag B0 (public key Q)"))?;
        if point.len() != UNCOMPRESSED_POINT_LEN || point[0] != 0x04 {
            return Err(Error::PublicKey);
        }
        Ok(point)
    }
}

/// Reads an SCP11 Certificate Store, tag BF21 (Table 7-4).
///
/// The leading certificates are optional CERT.KA-KLCC.ECDSA and the last is
/// always CERT.SD.ECKA.
pub fn parse_certificate_store(data: &[u8]) -> Result<Vec<Certificate<'_>>, Error> {
    let body = expect_value(data, 0xBF21, "tag BF21 (SCP11 Certificate Store)")?;
    let atoms = ber_walk(body)?;
    let mut out = Vec::with_capacity(atoms.len());
    for atom in atoms {
        if atom.tag != 0x7F21 {
            return Err(Error::BadTag {
                want: "tag 7F21 (certificate)",
                found: atom.tag,
            });
        }
        out.push(Certificate::decode(atom.raw)?);
    }
    Ok(out)
}

/// One certificate as the OCE checked it (7.2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateReport {
    /// Position in the store, 0 being the one signed by PK.CA-KLCC.ECDSA.
    pub index: usize,
    /// Tag 93, hex.
    pub serial: String,
    /// Tag 42, hex.
    pub ca_identifier: String,
    /// Tag 5F20, hex.
    pub subject: String,
    /// Tag 95, hex.
    pub key_usage: String,
    /// Tag 5F24, hex.
    pub expiration_date: String,
    /// Whether the signature verified.
    pub signature_ok: bool,
}

/// What [`verify_certificate_store`] concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStore {
    /// PK.SD.ECKA, the uncompressed point the OCE should encrypt to.
    pub card_public_key: Vec<u8>,
    /// Tag 5F20 of CERT.SD.ECKA.
    pub subject: Vec<u8>,
    /// One entry per certificate, in order.
    pub reports: Vec<CertificateReport>,
}

/// Walks a certificate store exactly as 7.2.2 requires and returns PK.SD.ECKA.
///
/// The first certificate must verify under ca_klcc, which 7.2.2 says the OCE
/// already knows, and each later one under the key the previous certificate
/// carried. Every signature and expiration date is checked, and the last
/// certificate must carry key usage 0080. at is the verification date as four
/// BCD octets of YYYYMMDD.
pub fn verify_certificate_store(
    store: &[Certificate<'_>],
    ca_klcc: &[u8],
    at: &[u8],
) -> Result<VerifiedStore, Error> {
    let last = store
        .len()
        .checked_sub(1)
        .ok_or(Error::Missing("a certificate"))?;
    if ca_klcc.len() != UNCOMPRESSED_POINT_LEN || ca_klcc[0] != 0x04 {
        return Err(Error::PublicKey);
    }
    let mut current = ca_klcc.to_vec();
    let mut reports = Vec::with_capacity(store.len());
    for (index, certificate) in store.iter().enumerate() {
        let Ok(signature) = <&[u8; sign::SIGNATURE_LEN]>::try_from(certificate.signature) else {
            return Err(Error::SignatureLen(certificate.signature.len()));
        };
        let signature_ok = sign::verify(&current, &certificate.signed_bytes(), signature);
        if !signature_ok {
            return Err(Error::Signature { index });
        }
        if !valid_on(certificate, at) {
            return Err(Error::Validity {
                index,
                date: hex::encode(at),
            });
        }
        current = certificate.public_key_point()?.to_vec();
        reports.push(CertificateReport {
            index,
            serial: hex::encode(certificate.serial),
            ca_identifier: hex::encode(certificate.ca_identifier),
            subject: hex::encode(certificate.subject),
            key_usage: hex::encode(certificate.key_usage),
            expiration_date: hex::encode(certificate.expiration_date),
            signature_ok,
        });
    }
    if store[last].key_usage != CERT_KEY_USAGE_KEY_AGREEMENT {
        return Err(Error::KeyUsageNotKeyAgreement(
            store[last].key_usage.to_vec(),
        ));
    }
    Ok(VerifiedStore {
        card_public_key: current,
        subject: store[last].subject.to_vec(),
        reports,
    })
}

/// Whether at falls between the effective and the expiration date (Table 6-1).
fn valid_on(certificate: &Certificate<'_>, at: &[u8]) -> bool {
    if at.len() != 4 {
        return false;
    }
    if let Some(effective) = certificate.effective_date {
        if effective.len() != 4 || at < effective {
            return false;
        }
    }
    certificate.expiration_date.len() == 4 && at <= certificate.expiration_date
}

/// The OCE half of the ECKA of 3.1.1.
///
/// SCP11a uses two static and two ephemeral key pairs, which 3.1.1 names as the
/// cofactor full unified model C(2e, 2s, ECC CDH). SCP11b uses two ephemeral
/// key pairs and one static pair, the OCE ephemeral pair being used twice.
/// SCP11c uses two static pairs and one ephemeral pair, the card static pair
/// being used twice, which 3.1.1 names as the one-pass unified model
/// C(1e, 2s, ECC CDH).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyAgreement<'a> {
    /// Which variant is being opened.
    pub variant: Variant,
    /// SK.OCE.ECKA: SCP11a and SCP11c only (Table 5-1).
    pub sk_static: Option<&'a [u8; 32]>,
    /// eSK.OCE.ECKA: every variant.
    pub sk_ephemeral: &'a [u8; 32],
    /// ePK.SD.ECKA: SCP11a and SCP11b only (Table 5-1).
    pub card_ephemeral: Option<&'a [u8]>,
    /// PK.SD.ECKA: every variant, taken from CERT.SD.ECKA.
    pub pk_static: &'a [u8],
}

/// The shared secrets one ECKA produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecrets {
    /// ShSee, ephemeral with ephemeral.
    pub sh_ee: Option<Vec<u8>>,
    /// ShSes, static with ephemeral.
    pub sh_es: Option<Vec<u8>>,
    /// ShSss, static with static.
    pub sh_ss: Option<Vec<u8>>,
    /// ShS, the key derivation input, concatenated in the order 7.6.2.3 states
    /// for this variant.
    pub sh_s: Vec<u8>,
}

impl KeyAgreement<'_> {
    /// Computes the shared secrets and ShS for this variant.
    pub fn shared_secrets(&self) -> Result<SharedSecrets, Error> {
        let ecdh = |sk: &[u8; 32], pk: &[u8]| -> Result<Vec<u8>, Error> {
            scp03t::shared_secret(sk, pk)
                .map(|secret| secret.to_vec())
                .map_err(|_| Error::PublicKey)
        };
        let sh_ee = match self.card_ephemeral {
            Some(pk) => Some(ecdh(self.sk_ephemeral, pk)?),
            None => None,
        };
        let sh_ss = match self.sk_static {
            Some(sk) => Some(ecdh(sk, self.pk_static)?),
            None => None,
        };
        let sh_es = Some(ecdh(self.sk_ephemeral, self.pk_static)?);
        let sh_s = match self.variant {
            Variant::A => concat(
                sh_ee.as_deref().ok_or(Error::Missing("ePK.SD.ECKA"))?,
                sh_ss.as_deref().ok_or(Error::Missing("SK.OCE.ECKA"))?,
            ),
            Variant::B => concat(
                sh_ee.as_deref().ok_or(Error::Missing("ePK.SD.ECKA"))?,
                sh_es.as_deref().ok_or(Error::Missing("PK.SD.ECKA"))?,
            ),
            Variant::C => concat(
                sh_es.as_deref().ok_or(Error::Missing("PK.SD.ECKA"))?,
                sh_ss.as_deref().ok_or(Error::Missing("SK.OCE.ECKA"))?,
            ),
        };
        Ok(SharedSecrets {
            sh_ee,
            sh_es,
            sh_ss,
            sh_s,
        })
    }
}

fn concat(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(first.len() + second.len());
    out.extend_from_slice(first);
    out.extend_from_slice(second);
    out
}

/// The SharedInfo of 7.6.2.3: the key usage qualifier, the key type and the key
/// length, then, only when SCP parameter b3 is set, the identifiers as
/// length-and-value pairs. SCP11a and b add HostID, SIN and SDIN; SCP11c adds
/// HostID and the Card Group ID.
pub fn shared_info(
    key_usage: u8,
    key_type: u8,
    key_length: u8,
    ids: Option<&DerivationIds<'_>>,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![key_usage, key_type, key_length];
    let Some(ids) = ids else {
        return Ok(out);
    };
    out.extend(lv(ids.host_id));
    match (ids.sin, ids.sdin, ids.card_group_id) {
        (Some(sin), Some(sdin), _) => {
            out.extend(lv(sin));
            out.extend(lv(sdin));
        }
        (None, None, Some(group)) => out.extend(lv(group)),
        _ => {
            return Err(Error::Missing(
                "SIN and SDIN for SCP11a and b, or the Card Group ID for SCP11c",
            ))
        }
    }
    Ok(out)
}

/// The keys one MUTUAL or INTERNAL AUTHENTICATE produces (Table 7-16).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// KeyData 1..L: the receipt key.
    pub receipt: Vec<u8>,
    /// KeyData L+1..2L: S-ENC.
    pub enc: Vec<u8>,
    /// KeyData 2L+1..3L: S-MAC.
    pub mac: Vec<u8>,
    /// KeyData 3L+1..4L: S-RMAC.
    pub rmac: Vec<u8>,
    /// KeyData 4L+1..5L: S-DEK, present only when the SD has no static Key-DEK.
    pub dek: Option<Vec<u8>>,
}

/// Key material must not reach logs through Debug.
impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

/// Derives the keys of Table 7-16 with the X9.63 KDF of 3.1.2 and SHA-256.
///
/// dek_present decides between four and five blocks: a static Key-DEK on the
/// card leaves the derived S-DEK unused.
pub fn derive_keys(
    sh_s: &[u8],
    info: &[u8],
    key_length: usize,
    dek_present: bool,
) -> Result<SessionKeys, Error> {
    if !matches!(key_length, 16 | 24 | 32) {
        return Err(Error::KeyLength(key_length));
    }
    let blocks = if dek_present { 4 } else { 5 };
    let mut data = vec![0u8; key_length * blocks];
    scp03t::x963_kdf(sh_s, info, &mut data);
    let l = key_length;
    Ok(SessionKeys {
        receipt: data[0..l].to_vec(),
        enc: data[l..2 * l].to_vec(),
        mac: data[2 * l..3 * l].to_vec(),
        rmac: data[3 * l..4 * l].to_vec(),
        dek: if dek_present {
            None
        } else {
            Some(data[4 * l..5 * l].to_vec())
        },
    })
}

/// The octets the receipt MAC covers (Table 7-17): the Control Reference
/// Template exactly as it was sent in the command, then the OCE ephemeral
/// public key, then the card key - ePK.SD.ECKA for SCP11a and SCP11b,
/// PK.SD.ECKA for SCP11c.
///
/// This is the concatenation itself, unpadded, so a caller that reads the
/// padding differently can hand it straight to [`crate::otacrypto::sign`].
pub fn receipt_input(crt: &[u8], e_pk_oce: &[u8], card_key: &[u8]) -> Vec<u8> {
    let mut out = crt.to_vec();
    out.extend(ber(0x5F49, e_pk_oce));
    out.extend(ber(0x5F49, card_key));
    out
}

/// GP Card Spec v2.3.1 B.2.3: append 80, then zeroes to a multiple of 16.
fn pad(input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

/// The receipt: AES-CMAC over [`receipt_input`], truncated to 16 octets.
///
/// 7.6.2.3 says a MAC across the data of Table 7-17 using the MAC algorithm of
/// the secure channel, which for AES is the Amendment D C-MAC. The padding is
/// GP Card Spec B.2.3, the rule Amendment D cites; Amendment F does not
/// restate it, so that is the one inference in this module.
pub fn receipt(receipt_key: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
    otacrypto::sign(
        otacrypto::Alg::Aes,
        receipt_key,
        &pad(input),
        Some(RECEIPT_LEN),
    )
    .map_err(|_| Error::KeyLength(receipt_key.len()))
}

/// Whether the receipt the card returned is the one this session expected.
pub fn verify_receipt(
    receipt_key: &[u8],
    input: &[u8],
    card_receipt: &[u8],
) -> Result<bool, Error> {
    Ok(receipt(receipt_key, input)? == card_receipt)
}

/// Builds a case 4 command: header, Lc, data, Le 00.
fn command(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend(data);
    }
    out.push(0x00);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The P-256 base point, SEC 2 and FIPS 186-4.
    const G: [u8; 65] = [
        0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
        0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
        0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
        0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
        0x68, 0x37, 0xBF, 0x51, 0xF5,
    ];

    /// The P-256 scalar 1 as 32 big-endian octets.
    fn scalar_one() -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = 1;
        out
    }

    /// G times the scalar one is G, so ECDH with that scalar returns x(G).
    const G_X_HEX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    #[test]
    fn scp_parameters_follow_table_7_2() {
        assert_eq!(Variant::B.scp_parameters(false), 0b0000);
        assert_eq!(Variant::A.scp_parameters(false), 0b0001);
        assert_eq!(Variant::C.scp_parameters(false), 0b0011);
        assert_eq!(Variant::A.scp_parameters(true), 0b1001);
        assert_eq!(Variant::B.scp_parameters(true), 0b1000);
        assert_eq!(Variant::C.scp_parameters(true), 0b1011);
        assert_eq!(SCP_IDENTIFIER, 0x11);
    }

    #[test]
    fn key_identifiers_follow_clause_5_1() {
        assert_eq!(Variant::A.sd_key_identifier(), 0x11);
        assert_eq!(Variant::B.sd_key_identifier(), 0x13);
        assert_eq!(Variant::C.sd_key_identifier(), 0x15);
        assert_eq!(Variant::A.dek_key_identifier(), 0x12);
        assert_eq!(Variant::B.dek_key_identifier(), 0x14);
        assert_eq!(Variant::C.dek_key_identifier(), 0x16);
        assert_eq!(KID_CA_KLOC, 0x10);
        assert_eq!(
            (KID_CA_KLOC_RANGE_START, KID_CA_KLOC_RANGE_END),
            (0x20, 0x2F)
        );
    }

    #[test]
    fn table_7_1_says_which_commands_each_variant_uses() {
        assert!(Variant::A.uses_pso() && Variant::C.uses_pso());
        assert!(!Variant::B.uses_pso());
        assert_eq!(Variant::A.final_ins(), INS_MUTUAL_AUTHENTICATE);
        assert_eq!(Variant::C.final_ins(), INS_MUTUAL_AUTHENTICATE);
        assert_eq!(Variant::B.final_ins(), INS_INTERNAL_AUTHENTICATE);
        assert!(Variant::A.has_static_oce_key() && Variant::C.has_static_oce_key());
        assert!(!Variant::B.has_static_oce_key());
    }

    #[test]
    fn get_data_certificate_store_is_the_apdu_clause_7_2_describes() {
        let apdu = get_data_certificate_store(0x80, &CertSelector::Key(KeyRef::new(0x11, 0x01)));
        assert_eq!(hex::encode(&apdu), "80cabf2106a6048302110100");

        let by_ca =
            get_data_certificate_store(0x00, &CertSelector::CaKlccIdentifier(vec![0xAB, 0xCD]));
        assert_eq!(hex::encode(&by_ca), "00cabf2106a6044202abcd00");
    }

    #[test]
    fn get_data_supported_ca_identifiers_is_the_apdu_clause_7_4_describes() {
        assert_eq!(
            hex::encode(get_data_supported_ca_identifiers(0x80, true)),
            "80caff3300"
        );
        assert_eq!(
            hex::encode(get_data_supported_ca_identifiers(0x80, false)),
            "80caff3400"
        );
    }

    #[test]
    fn a_short_certificate_is_one_command_with_no_chaining_bits() {
        let certificate = vec![0xAA; 10];
        let commands =
            perform_security_operation(0x80, &[&certificate], KeyRef::new(0x10, 0x02)).unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0][..5], [0x80, 0x2A, 0x02, 0x10, 0x0A]);
        assert_eq!(commands[0].last(), Some(&0x00));
        assert_eq!(commands[0].len(), 16);
        assert!(perform_security_operation(0x80, &[], KeyRef::new(0x10, 0x02)).is_err());
    }

    #[test]
    fn a_long_certificate_splits_at_255_with_p1_bit_8_set() {
        let certificate = vec![0xAA; 300];
        let commands =
            perform_security_operation(0x80, &[&certificate], KeyRef::new(0x10, 0x02)).unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][..5], [0x80, 0x2A, 0x02 | 0x80, 0x10, 0xFF]);
        assert_eq!(commands[1][..5], [0x80, 0x2A, 0x02, 0x10, 0x2D]);
        assert_eq!(commands[0].len(), 5 + 255 + 1);
        assert_eq!(commands[1].len(), 5 + 45 + 1);
    }

    #[test]
    fn an_intermediate_certificate_sets_p2_bit_8() {
        let first = vec![0xBB; 4];
        let second = vec![0xCC; 4];
        let commands =
            perform_security_operation(0x80, &[&first, &second], KeyRef::new(0x20, 0x03)).unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][..5], [0x80, 0x2A, 0x03, 0x20 | 0x80, 0x04]);
        assert_eq!(commands[1][..5], [0x80, 0x2A, 0x03, 0x20, 0x04]);
    }

    #[test]
    fn the_control_reference_template_is_the_literal_of_table_7_15() {
        let crt = ControlReferenceTemplate::new(Variant::A).encode(1).unwrap();
        assert_eq!(hex::encode(&crt), "a60d9002110195013c800188810110");

        let mut with_id = ControlReferenceTemplate::new(Variant::A);
        with_id.include_ids = true;
        with_id.host_id = Some(vec![0x01, 0x02]);
        assert_eq!(
            hex::encode(with_id.encode(1).unwrap()),
            "a6119002110995013c80018881011084020102"
        );
    }

    #[test]
    fn the_scp11c_template_carries_parameter_three() {
        let crt = ControlReferenceTemplate::new(Variant::C).encode(1).unwrap();
        assert_eq!(hex::encode(&crt), "a60d9002110395013c800188810110");
    }

    #[test]
    fn a_host_id_without_the_parameter_bit_is_refused() {
        let mut crt = ControlReferenceTemplate::new(Variant::A);
        crt.host_id = Some(vec![0x09]);
        assert_eq!(crt.encode(1), Err(Error::HostIdMismatch));

        let mut without = ControlReferenceTemplate::new(Variant::A);
        without.include_ids = true;
        assert_eq!(without.encode(1), Err(Error::HostIdMismatch));
    }

    #[test]
    fn key_usage_1c_and_74_are_scp11c_only() {
        for usage in [KEY_USAGE_CMAC_CENC, KEY_USAGE_CENC_CMAC_RMAC] {
            let mut a = ControlReferenceTemplate::new(Variant::A);
            a.key_usage = usage;
            assert_eq!(a.encode(1), Err(Error::KeyUsageVariant { usage }));

            let mut c = ControlReferenceTemplate::new(Variant::C);
            c.key_usage = usage;
            assert!(c.encode(1).is_ok());
        }
        assert!(Variant::A.allows_key_usage(KEY_USAGE_FULL));
        assert!(Variant::B.allows_key_usage(KEY_USAGE_CMAC_RMAC));
    }

    #[test]
    fn mutual_and_internal_authenticate_share_a_data_field() {
        let crt = ControlReferenceTemplate::new(Variant::A).encode(2).unwrap();
        let sd = KeyRef::new(0x11, 0x02);
        let a = mutual_authenticate(0x80, &crt, &G, sd);
        let b = internal_authenticate(0x80, &crt, &G, sd);
        assert_eq!(a[..5], [0x80, 0x82, 0x02, 0x11, 0x53]);
        assert_eq!(b[..5], [0x80, 0x88, 0x02, 0x11, 0x53]);
        assert_eq!(a[5..a.len() - 1], b[5..b.len() - 1]);
        assert_eq!(a.len(), 5 + 15 + 3 + 65 + 1);
        assert_eq!(a.last(), Some(&0x00));
        assert_eq!(a[a.len() - 69..a.len() - 66], [0x5F, 0x49, 0x41]);
    }

    #[test]
    fn the_ca_klcc_identifier_is_required_when_the_key_version_is_zero() {
        let crt = ControlReferenceTemplate::new(Variant::B);
        assert_eq!(crt.encode(0), Err(Error::CaKlccMismatch));
        assert!(crt.encode(1).is_ok());

        let mut with_id = ControlReferenceTemplate::new(Variant::B);
        with_id.ca_klcc_identifier = Some(vec![0xAB, 0xCD]);
        assert_eq!(
            hex::encode(with_id.encode(0).unwrap()),
            "a6119002110095013c8001888101104202abcd"
        );
        assert_eq!(with_id.encode(1), Err(Error::CaKlccMismatch));
    }

    #[test]
    fn the_response_carries_the_card_key_then_a_sixteen_octet_receipt() {
        let mut data = vec![0x5F, 0x49, 0x41];
        data.extend_from_slice(&G);
        data.extend_from_slice(&[0x86, 0x10]);
        data.extend_from_slice(&[0xAA; 16]);
        let parsed = parse_authenticate_response(&data).unwrap();
        assert_eq!(parsed.card_public_key, &G);
        assert_eq!(parsed.receipt, &[0xAAu8; 16][..]);

        let mut swapped = data.clone();
        swapped[0] = 0x86;
        assert!(matches!(
            parse_authenticate_response(&swapped),
            Err(Error::BadTag { found: 0x86, .. })
        ));

        let mut short_receipt = data.clone();
        short_receipt.truncate(short_receipt.len() - 4);
        let length_octet = short_receipt.len() - 13;
        short_receipt[length_octet] = 0x0C;
        assert_eq!(
            parse_authenticate_response(&short_receipt),
            Err(Error::ReceiptLen(12))
        );
    }

    #[test]
    fn shared_info_is_the_literal_of_clause_7_6_2_3() {
        assert_eq!(
            hex::encode(shared_info(KEY_USAGE_FULL, KEY_TYPE_AES, 16, None).unwrap()),
            "3c8810"
        );

        let ids = DerivationIds {
            host_id: &[0x01, 0x02],
            sin: Some(&[0x0A, 0x0B]),
            sdin: Some(&[0x0C]),
            card_group_id: None,
        };
        assert_eq!(
            hex::encode(shared_info(KEY_USAGE_FULL, KEY_TYPE_AES, 16, Some(&ids)).unwrap()),
            "3c8810020102020a0b010c"
        );
    }

    #[test]
    fn scp11c_swaps_the_card_identifiers_for_the_card_group_id() {
        let ids = DerivationIds {
            host_id: &[0x01],
            sin: None,
            sdin: None,
            card_group_id: Some(&[0x09, 0x09]),
        };
        assert_eq!(
            hex::encode(shared_info(KEY_USAGE_FULL, KEY_TYPE_AES, 16, Some(&ids)).unwrap()),
            "3c88100101020909"
        );

        let mixed = DerivationIds {
            host_id: &[0x01],
            sin: Some(&[0x02]),
            sdin: None,
            card_group_id: None,
        };
        assert!(shared_info(KEY_USAGE_FULL, KEY_TYPE_AES, 16, Some(&mixed)).is_err());
    }

    #[test]
    fn ecdh_with_the_scalar_one_is_the_x_coordinate_of_the_base_point() {
        let shared = scp03t::shared_secret(&scalar_one(), &G).expect("G is on the curve");
        assert_eq!(hex::encode(shared), G_X_HEX);
    }

    #[test]
    fn scp11a_concatenates_shsee_then_shsss() {
        let sk_static = scalar_one();
        let sk_ephemeral = [2u8; 32];
        let agreement = KeyAgreement {
            variant: Variant::A,
            sk_static: Some(&sk_static),
            sk_ephemeral: &sk_ephemeral,
            card_ephemeral: Some(&G),
            pk_static: &G,
        };
        let secrets = agreement.shared_secrets().unwrap();
        assert_eq!(secrets.sh_s.len(), 64);
        assert_eq!(
            secrets.sh_s,
            concat(
                secrets.sh_ee.as_ref().unwrap(),
                secrets.sh_ss.as_ref().unwrap()
            ),
            "7.6.2.3 concatenates ShSee then ShSss for SCP11a"
        );
        assert_eq!(hex::encode(secrets.sh_ss.unwrap()), G_X_HEX);
    }

    #[test]
    fn scp11b_concatenates_shsee_then_shses() {
        let sk_ephemeral = [2u8; 32];
        let agreement = KeyAgreement {
            variant: Variant::B,
            sk_static: None,
            sk_ephemeral: &sk_ephemeral,
            card_ephemeral: Some(&G),
            pk_static: &G,
        };
        let secrets = agreement.shared_secrets().unwrap();
        assert_eq!(
            secrets.sh_s,
            concat(
                secrets.sh_ee.as_ref().unwrap(),
                secrets.sh_es.as_ref().unwrap()
            ),
            "7.7.2.3 concatenates ShSee then ShSes for SCP11b"
        );
        assert_eq!(secrets.sh_ss, None);
    }

    #[test]
    fn scp11c_concatenates_shses_then_shsss() {
        let sk_static = scalar_one();
        let sk_ephemeral = [2u8; 32];
        let agreement = KeyAgreement {
            variant: Variant::C,
            sk_static: Some(&sk_static),
            sk_ephemeral: &sk_ephemeral,
            card_ephemeral: None,
            pk_static: &G,
        };
        let secrets = agreement.shared_secrets().unwrap();
        assert_eq!(secrets.sh_ee, None);
        assert_eq!(
            secrets.sh_s,
            concat(
                secrets.sh_es.as_ref().unwrap(),
                secrets.sh_ss.as_ref().unwrap()
            ),
            "7.6.2.3 concatenates ShSes then ShSss for SCP11c"
        );
    }

    #[test]
    fn table_7_16_splits_keydata_receipt_enc_mac_rmac_dek() {
        let keys = derive_keys(&[0x01; 32], &[0x3C, 0x88, 0x10], 16, false).unwrap();
        assert_eq!(
            (
                keys.receipt.len(),
                keys.enc.len(),
                keys.mac.len(),
                keys.rmac.len(),
                keys.dek.as_ref().map(Vec::len)
            ),
            (16, 16, 16, 16, Some(16))
        );
        assert_ne!(keys.receipt, keys.enc);
        assert_ne!(keys.enc, keys.mac);
        assert_ne!(keys.mac, keys.rmac);
        assert_ne!(keys.rmac, keys.dek.unwrap());

        let with_dek = derive_keys(&[0x01; 32], &[0x3C, 0x88, 0x20], 32, true).unwrap();
        assert_eq!(with_dek.receipt.len(), 32);
        assert_eq!(with_dek.dek, None);
        assert_eq!(
            derive_keys(&[0x01; 32], &[], 20, false),
            Err(Error::KeyLength(20))
        );
    }

    #[test]
    fn the_receipt_input_is_the_concatenation_of_table_7_17() {
        let crt = vec![0xA6, 0x02, 0x90, 0x00];
        let input = receipt_input(&crt, &G, &G);
        assert_eq!(&input[..4], &crt[..]);
        assert_eq!(input.len(), 4 + 3 + 65 + 3 + 65);
        assert_eq!(input[4..7], [0x5F, 0x49, 0x41]);
        assert_eq!(input[7 + 65], 0x5F);
    }

    #[test]
    fn padding_is_the_rule_of_gp_card_spec_b_2_3() {
        assert_eq!(pad(&[0x01; 15]).len(), 16);
        assert_eq!(pad(&[0x01; 15])[15], 0x80);
        assert_eq!(pad(&[0x01; 16]).len(), 32);
        assert_eq!(pad(&[0x01; 16])[16], 0x80);
        assert!(pad(&[0x01; 16])[17..].iter().all(|byte| *byte == 0));
        assert_eq!(
            pad(&[]),
            vec![0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_receipt_is_sixteen_octets_and_verifies_against_itself() {
        let key = [0x0Fu8; 16];
        let input = receipt_input(&[0xA6, 0x02, 0x90, 0x00], &G, &G);
        let value = receipt(&key, &input).unwrap();
        assert_eq!(value.len(), RECEIPT_LEN);
        assert!(verify_receipt(&key, &input, &value).unwrap());
        let mut wrong = value.clone();
        wrong[0] ^= 0xFF;
        assert!(!verify_receipt(&key, &input, &wrong).unwrap());
        assert_eq!(receipt(&[0u8; 7], &input), Err(Error::KeyLength(7)));
    }

    /// Builds one GP certificate per Table 6-1, for the decode tests.
    fn certificate(key_usage: &[u8], signature_len: usize) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(ber(0x93, &[0x01]));
        body.extend(ber(0x42, &[0xAA, 0xBB]));
        body.extend(ber(0x5F20, &[0xCC]));
        body.extend(ber(0x95, key_usage));
        body.extend(ber(0x5F24, &[0x30, 0x30, 0x01, 0x01]));
        body.extend(ber(0x5F25, &[0x20, 0x24, 0x01, 0x01]));
        body.extend(ber(0x53, &[0xDD]));
        let mut public_key = ber(0xB0, &G);
        public_key.extend(ber(0xF0, &[0x01]));
        body.extend(ber(0x7F49, &public_key));
        body.extend(ber(0x5F37, &vec![0xEE; signature_len]));
        ber(0x7F21, &body)
    }

    #[test]
    fn a_gp_certificate_decodes_per_table_6_1() {
        let raw = certificate(&CERT_KEY_USAGE_KEY_AGREEMENT, 64);
        let cert = Certificate::decode(&raw).unwrap();
        assert_eq!(cert.serial, [0x01]);
        assert_eq!(cert.ca_identifier, [0xAA, 0xBB]);
        assert_eq!(cert.subject, [0xCC]);
        assert_eq!(cert.key_usage, [0x00, 0x80]);
        assert_eq!(
            cert.effective_date,
            Some([0x20, 0x24, 0x01, 0x01].as_slice())
        );
        assert_eq!(cert.expiration_date, [0x30, 0x30, 0x01, 0x01]);
        assert_eq!(cert.discretionary, Some([0xDD].as_slice()));
        assert_eq!(cert.authorizations, None);
        assert_eq!(cert.public_key_point().unwrap(), &G);
    }

    #[test]
    fn the_signed_data_is_table_6_2_in_table_order() {
        let raw = certificate(&CERT_KEY_USAGE_KEY_AGREEMENT, 64);
        let cert = Certificate::decode(&raw).unwrap();
        let signed = cert.signed_bytes();
        // Table 6-2 order: 93, 42, 5F20, 95, 5F25, 5F24, 53, 7F49. The builder
        // above writes 5F24 before 5F25, so this pins the table order and not
        // the wire order.
        let mut expected: Vec<u8> = Vec::new();
        expected.extend(ber(0x93, &[0x01]));
        expected.extend(ber(0x42, &[0xAA, 0xBB]));
        expected.extend(ber(0x5F20, &[0xCC]));
        expected.extend(ber(0x95, &CERT_KEY_USAGE_KEY_AGREEMENT));
        expected.extend(ber(0x5F25, &[0x20, 0x24, 0x01, 0x01]));
        expected.extend(ber(0x5F24, &[0x30, 0x30, 0x01, 0x01]));
        expected.extend(ber(0x53, &[0xDD]));
        let mut public_key = ber(0xB0, &G);
        public_key.extend(ber(0xF0, &[0x01]));
        expected.extend(ber(0x7F49, &public_key));
        assert_eq!(signed, expected);
        assert!(hex::encode(&signed).starts_with("9301014202aabb5f2001cc950200805f250420240101"));
        assert!(!hex::encode(&signed).contains("5f37"));
    }

    #[test]
    fn a_certificate_store_reads_its_chain() {
        let mut body = certificate(&CERT_KEY_USAGE_SIGNATURE, 64);
        body.extend(certificate(&CERT_KEY_USAGE_KEY_AGREEMENT, 64));
        let store = ber(0xBF21, &body);
        let parsed = parse_certificate_store(&store).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].key_usage, [0x82]);
        assert_eq!(parsed[1].key_usage, [0x00, 0x80]);

        assert!(matches!(
            parse_certificate_store(&[0xA6, 0x00]),
            Err(Error::BadTag { found: 0xA6, .. })
        ));
    }

    #[test]
    fn verification_refuses_a_trust_anchor_that_is_not_a_point() {
        let raw = certificate(&CERT_KEY_USAGE_KEY_AGREEMENT, 64);
        let encoded = ber(0xBF21, &raw);
        let store = parse_certificate_store(&encoded).unwrap();
        assert_eq!(
            verify_certificate_store(&store, &[0x04; 10], &[0x20, 0x24, 0x06, 0x01]),
            Err(Error::PublicKey)
        );
        assert_eq!(
            verify_certificate_store(&store, &G, &[0x20, 0x24, 0x06, 0x01]),
            Err(Error::Signature { index: 0 })
        );
    }

    #[test]
    fn verification_refuses_a_signature_of_the_wrong_length() {
        let short = certificate(&CERT_KEY_USAGE_KEY_AGREEMENT, 32);
        let encoded = ber(0xBF21, &short);
        let store = parse_certificate_store(&encoded).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(
            verify_certificate_store(&store, &G, &[0x20, 0x24, 0x06, 0x01]),
            Err(Error::SignatureLen(32))
        );
    }

    #[test]
    fn expiration_is_compared_as_four_bcd_octets() {
        let raw = certificate(&CERT_KEY_USAGE_KEY_AGREEMENT, 64);
        let cert = Certificate::decode(&raw).unwrap();
        assert!(valid_on(&cert, &[0x20, 0x24, 0x01, 0x01]));
        assert!(valid_on(&cert, &[0x25, 0x01, 0x01, 0x01]));
        assert!(valid_on(&cert, &[0x30, 0x30, 0x01, 0x01]));
        assert!(!valid_on(&cert, &[0x20, 0x23, 0x12, 0x31]));
        assert!(!valid_on(&cert, &[0x30, 0x30, 0x01, 0x02]));
        assert!(!valid_on(&cert, &[0x20; 3]));
    }
}
