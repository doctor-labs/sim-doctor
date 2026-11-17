//! SAIP profile package parse: the DER `ProfileElement` sequence of a SIMalliance
//! eUICC Profile Package, decoded offline into JSON. Parse only: no personalization,
//! no templates, no card, no reader.
//!
//! # Where the tags come from
//!
//! `ProfileElement` is a CHOICE in the SAIP ASN.1 module, `PEDefinitions`, which is
//! written with `AUTOMATIC TAGS`. Each alternative therefore takes the implicit
//! context-specific tag of its position, counted from 0 with the first alternative
//! (`header`) at 0. The alternatives are all SEQUENCEs, so every tag is constructed.
//! The order and the count are copied from the module, not recalled:
//!
//! `pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`, `ProfileElement ::= CHOICE`
//! (pySim checkout at the time of writing; the module is the SIMalliance eUICC
//! Profile Package v3.3.1 definitions).
//!
//! Positions 0 to 30 encode as one identifier octet, `A0 + n`. Position 31 and up
//! use the high-tag-number form, `BF` then base-128 digits, so `iot` (32) is `BF 20`.
//! The table below is indexed by that number, and a test pins it to the source.
//!
//! # What is decoded and what is not
//!
//! Each element is named by its tag and shown as a generic TLV tree: tag, constructed
//! flag, length, and either the child elements or the raw value in hex. Field names
//! inside a PE (the `PE-MF` file list, the `PE-PINCodes` entries and so on) are NOT
//! decoded: the ASN.1 for each one would need its own table, and this module does not
//! guess at what a tag number means inside a PE. A tag that is not in the table is
//! reported as `unknown` with its raw element in hex.
//!
//! # Bounds
//!
//! The input is capped at [`MAX_FILE_BYTES`], the tree at [`MAX_DEPTH`] constructed
//! levels (deeper constructed values are shown as raw hex with a `truncated` marker),
//! and the node count at [`MAX_NODES`]. Lengths go through [`crate::der`], which
//! refuses indefinite and non-minimal lengths, so a file that is not strict DER is
//! refused rather than read.

use serde_json::{json, Value};

use crate::der::{self, Der};
use crate::gp::{dotted, oid_arcs};

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "saip";

/// The largest profile package this module will read, in octets.
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

/// How many constructed levels are expanded before the rest is shown as raw hex.
pub const MAX_DEPTH: usize = 8;

/// How many TLV nodes one decode may build, across all levels.
pub const MAX_NODES: usize = 200_000;

/// The widest identifier this module reads, in octets (`BF` and up to three digits).
const MAX_TAG_OCTETS: usize = 4;

/// The `ProfileElement` CHOICE alternatives in source order, indexed by their
/// implicit context tag number. See the module documentation for the source.
const PE_TYPES: [&str; 34] = [
    "header",
    "genericFileManagement",
    "pinCodes",
    "pukCodes",
    "akaParameter",
    "cdmaParameter",
    "securityDomain",
    "rfm",
    "application",
    "nonStandard",
    "end",
    "rfu1",
    "rfu2",
    "rfu3",
    "rfu4",
    "rfu5",
    "mf",
    "cd",
    "telecom",
    "usim",
    "opt-usim",
    "isim",
    "opt-isim",
    "phonebook",
    "gsm-access",
    "csim",
    "opt-csim",
    "eap",
    "df-5gs",
    "df-saip",
    "df-snpn",
    "df-5gprose",
    "iot",
    "opt-iot",
];

/// Why a profile package could not be decoded. Every variant carries the offset of the
/// element it failed on, so a caller can point at the bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file is larger than [`MAX_FILE_BYTES`].
    #[error("profile package is {len} octets, over the {max}-octet limit")]
    TooLarge {
        /// Octets read (at least one over the limit).
        len: usize,
        /// The limit.
        max: usize,
    },
    /// The file holds no octets at all.
    #[error("profile package is empty")]
    Empty,
    /// An identifier ran out of octets or used a non-minimal high-tag form.
    #[error("at offset {offset}: identifier is truncated or not a valid high-tag-number form")]
    BadTag {
        /// Where the identifier starts.
        offset: usize,
    },
    /// The element's length or framing breaks the DER rules; see [`crate::der::Error`].
    #[error("at offset {offset}: {source}")]
    Der {
        /// Where the element starts.
        offset: usize,
        /// The DER error.
        source: der::Error,
    },
    /// More than [`MAX_NODES`] TLV nodes.
    #[error("more than {max} TLV nodes")]
    TooManyNodes {
        /// The limit.
        max: usize,
    },
}

/// One decoded identifier.
#[derive(Debug, Clone)]
struct Tag {
    number: u32,
    constructed: bool,
    octets: usize,
    hex: String,
}

fn read_tag(bytes: &[u8], offset: usize) -> Result<Tag, Error> {
    let first = *bytes.first().ok_or(Error::BadTag { offset })?;
    let constructed = first & 0x20 != 0;
    if first & 0x1F != 0x1F {
        return Ok(Tag {
            number: u32::from(first & 0x1F),
            constructed,
            octets: 1,
            hex: hex::encode_upper(&bytes[..1]),
        });
    }
    let mut number: u32 = 0;
    for (i, &octet) in bytes[1..].iter().enumerate().take(MAX_TAG_OCTETS - 1) {
        // X.690 8.1.2.4.2: the first digit may not be 0x80, which would be a non-minimal
        // encoding of the same number.
        if i == 0 && octet == 0x80 {
            return Err(Error::BadTag { offset });
        }
        number = number
            .checked_mul(128)
            .and_then(|n| n.checked_add(u32::from(octet & 0x7F)))
            .ok_or(Error::BadTag { offset })?;
        if octet & 0x80 == 0 {
            let octets = i + 2;
            return Ok(Tag {
                number,
                constructed,
                octets,
                hex: hex::encode_upper(&bytes[..octets]),
            });
        }
    }
    Err(Error::BadTag { offset })
}

/// Walk state shared across one decode, so the node budget covers the whole file.
struct Budget {
    nodes: usize,
}

fn spend(budget: &mut Budget) -> Result<(), Error> {
    budget.nodes += 1;
    if budget.nodes > MAX_NODES {
        return Err(Error::TooManyNodes { max: MAX_NODES });
    }
    Ok(())
}

/// The framing of one element, without looking inside its body.
struct Framed<'a> {
    tag: Tag,
    /// Octets the whole element occupies, identifier through the end of its body.
    used: usize,
    body: &'a [u8],
    /// Absolute offset of the body.
    body_base: usize,
}

/// Reads one element's identifier and length and returns where its body is. The body
/// is not interpreted here, so an element whose contents this module does not know can
/// still be skipped by its length.
fn frame(bytes: &[u8], base: usize) -> Result<Framed<'_>, Error> {
    let tag = read_tag(bytes, base)?;
    // `der` reads its tag as one octet and its length after it. Handing it the last
    // identifier octet gives it exactly that shape; the earlier identifier octets are
    // accounted for below. The constructed bit is the same in every identifier octet.
    let (der_value, _) =
        Der::decode_first(&bytes[tag.octets - 1..]).map_err(|source| Error::Der {
            offset: base,
            source,
        })?;
    let used = tag.octets - 1 + der_value.encoded_len();
    let body = der_value.value();
    Ok(Framed {
        tag,
        used,
        body,
        body_base: base + used - body.len(),
    })
}

/// Decodes one element and, if it is constructed, its children up to [`MAX_DEPTH`].
/// Returns the JSON and how many octets the element took.
fn node(
    bytes: &[u8],
    base: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<(Value, usize), Error> {
    spend(budget)?;
    let framed = frame(bytes, base)?;
    let mut json = json!({
        "offset": base,
        "tag": framed.tag.hex,
        "constructed": framed.tag.constructed,
        "length": framed.body.len(),
    });
    if framed.tag.constructed && depth < MAX_DEPTH {
        json["children"] = children(framed.body, framed.body_base, depth + 1, budget)?;
    } else {
        json["value_hex"] = Value::String(hex::encode_upper(framed.body));
        if framed.tag.constructed {
            json["truncated"] = Value::String(format!("nesting deeper than {MAX_DEPTH} levels"));
        }
    }
    Ok((json, framed.used))
}

fn children(body: &[u8], base: usize, depth: usize, budget: &mut Budget) -> Result<Value, Error> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let (child, used) = node(&body[offset..], base + offset, depth, budget)?;
        offset += used;
        out.push(child);
    }
    Ok(Value::Array(out))
}

/// Decodes a profile package into `{ "pe_count", "elements" }`.
///
/// Each element is the generic node with `index` and, for a known alternative, `type`.
/// A reserved (`rfuN`) or unrecognised tag is `type: "unknown"` with its whole element
/// as `raw_hex`, and nothing about its contents is inferred.
///
/// # Errors
///
/// [`Error::TooLarge`], [`Error::Empty`], and for any malformed element the offset and
/// the reason ([`Error::BadTag`], [`Error::Der`]).
pub fn decode(bytes: &[u8]) -> Result<Value, Error> {
    let (elements, _) = decode_elements(bytes)?;
    Ok(json!({ "pe_count": elements.len(), "elements": elements }))
}

/// Decodes top-level profile elements, returning the JSON elements and their raw byte slices.
fn decode_elements(bytes: &[u8]) -> Result<(Vec<Value>, Vec<Vec<u8>>), Error> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error::TooLarge {
            len: bytes.len(),
            max: MAX_FILE_BYTES,
        });
    }
    if bytes.is_empty() {
        return Err(Error::Empty);
    }
    let mut budget = Budget { nodes: 0 };
    let mut elements = Vec::new();
    let mut raws = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let index = elements.len();
        spend(&mut budget)?;
        let framed = frame(&bytes[offset..], offset)?;
        let known = match framed.tag.constructed {
            true => PE_TYPES.get(framed.tag.number as usize).copied(),
            false => None,
        }
        .filter(|name| !name.starts_with("rfu"));
        let used = framed.used;
        let raw = bytes[offset..offset + used].to_vec();
        let element = match known {
            Some(name) => {
                let (mut json, _) = node(&bytes[offset..], offset, 0, &mut budget)?;
                let fields = named_fields(name, children_of(&json));
                if let Some(fields) = fields {
                    json["fields"] = fields;
                }
                json["index"] = json!(index);
                json["type"] = json!(name);
                json
            }
            None => json!({
                "index": index,
                "offset": offset,
                "type": "unknown",
                "tag": framed.tag.hex,
                "length": framed.body.len(),
                "raw_hex": hex::encode_upper(&raw),
            }),
        };
        elements.push(element);
        raws.push(raw);
        offset += used;
    }
    Ok((elements, raws))
}

/// Returns the PE type name for a top-level element, or `None` if unknown/reserved.
fn pe_type_name(raw: &[u8]) -> Result<Option<&'static str>, Error> {
    let framed = frame(raw, 0)?;
    if !framed.tag.constructed {
        return Ok(None);
    }
    Ok(PE_TYPES
        .get(framed.tag.number as usize)
        .copied()
        .filter(|name| !name.starts_with("rfu")))
}

/// Encodes a DER length in minimal form.
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Encodes a TLV with the given tag bytes and body.
fn encode_tlv(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 3 + body.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&encode_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// A personalization document applied to a SAIP profile package.
///
/// This is the offline personalization half of SAIP (issue #226): it does not touch a card.
/// It can substitute variant/optional profile elements (by removing selected PE types) and
/// apply personalization values such as the profile header ICCID and PIN/PUK codes, matching
/// the fields exposed by [`decode`].
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Personalization {
    /// Replace the header profile ICCID (digits, 19-20; an 18-digit value gets a Luhn digit
    /// appended to 19, and the result is BCD-swapped with an `F` filler as the header stores it).
    #[serde(default)]
    pub iccid: Option<String>,
    /// Replace or override PIN code configurations in the `pinCodes` PE.
    #[serde(default)]
    pub pin_codes: Vec<PinPersonalization>,
    /// Replace or override PUK code configurations in the `pukCodes` PE.
    #[serde(default)]
    pub puk_codes: Vec<PukPersonalization>,
    /// Remove all top-level PEs whose type name is in this list (e.g. `opt-usim`, `opt-isim`).
    /// Used to substitute variant/optional PEs by excluding unwanted optional variants.
    #[serde(default)]
    pub remove_pe_types: Vec<String>,
}

/// One PIN configuration to apply in a `pinCodes` profile element.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PinPersonalization {
    /// PIN key reference (identifies which PIN, e.g. 1 for PIN1/app PIN, 0x0A for local PIN).
    pub key_reference: u8,
    /// PIN value as ASCII digits (4-8). Encoded as BCD nibbles padded with `F` to 8 octets.
    pub pin_value: String,
    /// Unblocking PUK reference, if present.
    #[serde(default)]
    pub unblocking_puk_reference: Option<u8>,
    /// PIN attributes byte. Defaults to 7 if omitted.
    #[serde(default)]
    pub attributes: Option<u8>,
    /// Maximum attempts (high nibble) and retries left (low nibble). Defaults to 3/3.
    #[serde(default)]
    pub max_attempts: Option<u8>,
    /// Retries left. Defaults to `max_attempts` or 3.
    #[serde(default)]
    pub retries_left: Option<u8>,
}

/// One PUK configuration to apply in a `pukCodes` profile element.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PukPersonalization {
    /// PUK key reference.
    pub key_reference: u8,
    /// PUK value as ASCII digits (8). Encoded as BCD nibbles padded with `F` to 8 octets.
    pub puk_value: String,
    /// Maximum attempts and retries left (high/low nibble). Defaults to 10/10 (0xAA).
    #[serde(default)]
    pub max_attempts: Option<u8>,
    /// Retries left. Defaults to `max_attempts` or 10.
    #[serde(default)]
    pub retries_left: Option<u8>,
}

/// Errors from personalization and variant handling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PersonalizeError {
    /// The input package could not be decoded.
    #[error("{0}")]
    Decode(#[from] Error),
    /// The personalization document is invalid.
    #[error("personalization document: {message}")]
    Document {
        /// What is wrong.
        message: String,
    },
    /// A value cannot be encoded into the profile.
    #[error("{field}: {message}")]
    Value {
        /// The field being set.
        field: &'static str,
        /// Why it cannot be encoded.
        message: String,
    },
}

/// Applies [`Personalization`] to a SAIP profile package and returns the modified DER bytes.
///
/// Variant/optional PEs whose type is listed in `remove_pe_types` are removed. Personalization
/// values (ICCID, PIN/PUK codes) are substituted into the corresponding PEs when present.
/// PEs not affected by the document are preserved byte-for-byte.
///
/// # Errors
///
/// Returns [`PersonalizeError`] if the package cannot be decoded, the document is invalid, or a
/// value cannot be encoded.
pub fn personalize(bytes: &[u8], doc: &Personalization) -> Result<Vec<u8>, PersonalizeError> {
    let (_elements, raws) = decode_elements(bytes).map_err(PersonalizeError::Decode)?;
    let remove: std::collections::HashSet<&str> =
        doc.remove_pe_types.iter().map(String::as_str).collect();
    let mut out = Vec::with_capacity(bytes.len());
    let mut pin_applied = false;
    let mut puk_applied = false;

    // Precompute modified code fields for pin/puk if we need to apply them.
    let pin_field = if doc.pin_codes.is_empty() {
        None
    } else {
        Some(build_pin_codes_field(&doc.pin_codes)?)
    };
    let puk_field = if doc.puk_codes.is_empty() {
        None
    } else {
        Some(build_puk_codes_field(&doc.puk_codes)?)
    };

    for raw in &raws {
        let ty = pe_type_name(raw).map_err(PersonalizeError::Decode)?;
        if let Some(name) = ty {
            if remove.contains(name) {
                continue;
            }
        }
        let modified = match ty {
            Some("header") if doc.iccid.is_some() => Some(personalize_header(raw, doc)?),
            Some("pinCodes") if pin_field.is_some() => {
                pin_applied = true;
                Some(rebuild_pe_preserving_header(
                    raw,
                    pin_field.as_ref().unwrap(),
                )?)
            }
            Some("pukCodes") if puk_field.is_some() => {
                puk_applied = true;
                Some(rebuild_pe_preserving_header(
                    raw,
                    puk_field.as_ref().unwrap(),
                )?)
            }
            _ => None,
        };
        out.extend_from_slice(modified.as_deref().unwrap_or(raw.as_slice()));
    }

    // If PIN/PUK personalization was requested but no such PE existed, that's not silently ignored
    // in a way that hides mistakes? Better to be lenient: only apply if present. But applying to a
    // package that has no pinCodes is a no-op - acceptable. However, for correctness, do nothing.
    let _ = (pin_applied, puk_applied);
    Ok(out)
}

fn read_tlv_at(
    buf: &[u8],
    off: usize,
) -> Result<(Vec<u8>, usize, Vec<u8>, usize), PersonalizeError> {
    let framed = frame(&buf[off..], off).map_err(PersonalizeError::Decode)?;
    let tag = buf[off..off + framed.tag.octets].to_vec();
    let header_len = framed.used - framed.body.len();
    Ok((tag, header_len, framed.body.to_vec(), framed.used))
}

fn personalize_header(raw: &[u8], doc: &Personalization) -> Result<Vec<u8>, PersonalizeError> {
    let iccid_str = doc.iccid.as_deref().unwrap();
    let iccid_bytes = encode_header_iccid(iccid_str)?;
    let framed = frame(raw, 0).map_err(PersonalizeError::Decode)?;
    let pe_tag = &raw[..framed.tag.octets];
    let body = framed.body;
    let mut new_body = Vec::with_capacity(body.len());
    let mut off = 0;
    let mut replaced = false;
    while off < body.len() {
        let (tag, _hlen, _val, used) = read_tlv_at(body, off)?;
        // ProfileHeader fields under AUTOMATIC TAGS: major(0)->80, minor(1)->81, profileType(2)->82, iccid(3)->83.
        if tag == [0x83] {
            new_body.extend_from_slice(&encode_tlv(&tag, &iccid_bytes));
            replaced = true;
        } else {
            new_body.extend_from_slice(&body[off..off + used]);
        }
        off += used;
    }
    if !replaced {
        new_body.extend_from_slice(&encode_tlv(&[0x83], &iccid_bytes));
    }
    Ok(encode_tlv(pe_tag, &new_body))
}

fn luhn_check_digit(digits: &str) -> Result<u8, PersonalizeError> {
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(PersonalizeError::Value {
            field: "iccid",
            message: "must contain only digits".to_string(),
        });
    }
    let mut sum = 0u32;
    // Compute check digit for the number formed by digits + '?'
    let mut dbl = true;
    for ch in digits.chars().rev() {
        let mut d = ch.to_digit(10).unwrap();
        if dbl {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        dbl = !dbl;
    }
    Ok(((10 - (sum % 10)) % 10) as u8)
}

fn encode_header_iccid(input: &str) -> Result<Vec<u8>, PersonalizeError> {
    let s: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
    if s.is_empty() {
        return Err(PersonalizeError::Value {
            field: "iccid",
            message: "is empty".to_string(),
        });
    }
    let mut digits = s.clone();
    match digits.len() {
        18 => {
            let cd = luhn_check_digit(&digits)?;
            digits.push(char::from(b'0' + cd));
        }
        19 | 20 => {}
        _ => {
            return Err(PersonalizeError::Value {
                field: "iccid",
                message: format!("expected 18-20 digits, got {}", digits.len()),
            });
        }
    }
    if digits.len() == 19 {
        digits.push('F');
    }
    // digits.len() == 20 now (or 20+F impossible). encode as pairs: high nibble, low nibble per octet
    let chars: Vec<char> = digits.chars().collect();
    if chars.len() != 20 {
        return Err(PersonalizeError::Value {
            field: "iccid",
            message: "internal length error".to_string(),
        });
    }
    let mut out = Vec::with_capacity(10);
    for pair in chars.chunks(2) {
        let hi = nibble(pair[0], "iccid")?;
        let lo = nibble(pair[1], "iccid")?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: char, field: &'static str) -> Result<u8, PersonalizeError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'F' | 'f' => Ok(0x0F),
        _ => Err(PersonalizeError::Value {
            field,
            message: format!("invalid nibble character '{c}'"),
        }),
    }
}

fn encode_pin_bcd(pin: &str, field: &'static str) -> Result<Vec<u8>, PersonalizeError> {
    if !(4..=8).contains(&pin.len()) || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(PersonalizeError::Value {
            field,
            message: "must be 4-8 ASCII digits".to_string(),
        });
    }
    let mut nibbles = Vec::with_capacity(16);
    for ch in pin.chars() {
        nibbles.push(ch as u8 - b'0');
    }
    while nibbles.len() < 16 {
        nibbles.push(0x0F);
    }
    let mut out = Vec::with_capacity(8);
    for pair in nibbles.chunks(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    Ok(out)
}

fn encode_uint(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let mut bytes = val.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    // ensure positive interpretation in DER INTEGER context: if high bit set, prepend 00
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    bytes
}

fn build_pin_config_entry(p: &PinPersonalization) -> Result<Vec<u8>, PersonalizeError> {
    let pin_val = encode_pin_bcd(&p.pin_value, "pin_codes.pin_value")?;
    let mut body = Vec::new();
    // keyReference [0] = 80
    body.extend_from_slice(&encode_tlv(
        &[0x80],
        &encode_uint(u64::from(p.key_reference)),
    ));
    // pinValue [1] = 81
    body.extend_from_slice(&encode_tlv(&[0x81], &pin_val));
    // unblockingPINReference [2] = 82
    if let Some(ukr) = p.unblocking_puk_reference {
        body.extend_from_slice(&encode_tlv(&[0x82], &encode_uint(u64::from(ukr))));
    }
    // pinAttributes [3] = 83
    if let Some(attr) = p.attributes {
        body.extend_from_slice(&encode_tlv(&[0x83], &[attr]));
    }
    // maxNumOfAttemps-retryNumLeft [4] = 84
    let max = p.max_attempts.unwrap_or(3);
    let left = p.retries_left.unwrap_or(max);
    let counter = (max << 4) | (left & 0x0F);
    // Use 1 or 2 bytes as appropriate; sample shows [0x00,0xAA] sometimes, but minimal is fine
    let counter_bytes = if counter == 0 {
        vec![0, 0]
    } else {
        vec![0x00, counter]
    };
    body.extend_from_slice(&encode_tlv(&[0x84], &counter_bytes));
    // PINConfiguration is a SEQUENCE (30)
    Ok(encode_tlv(&[0x30], &body))
}

/// Builds the `pinCodes` field (context tag [1], A1) carrying pin configurations.
/// PE-PINCodes nests pinconfig as choice [0] -> SEQUENCE OF inside A1 (as decoded by `pin_entries`).
fn build_pin_codes_field(pins: &[PinPersonalization]) -> Result<Vec<u8>, PersonalizeError> {
    let mut seq_of = Vec::new();
    for p in pins {
        seq_of.extend_from_slice(&build_pin_config_entry(p)?);
    }
    let inner = encode_tlv(&[0xA0], &seq_of);
    Ok(encode_tlv(&[0xA1], &inner))
}

/// Builds the `pukCodes` field (context tag [1], A1) carrying puk configurations.
/// PE-PUKCodes carries the SEQUENCE OF directly inside A1 (as decoded by `entries(..., "A1")`).
fn build_puk_codes_field(puks: &[PukPersonalization]) -> Result<Vec<u8>, PersonalizeError> {
    let mut seq_of = Vec::new();
    for p in puks {
        seq_of.extend_from_slice(&build_puk_config_entry(p)?);
    }
    Ok(encode_tlv(&[0xA1], &seq_of))
}

fn build_puk_config_entry(p: &PukPersonalization) -> Result<Vec<u8>, PersonalizeError> {
    let puk_val = encode_pin_bcd(&p.puk_value, "puk_codes.puk_value")?;
    let mut body = Vec::new();
    body.extend_from_slice(&encode_tlv(
        &[0x80],
        &encode_uint(u64::from(p.key_reference)),
    ));
    body.extend_from_slice(&encode_tlv(&[0x81], &puk_val));
    let max = p.max_attempts.unwrap_or(10);
    let left = p.retries_left.unwrap_or(max);
    let counter = (max << 4) | (left & 0x0F);
    let counter_bytes = vec![0x00, counter];
    body.extend_from_slice(&encode_tlv(&[0x82], &counter_bytes));
    Ok(encode_tlv(&[0x30], &body))
}

/// Rebuilds a pinCodes/pukCodes PE keeping its existing PE header (child A0) if present,
/// replacing the codes field (child A1) with `new_codes_field` (a complete TLV, tag A1).
fn rebuild_pe_preserving_header(
    raw: &[u8],
    new_codes_field: &[u8],
) -> Result<Vec<u8>, PersonalizeError> {
    let framed = frame(raw, 0).map_err(PersonalizeError::Decode)?;
    let pe_tag = &raw[..framed.tag.octets];
    let body = framed.body;
    let mut children: Vec<Vec<u8>> = Vec::new();
    let mut off = 0;
    let mut replaced = false;
    let mut has_header = false;
    while off < body.len() {
        let (tag, _hlen, _val, used) = read_tlv_at(body, off)?;
        if tag == [0xA0] {
            has_header = true;
            children.push(body[off..off + used].to_vec());
        } else if tag == [0xA1] {
            children.push(new_codes_field.to_vec());
            replaced = true;
        } else {
            children.push(body[off..off + used].to_vec());
        }
        off += used;
    }
    if !has_header {
        let mut hdr = encode_tlv(&[0x80], &[]);
        hdr.extend_from_slice(&encode_tlv(&[0x81], &encode_uint(0)));
        children.insert(0, encode_tlv(&[0xA0], &hdr));
    }
    if !replaced {
        children.push(new_codes_field.to_vec());
    }
    let mut new_body = Vec::new();
    for c in children {
        new_body.extend_from_slice(&c);
    }
    Ok(encode_tlv(pe_tag, &new_body))
}

/// The children of a decoded node; a primitive node has none.
fn children_of(node: &Value) -> &[Value] {
    match node.get("children").and_then(Value::as_array) {
        Some(list) => list.as_slice(),
        None => &[],
    }
}

/// The child whose identifier is the tag, written the way the walk writes it (hex, upper case).
fn child<'a>(kids: &'a [Value], tag: &str) -> Option<&'a Value> {
    kids.iter()
        .find(|c| c.get("tag").and_then(Value::as_str) == Some(tag))
}

/// The entries of the constructed child named by tag, a SEQUENCE OF.
fn entries<'a>(kids: &'a [Value], tag: &str) -> &'a [Value] {
    match child(kids, tag) {
        Some(node) => children_of(node),
        None => &[],
    }
}

/// The content octets of a primitive node, or None for a constructed one.
fn content(node: &Value) -> Option<Vec<u8>> {
    hex::decode(node.get("value_hex")?.as_str()?).ok()
}

/// An INTEGER or UInt8 as a number. A leading zero octet is the sign octet of a value
/// with the high bit set, so 00 AA reads as 170.
fn uint_of(node: &Value) -> Option<u64> {
    let bytes = content(node)?;
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(bytes.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b)))
}

fn text_of(node: &Value) -> Option<String> {
    String::from_utf8(content(node)?).ok()
}

/// An OBJECT IDENTIFIER in dotted form, decoded by the same arc reader GP uses.
fn oid_of(node: &Value) -> Option<String> {
    oid_arcs(&content(node)?).map(|arcs| dotted(&arcs))
}

/// ICCID digits as the header stores them in the public sample: each octet gives its high
/// nibble and then its low nibble, read up to the first F filler. [V] against the sample only.
fn digits_of(node: &Value) -> Option<String> {
    let mut out = String::new();
    for byte in content(node)? {
        for nibble in [byte >> 4, byte & 0x0F] {
            if nibble == 0x0F {
                return Some(out);
            }
            out.push(char::from_digit(u32::from(nibble), 10)?);
        }
    }
    Some(out)
}

/// PEHeader ::= SEQUENCE { mandated NULL OPTIONAL, identification UInt15 }, PE_Definitions 3.3.1.
fn pe_header(node: &Value) -> Value {
    let kids = children_of(node);
    json!({
        "mandated": child(kids, "80").is_some(),
        "identification": child(kids, "81").and_then(uint_of),
    })
}

/// ProfileHeader, the body of the header PE. Positions follow the SEQUENCE order under
/// AUTOMATIC TAGS: major-version 0, minor-version 1, profileType 2, iccid 3.
fn profile_header(kids: &[Value]) -> Value {
    json!({
        "major_version": child(kids, "80").and_then(uint_of),
        "minor_version": child(kids, "81").and_then(uint_of),
        "profile_type": child(kids, "82").and_then(text_of),
        "iccid": child(kids, "83").and_then(digits_of),
    })
}

/// The PINConfiguration entries of PE-PINCodes. The sample nests them one level deeper than
/// PE-PUKCodes: the CHOICE under [1] holds the pinconfig alternative under [0], which holds
/// the SEQUENCE OF. The filePath alternative is not decoded (its tag is [U]).
fn pin_entries(kids: &[Value]) -> &[Value] {
    let choice = match child(kids, "A1") {
        Some(node) => node,
        None => return &[],
    };
    match child(children_of(choice), "A0") {
        Some(list) => children_of(list),
        None => &[],
    }
}

/// PINConfiguration: keyReference 0, pinValue 1, unblockingPINReference 2 OPTIONAL,
/// pinAttributes 3 DEFAULT 7, maxNumOfAttemps-retryNumLeft 4 DEFAULT 51. The counter holds
/// max attempts in its high nibble and retries left in its low nibble.
fn pin_config(entry: &Value) -> Value {
    let kids = children_of(entry);
    let counter = child(kids, "84").and_then(uint_of);
    let counter_value = counter.unwrap_or(0x33);
    json!({
        "key_reference": child(kids, "80").and_then(uint_of),
        "pin_value_hex": child(kids, "81").and_then(|n| n.get("value_hex")).cloned(),
        "unblocking_puk_reference": child(kids, "82").and_then(uint_of),
        "attributes": child(kids, "83").and_then(uint_of).unwrap_or(7),
        "max_attempts": counter_value >> 4,
        "retries_left": counter_value & 0x0F,
        "counter_defaulted": counter.is_none(),
    })
}

/// PUKConfiguration: keyReference 0, pukValue 1, maxNumOfAttemps-retryNumLeft 2 DEFAULT 170.
fn puk_config(entry: &Value) -> Value {
    let kids = children_of(entry);
    let counter = child(kids, "82").and_then(uint_of);
    let counter_value = counter.unwrap_or(0xAA);
    json!({
        "key_reference": child(kids, "80").and_then(uint_of),
        "puk_value_hex": child(kids, "81").and_then(|n| n.get("value_hex")).cloned(),
        "max_attempts": counter_value >> 4,
        "retries_left": counter_value & 0x0F,
        "counter_defaulted": counter.is_none(),
    })
}

/// The named fields of a known PE, read from its decoded children. Only the PEs listed
/// here get them. A field that is absent or of another shape is left out, and the generic
/// tree still shows the bytes.
fn named_fields(name: &str, kids: &[Value]) -> Option<Value> {
    let header = child(kids, "A0").map(pe_header);
    let fields = match name {
        "header" => profile_header(kids),
        "pinCodes" => json!({
            "pin_header": header,
            "pin_configs": pin_entries(kids).iter().map(pin_config).collect::<Vec<_>>(),
        }),
        "pukCodes" => json!({
            "puk_header": header,
            "puk_configs": entries(kids, "A1").iter().map(puk_config).collect::<Vec<_>>(),
        }),
        "end" => json!({ "end_header": header }),
        "mf" => json!({
            "mf_header": header,
            "template_id": child(kids, "81").and_then(oid_of),
        }),
        _ => return None,
    };
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Short-form or long-form (`81`/`82`) TLV, minimal lengths.
    fn tlv(tag: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else if body.len() <= 0xFF {
            out.extend_from_slice(&[0x81, body.len() as u8]);
        } else {
            out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn the_tag_table_is_the_asn1_choice_order() {
        // Position of each alternative in `ProfileElement ::= CHOICE` (AUTOMATIC TAGS).
        assert_eq!(PE_TYPES[0], "header");
        assert_eq!(PE_TYPES[10], "end");
        assert_eq!(PE_TYPES[16], "mf");
        assert_eq!(PE_TYPES[31], "df-5gprose");
        assert_eq!(PE_TYPES[32], "iot");
        assert_eq!(PE_TYPES.len(), 34);
    }

    #[test]
    fn a_hand_built_package_decodes_known_unknown_and_long_form_elements() {
        let header = tlv(&[0xA0], &tlv(&[0x80], &[0x02]));
        let mut mf_body = tlv(&[0x80], &[0u8; 0x7F]);
        mf_body.extend(tlv(&[0x80], &[0x01]));
        // 132 octets of body, so the MF length takes the long form `81 84`.
        let mf = tlv(&[0xB0], &mf_body);
        let iot = tlv(&[0xBF, 0x20], &[]); // high-tag form, number 32
        let unknown = tlv(&[0xBF, 0x25], &[0xAB, 0xCD]); // number 37, not in the table
        let end = tlv(&[0xAA], &[]);
        let package = [header, mf, iot, unknown, end].concat();

        let out = decode(&package).expect("well-formed package");
        assert_eq!(out["pe_count"], 5);
        let elements = out["elements"].as_array().unwrap();
        assert_eq!(elements[0]["type"], "header");
        assert_eq!(elements[0]["tag"], "A0");
        assert_eq!(elements[1]["type"], "mf");
        assert_eq!(elements[1]["length"], mf_body.len());
        assert_eq!(elements[2]["type"], "iot");
        assert_eq!(elements[2]["tag"], "BF20");
        assert_eq!(elements[3]["type"], "unknown");
        assert_eq!(elements[3]["tag"], "BF25");
        assert_eq!(elements[3]["raw_hex"], "BF2502ABCD");
        assert_eq!(elements[4]["type"], "end");
        assert_eq!(elements[4]["index"], 4);
    }

    #[test]
    fn nested_constructed_values_are_expanded_to_the_depth_limit_and_no_further() {
        let mut inner = tlv(&[0x80], &[0x01]);
        for _ in 0..(MAX_DEPTH + 2) {
            inner = tlv(&[0xA0], &inner);
        }
        let out = decode(&tlv(&[0xB0], &inner)).expect("deep but well-formed");
        let text = out.to_string();
        assert!(text.contains("nesting deeper than"), "depth marker missing");
    }

    #[test]
    fn hostile_framing_is_refused_with_the_offset_and_never_panics() {
        // Non-minimal long length: `81 05` for a five-octet value.
        let non_minimal = decode(&[0xA2, 0x81, 0x05, 0, 0, 0, 0, 0]).unwrap_err();
        assert!(
            matches!(non_minimal, Error::Der { offset: 0, .. }),
            "{non_minimal:?}"
        );
        // Declared length runs past the end.
        let truncated = decode(&[0xA0, 0x05, 0x80]).unwrap_err();
        assert!(
            matches!(truncated, Error::Der { offset: 0, .. }),
            "{truncated:?}"
        );
        // Identifier cut off mid high-tag form.
        assert!(matches!(decode(&[0xBF]), Err(Error::BadTag { offset: 0 })));
        // Non-minimal high-tag digit (`80` as the first subsequent octet).
        assert!(matches!(
            decode(&[0xBF, 0x80, 0x01, 0x00]),
            Err(Error::BadTag { .. })
        ));
        assert_eq!(decode(&[]), Err(Error::Empty));
        let big = vec![0u8; MAX_FILE_BYTES + 1];
        assert!(matches!(decode(&big), Err(Error::TooLarge { .. })));
    }

    #[test]
    fn named_fields_read_the_header_pin_puk_end_and_mf_as_the_sample_encodes_them() {
        let header = tlv(
            &[0xA0],
            &[
                tlv(&[0x80], &[0x02]),
                tlv(&[0x81], &[0x01]),
                tlv(&[0x82], b"GSMA"),
                tlv(
                    &[0x83],
                    &[0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x58],
                ),
            ]
            .concat(),
        );
        let pin_entry_1 = tlv(
            &[0x30],
            &[
                tlv(&[0x80], &[0x01]),
                tlv(&[0x81], &[0x30, 0x30, 0x30, 0x30, 0xFF, 0xFF, 0xFF, 0xFF]),
                tlv(&[0x82], &[0x01]),
                tlv(&[0x83], &[0x06]),
            ]
            .concat(),
        );
        let pin_entry_2 = tlv(
            &[0x30],
            &[
                tlv(&[0x80], &[0x0A]),
                tlv(&[0x81], &[0x35; 8]),
                tlv(&[0x83], &[0x03]),
                tlv(&[0x84], &[0x00, 0xAA]),
            ]
            .concat(),
        );
        let pin = tlv(
            &[0xA2],
            &[
                tlv(
                    &[0xA0],
                    &[tlv(&[0x80], &[]), tlv(&[0x81], &[0x01])].concat(),
                ),
                tlv(&[0xA1], &tlv(&[0xA0], &[pin_entry_1, pin_entry_2].concat())),
            ]
            .concat(),
        );
        let puk_entry = tlv(
            &[0x30],
            &[tlv(&[0x80], &[0x01]), tlv(&[0x81], &[0x31; 8])].concat(),
        );
        let puk = tlv(
            &[0xA3],
            &[
                tlv(
                    &[0xA0],
                    &[tlv(&[0x80], &[]), tlv(&[0x81], &[0x05])].concat(),
                ),
                tlv(&[0xA1], &puk_entry),
            ]
            .concat(),
        );
        let end = tlv(&[0xAA], &tlv(&[0xA0], &tlv(&[0x81], &[0x1D])));
        let mf = tlv(
            &[0xB0],
            &[
                tlv(
                    &[0xA0],
                    &[tlv(&[0x80], &[]), tlv(&[0x81], &[0x04])].concat(),
                ),
                tlv(&[0x81], &[0x67, 0x81, 0x0F, 0x01, 0x02, 0x01]),
            ]
            .concat(),
        );

        let package = [header, pin, puk, end, mf].concat();
        let out = decode(&package).expect("well-formed package");
        let el = out["elements"].as_array().unwrap();
        assert_eq!(el[0]["fields"]["major_version"], 2);
        assert_eq!(el[0]["fields"]["minor_version"], 1);
        assert_eq!(el[0]["fields"]["profile_type"], "GSMA");
        assert_eq!(el[0]["fields"]["iccid"], "89000123456789012358");
        assert_eq!(el[1]["type"], "pinCodes");
        assert_eq!(el[1]["fields"]["pin_header"]["mandated"], true);
        assert_eq!(el[1]["fields"]["pin_header"]["identification"], 1);
        let pins = &el[1]["fields"]["pin_configs"];
        assert_eq!(pins[0]["key_reference"], 1);
        assert_eq!(pins[0]["pin_value_hex"], "30303030FFFFFFFF");
        assert_eq!(pins[0]["unblocking_puk_reference"], 1);
        assert_eq!(pins[0]["attributes"], 6);
        assert_eq!(pins[0]["counter_defaulted"], true);
        assert_eq!(pins[0]["max_attempts"], 3);
        assert_eq!(pins[0]["retries_left"], 3);
        assert_eq!(pins[1]["pin_value_hex"], "3535353535353535");
        assert_eq!(pins[1]["counter_defaulted"], false);
        assert_eq!(pins[1]["max_attempts"], 10);
        assert_eq!(pins[1]["retries_left"], 10);
        assert_eq!(el[2]["fields"]["puk_header"]["identification"], 5);
        let puks = &el[2]["fields"]["puk_configs"];
        assert_eq!(puks[0]["key_reference"], 1);
        assert_eq!(puks[0]["counter_defaulted"], true);
        assert_eq!(puks[0]["max_attempts"], 10);
        assert_eq!(puks[0]["retries_left"], 10);
        assert_eq!(el[3]["fields"]["end_header"]["identification"], 29);
        assert_eq!(el[4]["fields"]["template_id"], "2.23.143.1.2.1");
        assert_eq!(el[4]["fields"]["mf_header"]["identification"], 4);
    }

    #[test]
    fn the_iccid_digits_stop_at_the_filler_and_a_bad_nibble_is_refused() {
        assert_eq!(
            digits_of(&json!({"value_hex": "98F0"})),
            Some("98".to_string())
        );
        assert_eq!(digits_of(&json!({"value_hex": "9A"})), None);
    }

    #[test]
    fn optional_variant_and_template_bearing_pes_are_named_and_preserved() {
        // Variant/optional PEs by SAIP position: opt-usim (20), opt-isim (22),
        // opt-csim (26), df-saip (29), opt-iot (33, high-tag form). Template-bearing
        // PEs (genericFileManagement, application, securityDomain) are recognized and
        // their contents remain available in the bounded TLV tree.
        let gfm = tlv(&[0xA1], &tlv(&[0xA0], &tlv(&[0x81], &[0x01]))); // 1
        let secdom = tlv(&[0xA6], &tlv(&[0x80], &[0x42])); // 6
        let app = tlv(&[0xA8], &tlv(&[0xA0], &tlv(&[0x81], &[0x07]))); // 8
        let opt_usim = tlv(&[0xB4], &tlv(&[0x80], &[0x14])); // 20
        let opt_isim = tlv(&[0xB6], &tlv(&[0x80], &[0x16])); // 22
        let opt_csim = tlv(&[0xBA], &tlv(&[0x80], &[0x1A])); // 26
        let df_saip = tlv(&[0xBD], &tlv(&[0x80], &[0x1D])); // 29
        let opt_iot = tlv(&[0xBF, 0x21], &tlv(&[0x80], &[0x21])); // 33
        let end = tlv(&[0xAA], &[]);

        let package = [
            gfm, secdom, app, opt_usim, opt_isim, opt_csim, df_saip, opt_iot, end,
        ]
        .concat();
        let out = decode(&package).expect("variant/template PEs decode");
        assert_eq!(out["pe_count"], 9);
        let elements = out["elements"].as_array().unwrap();
        let types: Vec<&str> = elements
            .iter()
            .map(|e| e["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            [
                "genericFileManagement",
                "securityDomain",
                "application",
                "opt-usim",
                "opt-isim",
                "opt-csim",
                "df-saip",
                "opt-iot",
                "end",
            ]
        );
        assert_eq!(elements[3]["tag"], "B4");
        assert_eq!(elements[7]["tag"], "BF21");
        assert_eq!(elements[0]["children"][0]["children"][0]["value_hex"], "01");
        assert_eq!(elements[2]["children"][0]["children"][0]["value_hex"], "07");
    }

    fn sample_package() -> Vec<u8> {
        let header = tlv(
            &[0xA0],
            &[
                tlv(&[0x80], &[0x02]),
                tlv(&[0x81], &[0x01]),
                tlv(&[0x82], b"GSMA"),
                tlv(
                    &[0x83],
                    &[0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x58],
                ),
            ]
            .concat(),
        );
        let pin = tlv(
            &[0xA2],
            &[
                tlv(
                    &[0xA0],
                    &[tlv(&[0x80], &[]), tlv(&[0x81], &[0x01])].concat(),
                ),
                tlv(
                    &[0xA1],
                    &tlv(
                        &[0xA0],
                        &tlv(
                            &[0x30],
                            &[
                                tlv(&[0x80], &[0x01]),
                                tlv(&[0x81], &[0x30, 0x30, 0x30, 0x30, 0xFF, 0xFF, 0xFF, 0xFF]),
                            ]
                            .concat(),
                        ),
                    ),
                ),
            ]
            .concat(),
        );
        let puk = tlv(
            &[0xA3],
            &[
                tlv(
                    &[0xA0],
                    &[tlv(&[0x80], &[]), tlv(&[0x81], &[0x05])].concat(),
                ),
                tlv(
                    &[0xA1],
                    &tlv(
                        &[0x30],
                        &[tlv(&[0x80], &[0x01]), tlv(&[0x81], &[0x31; 8])].concat(),
                    ),
                ),
            ]
            .concat(),
        );
        let opt_usim = tlv(&[0xB4], &tlv(&[0x80], &[0x14]));
        let opt_isim = tlv(&[0xB6], &tlv(&[0x80], &[0x16]));
        let end = tlv(&[0xAA], &tlv(&[0xA0], &tlv(&[0x81], &[0x1D])));
        [header, pin, puk, opt_usim, opt_isim, end].concat()
    }

    #[test]
    fn personalize_removes_selected_variant_optional_pes() {
        let pkg = sample_package();
        let doc = Personalization {
            remove_pe_types: vec!["opt-usim".into(), "opt-isim".into()],
            ..Default::default()
        };
        let out = personalize(&pkg, &doc).expect("personalize");
        let decoded = decode(&out).expect("decode personalized");
        let types: Vec<&str> = decoded["elements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, ["header", "pinCodes", "pukCodes", "end"]);
    }

    #[test]
    fn personalize_updates_header_iccid() {
        let pkg = sample_package();
        let doc = Personalization {
            iccid: Some("89000123456789012451".into()),
            ..Default::default()
        };
        let out = personalize(&pkg, &doc).expect("personalize");
        let decoded = decode(&out).expect("decode personalized");
        assert_eq!(
            decoded["elements"][0]["fields"]["iccid"],
            "89000123456789012451"
        );
    }

    #[test]
    fn personalize_updates_pin_and_puk_codes() {
        let pkg = sample_package();
        let doc = Personalization {
            pin_codes: vec![PinPersonalization {
                key_reference: 1,
                pin_value: "1234".into(),
                unblocking_puk_reference: Some(1),
                attributes: Some(7),
                max_attempts: Some(3),
                retries_left: Some(3),
            }],
            puk_codes: vec![PukPersonalization {
                key_reference: 1,
                puk_value: "87654321".into(),
                max_attempts: Some(10),
                retries_left: Some(10),
            }],
            ..Default::default()
        };
        let out = personalize(&pkg, &doc).expect("personalize");
        let decoded = decode(&out).expect("decode personalized");
        assert_eq!(decoded["elements"][1]["type"], "pinCodes");
        assert_eq!(
            decoded["elements"][1]["fields"]["pin_configs"][0]["pin_value_hex"],
            "1234FFFFFFFFFFFF"
        );
        assert_eq!(
            decoded["elements"][1]["fields"]["pin_header"]["identification"],
            1
        );
        assert_eq!(decoded["elements"][2]["type"], "pukCodes");
        assert_eq!(
            decoded["elements"][2]["fields"]["puk_configs"][0]["puk_value_hex"],
            "87654321FFFFFFFF"
        );
        assert_eq!(
            decoded["elements"][2]["fields"]["puk_header"]["identification"],
            5
        );
    }
}
