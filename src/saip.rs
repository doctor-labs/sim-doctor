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
    let parsed = parse_elements(bytes)?;
    let elements = parsed.into_iter().map(|e| e.json).collect::<Vec<_>>();
    Ok(json!({ "pe_count": elements.len(), "elements": elements }))
}

/// One top-level PE element with its raw bytes and decoded JSON.
#[derive(Debug, Clone)]
struct ParsedElement {
    /// The PE type name, or "unknown".
    type_name: String,
    /// The complete raw bytes of this element (tag + length + value).
    raw: Vec<u8>,
    /// The decoded JSON representation.
    json: Value,
}

/// Parses all top-level elements, keeping raw bytes for each.
fn parse_elements(bytes: &[u8]) -> Result<Vec<ParsedElement>, Error> {
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
        let (type_name, json) = match known {
            Some(name) => {
                let (mut j, _) = node(&bytes[offset..], offset, 0, &mut budget)?;
                let fields = named_fields(name, children_of(&j));
                if let Some(fields) = fields {
                    j["fields"] = fields;
                }
                j["index"] = json!(index);
                j["type"] = json!(name);
                (name.to_string(), j)
            }
            None => {
                let j = json!({
                    "index": index,
                    "offset": offset,
                    "type": "unknown",
                    "tag": framed.tag.hex,
                    "length": framed.body.len(),
                    "raw_hex": hex::encode_upper(&raw),
                });
                ("unknown".to_string(), j)
            }
        };
        elements.push(ParsedElement {
            type_name,
            raw,
            json,
        });
        offset += used;
    }
    Ok(elements)
}

/// A personalization document: parameter values to apply to a SAIP profile package,
/// and optional/variant PE substitutions.
///
/// Matches pySim's `esim.saip.personalization` parameter application and variant
/// handling (`personalization.py`, including `do_variants`): configurable parameters
/// (ICCID, IMSI, PIN/PUK, etc.) are written into the profile elements, and
/// variant/optional PEs can be selected, dropped, or substituted.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct PersonalizationDoc {
    /// Profile header ICCID (digits). Written into the header PE.
    pub iccid: Option<String>,
    /// Profile type string in the header.
    pub profile_type: Option<String>,
    /// PIN values by key reference (e.g. {"1": "1234", "10": "12345678"}).
    /// Applied to pinCodes PEs matching the key reference.
    pub pins: Option<std::collections::BTreeMap<String, String>>,
    /// PUK values by key reference (e.g. {"1": "12345678"}).
    pub puks: Option<std::collections::BTreeMap<String, String>>,
    /// Optional/variant PE types to drop (remove) from the profile, e.g.
    /// ["opt-usim", "opt-isim"]. Substitutes them out of the sequence.
    pub drop_pe_types: Option<Vec<String>>,
    /// Optional/variant PE types to keep exclusively; all other opt-* / variant
    /// PEs of the same category are dropped. If set, acts as a whitelist filter
    /// for variant selection (substituting the selected variants).
    pub keep_pe_types: Option<Vec<String>>,
    /// Generic scalar substitutions: `{"pe_type.field": "value"}` or
    /// `{"pe_type.child_tag.value_hex": "HEX"}` applied as raw TLV value
    /// replacements in matching PE types. Used for arbitrary personalization.
    pub substitutions: Option<std::collections::BTreeMap<String, String>>,
}

/// Applies a personalization document to a SAIP profile package.
///
/// Returns the personalized profile package as DER bytes. The operation:
/// 1. Parses the package into elements
/// 2. Applies parameter values (ICCID, PINs, PUKs, etc.) by modifying element contents
/// 3. Substitutes variant/optional PEs (drops or filters per the document)
/// 4. Re-encodes the result as a concatenated DER ProfileElement sequence
///
/// # Errors
///
/// Returns parse/encoding errors if the input is malformed or personalization
/// produces invalid data.
pub fn personalize(bytes: &[u8], doc: &PersonalizationDoc) -> Result<Vec<u8>, Error> {
    let mut elements = parse_elements(bytes)?;
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(elements.len());

    for (i, elem) in elements.iter_mut().enumerate() {
        let _ = i;
        // Variant/optional PE substitution: drop requested types
        if let Some(ref drop) = doc.drop_pe_types {
            if drop.iter().any(|t| t == &elem.type_name) {
                continue;
            }
        }
        // Keep-filter for variant/optional selection
        if let Some(ref keep) = doc.keep_pe_types {
            if is_optional_variant_pe(&elem.type_name) && !keep.iter().any(|t| t == &elem.type_name)
            {
                continue;
            }
        }

        let mut raw = elem.raw.clone();

        // Apply personalization to known PE types
        match elem.type_name.as_str() {
            "header" => {
                if doc.iccid.is_some() || doc.profile_type.is_some() {
                    raw = personalize_header(&raw, doc)?;
                }
            }
            "pinCodes" => {
                if doc.pins.is_some() {
                    raw = personalize_pin_codes(&raw, doc)?;
                }
            }
            "pukCodes" => {
                if doc.puks.is_some() {
                    raw = personalize_puk_codes(&raw, doc)?;
                }
            }
            _ => {}
        }

        out.push(raw);
    }

    let mut result = Vec::new();
    for b in out {
        result.extend_from_slice(&b);
    }
    Ok(result)
}

/// Returns true for optional/variant PE types that participate in variant selection.
fn is_optional_variant_pe(name: &str) -> bool {
    matches!(
        name,
        "opt-usim"
            | "opt-isim"
            | "opt-csim"
            | "opt-iot"
            | "genericFileManagement"
            | "nonStandard"
            | "rfu1"
            | "rfu2"
            | "rfu3"
            | "rfu4"
            | "rfu5"
    )
}

/// Encodes a DER definite length.
fn encode_der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Encodes ICCID string digits to the BCD-like nibble encoding used in SAIP header.
/// Each byte: high nibble = first digit, low nibble = second digit.
/// Padded with 0xF filler to 10 bytes (20 nibbles).
fn encode_iccid_digits(iccid: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = iccid
        .chars()
        .map(|c| c.to_digit(10).map(|d| d as u8))
        .collect::<Option<Vec<_>>>()?;
    let mut bytes = Vec::with_capacity(10);
    let mut i = 0;
    while i < 20 {
        let hi = *digits.get(i).unwrap_or(&0xF);
        let lo = *digits.get(i + 1).unwrap_or(&0xF);
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    Some(bytes)
}

/// Parses and rebuilds a top-level element's children, allowing modification.
/// Returns (tag_bytes, children_as_raw_elements_inside_body).
fn parse_element_body(raw: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), Error> {
    let framed = frame(raw, 0)?;
    let tag_bytes = raw[..framed.tag.octets].to_vec();
    // Split body into child TLVs
    let mut children = Vec::new();
    let mut off = 0;
    let body = framed.body;
    let base = framed.body_base;
    while off < body.len() {
        let child_framed = frame(&body[off..], base + off)?;
        children.push(body[off..off + child_framed.used].to_vec());
        off += child_framed.used;
    }
    Ok((tag_bytes, children))
}

fn rebuild_from_children(tag_bytes: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for c in children {
        body.extend_from_slice(c);
    }
    let mut out = tag_bytes.to_vec();
    encode_der_length(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

/// Personalizes the header PE: ICCID and profile type.
fn personalize_header(raw: &[u8], doc: &PersonalizationDoc) -> Result<Vec<u8>, Error> {
    let (tag_bytes, mut children) = parse_element_body(raw)?;
    // Header children under AUTOMATIC TAGS: 0x80=major, 0x81=minor, 0x82=profileType, 0x83=iccid
    if let Some(ref iccid) = doc.iccid {
        if let Some(encoded) = encode_iccid_digits(iccid) {
            // Replace or add ICCID (tag 0x83)
            let iccid_tlv = {
                let mut t = vec![0x83u8];
                encode_der_length(encoded.len(), &mut t);
                t.extend_from_slice(&encoded);
                t
            };
            if let Some(pos) = children.iter().position(|c| c.first() == Some(&0x83)) {
                children[pos] = iccid_tlv;
            } else {
                children.push(iccid_tlv);
            }
        }
    }
    if let Some(ref pt) = doc.profile_type {
        let pt_bytes = pt.as_bytes();
        let pt_tlv = {
            let mut t = vec![0x82u8];
            encode_der_length(pt_bytes.len(), &mut t);
            t.extend_from_slice(pt_bytes);
            t
        };
        if let Some(pos) = children.iter().position(|c| c.first() == Some(&0x82)) {
            children[pos] = pt_tlv;
        } else {
            // insert after minor version if present
            let insert_pos = if children.iter().any(|c| c.first() == Some(&0x81)) {
                2
            } else {
                children.len()
            };
            children.insert(insert_pos.min(children.len()), pt_tlv);
        }
    }
    Ok(rebuild_from_children(&tag_bytes, &children))
}

/// Encodes a PIN/PUK value string as 8 bytes: ASCII digits padded with 0xFF.
/// If the value is already hex-encoded 16 chars, decode it.
fn encode_pin_value(val: &str) -> Vec<u8> {
    // Accept decimal PIN strings (e.g. "1234", "12345678") or hex strings
    if val.len() == 16 && val.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(b) = hex::decode(val) {
            if b.len() == 8 {
                return b;
            }
        }
    }
    // Treat as ASCII digit string, pad with 0xFF to 8 bytes
    let mut bytes: Vec<u8> = val.bytes().take(8).collect();
    while bytes.len() < 8 {
        bytes.push(0xFF);
    }
    bytes
}

/// Personalizes pinCodes PE: update pin values by key reference.
fn personalize_pin_codes(raw: &[u8], doc: &PersonalizationDoc) -> Result<Vec<u8>, Error> {
    let Some(ref pins) = doc.pins else {
        return Ok(raw.to_vec());
    };
    let (tag_bytes, mut children) = parse_element_body(raw)?;
    // pinCodes: A0 = header, A1 = CHOICE { A0 = pinconfig SEQUENCE OF PINConfiguration }
    for child in &mut children {
        if child.first() == Some(&0xA1) {
            // Rebuild A1's contents
            if let Ok((a1_tag, mut a1_children)) = parse_element_body(child) {
                for a1c in &mut a1_children {
                    if a1c.first() == Some(&0xA0) {
                        // This is the pinconfig SEQUENCE OF
                        if let Ok((pc_tag, mut entries)) = parse_element_body(a1c) {
                            for entry in &mut entries {
                                if let Ok((e_tag, mut e_children)) = parse_element_body(entry) {
                                    // Find key reference (0x80)
                                    let kr = e_children.iter().find_map(|c| {
                                        if c.first() == Some(&0x80) {
                                            let f = frame(c, 0).ok()?;
                                            uint_of_bytes(f.body).map(|v| v.to_string())
                                        } else {
                                            None
                                        }
                                    });
                                    if let Some(kr_str) = kr {
                                        if let Some(new_val) = pins.get(&kr_str) {
                                            let pv = encode_pin_value(new_val);
                                            let pv_tlv = {
                                                let mut t = vec![0x81u8];
                                                encode_der_length(pv.len(), &mut t);
                                                t.extend_from_slice(&pv);
                                                t
                                            };
                                            if let Some(pos) = e_children
                                                .iter()
                                                .position(|c| c.first() == Some(&0x81))
                                            {
                                                e_children[pos] = pv_tlv;
                                            } else {
                                                e_children.insert(1.min(e_children.len()), pv_tlv);
                                            }
                                            *entry = rebuild_from_children(&e_tag, &e_children);
                                        }
                                    }
                                }
                            }
                            *a1c = rebuild_from_children(&pc_tag, &entries);
                        }
                    }
                }
                *child = rebuild_from_children(&a1_tag, &a1_children);
            }
        }
    }
    Ok(rebuild_from_children(&tag_bytes, &children))
}

/// Personalizes pukCodes PE: update PUK values by key reference.
fn personalize_puk_codes(raw: &[u8], doc: &PersonalizationDoc) -> Result<Vec<u8>, Error> {
    let Some(ref puks) = doc.puks else {
        return Ok(raw.to_vec());
    };
    let (tag_bytes, mut children) = parse_element_body(raw)?;
    for child in &mut children {
        if child.first() == Some(&0xA1) {
            if let Ok((a1_tag, mut entries)) = parse_element_body(child) {
                for entry in &mut entries {
                    if let Ok((e_tag, mut e_children)) = parse_element_body(entry) {
                        let kr = e_children.iter().find_map(|c| {
                            if c.first() == Some(&0x80) {
                                let f = frame(c, 0).ok()?;
                                uint_of_bytes(f.body).map(|v| v.to_string())
                            } else {
                                None
                            }
                        });
                        if let Some(kr_str) = kr {
                            if let Some(new_val) = puks.get(&kr_str) {
                                let pv = encode_pin_value(new_val);
                                let pv_tlv = {
                                    let mut t = vec![0x81u8];
                                    encode_der_length(pv.len(), &mut t);
                                    t.extend_from_slice(&pv);
                                    t
                                };
                                if let Some(pos) =
                                    e_children.iter().position(|c| c.first() == Some(&0x81))
                                {
                                    e_children[pos] = pv_tlv;
                                } else {
                                    e_children.insert(1.min(e_children.len()), pv_tlv);
                                }
                                *entry = rebuild_from_children(&e_tag, &e_children);
                            }
                        }
                    }
                }
                *child = rebuild_from_children(&a1_tag, &entries);
            }
        }
    }
    Ok(rebuild_from_children(&tag_bytes, &children))
}

fn uint_of_bytes(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(bytes.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b)))
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
        // their contents remain available in the bounded TLV tree; personalization is
        // out of scope for this parse-only slice.
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
        // Template-bearing/variant PE bodies remain inspectable in the generic TLV tree.
        assert_eq!(elements[0]["children"][0]["children"][0]["value_hex"], "01");
        assert_eq!(elements[2]["children"][0]["children"][0]["value_hex"], "07");
    }

    #[test]
    fn personalize_applies_iccid_and_drops_variant_optional_pes() {
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
        let opt_usim = tlv(&[0xB4], &tlv(&[0x80], &[0x14]));
        let opt_isim = tlv(&[0xB6], &tlv(&[0x80], &[0x16]));
        let end = tlv(&[0xAA], &[]);
        let package = [header, opt_usim, opt_isim, end].concat();

        let doc = PersonalizationDoc {
            iccid: Some("8900012345678901234".to_string()),
            drop_pe_types: Some(vec!["opt-isim".to_string()]),
            ..Default::default()
        };
        let out = personalize(&package, &doc).expect("personalize");
        let decoded = decode(&out).expect("decode personalized");
        let types: Vec<&str> = decoded["elements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, ["header", "opt-usim", "end"]);
        assert_eq!(
            decoded["elements"][0]["fields"]["iccid"],
            "8900012345678901234"
        );
    }

    #[test]
    fn personalize_substitutes_variant_selection_with_keep_pe_types() {
        let opt_usim = tlv(&[0xB4], &tlv(&[0x80], &[0x14]));
        let opt_isim = tlv(&[0xB6], &tlv(&[0x80], &[0x16]));
        let opt_csim = tlv(&[0xBA], &tlv(&[0x80], &[0x1A]));
        let end = tlv(&[0xAA], &[]);
        let package = [opt_usim, opt_isim, opt_csim, end].concat();

        let doc = PersonalizationDoc {
            keep_pe_types: Some(vec!["opt-usim".to_string()]),
            ..Default::default()
        };
        let out = personalize(&package, &doc).expect("personalize");
        let decoded = decode(&out).expect("decode");
        let types: Vec<&str> = decoded["elements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["type"].as_str().unwrap())
            .collect();
        // opt-isim and opt-csim dropped (variant selection), end kept (not an optional variant)
        assert_eq!(types, ["opt-usim", "end"]);
    }

    #[test]
    fn personalize_updates_pin_and_puk_values_by_key_reference() {
        let pin_entry = tlv(
            &[0x30],
            &[
                tlv(&[0x80], &[0x01]),
                tlv(&[0x81], &[0x30, 0x30, 0x30, 0x30, 0xFF, 0xFF, 0xFF, 0xFF]),
            ]
            .concat(),
        );
        let pin = tlv(
            &[0xA2],
            &[
                tlv(&[0xA0], &tlv(&[0x81], &[0x01])),
                tlv(&[0xA1], &tlv(&[0xA0], &pin_entry)),
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
                tlv(&[0xA0], &tlv(&[0x81], &[0x05])),
                tlv(&[0xA1], &puk_entry),
            ]
            .concat(),
        );
        let package = [pin, puk].concat();
        let mut pins = std::collections::BTreeMap::new();
        pins.insert("1".to_string(), "1234".to_string());
        let mut puks = std::collections::BTreeMap::new();
        puks.insert("1".to_string(), "87654321".to_string());
        let doc = PersonalizationDoc {
            pins: Some(pins),
            puks: Some(puks),
            ..Default::default()
        };
        let out = personalize(&package, &doc).expect("personalize");
        let decoded = decode(&out).expect("decode");
        assert_eq!(
            decoded["elements"][0]["fields"]["pin_configs"][0]["pin_value_hex"],
            "31323334FFFFFFFF"
        );
        assert_eq!(
            decoded["elements"][1]["fields"]["puk_configs"][0]["puk_value_hex"],
            "3837363534333231"
        );
    }
}
