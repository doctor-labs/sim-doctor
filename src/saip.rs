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
        // Only a known, non-reserved, constructed alternative is expanded. Anything else is
        // skipped by its length: its body is not parsed, so its bytes cannot fail the decode.
        let known = match framed.tag.constructed {
            true => PE_TYPES.get(framed.tag.number as usize).copied(),
            false => None,
        }
        .filter(|name| !name.starts_with("rfu"));
        let used = framed.used;
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
                "raw_hex": hex::encode_upper(&bytes[offset..offset + used]),
            }),
        };
        elements.push(element);
        offset += used;
    }
    Ok(json!({ "pe_count": elements.len(), "elements": elements }))
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
}
