//! Field decoders shared by the EF table (`names.rs`): the building blocks TS 31.102 / 51.011 files are
//! made of. Each takes the bytes of one record (or of a transparent file) and returns JSON; none panics
//! on short or hostile input.

use serde_json::{json, Value};

use crate::cardsh::hex_upper;
use crate::ef::{self, Ef};

/// The GSM 7-bit default alphabet (3GPP TS 23.038), one character per octet as SIM files store it.
/// Octets above 0x7F and the escape table are shown as `?`; the extension table is not used by SIM
/// alpha fields in practice.
const GSM7: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\u{1b}ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

/// An alpha identifier or text field: GSM 7-bit, or UCS2 when the first octet is 80, 81 or 82
/// (TS 51.011 annex B). Trailing `FF` padding is dropped.
pub fn alpha(bytes: &[u8]) -> String {
    let end = bytes.iter().rposition(|b| *b != 0xFF).map_or(0, |p| p + 1);
    let b = &bytes[..end];
    match b.first() {
        Some(0x80) => ucs2(
            b[1..]
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])),
        ),
        Some(0x81) if b.len() >= 3 => {
            let (n, base) = (usize::from(b[1]).min(b.len() - 3), u16::from(b[2]) << 7);
            ucs2(b[3..3 + n].iter().map(|c| {
                if c & 0x80 != 0 {
                    base + u16::from(c & 0x7F)
                } else {
                    u16::from(*c)
                }
            }))
        }
        Some(0x82) if b.len() >= 4 => {
            let (n, base) = (
                usize::from(b[1]).min(b.len() - 4),
                u16::from_be_bytes([b[2], b[3]]),
            );
            ucs2(b[4..4 + n].iter().map(|c| {
                if c & 0x80 != 0 {
                    base + u16::from(c & 0x7F)
                } else {
                    u16::from(*c)
                }
            }))
        }
        _ => {
            let table: Vec<char> = GSM7.chars().collect();
            b.iter()
                .map(|c| {
                    table
                        .get(usize::from(*c))
                        .copied()
                        .filter(|_| *c < 0x80)
                        .unwrap_or('?')
                })
                .collect()
        }
    }
}

fn ucs2(units: impl Iterator<Item = u16>) -> String {
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('?'))
        .collect()
}

/// Swapped-nibble BCD digits (`0-9`, `*`, `#`, `a b c` for A-C) up to the `F` filler.
pub fn bcd(bytes: &[u8]) -> String {
    let mut out = String::new();
    'octets: for b in bytes {
        for n in [b & 0x0F, b >> 4] {
            match n {
                0..=9 => out.push(char::from(b'0' + n)),
                0xA => out.push('*'),
                0xB => out.push('#'),
                0xC => out.push('p'),
                0xD => out.push('w'),
                0xE => out.push('e'),
                _ => break 'octets,
            }
        }
    }
    out
}

/// A dialling number: length octet (bytes of TON/NPI + digits), TON/NPI, digits (TS 51.011 10.5.1).
pub fn dialling(bytes: &[u8]) -> Value {
    match bytes {
        [len, ton, rest @ ..] if *len != 0xFF && *len > 0 => {
            let digits = &rest[..rest.len().min(usize::from(*len).saturating_sub(1))];
            let number = bcd(digits);
            let number = if ton & 0x70 == 0x10 {
                format!("+{number}")
            } else {
                number
            };
            json!({ "ton_npi": format!("{ton:02X}"), "number": number })
        }
        _ => Value::Null,
    }
}

/// Big-endian unsigned integer of up to 8 octets.
pub fn uint(bytes: &[u8]) -> Value {
    if bytes.len() > 8 {
        return json!(hex_upper(bytes));
    }
    json!(bytes.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

/// The 1-based numbers of the set bits, service-table style (bit 1 of octet 1 is service 1).
pub fn bitmap(bytes: &[u8]) -> Vec<u32> {
    bytes
        .iter()
        .enumerate()
        .flat_map(|(i, b)| {
            (0..8)
                .filter(move |k| b >> k & 1 == 1)
                .map(move |k| (i * 8 + k + 1) as u32)
        })
        .collect()
}

/// A 3-octet PLMN (TS 24.008 10.5.1.13), `None` when unused (`FFFFFF`).
pub fn plmn(b: &[u8]) -> Option<String> {
    let [a, b2, c] = <[u8; 3]>::try_from(b.get(..3)?).ok()?;
    if [a, b2, c] == [0xFF; 3] {
        return None;
    }
    let (mcc, mnc3) = (format!("{}{}{}", a & 0x0F, a >> 4, b2 & 0x0F), b2 >> 4);
    let mnc = format!(
        "{}{}{}",
        c & 0x0F,
        c >> 4,
        if mnc3 == 0xF {
            String::new()
        } else {
            mnc3.to_string()
        }
    );
    Some(format!("{mcc}{mnc}"))
}

/// A BER-TLV object tree. Constructed objects (tag bit 6) recurse up to `depth`.
pub fn tlv(bytes: &[u8], depth: u8) -> Value {
    let mut stream = crate::tlv::Stream::new(bytes);
    let mut out = Vec::new();
    loop {
        match stream.next_atom() {
            Ok(Some(atom)) => {
                let tag = atom.tag().to_string();
                let value = atom.value();
                if atom.is_constructed() && depth > 0 {
                    out.push(json!({ "tag": tag, "children": tlv(value, depth - 1) }));
                } else {
                    out.push(json!({ "tag": tag, "value": hex_upper(value) }));
                }
            }
            Ok(None) => break,
            Err(e) => {
                out.push(json!({ "error": e.to_string() }));
                break;
            }
        }
    }
    Value::Array(out)
}

fn lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn per_record(records: &[Vec<u8>], f: impl Fn(&[u8]) -> Value) -> Value {
    json!({ "records": records.iter().enumerate().map(|(i, r)| {
        let mut v = f(r);
        if let Some(o) = v.as_object_mut() {
            o.insert("record".into(), json!(i + 1));
            o.insert("empty".into(), json!(!r.is_empty() && r.iter().all(|b| *b == 0xFF)));
        }
        v
    }).collect::<Vec<_>>() })
}

/// The `ef` decoder a kind and file name stand for, when `crate::ef` already has one.
fn ef_for(kind: &str, name: &str) -> Option<Ef> {
    let n = name.to_ascii_uppercase();
    Some(match (kind, n.as_str()) {
        ("iccid", _) => Ef::Iccid,
        ("imsi", "EF.IMSI") => Ef::Imsi,
        ("ad", _) => Ef::Ad,
        ("spn", "EF.SPN") => Ef::Spn,
        ("acc", _) => Ef::Acc,
        ("loci", "EF.LOCI" | "EF.LOCIGPRS") => Ef::Loci,
        ("loci", "EF.PSLOCI") => Ef::Psloci,
        ("loci", "EF.EPSLOCI") => Ef::Epsloci,
        ("plmn-list", "EF.FPLMN") => Ef::Fplmn,
        ("plmn-act", "EF.OPLMNWACT") => Ef::OplmnWact,
        ("plmn-act", "EF.HPLMNWACT") => Ef::HplmnWact,
        ("suci", _) => Ef::SuciCalcInfo,
        ("routing-ind", _) => Ef::RoutingIndicator,
        ("impi", _) => Ef::Impi,
        ("impu", _) => Ef::Impu,
        ("pcscf", _) => Ef::Pcscf,
        // 5G ProSe config EFs (TS 31.102 clause 4.4.13.x): transparent files
        // carrying a tag-A0-rooted TLV tree decoded by `ef::decode_prose_config`.
        ("tlv", "EF.5G_PROSE_DD") => Ef::ProseDd,
        ("tlv", "EF.5G_PROSE_DC") => Ef::ProseDc,
        ("tlv", "EF.5G_PROSE_U2NRU") => Ef::ProseU2nru,
        ("tlv", "EF.5G_PROSE_RU") => Ef::ProseRu,
        ("tlv", "EF.5G_PROSE_UIR") => Ef::ProseUir,
        ("tlv", "EF.5G_PROSE_U2URU") => Ef::ProseU2uru,
        ("tlv", "EF.5G_PROSE_EU") => Ef::ProseEu,
        // DF.ProSe files (TS 31.102 clause 4.4.8): read as raw records/bytes.
        ("hex", "EF.PROSE_MON") => Ef::ProseMon,
        ("hex", "EF.PROSE_RADIO_COM") => Ef::ProseRadioCom,
        _ => return None,
    })
}

/// How a service-table EF is named: the UST, EST, IST and SST have the names
/// `crate::ef` carries.
pub fn service_table(name: &str) -> Option<ef::Table> {
    match name.to_ascii_uppercase().as_str() {
        "EF.UST" => Some(ef::Table::Ust),
        "EF.EST" => Some(ef::Table::Est),
        "EF.IST" => Some(ef::Table::Ist),
        "EF.SST" => Some(ef::Table::Sst),
        "EF.5G_PROSE_ST" => Some(ef::Table::Prose),
        _ => None,
    }
}

/// Decode a TS 24.008 / TS 31.102 network name value (coding octet + text bytes).
/// Scheme 0 (coding octet bits 7-5 == 0) is GSM 7-bit default alphabet; scheme 1 is UCS-2 big-endian.
/// Returns `None` when the coding scheme is unrecognised or the bytes are empty/just padding.
fn network_name(v: &[u8]) -> Option<String> {
    if v.is_empty() {
        return None;
    }
    let scheme = (v[0] >> 4) & 0x07;
    let text = &v[1..];
    let spare = usize::from(v[0] & 0x07);
    match scheme {
        0 => {
            // GSM 7-bit: septet count = (text_len * 8 - spare) / 7
            if text.is_empty() {
                return None;
            }
            let text_len = text.len();
            let count = (text_len as u32 * 8 - spare as u32) / 7;
            Some(crate::sms::unpack_gsm7(text, 0, count))
        }
        1 => {
            // UCS2 big-endian: decode the whole buffer so surrogate pairs survive
            let units: Vec<u16> = text
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

/// One EF.ARR record: TS 102 221 9.2.4 expanded format. Each rule is an AM_DO (80) access-mode byte
/// followed by its SC_DO (90/97/A4/A0/AF) condition. Walk TLVs, stop at 0xFF or the end, bounds-check.
fn arr_record(r: &[u8]) -> Value {
    let mut rules = Vec::new();
    let mut pos = 0;
    while pos + 1 < r.len() && r[pos] != 0xFF {
        if r[pos] != 0x80 {
            // Not an AM_DO: not a rule start; skip this octet.
            pos += 1;
            continue;
        }
        let len = usize::from(r[pos + 1]);
        let Some(am) = r.get(pos + 2..).and_then(|s| s.first().copied()) else {
            break;
        };
        let operations: Vec<String> = if len != 1 || am & 0x80 != 0 {
            vec![format!("proprietary:{am:02X}")]
        } else {
            let names = [
                (0x01, "read"),
                (0x02, "update"),
                (0x04, "write"),
                (0x08, "deactivate"),
                (0x10, "activate"),
                (0x20, "terminate"),
                (0x40, "delete"),
            ];
            names
                .iter()
                .filter_map(|(bit, name)| {
                    if am & bit != 0 {
                        Some((*name).to_string())
                    } else {
                        None
                    }
                })
                .collect()
        };
        // Condition: the SC_DO that follows the AM_DO, if present.
        let (cond, advanced) = arr_condition(r, pos + 2 + len);
        let condition = if advanced {
            cond
        } else {
            "unknown".to_string()
        };
        rules.push(json!({ "operations": operations, "condition": condition }));
        if advanced {
            pos = arr_advance_past_sc_do(r, pos + 2 + len);
        } else {
            pos += 2 + len.max(1);
        }
    }
    json!({ "rules": rules })
}
/// Parse one SC_DO (starting at `start`) and return (condition_string, is_sc_do).
/// `is_sc_do` is false when the byte at `start` is not a recognised SC_DO tag, signalling the caller
/// to advance only past the AM_DO.
fn arr_condition(r: &[u8], start: usize) -> (String, bool) {
    let Some(&tag) = r.get(start) else {
        return ("unknown".to_string(), false);
    };
    let Some(&len) = r.get(start + 1) else {
        return ("unknown".to_string(), false);
    };
    match tag {
        0x90 => (String::from("always"), true),
        0x97 => (String::from("never"), true),
        0xA4 => {
            // Control reference template: find 83 01 <key ref> inside it.
            let inner = match r.get(start + 2..start + 2 + usize::from(len)) {
                Some(v) => v,
                None => return ("unknown".to_string(), true),
            };
            let mut key = None;
            let mut i = 0;
            while i + 1 < inner.len() {
                let t = inner[i];
                let l = usize::from(inner[i + 1]);
                if t == 0x83 && l == 1 {
                    key = inner.get(i + 2).copied();
                    break;
                }
                // Ignore 0x95 usage qualifier and unknown tags: skip them.
                i += 2 + l;
            }
            let name = match key {
                Some(k) if (0x01..=0x08).contains(&k) => format!("PIN{}", k),
                Some(k) if (0x0A..=0x0E).contains(&k) => format!("ADM{}", k - 0x09),
                Some(0x11) => "universal PIN".to_string(),
                Some(k) if (0x81..=0x88).contains(&k) => format!("second PIN{}", k - 0x80),
                Some(k) => format!("key {k:02X}"),
                None => "unknown".to_string(),
            };
            (name, true)
        }
        0xA0 | 0xAF => {
            // OR template / AND template: join the 0xA4 conditions inside.
            let inner = match r.get(start + 2..start + 2 + usize::from(len)) {
                Some(v) => v,
                None => return ("unknown".to_string(), true),
            };
            let sep = if tag == 0xA0 { " or " } else { " and " };
            let mut parts = Vec::new();
            let mut i = 0;
            while i + 1 < inner.len() {
                let t = inner[i];
                let l = usize::from(inner[i + 1]);
                if t == 0xA4 {
                    let (c, _) = arr_condition(inner, i);
                    parts.push(c);
                }
                i += 2 + l;
            }
            (parts.join(sep), true)
        }
        _ => ("unknown".to_string(), false),
    }
}
/// Advance `pos` past an SC_DO at `start` (already positioned at its tag byte).
fn arr_advance_past_sc_do(r: &[u8], start: usize) -> usize {
    let Some(&len) = r.get(start + 1) else {
        return start;
    };
    start + 2 + usize::from(len)
}

/// One EF.EXT record (TS 31.102 4.4.2.4): a 13-byte record split as record type (byte 0),
/// 11 data bytes (bytes 1..12) and a next-extension-record id (byte 12). Type 0x01 is a
/// subaddress (data[0] length, then that many bytes as lowercase hex), 0x02 is additional
/// dialling data (data[0] BCD-digit count, then that many swapped-BCD octets), anything
/// else (0x00, 0xFF, ...) is unused. Everything is bounds-checked so short records decode
/// what they can and never panic.
fn ext_record(r: &[u8]) -> Value {
    let rtype = r.first().copied();
    let next = r.get(12).copied().filter(|&b| b != 0xFF).map(|b| json!(b));
    match rtype {
        Some(0x01) => {
            let len = usize::from(r.get(1).copied().unwrap_or(0)).min(11); // the data field is 11 bytes
            let sa = r.get(2..2 + len).unwrap_or(&[]);
            json!({ "type": "subaddress", "subaddress": lower(sa), "next": next })
        }
        Some(0x02) => {
            let len = usize::from(r.get(1).copied().unwrap_or(0)).min(11); // the data field is 11 bytes
            let digits = bcd(r.get(2..2 + len).unwrap_or(&[]));
            json!({ "type": "additional data", "digits": digits, "next": next })
        }
        _ => json!({ "type": Value::Null, "next": next }),
    }
}

/// One EF.PNN record: TLVs (0x43 full name, 0x45 short name) until 0xFF padding or the end.
fn pnn_record(r: &[u8]) -> Value {
    let (mut full_name, mut short_name) = (None, None);
    let mut pos = 0;
    while pos + 1 < r.len() && r[pos] != 0xFF {
        let (tag, len) = (r[pos], usize::from(r[pos + 1]));
        let Some(value) = r.get(pos + 2..pos + 2 + len) else {
            break;
        };
        match tag {
            0x43 => full_name = network_name(value),
            0x45 => short_name = network_name(value),
            _ => {}
        }
        pos += 2 + len;
    }
    json!({ "full_name": full_name, "short_name": short_name })
}

/// One EF.MWIS record (TS 31.102 4.2.63): status bits (b1 voicemail, b2 fax, b3 e-mail, b4 other,
/// b5 videomail) then one count byte each (videomail count optional).
fn mwis_record(r: &[u8]) -> Value {
    let status = r.first().copied().unwrap_or(0);
    let waiting = |bit| (status >> bit) & 1u8 != 0u8;
    let count = |i| r.get(i).map(|b| json!(b));
    let mut out = json!({
        "voicemail": json!({ "waiting": waiting(0), "count": count(1) }),
        "fax": json!({ "waiting": waiting(1), "count": count(2) }),
        "email": json!({ "waiting": waiting(2), "count": count(3) }),
        "other": json!({ "waiting": waiting(3), "count": count(4) }),
    });
    if waiting(4) || r.get(5).is_some() {
        out["videomail"] = json!({ "waiting": waiting(4), "count": count(5) });
    }
    out
}

/// One EF.MBI record (4.2.62): the EF.MBDN record number for each message waiting type, 0 = none.
fn mbi_record(r: &[u8]) -> Value {
    let rec = |i| {
        r.get(i)
            .and_then(|&b| if b == 0 { None } else { Some(json!(b)) })
    };
    let mut out = json!({ "voicemail": rec(0), "fax": rec(1), "email": rec(2), "other": rec(3) });
    if let Some(b) = r.get(4) {
        out["videomail"] = if *b == 0 { Value::Null } else { json!(b) };
    }
    out
}

/// One EF.CFIS record (4.2.64): MSP id, CFU status bits, then a dialling number with CCP2/EXT7 tails.
fn cfis_record(r: &[u8]) -> Value {
    let d = dialling(r.get(2..).unwrap_or(&[]));
    json!({
        "msp": r.first(),
        "voice_forwarding": r.get(1).map(|b| b & 1 != 0).unwrap_or(false),
        "fax_forwarding": r.get(1).map(|b| b & 2 != 0).unwrap_or(false),
        "data_forwarding": r.get(1).map(|b| b & 4 != 0).unwrap_or(false),
        "sms_forwarding": r.get(1).map(|b| b & 8 != 0).unwrap_or(false),
        "all_forwarding": r.get(1).map(|b| b & 0x10 != 0).unwrap_or(false),
        "number": d.get("number"),
    })
}

/// One EF.SMSR record (4.2.28): the EF.SMS record id (0 = empty) then the status-report TPDU.
fn smsr_record(r: &[u8]) -> Value {
    let sms_record = r
        .first()
        .and_then(|&b| if b == 0 { None } else { Some(json!(b)) });
    json!({
        "sms_record": sms_record,
        "tpdu": lower(r.get(1..).unwrap_or(&[])),
    })
}

/// Decodes the content of one standard EF. `kind` is the table's decoder name, `name` the file name
/// and `records` the content (one element for a transparent file). The result is the typed fields;
/// a file that does not parse comes back as `{"error", "hex"}` and never as an empty success.
pub fn decode_ef(kind: &str, name: &str, records: &[Vec<u8>]) -> Value {
    let first = records.first().map_or(&[][..], Vec::as_slice);
    let raw = || json!({ "hex": lower(first) });
    let fail = |why: &str| json!({ "error": why, "hex": records.iter().map(|r| lower(r)).collect::<Vec<_>>().join(" ") });
    if let Some(e) = ef_for(kind, name) {
        return match ef::decode(e, records, None) {
            Ok(d) => d.fields(),
            Err(m) => fail(&m.to_string()),
        };
    }
    match kind {
        "services" => match service_table(name) {
            Some(ef::Table::Sst) => {
                let (allocated, activated) = ef::decode_sst(first);
                let services: Vec<Value> = allocated
                    .iter()
                    .map(|n| {
                        let alloc = true;
                        let act = activated.contains(n);
                        json!({
                            "service": n,
                            "name": ef::sst_service_name(*n),
                            "allocated": alloc,
                            "activated": act,
                        })
                    })
                    .collect();
                let enabled: Vec<u16> = allocated
                    .iter()
                    .copied()
                    .filter(|n| activated.contains(n))
                    .collect();
                json!({
                    "allocated": allocated,
                    "activated": activated,
                    "enabled": enabled,
                    "services": services,
                })
            }
            Some(table) => {
                let on = bitmap(first);
                let named: Vec<Value> = on
                    .iter()
                    .map(|n| json!({ "service": n, "name": ef::service_name(table, *n as u16) }))
                    .collect();
                json!({ "enabled": on, "services": named })
            }
            None => {
                let on = bitmap(first);
                let named: Vec<Value> = on
                    .iter()
                    .map(|n| json!({ "service": n, "name": Value::Null }))
                    .collect();
                json!({ "enabled": on, "services": named })
            }
        },
        "uint" => json!({ "value": uint(first), "hex": lower(first) }),
        "plmn-list" => {
            json!({ "plmns": first.chunks_exact(3).filter_map(plmn).collect::<Vec<_>>() })
        }
        "plmn-act" => match ef::decode_plmn_list(first, 5) {
            Ok(list) => json!({ "plmns": list.iter().map(|e| json!({
                "plmn": format!("{}{}", e.plmn.mcc, e.plmn.mnc),
                "act": e.act_names(),
            })).collect::<Vec<_>>() }),
            Err(m) => fail(&m.to_string()),
        },
        "adn" => per_record(records, |r| {
            let n = r.len().saturating_sub(14);
            let (alpha_b, num) = r.split_at(n.min(r.len()));
            // ext identifier and capability id are the last two octets; dialling number is the 12 before.
            let d = num.get(..12).map_or(Value::Null, dialling);
            json!({ "alpha": alpha(alpha_b), "number": d.get("number"), "ton_npi": d.get("ton_npi"),
                    "capability": num.get(12).map(|b| format!("{b:02X}")), "ext": num.get(13).map(|b| format!("{b:02X}")) })
        }),
        "sms" => per_record(records, |r| {
            let status = r.first().copied().unwrap_or(0);
            json!({ "status": match status & 7 { 0 => "free", 1 => "received-read", 3 => "received-unread", 5 => "sent", 7 => "to-be-sent", _ => "reserved" },
                    "pdu": lower(r.get(1..).unwrap_or(&[])) })
        }),
        "smsp" => per_record(records, |r| {
            let n = r.len().saturating_sub(28);
            let p = &r[n.min(r.len())..];
            let ind = p.first().copied().unwrap_or(0xFF);
            let addr = |b: Option<&[u8]>| b.map_or(Value::Null, dialling);
            json!({ "alpha": alpha(&r[..n.min(r.len())]), "indicators": format!("{ind:02X}"),
                    "destination": if ind & 1 == 0 { addr(p.get(1..13)) } else { Value::Null },
                    "service_centre": if ind & 2 == 0 { addr(p.get(13..25)) } else { Value::Null },
                    "pid": p.get(25).map(|b| format!("{b:02X}")), "dcs": p.get(26).map(|b| format!("{b:02X}")),
                    "validity": p.get(27).map(|b| format!("{b:02X}")) })
        }),
        "smss" => {
            json!({ "last_tp_mr": first.first(), "memory_capacity_exceeded": first.get(1).map(|b| b & 1 == 0) })
        }
        "alpha-list" => {
            json!({ "languages": first.chunks_exact(2).filter(|c| c[0] != 0xFF).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>() })
        }
        "spn" => {
            json!({ "display_condition": first.first().map(|b| format!("{b:02X}")), "name": alpha(first.get(1..).unwrap_or(&[])) })
        }
        "ecc" => per_record(records, |r| {
            let n = bcd(r.get(..3).unwrap_or(&[]));
            json!({ "number": n, "alpha": alpha(r.get(3..r.len().saturating_sub(1)).unwrap_or(&[])), "category": r.last().map(|b| format!("{b:02X}")) })
        }),
        "cbmi" => {
            json!({ "ids": first.chunks_exact(2).filter(|c| c[..] != [0xFF, 0xFF]).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>() })
        }
        "opl" => per_record(
            records,
            |r| json!({ "plmn": r.get(..3).and_then(plmn), "lac_min": r.get(3..5).map(lower), "lac_max": r.get(5..7).map(lower), "pnn_record": r.get(7) }),
        ),
        "arr" => {
            if records.len() > 1 {
                per_record(records, arr_record)
            } else {
                arr_record(first)
            }
        }
        "pnn" => {
            if records.len() > 1 {
                per_record(records, pnn_record)
            } else {
                pnn_record(first)
            }
        }
        "ext" => {
            if records.len() > 1 {
                per_record(records, ext_record)
            } else {
                ext_record(first)
            }
        }
        "mwis" => {
            if records.len() > 1 {
                per_record(records, mwis_record)
            } else {
                mwis_record(first)
            }
        }
        "mbi" => {
            if records.len() > 1 {
                per_record(records, mbi_record)
            } else {
                mbi_record(first)
            }
        }
        "cfis" => {
            if records.len() > 1 {
                per_record(records, cfis_record)
            } else {
                cfis_record(first)
            }
        }
        "smsr" => {
            if records.len() > 1 {
                per_record(records, smsr_record)
            } else {
                smsr_record(first)
            }
        }
        "uri" => {
            let t = tlv(first, 0);
            json!({ "value": t[0]["value"].as_str().and_then(|h| hex::decode(h).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()), "tlv": t })
        }
        "acl" => json!({ "count": first.first(), "tlv": tlv(first.get(1..).unwrap_or(&[]), 0) }),
        "tlv" => {
            if records.len() > 1 {
                per_record(records, |r| json!({ "tlv": tlv(r, 4) }))
            } else {
                json!({ "tlv": tlv(first, 4) })
            }
        }
        _ if records.len() > 1 => per_record(records, |r| json!({ "hex": lower(r) })),
        _ => raw(),
    }
}

/// Whether [`decode_ef`] gives a kind more than the hex of its content.
pub fn is_structured(kind: &str) -> bool {
    kind != "hex"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_reads_gsm7_and_ucs2() {
        assert_eq!(alpha(&[b'A', b'n', b'n', 0xFF, 0xFF]), "Ann");
        assert_eq!(alpha(&[0x00, 0x02]), "@$");
        assert_eq!(alpha(&[0x80, 0x00, 0x48, 0x00, 0x69, 0xFF]), "Hi");
        assert_eq!(alpha(&[0x81, 0x02, 0x08, b'A', 0x81]), "A\u{0401}");
        assert_eq!(alpha(&[0xFF, 0xFF]), "");
    }

    #[test]
    fn ext_records_decode_additional_digits_and_the_chain() {
        // TS 31.102 4.4.2.4: record type (01 subaddress, 02 additional data), 11 data bytes, next record id (FF = none).
        // Additional data: length of the BCD digits, then swapped BCD (F filler): 21 43 F5 = "12345".
        let rec = vec![
            0x02, 0x03, 0x21, 0x43, 0xF5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x05,
        ];
        let v = decode_ef("ext", "EF.EXT1", &[rec]);
        assert_eq!(v["type"], "additional data", "{v}");
        assert_eq!(v["digits"], "12345", "{v}");
        assert_eq!(v["next"], 5, "{v}");
        // a subaddress keeps its bytes as hex; no next record
        let sub = decode_ef(
            "ext",
            "EF.EXT1",
            &[vec![
                0x01, 0x02, 0xA0, 0x50, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ]],
        );
        assert_eq!(sub["type"], "subaddress", "{sub}");
        assert_eq!(sub["subaddress"], "a050", "{sub}");
        assert!(sub["next"].is_null(), "{sub}");
        // an unused record (type 00 or FF) has no type
        assert!(decode_ef("ext", "EF.EXT1", &[vec![0xFF; 13]])["type"].is_null());
    }

    #[test]
    fn arr_truncated_records_never_panic() {
        let rec = [
            0x80, 0x01, 0x02, 0xA4, 0x06, 0x83, 0x01, 0x0A, 0x95, 0x01, 0x08, 0xAF, 0x05, 0xA4,
            0x03, 0x83, 0x01,
        ];
        for n in 0..=rec.len() {
            let _ = decode_ef("arr", "EF.ARR", &[rec[..n].to_vec()]);
        }
    }

    #[test]
    fn arr_records_decode_access_rules() {
        // TS 102 221 9.2.4 expanded format: 80 AM_DO (ISO 7816-4 access-mode byte for an EF:
        // b1 read, b2 update, b3 write, b4 deactivate, b5 activate, b6 terminate, b7 delete), followed by its SC_DO:
        // 90 00 = always, 97 00 = never, A4 = control reference template with 83 01 <key ref> (01-08 PIN1-8, 0A-0E ADM1-5, 11 universal PIN).
        let rec = vec![
            0x80, 0x01, 0x01, 0x90, 0x00, // read: always
            0x80, 0x01, 0x02, 0xA4, 0x06, 0x83, 0x01, 0x0A, 0x95, 0x01, 0x08, // update: ADM1
            0x80, 0x01, 0x18, 0x97, 0x00, // deactivate + activate: never
            0xFF, 0xFF,
        ];
        let v = decode_ef("arr", "EF.ARR", &[rec]);
        let rules = v["rules"].as_array().unwrap_or_else(|| panic!("{v}"));
        assert_eq!(rules.len(), 3, "{v}");
        assert_eq!(rules[0]["operations"], serde_json::json!(["read"]));
        assert_eq!(rules[0]["condition"], "always");
        assert_eq!(rules[1]["operations"], serde_json::json!(["update"]));
        assert_eq!(rules[1]["condition"], "ADM1");
        assert_eq!(
            rules[2]["operations"],
            serde_json::json!(["deactivate", "activate"])
        );
        assert_eq!(rules[2]["condition"], "never");
        // an unused record has no rules
        assert_eq!(
            decode_ef("arr", "EF.ARR", &[vec![0xFF; 6]])["rules"],
            serde_json::json!([])
        );
    }

    #[test]
    fn sms_related_efs_decode_mwis_mbi_cfis_smsr() {
        // EF.MWIS (TS 31.102 4.2.63): status bits (b1 voicemail, b2 fax, b3 e-mail, b4 other, b5 videomail), then counts.
        let mwis = decode_ef("mwis", "EF.MWIS", &[vec![0x01, 0x03, 0x00, 0x00, 0x00]]);
        assert_eq!(mwis["voicemail"]["waiting"], true, "{mwis}");
        assert_eq!(mwis["voicemail"]["count"], 3, "{mwis}");
        assert_eq!(mwis["fax"]["waiting"], false, "{mwis}");
        // EF.MBI (4.2.62): mailbox dialling-number record ids, 0 = none.
        let mbi = decode_ef("mbi", "EF.MBI", &[vec![0x01, 0x00, 0x00, 0x00]]);
        assert_eq!(mbi["voicemail"], 1, "{mbi}");
        assert!(mbi["fax"].is_null(), "{mbi}");
        // EF.CFIS (4.2.64): MSP, CFU status (b1 voice), BCD length incl. TON/NPI, TON/NPI, 10 BCD octets, CCP2, EXT7.
        let cfis = decode_ef(
            "cfis",
            "EF.CFIS",
            &[vec![
                0x01, 0x01, 0x06, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ]],
        );
        assert_eq!(cfis["msp"], 1, "{cfis}");
        assert_eq!(cfis["voice_forwarding"], true, "{cfis}");
        assert_eq!(cfis["number"], "+1234567890", "{cfis}");
        // EF.SMSR (4.2.28): the EF.SMS record it belongs to, then the status-report TPDU (kept as hex). 0 = empty.
        let smsr = decode_ef("smsr", "EF.SMSR", &[vec![0x02, 0x06, 0x01, 0xFF]]);
        assert_eq!(smsr["sms_record"], 2, "{smsr}");
        assert_eq!(smsr["tpdu"], "0601ff", "{smsr}");
        assert!(decode_ef("smsr", "EF.SMSR", &[vec![0x00, 0xFF, 0xFF]])["sms_record"].is_null());
    }

    #[test]
    fn pnn_network_names_decode_gsm7_and_ucs2() {
        // TS 24.008 network name: coding octet (ext bit, scheme in bits 7-5, spare bits in the last octet in bits 3-1), then text.
        // "Jio" packed GSM 7-bit = CA F4 1B with 3 spare bits -> coding 0x83. Full name tag 0x43, short name tag 0x45.
        let rec = vec![
            0x43, 0x04, 0x83, 0xCA, 0xF4, 0x1B, 0x45, 0x04, 0x83, 0xCA, 0xF4, 0x1B, 0xFF, 0xFF,
        ];
        let v = decode_ef("pnn", "EF.PNN", &[rec]);
        assert_eq!(v["full_name"], "Jio", "{v}");
        assert_eq!(v["short_name"], "Jio", "{v}");
        // UCS2 (scheme 001 -> coding 0x90): "Hi"
        let ucs2 = vec![0x43, 0x05, 0x90, 0x00, 0x48, 0x00, 0x69, 0xFF];
        assert_eq!(decode_ef("pnn", "EF.PNN", &[ucs2])["full_name"], "Hi");
        // an unused record decodes to no names, not an error
        let empty = decode_ef("pnn", "EF.PNN", &[vec![0xFF; 8]]);
        assert!(
            empty.get("error").is_none() && empty["full_name"].is_null(),
            "{empty}"
        );
    }

    #[test]
    fn digits_numbers_and_plmns() {
        assert_eq!(bcd(&[0x21, 0x43, 0xF5]), "12345");
        assert_eq!(bcd(&[0xA1, 0xB2, 0xFF]), "1*2#");
        let n = dialling(&[0x07, 0x91, 0x10, 0x32, 0x54, 0x76, 0x98, 0xFF]);
        assert_eq!(n["number"], "+0123456789");
        assert_eq!(dialling(&[0xFF, 0xFF]), Value::Null);
        assert_eq!(plmn(&[0x00, 0xF1, 0x10]).as_deref(), Some("00101"));
        assert_eq!(plmn(&[0x62, 0xF2, 0x10]).as_deref(), Some("26201"));
        assert_eq!(plmn(&[0xFF, 0xFF, 0xFF]), None);
        assert_eq!(uint(&[0x01, 0x00]), 256);
        assert_eq!(bitmap(&[0b0000_0101, 0b1000_0000]), vec![1, 3, 16]);
    }

    #[test]
    fn tlv_trees_nest() {
        let v = tlv(&[0xA0, 0x03, 0x80, 0x01, 0x05, 0x81, 0x00], 3);
        assert_eq!(v[0]["children"][0]["value"], "05");
        assert_eq!(v[1]["value"], "");
        assert!(tlv(&[0x80, 0x05, 0x01], 3)[0]["error"].is_string());
    }

    fn d(kind: &str, name: &str, recs: &[&[u8]]) -> Value {
        decode_ef(
            kind,
            name,
            &recs.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn every_kind_in_the_table_has_a_decoder_and_the_table_is_sound() {
        use crate::cardsh::names;
        let known = [
            "hex",
            "tlv",
            "uint",
            "adn",
            "plmn-act",
            "cbmi",
            "loci",
            "plmn-list",
            "services",
            "ad",
            "sms",
            "smsp",
            "smss",
            "alpha-list",
            "imsi",
            "spn",
            "acc",
            "ecc",
            "opl",
            "pnn",
            "ext",
            "suci",
            "iccid",
            "acl",
            "impi",
            "uri",
            "impu",
            "pcscf",
            "routing-ind",
            "mwis",
            "mbi",
            "cfis",
            "smsr",
            "arr",
        ];
        let mut seen = std::collections::HashSet::new();
        for e in names::all() {
            assert!(
                known.contains(&e.kind),
                "{} has the unknown kind {}",
                e.name,
                e.kind
            );
            assert!(
                seen.insert((e.scope, e.name, e.fid)),
                "{} {} twice",
                e.scope,
                e.name
            );
            assert!(matches!(e.structure, 'T' | 'L' | 'C' | 'B'));
            // No kind falls through to a bare "hex" by accident: a non-hex kind decodes to something typed.
            if e.kind != "hex" {
                let out = decode_ef(e.kind, e.name, &[vec![0xFF; 14]]);
                assert!(
                    out.get("hex").is_none() || out.get("error").is_some() || e.kind == "uint",
                    "{} {out}",
                    e.name
                );
            }
        }
        let distinct: std::collections::HashSet<_> =
            names::all().map(|e| e.name.to_ascii_lowercase()).collect();
        assert!(
            names::all().count() >= 280 && distinct.len() >= 200,
            "{} {}",
            names::all().count(),
            distinct.len()
        );
        // Identifiers the specifications fix (spot checks beyond the pySim cross-check).
        for (scope, name, fid) in [
            ("ADF.USIM", "EF.IMSI", 0x6F07),
            ("ADF.USIM", "EF.UST", 0x6F38),
            ("ADF.USIM", "EF.FPLMN", 0x6F7B),
            ("ADF.USIM", "EF.EPSLOCI", 0x6FE3),
            ("ADF.USIM", "EF.EHPLMN", 0x6FD9),
            ("ADF.ISIM", "EF.IMPI", 0x6F02),
            ("ADF.ISIM", "EF.IST", 0x6F07),
            ("DF.5GS", "EF.SUCI_Calc_Info", 0x4F07),
            ("DF.TELECOM", "EF.MSISDN", 0x6F40),
            ("DF.GSM", "EF.SST", 0x6F38),
            ("MF", "EF.ICCID", 0x2FE2),
        ] {
            assert!(
                names::all().any(|e| e.scope == scope
                    && e.name == name
                    && e.fid.to_bytes() == fid_bytes(fid)),
                "{scope} {name} {fid:04X}"
            );
        }
    }

    fn fid_bytes(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    #[test]
    fn records_and_lists_decode() {
        let adn = d(
            "adn",
            "EF.ADN",
            &[&[
                b'B', b'o', b'b', 0x05, 0x91, 0x21, 0x43, 0xF5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ]],
        );
        assert_eq!(adn["records"][0]["alpha"], "Bob");
        assert_eq!(adn["records"][0]["number"], "+12345");
        let sms = d("sms", "EF.SMS", &[&[0x03, 0x07, 0x91], &[0x00, 0xFF]]);
        assert_eq!(sms["records"][0]["status"], "received-unread");
        assert_eq!(sms["records"][1]["status"], "free");
        let opl = d(
            "opl",
            "EF.OPL",
            &[&[0x62, 0xF2, 0x10, 0x00, 0x01, 0xFF, 0xFE, 0x01]],
        );
        assert_eq!(opl["records"][0]["plmn"], "26201");
        assert_eq!(opl["records"][0]["pnn_record"], 1);
        let ecc = d(
            "ecc",
            "EF.ECC",
            &[&[0x11, 0xF2, 0xFF, b'S', b'O', b'S', 0x01]],
        );
        assert_eq!(ecc["records"][0]["number"], "112");
        assert_eq!(ecc["records"][0]["alpha"], "SOS");
        let plmn = d(
            "plmn-list",
            "EF.PLMNsel",
            &[&[0x62, 0xF2, 0x10, 0xFF, 0xFF, 0xFF]],
        );
        assert_eq!(plmn["plmns"], json!(["26201"]));
        let act = d(
            "plmn-act",
            "EF.PLMNwAcT",
            &[&[0x62, 0xF2, 0x10, 0x80, 0x80]],
        );
        assert_eq!(act["plmns"][0]["act"], json!(["UTRAN", "GSM"]));
        assert_eq!(
            d("cbmi", "EF.CBMI", &[&[0x00, 0x32, 0xFF, 0xFF]])["ids"],
            json!([50])
        );
        assert_eq!(
            d("alpha-list", "EF.LI", &[b"deen"])["languages"],
            json!(["de", "en"])
        );
        assert_eq!(d("uint", "EF.ACMmax", &[&[0x00, 0x01, 0x00]])["value"], 256);
        let smsp = d(
            "smsp",
            "EF.SMSP",
            &[&[
                b'X', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF,
            ]],
        );
        assert_eq!(smsp["records"][0]["alpha"], "X");
        let acl = d("acl", "EF.ACL", &[&[0x01, 0xDD, 0x03, b'a', b'b', b'c']]);
        assert_eq!(acl["count"], 1);
        let ust = d("services", "EF.UST", &[&[0b0000_0010, 0, 0, 0b0000_1000]]);
        assert_eq!(ust["enabled"], json!([2, 28]));
        assert_eq!(ust["services"][1]["name"], "Data download via SMS-PP");
        // A file that does not parse is an error with the bytes, never an empty success.
        let bad = d("imsi", "EF.IMSI", &[&[0x08, 0x09]]);
        assert!(bad["error"].is_string() && bad["hex"] == "0809", "{bad}");
        // A BER-TLV file nests.
        let tl = d("tlv", "EF.PNN", &[&[0x43, 0x03, 0x80, 0x01, 0x41]]);
        assert_eq!(tl["tlv"][0]["tag"], "43");
    }
}
