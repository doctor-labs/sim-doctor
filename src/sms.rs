//! Offline SMS TPDU decoder per 3GPP TS 23.040 / 23.038.
//! Decodes SMS-DELIVER, SMS-SUBMIT, addresses, DCS, UDH, concatenation,
//! and GSM 7-bit / UCS-2 / 8-bit text. Sends nothing and needs no network.

/// Module identifier for the SMS decoder.
pub const NAME: &str = "sms";

/// GSM 7-bit default alphabet (TS 23.038). Septet N is the N-th char.
const GSM7: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\u{1b}ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

fn err(msg: &str) -> String {
    msg.to_string()
}

fn at(bytes: &[u8], i: usize) -> Result<u8, String> {
    bytes.get(i).copied().ok_or_else(|| err("truncated input"))
}

/// Decode semi-octets but cap the number of digits produced.
fn decode_semi_octets_with_cap(data: &[u8], cap: usize) -> String {
    let mut out = String::new();
    for byte in data {
        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;
        if out.len() < cap && lo != 0xF {
            out.push((b'0' + lo) as char);
        }
        if out.len() < cap && hi != 0xF {
            out.push((b'0' + hi) as char);
        }
    }
    out
}

/// Decode a single semi-octet address (TON/NPI octet present; len counts digits).
fn decode_address(bytes: &[u8], pos: usize) -> Result<(String, usize), String> {
    if pos >= bytes.len() {
        return Err(err("truncated address length"));
    }
    let len = bytes[pos];
    let tonpi_pos = pos + 1;
    if len == 0 {
        // Empty address: length 0, then a TON/NPI octet still follows.
        return Ok((String::new(), pos + 2));
    }
    if tonpi_pos >= bytes.len() {
        return Err(err("truncated TON/NPI"));
    }
    let tonnpi = bytes[tonpi_pos];
    let data_start = tonpi_pos + 1;
    // length counts the number of digits (semi-octets), ceil(len/2) octets.
    let num_octets = (len as usize + 1).div_ceil(2);
    let end = data_start + num_octets;
    if end > bytes.len() {
        return Err(err("truncated address"));
    }
    let digits = decode_semi_octets_with_cap(&bytes[data_start..end], len as usize);
    let addr = if (tonnpi & 0x70) == 0x10 {
        format!("+{}", digits)
    } else if (tonnpi & 0x70) == 0x50 {
        // Alphanumeric: GSM 7-bit packed.
        unpack_gsm7(&bytes[data_start..end], 0, len as u32)
    } else {
        digits
    };
    Ok((addr, end))
}

/// Decode SMSC address: length octet counts OCTETS (TON/NPI included).
fn decode_smsc(bytes: &[u8], pos: usize) -> Result<(Option<String>, usize), String> {
    if pos >= bytes.len() {
        return Err(err("truncated SMSC length"));
    }
    let len = bytes[pos];
    let data_start = pos + 1;
    if len == 0 {
        return Ok((None, data_start));
    }
    let end = data_start + len as usize;
    if end > bytes.len() {
        return Err(err("truncated SMSC"));
    }
    let tonnpi = at(bytes, data_start)?;
    let num_octets = (len as usize) - 1; // subtract the TON/NPI octet
    let num_digits = num_octets * 2;
    let digits = decode_semi_octets_with_cap(&bytes[data_start + 1..end], num_digits);
    let addr = if (tonnpi & 0x70) == 0x10 {
        format!("+{}", digits)
    } else {
        digits
    };
    Ok((Some(addr), end))
}

/// Unpack GSM 7-bit septets (LSB-first packing) skipping `skip_septets` leading septets.
fn unpack_gsm7(ud: &[u8], skip_septets: u32, count: u32) -> String {
    let mut out = String::new();
    let total_bits = (ud.len() as u32) * 8;
    let mut produced = 0u32;
    let mut i = 0u32;
    loop {
        let septet_bit_start = 7 * i;
        if septet_bit_start >= total_bits {
            break;
        }
        if i >= skip_septets {
            if produced >= count {
                break;
            }
            let mut value: u32 = 0;
            for bit in 0..7 {
                let bit_index = septet_bit_start + bit;
                let octet_index = (bit_index / 8) as usize;
                let bit_offset = bit_index % 8;
                if octet_index >= ud.len() {
                    break;
                }
                let b = ud[octet_index];
                if (b >> bit_offset) & 1 != 0 {
                    value |= 1 << bit;
                }
            }
            let ch = GSM7.chars().nth(value as usize).unwrap_or(' ');
            out.push(ch);
            produced += 1;
        }
        i += 1;
    }
    out
}

/// Compute the number of UD octets from the UD length field, which counts
/// septets (gsm7) or octets (ucs2/8bit).
fn ud_octet_count(udl: u8, udhi: bool, dcs: u8) -> usize {
    let _ = (udhi, dcs);
    let alphabet = dcs_alphabet(dcs);
    if alphabet == "gsm7" {
        let septets = udl as usize;
        (septets * 7).div_ceil(8)
    } else {
        udl as usize
    }
}

fn dcs_alphabet(dcs: u8) -> &'static str {
    match (dcs >> 2) & 0x03 {
        0 => "gsm7",
        1 => "8bit",
        2 => "ucs2",
        _ => "8bit", // 3 reserved -> treat as 8bit
    }
}

/// Decode the user data given the DCS and UD length, returning (text, udh, concatenation).
fn decode_ud(
    ud: &[u8],
    udhi: bool,
    dcs: u8,
    udl: u8,
) -> Result<(String, Option<serde_json::Value>, Option<serde_json::Value>), String> {
    let mut ud_pos = 0usize;
    let mut udh_val: Option<serde_json::Value> = None;
    let mut concat_val: Option<serde_json::Value> = None;

    if udhi {
        if ud.is_empty() {
            return Err(err("truncated UDHI header length"));
        }
        let udhl = ud[0] as usize;
        ud_pos = 1;
        let udh_end = ud_pos + udhl;
        if udh_end > ud.len() {
            return Err(err("truncated UDH"));
        }
        let udh_bytes = &ud[ud_pos..udh_end];
        ud_pos = udh_end;
        let (udh, concat) = parse_udh(udh_bytes)?;
        udh_val = Some(udh);
        concat_val = concat;
    }

    let content = &ud[ud_pos..];
    let alphabet = dcs_alphabet(dcs);
    let text = match alphabet {
        "ucs2" => {
            // UDL counts octets; decode content as UTF-16BE.
            let s: String = content
                .chunks(2)
                .filter_map(|c| {
                    if c.len() < 2 {
                        None
                    } else {
                        let v = u16::from_be_bytes([c[0], c[1]]);
                        char::from_u32(v as u32)
                    }
                })
                .collect();
            s
        }
        "8bit" => {
            let hex: String = content.iter().map(|b| format!("{:02x}", b)).collect();
            hex
        }
        "gsm7" => {
            // UDL counts SEPTETS over the whole UD.
            let udl_septets = udl as u32;
            let skip = if udhi {
                // skip ceil((UDHL+1)*8/7) septets covering the header + fill.
                let udhl = ud[0] as u32;
                ((udhl + 1) * 8).div_ceil(7)
            } else {
                0
            };
            unpack_gsm7(ud, skip, udl_septets)
        }
        _ => String::new(),
    };

    Ok((text, udh_val, concat_val))
}

/// Parse UDH into (ies array, concatenation).
fn parse_udh(udh: &[u8]) -> Result<(serde_json::Value, Option<serde_json::Value>), String> {
    let mut ies: Vec<serde_json::Value> = Vec::new();
    let mut concat_val: Option<serde_json::Value> = None;
    let mut pos = 0usize;
    while pos + 1 < udh.len() {
        let iei = udh[pos];
        let elen = udh[pos + 1] as usize;
        pos += 2;
        if pos + elen > udh.len() {
            return Err(err("truncated IE data"));
        }
        let data = &udh[pos..pos + elen];
        pos += elen;
        match iei {
            0x00 => {
                if data.len() >= 3 {
                    concat_val = Some(serde_json::json!({
                        "reference": data[0],
                        "total": data[1],
                        "sequence": data[2]
                    }));
                }
            }
            0x08 if data.len() >= 4 => {
                let ref_val = u16::from_be_bytes([data[0], data[1]]);
                let total = data[2];
                let sequence = data[3];
                concat_val = Some(serde_json::json!({
                    "reference": ref_val,
                    "total": total,
                    "sequence": sequence
                }));
            }
            _ => {}
        }
        let hex_data: String = data.iter().map(|b| format!("{:02x}", b)).collect();
        ies.push(serde_json::json!({ "iei": iei, "data": hex_data }));
    }
    Ok((serde_json::Value::Array(ies), concat_val))
}

/// Format a 7-octet SCTS into "YY-MM-DD hh:mm:ss".
fn format_scts(scts: &[u8]) -> String {
    if scts.len() < 7 {
        return String::new();
    }
    let b = |i: usize| format!("{:02}", scts[i]);
    let yy = b(0);
    let mo = b(1);
    let dd = b(2);
    let hh = b(3);
    let mm = b(4);
    let ss = b(5);
    let tz = b(6);
    format!("20{}-{}-{} {}:{}:{} (+{})", yy, mo, dd, hh, mm, ss, tz)
}

/// Decode an SMS TPDU (with optional leading SMSC) into a JSON object.
pub fn decode(bytes: &[u8], has_smsc: bool) -> Result<serde_json::Value, String> {
    if bytes.is_empty() {
        return Err(err("truncated input"));
    }
    let mut pos = 0usize;
    let mut smsc_val = serde_json::Value::Null;

    if has_smsc {
        let (smsc, new_pos) = decode_smsc(bytes, pos)?;
        smsc_val = match smsc {
            Some(s) => serde_json::json!(s),
            None => serde_json::Value::Null,
        };
        pos = new_pos;
    }

    if pos >= bytes.len() {
        return Err(err("truncated input"));
    }
    let fo = bytes[pos];
    pos += 1;
    let mti = fo & 0x03;
    let udhi = (fo & 0x40) != 0;
    let vpf = (fo >> 3) & 0x03;

    let mut obj = serde_json::Map::new();
    obj.insert("smsc".to_string(), smsc_val.clone());

    match mti {
        0 => {
            // SMS-DELIVER
            obj.insert("type".to_string(), serde_json::json!("SMS-DELIVER"));
            let (oa, new_pos) = decode_address(bytes, pos)?;
            pos = new_pos;
            obj.insert("originating_address".to_string(), serde_json::json!(oa));

            if pos >= bytes.len() {
                return Err(err("truncated PID"));
            }
            let pid = bytes[pos];
            pos += 1;
            obj.insert("pid".to_string(), serde_json::json!(format!("{:02X}", pid)));

            if pos >= bytes.len() {
                return Err(err("truncated DCS"));
            }
            let dcs = bytes[pos];
            pos += 1;
            let alphabet = dcs_alphabet(dcs);
            obj.insert(
                "dcs".to_string(),
                serde_json::json!({ "value": format!("{:02X}", dcs), "alphabet": alphabet }),
            );

            // SCTS = 7 octets
            if pos + 7 > bytes.len() {
                return Err(err("truncated SCTS"));
            }
            let scts_bytes = &bytes[pos..pos + 7];
            pos += 7;
            let scts = format_scts(scts_bytes);
            obj.insert("scts".to_string(), serde_json::json!(scts));

            if pos >= bytes.len() {
                return Err(err("truncated UD length"));
            }
            let udl = bytes[pos];
            pos += 1;
            let ud_octs = ud_octet_count(udl, udhi, dcs);
            if pos + ud_octs > bytes.len() {
                return Err(err("truncated UD"));
            }
            let ud = &bytes[pos..pos + ud_octs];
            let (text, udh_val, concat_val) = decode_ud(ud, udhi, dcs, udl)?;
            if let Some(udh) = udh_val {
                obj.insert("udh".to_string(), udh);
            }
            if let Some(concat) = concat_val {
                obj.insert("concatenation".to_string(), concat);
            }
            obj.insert("text".to_string(), serde_json::json!(text));
        }
        1 => {
            // SMS-SUBMIT
            obj.insert("type".to_string(), serde_json::json!("SMS-SUBMIT"));
            if pos >= bytes.len() {
                return Err(err("truncated MR"));
            }
            let mr = bytes[pos];
            pos += 1;
            let _ = mr;

            let (da, new_pos) = decode_address(bytes, pos)?;
            pos = new_pos;
            obj.insert("destination_address".to_string(), serde_json::json!(da));

            if pos >= bytes.len() {
                return Err(err("truncated PID"));
            }
            let pid = bytes[pos];
            pos += 1;
            obj.insert("pid".to_string(), serde_json::json!(format!("{:02X}", pid)));

            if pos >= bytes.len() {
                return Err(err("truncated DCS"));
            }
            let dcs = bytes[pos];
            pos += 1;
            let alphabet = dcs_alphabet(dcs);
            obj.insert(
                "dcs".to_string(),
                serde_json::json!({ "value": format!("{:02X}", dcs), "alphabet": alphabet }),
            );

            // VP
            match vpf {
                2 => {
                    if pos >= bytes.len() {
                        return Err(err("truncated VP"));
                    }
                    pos += 1; // 1 octet VP
                }
                1 | 3 => {
                    if pos + 7 > bytes.len() {
                        return Err(err("truncated VP"));
                    }
                    pos += 7; // 7 octet VP
                }
                _ => {} // 0 = none
            }

            if pos >= bytes.len() {
                return Err(err("truncated UD length"));
            }
            let udl = bytes[pos];
            pos += 1;
            let ud_octs = ud_octet_count(udl, udhi, dcs);
            if pos + ud_octs > bytes.len() {
                return Err(err("truncated UD"));
            }
            let ud = &bytes[pos..pos + ud_octs];
            let (text, udh_val, concat_val) = decode_ud(ud, udhi, dcs, udl)?;
            if let Some(udh) = udh_val {
                obj.insert("udh".to_string(), udh);
            }
            if let Some(concat) = concat_val {
                obj.insert("concatenation".to_string(), concat);
            }
            obj.insert("text".to_string(), serde_json::json!(text));
            // SUBMIT has no SCTS in output per spec (DELIVER only).
        }
        2 => {
            // SMS-STATUS-REPORT
            obj.insert("type".to_string(), serde_json::json!("SMS-STATUS-REPORT"));
            if pos >= bytes.len() {
                return Err(err("truncated MR"));
            }
            let mr = bytes[pos];
            pos += 1;
            let _ = mr;
            let (_oa, new_pos) = decode_address(bytes, pos)?;
            pos = new_pos;
            if pos >= bytes.len() {
                return Err(err("truncated PID"));
            }
            let _pid = bytes[pos];
            pos += 1;
            if pos >= bytes.len() {
                return Err(err("truncated DCS"));
            }
            let dcs = bytes[pos];
            pos += 1;
            let alphabet = dcs_alphabet(dcs);
            obj.insert(
                "dcs".to_string(),
                serde_json::json!({ "value": format!("{:02X}", dcs), "alphabet": alphabet }),
            );
            if pos + 7 > bytes.len() {
                return Err(err("truncated SCTS"));
            }
            let scts_bytes = &bytes[pos..pos + 7];
            pos += 7;
            let scts = format_scts(scts_bytes);
            obj.insert("scts".to_string(), serde_json::json!(scts));
            if pos >= bytes.len() {
                return Err(err("truncated UD length"));
            }
            let udl = bytes[pos];
            pos += 1;
            let ud_octs = ud_octet_count(udl, udhi, dcs);
            if pos + ud_octs > bytes.len() {
                return Err(err("truncated UD"));
            }
            let ud = &bytes[pos..pos + ud_octs];
            let (text, udh_val, concat_val) = decode_ud(ud, udhi, dcs, udl)?;
            if let Some(udh) = udh_val {
                obj.insert("udh".to_string(), udh);
            }
            if let Some(concat) = concat_val {
                obj.insert("concatenation".to_string(), concat);
            }
            obj.insert("text".to_string(), serde_json::json!(text));
        }
        _ => {
            return Err(err("unknown MTI"));
        }
    }

    Ok(serde_json::Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::decode;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn deliver_with_smsc_and_gsm7_text() {
        let m = decode(
            &hex("07911326040000F0040B911346610089F60000208062917314080CC8F71D14969741F977FD07"),
            true,
        )
        .unwrap();
        assert_eq!(m["type"], "SMS-DELIVER");
        assert_eq!(m["smsc"], "+31624000000");
        assert_eq!(m["originating_address"], "+31641600986");
        assert_eq!(m["dcs"]["alphabet"], "gsm7");
        assert_eq!(m["text"], "How are you?");
    }

    #[test]
    fn submit_without_smsc() {
        let m = decode(
            &hex("0011000B916407281553F80000AA0AE8329BFD4697D9EC37"),
            true,
        )
        .unwrap();
        assert_eq!(m["type"], "SMS-SUBMIT");
        assert!(m["smsc"].is_null());
        assert_eq!(m["destination_address"], "+46708251358");
        assert_eq!(m["text"], "hellohello");
    }

    #[test]
    fn ucs2_and_concatenation() {
        let m = decode(
            &hex("00040B911346610089F60008208062917314080400480049"),
            true,
        )
        .unwrap();
        assert_eq!(m["dcs"]["alphabet"], "ucs2");
        assert_eq!(m["text"], "HI");
        let c = decode(
            &hex("00440B911346610089F6000820806291731408080500032A02010041"),
            true,
        )
        .unwrap();
        assert_eq!(c["udh"][0]["iei"], 0);
        assert_eq!(
            c["concatenation"],
            serde_json::json!({"reference": 42, "total": 2, "sequence": 1})
        );
        assert_eq!(c["text"], "A");
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        assert!(decode(&hex("0791"), true).is_err());
        assert!(decode(&[], true).is_err());
    }
}
