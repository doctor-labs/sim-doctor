//! Profile programming: the profile document, its checks, and the writes it becomes.
//!
//! The document is `key = value` lines (`#` starts a comment). `target` is `sim`, `usim` or `isim`,
//! and the keys that target takes are written by the card shell's own `select` and `update_binary`
//! (`cmd_program_profile` in `cardsh.rs`): one write path, one `--yes` gate, one read-back.
//!
//! Byte layouts, from pySim (osmocom/pysim, GPL; read, not copied) and this crate's decoders:
//! - EF.IMSI 6F07, 9 octets: `pySim/ts_51_011.py` class `EF_IMSI`, size (9, 9) [V]. Coding as
//!   `ef::decode_imsi` (TS 31.102 clause 4.2.2, TS 51.011 clause 10.3.2) [V].
//! - EF.ICCID 2FE2, 10 octets: `EF_ICCID`, size (10, 10) [V]. Its test vector `988812010000400310f0`
//!   reads `8988211000000430010`, the coding used here [V].
//! - EF.ACC 6F78, 2 octets: `EF_ACC`, size (2, 2) [V].
//! - EF.FPLMN 6F7B, 12 octets under DF GSM: `pySim/ts_51_011.py`, size (12, 12) [V]. PLMN coding as
//!   `ef::decode_plmn` (TS 24.008 clause 10.5.1.13) [V].
//! - ISIM EF.IMPI 6F02 and EF.DOMAIN 6F03: transparent, holding one BER-TLV tag 0x80 value
//!   (`pySim/ts_31_103.py`, classes `EF_IMPI` and `EF_DOMAIN`) [V for the TLV]. The file's size is
//!   the card's, so the value is padded with FF to it and refused when longer [U for the size rule].
//!
//! Not written: Ki and OPc. No standard EF holds them, they live in the card's secret store [U].
//! Refused: MSISDN, SMSP, IMPU, P-CSCF, ePDG, and a USIM FPLMN, because their record length or file
//! is not established here [U]. Ki and OPc are checked and then dropped, never printed.

use std::collections::BTreeMap;

/// Every key a document may hold.
const KEYS: &[&str] = &[
    "target", "imsi", "iccid", "acc", "fplmn", "ki", "opc", "impi", "domain",
];

/// The application a document programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// GSM SIM: files under MF and DF GSM.
    Sim,
    /// USIM: files under ADF USIM.
    Usim,
    /// ISIM: files under ADF ISIM.
    Isim,
}

impl Target {
    /// The spelling the document uses.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sim => "sim",
            Self::Usim => "usim",
            Self::Isim => "isim",
        }
    }

    /// The keys this target takes, in write order.
    fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Sim => &["imsi", "iccid", "acc", "fplmn", "ki", "opc"],
            Self::Usim => &["imsi", "iccid", "acc", "ki", "opc"],
            Self::Isim => &["impi", "domain"],
        }
    }
}

/// One EF write: the path `select` takes, the octets, and whether they are padded to the file's size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The document key this write came from.
    pub key: &'static str,
    /// The path `select` takes.
    pub path: &'static str,
    /// The octets, before any padding.
    pub data: Vec<u8>,
    /// Pad with FF to the card's file size (TLV values); otherwise the size must match exactly.
    pub pad_to_size: bool,
}

/// What a document asks for: the writes in order, and the keys checked but never written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The application.
    pub target: Target,
    /// The writes, in order.
    pub steps: Vec<Step>,
    /// Keys checked and dropped (Ki, OPc).
    pub not_written: Vec<&'static str>,
}

/// Reads a profile document and returns its plan, or every reason it was refused.
pub fn plan(text: &str) -> Result<Plan, Vec<String>> {
    let mut errors = Vec::new();
    let mut values: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let Some((key, value)) = line.split_once('=') else {
            errors.push(format!("line {number}: expected `key = value`"));
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if let Some((first, _)) = values.get(&key) {
            errors.push(format!(
                "line {number}: duplicate key `{key}` (first at line {first})"
            ));
        } else {
            values.insert(key, (number, value.trim().to_owned()));
        }
    }
    let target = match values.get("target").map(|(_, v)| v.to_ascii_lowercase()) {
        None => {
            errors.push("`target` is required: sim, usim or isim".to_owned());
            None
        }
        Some(name) => match name.as_str() {
            "sim" => Some(Target::Sim),
            "usim" => Some(Target::Usim),
            "isim" => Some(Target::Isim),
            other => {
                errors.push(format!("`target` is `{other}`, not sim, usim or isim"));
                None
            }
        },
    };
    for (key, (number, _)) in &values {
        if !KEYS.contains(&key.as_str()) {
            errors.push(format!("line {number}: unknown key `{key}`"));
        } else if let Some(target) = target {
            if key != "target" && !target.keys().contains(&key.as_str()) {
                errors.push(format!(
                    "line {number}: `{key}` is not a field of {}",
                    target.name()
                ));
            }
        }
    }
    let Some(target) = target else {
        return Err(errors);
    };
    let mut steps = Vec::new();
    let mut not_written = Vec::new();
    for &key in target.keys() {
        let Some((_, value)) = values.get(key) else {
            continue;
        };
        match field(target, key, value) {
            Ok(Some(step)) => steps.push(step),
            Ok(None) => not_written.push(key),
            Err(reason) => errors.push(reason),
        }
    }
    if steps.is_empty() {
        errors.push(format!(
            "nothing to program: {} takes no written field here",
            target.name()
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Plan {
        target,
        steps,
        not_written,
    })
}

/// Checks one value and says where it goes. `Ok(None)` means checked but not written.
fn field(target: Target, key: &'static str, value: &str) -> Result<Option<Step>, String> {
    match key {
        "imsi" => {
            if !is_digits(value) || !(6..=15).contains(&value.len()) {
                return Err(format!(
                    "IMSI must be 6 to 15 decimal digits (got {} characters)",
                    value.len()
                ));
            }
            let path = match target {
                Target::Sim => "MF/DF.GSM/EF.IMSI",
                _ => "ADF.USIM/EF.IMSI",
            };
            step(key, path, imsi_ef(value), false)
        }
        "iccid" => {
            if !is_digits(value) || !(18..=20).contains(&value.len()) {
                return Err(format!(
                    "ICCID must be 18 to 20 decimal digits (got {} characters)",
                    value.len()
                ));
            }
            step(key, "MF/EF.ICCID", iccid_ef(value), false)
        }
        "acc" => {
            if value.len() != 4 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("ACC must be 4 hex digits (2 octets)".to_owned());
            }
            let path = match target {
                Target::Sim => "MF/DF.GSM/EF.ACC",
                _ => "ADF.USIM/EF.ACC",
            };
            step(key, path, hex_bytes(value), false)
        }
        "fplmn" => step(key, "MF/DF.GSM/EF.FPLMN", fplmn_ef(value)?, false),
        "ki" => {
            key_octets("Ki", value)?;
            Ok(None)
        }
        "opc" => {
            key_octets("OPc", value)?;
            Ok(None)
        }
        "impi" => step(key, "ADF.ISIM/EF.IMPI", nai_tlv("IMPI", value)?, true),
        "domain" => step(key, "ADF.ISIM/EF.DOMAIN", nai_tlv("domain", value)?, true),
        _ => Err(format!("`{key}` is not a profile field")),
    }
}

fn step(
    key: &'static str,
    path: &'static str,
    data: Vec<u8>,
    pad_to_size: bool,
) -> Result<Option<Step>, String> {
    Ok(Some(Step {
        key,
        path,
        data,
        pad_to_size,
    }))
}

fn is_digits(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_digit())
}

fn digit_values(text: &str) -> Vec<u8> {
    text.bytes().map(|b| b - b'0').collect()
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

/// Octets of hex text. The caller has checked the text is hex digits of even length.
fn hex_bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|p| (hex_nibble(p[0]) << 4) | hex_nibble(p[1]))
        .collect()
}

/// A 128-bit key from 32 hex digits, not all zero.
fn key_octets(label: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{label} must be 32 hex digits (16 octets)"));
    }
    let bytes = hex_bytes(value);
    if bytes.iter().all(|&b| b == 0) {
        return Err(format!("{label} is all zeros, which is no key"));
    }
    Ok(bytes)
}

/// EF.IMSI (9 octets): the length octet, then the TS 24.008 identity octet (digit 1 in b8..b5, the
/// odd/even indicator in b4, type 001 in b3..b1), then two digits per octet, low nibble first, `F`
/// filling an even count. The rest of the file is FF.
fn imsi_ef(digits: &str) -> Vec<u8> {
    let d = digit_values(digits);
    let odd = d.len() % 2 == 1;
    let mut body = vec![(d[0] << 4) | (u8::from(odd) << 3) | 0x01];
    for pair in d[1..].chunks(2) {
        let high = pair.get(1).copied().unwrap_or(0x0F);
        body.push((high << 4) | pair[0]);
    }
    let mut out = vec![u8::try_from(body.len()).expect("an IMSI body is at most 8 octets")];
    out.extend(body);
    out.resize(9, 0xFF);
    out
}

/// EF.ICCID (10 octets): the digits padded with `F` to 20, two per octet, low nibble first.
fn iccid_ef(digits: &str) -> Vec<u8> {
    let mut nibbles = digit_values(digits);
    nibbles.resize(20, 0x0F);
    nibbles.chunks(2).map(|p| (p[1] << 4) | p[0]).collect()
}

/// EF.FPLMN (12 octets): up to four PLMNs, `,` separated, each 5 or 6 digits. Unused entries are FF.
fn fplmn_ef(value: &str) -> Result<Vec<u8>, String> {
    let entries: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    if entries.len() > 4 {
        return Err(format!("EF.FPLMN holds 4 PLMNs, got {}", entries.len()));
    }
    let mut out = Vec::with_capacity(12);
    for (i, plmn) in entries.iter().enumerate() {
        if !is_digits(plmn) || !matches!(plmn.len(), 5 | 6) {
            return Err(format!("PLMN {} must be 5 or 6 digits", i + 1));
        }
        if entries[..i].contains(plmn) {
            return Err(format!("duplicate PLMN {plmn}"));
        }
        let d = digit_values(plmn);
        let mnc3 = if d.len() == 6 { d[5] } else { 0x0F };
        out.extend([(d[1] << 4) | d[0], (mnc3 << 4) | d[2], (d[4] << 4) | d[3]]);
    }
    out.resize(12, 0xFF);
    Ok(out)
}

/// An ISIM value as BER-TLV tag 0x80: one ASCII string of 1 to 127 printable characters, no spaces.
fn nai_tlv(label: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > 127 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "{label} must be 1 to 127 printable ASCII characters without spaces"
        ));
    }
    let mut tlv = vec![0x80, value.len() as u8];
    tlv.extend(value.bytes());
    Ok(tlv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardsh::testcard::shell_log;
    use serde_json::json;

    fn data(plan: &Plan, key: &str) -> Vec<u8> {
        plan.steps
            .iter()
            .find(|s| s.key == key)
            .expect("a step for the key")
            .data
            .clone()
    }

    #[test]
    fn every_refusal_gives_its_reason() {
        let cases: &[(&str, &str)] = &[
            ("imsi = 001010123456789", "`target` is required"),
            ("target = gsm\nimsi = 001010123456789", "`target` is `gsm`"),
            (
                "target = sim\nimsi = 12345",
                "IMSI must be 6 to 15 decimal digits",
            ),
            (
                "target = sim\nimsi = 0010101234567890",
                "IMSI must be 6 to 15 decimal digits",
            ),
            (
                "target = sim\nimsi = 00101ABC",
                "IMSI must be 6 to 15 decimal digits",
            ),
            (
                "target = sim\nimsi = 001010123456789\nimsi = 001010123456789",
                "duplicate key `imsi`",
            ),
            (
                "target = sim\niccid = 1234",
                "ICCID must be 18 to 20 decimal digits",
            ),
            ("target = sim\nki = 00112233", "Ki must be 32 hex digits"),
            (
                "target = sim\nki = 00000000000000000000000000000000",
                "Ki is all zeros",
            ),
            ("target = usim\nopc = xyz", "OPc must be 32 hex digits"),
            ("target = sim\nacc = 01", "ACC must be 4 hex digits"),
            ("target = sim\nacc = 0G01", "ACC must be 4 hex digits"),
            ("target = sim\nfplmn = 0010", "PLMN 1 must be 5 or 6 digits"),
            (
                "target = sim\nfplmn = 00101,00101,00101,00101,00101",
                "holds 4 PLMNs, got 5",
            ),
            ("target = sim\nfplmn = 00101,00101", "duplicate PLMN 00101"),
            (
                "target = isim\nimsi = 001010123456789\nimpi = a@b",
                "`imsi` is not a field of isim",
            ),
            (
                "target = usim\nfplmn = 00101\nimsi = 001010123456789",
                "`fplmn` is not a field of usim",
            ),
            ("target = isim\nimpi = ", "IMPI must be 1 to 127"),
            ("target = isim\nimpi = a b", "IMPI must be 1 to 127"),
            ("target = sim\nmsisdn = 123", "unknown key `msisdn`"),
            ("target = sim", "nothing to program"),
            (
                "target = sim\nimsi 001010123456789",
                "expected `key = value`",
            ),
        ];
        for (text, expected) in cases {
            let errors = plan(text).expect_err("the document should be refused");
            assert!(
                errors.iter().any(|e| e.contains(expected)),
                "{text:?}: wanted `{expected}`, got {errors:?}"
            );
        }
    }

    #[test]
    fn sim_octets_and_paths() {
        let sim = plan(
            "target = sim\nimsi = 001010123456789\niccid = 8988211000000430010\nacc = 0001\n\
             fplmn = 00101,310260\nki = 465b5ce8b199b49faa5f0a2ee238a6bc\nopc = cd63cb71954a9f4e48a5994e37a02baf",
        )
        .expect("a valid SIM profile");
        assert_eq!(
            data(&sim, "imsi"),
            [0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]
        );
        assert_eq!(
            data(&sim, "iccid"),
            [0x98, 0x88, 0x12, 0x01, 0x00, 0x00, 0x40, 0x03, 0x10, 0xF0]
        );
        assert_eq!(data(&sim, "acc"), [0x00, 0x01]);
        assert_eq!(
            data(&sim, "fplmn"),
            [0x00, 0xF1, 0x10, 0x13, 0x00, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(sim.not_written, ["ki", "opc"]);
        assert_eq!(sim.steps[0].path, "MF/DF.GSM/EF.IMSI");
        assert_eq!(sim.steps[1].path, "MF/EF.ICCID");
    }

    #[test]
    fn isim_values_are_tlv_padded_to_the_card_file() {
        let domain = "ims.mnc001.mcc001.3gppnetwork.org";
        let isim = plan(&format!(
            "target = isim\nimpi = 001010123456789@{domain}\ndomain = {domain}"
        ))
        .expect("a valid ISIM profile");
        let tlv = data(&isim, "domain");
        assert_eq!(&tlv[..2], &[0x80, domain.len() as u8]);
        assert_eq!(&tlv[2..], domain.as_bytes());
        assert!(isim.steps.iter().all(|s| s.pad_to_size));
        assert_eq!(isim.steps[1].path, "ADF.ISIM/EF.DOMAIN");
    }

    #[test]
    fn a_card_missing_one_file_is_refused_before_any_write() {
        let (mut sh, log) = shell_log();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/profile_usim.profile"
        );
        let reply = sh.exec(&format!("program_profile --file {path} --yes"));
        assert!(!reply.ok, "the test card has no ADF.USIM/EF.ACC");
        assert!(reply.text.contains("nothing written"), "{}", reply.text);
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|c| c.get(1) == Some(&0xD6))
                .count(),
            0,
            "a write was sent"
        );
    }

    #[test]
    fn send_writes_each_file_and_reads_it_back_on_the_test_card() {
        let (mut sh, log) = shell_log();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/profile_usim_no_acc.profile"
        );
        let reply = sh.exec(&format!("program_profile --file {path} --yes"));
        assert!(reply.ok, "{}", reply.text);
        assert_eq!(reply.data["card_touched"], json!(true));
        assert_eq!(
            reply.data["written"].as_array().map(Vec::len),
            Some(2),
            "imsi and iccid"
        );
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|c| c.get(1) == Some(&0xD6))
                .count(),
            2,
            "one UPDATE BINARY per file"
        );
    }

    #[test]
    fn a_dry_run_sends_nothing_and_says_so() {
        let (mut sh, log) = shell_log();
        let before = log.borrow().len();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/profile_usim.profile"
        );
        let reply = sh.exec(&format!("program_profile --file {path}"));
        assert!(reply.ok, "{}", reply.text);
        assert_eq!(reply.data["card_touched"], json!(false));
        assert!(reply.text.contains("WARNING"));
        assert_eq!(log.borrow().len(), before, "a dry run sent APDUs");
    }
}
