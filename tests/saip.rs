//! `sim-doctor saip parse` as the built binary: an offline SAIP profile package decoded to
//! JSON (issue #226). The package is hand-built here; no card, reader or real profile is used.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Short-form or `81`/`82` long-form TLV with minimal lengths.
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

/// header (A0), mf (B0, long-form length), iot (BF 20, high-tag form), an unknown
/// high-tag element (BF 25) and end (AA), concatenated as a SAIP package is.
fn package() -> Vec<u8> {
    let header = tlv(&[0xA0], &tlv(&[0x80], &[0x02]));
    let mf = tlv(
        &[0xB0],
        &[tlv(&[0x80], &[0u8; 0x7F]), tlv(&[0x80], &[0x01])].concat(),
    );
    let iot = tlv(&[0xBF, 0x20], &[]);
    let unknown = tlv(&[0xBF, 0x25], &[0xAB, 0xCD]);
    let end = tlv(&[0xAA], &[]);
    [header, mf, iot, unknown, end].concat()
}

/// Writes `bytes` under the test target directory and returns the path.
fn write_fixture(name: &str, bytes: &[u8]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn parse(path: &PathBuf, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("saip")
        .arg("parse")
        .arg(path)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn a_package_decodes_to_named_elements_with_unknown_ones_as_raw_hex() {
    let path = write_fixture("saip-package.der", &package());
    let out = parse(&path, &["--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["type"], "saip");
    let data = &envelope["payload"]["data"];
    assert_eq!(data["pe_count"], 5);
    let elements = data["elements"].as_array().unwrap();
    let types: Vec<&str> = elements
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["header", "mf", "iot", "unknown", "end"]);
    // The unknown element is not parsed inside: its raw element is the whole thing.
    assert_eq!(elements[3]["tag"], "BF25");
    assert_eq!(elements[3]["raw_hex"], "BF2502ABCD");
    // The MF's long-form length (81 84) is read as a 132-octet body.
    assert_eq!(elements[1]["length"], 132);
}

#[test]
fn text_output_lists_one_line_per_element() {
    let path = write_fixture("saip-package-text.der", &package());
    let out = parse(&path, &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("mf"), "{text}");
    assert!(text.trim_end().ends_with("5 profile elements"), "{text}");
}

#[test]
fn a_non_minimal_length_is_refused_with_exit_two_and_the_offset() {
    // `81 05` for a five-octet body: legal BER, not DER. The decoder refuses it.
    let path = write_fixture("saip-bad-length.der", &[0xA2, 0x81, 0x05, 0, 0, 0, 0, 0]);
    let out = parse(&path, &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let message = envelope["payload"]["data"]["error"].as_str().unwrap();
    assert!(message.contains("offset 0"), "{message}");
}

#[test]
fn a_missing_file_is_exit_two_not_a_panic() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("saip-does-not-exist.der");
    let out = parse(&path, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}

/// header with ICCID, pinCodes, pukCodes, two optional PEs and end.
fn personalizable_package() -> Vec<u8> {
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
fn personalize_applies_document_and_removes_variant_pes() {
    let input = write_fixture("saip-personalize-in.der", &personalizable_package());
    let doc_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("saip-personalize-doc.json");
    std::fs::write(
        &doc_path,
        serde_json::json!({
            "iccid": "89000123456789012451",
            "pin_codes": [{
                "key_reference": 1,
                "pin_value": "1234",
                "unblocking_puk_reference": 1
            }],
            "puk_codes": [{
                "key_reference": 1,
                "puk_value": "87654321"
            }],
            "remove_pe_types": ["opt-usim", "opt-isim"]
        })
        .to_string(),
    )
    .unwrap();
    let out_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("saip-personalize-out.der");
    let _ = std::fs::remove_file(&out_path);
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("saip")
        .arg("personalize")
        .arg(&input)
        .arg("--doc")
        .arg(&doc_path)
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["type"], "saip");
    assert_eq!(envelope["payload"]["data"]["pe_count"], 4);
    let parsed = parse(&out_path, &["--json"]);
    assert_eq!(parsed.status.code(), Some(0));
    let decoded: serde_json::Value = serde_json::from_slice(&parsed.stdout).unwrap();
    let elements = decoded["payload"]["data"]["elements"].as_array().unwrap();
    let types: Vec<&str> = elements
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["header", "pinCodes", "pukCodes", "end"]);
    assert_eq!(elements[0]["fields"]["iccid"], "89000123456789012451");
    assert_eq!(
        elements[1]["fields"]["pin_configs"][0]["pin_value_hex"],
        "1234FFFFFFFFFFFF"
    );
    assert_eq!(
        elements[2]["fields"]["puk_configs"][0]["puk_value_hex"],
        "87654321FFFFFFFF"
    );
}
