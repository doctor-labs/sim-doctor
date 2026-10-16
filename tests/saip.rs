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
