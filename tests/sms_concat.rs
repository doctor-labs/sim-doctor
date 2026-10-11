//! `sim-doctor sms decode` reassembles concatenated SMS parts (issue #200).

use std::process::Command;

// Two SMS-DELIVER TPDUs from +31641600986, UCS2, concatenation header reference 42 of 2: "HI" then "YO".
const PART1: &str = "400B911346610089F60008210101000000000A0500032A020100480049";
const PART2: &str = "400B911346610089F60008210101000000000A0500032A02020059004F";

fn data(args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["sms", "decode", "--tpdu", "--json"])
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v["payload"]["data"].clone()
}

#[test]
fn parts_given_out_of_order_are_joined_by_sequence() {
    let d = data(&[PART2, PART1]);
    assert_eq!(d["count"], 2);
    let r = &d["reassembled"][0];
    assert_eq!(r["address"], "+31641600986");
    assert_eq!(r["reference"], 42);
    assert_eq!(r["total"], 2);
    assert_eq!(r["parts"], serde_json::json!([1, 2]));
    assert_eq!(r["complete"], true);
    assert_eq!(r["missing"], serde_json::json!([]));
    assert_eq!(r["text"], "HIYO");
}

#[test]
fn a_missing_part_is_reported_and_the_rest_is_kept() {
    let r = &data(&[PART1])["reassembled"][0];
    assert_eq!(r["complete"], false);
    assert_eq!(r["missing"], serde_json::json!([2]));
    assert_eq!(r["text"], "HI");
}

#[test]
fn a_single_part_message_has_no_reassembly() {
    // the classic "How are you?" DELIVER, no user-data header
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "sms",
            "decode",
            "--json",
            "07911326040000F0040B911346610089F60000208062917314080CC8F71D14969741F977FD07",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["payload"]["data"]["reassembled"], serde_json::json!([]));
}
