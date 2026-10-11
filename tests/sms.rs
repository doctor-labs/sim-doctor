//! `sim-doctor sms decode` as the built binary: no card, no reader (issue #199).

use std::process::Command;

fn decode(args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["sms", "decode", "--json"])
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
    assert_eq!(v["type"], "sms");
    v["payload"]["data"]["messages"].clone()
}

#[test]
fn sms_deliver_with_smsc_and_gsm7_text() {
    // the classic example PDU: SMSC +31624000000, from +31641600986, "How are you?"
    let m =
        &decode(&["07911326040000F0040B911346610089F60000208062917314080CC8F71D14969741F977FD07"])
            [0];
    assert_eq!(m["type"], "SMS-DELIVER");
    assert_eq!(m["smsc"], "+31624000000");
    assert_eq!(m["originating_address"], "+31641600986");
    assert_eq!(m["dcs"]["alphabet"], "gsm7");
    assert_eq!(m["text"], "How are you?");
}

#[test]
fn sms_submit_without_smsc() {
    let m = &decode(&["0011000B916407281553F80000AA0AE8329BFD4697D9EC37"])[0];
    assert_eq!(m["type"], "SMS-SUBMIT");
    assert_eq!(m["smsc"], serde_json::Value::Null);
    assert_eq!(m["destination_address"], "+46708251358");
    assert_eq!(m["text"], "hellohello");
}

#[test]
fn ucs2_text_and_a_concatenation_header() {
    // SMS-DELIVER, no SMSC, UCS2 "HI"
    let m = &decode(&["00040B911346610089F60008208062917314080400480049"])[0];
    assert_eq!(m["dcs"]["alphabet"], "ucs2");
    assert_eq!(m["text"], "HI");
    // UDHI set (0x44): UDH 05 00 03 2A 02 01 = concatenated SMS ref 42, part 1 of 2; then UCS2 "A"
    let c = &decode(&["00440B911346610089F6000820806291731408080500032A02010041"])[0];
    assert_eq!(c["udh"][0]["iei"], 0);
    assert_eq!(
        c["concatenation"],
        serde_json::json!({ "reference": 42, "total": 2, "sequence": 1 })
    );
    assert_eq!(c["text"], "A");
}

#[test]
fn bad_hex_is_a_refusal_with_exit_two() {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["sms", "decode", "zz"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
