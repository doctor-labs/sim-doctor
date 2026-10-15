//! `sim-doctor ota-expanded` as the built binary and as the library: the OTA expanded remote
//! application data format of ETSI TS 102 226 clause 5.2, the Proof-of-Response of TS 102 225
//! table 5 and 3GPP TS 31.115 (issue #205).
//!
//! Every vector below is a hand-written byte string. The response-template and PoR vectors are
//! **not** produced by the encoder in this crate: a decoder tested against its own encoder proves
//! only that the two agree with each other, which is not the same as being right about the wire.

use std::process::Command;

use sim_doctor::ota_expanded::{self, LengthCoding, RemoteFormat};
use sim_doctor::tlv;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex.replace(' ', "")).expect("the test vector is hex")
}

fn run(args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("ota-expanded")
        .args(args)
        .arg("--json")
        .output()
        .unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (
        out.status.code(),
        v["payload"]["data"].clone(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn run_human(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("ota-expanded")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// A Response Packet built from its field layout, which is where the octet accounting comes from.
///
/// RPL counts every octet after itself; RHL covers the ten header octets from TAR to the response
/// status plus any CC/RC/DS. So RPL = RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STS(1) + CC + data,
/// and RHL = 10 + the length of the CC/RC/DS. Getting this wrong in a test would make the test
/// assert a decoder that only agrees with it, so the layout is spelled out here once.
fn por(status: u8, cc_rc: &[u8], secure: &[u8]) -> Vec<u8> {
    let rhl = 10 + cc_rc.len() as u8;
    let rpl = 11 + cc_rc.len() as u16 + secure.len() as u16;
    let mut out = Vec::new();
    out.extend_from_slice(&rpl.to_be_bytes());
    out.push(rhl);
    out.extend_from_slice(&[0xB0, 0x00, 0x11]); // TAR
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]); // CNTR
    out.push(0x00); // PCNTR
    out.push(status);
    out.extend_from_slice(cc_rc);
    out.extend_from_slice(secure);
    out
}

/// A Response Packet that is nothing but its header: no CC/RC/DS and no secure data, so there is
/// no Remote Application structure to decode whichever response status it carries.
fn header_only_por(status: u8) -> Vec<u8> {
    por(status, &[], &[])
}

fn hex_upper(b: &[u8]) -> String {
    hex::encode_upper(b)
}

// ---------------------------------------------------------------------------------------------
// Part 1: the Command Scripting template encoder (TS 102 226 5.2.1)
// ---------------------------------------------------------------------------------------------

#[test]
fn one_c_apdu_gets_a_definite_command_scripting_template() {
    // A0 A4 00 00 = SELECT MF. Wrapped in a C-APDU TLV (22 04 ...) and in a definite Command
    // Scripting template (AA 06 ...): TS 102 226 table 5.2, TS 102 223 clause 8.35.
    let script =
        ota_expanded::command_scripting(&[bytes("A0A40000")], LengthCoding::Definite).unwrap();
    assert_eq!(script.template, "AA062204A0A40000");
    assert_eq!(script.template_tag, 0xAA);
    assert_eq!(script.commands[0].c_apdu, "A0A40000");
    assert_eq!(script.commands[0].tlv, "2204A0A40000");
    assert_eq!(script.json()["length_coding"], "definite");
}

#[test]
fn one_c_apdu_gets_an_indefinite_command_scripting_template() {
    // TS 102 226 table 5.2a: AE, the 80 length marker, the definite C-APDU TLVs, then 00 00.
    let script =
        ota_expanded::command_scripting(&[bytes("A0A40000")], LengthCoding::Indefinite).unwrap();
    assert_eq!(script.template, "AE802204A0A400000000");
    assert_eq!(script.template_tag, 0xAE);
    assert_eq!(script.json()["length_coding"], "indefinite");
}

#[test]
fn a_multi_command_script_keeps_its_order_and_adds_no_le() {
    let script = ota_expanded::command_scripting(
        &[bytes("A0A40000"), bytes("00A4040007A0000000030000")],
        LengthCoding::Definite,
    )
    .unwrap();
    // 22 04 A0A40000 is 6 octets and 22 0C 00A4040007A0000000030000 is 14, so the template value is
    // 20 = 0x14 and the whole template is 22 octets.
    assert_eq!(
        script.template,
        "AA142204A0A40000220C00A4040007A0000000030000"
    );
    assert_eq!(script.commands.len(), 2);
    // No Le anywhere: the last octet of the second C-APDU is P2, exactly as it was given.
    assert_eq!(script.commands[1].c_apdu, "00A4040007A0000000030000");
    assert_eq!(script.json()["command_count"], 2);
}

#[test]
fn a_script_over_127_octets_uses_the_long_length_form() {
    // 11 C-APDUs of 10 octets: each C-APDU TLV is 12 octets, 11 x 12 = 132 = 0x84, so the
    // template length is the long form 81 84 rather than the short form, whose ceiling is 0x7F.
    let c_apdus = vec![bytes("A0A40000000000000000"); 11];
    let script = ota_expanded::command_scripting(&c_apdus, LengthCoding::Definite).unwrap();
    assert!(script.template.starts_with("AA8184"), "{}", script.template);
    let raw = bytes(&script.template);
    assert_eq!(raw[0], 0xAA);
    assert_eq!((raw[1], raw[2]), (0x81, 0x84));
}

#[test]
fn an_empty_script_is_refused_and_nothing_is_guessed() {
    let err = ota_expanded::command_scripting(&[], LengthCoding::Definite).unwrap_err();
    assert!(matches!(err, ota_expanded::Error::NoCommand), "{err}");
}

// ---------------------------------------------------------------------------------------------
// Part 2: the Response Scripting template decoder (TS 102 226 5.2.2)
// ---------------------------------------------------------------------------------------------

#[test]
fn a_definite_response_template_names_every_r_apdu() {
    // AB 0C                     definite Response Scripting template (TS 102 226 table 5.10)
    //   80 01 02                 number of executed command TLV objects = 2 (table 5.11)
    //   23 03 4F 90 00           R-APDU TLV (tag 23, TS 102 223 clause 8.36): data 4F, SW 9000
    //   23 02 90 00              R-APDU TLV: no data, SW 9000
    let d = ota_expanded::decode_response_scripting(&bytes("AB 0C 800102 23034F9000 23029000"))
        .unwrap();
    assert_eq!(d.length_coding, LengthCoding::Definite);
    assert_eq!(d.template_tag, 0xAB);
    assert_eq!(d.number_of_executed, Some(2));
    assert_eq!(d.executed(), 2);
    assert_eq!(d.responses.len(), 2);
    assert_eq!(d.responses[0].response_data, "4F");
    assert_eq!(d.responses[0].status_word, "9000");
    assert_eq!(d.responses[1].response_data, "");
    assert_eq!(d.last_status_word(), Some("9000"));
    assert_eq!(d.last_response_data(), "");
    assert!(!d.truncated);
    assert!(d.bad_format.is_none());
    assert!(d.immediate_action.is_none());
    assert!(d.script_chaining.is_none());
}

#[test]
fn a_definite_response_template_carries_the_three_error_tlvs_by_name() {
    //   23 04 41 42 6E 00       R-APDU TLV: data 4142, SW 6E00
    //   90 01 01                 Bad format TLV, unknown_tag                     (table 5.12)
    //   81 01 01                 Immediate Action Response TLV, suspension_error (table 5.14)
    //   83 01 02                 Script Chaining Response TLV, not_supported     (table 5.16)
    let d = ota_expanded::decode_response_scripting(&bytes(
        "AB 12 800100 230441426E00 900101 810101 830102",
    ))
    .unwrap();
    assert_eq!(d.responses[0].status_word, "6E00");
    assert_eq!(d.responses[0].response_data, "4142");
    assert_eq!(
        d.bad_format.as_ref().map(|c| (c.code, c.name)),
        Some((1, "unknown_tag"))
    );
    assert_eq!(
        d.immediate_action.as_ref().map(|c| (c.code, c.name)),
        Some((1, "suspension_error"))
    );
    assert_eq!(
        d.script_chaining.as_ref().map(|c| (c.code, c.name)),
        Some((2, "not_supported"))
    );
    // The other two codes of each table, so a wrong table entry cannot pass.
    assert_eq!(ota_expanded::bad_format_name(2), Some("wrong_length"));
    assert_eq!(ota_expanded::bad_format_name(3), Some("length_not_found"));
    assert_eq!(
        ota_expanded::script_chaining_name(1),
        Some("no_previous_script")
    );
    assert_eq!(
        ota_expanded::script_chaining_name(3),
        Some("unable_to_process")
    );
}

#[test]
fn a_62f1_status_word_means_the_card_truncated_and_terminated_the_list() {
    //   23 05 41 42 43 62 F1    R-APDU TLV: data 414243, SW 62F1
    // TS 102 226 clause 5.2.1.1: the card set that because it had to truncate the C-APDU's
    // response and shall terminate the processing of the command list, so the third command never
    // ran even though the header says three were executed.
    let d = ota_expanded::decode_response_scripting(&bytes("AB 0E 800103 230541424362F1 23029000"))
        .unwrap();
    assert!(d.truncated, "62F1 must raise truncated");
    assert!(d.responses[0].truncated);
    assert!(!d.responses[1].truncated);
    assert_eq!(d.responses[0].status_word, "62F1");
    assert_eq!(d.responses[0].response_data, "414243");
    assert_eq!(d.number_of_executed, Some(3));
    assert!(d.render().contains("TRUNCATED"));
}

#[test]
fn an_indefinite_response_template_counts_r_apdus_because_it_has_no_count_tlv() {
    // AF 80 <items> 00 00 (TS 102 226 table 5.10a): there is NO 80 number-of-executed TLV.
    let d =
        ota_expanded::decode_response_scripting(&bytes("AF 80 23034F9000 23029000 0000")).unwrap();
    assert_eq!(d.length_coding, LengthCoding::Indefinite);
    assert_eq!(d.template_tag, 0xAF);
    assert_eq!(d.number_of_executed, None);
    assert_eq!(d.executed(), 2, "the count comes from the R-APDUs");
    assert!(d
        .executed_source()
        .contains("carries no number-of-executed"));
    assert_eq!(d.responses.len(), 2);
    assert_eq!(d.last_status_word(), Some("9000"));
}

#[test]
fn an_indefinite_response_template_carries_the_error_tlvs_too() {
    let d =
        ota_expanded::decode_response_scripting(&bytes("AF 80 900102 810101 830103 0000")).unwrap();
    assert_eq!(d.responses.len(), 0);
    assert_eq!(d.executed(), 0);
    assert_eq!(d.bad_format.as_ref().map(|c| c.name), Some("wrong_length"));
    assert_eq!(
        d.immediate_action.as_ref().map(|c| c.name),
        Some("suspension_error")
    );
    assert_eq!(
        d.script_chaining.as_ref().map(|c| c.name),
        Some("unable_to_process")
    );
}

#[test]
fn a_definite_response_template_accepts_the_long_length_form() {
    // 81 0C is a non-minimal but legal BER length for the same 12-octet value.
    let d = ota_expanded::decode_response_scripting(&bytes("AB 81 0C 800102 23034F9000 23029000"))
        .unwrap();
    assert_eq!(d.executed(), 2);
    assert_eq!(d.responses.len(), 2);
}

#[test]
fn response_data_that_ends_in_zero_zero_is_not_mistaken_for_the_end_of_contents() {
    // AF 80 <items> 00 00. The R-APDU TLV value is 00 00 90 00, so the two octets the
    // end-of-contents marker is made of appear INSIDE a definite TLV. Walking the item stream is
    // what keeps them from ending the template early.
    let d = ota_expanded::decode_response_scripting(&bytes("AF 80 230400009000 0000")).unwrap();
    assert_eq!(d.responses.len(), 1);
    assert_eq!(d.responses[0].response_data, "0000");
    assert_eq!(d.responses[0].status_word, "9000");
}

#[test]
fn a_malformed_response_template_is_an_error_and_never_a_partial_answer() {
    // Templates of the wrong kind, and the command template's own tag.
    for bad in [
        "AE 80 2204A0A40000 0000",
        "22 04 A0A40000",
        "AA 06 2204A0A40000",
    ] {
        assert!(
            matches!(
                ota_expanded::decode_response_scripting(&bytes(bad)),
                Err(ota_expanded::Error::WrongTemplate { .. })
            ),
            "{bad} must be refused"
        );
    }

    // An indefinite length where a definite one is required: 23 80 inside a definite template.
    // src/tlv.rs refuses 0x80 as a length, and that error has to reach the caller rather than be
    // smoothed into an answer.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AB 05 800101 2380")),
        Err(ota_expanded::Error::Tlv(tlv::Error::IndefiniteLength))
    ));

    // Truncated: the template declares 7 octets and 5 follow.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AB 07 800101 2301")),
        Err(ota_expanded::Error::Tlv(tlv::Error::UnexpectedEof { .. }))
    ));

    // An indefinite template with no 00 00, and one with octets after it.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AF 80 23034F9000")),
        Err(ota_expanded::Error::MissingEndOfContents)
    ));
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AF 80 23034F9000 0000 AA0100")),
        Err(ota_expanded::Error::TrailingData { remaining: 3, .. })
    ));
    // AF without the 80 marker.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AF 01 00")),
        Err(ota_expanded::Error::MissingIndefiniteMarker)
    ));

    // An R-APDU TLV too short to hold SW1 SW2.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AB 06 800100 230190")),
        Err(ota_expanded::Error::ShortRApdu { length: 1 })
    ));

    // An item tag no table in TS 102 226 5.2.2 defines.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AB 05 800100 7F00")),
        Err(ota_expanded::Error::UnexpectedItem { tag: 0x7F })
    ));

    // Octets after a complete definite template.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&bytes("AB 03 800100 9000")),
        Err(ota_expanded::Error::TrailingData { .. })
    ));

    // Nothing at all.
    assert!(matches!(
        ota_expanded::decode_response_scripting(&[]),
        Err(ota_expanded::Error::Empty)
    ));
}

// ---------------------------------------------------------------------------------------------
// Part 3: the Proof-of-Response (TS 102 225 table 5, TS 31.115)
// ---------------------------------------------------------------------------------------------

#[test]
fn a_por_inside_the_sms_user_data_header_is_decoded() {
    // The worked example in osmocom/pysim pySim/ota.py decode_resp:
    //   027100 000e 0a b00011 0000000000 00 00 01612f
    //   UDHL  RPI RPL  RHL TAR    CNTR       PCNTR STS  secure data
    let p = ota_expanded::decode_por(
        &bytes("027100000e0ab000110000000000000001612f"),
        RemoteFormat::Compact,
    )
    .unwrap();
    assert_eq!(p.uoh.as_deref(), Some("027100"));
    assert_eq!(p.rpl, 14);
    assert_eq!(p.rhl, 10);
    assert_eq!(p.tar, "B00011");
    assert_eq!(p.cntr, "0000000000");
    assert_eq!(p.pcntr, 0);
    assert_eq!(
        (p.response_status.code, p.response_status.name),
        (0, "por_ok")
    );
    assert_eq!(p.cc_rc, "");
    assert_eq!(p.secured_data, "01612F");
    // por_ok and non-empty secure data: there IS a Remote Application structure, compact 5.1.2.
    match p.remote.as_ref().unwrap() {
        ota_expanded::Remote::Compact(c) => {
            assert_eq!(c.number_of_commands, 1);
            assert_eq!(c.last_status_word, "612F");
            assert_eq!(c.last_response_data, "");
        }
        other => panic!("expected the compact structure, got {other:?}"),
    }
    assert!(p.remote_absent_reason().is_none());
}

#[test]
fn the_same_por_without_the_user_data_header_is_decoded_to_the_same_fields() {
    let p = ota_expanded::decode_por(
        &bytes("000e0ab000110000000000000001612f"),
        RemoteFormat::Compact,
    )
    .unwrap();
    assert_eq!(p.uoh, None);
    assert_eq!(p.rpl, 14);
    assert_eq!(p.tar, "B00011");
    assert_eq!(p.secured_data, "01612F");
    assert!(p.remote.is_some());
}

#[test]
fn a_por_carrying_a_cc_and_a_compact_response_is_decoded() {
    // The second worked example in pySim/ota.py: RHL 0x12 = 18, so RHL - 10 = 8 octets of CC/RC/DS
    // sit between the header and the secure data.
    let p = ota_expanded::decode_por(
        &bytes("027100001612b000110000000000000055f47118381175fb01612f"),
        RemoteFormat::Compact,
    )
    .unwrap();
    assert_eq!(p.rhl, 18);
    assert_eq!(p.cc_rc, "55F47118381175FB");
    assert_eq!(p.secured_data, "01612F");
    assert!(matches!(p.remote, Some(ota_expanded::Remote::Compact(_))));
}

#[test]
fn a_por_whose_secure_data_is_an_expanded_response_scripting_template() {
    // RPL 0x19 = 25 = RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STS(1) + a 14-octet definite
    // Response Scripting template. The template is the hand-written vector from above, so this
    // does not depend on the encoder.
    let por = "027100 0019 0A B00011 0000000000 00 00 AB0C80010223034F900023029000";
    let p = ota_expanded::decode_por(&bytes(por), RemoteFormat::Expanded).unwrap();
    assert_eq!(p.rpl, 25);
    assert_eq!(p.rhl, 10);
    assert_eq!(p.cc_rc, "");
    match p.remote.as_ref().unwrap() {
        ota_expanded::Remote::Expanded(e) => {
            assert_eq!(e.executed(), 2);
            assert_eq!(e.responses.len(), 2);
            assert_eq!(e.responses[0].status_word, "9000");
        }
        other => panic!("expected the expanded structure, got {other:?}"),
    }
    // The same secure data read as compact is a command count of 0xAB and a status word of 0x0C80,
    // which is not what the template says: the --remote-format choice is not cosmetic.
    let compact = ota_expanded::decode_por(&bytes(por), RemoteFormat::Compact).unwrap();
    match compact.remote.as_ref().unwrap() {
        ota_expanded::Remote::Compact(c) => {
            assert_eq!(c.number_of_commands, 0xAB);
            assert_eq!(c.last_status_word, "0C80");
        }
        other => panic!("expected the compact structure, got {other:?}"),
    }
}

#[test]
fn every_named_response_status_is_reported_by_name_and_by_number() {
    let named = [
        (0x00u8, "por_ok"),
        (0x01, "rc_cc_ds_failed"),
        (0x02, "cntr_low"),
        (0x03, "cntr_high"),
        (0x04, "cntr_blocked"),
        (0x05, "ciphering_error"),
        (0x06, "undefined_security_error"),
        (0x07, "insufficient_memory"),
        (0x08, "more_time_needed"),
        (0x09, "tar_unknown"),
        (0x0A, "insufficient_security_level"),
        (0x0B, "actual_response_sms_submit"),
        (0x0C, "actual_response_ussd"),
    ];
    for (code, name) in named {
        assert_eq!(ota_expanded::response_status_name(code), Some(name));
        let p = ota_expanded::decode_por(&header_only_por(code), RemoteFormat::Compact).unwrap();
        assert_eq!(
            (p.response_status.code, p.response_status.name),
            (code, name)
        );
        assert_eq!(p.tar, "B00011");
        assert_eq!(p.secured_data, "");
        // An empty secure data means there is no Remote Application structure whatever the status.
        assert!(p.remote.is_none());
        assert!(p.remote_absent_reason().is_some());
    }
}

#[test]
fn an_unassigned_response_status_is_kept_as_an_extension_and_not_guessed() {
    let p = ota_expanded::decode_por(&header_only_por(0x0F), RemoteFormat::Compact).unwrap();
    assert_eq!(p.response_status.code, 0x0F);
    assert_eq!(p.response_status.name, "unassigned");
    assert_eq!(ota_expanded::response_status_name(0x0F), None);
    assert!(p.json()["response_status"]["name"] == "unassigned");
}

#[test]
fn por_ok_with_no_secure_data_has_no_remote_structure() {
    let p = ota_expanded::decode_por(&header_only_por(0x00), RemoteFormat::Compact).unwrap();
    assert_eq!(p.response_status.name, "por_ok");
    assert_eq!(p.secured_data, "");
    assert!(p.remote.is_none());
    assert!(p.remote_absent_reason().unwrap().contains("empty"));
}

#[test]
fn a_por_whose_own_lengths_disagree_is_an_error() {
    // RPL says 12 but 11 octets follow it.
    let mut wrong_rpl = header_only_por(0x00);
    wrong_rpl[1] = 0x0C;
    assert!(matches!(
        ota_expanded::decode_por(&wrong_rpl, RemoteFormat::Compact),
        Err(ota_expanded::Error::RpLLength {
            rpl: 12,
            actual: 11
        })
    ));
    // Shorter than the header that carries the response status.
    assert!(matches!(
        ota_expanded::decode_por(&header_only_por(0x00)[..5], RemoteFormat::Compact),
        Err(ota_expanded::Error::ShortPor { have: 5 })
    ));
    // RHL below the ten header octets it has to cover.
    let mut short_rhl = header_only_por(0x00);
    short_rhl[2] = 9;
    assert!(matches!(
        ota_expanded::decode_por(&short_rhl, RemoteFormat::Compact),
        Err(ota_expanded::Error::ShortRhl { rhl: 9 })
    ));
    // RHL that leaves nothing for the secure data.
    let mut wide_rhl = header_only_por(0x00);
    wide_rhl[2] = 20;
    assert!(matches!(
        ota_expanded::decode_por(&wide_rhl, RemoteFormat::Compact),
        Err(ota_expanded::Error::RhlOverflow { rpl: 11, rhl: 20 })
    ));
    // por_ok whose secure data is too short for a compact command count and status word.
    assert!(matches!(
        ota_expanded::decode_por(&por(0x00, &[], &[0x41, 0x23]), RemoteFormat::Compact),
        Err(ota_expanded::Error::ShortCompact { length: 2 })
    ));
    // Expanded asked for over secure data that is not a Response Scripting template.
    assert!(matches!(
        ota_expanded::decode_por(&por(0x00, &[], &[0x01, 0x61, 0x2F]), RemoteFormat::Expanded),
        Err(ota_expanded::Error::WrongTemplate { tag: 0x01, .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// The CLI: one envelope, human table, exit codes, sanitised card text
// ---------------------------------------------------------------------------------------------

#[test]
fn encode_emits_one_envelope_and_a_human_table() {
    let (code, d, _) = run(&["encode", "A0A40000"]);
    assert_eq!(code, Some(0));
    assert_eq!(d["card_touched"], false);
    assert_eq!(d["template"], "AA062204A0A40000");
    assert!(d["note"].as_str().unwrap().contains("HTTPS and CoAP"));

    let (code, human) = run_human(&[
        "encode",
        "A0A40000",
        "00A4040007A0000000030000",
        "--indefinite",
    ]);
    assert_eq!(code, Some(0));
    assert!(human.contains("indefinite length coding"), "{human}");
    assert!(
        human.contains("AE802204A0A40000220C00A4040007A00000000300000000"),
        "{human}"
    );
    assert!(human.contains("not for SMS"), "{human}");
}

#[test]
fn decode_reports_the_fields_through_the_cli() {
    let (code, d, _) = run(&["decode", "AB0C80010223034F900023029000"]);
    assert_eq!(code, Some(0));
    assert_eq!(d["number_of_executed"], 2);
    assert_eq!(d["response_count"], 2);
    assert_eq!(d["last_status_word"], "9000");
    assert_eq!(d["truncated"], false);
    assert_eq!(d["bad_format"], serde_json::Value::Null);

    // Indefinite: the count is counted from the R-APDUs and the report says where it came from.
    let (code, d, _) = run(&["decode", "AF8023034F9000230290000000"]);
    assert_eq!(code, Some(0));
    assert_eq!(d["number_of_executed_declared"], serde_json::Value::Null);
    assert_eq!(d["number_of_executed"], 2);
    assert!(d["number_of_executed_source"]
        .as_str()
        .unwrap()
        .contains("counted"));
}

#[test]
fn a_malformed_template_exits_2_with_one_envelope_and_no_answer() {
    for bad in ["AB070001012301", "AE802204A0A400000000", "AB058001007F00"] {
        let (code, d, raw) = run(&["decode", bad]);
        assert_eq!(code, Some(2), "{bad} must exit 2");
        assert!(d["error"].is_string(), "{bad}: {raw}");
        assert!(
            !raw.contains("\"responses\""),
            "{bad} must not answer with a guess"
        );
    }
    // Not hex at all.
    assert_eq!(run(&["decode", "zzzz"]).0, Some(2));
}

#[test]
fn por_through_the_cli_names_the_status_and_says_what_was_not_done() {
    let (code, d, _) = run(&["por", "027100000e0ab000110000000000000001612f"]);
    assert_eq!(code, Some(0));
    assert_eq!(d["uoh"], "027100");
    assert_eq!(d["response_status"]["name"], "por_ok");
    assert_eq!(d["remote"]["format"], "compact");
    assert!(d["note"].as_str().unwrap().contains("not deciphered"));
    assert!(d["uoh_note"].as_str().unwrap().contains("02 71 00"));

    // No user data header, and a response status no table names.
    let bare = hex_upper(&header_only_por(0x1F));
    let (code, d, _) = run(&["por", &bare]);
    assert_eq!(code, Some(0));
    assert_eq!(d["uoh"], serde_json::Value::Null);
    assert_eq!(d["response_status"]["code"], 0x1F);
    assert_eq!(d["response_status"]["name"], "unassigned");
    assert_eq!(d["remote"], serde_json::Value::Null);
    assert!(d["remote_absent_reason"].is_string());

    // A malformed PoR exits 2 rather than reporting half a packet.
    assert_eq!(
        run(&["por", &hex_upper(&header_only_por(0)[..5])]).0,
        Some(2)
    );
}

#[test]
fn card_supplied_text_cannot_drive_the_terminal() {
    // The two R-APDU response data fields carry ESC [ 3 1 m (a terminal colour sequence) and
    // U+202E (a bidi override). AGENTS.md, Sanitization: one helper, contract::sanitize, on every
    // human renderer.
    let vector = "AB1580010223071B5B33316D90002307E280AE41429000";
    let (code, human) = run_human(&["decode", vector]);
    assert_eq!(code, Some(0));
    assert!(
        !human.contains('\u{1b}'),
        "ESC reached the terminal: {human:?}"
    );
    assert!(
        !human.contains('\u{202e}'),
        "bidi override reached the terminal: {human:?}"
    );
    assert!(human.contains(" [31m"), "{human}");
    assert!(human.contains(" AB"), "{human}");
    // The JSON keeps the octets as hex; only the human table renders text.
    let (_, d, _) = run(&["decode", vector]);
    assert_eq!(d["responses"][0]["response_data"], "1B5B33316D");
    assert_eq!(d["responses"][1]["response_data"], "E280AE4142");
}
