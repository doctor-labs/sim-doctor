//! ACTIVATE FILE / DEACTIVATE FILE (sim-doctor #185).
//!
//! Byte layout is TS 31.101 clause 11.1: CLA 0x00, P1 0x00, P2 0x00 with the two-octet
//! file identifier in the data field. INS values are the ones the repo already names in
//! src/apdu_fuzz.rs (`0x44` ACTIVATE FILE, `0x04` DEACTIVATE FILE).
//!
//! Ground truth was probed against `apdu::Command::encode` itself before this file was
//! written: `Body::Data([0x2F,0x00])` under `Header::new(0x00,0x44,0x00,0x00)` encodes to
//! `[00,44,00,00,02,2F,00]`, and a logical channel of 1 replaces the class byte with `0x01`.

use sim_doctor::cardsh::{activate_file_command, deactivate_file_command, is_read_only};

#[test]
fn activate_and_deactivate_file_build_the_right_apdu_and_are_gated() {
    // ACTIVATE FILE (INS 0x44): P1 = 0x00, P2 = 0x00, body = the two-octet file ID (EF.GID1).
    assert_eq!(
        activate_file_command(0, &[0x2F, 0x00]).encode().unwrap(),
        vec![0x00, 0x44, 0x00, 0x00, 0x02, 0x2F, 0x00]
    );
    // DEACTIVATE FILE (INS 0x04), same shape, EF.ACC (0x6F07).
    assert_eq!(
        deactivate_file_command(0, &[0x6F, 0x07]).encode().unwrap(),
        vec![0x00, 0x04, 0x00, 0x00, 0x02, 0x6F, 0x07]
    );
    // On a logical channel the class byte carries the channel number.
    assert_eq!(
        activate_file_command(1, &[0x2F, 0x00]).encode().unwrap(),
        vec![0x01, 0x44, 0x00, 0x00, 0x02, 0x2F, 0x00]
    );
    // Both change the file lifecycle state, so neither is read-only: the shell gates them
    // behind --yes, exactly like the other card-changing instructions.
    assert!(!is_read_only(0x44));
    assert!(!is_read_only(0x04));
}

#[test]
fn activate_and_deactivate_file_refuse_a_file_id_that_is_not_two_octets() {
    // P2 is 0x00, so the file ID lives in the data field and must be exactly two octets.
    assert!(activate_file_command(0, &[]).is_err());
    assert!(deactivate_file_command(0, &[]).is_err());
    assert!(activate_file_command(0, &[0x2F]).is_err());
    assert!(deactivate_file_command(0, &[0x2F, 0x00, 0x01]).is_err());
}
