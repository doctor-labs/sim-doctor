//! `sim-doctor erase` as the binary runs it: the dry run that sends nothing, the
//! WARNING that has to reach --help, the acknowledgements that have to be there
//! before anything is sent, and the exact APDU sequence, pinned through this
//! command line rather than through the unit tests of the plan.
//!
//! No card and no reader is involved, deliberately. The test host has no reader
//! attached, so a dry run that exits 0 IS the evidence that it opened nothing:
//! listing a reader is the first thing every write path does, and this one
//! returns before it.

use std::process::Command;

use sim_doctor::erase;

/// The binary under test, as built by cargo for this integration test.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sim-doctor")
}

fn run(args: &[&str]) -> (String, String, Option<i32>) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("spawn sim-doctor");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// The text with its whitespace collapsed, so a phrase can be found in output
/// that a help page has re-wrapped.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_dry_run_sends_nothing_and_names_what_would_be_erased() {
    let (stdout, stderr, code) = run(&["erase", "--class", "magicsim", "--records", "1"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "", "a dry run has nothing to warn about on stderr");
    assert!(stdout.contains("dry run, nothing was sent"), "{stdout}");
    // Every file, its record range, its length and the instruction.
    for line in [
        "would erase 1 record(s) 2..2 of 3f00/7f4d/8f0c with UPDATE RECORD (INS DC), 18 bytes each",
        "would erase 1 record(s) 1..1 of 3f00/7f4d/8f0d with UPDATE RECORD (INS DC), 130 bytes each",
        "would erase 1 record(s) 1..1 of 3f00/7f4d/8f0e with UPDATE RECORD (INS DC), 102 bytes each",
    ] {
        assert!(stdout.contains(line), "missing {line:?} in\n{stdout}");
    }
    // The WARNING, whole.
    assert!(
        words(&stdout).contains(&words(erase::WARNING)),
        "the dry run does not carry the WARNING"
    );
    // Nothing came back from anything.
    assert!(!stdout.contains("90 00"), "{stdout}");
}

#[test]
fn the_exact_apdu_sequence_is_pinned_through_this_command_line() {
    let (stdout, stderr, code) = run(&["erase", "--class", "magicsim", "--records", "2", "--json"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let envelope: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{stdout}: {e}"));
    assert_eq!(envelope["type"], "program-erase");
    let data = &envelope["payload"]["data"];
    assert_eq!(data["card_touched"], false);
    assert_eq!(data["records"], 2);
    assert_eq!(data["warning"], erase::WARNING);

    // The reference's order: the record index is the OUTER loop, the file table
    // the inner one, and MF is re-selected before every single file. This is
    // MagicSim over two record slots: 8f0c rec 2, 8f0d rec 1, 8f0e rec 1, then
    // 8f0c rec 3, 8f0d rec 2, 8f0e rec 2.
    let expected = [
        "00A400023F0000".to_owned(),
        "00A400027F4D00".to_owned(),
        "00A400028F0C00".to_owned(),
        "00DC020412FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000".to_owned(),
        "00A400023F0000".to_owned(),
        "00A400027F4D00".to_owned(),
        "00A400028F0D00".to_owned(),
        format!("00DC010482{}", "FF".repeat(130)),
        "00A400023F0000".to_owned(),
        "00A400027F4D00".to_owned(),
        "00A400028F0E00".to_owned(),
        format!("00DC010466{}", "FF".repeat(102)),
        "00A400023F0000".to_owned(),
        "00A400027F4D00".to_owned(),
        "00A400028F0C00".to_owned(),
        "00DC030412FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000".to_owned(),
        "00A400023F0000".to_owned(),
        "00A400027F4D00".to_owned(),
        "00A400028F0D00".to_owned(),
        format!("00DC020482{}", "FF".repeat(130)),
        "00A400023F0000".to_owned(),
        "00A400027F4D00".to_owned(),
        "00A400028F0E00".to_owned(),
        format!("00DC020466{}", "FF".repeat(102)),
    ];
    let steps = data["steps"].as_array().expect("steps");
    let sent: Vec<&str> = steps
        .iter()
        .map(|step| step["apdu"].as_str().expect("an apdu"))
        .collect();
    assert_eq!(sent.len(), expected.len(), "{stdout}");
    for (index, (got, want)) in sent.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "step {index} of the plan");
    }
    // Every step names the instruction it is, and no step is a delete.
    for step in steps {
        let what = step["what"].as_str().expect("what");
        assert!(
            what.contains("select") || what.contains("UPDATE RECORD"),
            "{what} names no instruction"
        );
    }
    // The instruction byte of every step: SELECT, UPDATE RECORD, READ of the
    // plan... and in a sent run READ RECORD for the re-read. Never a
    // GlobalPlatform DELETE (E0) or ERASE (E2).
    let instructions: Vec<&str> = sent.iter().map(|apdu| &apdu[2..4]).collect();
    assert!(
        instructions.iter().all(|ins| ["A4", "DC"].contains(ins)),
        "{instructions:?}"
    );
    assert!(
        !instructions.iter().any(|ins| ["E0", "E2"].contains(ins)),
        "{instructions:?}"
    );
}

#[test]
fn the_warning_reaches_help() {
    let (stdout, _, code) = run(&["erase", "--help"]);
    assert_eq!(code, Some(0));
    assert!(
        words(&stdout).contains(&words(erase::WARNING)),
        "erase --help does not carry the WARNING:\n{stdout}"
    );
    // The two facts the help says cannot be guessed are on it, because a help
    // page that hid the refusals would make the operator find out at run time.
    assert!(stdout.contains("--class"), "{stdout}");
    assert!(stdout.contains("--records"), "{stdout}");
    // Every class the erase engine knows is offered by --class, so the flag
    // cannot fall behind the plan it selects.
    for (_, name) in erase::CardClass::all() {
        assert!(
            stdout.contains(name),
            "--class does not offer {name}:\n{stdout}"
        );
    }
    // The top-level help lists the command, so it is discoverable without
    // knowing the name in advance.
    let (top, _, code) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(top.contains("erase"), "{top}");
}

#[test]
fn yes_without_a_key_source_is_refused() {
    let (stdout, stderr, code) = run(&[
        "erase",
        "--class",
        "magicsim",
        "--records",
        "1",
        "--yes",
        "--confirm-iccid",
        "89141122334455667788",
        "--json",
    ]);
    assert_ne!(code, Some(0), "a send with no keys was not refused");
    assert!(!stdout.contains("90 00"), "{stdout}");
    assert!(
        stderr.contains("--keys-file") && stderr.contains("--keys-env"),
        "the refusal does not name the key sources: {stderr}"
    );
}

#[test]
fn yes_without_confirming_the_iccid_is_refused() {
    let (stdout, stderr, code) = run(&[
        "erase",
        "--class",
        "magicsim",
        "--records",
        "1",
        "--yes",
        "--keys-env",
        "SIM_DOCTOR_TEST_KEYS",
        "--json",
    ]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("--confirm-iccid"), "{stderr}");
    assert!(stderr.contains("permanent"), "{stderr}");
    // The refusal is named, so an agent can branch on it rather than on the prose.
    assert!(stdout.contains("confirm-required"), "{stdout}");
}

#[test]
fn a_missing_record_count_is_reported_rather_than_defaulted() {
    let (stdout, stderr, code) = run(&["erase", "--class", "magicsim"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("--records is required"), "{stderr}");
    assert!(stderr.contains("no default"), "{stderr}");
    // It names where the reference reads the count from, so the refusal is a
    // way out and not just a wall.
    assert!(stderr.contains("8F0C"), "{stderr}");
    assert!(stderr.contains("FCP"), "{stderr}");
    // And it did not fall back to a plan.
    assert!(!stdout.contains("UPDATE RECORD"), "{stdout}");
    assert!(!stdout.contains("90 00"), "{stdout}");
}

#[test]
fn a_missing_class_is_reported_rather_than_defaulted() {
    let (stdout, stderr, code) = run(&["erase", "--records", "1", "--json"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("--class is required"), "{stderr}");
    assert!(stderr.contains("magicsim"), "{stderr}");
    assert!(stdout.contains("class-unknown"), "{stdout}");
    assert!(!stdout.contains("UPDATE RECORD"), "{stdout}");
}
