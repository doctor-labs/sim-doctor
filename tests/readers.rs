//! `sim-doctor readers` and `scan --reader-index`, through the built binary.
//!
//! No PC/SC service and no card: `SIM_DOCTOR_TEST_REPLAY` (the replay seam,
//! `test-seams` feature) stands in for one reader, which replay names "replay".

use std::path::PathBuf;
use std::process::{Command, Output};

/// One recorded exchange, so the replayed reader exists and has one answer.
const ONE_EXCHANGE: &str = "{\"command\":\"00a4000002\",\"response\":\"9000\"}\n";

fn replay_log(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, ONE_EXCHANGE).expect("write the replay log");
    path
}

fn run(args: &[&str], replay: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(args)
        .env("SIM_DOCTOR_TEST_REPLAY", replay)
        .output()
        .expect("run sim-doctor")
}

#[test]
fn readers_lists_the_replayed_reader_by_index() {
    let log = replay_log("readers_text.log");
    let out = run(&["readers"], &log);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "0  replay\n");
}

#[test]
fn readers_json_is_one_envelope_with_name_and_index() {
    let log = replay_log("readers_json.log");
    let out = run(&["readers", "--json"], &log);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON envelope");
    assert_eq!(envelope["payload"]["data"]["readers"][0]["index"], 0);
    assert_eq!(envelope["payload"]["data"]["readers"][0]["name"], "replay");
}

#[test]
fn reader_index_past_the_end_is_refused_not_guessed() {
    let log = replay_log("reader_index_past_end.log");
    let out = run(
        &["shell", "--json", "--reader-index", "1", "-c", "info"],
        &log,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no reader at index 1"), "stderr: {stderr}");
}

#[test]
fn reader_index_zero_selects_the_one_reader() {
    let log = replay_log("reader_index_zero.log");
    let out = run(
        &["shell", "--json", "--reader-index", "0", "-c", "info"],
        &log,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("no reader at index"), "stderr: {stderr}");
}

#[test]
fn reader_index_and_reader_name_are_mutually_exclusive() {
    let log = replay_log("reader_index_conflict.log");
    let out = run(
        &[
            "shell",
            "--reader",
            "replay",
            "--reader-index",
            "0",
            "-c",
            "info",
        ],
        &log,
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"), "stderr: {stderr}");
}

#[test]
fn scan_reader_index_past_the_end_is_refused() {
    let log = replay_log("scan_reader_index_past_end.log");
    let out = run(&["scan", "--json", "--reader-index", "1"], &log);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no reader at index 1"), "stderr: {stderr}");
}

#[test]
fn scan_reader_index_and_reader_name_are_mutually_exclusive() {
    let log = replay_log("scan_reader_index_conflict.log");
    let out = run(&["scan", "--reader", "replay", "--reader-index", "0"], &log);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"), "stderr: {stderr}");
}
