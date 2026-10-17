//! `sim-doctor fuzz compare` end to end, over two small `fuzz ota` result
//! fixtures. Offline: nothing here touches a reader.

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(args)
        .output()
        .expect("sim-doctor runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn compare_ranks_keysets_and_reports_the_disagreements_as_json() {
    let a = fixture("fuzz_compare_a.json");
    let b = fixture("fuzz_compare_b.json");
    let (code, stdout, stderr) = run(&[
        "fuzz",
        "compare",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON envelope");
    let compare = &value["payload"]["data"]["compare"];
    assert_eq!(compare["common_probes"], 3);
    assert_eq!(compare["excluded_probes"], 0);
    // keyset 1 accepted 3 of 4 (run, triple) pairs; keyset 0 accepted 1 of 2.
    assert_eq!(compare["keysets"][0]["keyset"], 1);
    assert_eq!(compare["keysets"][0]["accepted"], 3);
    assert_eq!(compare["keysets"][1]["keyset"], 0);
    assert_eq!(compare["keysets"][1]["accepted"], 1);
    // Two triples split the runs: TAR 000001 under keysets 0 and 1.
    assert_eq!(compare["disagreements"]["count"], 2);
    assert_eq!(compare["disagreements"]["triples"][0]["tar"], "000001");
}

#[test]
fn compare_text_names_each_run() {
    let a = fixture("fuzz_compare_a.json");
    let b = fixture("fuzz_compare_b.json");
    let (code, stdout, _) = run(&["fuzz", "compare", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("fuzz compare: 2 runs, 3 common probes, 0 excluded"));
    assert!(stdout.contains("disagreements: 2"));
}

#[test]
fn one_file_is_a_usage_error() {
    let a = fixture("fuzz_compare_a.json");
    let (code, _, _) = run(&["fuzz", "compare", a.to_str().unwrap()]);
    assert_eq!(code, 129);
}

#[test]
fn a_file_that_is_not_a_result_is_refused_with_exit_2() {
    let a = fixture("fuzz_compare_a.json");
    let not_a_result = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let (code, _, stderr) = run(&[
        "fuzz",
        "compare",
        a.to_str().unwrap(),
        not_a_result.to_str().unwrap(),
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Cargo.toml"), "stderr: {stderr}");
}
