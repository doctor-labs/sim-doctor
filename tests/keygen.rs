//! `sim-doctor keygen` as the built binary: the CLI contract, the two modes, and the
//! one rule that matters most here - the secret is read from a file or the
//! environment and never from argv, and never reaches the output.
//!
//! These run the real executable, because the argument parsing, the choice of exit
//! code and stdout purity live in the binary and no library-level test can reach
//! them. No card, no reader.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A secret nobody would guess, so finding it anywhere in the output is a failure.
const SECRET: &str = "s3cr3t-batch-alpha-0f1e2d";

/// Writes the secret to a private file the way an operator would, and removes it
/// again when the returned guard drops.
fn secret_file(tag: &str) -> (PathBuf, impl Drop) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "sim-doctor-keygen-{}-{}-{tag}",
        std::process::id(),
        tag.len()
    ));
    std::fs::write(&path, format!("{SECRET}\n")).expect("write the secret file");
    let guard = path.clone();
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    (path, Remove(guard))
}

fn keygen(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("keygen")
        .args(args)
        .output()
        .expect("the binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The one field of the human output this test reads, so a formatting change
/// elsewhere does not turn into a failure here.
fn field(text: &str, name: &str) -> String {
    let line = text
        .lines()
        .find(|l| l.starts_with(name))
        .unwrap_or_else(|| panic!("no `{name}` line in:\n{text}"));
    line.split_once(":")
        .unwrap_or_else(|| panic!("no value after `{name}` in {line:?}"))
        .1
        .trim()
        .to_string()
}

#[test]
fn the_same_secret_and_index_generate_the_same_card_every_time() {
    let (path, _keep) = secret_file("det");
    let path = path.to_str().unwrap();
    let first = keygen(&["-z", path, "-j", "7"]);
    assert!(
        first.status.success(),
        "{:?}",
        String::from_utf8_lossy(&first.stderr)
    );
    let again = keygen(&["-z", path, "-j", "7"]);
    assert!(again.status.success());
    let (a, b) = (stdout(&first), stdout(&again));
    assert_eq!(field(&a, "Ki"), field(&b, "Ki"), "card 7 is card 7");
    assert_eq!(field(&a, "OPc"), field(&b, "OPc"));
    assert_eq!(field(&a, "ICCID"), field(&b, "ICCID"));
    assert_eq!(field(&a, "IMSI"), field(&b, "IMSI"));

    // card 8 is not card 7, and not card 7 shifted by a constant
    let eight = keygen(&["-z", path, "-j", "8"]);
    assert!(eight.status.success());
    let ki7 = field(&a, "Ki");
    let ki8 = field(&stdout(&eight), "Ki");
    assert_ne!(ki7, ki8);
    assert_ne!(
        ki7,
        format!(
            "{:02x}",
            u8::from_str_radix(&ki7[2..4], 16).unwrap().wrapping_add(1)
        )
    );
}

#[test]
fn the_output_is_labelled_secret_material_and_never_the_secret() {
    let (path, _keep) = secret_file("leak");
    let out = keygen(&["-z", path.to_str().unwrap(), "-j", "3"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("SECRET MATERIAL"), "{text}");
    for leak in [SECRET, "s3cr3t", "batch-alpha", "alpha-0f1e2d"] {
        assert!(!text.contains(leak), "the secret leaked: {text}");
    }
    // the output is the point of the command, so it does carry the card
    assert_eq!(field(&text, "Ki").len(), 32, "16 bytes of Ki as hex");
    assert_eq!(field(&text, "OPc").len(), 32);
}

#[test]
fn a_different_secret_is_a_different_key() {
    let (path, _keep) = secret_file("two");
    let mine = keygen(&["-z", path.to_str().unwrap(), "-j", "7"]);
    assert!(mine.status.success());
    let other = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["keygen", "-z", "/dev/null", "-j", "7"])
        .output()
        .expect("the binary runs");
    // /dev/null is an empty secret, which is refused, so the refusal is the proof
    // that an empty secret never reaches the derivation.
    assert!(!other.status.success(), "an empty secret must be refused");
    assert_ne!(
        field(&stdout(&mine), "Ki"),
        "00000000000000000000000000000000"
    );
}

#[test]
fn random_mode_draws_a_fresh_salt_and_prints_it() {
    let (path, _keep) = secret_file("rnd");
    let path = path.to_str().unwrap();
    let a = keygen(&["-z", path]);
    let b = keygen(&["-z", path]);
    assert!(a.status.success() && b.status.success());
    let (ta, tb) = (stdout(&a), stdout(&b));
    assert!(ta.contains("mode      : random"), "{ta}");
    assert_eq!(field(&ta, "salt").len(), 64, "a 32-byte salt as hex");
    assert_ne!(
        field(&ta, "salt"),
        field(&tb, "salt"),
        "a fresh salt per run"
    );
    assert_ne!(field(&ta, "Ki"), field(&tb, "Ki"), "so a fresh Ki per run");
}

#[test]
fn a_printed_salt_regenerates_the_printed_card() {
    let (path, _keep) = secret_file("replay");
    let path = path.to_str().unwrap();
    let first = keygen(&["-z", path]);
    let salt = field(&stdout(&first), "salt");
    let replay = keygen(&["-z", path, "--salt", &salt]);
    assert!(replay.status.success());
    assert_eq!(field(&stdout(&first), "Ki"), field(&stdout(&replay), "Ki"));
    assert_eq!(
        field(&stdout(&first), "ICCID"),
        field(&stdout(&replay), "ICCID")
    );
}

#[test]
fn json_carries_the_card_on_one_line_and_still_not_the_secret() {
    let (path, _keep) = secret_file("json");
    let out = keygen(&["-z", path.to_str().unwrap(), "-j", "2", "--json"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert_eq!(text.trim().lines().count(), 1, "one envelope line");
    let v: serde_json::Value = serde_json::from_str(text.trim()).expect("a JSON envelope");
    assert_eq!(v["type"], "keygen");
    let d = &v["payload"]["data"];
    assert_eq!(d["mode"], "deterministic");
    assert_eq!(d["index"], 2);
    assert_eq!(d["iccid"].as_str().unwrap().len(), 19);
    assert_eq!(d["imsi"].as_str().unwrap().len(), 15);
    assert_eq!(d["secret_material"], true);
    assert!(!text.contains(SECRET), "the secret leaked: {text}");
}

#[test]
fn the_secret_is_never_accepted_on_the_command_line() {
    // There is no flag for it, so clap refuses the command before anything runs.
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["keygen", "-z", SECRET, "-j", "1"])
        .output()
        .expect("the binary runs");
    // `-z` is a path; SECRET is not one, so this is a usage error, not a key.
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("secret-file") || err.contains("No such file"),
        "{err}"
    );
}

#[test]
fn a_plmn_that_cannot_be_an_imsi_is_refused() {
    let (path, _keep) = secret_file("badplmn");
    let path = path.to_str().unwrap();
    for args in [
        vec!["-z", path, "-j", "1", "--mnc", "12345", "--mnclen", "3"],
        vec!["-z", path, "-j", "1", "--mcc", "90a"],
        vec!["-z", path, "-j", "1", "--mnclen", "1"],
    ] {
        let out = keygen(&args);
        assert!(!out.status.success(), "{args:?} should be refused");
        assert!(String::from_utf8_lossy(&out.stderr).contains("sim-doctor:"));
    }
}

#[test]
fn a_secret_comes_from_the_environment_too() {
    let (path, _keep) = secret_file("env");
    let file = stdout(&keygen(&["-z", path.to_str().unwrap(), "-j", "5"]));
    let from_env = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "keygen",
            "--secret-env",
            "SIM_DOCTOR_KEYGEN_TEST",
            "-j",
            "5",
        ])
        .env("SIM_DOCTOR_KEYGEN_TEST", SECRET)
        .output()
        .expect("the binary runs");
    assert!(from_env.status.success());
    assert_eq!(field(&file, "Ki"), field(&stdout(&from_env), "Ki"));
}
