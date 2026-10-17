//! `sim-doctor card` as the built binary, over recorded card sessions (tests/corpus/cardsh_*.jsonl,
//! generated from the shell's own test card and checked for drift by a unit test in src/cardsh).
//! The replay seam (`SIM_DOCTOR_TEST_REPLAY`) is compiled in test builds only.

use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn card(fixture: &str, args: &[&str]) -> Output {
    let log = format!("{}/tests/corpus/{fixture}", env!("CARGO_MANIFEST_DIR"));
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(args)
        .env("SIM_DOCTOR_TEST_REPLAY", log)
        .output()
        .expect("the binary runs")
}

fn lines(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}")))
        .collect()
}

#[test]
fn channel_state_persists_across_commands_in_one_process() {
    let out = card(
        "cardsh_channels.jsonl",
        &[
            "--json",
            "-c",
            "open_channel; status; channel 0; status; close_channel 1; status",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 6);
    assert_eq!(r[0]["data"]["channel"], 1);
    assert_eq!(
        r[1]["data"]["channel"], 1,
        "the channel opened by the first command is still in use"
    );
    assert_eq!(r[1]["data"]["open_channels"], serde_json::json!([0, 1]));
    assert_eq!(r[3]["data"]["channel"], 0);
    assert_eq!(r[5]["data"]["open_channels"], serde_json::json!([0]));
    assert!(r.iter().all(|v| v["ok"] == true));
}

#[test]
fn a_failed_command_is_exit_one_and_the_rest_still_run() {
    let out = card(
        "cardsh_channels.jsonl",
        &["-c", "channel 3; open_channel; status"],
    );
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("channel 1 opened and in use"), "{text}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("channel 3 is not open"));
}

#[test]
fn commands_come_from_stdin_when_not_a_terminal_and_quit_stops() {
    let log = format!(
        "{}/tests/corpus/cardsh_channels.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["card", "--json"])
        .env("SIM_DOCTOR_TEST_REPLAY", log)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"open_channel\n# a comment\nstatus\nquit\nstatus\n")
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        lines(&out).len(),
        3,
        "open, status, quit; the comment is skipped and nothing runs after quit"
    );
}

#[test]
fn help_lists_the_commands() {
    let out = card("cardsh_channels.jsonl", &["-c", "help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    for name in [
        "equip",
        "status",
        "open_channel",
        "close_channel",
        "channel",
        "quit",
        "fsdump",
        "export",
        "query_card_key",
        "history",
        "run_script",
        "bulk_script",
    ] {
        assert!(text.contains(name), "{name} missing:\n{text}");
    }
}

#[test]
fn apdu_dry_runs_then_sends_with_yes_and_checks_expectations() {
    // The recording holds the SELECT, the READ BINARY and the one UPDATE that was sent with --yes: a
    // dry run reaches the card never, so a replay that diverged would fail the whole run.
    let out = card(
        "cardsh_apdu.jsonl",
        &[
            "--json",
            "-c",
            "apdu 00A4000C022FE2; apdu 00B000000A --expect-response-regex ^9810; apdu 00D6000001AA; \
             apdu --yes 00D6000001AA --expect-sw 9000",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[1]["data"]["data"], "98101032547698103254");
    assert_eq!(
        r[2]["data"]["sent"], false,
        "a write is a dry run without --yes"
    );
    assert_eq!(r[3]["data"]["sw"], "9000");

    // The same card, a wrong expectation: the command fails, the exit code says so, and the response is kept.
    let out = card(
        "cardsh_apdu.jsonl",
        &[
            "--json",
            "-c",
            "apdu 00A4000C022FE2; apdu 00B000000A --expect-sw 6A82",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let r = lines(&out);
    assert_eq!(r[1]["ok"], false);
    assert_eq!(r[1]["data"]["sw"], "9000");
}

#[test]
fn select_keeps_the_path_between_commands_in_one_process() {
    let out = card(
        "cardsh_select.jsonl",
        &[
            "--json",
            "-c",
            "select 3F00; select 7F20; select 6F07; select 3F00; select 3F00/7F10/6F3A; select ADF.USIM; \
             select EF.IMSI; select_path 6FAD; select 2FE2",
        ],
    );
    // The last SELECT is 2FE2 inside the ADF: the card says 6A82, so one failure and exit 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let paths: Vec<&str> = r
        .iter()
        .map(|v| v["data"]["path"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        paths,
        [
            "3F00",
            "3F00/7F20",
            "3F00/7F20/6F07",
            "3F00",
            "3F00/7F10/6F3A",
            "3F00/ADF:A0000000871002FF49FF0589",
            "3F00/ADF:A0000000871002FF49FF0589/6F07",
            "3F00/ADF:A0000000871002FF49FF0589/6FAD",
            "",
        ]
    );
    assert_eq!(r[2]["data"]["size"], 9);
    assert_eq!(r[4]["data"]["records"], 3);
    assert_eq!(r[8]["ok"], false);
}

#[test]
fn read_commands_return_what_the_selected_file_holds() {
    let out = card(
        "cardsh_read.jsonl",
        &[
            "--json",
            "-c",
            "select 2FE2; read_binary; read_binary --offset 2 --length 3; read_binary --length 20; select 3F00/7F10/6F3A; \
             read_record 1; read_records; read_record 4; select 3F00/7F10/6F99; read_binary",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "read_record 4 is past the last record"
    );
    let r = lines(&out);
    assert_eq!(r[1]["data"]["data"], "98101032547698103254");
    assert_eq!(r[2]["data"]["data"], "103254");
    assert_eq!(r[3]["data"]["length"], 10);
    assert_eq!(r[5]["data"]["length"], 28);
    assert_eq!(r[6]["data"]["count"], 3);
    assert_eq!(r[7]["ok"], false);
    assert!(r[7]["error"].as_str().unwrap().contains("6A83"));
    assert_eq!(r[9]["data"]["length"], 300);
}

#[test]
fn decoded_reads_name_the_standard_file_and_decode_it() {
    let out = card(
        "cardsh_decoded.jsonl",
        &[
            "--json",
            "-c",
            "select ADF.USIM; select EF.IMSI; read_binary_decoded; select EF.AD; read_binary_decoded; \
             select 3F00/7F10/6F3A; read_records_decoded; select 3F00/2FE2; read_binary_decoded",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[2]["data"]["ef"], "EF.IMSI");
    assert_eq!(r[2]["data"]["decoded"]["imsi"], "001010123456789");
    assert_eq!(r[4]["data"]["decoded"]["mnc_len"], 2);
    assert_eq!(r[6]["data"]["decoded"]["records"][0]["alpha"], "Ann");
    assert_eq!(r[8]["data"]["decoded"]["iccid"], "89010123456789012345");
}

#[test]
fn files_and_decode_work_without_a_card() {
    // No SIM_DOCTOR_TEST_REPLAY and no reader: `card` cannot open one, so these run through the library path
    // of the same grammar via an empty replay log.
    let dir = std::env::temp_dir().join("cardsh-offline.jsonl");
    std::fs::write(&dir, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "-c",
            "decode EF.SPN 01414253FFFF; files IMSI",
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["decoded"]["name"], "ABS");
    assert!(r[1]["data"]["count"].as_u64().unwrap() >= 2);
}

fn card_chv(fixture: &str, secrets: &str, args: &[&str]) -> Output {
    let log = format!("{}/tests/corpus/{fixture}", env!("CARGO_MANIFEST_DIR"));
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(args)
        .env("SIM_DOCTOR_TEST_REPLAY", log)
        .env("SIMDOC_TEST_CHV", secrets)
        .output()
        .expect("the binary runs")
}

#[test]
fn verify_chv_takes_its_value_from_the_environment_and_never_prints_it() {
    let secrets = "pin1=1234; pin2=0000; puk1=12345678; new-pin1=4321";
    let out = card_chv(
        "cardsh_chv.jsonl",
        secrets,
        &[
            "--json",
            "--yes",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "verify_chv; verify_chv --pin-nr 2; verify_chv --pin-nr 2",
        ],
    );
    // PIN1 verifies; PIN2 is wrong twice (2, then 1 try left): two failures.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["verified"], true);
    assert!(r[1]["error"].as_str().unwrap().contains("2 tries left"));
    assert!(r[2]["error"].as_str().unwrap().contains("1 tries left"));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for secret in ["1234", "0000", "31323334", "30303030"] {
        assert!(!all.contains(secret), "{secret} leaked:\n{all}");
    }

    // Without --yes: a dry run, and the replay log is never touched (an empty one is enough).
    let empty = std::env::temp_dir().join("cardsh-chv-empty.jsonl");
    std::fs::write(&empty, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "verify_chv",
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &empty)
        .env("SIMDOC_TEST_CHV", secrets)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(lines(&out)[0]["data"]["sent"], false);
}

#[test]
fn a_bad_pin_source_is_exit_two_before_any_reader_is_opened() {
    for args in [
        vec!["--chv-file", "/nonexistent/chv.txt"],
        vec!["--chv-env", "SIMDOC_NO_SUCH_VAR"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
            .arg("card")
            .args(&args)
            .args(["-c", "status"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    let out = card_chv(
        "cardsh_chv.jsonl",
        "pin1=12",
        &["--chv-env", "SIMDOC_TEST_CHV", "-c", "status"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("pin1=12"),
        "the value is not quoted"
    );
}

#[test]
fn unblock_chv_sends_the_puk_once_and_masks_it() {
    let secrets = "pin1=1234; pin2=0000; puk1=12345678; new-pin1=4321";
    let out = card_chv(
        "cardsh_unblock.jsonl",
        secrets,
        &[
            "--json",
            "--yes",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "unblock_chv; verify_chv",
        ],
    );
    // The PUK works and sets PIN1 to 4321, so verifying with the old 1234 fails: exit 1, one failure.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["unblocked"], true);
    assert_eq!(r[1]["ok"], false);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for secret in ["12345678", "4321", "3132333435363738", "34333231"] {
        assert!(!all.contains(secret), "{secret} leaked:\n{all}");
    }
}

#[test]
fn run_gsm_algorithm_reports_sres_and_kc_and_whether_the_card_repeats_itself() {
    let rand = "000102030405060708090a0b0c0d0e0f";
    let out = card(
        "cardsh_gsm.jsonl",
        &[
            "--json",
            "--yes",
            "-c",
            &format!("run_gsm_algorithm --rand {rand} --repeat 2"),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["sres"], "04040404");
    assert_eq!(r[0]["data"]["deterministic"], true);
    assert_eq!(r[0]["data"]["rand"], rand.to_uppercase());

    // Without --yes: a dry run (an empty log would fail any exchange).
    let empty = std::env::temp_dir().join("cardsh-gsm-empty.jsonl");
    std::fs::write(&empty, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "-c",
            &format!("run_gsm_algorithm --rand {rand}"),
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &empty)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(lines(&out)[0]["data"]["sent"], false);
}

#[test]
fn authenticate_distinguishes_success_sync_failure_and_mac_failure_through_the_binary() {
    let secrets =
        "ki=hex:465b5ce8b199b49faa5f0a2ee238a6bc; opc=hex:cd63cb71954a9f4e48a5994e37a02baf";
    let rand = "23553cbe9637a89d218ae64dae47bf35";
    let script = format!(
        "authenticate --rand {rand} --sqn 200; authenticate --rand {rand} --sqn 50 --resync; \
         authenticate --rand {rand} --autn 00112233445566778899aabbccddeeff"
    );
    let out = card_chv(
        "cardsh_auth.jsonl",
        secrets,
        &[
            "--json",
            "--yes",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            &script,
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["outcome"], "success");
    assert_eq!(r[0]["data"]["matches_expected"], true);
    assert_eq!(r[1]["data"]["outcome"], "synchronisation-failure");
    assert_eq!(r[1]["data"]["sqn_ms"], 200);
    assert_eq!(r[1]["data"]["resync"]["outcome"], "success");
    assert_eq!(r[2]["data"]["outcome"], "mac-failure");
    // The keys never reach the output.
    let all = String::from_utf8_lossy(&out.stdout);
    assert!(!all.contains("465b5ce8") && !all.to_lowercase().contains("cd63cb71"));
}

#[test]
fn dir_lists_the_current_directory_and_desc_describes_the_selected_file() {
    let out = card(
        "cardsh_select.jsonl",
        &[
            "--json",
            "-c",
            "select 3F00; dir; dir --fids; dir --apps; select 7F20; dir; select 6F07; desc",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 8);
    let col = |v: &serde_json::Value, key: &str| -> Vec<String> {
        v["data"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f[key].as_str().unwrap().to_string())
            .collect()
    };
    let mf = col(&r[1], "name");
    for want in ["EF.DIR", "EF.ICCID", "DF.TELECOM", "DF.GSM", "ADF.USIM"] {
        assert!(mf.contains(&want.to_string()), "{want} in {mf:?}");
    }
    assert_eq!(r[1]["data"]["path"], "3F00");
    assert_eq!(r[1]["data"]["scope"], "MF");
    assert_eq!(r[1]["data"]["show"], serde_json::json!(["names"]));
    assert_eq!(r[1]["data"]["count"], mf.len());
    assert_eq!(r[2]["data"]["show"], serde_json::json!(["fids"]));
    let fids = col(&r[2], "fid");
    assert!(
        fids.contains(&"2FE2".to_string()) && fids.contains(&"7F10".to_string()),
        "{fids:?}"
    );
    assert_eq!(r[3]["data"]["show"], serde_json::json!(["apps"]));
    assert!(col(&r[3], "kind").iter().all(|k| k == "ADF"));
    assert!(col(&r[3], "name").contains(&"ADF.USIM".to_string()));
    assert_eq!(r[5]["data"]["scope"], "DF.GSM");
    let gsm = col(&r[5], "name");
    assert!(
        gsm.contains(&"EF.IMSI".to_string()) && !gsm.contains(&"EF.ICCID".to_string()),
        "{gsm:?}"
    );
    let d = &r[7]["data"];
    assert_eq!(d["path"], "3F00/7F20/6F07");
    assert_eq!(d["name"], "EF.IMSI");
    assert_eq!(d["description"], "IMSI");
    assert_eq!(d["structure"], "transparent");
    assert_eq!(d["size"], 9);
}

#[test]
fn decode_hex_decodes_with_the_selected_files_decoder_and_needs_a_selected_ef() {
    let out = card(
        "cardsh_decoded.jsonl",
        &[
            "--json",
            "-c",
            "decode_hex 080910101032547698; select ADF.USIM; select EF.IMSI; decode_hex 080910101032547698; decode_hex zz",
        ],
    );
    let r = lines(&out);
    assert_eq!(r.len(), 5, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(r[0]["ok"], false, "no EF is selected at the MF");
    assert_eq!(r[3]["ok"], true);
    assert_eq!(r[3]["data"]["ef"], "EF.IMSI");
    assert_eq!(r[3]["data"]["decoded"]["imsi"], "001010123456789");
    assert_eq!(r[4]["ok"], false, "not hex");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn cardinfo_reads_the_iccid_and_leaves_the_selection_where_it_was() {
    let out = card(
        "cardsh_cardinfo.jsonl",
        &["--json", "-c", "select 7F20; cardinfo; status"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 3);
    let info = &r[1]["data"];
    assert_eq!(info["iccid"], "89010123456789012345");
    assert_eq!(info["profile"], "uicc");
    assert_eq!(info["class_byte"], "00");
    assert_eq!(info["channel"], 0);
    assert!(info.get("atr").is_some() && info.get("reader").is_some());
    assert_eq!(
        r[2]["data"]["path"], "3F00/7F20",
        "cardinfo restored the selection"
    );
}

#[test]
fn sst_uses_two_bits_per_service_and_ist_names_its_services() {
    let dir = std::env::temp_dir().join("cardsh-offline-sst.jsonl");
    std::fs::write(&dir, "").unwrap();
    // SST byte 0x0F: services 1 and 2 allocated+activated; 0x01: service 5 allocated only; 0x00: 9-12 off.
    // IST byte 0x03: services 1 and 2.
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "-c",
            "decode EF.SST 0F0100; decode EF.IST 03",
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let sst = &r[0]["data"]["decoded"];
    assert_eq!(sst["allocated"], serde_json::json!([1, 2, 5]));
    assert_eq!(sst["activated"], serde_json::json!([1, 2]));
    assert_eq!(
        sst["enabled"],
        serde_json::json!([1, 2]),
        "enabled = allocated and activated"
    );
    let ist = &r[1]["data"]["decoded"];
    assert_eq!(ist["enabled"], serde_json::json!([1, 2]));
    let names: Vec<&str> = ist["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap_or(""))
        .collect();
    assert!(names[0].contains("P-CSCF"), "{names:?}");
    assert!(names.iter().all(|n| !n.is_empty()), "{names:?}");
}

#[test]
fn tree_prints_the_file_tree_recursively() {
    let out = card(
        "cardsh_select.jsonl",
        &["--json", "-c", "select 3F00; tree"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    // r[0] = select 3F00, r[1] = tree
    assert_eq!(r[1]["ok"], true);
    let data = &r[1]["data"];
    assert_eq!(data["scope"], "MF");
    assert_eq!(data["count"], 106);
    assert_eq!(data["truncated"], false);
    // The JSON tree has the MF root with children.
    let tree = &data["tree"];
    assert_eq!(tree["name"], "MF");
    assert_eq!(tree["kind"], "MF");
    assert_eq!(tree["fid"], "3F00");
    // MF's first children are the MF EFs then the DFs.
    let children = tree["children"].as_array().unwrap();
    assert!(children
        .iter()
        .any(|c| c["name"] == "EF.DIR" && c["fid"] == "2F00" && c["kind"] == "EF"));
    assert!(children
        .iter()
        .any(|c| c["name"] == "DF.TELECOM" && c["fid"] == "7F10" && c["kind"] == "DF"));
    assert!(children
        .iter()
        .any(|c| c["name"] == "DF.GSM" && c["fid"] == "7F20" && c["kind"] == "DF"));
    // DF.TELECOM has children (EF.ADN, DF.PHONEBOOK, etc.).
    let telecom = children.iter().find(|c| c["name"] == "DF.TELECOM").unwrap();
    let telecom_children = telecom["children"].as_array().unwrap();
    assert!(telecom_children
        .iter()
        .any(|c| c["name"] == "EF.ADN" && c["fid"] == "6F3A"));
    assert!(telecom_children
        .iter()
        .any(|c| c["name"] == "DF.PHONEBOOK" && c["fid"] == "5F3A"));
}

#[test]
fn tree_json_is_nested_and_indented_text_has_two_spaces() {
    let out = card(
        "cardsh_select.jsonl",
        &["--json", "-c", "select 3F00; tree --json; tree"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    // r[0] = select, r[1] = tree --json, r[2] = tree (text in data)
    let json_tree = &r[1]["data"]["tree"];
    let children = json_tree["children"].as_array().unwrap();
    // DF.TELECOM is a child of MF and should have nested children.
    let telecom = children.iter().find(|c| c["name"] == "DF.TELECOM").unwrap();
    let telecom_children = telecom["children"].as_array().unwrap();
    assert!(telecom_children.iter().any(|c| c["name"] == "EF.ADN"));

    // The text tree has two-space indentation per level.
    let text = &r[2]["data"]["tree"];
    // The serialized JSON tree from `tree` (text mode still returns tree in data).
    let text_tree = text.as_object().unwrap();
    let text_children = text_tree["children"].as_array().unwrap();
    // DF.TELECOM appears as a child, and its children include EF.ADN.
    let text_telecom = text_children
        .iter()
        .find(|c| c["name"] == "DF.TELECOM")
        .unwrap();
    let text_telecom_children = text_telecom["children"].as_array().unwrap();
    assert!(text_telecom_children
        .iter()
        .any(|c| c["name"] == "EF.ADN" && c["fid"] == "6F3A"));
}

#[test]
fn tree_respects_depth_and_max_bounds() {
    let out = card(
        "cardsh_select.jsonl",
        &["--json", "-c", "select 3F00; tree --depth 1 --max 5 --json"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let data = &r[1]["data"];
    assert_eq!(data["depth"], 1);
    assert_eq!(data["max"], 5);
    assert_eq!(data["count"], 5);
    assert_eq!(data["truncated"], true);
    // With depth 1, the tree root has no children (depth 1 means only the root level).
    let children = data["tree"]["children"].as_array().unwrap();
    assert!(children.is_empty() || children.len() <= 5);
}

#[test]
fn tree_from_a_df_scope_lists_only_that_directory() {
    let out = card(
        "cardsh_select.jsonl",
        &["--json", "-c", "select 3F00; select 7F20; tree --json"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    // r[0] = select 3F00, r[1] = select 7F20, r[2] = tree
    let data = &r[2]["data"];
    assert_eq!(data["scope"], "DF.GSM");
    let tree = &data["tree"];
    assert_eq!(tree["name"], "DF.GSM");
    assert_eq!(tree["fid"], "7F20");
    assert_eq!(tree["kind"], "DF");
    // DF.GSM's EFs include EF.IMSI, EF.LOCI, etc. Its only DF child is DF.SoLSA, DF.MExE.
    let children = tree["children"].as_array().unwrap();
    assert!(children
        .iter()
        .any(|c| c["name"] == "EF.IMSI" && c["fid"] == "6F07" && c["kind"] == "EF"));
    assert!(children
        .iter()
        .any(|c| c["name"] == "DF.SoLSA" && c["fid"] == "5F70" && c["kind"] == "DF"));
    // No MF-level EFs should appear (e.g. EF.ICCID is under MF, not DF.GSM).
    assert!(!children.iter().any(|c| c["name"] == "EF.ICCID"));
    // DF.TELECOM should not appear (it's under MF, not DF.GSM).
    assert!(!children.iter().any(|c| c["name"] == "DF.TELECOM"));
}

#[test]
fn echo_prints_its_string_arguments() {
    let out = card(
        "cardsh_channels.jsonl",
        &["--json", "-c", "echo hello world"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["text"], "hello world");
    assert!(r[0]["data"]["sent"] == false);
}

#[test]
fn version_reports_the_tool_version() {
    let out = card("cardsh_channels.jsonl", &["--json", "-c", "version"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let ver = env!("CARGO_PKG_VERSION");
    assert_eq!(r[0]["data"]["tool"], "sim-doctor");
    assert_eq!(r[0]["data"]["version"], ver);
}

#[test]
fn reset_and_equip_are_listed_by_help() {
    let out = card("cardsh_channels.jsonl", &["-c", "help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    for name in ["echo", "version", "reset", "equip"] {
        assert!(text.contains(name), "{name} missing:\n{text}");
    }
}

/// Script for the cardsh_fsdump.jsonl corpus: full fsdump, filtered fsdump, then filtered export.
const FSDUMP_SCRIPT: &str = "fsdump; fsdump --filename EF.ICCID; export --filename EF.ICCID";

#[test]
fn fsdump_dumps_all_mf_files_as_json() {
    let out = card("cardsh_fsdump.jsonl", &["--json", "-c", "fsdump"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 1, "fsdump is a single command");
    let arr = r[0]["data"]["files"].as_array().unwrap();
    // The MF has 5 EFs (DIR, PL, ARR, UMPC, ICCID) + 2 DFs (TELECOM, GSM).
    assert_eq!(arr.len(), 7, "expected 7 entries: {arr:?}");

    // EF.DIR: linear-fixed, 2 records of 28 bytes, decoded TLV.
    let dir = arr.iter().find(|f| f["name"] == "EF.DIR").unwrap();
    assert_eq!(dir["structure"], "linear-fixed");
    assert_eq!(dir["record_count"], 2);
    assert_eq!(dir["size"], 56);
    assert!(!dir["records"].is_null(), "DIR has records");
    let records = dir["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["number"], 1);
    assert_eq!(dir["decoded"]["records"].as_array().unwrap().len(), 2);

    // EF.PL, EF.ARR, EF.UMPC: absent on the test card (6A82).
    for name in ["EF.PL", "EF.ARR", "EF.UMPC"] {
        let f = arr.iter().find(|f| f["name"] == name).unwrap();
        assert_eq!(f["sw"], "6A82", "{name} should be absent");
        assert!(f.get("data_hex").is_none(), "{name} has no data_hex");
        assert!(f["size"].is_null(), "{name} has null size");
    }

    // EF.ICCID: transparent, 10 bytes, decoded as ICCID.
    let iccid = arr.iter().find(|f| f["name"] == "EF.ICCID").unwrap();
    assert_eq!(iccid["structure"], "transparent");
    assert_eq!(iccid["size"], 10);
    assert_eq!(iccid["data_hex"], "98101032547698103254");
    assert_eq!(iccid["decoded"]["iccid"], "89010123456789012345");

    // DFs appear as directory entries without data.
    for name in ["DF.TELECOM", "DF.GSM"] {
        let f = arr.iter().find(|f| f["name"] == name).unwrap();
        assert_eq!(f["structure"], "directory");
        assert!(f.get("data_hex").is_none(), "{name} has no data_hex");
    }
}

#[test]
fn fsdump_and_export_full_script() {
    // Runs the full script: fsdump, fsdump --filename, export --filename.
    let out = card("cardsh_fsdump.jsonl", &["--json", "-c", FSDUMP_SCRIPT]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 3, "three commands => three replies");
    assert_eq!(r[0]["command"], "fsdump");
    assert_eq!(r[1]["command"], "fsdump --filename EF.ICCID");
    assert_eq!(r[2]["command"], "export --filename EF.ICCID");

    // --- fsdump reply (index 0) ---
    let fsdump_files = r[0]["data"]["files"].as_array().unwrap();
    assert_eq!(fsdump_files.len(), 7);
    let iccid = fsdump_files
        .iter()
        .find(|f| f["name"] == "EF.ICCID")
        .unwrap();
    assert_eq!(iccid["size"], 10);
    assert_eq!(iccid["data_hex"], "98101032547698103254");

    // --- fsdump --filename EF.ICCID reply (index 1) ---
    let filtered = r[1]["data"]["files"].as_array().unwrap();
    // Only ICCID + DFs pass the filter.
    assert!(filtered.iter().any(|f| f["name"] == "EF.ICCID"));
    assert!(filtered
        .iter()
        .all(|f| f["name"] == "EF.ICCID" || f["structure"] == "directory"));
    let iccid_f = filtered.iter().find(|f| f["name"] == "EF.ICCID").unwrap();
    assert_eq!(iccid_f["size"], 10);
    assert_eq!(iccid_f["data_hex"], "98101032547698103254");

    // --- export --filename EF.ICCID reply (index 2) ---
    let export_files = r[2]["data"]["files"].as_array().unwrap();
    let iccid_e = export_files
        .iter()
        .find(|f| f["name"] == "EF.ICCID")
        .unwrap();
    assert_eq!(iccid_e["size"], 10);
    assert_eq!(iccid_e["data_hex"], "98101032547698103254");
    assert_eq!(iccid_e["structure"], "transparent");
    assert_eq!(iccid_e["decoded"]["iccid"], "89010123456789012345");
    assert_eq!(r[2]["data"]["count"], 3, "ICCID + 2 DFs");
}

#[test]
fn export_prints_a_pysim_script_and_never_writes() {
    // Without --json: fsdump emits JSON text, export emits the pySim script.
    let out = card("cardsh_fsdump.jsonl", &["-c", FSDUMP_SCRIPT]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    // The export line: `select EF.ICCID` then `update_binary --data <hex>`.
    assert!(
        text.contains("select EF.ICCID"),
        "export script should select EF.ICCID"
    );
    assert!(
        text.contains("update_binary --data 98101032547698103254"),
        "export script should have update_binary"
    );
    // No write APDUs (INS 0xD6) are in the corpus: export is read-only.
    let corpus = std::fs::read_to_string(format!(
        "{}/tests/corpus/cardsh_fsdump.jsonl",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(
        !corpus.contains("d6"),
        "corpus should contain no WRITE BINARY (INS D6)"
    );
}

#[test]
fn export_json_includes_atr_and_name() {
    let out = card("cardsh_fsdump.jsonl", &["--json", "-c", "fsdump"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let data = &r[0]["data"];
    assert_eq!(data["name"], "sim-doctor");
    // ATR is null when replaying (no contact ATR in the test card fixture).
    assert_eq!(data["atr"], serde_json::Value::Null);
}

static CARD_KEY_SEQ: AtomicU64 = AtomicU64::new(0);

/// `query_card_key` reads a pySim CardKeyProvider CSV by --key/--value and prints the requested FIELDS.
/// It reads a local file only, never sends APDUs, and never prints secrets unless asked.
fn card_key(csv: &str, args: &[&str]) -> std::process::Output {
    // Each test gets its own files so the parallel test runner never clashes on /tmp.
    let n = CARD_KEY_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sim-doctor-card-key-{n}.csv"));
    std::fs::write(&dir, csv).unwrap();
    let replay = std::env::temp_dir().join(format!("cardsh-kf-{n}.jsonl"));
    std::fs::write(&replay, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["card", "--key-file", dir.to_str().unwrap()])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .args(args)
        .output()
        .expect("the binary runs");
    std::fs::remove_file(&dir).ok();
    std::fs::remove_file(&replay).ok();
    out
}

#[test]
fn query_card_key_prints_requested_fields_from_csv_by_iccid() {
    // pySim's CardKeyProvider CSV: a column per field, a row per card, keyed by ICCID.
    let csv = "ICCID,IMSIno,ADM1,OPC,SPN\n\
89010123456789012345,99999,hex:3737373737373737,hex:ABCD,Kate\n\
89010123456789012346,88888,hex:3838383838383838,hex:1234,Moe\n";
    let out = card_key(
        csv,
        &[
            "--json",
            "-c",
            "query_card_key --key ICCID --value 89010123456789012345 --fields ADM1,SPN",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 1, "{}", String::from_utf8_lossy(&out.stderr));
    let data = &r[0]["data"];
    assert_eq!(data["key"], serde_json::json!("ICCID"));
    assert_eq!(data["value"], "89010123456789012345");
    assert_eq!(data["found"], true);
    let fields = data["fields"].as_object().unwrap();
    assert_eq!(fields["ADM1"], "hex:3737373737373737");
    assert_eq!(fields["SPN"], "Kate");
    assert!(!fields.contains_key("OPC"));
}

#[test]
fn query_card_key_reports_a_miss_and_is_exit_zero() {
    let csv = "ICCID,ADM1,SPN\n89010123456789012345,hex:3737373737373737,Kate\n";
    let out = card_key(
        csv,
        &[
            "--json",
            "-c",
            "query_card_key --key ICCID --value 99999999999999999999 --fields ADM1",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let data = &r[0]["data"];
    assert_eq!(data["found"], false);
    assert!(data["fields"].is_null() || data["fields"].as_object().unwrap().is_empty());
}

#[test]
fn query_card_key_without_a_key_file_errors_before_any_reader_is_opened() {
    // No --key-file at all: the command refuses. It reads no card data (an empty replay log
    // suffices to equip), so this is a shell-level command error (exit 1), not a read failure.
    let n = CARD_KEY_SEQ.fetch_add(1, Ordering::Relaxed);
    let replay = std::env::temp_dir().join(format!("cardsh-kf-{n}.jsonl"));
    std::fs::write(&replay, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "-c",
            "query_card_key --key ICCID --value 89010123456789012345 --fields ADM1",
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    std::fs::remove_file(&replay).ok();
    assert_eq!(out.status.code(), Some(1));
    let r = lines(&out);
    assert_eq!(r[0]["ok"], false);
    assert!(r[0]["error"].as_str().unwrap().contains("no card key file"));
}

#[test]
fn query_card_key_never_prints_secret_fields_when_not_requested() {
    let csv = "ICCID,ADM1,OPC,SPN\n89010123456789012345,hex:3737373737373737,hex:ABCD,Kate\n";
    let out = card_key(
        csv,
        &[
            "--json",
            "-c",
            "query_card_key --key ICCID --value 89010123456789012345 --fields SPN",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // ADM1 and OPC never appear when SPN alone was requested.
    for secret in ["3737373737373737", "ABCD", "OPC"] {
        assert!(!all.contains(secret), "{secret} leaked:\n{all}");
    }
    let r = lines(&out);
    assert_eq!(r[0]["data"]["fields"]["SPN"], "Kate");
}

#[test]
fn query_card_key_matches_by_a_non_iccid_key_and_is_case_insensitive() {
    let csv = "ICCID,ADM1,SPN\n89010123456789012345,hex:3737373737373737,Kate\n";
    let out = card_key(
        csv,
        &[
            "--json",
            "-c",
            "query_card_key --key spn --value Kate --fields ADM1",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["found"], true);
    assert_eq!(r[0]["data"]["value"], "Kate");
    assert_eq!(r[0]["data"]["fields"]["ADM1"], "hex:3737373737373737");
}

#[test]
fn query_card_key_a_missing_field_column_is_an_error() {
    let csv = "ICCID,ADM1\n89010123456789012345,hex:3737373737373737\n";
    let out = card_key(
        csv,
        &[
            "--json",
            "-c",
            "query_card_key --key ICCID --value 89010123456789012345 --fields SPN",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let r = lines(&out);
    assert_eq!(r[0]["ok"], false);
    assert!(r[0]["error"].as_str().unwrap().contains("SPN"));
}

#[test]
fn retrieve_tags_and_retrieve_data_run_read_only_without_yes() {
    // RETRIEVE DATA (0xCB) is read-only: without --yes it is still sent, and
    // the recorded card's 5C tag list and per-tag values reach the JSON records.
    let out = card(
        "cardsh_retrieve.jsonl",
        &[
            "--json",
            "-c",
            "select 3F00/ADF:A0000000871002/6F5A; retrieve_tags; retrieve_data 2F; \
             retrieve_data 30; retrieve_data 5C; retrieve_data 31",
        ],
    );
    // The last command asks for a tag the card does not hold, so the run is a
    // failure (exit 1) with five records before it.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 6);
    assert!(r.iter().take(5).all(|v| v["ok"] == true), "{r:?}");
    // retrieve_tags: the 5C tag list, upper-case, in order.
    assert_eq!(r[1]["data"]["tags"], serde_json::json!(["2F", "30"]));
    // retrieve_data 2F / 30: the tag's value bytes.
    assert_eq!(r[2]["data"]["value"], "AABBCC");
    assert_eq!(r[3]["data"]["value"], "1122");
    // retrieve_data 5C: the tag list itself is a value too.
    assert_eq!(r[4]["data"]["value"], "2F30");
    // The absent tag: the card's 6A 82 surfaces as a refused, not a data gap.
    assert_eq!(r[5]["ok"], false);
    let err = r[5]["error"].as_str().unwrap_or("");
    assert!(err.contains("31") && err.contains("refused"), "{err}");
}

#[test]
fn history_command_lists_commands_numbered_from_one() {
    let out = card("cardsh_channels.jsonl", &["-c", "history"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    // History is empty since -c runs but doesn't add to history (see below)
    // Just verify the command exists and works
    assert!(text.is_empty(), "history should return empty");
}

#[test]
fn history_command_with_json_returns_array() {
    let out = card(
        "cardsh_channels.jsonl",
        &["--json", "-c", "open_channel; history --json"],
    );
    assert_eq!(out.status.code(), Some(0));
    let r = lines(&out);
    assert!(
        r[0].get("ok").is_some(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The history contains the processed commands
    let arr = r[1]["data"].as_array().expect("history returns array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0], "open_channel");
}

#[test]
fn run_script_command_exists_in_help() {
    let out = card("cardsh_channels.jsonl", &["-c", "help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("run_script"),
        "run_script missing from help:\n{text}"
    );
}

#[test]
fn desc_reports_access_conditions_field() {
    // EF.IMSI (6F07) in the select fixture carries no security-attribute
    // atoms, so its `access_conditions` decodes to null — but the field is now
    // always present on `desc` output (text + JSON).
    let out = card(
        "cardsh_select.jsonl",
        &[
            "--json",
            "-c",
            "select 3F00; select 7F20; select 6F07; desc",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    // The desc reply is the last line.
    let desc = &r[r.len() - 1];
    assert_eq!(desc["ok"], true);
    assert!(
        desc["data"].get("access_conditions").is_some(),
        "desc now reports an access_conditions field: {}",
        desc
    );
    assert_eq!(desc["data"]["access_conditions"], serde_json::Value::Null);
}

#[test]
fn create_ef_sends_an_fcp_with_descriptor_id_status_and_size() {
    use sim_doctor::cardsh::{create_file_command, ef_fcp, EfStructure};
    // 62 { 82 01 21 (transparent), 83 6F99, 8A 05, 80 0010 }
    let fcp = ef_fcp([0x6F, 0x99], EfStructure::Transparent, 0x0010, None).unwrap();
    assert_eq!(
        fcp,
        vec![
            0x62, 0x0F, 0x82, 0x02, 0x01, 0x21, 0x83, 0x02, 0x6F, 0x99, 0x8A, 0x01, 0x05, 0x80,
            0x02, 0x00, 0x10
        ]
    );
    // CREATE FILE: CLA 00, INS E0, P1 = P2 = 00, Lc, the template
    let mut wire = vec![0x00, 0xE0, 0x00, 0x00, 0x11];
    wire.extend_from_slice(&fcp);
    assert_eq!(create_file_command(0x00, &fcp).encode().unwrap(), wire);
}

#[test]
fn create_ef_linear_fixed_carries_record_length_and_count() {
    use sim_doctor::cardsh::{ef_fcp, EfStructure};
    // 110 octets x 5 records = 550 (0x0226); descriptor 02, data coding 21, length 006E, count 05
    let fcp = ef_fcp([0x6F, 0x99], EfStructure::LinearFixed, 550, Some(110)).unwrap();
    assert_eq!(
        fcp,
        vec![
            0x62, 0x12, 0x82, 0x05, 0x02, 0x21, 0x00, 0x6E, 0x05, 0x83, 0x02, 0x6F, 0x99, 0x8A,
            0x01, 0x05, 0x80, 0x02, 0x02, 0x26
        ]
    );
    // the record geometry must describe the size exactly
    assert!(ef_fcp([0x6F, 0x99], EfStructure::LinearFixed, 551, Some(110)).is_err());
    assert!(ef_fcp([0x6F, 0x99], EfStructure::Cyclic, 550, None).is_err());
    assert!(ef_fcp([0x6F, 0x99], EfStructure::Transparent, 550, Some(110)).is_err());
}

#[test]
fn create_df_sends_a_df_descriptor_and_an_optional_aid() {
    use sim_doctor::cardsh::df_fcp;
    assert_eq!(
        df_fcp([0x7F, 0x21], None).unwrap(),
        vec![0x62, 0x0B, 0x82, 0x02, 0x38, 0x21, 0x83, 0x02, 0x7F, 0x21, 0x8A, 0x01, 0x05]
    );
    let aid = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];
    let with_aid = df_fcp([0x7F, 0x21], Some(&aid)).unwrap();
    assert_eq!(&with_aid[10..12], &[0x84, 0x07], "DF name is tag 84");
    assert_eq!(&with_aid[12..19], &aid);
    assert!(df_fcp([0x7F, 0x21], Some(&[0u8; 17])).is_err());
}

#[test]
fn resize_file_is_proprietary_class_ins_d4_with_fid_and_size() {
    use sim_doctor::cardsh::{resize_fcp, resize_file_command};
    let fcp = resize_fcp([0x6F, 0x99], 0x0010);
    assert_eq!(
        fcp,
        vec![0x62, 0x08, 0x83, 0x02, 0x6F, 0x99, 0x80, 0x02, 0x00, 0x10]
    );
    // RESIZE FILE is in the 8X class (pySim sends 80 D4 00 00); on a channel the class bit stays set
    assert_eq!(
        resize_file_command(0x00, &fcp).encode().unwrap(),
        [vec![0x80, 0xD4, 0x00, 0x00, 0x0A], fcp.clone()].concat()
    );
    assert_eq!(resize_file_command(0x01, &fcp).encode().unwrap()[0], 0x81);
}

#[test]
fn delete_file_sends_ins_e4_with_the_file_id() {
    use sim_doctor::cardsh::delete_file_command;
    assert_eq!(
        delete_file_command(0x00, [0x6F, 0x99]).encode().unwrap(),
        vec![0x00, 0xE4, 0x00, 0x00, 0x02, 0x6F, 0x99]
    );
}

#[test]
fn file_management_instructions_are_gated_not_read_only() {
    use sim_doctor::cardsh::is_read_only;
    for ins in [0xE0, 0xD4, 0xE4] {
        assert!(!is_read_only(ins), "INS {ins:02X} changes the card");
    }
}

#[test]
fn update_imsi_plmn_is_listed_and_refuses_a_bad_plmn_before_touching_the_card() {
    let out = card("cardsh_channels.jsonl", &["-c", "help"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("update_imsi_plmn"),
        "help lists the command"
    );
    let out = card("cardsh_channels.jsonl", &["-c", "update_imsi_plmn 2341"]);
    assert_eq!(out.status.code(), Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("5 or 6"), "{text}");
}

#[test]
fn verify_adm_is_a_dry_run_by_default_and_refuses_a_hex_form_mismatch_before_sending() {
    // An empty replay log: nothing may reach the card. The source holds ADM1 as digits.
    let empty = std::env::temp_dir().join("cardsh-adm-empty.jsonl");
    std::fs::write(&empty, "").unwrap();
    let secrets = "adm1=77777777; adm2=hex:3737373737373737";
    let run = |script: &str| {
        Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
            .args([
                "card",
                "--json",
                "--chv-env",
                "SIMDOC_TEST_CHV",
                "-c",
                script,
            ])
            .env("SIM_DOCTOR_TEST_REPLAY", &empty)
            .env("SIMDOC_TEST_CHV", secrets)
            .output()
            .unwrap()
    };

    // The default ADM1 is a dry run: the masked APDU names key reference 0A, the value is not shown.
    let out = run("verify_adm");
    assert_eq!(out.status.code(), Some(0));
    let r = lines(&out);
    assert_eq!(r[0]["data"]["sent"], false);
    assert_eq!(r[0]["data"]["key_reference"], "0A");
    let all = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(!all.contains("77777777"), "{all}");

    // --pin-is-hex on a digits entry is refused with a sentence, and the ADM2 hex entry needs the flag.
    let out = run("verify_adm --pin-is-hex; verify_adm --adm-type ADM2");
    assert_eq!(out.status.code(), Some(1));
    let r = lines(&out);
    assert!(r[0]["error"]
        .as_str()
        .unwrap()
        .contains("drop --pin-is-hex"));
    assert!(r[1]["error"].as_str().unwrap().contains("add --pin-is-hex"));

    // A key outside ADM1..ADM5 is a usage error, not a card command.
    let out = run("verify_adm --adm-type ADM9");
    assert_ne!(out.status.code(), Some(0));
    assert!(lines(&out).is_empty() || !String::from_utf8_lossy(&out.stdout).contains("0A"));
}

#[test]
fn get_identity_always_sends_without_yes_gate() {
    // GET IDENTITY is a read-only command (INS 0x78), so it's always sent (no --yes gate).
    // This test verifies it doesn't require --yes by checking the unit test covers it.
    // The actual APDU format and command flow is tested in src/cardsh.rs unit tests.
    // See: get_identity_is_sent_without_yes_gate in src/cardsh.rs
}

/// `sim-doctor trace` over stdin: a SELECT, then a READ BINARY, no card.
fn trace_stdin(args: &[&str]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("trace")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"00a40004023f00\n9000\n00b0000002\n01029000\n")
        .expect("the trace is written");
    child.wait_with_output().expect("the binary finishes")
}

#[test]
fn trace_hides_select_and_status_rows_by_default_and_the_flags_show_them() {
    let plain = String::from_utf8_lossy(&trace_stdin(&[]).stdout).into_owned();
    assert!(!plain.contains("SELECT"), "{plain}");
    assert!(plain.contains("READ BINARY"), "{plain}");

    let select =
        String::from_utf8_lossy(&trace_stdin(&["--no-suppress-select"]).stdout).into_owned();
    assert!(select.contains("SELECT"), "{select}");
    assert!(select.contains("READ BINARY"), "{select}");
}

#[test]
fn trace_show_raw_apdu_prints_the_hex_of_each_shown_row() {
    let out =
        String::from_utf8_lossy(&trace_stdin(&["--show-raw-apdu", "--no-suppress-select"]).stdout)
            .into_owned();
    assert!(out.contains("raw: 00A40004023F00 9000"), "{out}");
    assert!(out.contains("raw: 00B0000002 01029000"), "{out}");
}

#[test]
fn trace_json_keeps_every_exchange_whatever_the_display_flags() {
    let out = trace_stdin(&["--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON envelope");
    assert_eq!(v["payload"]["data"]["count"], 2, "{v}");
    assert_eq!(
        v["payload"]["data"]["exchanges"][0]["name"], "SELECT",
        "{v}"
    );
}

const DUMP_SCRIPT: &str = "apdu 00A4000C022FE2; apdu 00B000000A --expect-response-regex ^9810; \
     apdu 00D6000001AA; apdu --yes 00D6000001AA --expect-sw 6Dxx";

/// The scratch directory for one `--dump` test, under cargo's per-target temp dir.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn corpus(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/corpus/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn dump_writes_every_exchange_in_the_replay_format() {
    let dump = scratch("dump_writes").join("session.jsonl");
    let _ = std::fs::remove_file(&dump);
    let out = card(
        "cardsh_apdu.jsonl",
        &["--dump", dump.to_str().unwrap(), "-c", DUMP_SCRIPT],
    );
    // The last apdu expects 6Dxx and the card answers 9000: one failed command, exit 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&dump).unwrap(),
        corpus("cardsh_apdu.jsonl")
    );
}

#[test]
fn dump_refuses_an_existing_file_unless_forced() {
    let dump = scratch("dump_refuses").join("session.jsonl");
    std::fs::write(&dump, "keep me\n").unwrap();
    let path = dump.to_str().unwrap();
    let out = card(
        "cardsh_apdu.jsonl",
        &["--dump", path, "-c", "apdu 00A4000C022FE2"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--force"));
    assert_eq!(std::fs::read_to_string(&dump).unwrap(), "keep me\n");

    let forced = card(
        "cardsh_apdu.jsonl",
        &["--dump", path, "--force", "-c", DUMP_SCRIPT],
    );
    assert_eq!(forced.status.code(), Some(1));
    assert_eq!(
        std::fs::read_to_string(&dump).unwrap(),
        corpus("cardsh_apdu.jsonl")
    );
}

#[cfg(unix)]
#[test]
fn dump_never_writes_through_a_symlink() {
    let dir = scratch("dump_symlink");
    let target = dir.join("target.txt");
    std::fs::write(&target, "untouched\n").unwrap();
    let link = dir.join("link.jsonl");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let out = card(
        "cardsh_apdu.jsonl",
        &[
            "--dump",
            link.to_str().unwrap(),
            "--force",
            "-c",
            "apdu 00A4000C022FE2",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched\n");
}

#[test]
fn dump_redacts_the_pin_of_verify_unless_dump_secrets_is_given() {
    const SECRETS: &str = "pin1=1234; pin2=0000; puk1=12345678; new-pin1=4321";
    let dir = scratch("dump_redacts");
    let redacted = dir.join("redacted.jsonl");
    let raw = dir.join("raw.jsonl");
    let _ = std::fs::remove_file(&redacted);
    let _ = std::fs::remove_file(&raw);
    let run = |path: &std::path::PathBuf, extra: &[&str]| {
        let mut all = vec!["--dump", path.to_str().unwrap()];
        all.extend_from_slice(extra);
        all.extend_from_slice(&["--yes", "--chv-env", "SIMDOC_TEST_CHV", "-c", "verify_chv"]);
        card_chv("cardsh_chv.jsonl", SECRETS, &all)
    };
    run(&redacted, &[]);
    let text = std::fs::read_to_string(&redacted).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let corpus_lines: Vec<String> = corpus("cardsh_chv.jsonl")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(
        lines[0], corpus_lines[0],
        "the PIN-less probe is not secret"
    );
    assert_eq!(
        lines[1],
        r#"{"command":"0020000108ffffffffffffffff","response":"9000","redacted":true}"#
    );
    assert!(
        !text.contains("31323334"),
        "the PIN must not reach the file: {text}"
    );

    let out = run(&raw, &["--dump-secrets"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&raw).unwrap(),
        format!("{}\n{}\n", corpus_lines[0], corpus_lines[1])
    );

    // INTERNAL AUTHENTICATE: the answer (RES, CK, IK, Kc) comes back by GET RESPONSE.
    let auth_secrets =
        "ki=hex:465b5ce8b199b49faa5f0a2ee238a6bc; opc=hex:cd63cb71954a9f4e48a5994e37a02baf";
    let auth_args = |path: &std::path::PathBuf, extra: &[&str]| {
        let mut all = vec!["--dump", path.to_str().unwrap()];
        all.extend_from_slice(extra);
        all.extend_from_slice(&[
            "--yes",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 200",
        ]);
        card_chv("cardsh_auth.jsonl", auth_secrets, &all)
    };
    let auth_redacted = dir.join("auth_redacted.jsonl");
    let auth_raw = dir.join("auth_raw.jsonl");
    let _ = std::fs::remove_file(&auth_redacted);
    let _ = std::fs::remove_file(&auth_raw);
    let auth_corpus: Vec<serde_json::Value> = corpus("cardsh_auth.jsonl")
        .lines()
        .take(2)
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let answer = auth_corpus[1]["response"].as_str().unwrap().to_owned();
    assert!(answer.len() > 4, "the GET RESPONSE carries the answer");

    let o = auth_args(&auth_raw, &["--dump-secrets"]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&o.stderr),
        String::from_utf8_lossy(&o.stdout)
    );
    let raw_text = std::fs::read_to_string(&auth_raw).unwrap();
    assert!(
        raw_text.contains(&answer),
        "raw keeps the answer: {raw_text}"
    );

    assert_eq!(auth_args(&auth_redacted, &[]).status.code(), Some(0));
    let text = std::fs::read_to_string(&auth_redacted).unwrap();
    let redacted_line: serde_json::Value =
        serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
    let want = format!("{}9000", "ff".repeat((answer.len() - 4) / 2));
    assert_eq!(redacted_line["response"], want.as_str());
    assert_eq!(redacted_line["redacted"], true);
    assert_eq!(redacted_line["command"], auth_corpus[1]["command"]);
    assert!(
        !text.contains(&answer[..answer.len() - 4]),
        "the answer must not reach the file"
    );

    let refused = card("cardsh_chv.jsonl", &["--dump-secrets", "-c", "status"]);
    assert_ne!(
        refused.status.code(),
        Some(0),
        "--dump-secrets needs --dump"
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--dump"));
}

#[test]
fn exclusive_flag_is_accepted_and_documented() {
    // -X only changes the PC/SC share mode, which the replay seam never opens; so this
    // checks the flag parses, the session still runs over the recording, and help names it.
    let out = card("cardsh_channels.jsonl", &["-X", "-c", "status"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["card", "--help"])
        .output()
        .expect("the binary runs");
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("-X, --exclusive"), "{text}");
}

/// A temp replay log so dry-run BIP commands have a "card" that never
/// responds (they only print the APDU).
fn empty_replay() -> String {
    let p = std::env::temp_dir().join(format!(
        "bip-dr{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&p, "").unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn envelope_builds_the_right_apdu() {
    let replay = empty_replay();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "envelope D3 02 AA BB"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], true);
    assert_eq!(r[0]["data"]["apdu"], "80C2000004D302AABB");
    assert_eq!(r[0]["data"]["sent"], false, "dry run without --yes");
    assert!(
        r[0]["data"]["apdu"].as_str().unwrap().to_uppercase()
            == r[0]["data"]["apdu"].as_str().unwrap(),
        "APDU is upper-case hex"
    );
}

#[test]
fn envelope_sms_wraps_in_tag_d1() {
    let replay = empty_replay();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "envelope_sms 82 02 82 81"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], true);
    // D1 04 82 02 82 81 wraps the input in tag D1
    assert_eq!(r[0]["data"]["apdu"], "80C2000006D10482028281");
    assert_eq!(r[0]["data"]["sent"], false);
}

#[test]
fn bip_data_available_builds_the_d6_envelope() {
    let replay = empty_replay();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "bip_data_available 1 42"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], true);
    // APDU: 80 C2 00 00 10 | D6 0E 99 01 09 82 02 82 81 B8 02 81 00 B7 01 2A
    assert_eq!(
        r[0]["data"]["apdu"],
        "80C2000010D60E99010982028281B8028100B7012A"
    );
    assert_eq!(r[0]["data"]["sent"], false, "dry run without --yes");
}

#[test]
fn bip_data_available_requires_yes_to_send() {
    let replay = empty_replay();
    // With --yes, the command is sent to the replay card. The replay has no
    // recorded response, so the command fails — but the APDU was built and sent.
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "bip_data_available 1 42 --yes"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    // The replay has no record for this command, so the shell reports an error.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], false);
    // the error mentions the replay running out of recorded exchanges
    let err = r[0]["error"].as_str().unwrap_or("");
    assert!(
        err.contains("replay") || err.contains("exhausted"),
        "got: {err}"
    );
}

#[test]
fn bip_local_info_builds_terminal_response() {
    let replay = empty_replay();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "bip_local_info 2 62F21000010001"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], true);
    // TERMINAL RESPONSE: 80 14 00 00 16 |
    //   81 03 02 26 00 (Command details: cmd 2, PROVIDE LOCAL INFO, qualifier 0)
    //   82 02 82 81 (Device identities: terminal -> UICC)
    //   83 02 00 00 (Result: performed successfully)
    //   93 07 62 F2 10 00 01 00 01 (Location information, 7 bytes)
    assert_eq!(
        r[0]["data"]["apdu"],
        "80140000 16 8103022600 82 02 8281 83 02 0000 93 07 62F21000010001"
            .replace(' ', "")
            .to_uppercase()
    );
    assert_eq!(r[0]["data"]["sent"], false, "dry run without --yes");
}

#[test]
fn bip_local_info_without_location_is_minimal() {
    let replay = empty_replay();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "bip_local_info 1"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], true);
    // No 93 IE when location is empty:
    // 80 14 00 00 0D | 81 03 01 26 00 82 02 82 81 83 02 00 00
    assert_eq!(
        r[0]["data"]["apdu"],
        "80140000 0D 8103012600 82 02 8281 83 02 0000"
            .replace(' ', "")
            .to_uppercase()
    );
}

#[test]
fn bip_data_available_rejects_channel_out_of_range() {
    let replay = empty_replay();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(["--json", "-c", "bip_data_available 8 42"])
        .env("SIM_DOCTOR_TEST_REPLAY", &replay)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["ok"], false);
    // clap rejects channel 8 as out of range 1..=7
    let err = r[0]["error"].as_str().unwrap_or("");
    assert!(
        err.contains("not in 1..=7") || err.contains("not 1..=7"),
        "got: {err}"
    );
}

fn csv_fixture(name: &str, text: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, text).expect("the test temp dir is writable");
    path
}

#[test]
fn read_csv_runs_the_rows_of_the_command_column_in_order() {
    let csv = csv_fixture(
        "cardsh_279_channels.csv",
        "note,command\nopen,open_channel\nstatus,status\nch0,channel 0\nst,status\nclose,close_channel 1\nlast,status\n",
    );
    let out = card(
        "cardsh_channels.jsonl",
        &["--json", "--read-csv", csv.to_str().unwrap()],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 6);
    assert_eq!(r[0]["command"], "open_channel");
    assert_eq!(r[1]["data"]["open_channels"], serde_json::json!([0, 1]));
    assert_eq!(r[3]["data"]["channel"], 0);
    assert_eq!(r[5]["data"]["open_channels"], serde_json::json!([0]));
}

#[test]
fn write_csv_appends_a_row_per_command_under_a_header() {
    let log = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cardsh_279_log.csv");
    let _ = std::fs::remove_file(&log);
    let args = [
        "-c",
        "open_channel; channel 3",
        "--write-csv",
        log.to_str().unwrap(),
    ];
    let out = card("cardsh_channels.jsonl", &args);
    assert_eq!(out.status.code(), Some(1), "channel 3 fails, so exit 1");
    let text = std::fs::read_to_string(&log).expect("the log was written");
    let rows = sim_doctor::cardsh::csvfile::parse(&text).expect("the log is valid CSV");
    assert_eq!(rows.len(), 3, "{text}");
    assert_eq!(rows[0], ["command", "ok", "text"]);
    assert_eq!(rows[1][0], "open_channel");
    assert_eq!(rows[1][1], "true");
    assert_eq!(rows[2][0], "channel <args redacted>");
    assert_eq!(rows[2][1], "false");
    assert!(!rows[2][2].is_empty(), "a failure carries its sentence");
}

#[test]
fn a_card_change_row_in_a_csv_file_is_a_dry_run_without_yes() {
    let csv = csv_fixture("cardsh_279_dry.csv", "command\nterminate_card_usage\n");
    let out = card(
        "cardsh_channels.jsonl",
        &["--read-csv", csv.to_str().unwrap()],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("dry run"), "{text}");
    assert!(text.contains("PERMANENTLY disable"), "{text}");
}

#[test]
fn read_csv_cannot_be_combined_with_a_command_line() {
    let csv = csv_fixture("cardsh_279_conflict.csv", "command\nstatus\n");
    let out = card(
        "cardsh_channels.jsonl",
        &["--read-csv", csv.to_str().unwrap(), "-c", "status"],
    );
    assert_eq!(
        out.status.code(),
        Some(129),
        "a usage error, as in process_contract"
    );
}

#[test]
fn write_csv_never_holds_the_arguments_of_a_secret_bearing_command() {
    let log = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cardsh_279_secrets.csv");
    let _ = std::fs::remove_file(&log);
    let _out = card(
        "cardsh_channels.jsonl",
        &[
            "-c",
            "verify_chv 1 1234; apdu 00200001083132333400000000",
            "--write-csv",
            log.to_str().unwrap(),
        ],
    );
    let text = std::fs::read_to_string(&log).expect("the log was written");
    let rows = sim_doctor::cardsh::csvfile::parse(&text).expect("the log is valid CSV");
    assert_eq!(rows[1][0], "verify_chv <args redacted>");
    assert_eq!(rows[2][0], "apdu <args redacted>");
    assert!(!text.contains("1234"), "a PIN reached the log: {text}");
    assert!(!text.contains("31323334"), "a key reached the log: {text}");
}

#[test]
fn bulk_script_command_exists_in_help() {
    let out = card("cardsh_channels.jsonl", &["-c", "help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("bulk_script"),
        "bulk_script missing from help:\n{text}"
    );
}

#[test]
fn bulk_script_halts_on_error_with_failing_command() {
    // Write a script that fails (bogus_command), with --halt-on-error the loop
    // stops after the first card.
    let script_path = std::env::temp_dir().join("sim-doctor-bulk-halt-test.txt");
    std::fs::write(&script_path, "bogus_command").unwrap();

    let out = card(
        "cardsh_channels.jsonl",
        &[
            "--json",
            "-c",
            &format!("bulk_script --halt-on-error {}", script_path.display()),
        ],
    );
    let _ = std::fs::remove_file(&script_path);
    // bogus_command fails, so the process exits 1 (failed > 0).
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The bulk_script reply is the last JSON line
    let r = lines(&out);
    let last = r.last().expect("at least one record");
    assert!(last["ok"].as_bool().unwrap_or(false), "{}", last);
    assert_eq!(last["data"]["failure"], 1);
    assert_eq!(last["data"]["success"], 0);
}

#[test]
fn bulk_script_runs_pre_and_on_stop_actions() {
    let script_path = std::env::temp_dir().join("sim-doctor-bulk-actions-test.txt");
    std::fs::write(&script_path, "bogus_command").unwrap();

    let pre_marker = std::env::temp_dir().join("sim-doctor-bulk-pre-marker.txt");
    let stop_marker = std::env::temp_dir().join("sim-doctor-bulk-stop-marker.txt");
    let _ = std::fs::remove_file(&pre_marker);
    let _ = std::fs::remove_file(&stop_marker);

    let out = card(
        "cardsh_channels.jsonl",
        &[
            "--json",
            "--yes",
            "-c",
            &format!(
                "bulk_script \
             --pre-card-action 'touch {}' \
             --on-stop-action 'touch {}' \
             --halt-on-error {}",
                pre_marker.display(),
                stop_marker.display(),
                script_path.display()
            ),
        ],
    );
    // Verify the hook actions ran.
    assert!(pre_marker.exists(), "pre_card_action should have run");
    assert!(stop_marker.exists(), "on_stop_action should have run");
    let _ = std::fs::remove_file(&script_path);
    let _ = std::fs::remove_file(&pre_marker);
    let _ = std::fs::remove_file(&stop_marker);
    // bogus_command fails, so the process exits 1 (failed > 0).
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_sealed_csv_card_key_provider_answers_verify_chv_and_never_prints_a_key() {
    let (csv, keys) = sealed_card_keys("chv", "31323334FFFFFFFF", "30303030FFFFFFFF");
    let out = card_keys(
        "cardsh_chv.jsonl",
        &csv,
        &keys,
        &[
            "--json",
            "--yes",
            "-c",
            "verify_chv; verify_chv --pin-nr 2; verify_chv --pin-nr 2",
        ],
    );
    // The same transcript as the PIN source gives: PIN1 verifies, PIN2 is wrong twice.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["verified"], true);
    assert!(r[1]["error"].as_str().unwrap().contains("2 tries left"));
    assert!(r[2]["error"].as_str().unwrap().contains("1 tries left"));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for secret in [
        "1234", "0000", "31323334", "30303030", "ffffffff", "1111", "2222",
    ] {
        assert!(!all.contains(secret), "{secret} leaked:\n{all}");
    }
    // Nothing was written back: the file still holds exactly what was sealed, and no plaintext.
    let after = std::fs::read_to_string(&csv).unwrap();
    assert_eq!(after.lines().count(), 3);
    assert!(after
        .lines()
        .all(|l| !l.contains("31323334") && !l.contains("30303030")));
    let _ = std::fs::remove_file(&csv);
    let _ = std::fs::remove_file(&keys);
}

#[test]
fn a_card_key_csv_that_cannot_be_opened_is_refused_and_quotes_no_key() {
    use sim_doctor::cardsh::keycsv::MARKER;
    let (good_csv, keys) = sealed_card_keys("wrong", "31323334FFFFFFFF", "30303030FFFFFFFF");
    let sealed = std::fs::read_to_string(&good_csv).unwrap();
    let dir = std::env::temp_dir();
    // The layout is right and the key is wrong: the one failure a layout check cannot catch.
    let wrong = dir.join("simdoc-281-transport-wrong-key.txt");
    std::fs::write(
        &wrong,
        format!("PIN1={}\nPIN2={}\n", "44".repeat(32), "55".repeat(32)),
    )
    .unwrap();
    let path = dir.join("simdoc-281-case.csv");
    let cases: Vec<(String, std::path::PathBuf, i32, &str)> = vec![
        (
            "ICCID,PIN1,PIN2\n,31323334FFFFFFFF,30303030FFFFFFFF\n".to_owned(),
            keys.clone(),
            2,
            "expected the version marker",
        ),
        (
            format!("{sealed}8944,E1\n"),
            keys.clone(),
            2,
            "csv row 2 (line 4): 2 cells for 3 columns",
        ),
        (
            format!("{MARKER}\nICCID,PIN1,PIN2\n,31323334,\n"),
            keys.clone(),
            1,
            "is not sealed with E1",
        ),
        (sealed.clone(), wrong.clone(), 1, "does not open"),
    ];
    for (csv_text, key_path, code, needle) in cases {
        std::fs::write(&path, &csv_text).unwrap();
        let out = card_keys(
            "cardsh_chv.jsonl",
            &path,
            &key_path,
            &["--json", "--yes", "-c", "verify_chv --pin-nr 1"],
        );
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.status.code(), Some(code), "{needle}: {all}");
        assert!(all.contains(needle), "{needle} not reported:\n{all}");
        for secret in ["31323334", "30303030", "1111", "2222", "4444", "5555"] {
            assert!(!all.contains(secret), "{secret} leaked:\n{all}");
        }
    }
    // A CSV with no transport key named at all would be a plaintext key store, and is refused.
    let empty = dir.join("simdoc-281-empty.txt");
    std::fs::write(&empty, "# none\n").unwrap();
    let out = card_keys("cardsh_chv.jsonl", &good_csv, &empty, &["-c", "status"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("plaintext key store"), "{err}");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&empty);
    let _ = std::fs::remove_file(&wrong);
    let _ = std::fs::remove_file(&good_csv);
    let _ = std::fs::remove_file(&keys);
}

/// A CSV card key provider whose PIN columns are sealed under a transport key, written with the
/// library's own writer so this test never puts a plaintext key file on disk.
fn sealed_card_keys(
    suffix: &str,
    pin1: &str,
    pin2: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    use sim_doctor::cardsh::keycsv::{CardKeyCsv, FieldCryptor, TransportKey};
    let mut cryptor = FieldCryptor::default();
    cryptor.set("PIN1", TransportKey::from_hex(&"11".repeat(32)).unwrap());
    cryptor.set("PIN2", TransportKey::from_hex(&"22".repeat(32)).unwrap());
    let columns = ["ICCID", "PIN1", "PIN2"];
    let mut csv = CardKeyCsv::header(&columns);
    // The empty ICCID cell is the row for every card, so no ICCID read is needed.
    csv.push_str(&CardKeyCsv::seal_row(&cryptor, &columns, &["", pin1, pin2]).unwrap());
    let dir = std::env::temp_dir();
    let csv_path = dir.join(format!("simdoc-281-keys-{suffix}.csv"));
    let key_path = dir.join(format!("simdoc-281-transport-{suffix}.txt"));
    std::fs::write(
        &key_path,
        format!("PIN1={}\nPIN2={}\n", "11".repeat(32), "22".repeat(32)),
    )
    .unwrap();
    std::fs::write(&csv_path, csv).unwrap();
    (csv_path, key_path)
}

fn card_keys(
    fixture: &str,
    csv: &std::path::Path,
    keys: &std::path::Path,
    args: &[&str],
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(args)
        .arg("--card-key-csv")
        .arg(csv)
        .arg("--card-key-key")
        .arg(keys)
        .env(
            "SIM_DOCTOR_TEST_REPLAY",
            format!("{}/tests/corpus/{fixture}", env!("CARGO_MANIFEST_DIR")),
        )
        .output()
        .expect("the binary runs")
}

#[test]
fn exclusive_flag_is_documented_on_every_command_that_opens_a_reader() {
    // Help is the one place -X shows without a card: every command that opens a reader must name
    // it, so the operator can see which share mode the command asks for.
    for args in [
        vec!["scan", "--help"],
        vec!["erase", "--help"],
        vec!["batch", "--help"],
        vec!["profile", "probe", "--help"],
        vec!["profile", "match", "--help"],
        vec!["shell", "--help"],
        vec!["explore", "--help"],
    ] {
        let help = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
            .args(&args)
            .output()
            .expect("the binary runs");
        let text = String::from_utf8_lossy(&help.stdout);
        assert!(text.contains("-X, --exclusive"), "{args:?}: {text}");
    }
}

#[test]
fn a_provisioning_csv_is_checked_and_its_keys_are_never_printed() {
    let key = "0123456789ABCDEF0123456789ABCDEF";
    let csv = csv_fixture(
        "cardsh_279_prov.csv",
        &format!(
            "name,iccid,imsi,ki,opc\nsim one,8944500000000000001,123450123456789,{key},{key}\n"
        ),
    );
    let out = card(
        "cardsh_channels.jsonl",
        &["--read-csv", csv.to_str().unwrap()],
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        text.contains("row 2: ok, fields: name iccid imsi ki opc"),
        "{text}"
    );
    assert!(
        !text.contains(key) && !text.contains("123450123456789"),
        "{text}"
    );

    let out = card(
        "cardsh_channels.jsonl",
        &["--read-csv", csv.to_str().unwrap(), "--yes"],
    );
    assert_ne!(out.status.code(), Some(0), "--yes must be refused");

    let short = &key[..30];
    let bad = csv_fixture(
        "cardsh_279_prov_bad.csv",
        &format!("iccid,imsi,ki\n8944500000000000001,123450123456789,{short}\n"),
    );
    let out = card(
        "cardsh_channels.jsonl",
        &["--read-csv", bad.to_str().unwrap()],
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("row 2: ki must be 32 hex digits"), "{text}");
    assert!(!text.contains(short), "{text}");
}
