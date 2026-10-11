//! `sim-doctor ota-crypto` as the built binary: offline OTA ciphers and checksums (issue #204).

use std::process::Command;

fn run(args: &[&str]) -> (Option<i32>, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("ota-crypto")
        .args(args)
        .arg("--json")
        .output()
        .unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (out.status.code(), v["payload"]["data"].clone())
}

const AES_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const DES_KEY: &str = "133457799BBCDFF1";

#[test]
fn aes_cbc_matches_nist_sp800_38a() {
    let (code, d) = run(&[
        "encrypt",
        "--alg",
        "aes",
        "--key",
        AES_KEY,
        "--iv",
        "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172a",
    ]);
    assert_eq!(code, Some(0));
    assert_eq!(d["output"], "7649abac8119b246cee98e9b12e9197d");
    let (_, back) = run(&[
        "decrypt",
        "--alg",
        "aes",
        "--key",
        AES_KEY,
        "--iv",
        "000102030405060708090a0b0c0d0e0f",
        "7649abac8119b246cee98e9b12e9197d",
    ]);
    assert_eq!(back["output"], "6bc1bee22e409f96e93d7e117393172a");
}

#[test]
fn des_and_two_key_3des_with_equal_halves_agree_with_the_classic_vector() {
    let (_, d) = run(&[
        "encrypt",
        "--alg",
        "des",
        "--key",
        DES_KEY,
        "0123456789ABCDEF",
    ]);
    assert_eq!(d["output"], "85e813540f0ab405");
    let (_, t) = run(&[
        "encrypt",
        "--alg",
        "3des",
        "--key",
        &format!("{DES_KEY}{DES_KEY}"),
        "0123456789ABCDEF",
    ]);
    assert_eq!(t["output"], "85e813540f0ab405");
}

#[test]
fn sign_and_check_use_aes_cmac_and_des_cbc_mac() {
    let (_, s) = run(&[
        "sign",
        "--alg",
        "aes",
        "--key",
        AES_KEY,
        "6bc1bee22e409f96e93d7e117393172a",
    ]);
    assert_eq!(
        s["mac"], "070a16b46b4d4144",
        "AES-CMAC (RFC 4493) truncated to the 8-byte OTA checksum"
    );
    let (_, full) = run(&[
        "sign",
        "--alg",
        "aes",
        "--key",
        AES_KEY,
        "--mac-len",
        "16",
        "6bc1bee22e409f96e93d7e117393172a",
    ]);
    assert_eq!(full["mac"], "070a16b46b4d4144f79bdd9dd04a287c");
    let (_, d) = run(&["sign", "--alg", "des", "--key", DES_KEY, "0123456789ABCDEF"]);
    assert_eq!(
        d["mac"], "85e813540f0ab405",
        "one-block CBC-MAC with a zero IV is the DES block"
    );
    let (code, ok) = run(&[
        "check",
        "--alg",
        "aes",
        "--key",
        AES_KEY,
        "--mac",
        "070a16b46b4d4144",
        "6bc1bee22e409f96e93d7e117393172a",
    ]);
    assert_eq!(
        (code, ok["valid"].clone()),
        (Some(0), serde_json::json!(true))
    );
    let (code, bad) = run(&[
        "check",
        "--alg",
        "aes",
        "--key",
        AES_KEY,
        "--mac",
        "0000000000000000",
        "6bc1bee22e409f96e93d7e117393172a",
    ]);
    assert_eq!(
        (code, bad["valid"].clone()),
        (Some(1), serde_json::json!(false))
    );
}

#[test]
fn data_that_is_not_a_whole_block_is_refused() {
    let (code, _) = run(&["encrypt", "--alg", "aes", "--key", AES_KEY, "00112233"]);
    assert_eq!(code, Some(2));
}
