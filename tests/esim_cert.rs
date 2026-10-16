//! `sim-doctor esim-cert verify` as the built binary, over a throwaway P-256 chain made with openssl.
//! The clock is fixed with `--at`, so the test does not depend on when it runs.

use std::path::{Path, PathBuf};
use std::process::Command;

const ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkjCCATmgAwIBAgIUYOJljb54sgDgAxJF7YLH9c/A7hMwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBDSSBSb290MB4XDTI2MTAxNTA1MzQzOVoXDTM2MTAx
MjA1MzQzOVowFzEVMBMGA1UEAwwMVGVzdCBDSSBSb290MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE6sxZmeFk6VxyMpvRFn69OAY0bq8mhtYDgPOCd0LXEcQoBcPl
RGa5NKY42H+5siMzt+HBtV23rOvOfqhD1Z5JnqNjMGEwHQYDVR0OBBYEFEtxOYGG
CbfKG+ljqpTzGhixSiAPMB8GA1UdIwQYMBaAFEtxOYGGCbfKG+ljqpTzGhixSiAP
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cA
MEQCIEArb5gvOeNxaK10vR+uqcaT857Jt1VN08oJYkvmbZ52AiBFke8lNiB4yUlk
xi3beTBzlDkFIrUdA4ezDnczCU9wLg==
-----END CERTIFICATE-----
";
const LEAF_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBeTCCASCgAwIBAgICBNIwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMVGVzdCBD
SSBSb290MB4XDTI2MTAxNTA1MzQzOVoXDTMxMTAxNDA1MzQzOVowEzERMA8GA1UE
AwwIVGVzdCBFVU0wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtocQAtt0ZCoGK
4/4xh0bNKm3qz1KE5/2p+ErZhhfISQb9SBd4Hgc7mtqTKt33sCnd2SUTSe+ix/MH
fVmC13SYo2AwXjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQUMb53FfElnqZslFWeBBAmKXzADbMwHwYDVR0jBBgwFoAUS3E5gYYJt8ob6WOq
lPMaGLFKIA8wCgYIKoZIzj0EAwIDRwAwRAIgG7r+idgeU1S2+aBdhNvkhuyTXy9C
M2IOIIskVvtMhvECICPDG2YKnGqzt5Sj6ulwq/ZLI2sH3yjElnCp9JVhudTz
-----END CERTIFICATE-----
";

fn run(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(args)
        .output()
        .expect("sim-doctor runs");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("fixture written");
    path
}

#[test]
fn esim_cert_verify_reports_verified_then_expired_over_the_embedded_chain() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("esim-cert");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let chain = write(&dir, "chain.pem", LEAF_PEM);
    let root = write(&dir, "ci.pem", ROOT_PEM);
    let (chain, root) = (chain.to_str().unwrap(), root.to_str().unwrap());

    // Inside the leaf's validity period: verified, exit 0, no findings.
    let (code, stdout) = run(&[
        "esim-cert",
        "verify",
        chain,
        "--root",
        root,
        "--at",
        "20261015120000",
        "--json",
    ]);
    assert_eq!(code, Some(0), "{stdout}");
    let env: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON envelope");
    assert_eq!(env["type"], "esim-cert");
    assert_eq!(env["payload"]["data"]["verdict"], "verified");
    assert_eq!(env["payload"]["data"]["verified"], true);
    assert_eq!(env["payload"]["data"]["expired_or_not_yet_valid"], false);
    assert_eq!(env["payload"]["data"]["certs"][0]["signature"], "valid");
    assert_eq!(
        env["payload"]["data"]["certs"][0]["key_usage"][0],
        "digitalSignature"
    );
    assert!(env["payload"]["data"]["findings"]
        .as_array()
        .unwrap()
        .is_empty());

    // Same chain, years after notAfter: signatures still verify, but the verdict is not plain good.
    let (code, stdout) = run(&[
        "esim-cert",
        "verify",
        chain,
        "--root",
        root,
        "--at",
        "20400101000000",
        "--json",
    ]);
    assert_eq!(code, Some(1), "{stdout}");
    let env: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON envelope");
    assert_eq!(
        env["payload"]["data"]["verdict"],
        "verified-but-out-of-validity"
    );
    assert_eq!(env["payload"]["data"]["verified"], true);
    assert_eq!(env["payload"]["data"]["expired_or_not_yet_valid"], true);
    assert_eq!(
        env["payload"]["data"]["findings"][0]["code"],
        "validity-expired"
    );

    // A directory is not a regular file: refused, nothing verified.
    let (code, _) = run(&[
        "esim-cert",
        "verify",
        dir.to_str().unwrap(),
        "--root",
        root,
        "--json",
    ]);
    assert_ne!(code, Some(0));
}
