use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn bin() -> Command {
    Command::new(
        std::env::var_os("CARGO_BIN_EXE_sim-doctor").unwrap_or_else(|| {
            std::ffi::OsString::from(format!(
                "{}/target/debug/sim-doctor{}",
                env!("CARGO_MANIFEST_DIR"),
                std::env::consts::EXE_SUFFIX
            ))
        }),
    )
}

#[test]
fn write_hlr_from_provisioning_csv_creates_mode_0600_sql_script() {
    let dir = std::env::temp_dir().join(format!("sim-doctor-write-hlr-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("prov.csv");
    let out = dir.join("hlr.sql");
    let ki = "000102030405060708090A0B0C0D0E0F";
    let opc = "0F0E0D0C0B0A09080706050403020100";
    fs::write(
        &csv,
        format!(
            "name,iccid,imsi,msisdn,ki,opc\nAlice,8944100000000000001,001010123456789,5550123,{ki},{opc}\n"
        ),
    )
    .unwrap();

    let res = bin()
        .args([
            "card",
            "--read-csv",
            csv.to_str().unwrap(),
            "--write-hlr",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&res.stdout);
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(res.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("wrote 1 subscriber(s)"), "stdout={stdout}");
    let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let script = fs::read_to_string(&out).unwrap();
    assert!(script.contains("INSERT INTO subscriber"));
    assert!(script.contains("INSERT INTO auc_3g"));
    assert!(script.contains("001010123456789"));
    assert!(script.contains("5550123"));
    assert!(script.contains(&ki.to_ascii_lowercase()));
    assert!(!stdout.contains(&ki.to_ascii_lowercase()));
    assert!(!stderr.contains(&ki.to_ascii_lowercase()));

    // never overwrite
    let res2 = bin()
        .args([
            "card",
            "--read-csv",
            csv.to_str().unwrap(),
            "--write-hlr",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!res2.status.success());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_hlr_requires_msisdn_ki_opc() {
    let dir =
        std::env::temp_dir().join(format!("sim-doctor-write-hlr-miss-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("prov.csv");
    let out = dir.join("hlr.sql");
    fs::write(
        &csv,
        "iccid,imsi,ki,opc\n8944100000000000001,001010123456789,000102030405060708090A0B0C0D0E0F,0F0E0D0C0B0A09080706050403020100\n",
    )
    .unwrap();
    let res = bin()
        .args([
            "card",
            "--read-csv",
            csv.to_str().unwrap(),
            "--write-hlr",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!res.status.success());
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("needs imsi, msisdn, ki and opc"),
        "{stderr}"
    );
    assert!(!out.exists());
    let _ = fs::remove_dir_all(&dir);
}
