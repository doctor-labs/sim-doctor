//! `-X/--exclusive` with `--simulator` is refused: exit 2, both flags named, no connection tried.

use std::process::Command;

#[test]
fn exclusive_with_simulator_is_refused_with_exit_2() {
    // Port 9 (discard) is closed: had the refusal not come first, the error would be a connect failure.
    let out = Command::new(
        std::env::var_os("CARGO_BIN_EXE_sim-doctor").unwrap_or_else(|| {
            std::ffi::OsString::from(format!(
                "{}/target/debug/sim-doctor{}",
                env!("CARGO_MANIFEST_DIR"),
                std::env::consts::EXE_SUFFIX
            ))
        }),
    )
    .args(["scan", "-X", "--simulator", "127.0.0.1:9"])
    .output()
    .expect("run sim-doctor");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(
        err.contains("--exclusive") && err.contains("--simulator"),
        "{err}"
    );
}
