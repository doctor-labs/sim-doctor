use sim_doctor::hlr::{self, Param, Subscriber};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const IMSI: &str = "001010123456789";
const MSISDN: &str = "5550123";
const K: &str = "000102030405060708090a0b0c0d0e0f";
const OPC: &str = "0f0e0d0c0b0a09080706050403020100";

fn sub() -> Subscriber {
    Subscriber::new(IMSI, MSISDN, K, OPC).expect("valid test subscriber")
}

/// SQL string literal, written with an escape so this file holds no bare single quote.
fn q(v: &str) -> String {
    format!("\x27{v}\x27")
}

#[test]
fn statements_are_the_exact_sql_with_parameters_in_order() {
    let st = hlr::statements(&sub());
    assert_eq!(st.len(), 2);
    assert_eq!(
        st[0].sql,
        "INSERT INTO subscriber (imsi, msisdn) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM subscriber WHERE imsi = ? AND msisdn = ?)"
    );
    assert_eq!(
        st[0].params,
        vec![
            Param::Text(IMSI.into()),
            Param::Text(MSISDN.into()),
            Param::Text(IMSI.into()),
            Param::Text(MSISDN.into())
        ]
    );
    assert_eq!(
        st[1].sql,
        "INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, opc) SELECT id, ?, ?, ? FROM subscriber WHERE imsi = ? AND NOT EXISTS (SELECT 1 FROM auc_3g a WHERE a.subscriber_id = subscriber.id AND a.k = ? AND a.opc = ?)"
    );
    assert_eq!(
        st[1].params,
        vec![
            Param::Int(5),
            Param::Secret(K.into()),
            Param::Secret(OPC.into()),
            Param::Text(IMSI.into()),
            Param::Secret(K.into()),
            Param::Secret(OPC.into())
        ]
    );
}

#[test]
fn script_inlines_values_and_wraps_one_transaction() {
    let s1 = format!(
        "INSERT INTO subscriber (imsi, msisdn) SELECT {0}, {1} WHERE NOT EXISTS (SELECT 1 FROM subscriber WHERE imsi = {0} AND msisdn = {1})",
        q(IMSI),
        q(MSISDN)
    );
    let s2 = format!(
        "INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, opc) SELECT id, 5, {1}, {2} FROM subscriber WHERE imsi = {0} AND NOT EXISTS (SELECT 1 FROM auc_3g a WHERE a.subscriber_id = subscriber.id AND a.k = {1} AND a.opc = {2})",
        q(IMSI),
        q(K),
        q(OPC)
    );
    let expected = format!(
        "-- sim-doctor HLR provisioning (issue #280). Contains K and OPc in clear: keep this file secret.\n.bail on\nBEGIN IMMEDIATE;\n{s1};\n{s2};\nCOMMIT;\n"
    );
    assert_eq!(hlr::script(&hlr::statements(&sub()), false), expected);
}

#[test]
fn dry_run_output_redacts_k_and_opc_everywhere() {
    let st = hlr::statements(&sub());
    let shown = hlr::script(&st, true);
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains(K) && !shown.contains(OPC));
    assert!(!format!("{:?}", sub()).contains(K));
    assert!(!format!("{:?}", st).contains(OPC));
}

#[test]
fn new_lowercases_hex_and_rejects_bad_lengths() {
    let upper = Subscriber::new(IMSI, MSISDN, "000102030405060708090A0B0C0D0E0F", OPC).unwrap();
    assert!(hlr::script(&hlr::statements(&upper), false).contains(K));
    assert!(Subscriber::new("12", MSISDN, K, OPC).is_err());
    assert!(Subscriber::new(IMSI, MSISDN, "00", OPC).is_err());
    assert!(Subscriber::new(IMSI, "", K, OPC).is_err());
}

#[test]
fn write_new_is_mode_0600_and_refuses_overwrite() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("hlr-280-write-new.sql");
    let _ = std::fs::remove_file(&path);
    let st = hlr::statements(&sub());
    hlr::write_new(&path, &st).expect("first write creates the file");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let before = std::fs::read_to_string(&path).unwrap();
    assert_eq!(before, hlr::script(&st, false));
    assert!(hlr::write_new(&path, &st).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}
