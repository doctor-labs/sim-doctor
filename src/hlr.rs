//! HLR subscriber provisioning as a reviewable SQL script (issue #280, `--write-hlr`).
//!
//! The statements target the current osmo-hlr schema, `sql/hlr.sql` (PRAGMA
//! user_version = 7): table `subscriber` (imsi UNIQUE, msisdn UNIQUE) and table
//! `auc_3g` (subscriber_id PRIMARY KEY; algo_id_3g, k, op, opc, sqn and
//! ind_bitlen, of which op, sqn and ind_bitlen take their schema defaults here).
//! The 3G algorithm id is `OSMO_AUTH_ALG_MILENAGE` = 5 in libosmocore
//! `include/osmocom/crypt/auth.h`, enum osmo_auth_algo.
//!
//! No SQLite binding is in the crate and none may be added, so this module
//! never opens a database. It builds the statements with their parameters and
//! renders them as a script for the sqlite3 shell. The pySim-prog reference
//! (`write_params_hlr`, pySim-prog.py) writes an older Subscriber/AuthKeys layout
//! and says so itself; its SQL is not reused.
//!
//! Refusal is left to the database. A row that conflicts with an existing one
//! (same IMSI with another MSISDN, or another K/OPc, or an MSISDN owned by
//! another IMSI) violates UNIQUE or PRIMARY KEY, and the script runs in one
//! transaction with `.bail on`, so the whole write rolls back. Writing the same
//! subscriber again changes nothing.
//!
//! The script holds K and OPc in clear. The file is created with mode 0600 and
//! an existing file is never overwritten.

use std::fmt;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Module name, as listed in MODULES.
pub const NAME: &str = "hlr";

/// `OSMO_AUTH_ALG_MILENAGE` in libosmocore `include/osmocom/crypt/auth.h`.
pub const ALGO_ID_3G_MILENAGE: i64 = 5;

const SQL_SUBSCRIBER: &str = "INSERT INTO subscriber (imsi, msisdn) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM subscriber WHERE imsi = ? AND msisdn = ?)";
const SQL_AUC_3G: &str = "INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, opc) SELECT id, ?, ?, ? FROM subscriber WHERE imsi = ? AND NOT EXISTS (SELECT 1 FROM auc_3g a WHERE a.subscriber_id = subscriber.id AND a.k = ? AND a.opc = ?)";

const HEADER: &str = "-- sim-doctor HLR provisioning (issue #280). Contains K and OPc in clear: keep this file secret.\n.bail on\nBEGIN IMMEDIATE;\n";

/// One subscriber to provision. Fields are private, so every value passes `Subscriber::new`.
#[derive(Clone, PartialEq, Eq)]
pub struct Subscriber {
    imsi: String,
    msisdn: String,
    k: String,
    opc: String,
}

impl fmt::Debug for Subscriber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Subscriber")
            .field("imsi", &self.imsi)
            .field("msisdn", &self.msisdn)
            .field("k", &"<redacted>")
            .field("opc", &"<redacted>")
            .finish()
    }
}

impl Subscriber {
    /// Checks each field. Error text never echoes a secret value.
    pub fn new(imsi: &str, msisdn: &str, k: &str, opc: &str) -> Result<Self, String> {
        check_digits(imsi, 14, 15, "IMSI")?;
        check_digits(msisdn, 1, 15, "MSISDN")?;
        Ok(Self {
            imsi: imsi.to_string(),
            msisdn: msisdn.to_string(),
            k: check_hex(k, "K")?,
            opc: check_hex(opc, "OPc")?,
        })
    }
}

fn check_digits(value: &str, min: usize, max: usize, what: &str) -> Result<(), String> {
    if (min..=max).contains(&value.len()) && value.chars().all(|c| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err(format!("{what} must be {min} to {max} decimal digits"))
    }
}

/// Returns the hex in lower case, so a stored value and a new one compare equal.
fn check_hex(value: &str, what: &str) -> Result<String, String> {
    if (value.len() == 32 || value.len() == 64) && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err(format!(
            "{what} must be 32 or 64 hex digits (value not shown)"
        ))
    }
}

/// A bound parameter. `Secret` is K or OPc: redacted in every display, and never in Debug.
#[derive(Clone, PartialEq, Eq)]
pub enum Param {
    /// A plain text value, quoted in the script.
    Text(String),
    /// An integer, written bare.
    Int(i64),
    /// K or OPc: redacted in a dry run.
    Secret(String),
}

impl fmt::Debug for Param {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Param::Text(v) => write!(f, "Text({v:?})"),
            Param::Int(n) => write!(f, "Int({n})"),
            Param::Secret(_) => write!(f, "Secret(<redacted>)"),
        }
    }
}

/// One prepared statement: `sql` has a `?` per parameter, in `params` order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// SQL text with one ? per parameter.
    pub sql: String,
    /// Parameters, in placeholder order.
    pub params: Vec<Param>,
}

/// The statements for one subscriber, in execution order.
pub fn statements(s: &Subscriber) -> Vec<Statement> {
    let text = |v: &str| Param::Text(v.to_string());
    let secret = |v: &str| Param::Secret(v.to_string());
    vec![
        Statement {
            sql: SQL_SUBSCRIBER.to_string(),
            params: vec![
                text(&s.imsi),
                text(&s.msisdn),
                text(&s.imsi),
                text(&s.msisdn),
            ],
        },
        Statement {
            sql: SQL_AUC_3G.to_string(),
            params: vec![
                Param::Int(ALGO_ID_3G_MILENAGE),
                secret(&s.k),
                secret(&s.opc),
                text(&s.imsi),
                secret(&s.k),
                secret(&s.opc),
            ],
        },
    ]
}

fn quoted(v: &str) -> String {
    format!("\x27{}\x27", v.replace("\x27", "\x27\x27"))
}

fn literal(p: &Param, redact: bool) -> String {
    match p {
        Param::Int(n) => n.to_string(),
        Param::Text(v) => quoted(v),
        Param::Secret(_) if redact => "<redacted>".to_string(),
        Param::Secret(v) => quoted(v),
    }
}

fn bind(st: &Statement, redact: bool) -> String {
    debug_assert_eq!(st.sql.matches("?").count(), st.params.len());
    let mut pieces = st.sql.split("?");
    let mut out = pieces.next().unwrap_or("").to_string();
    for (piece, p) in pieces.zip(st.params.iter()) {
        out.push_str(&literal(p, redact));
        out.push_str(piece);
    }
    out
}

/// The whole script. `redact` replaces K and OPc with a marker, for a dry run display.
pub fn script(stmts: &[Statement], redact: bool) -> String {
    let mut out = String::from(HEADER);
    for st in stmts {
        out.push_str(&bind(st, redact));
        out.push_str(";\n");
    }
    out.push_str("COMMIT;\n");
    out
}

/// Creates `path` with mode 0600 and writes the unredacted script. An existing path is refused.
pub fn write_new(path: &Path, stmts: &[Statement]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            format!(
                "cannot create {}: {e} (an existing file is never overwritten)",
                path.display()
            )
        })?;
    file.write_all(script(stmts, false).as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}
