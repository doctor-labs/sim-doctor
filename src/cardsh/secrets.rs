//! The PIN / PUK / ADM key provider of the card shell (pySim's `CardKeyProvider`, here a file or an
//! environment variable). Secrets never come from the command line and never reach output: `Debug` is
//! redacted and the shell prints the APDUs that carry them with the data masked.
//!
//! Text format, one entry per line (or separated by `;` in an environment variable):
//!
//! ```text
//! pin1=1234
//! pin2=5678
//! puk1=12345678
//! adm1=hex:3737373737373737
//! 8949000000000000001:pin1=4321     # only for the card with this ICCID
//! ```
//!
//! A value is 4 to 8 ASCII digits (padded with `FF` to 8 octets as the card expects) or `hex:` and
//! octets (8 for a PIN, PUK or ADM key; `ki`, `opc` and `op` are 16 for the authentication commands). Names: `pinN` (1-8), `pukN`, `admN` (1-5), `universal`, `upuk`, `new-pinN` and `new-universal` (the
//! PIN `unblock_chv` sets), `key-XX` (a raw key reference). `#` starts a comment.

use std::fmt;

/// Where the text comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// A file (read up to [`MAX_TEXT`] bytes).
    File(std::path::PathBuf),
    /// An environment variable.
    Env(String),
}

/// Most text read.
pub const MAX_TEXT: u64 = 4096;

#[derive(Clone)]
struct Entry {
    iccid: Option<String>,
    name: String,
    value: Vec<u8>,
    /// Written as `hex:` (true) or as decimal digits (false).
    hex: bool,
}

/// The parsed secrets.
#[derive(Clone, Default)]
pub struct Secrets {
    entries: Vec<Entry>,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secrets({} entries, redacted)", self.entries.len())
    }
}

/// The octets of a value, and whether it was written as `hex:`.
fn value(text: &str) -> Result<(Vec<u8>, bool), String> {
    if let Some(h) = text.strip_prefix("hex:") {
        let b = hex::decode(h).map_err(|_| "a hex: value is not hex".to_owned())?;
        return if (1..=32).contains(&b.len()) {
            Ok((b, true))
        } else {
            Err("a hex: value is 1 to 32 octets".to_owned())
        };
    }
    if !(4..=8).contains(&text.len()) || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("a value is 4 to 8 digits, or hex:".to_owned());
    }
    let mut out = vec![0xFF; 8];
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok((out, false))
}

impl Secrets {
    /// Parses the text. Errors name the line and never quote the value.
    ///
    /// # Errors
    ///
    /// A sentence naming the line number.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (n, line) in text.split(['\n', ';']).enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let bad = |why: &str| format!("entry {}: {why}", n + 1);
            let (key, val) = line
                .split_once('=')
                .ok_or_else(|| bad("expected NAME=VALUE"))?;
            let (iccid, name) = match key.trim().split_once(':') {
                Some((i, nm)) if i.chars().all(|c| c.is_ascii_digit()) && !i.is_empty() => {
                    (Some(i.to_owned()), nm)
                }
                _ => (None, key.trim()),
            };
            let name = name.trim().to_ascii_lowercase();
            if !known(&name) {
                return Err(bad(
                    "unknown name (pinN, pukN, admN, universal, upuk, new-pinN, key-XX)",
                ));
            }
            let (value, hex) = value(val.trim()).map_err(|e| bad(&e))?;
            entries.push(Entry {
                iccid,
                name,
                value,
                hex,
            });
        }
        Ok(Self { entries })
    }

    /// Reads and parses a source.
    ///
    /// # Errors
    ///
    /// The source is unreadable, too long or malformed.
    pub fn load(source: &Source) -> Result<Self, String> {
        use std::io::Read;
        let text = match source {
            Source::Env(name) => std::env::var(name)
                .map_err(|_| format!("environment variable {name} is not set"))?,
            Source::File(path) => {
                let mut text = String::new();
                std::fs::File::open(path)
                    .and_then(|f| f.take(MAX_TEXT + 1).read_to_string(&mut text))
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                text
            }
        };
        if text.len() as u64 > MAX_TEXT {
            return Err("the secrets text is too long".into());
        }
        Self::parse(&text)
    }

    /// Whether an entry called `name` exists (for any card).
    pub fn has(&self, name: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.name == name.to_ascii_lowercase())
    }

    /// Whether some entry is bound to an ICCID (so the card's ICCID has to be read to choose).
    pub fn needs_iccid(&self) -> bool {
        self.entries.iter().any(|e| e.iccid.is_some())
    }

    /// The value for `name` on the card with `iccid` (when known): an entry bound to that ICCID wins
    /// over an unbound one.
    pub fn get(&self, name: &str, iccid: Option<&str>) -> Option<Vec<u8>> {
        self.entry(name, iccid).map(|e| e.value.clone())
    }

    /// Whether the value `get` would pick was written as `hex:`.
    pub fn is_hex(&self, name: &str, iccid: Option<&str>) -> Option<bool> {
        self.entry(name, iccid).map(|e| e.hex)
    }

    fn entry(&self, name: &str, iccid: Option<&str>) -> Option<&Entry> {
        let name = name.to_ascii_lowercase();
        let pick = |bound: bool| {
            self.entries.iter().find(|e| {
                e.name == name
                    && (if bound {
                        e.iccid.as_deref() == iccid && iccid.is_some()
                    } else {
                        e.iccid.is_none()
                    })
            })
        };
        pick(true).or_else(|| pick(false))
    }
}

fn known(name: &str) -> bool {
    let n = |p: &str, lo: u8, hi: u8| {
        name.strip_prefix(p)
            .and_then(|r| r.parse::<u8>().ok())
            .is_some_and(|v| (lo..=hi).contains(&v))
    };
    n("pin", 1, 8)
        || n("puk", 1, 8)
        || n("adm", 1, 5)
        || n("new-pin", 1, 8)
        || matches!(
            name,
            "universal" | "upuk" | "new-universal" | "ki" | "opc" | "op"
        )
        || name
            .strip_prefix("key-")
            .is_some_and(|h| h.len() == 2 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A pySim `CardKeyProvider` CSV reader (pySim-shell's `--key-file`).
///
/// pySim's CSV card-key provider (`CardKeyProviderCsv` in `pySim/card_key_provider.py`)
/// is a header row of field names (case-insensitive, upper-cased internally) with one
/// card per row, keyed by --key (default `ICCID`) and --value. pySim returns `None` when
/// the key column or the card row is missing, and raises when a requested field column is
/// absent. This mirrors that shape: `get` reads only the requested fields for the first
/// row whose key column matches `value`, and errors describe the missing column without
/// quoting any card data.
///
/// Column values are returned verbatim; a `hex:` prefix is not stripped here (the shell's
/// callers decide how to interpret them, matching pySim where the value is passed through
/// to the command that needs it). The file is read with a size ceiling so an untrusted
/// path cannot exhaust memory, and secrets it holds are never logged: `Debug` is redacted.
pub mod csv {
    use std::fs;
    use std::path::Path;

    /// Most bytes accepted from the CSV file.
    pub const MAX_BYTES: u64 = 1 << 20; // 1 MiB is plenty for a card-key roster; pySim reads the whole file.

    /// A row of `field -> value` for one card, keyed by the column named by `key`.
    #[derive(Clone, PartialEq, Eq)]
    pub struct Row {
        /// The matched value of the key column.
        pub key: String,
        /// The requested fields, present only when the column existed. Values are verbatim.
        pub fields: Vec<(String, String)>,
    }

    impl std::fmt::Debug for Row {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Row")
                .field("key", &self.key)
                .field(
                    "fields",
                    &format!("<{} values, redacted>", self.fields.len()),
                )
                .finish()
        }
    }

    impl Row {
        /// The value for `field`, case-insensitively, or `None` when the column was absent.
        pub fn get(&self, field: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(f, _)| f.eq_ignore_ascii_case(field))
                .map(|(_, v)| v.as_str())
        }
    }

    /// The parsed card-key file: columns are case-folded to upper case.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CardKeyFile {
        /// Column names, upper-cased, in file order.
        columns: Vec<String>,
        /// One row per record.
        rows: Vec<Vec<String>>,
    }

    impl CardKeyFile {
        /// Reads and parses the CSV at `path`.
        ///
        /// Errors name the file and never quote its contents.
        pub fn load(path: &Path) -> Result<Self, String> {
            let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            if text.len() as u64 > MAX_BYTES {
                return Err(format!(
                    "{}: the card-key file is larger than {} bytes",
                    path.display(),
                    MAX_BYTES
                ));
            }
            Self::parse(&text)
        }

        /// Parses CSV text. A row must have exactly one field fewer commas than the header.
        pub fn parse(text: &str) -> Result<Self, String> {
            let mut lines = text.lines().peekable();
            let header = lines
                .next()
                .ok_or_else(|| "the card-key file is empty".to_owned())?;
            let columns: Vec<String> = header
                .split(',')
                .map(|c| c.trim().to_ascii_uppercase())
                .collect();
            if columns.is_empty() || columns[0].is_empty() {
                return Err("the card-key file has no header row".to_owned());
            }
            let mut rows = Vec::new();
            for (n, line) in lines.enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() != columns.len() {
                    return Err(format!(
                        "row {}: expected {} fields, found {}",
                        n + 2,
                        columns.len(),
                        fields.len()
                    ));
                }
                rows.push(fields.iter().map(|f| f.trim().to_owned()).collect());
            }
            Ok(Self { columns, rows })
        }

        /// The first row whose `key` column value equals `value` (case-insensitive), returning
        /// the matched key and the values for each `fields` request. pySim raises when a
        /// requested field column is missing; so does this. Returns `Ok(None)` when no row
        /// matched, which a caller reports as a miss rather than an error.
        pub fn get(&self, key: &str, value: &str, fields: &[&str]) -> Result<Option<Row>, String> {
            let key_col = self
                .columns
                .iter()
                .position(|c| c.eq_ignore_ascii_case(key))
                .ok_or_else(|| format!("the card-key file has no `{key}` column"))?;
            // Validate the requested fields up front, mirroring pySim's early refusal.
            for f in fields {
                if !self.columns.iter().any(|c| c.eq_ignore_ascii_case(f)) {
                    return Err(format!("the card-key file has no `{}` column", f));
                }
            }
            for row in &self.rows {
                if row[key_col].eq_ignore_ascii_case(value) {
                    let selected: Vec<(String, String)> = fields
                        .iter()
                        .map(|f| {
                            let col = self
                                .columns
                                .iter()
                                .position(|c| c.eq_ignore_ascii_case(f))
                                .unwrap();
                            (f.to_ascii_uppercase(), row[col].clone())
                        })
                        .collect();
                    return Ok(Some(Row {
                        key: row[key_col].clone(),
                        fields: selected,
                    }));
                }
            }
            Ok(None)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SAMPLE: &str = "ICCID,ADM1,OPC,SPN\n\
            89010123456789012345,hex:3737373737373737,hex:ABCD,Kate\n\
            89010123456789012346,hex:3838383838383838,hex:1234,Moe\n";

        #[test]
        fn finds_a_row_and_the_requested_fields() {
            let f = CardKeyFile::parse(SAMPLE).unwrap();
            let r = f
                .get("ICCID", "89010123456789012345", &["ADM1", "SPN"])
                .unwrap()
                .unwrap();
            assert_eq!(r.key, "89010123456789012345");
            assert_eq!(r.get("adm1"), Some("hex:3737373737373737"));
            assert_eq!(r.get("spn"), Some("Kate"));
            assert!(!r.fields.iter().any(|(n, _)| n == "OPC"));
        }

        #[test]
        fn a_missing_row_is_ok_none() {
            let f = CardKeyFile::parse(SAMPLE).unwrap();
            assert!(f.get("ICCID", "99999", &["ADM1"]).unwrap().is_none());
        }

        #[test]
        fn a_missing_column_is_an_error_without_quoting_values() {
            let f = CardKeyFile::parse("ICCID,ADM1\n89010123456789012345,hex:37\n").unwrap();
            let e = f
                .get("ICCID", "89010123456789012345", &["NOPE"])
                .unwrap_err();
            assert!(e.contains("NOPE"));
            assert!(!e.contains("37"));
        }

        #[test]
        fn a_missing_key_column_is_an_error() {
            let f = CardKeyFile::parse("ADM1,SPN\nhex:37,Kate\n").unwrap();
            let e = f.get("ICCID", "x", &["ADM1"]).unwrap_err();
            assert!(e.contains("ICCID"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pads_and_picks_by_iccid() {
        let s = Secrets::parse(
            "pin1=1234; puk1=12345678\nadm1=hex:3737373737373737 # comment\n8949001:pin1=9999",
        )
        .unwrap();
        assert_eq!(s.get("PIN1", None), Some(b"1234\xFF\xFF\xFF\xFF".to_vec()));
        assert_eq!(
            s.get("pin1", Some("8949001")),
            Some(b"9999\xFF\xFF\xFF\xFF".to_vec())
        );
        assert_eq!(
            s.get("pin1", Some("other")),
            Some(b"1234\xFF\xFF\xFF\xFF".to_vec())
        );
        assert_eq!(s.get("adm1", None), Some(b"77777777".to_vec()));
        assert_eq!(s.get("pin2", None), None);
        assert!(s.needs_iccid());
    }

    #[test]
    fn bad_entries_name_the_line_not_the_value() {
        for text in [
            "pin1",
            "pin1=12",
            "pin9=1234",
            "pin1=12a4",
            "adm1=hex:",
            "nonsense=1234",
        ] {
            let e = Secrets::parse(text).unwrap_err();
            assert!(e.starts_with("entry 1:"), "{e}");
            assert!(!e.contains("12a4"), "{e}");
        }
        assert!(format!("{:?}", Secrets::parse("pin1=1234").unwrap()).contains("redacted"));
        assert!(!format!("{:?}", Secrets::parse("pin1=1234").unwrap()).contains("1234"));
    }
}
