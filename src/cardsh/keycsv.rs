//! The CSV card key provider: pySim's `CardKeyProviderCsv` (`pySim/card_key_provider.py:190` in
//! osmocom/pysim, branch `master`) with the field-level encryption of its `CardKeyFieldCryptor`
//! (`:47`), which pySim leaves as bare AES-CBC.
//!
//! # The layout
//!
//! A file is a version marker, a header row and one record per card:
//!
//! ```text
//! # sim-doctor card-key-csv v1
//! ICCID,ADM1,PIN1,OPC
//! 8944500000000000001,E1a1b2...,E1c3d4...,E1e5f6...
//! ,E1....,E1....,E1....
//! ```
//!
//! The first column identifies the card; its cell is the value `get` looks up (pySim takes that
//! column as an argument, `:171`, and it is positional here, so there is one less thing to get
//! wrong). An **empty** identifier cell is the row for every card, which is the rule the PIN
//! source already uses for an entry not bound to an ICCID (`secrets.rs:86`): a row naming the
//! card wins over the empty one. Column names are upper-cased (`:211`).
//!
//! The marker line is a deliberate difference. pySim hands the file straight to `csv.DictReader`
//! (`:208`), so a layout change is silently misparsed; here a file that does not start with this
//! marker, or that carries another version's, is refused. A pySim-shaped file is therefore not
//! readable by this build, and a file this build writes is not readable by pySim.
//!
//! # The encryption
//!
//! GSMA FS.28 protects key material with a key-encryption key (pySim: "transport key", `:51-53`),
//! one per column, because one key over every column of a card re-uses it far too widely. The
//! transport keys are named in the same `NAME=HEX`-per-line text the PIN source takes, read from
//! a file or an environment variable and never from the command line.
//!
//! A sealed cell is
//!
//! ```text
//! "E1" | 8 octets AES-CMAC tag | 16 octets IV | the AES-CBC ciphertext      (all hex)
//! ```
//!
//! AES-CBC with PKCS#7 padding, a **fresh random IV per cell**, and an AES-CMAC tag over the
//! column name, the IV and the ciphertext. Three things differ from pySim's cryptor, each
//! because pySim's choice breaks the requirement that a wrong key be loud rather than yield key
//! material:
//!
//! - pySim uses one fixed IV, `b"\x23" * 16` (`:67`), for every cell of every column. Identical
//!   plaintexts then encrypt to identical ciphertexts, and a flipped ciphertext bit edits the
//!   plaintext at a known place. A fresh IV per cell removes both.
//! - pySim adds no integrity tag (`:115`), so a wrong transport key yields garbage that is
//!   returned as a key. Here the tag is verified first, so a wrong key is an error that quotes
//!   neither the key nor the cell.
//! - pySim passes a cell through as plaintext when its column has no transport key (`:113-114`),
//!   a silent downgrade when a mapping is missing. Here a cell carrying the `E1` marker is
//!   refused if its column has no transport key, and a cell in a column that has one is refused
//!   if it is not sealed. Both directions fail loudly.
//!
//! Only the fields a command asks for are opened, and only for the row that matched (`:220`), so
//! nothing else in the file is decrypted and nothing is written back: no function here takes a
//! decrypted value and writes it anywhere.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes::{Aes128, Aes256};
use cmac::{Cmac, KeyInit as CmacKeyInit, Mac};

use super::secrets::{Source, MAX_TEXT};

/// The line every card key CSV of this layout starts with.
pub const MARKER: &str = "# sim-doctor card-key-csv v1";

/// Most bytes read from a card key CSV.
pub const MAX_CSV: u64 = 1 << 20;

/// The AES block, and so the IV length written with every sealed cell.
const BLOCK: usize = 16;

/// Octets of AES-CMAC tag on a sealed cell.
const TAG: usize = 8;

/// What marks a sealed cell, and so which cell format this build reads.
const SEAL: &str = "E1";

/// Characters of the marker at the head of a sealed cell.
const SEAL_CHARS: usize = 2;
/// Characters of the tag.
const TAG_CHARS: usize = TAG * 2;
/// Characters of the IV.
const IV_CHARS: usize = BLOCK * 2;

/// One column's key-encryption key. Never rendered, never in an error.
#[derive(Clone)]
pub struct TransportKey(Vec<u8>);

impl TransportKey {
    /// From 16 (AES-128) or 32 (AES-256) octets of hex.
    ///
    /// # Errors
    ///
    /// The text is not hex, or is not 16 or 32 octets. The text is not quoted.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let bytes =
            hex::decode(text.trim()).map_err(|_| "a transport key is not hex".to_owned())?;
        if !matches!(bytes.len(), 16 | 32) {
            return Err("a transport key is 16 or 32 octets (AES-128 or AES-256)".to_owned());
        }
        Ok(Self(bytes))
    }

    /// The octets, for the cipher and the MAC.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportKey({} octets, redacted)", self.0.len())
    }
}

/// Seals and opens the columns of a card key CSV, one key-encryption key per column.
#[derive(Clone, Default)]
pub struct FieldCryptor {
    columns: BTreeMap<String, TransportKey>,
}

impl fmt::Debug for FieldCryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldCryptor({} columns, redacted)", self.columns.len())
    }
}

impl FieldCryptor {
    /// Binds `column` to a key-encryption key. The name is upper-cased, as pySim's does
    /// (`card_key_provider.py:70`).
    pub fn set(&mut self, column: &str, key: TransportKey) {
        self.columns.insert(column.trim().to_ascii_uppercase(), key);
    }

    /// Whether `column` is one of the encrypted columns.
    pub fn covers(&self, column: &str) -> bool {
        self.columns
            .contains_key(&column.trim().to_ascii_uppercase())
    }

    /// How many columns are encrypted.
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    /// Whether no column is encrypted.
    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    /// The encrypted column names, upper-cased and sorted.
    pub fn columns(&self) -> Vec<&str> {
        self.columns.keys().map(String::as_str).collect()
    }

    /// Reads `NAME=HEX` per line (`;` or newline separated) and binds each name to a key. The
    /// shape is the PIN source's (`secrets.rs:5`), so the two are told apart by what holds them
    /// and not by how they are written.
    ///
    /// # Errors
    ///
    /// The source is unreadable, too long, or an entry is malformed. Errors name the entry
    /// number and never quote a value.
    pub fn load(source: &Source) -> Result<Self, String> {
        let mut text = String::new();
        match source {
            Source::Env(name) => {
                text = std::env::var(name)
                    .map_err(|_| format!("environment variable {name} is not set"))?
            }
            Source::File(path) => {
                std::fs::File::open(path)
                    .and_then(|f| f.take(MAX_TEXT + 1).read_to_string(&mut text))
                    .map_err(|e| format!("{}: {e}", path.display()))?;
            }
        };
        if text.len() as u64 > MAX_TEXT {
            return Err("the transport key text is too long".into());
        }
        Self::parse(&text)
    }

    /// Parses the text. Errors name the entry number and never quote a value.
    ///
    /// # Errors
    ///
    /// An entry is not `NAME=HEX`, or the key is not 16 or 32 octets of hex.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut cryptor = Self::default();
        for (n, line) in text.split(['\n', ';']).enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let bad = |why: &str| format!("entry {}: {why}", n + 1);
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| bad("expected NAME=HEX"))?;
            let name = name.trim();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(bad("a column name is letters, digits, `_` or `-`"));
            }
            cryptor.set(name, TransportKey::from_hex(value).map_err(|e| bad(&e))?);
        }
        Ok(cryptor)
    }

    /// Seals one hex plaintext for `column`: `E1`, an 8-octet AES-CMAC tag, a fresh 16-octet IV
    /// and the AES-CBC ciphertext, all hex. This is the write side of a cell, and the only place
    /// a plaintext becomes a stored value.
    ///
    /// # Errors
    ///
    /// `column` has no transport key, or the plaintext is not hex.
    pub fn encrypt_field(&self, column: &str, plaintext_hex: &str) -> Result<String, String> {
        let key = self.key_for(column)?;
        let plain =
            hex::decode(plaintext_hex.trim()).map_err(|_| "a plaintext is not hex".to_owned())?;
        let mut iv = [0u8; BLOCK];
        rand::fill(&mut iv);
        let ct = cbc_encrypt(key.as_bytes(), &iv, &plain)?;
        let mut out = String::with_capacity(SEAL_CHARS + TAG_CHARS + IV_CHARS + ct.len() * 2);
        out.push_str(SEAL);
        out.push_str(&hex::encode_upper(tag(key.as_bytes(), column, &iv, &ct)));
        out.push_str(&hex::encode_upper(iv));
        out.push_str(&hex::encode_upper(&ct));
        Ok(out)
    }

    /// Opens one sealed cell for `column`. The tag is checked before the ciphertext is decrypted,
    /// so a wrong transport key is an error rather than a value.
    ///
    /// # Errors
    ///
    /// The column has no transport key, the cell is not sealed, the cell is malformed, or the tag
    /// does not verify. None of these quote the key or the cell.
    pub fn decrypt_field(&self, column: &str, sealed: &str) -> Result<String, String> {
        let name = column.trim().to_ascii_uppercase();
        let key = self.key_for(column)?;
        let cell = sealed.trim();
        if !cell.starts_with(SEAL) {
            return Err(format!(
                "column {name} has a transport key but this cell is not sealed with {SEAL}"
            ));
        }
        let body = &cell[SEAL_CHARS..];
        if body.len() < TAG_CHARS + IV_CHARS + 2 * BLOCK
            || (body.len() - TAG_CHARS - IV_CHARS) % 2 != 0
        {
            return Err(format!(
                "column {name}: the sealed cell is the wrong length"
            ));
        }
        let want = hex::decode(&body[..TAG_CHARS])
            .map_err(|_| format!("column {name}: the sealed cell tag is not hex"))?;
        let iv = hex::decode(&body[TAG_CHARS..TAG_CHARS + IV_CHARS])
            .map_err(|_| format!("column {name}: the sealed cell IV is not hex"))?;
        let ct = hex::decode(&body[TAG_CHARS + IV_CHARS..])
            .map_err(|_| format!("column {name}: the sealed cell ciphertext is not hex"))?;
        if !equal(&want, &tag(key.as_bytes(), column, &iv, &ct)) {
            return Err(format!(
                "column {name}: the transport key does not open this cell (wrong key, or the file was edited)"
            ));
        }
        Ok(hex::encode_upper(&cbc_decrypt(key.as_bytes(), &iv, &ct)?))
    }

    fn key_for(&self, column: &str) -> Result<&TransportKey, String> {
        let name = column.trim().to_ascii_uppercase();
        self.columns
            .get(&name)
            .ok_or_else(|| format!("no transport key for column {name}"))
    }
}

/// The 8-octet AES-CMAC tag over the column name, the IV and the ciphertext. The column name is
/// in the MAC, so a cell cannot be moved to another column.
fn tag(key: &[u8], column: &str, iv: &[u8], ct: &[u8]) -> [u8; TAG] {
    macro_rules! mac {
        ($cipher:ty) => {{
            let mut m = <Cmac<$cipher> as CmacKeyInit>::new_from_slice(key)
                .expect("16 or 32 octets checked");
            m.update(column.trim().to_ascii_uppercase().as_bytes());
            m.update(iv);
            m.update(ct);
            m.finalize().into_bytes()
        }};
    }
    let full = match key.len() {
        16 => mac!(Aes128),
        _ => mac!(Aes256),
    };
    let mut out = [0u8; TAG];
    out.copy_from_slice(&full[..TAG]);
    out
}

/// Compares without an early exit, so a wrong tag costs the same wherever it differs.
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn cbc_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    macro_rules! enc {
        ($cipher:ty) => {{
            let mut buf = vec![0u8; plain.len() + BLOCK];
            buf[..plain.len()].copy_from_slice(plain);
            cbc::Encryptor::<$cipher>::new_from_slices(key, iv)
                .map_err(|_| "the transport key and the IV length disagree".to_owned())?
                .encrypt_padded::<Pkcs7>(&mut buf, plain.len())
                .map_err(|_| "the PKCS#7 padding did not fit".to_owned())?
                .to_vec()
        }};
    }
    Ok(match key.len() {
        16 => enc!(Aes128),
        _ => enc!(Aes256),
    })
}

fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    macro_rules! dec {
        ($cipher:ty) => {{
            let mut buf = ct.to_vec();
            cbc::Decryptor::<$cipher>::new_from_slices(key, iv)
                .map_err(|_| "the transport key and the IV length disagree".to_owned())?
                .decrypt_padded::<Pkcs7>(&mut buf)
                .map_err(|_| "the cell does not unpad".to_owned())?
                .to_vec()
        }};
    }
    Ok(match key.len() {
        16 => dec!(Aes128),
        _ => dec!(Aes256),
    })
}

/// One CSV record, with the physical line it starts on so an error can name both.
type Record = (usize, Vec<String>);

/// Splits CSV text the way RFC 4180 does: `,` between cells, `"` quoting, `""` for a literal
/// quote, and a newline ending a record. Blank lines are skipped and a `\r` before the newline is
/// dropped. Returns the physical line of each record's first line.
fn records(text: &str) -> Result<Vec<Record>, String> {
    let mut out: Vec<Record> = Vec::new();
    let mut cells: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut line = 1usize;
    let mut start = 1usize;
    let mut in_quotes = false;
    let mut quoted = false;
    let mut dirty = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                dirty = true;
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' if cell.is_empty() && !quoted => {
                in_quotes = true;
                quoted = true;
                dirty = true;
            }
            ',' if !in_quotes => {
                dirty = true;
                cells.push(std::mem::take(&mut cell));
                quoted = false;
            }
            '\n' => {
                if in_quotes {
                    cell.push('\n');
                    line += 1;
                    continue;
                }
                if quoted && cell.ends_with('\r') {
                    cell.pop();
                }
                if !dirty && cells.is_empty() && cell.is_empty() {
                    line += 1;
                    start = line;
                    continue;
                }
                cells.push(std::mem::take(&mut cell));
                out.push((start, std::mem::take(&mut cells)));
                line += 1;
                start = line;
                dirty = false;
                quoted = false;
            }
            '\r' if !in_quotes && chars.peek() == Some(&'\n') => {}
            _ => {
                dirty = true;
                cell.push(c);
            }
        }
    }
    if in_quotes {
        return Err(format!("line {start}: a quoted cell is never closed"));
    }
    if dirty || !cell.is_empty() || !cells.is_empty() {
        cells.push(cell);
        out.push((start, cells));
    }
    Ok(out)
}

/// A parsed card key CSV: the header, and one row per card. The cells stay as they were written,
/// so nothing is decrypted until a lookup asks for a field.
#[derive(Clone, Debug)]
pub struct CardKeyCsv {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
    lines: Vec<usize>,
}

impl CardKeyCsv {
    /// Reads and parses a card key CSV.
    ///
    /// # Errors
    ///
    /// The file is unreadable, longer than [`MAX_CSV`], or not a card key CSV of this layout.
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(MAX_CSV + 1).read_to_string(&mut text))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text)
    }

    /// The version marker and header row a file of this layout starts with.
    pub fn header(columns: &[&str]) -> String {
        format!("{MARKER}\n{}\n", columns.join(","))
    }

    /// One record with the key columns sealed under `cryptor` and the rest as given. Every cell
    /// it writes is hex or a card identifier, so none needs quoting.
    ///
    /// # Errors
    ///
    /// `values` is not one per column, or a sealed cell could not be built.
    pub fn seal_row(
        cryptor: &FieldCryptor,
        columns: &[&str],
        values: &[&str],
    ) -> Result<String, String> {
        if columns.len() != values.len() {
            return Err("a card key record has one value per column".to_owned());
        }
        let mut cells = Vec::with_capacity(values.len());
        for (column, value) in columns.iter().zip(values) {
            cells.push(if cryptor.covers(column) {
                cryptor.encrypt_field(column, value)?
            } else {
                (*value).to_owned()
            });
        }
        Ok(format!("{}\n", cells.join(",")))
    }

    /// Parses the file text. A file is accepted whole or not at all: a single bad record leaves no
    /// provider to read half of. Errors name the record and its physical line, and never quote a
    /// cell.
    ///
    /// # Errors
    ///
    /// The marker is absent or is another version's, the header is empty or repeats a column, or
    /// a record does not have one cell per column.
    pub fn parse(text: &str) -> Result<Self, String> {
        let all = records(text)?;
        let mut it = all.iter();
        let (marker_line, marker) = it
            .next()
            .ok_or_else(|| "the card key CSV is empty".to_owned())?;
        let marker = marker.join(",").trim().to_owned();
        if !marker.starts_with('#') {
            return Err(format!(
                "line {marker_line}: expected the version marker `{MARKER}`, so a layout this build does not know is refused rather than misparsed"
            ));
        }
        if marker != MARKER {
            return Err(format!(
                "line {marker_line}: this is not a `{MARKER}` card key CSV"
            ));
        }
        let (_, header) = it.next().ok_or_else(|| {
            format!("line {marker_line}: `{MARKER}` is not followed by a header row")
        })?;
        let columns: Vec<String> = header
            .iter()
            .map(|c| c.trim().to_ascii_uppercase())
            .collect();
        if columns.is_empty() || columns.iter().any(String::is_empty) {
            return Err(format!("line {}: an empty column name", marker_line + 1));
        }
        for (n, name) in columns.iter().enumerate() {
            if columns[..n].contains(name) {
                return Err(format!(
                    "line {}: column {name} appears twice",
                    marker_line + 1
                ));
            }
        }
        let mut rows = Vec::new();
        let mut lines = Vec::new();
        for (n, (line, cells)) in it.enumerate() {
            if cells.len() != columns.len() {
                return Err(format!(
                    "csv row {} (line {line}): {} cells for {} columns",
                    n + 1,
                    cells.len(),
                    columns.len()
                ));
            }
            rows.push(cells.iter().map(|c| c.trim().to_owned()).collect());
            lines.push(*line);
        }
        Ok(Self {
            columns,
            rows,
            lines,
        })
    }

    /// The column names, upper-cased as the header gives them.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// How many card records the file has.
    pub fn rows(&self) -> usize {
        self.rows.len()
    }

    /// Whether any row names a card, which is what makes the card's ICCID worth reading.
    pub fn needs_iccid(&self) -> bool {
        self.rows.iter().any(|r| !r[0].is_empty())
    }

    /// The requested `fields` of the row whose first column is `value`, or `None` when the file
    /// has no such row or no first column. Only the fields asked for are opened, and only for the
    /// row that matched (pySim `:220`); a field the file has no column for is an error rather
    /// than a missing value (`:222`). A row naming the card wins over the empty-identifier row.
    ///
    /// # Errors
    ///
    /// A requested field has no column, or a cell would not open under `cryptor`.
    pub fn get(
        &self,
        fields: &[&str],
        value: &str,
        cryptor: &FieldCryptor,
    ) -> Result<Option<BTreeMap<String, String>>, String> {
        if self.columns.is_empty() {
            return Ok(None);
        }
        let bound = self
            .rows
            .iter()
            .zip(&self.lines)
            .position(|(r, _)| r[0] == value);
        let row = bound.or_else(|| self.rows.iter().position(|r| r[0].is_empty()));
        let (Some(row), Some(line)) = (row, row.map(|n| self.lines[n])) else {
            return Ok(None);
        };
        let cells = &self.rows[row];
        let mut out = BTreeMap::new();
        for field in fields {
            let name = field.trim().to_ascii_uppercase();
            let Some(index) = self.columns.iter().position(|c| *c == name) else {
                return Err(format!("the card key CSV lacks column `{name}`"));
            };
            let cell = cells[index].as_str();
            let opened = if cell.is_empty() {
                String::new()
            } else if cryptor.covers(&name) || cell.starts_with(SEAL) {
                cryptor
                    .decrypt_field(&name, cell)
                    .map_err(|e| format!("csv row {} (line {line}): {e}", row + 1))?
            } else {
                cell.to_owned()
            };
            out.insert(name, opened);
        }
        Ok(Some(out))
    }
}

/// A card key CSV with the transport keys that open it, as `sim-doctor card` holds one.
#[derive(Clone, Debug)]
pub struct CardKeyStore {
    csv: CardKeyCsv,
    cryptor: FieldCryptor,
}

impl CardKeyStore {
    /// Reads `csv` and the transport keys from `keys`. Both are read and checked before a reader
    /// is opened, so a typo costs the card nothing, and the keys never come from an argument.
    ///
    /// # Errors
    ///
    /// The CSV is not a card key CSV of this layout, the key text is malformed, or no column is
    /// encrypted at all: a card key CSV used with no transport key would be a plaintext secret
    /// store, which is the leak this provider exists to prevent.
    pub fn load(csv: &Path, keys: &Source) -> Result<Self, String> {
        let cryptor = FieldCryptor::load(keys)?;
        if cryptor.is_empty() {
            return Err("the transport key source names no column: a card key CSV with nothing encrypted is a plaintext key store".to_owned());
        }
        Ok(Self {
            csv: CardKeyCsv::load(csv)?,
            cryptor,
        })
    }

    /// The column names of the CSV.
    pub fn columns(&self) -> &[String] {
        self.csv.columns()
    }

    /// How many card records the CSV holds.
    pub fn rows(&self) -> usize {
        self.csv.rows()
    }

    /// Whether any row names a card.
    pub fn needs_iccid(&self) -> bool {
        self.csv.needs_iccid()
    }

    /// The requested `fields` for the card with `iccid` (the empty-identifier row when no ICCID
    /// is needed or none is known).
    ///
    /// # Errors
    ///
    /// As [`CardKeyCsv::get`], and additionally a value that is not hex.
    pub fn get(
        &self,
        fields: &[&str],
        iccid: Option<&str>,
    ) -> Result<BTreeMap<String, String>, String> {
        self.csv
            .get(fields, iccid.unwrap_or(""), &self.cryptor)?
            .ok_or_else(|| "the card key CSV has no row for this card".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLUMNS: [&str; 4] = ["ICCID", "ADM1", "PIN1", "OPC"];
    /// 8 octets for the PIN and the ADM key, 16 for OPc: the shapes `verify_chv` and
    /// `authenticate` need, so a round trip here is one those commands can use.
    const VALUES: [&str; 4] = [
        "8944500000000000001",
        "3737373737373737",
        "31323334FFFFFFFF",
        "0102030405060708090A0B0C0D0E0F10",
    ];

    fn cryptor() -> FieldCryptor {
        let mut c = FieldCryptor::default();
        c.set("adm1", TransportKey::from_hex(&"00".repeat(32)).unwrap());
        c.set("PIN1", TransportKey::from_hex(&"11".repeat(32)).unwrap());
        c.set("opc", TransportKey::from_hex(&"22".repeat(16)).unwrap());
        c
    }

    fn file(c: &FieldCryptor) -> String {
        let mut text = CardKeyCsv::header(&COLUMNS);
        text.push_str(&CardKeyCsv::seal_row(c, &COLUMNS, &VALUES).unwrap());
        text
    }

    #[test]
    fn a_sealed_row_round_trips_through_the_provider() {
        let c = cryptor();
        let text = file(&c);
        for secret in VALUES.iter().skip(1) {
            assert!(
                !text.contains(secret),
                "{secret} is on disk in the clear:\n{text}"
            );
        }
        let csv = CardKeyCsv::parse(&text).unwrap();
        assert_eq!(csv.columns(), COLUMNS);
        assert_eq!(csv.rows(), 1);

        let got = csv.get(&["pin1", "adm1"], VALUES[0], &c).unwrap().unwrap();
        assert_eq!(got["PIN1"], VALUES[2]);
        assert_eq!(got["ADM1"], VALUES[1]);

        // The identifier column is not encrypted, so it comes back as stored.
        let got = csv.get(&["ICCID"], VALUES[0], &c).unwrap().unwrap();
        assert_eq!(got["ICCID"], VALUES[0]);

        // OPc was not asked for, so it was never opened.
        let got = csv.get(&["PIN1"], VALUES[0], &c).unwrap().unwrap();
        assert_eq!(got.len(), 1);

        // The lookup key is matched case-insensitively, as pySim upper-cases it (`:211`).
        assert!(csv
            .get(&["PIN1"], VALUES[0].to_lowercase().as_str(), &c)
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_fresh_iv_per_cell_keeps_equal_plaintexts_from_looking_equal() {
        let c = cryptor();
        let first = c.encrypt_field("PIN1", VALUES[2]).unwrap();
        let second = c.encrypt_field("PIN1", VALUES[2]).unwrap();
        assert_ne!(
            first, second,
            "the same PIN sealed twice looks the same on disk"
        );
        assert_eq!(
            c.decrypt_field("PIN1", &first).unwrap(),
            c.decrypt_field("PIN1", &second).unwrap()
        );
    }

    #[test]
    fn the_wrong_transport_key_is_refused_and_yields_no_key() {
        let c = cryptor();
        let sealed = file(&c);
        let mut wrong = FieldCryptor::default();
        wrong.set("ADM1", TransportKey::from_hex(&"00".repeat(32)).unwrap());
        wrong.set("PIN1", TransportKey::from_hex(&"33".repeat(32)).unwrap());
        wrong.set("OPC", TransportKey::from_hex(&"22".repeat(16)).unwrap());
        let csv = CardKeyCsv::parse(&sealed).unwrap();
        let e = csv.get(&["PIN1"], VALUES[0], &wrong).unwrap_err();
        assert!(e.starts_with("csv row 1 (line 3):"), "{e}");
        assert!(e.contains("does not open"), "{e}");
        for secret in [VALUES[2], &sealed.lines().nth(2).unwrap()[..40]] {
            assert!(!e.contains(secret), "{secret} leaked into the error: {e}");
        }
        // The refusal is the key, not the file: the right key still opens the same row.
        assert!(csv.get(&["PIN1"], VALUES[0], &c).unwrap().is_some());
    }

    #[test]
    fn an_edited_cell_is_refused_rather_than_decrypted() {
        let c = cryptor();
        let mut lines: Vec<String> = file(&c).lines().map(str::to_owned).collect();
        let mut row: Vec<u8> = lines[2].clone().into_bytes();
        let last = row.len() - 1;
        row[last] = if row[last] == b'0' { b'1' } else { b'0' };
        lines[2] = String::from_utf8(row).unwrap();
        let csv = CardKeyCsv::parse(&lines.join("\n")).unwrap();
        let e = csv.get(&["OPC"], VALUES[0], &c).unwrap_err();
        assert!(e.contains("does not open"), "{e}");
    }

    #[test]
    fn a_cell_in_a_keyed_column_must_be_sealed_and_the_other_way_round() {
        let c = cryptor();
        // Plaintext where a transport key is configured: refused, never read as the value.
        let text = format!(
            "{}{},{},{},{}\n",
            CardKeyCsv::header(&COLUMNS),
            VALUES[0],
            VALUES[1],
            VALUES[2],
            VALUES[3]
        );
        let csv = CardKeyCsv::parse(&text).unwrap();
        let e = csv.get(&["ADM1"], VALUES[0], &c).unwrap_err();
        assert!(e.contains("is not sealed with E1"), "{e}");
        assert!(!e.contains(VALUES[1]), "{e}");
        // A sealed cell whose column has no transport key is refused too, rather than handed
        // back as ciphertext for the card to be sent.
        let mut partial = FieldCryptor::default();
        partial.set("PIN1", TransportKey::from_hex(&"11".repeat(32)).unwrap());
        let csv = CardKeyCsv::parse(&file(&c)).unwrap();
        let e = csv.get(&["OPC"], VALUES[0], &partial).unwrap_err();
        assert_eq!(e, "csv row 1 (line 3): no transport key for column OPC");
    }

    #[test]
    fn a_malformed_row_is_refused_by_its_number_and_nothing_is_read() {
        let c = cryptor();
        let mut text = file(&c);
        text.push_str("8944500000000000002,E1deadbeef\n");
        let e = CardKeyCsv::parse(&text).unwrap_err();
        assert_eq!(e, "csv row 2 (line 4): 2 cells for 4 columns");
        let mut other = file(&c);
        other.push_str("\"unterminated,E1\n");
        let e = CardKeyCsv::parse(&other).unwrap_err();
        assert_eq!(e, "line 4: a quoted cell is never closed");
    }

    #[test]
    fn a_missing_column_is_refused_rather_than_read_as_empty() {
        let c = cryptor();
        let csv = CardKeyCsv::parse(&file(&c)).unwrap();
        let e = csv.get(&["PUK1"], VALUES[0], &c).unwrap_err();
        assert_eq!(e, "the card key CSV lacks column `PUK1`");
        // An empty cell is a value that is not set, not a failure; its neighbours still open.
        let mut short = CardKeyCsv::header(&COLUMNS);
        short.push_str(
            &CardKeyCsv::seal_row(&c, &COLUMNS, &[VALUES[0], "", "", VALUES[3]]).unwrap(),
        );
        let csv = CardKeyCsv::parse(&short).unwrap();
        let got = csv.get(&["PIN1", "OPC"], VALUES[0], &c).unwrap().unwrap();
        assert_eq!(got["PIN1"], "");
        assert_eq!(got["OPC"], VALUES[3]);
    }

    #[test]
    fn an_unknown_card_is_not_an_error_and_a_pysim_shaped_file_is_refused() {
        let c = cryptor();
        let csv = CardKeyCsv::parse(&file(&c)).unwrap();
        assert!(csv
            .get(&["PIN1"], "8944500000000000009", &c)
            .unwrap()
            .is_none());
        // A file with no marker: pySim would read its header, we refuse it.
        let e =
            CardKeyCsv::parse(&format!("ICCID,ADM1\n{},{}\n", VALUES[0], VALUES[1])).unwrap_err();
        assert!(e.contains("expected the version marker"), "{e}");
        assert!(e.starts_with("line 1:"), "{e}");
        // Another version's marker is refused too, so a future layout is detected.
        let e = CardKeyCsv::parse("# sim-doctor card-key-csv v2\nICCID\n").unwrap_err();
        assert_eq!(
            e,
            "line 1: this is not a `# sim-doctor card-key-csv v1` card key CSV"
        );
    }

    #[test]
    fn the_row_naming_the_card_wins_over_the_row_for_every_card() {
        let c = cryptor();
        let other = [
            "8944500000000000002",
            "1111111111111111",
            "9999999999999999",
            "0F0E0D0C0B0A09080706050403020100",
        ];
        let any = [
            "",
            "8888888888888888",
            "AAAAAAAAAAAA5555",
            "000102030405060708090A0B0C0D0E0F",
        ];
        let mut text = file(&c);
        text.push_str(&CardKeyCsv::seal_row(&c, &COLUMNS, &other).unwrap());
        text.push_str(&CardKeyCsv::seal_row(&c, &COLUMNS, &any).unwrap());
        let csv = CardKeyCsv::parse(&text).unwrap();
        assert!(
            csv.needs_iccid(),
            "a named row means the ICCID has to be read"
        );
        let got = csv.get(&["PIN1"], VALUES[0], &c).unwrap().unwrap();
        assert_eq!(got["PIN1"], VALUES[2], "the row naming this card wins");
        let got = csv.get(&["PIN1"], other[0], &c).unwrap().unwrap();
        assert_eq!(got["PIN1"], other[2]);
        let got = csv
            .get(&["PIN1"], "8944500000000000003", &c)
            .unwrap()
            .unwrap();
        assert_eq!(
            got["PIN1"], any[2],
            "an unnamed card takes the row for every card"
        );
    }

    #[test]
    fn no_key_material_reaches_a_debug_print_a_source_error_or_the_csv() {
        let c = cryptor();
        let text = file(&c);
        let csv = CardKeyCsv::parse(&text).unwrap();
        let ciphertext = text.lines().nth(2).unwrap().to_owned();

        assert_eq!(format!("{c:?}"), "FieldCryptor(3 columns, redacted)");
        assert_eq!(c.columns(), ["ADM1", "OPC", "PIN1"]);
        assert_eq!(
            format!("{:?}", TransportKey::from_hex(&"00".repeat(32)).unwrap()),
            "TransportKey(32 octets, redacted)"
        );

        // A malformed transport key source names the entry and quotes neither name nor value.
        for (source, needle) in [
            ("PIN1=zzzz", "entry 1: a transport key is not hex"),
            (
                "PIN1=0011",
                "entry 1: a transport key is 16 or 32 octets (AES-128 or AES-256)",
            ),
            ("PIN1", "entry 1: expected NAME=HEX"),
            (
                "=0011",
                "entry 1: a column name is letters, digits, `_` or `-`",
            ),
        ] {
            let e = FieldCryptor::parse(source).unwrap_err();
            assert_eq!(e, needle);
            assert!(!e.contains("zzzz") && !e.contains("0011"), "{e}");
        }
        let e = FieldCryptor::load(&Source::Env("SIMDOC_NO_SUCH_KEY_VAR".into())).unwrap_err();
        assert_eq!(e, "environment variable SIMDOC_NO_SUCH_KEY_VAR is not set");

        // A cell of the wrong shape names the column and never echoes the cell.
        for cell in ["E1", "E1abcd", &format!("{SEAL}{}", "z".repeat(60))] {
            let e = c.decrypt_field("PIN1", cell).unwrap_err();
            assert!(e.starts_with("column PIN1:"), "{e}");
            assert!(!e.contains('z'), "{e}");
        }
        // The right key opens the row; the ciphertext is not the value and never was.
        assert!(csv.get(&["PIN1"], VALUES[0], &c).unwrap().is_some());
        assert!(!ciphertext.contains(VALUES[2]));
    }
}
