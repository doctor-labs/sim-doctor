//! The CSV files `sim-doctor card --read-csv` and `--write-csv` use: RFC 4180 (comma-separated,
//! a field holding a comma, a quote or a line break is wrapped in double quotes, and a quote inside
//! one is doubled). Hand-written because the crate has no CSV dependency and the format is small.

/// Splits CSV text into records of fields. A final line break does not add an empty record.
pub fn parse(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_quotes = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => in_quotes = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    if in_quotes {
        return Err("a quoted field is never closed".into());
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

/// The `command` column of a CSV file: one shell command per row, in file order. The column is
/// found by name in the first row. Rows with an empty command are skipped. A cell written with the
/// formula guard (a leading `'`, see [`row`]) is returned with the guard: it is not a command, so
/// the shell rejects it as unknown rather than guessing what was meant.
pub fn commands(text: &str) -> Result<Vec<String>, String> {
    let mut rows = parse(text)?.into_iter();
    let header = rows.next().ok_or("the CSV file is empty")?;
    let column = header
        .iter()
        .position(|name| name.trim() == "command")
        .ok_or("the first row of the CSV file has no `command` column")?;
    Ok(rows
        .filter_map(|row| row.get(column).map(|cell| cell.trim().to_owned()))
        .filter(|cell| !cell.is_empty())
        .collect())
}

/// One CSV row, terminated by a line break. A cell that starts with `=`, `+`, `-`, `@`, a tab or a CR is
/// prefixed with `'` so a spreadsheet opens it as text, not as a formula (OWASP CSV injection).
pub fn row<S: AsRef<str>>(fields: &[S]) -> String {
    let mut out = fields
        .iter()
        .map(|field| quote(field.as_ref()))
        .collect::<Vec<_>>()
        .join(",");
    out.push('\n');
    out
}

fn quote(field: &str) -> String {
    let guarded = match field.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{field}"),
        _ => field.to_owned(),
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// A key value from a provisioning row. It has no Display, and Debug never shows the digits.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(String);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// One row of the pySim provisioning layout: pySim-prog.py writes `name,iccid,mcc,mnc,imsi,smsp,ki,opc`
/// (lines 509-511) and its reader requires the `iccid` and `imsi` headers (lines 530-535). `smsp` and
/// the PIN/ADM columns are not verifiable from the issue or the repo, so they are not read.
#[derive(Debug)]
pub struct Provision {
    /// The record number in the file; the header is record 1.
    pub record: usize,
    /// The columns this row fills, in the fixed order name, iccid, imsi, mcc, mnc, ki, opc.
    pub filled: Vec<&'static str>,
    /// The name column, free text; empty when absent.
    pub name: String,
    /// The ICCID: digits only.
    pub iccid: String,
    /// The IMSI: 15 digits.
    pub imsi: String,
    /// The MCC, 3 digits, when the column is filled.
    pub mcc: Option<String>,
    /// The MNC, 2 or 3 digits, when the column is filled.
    pub mnc: Option<String>,
    /// The Ki, 32 hex digits, when the column is filled.
    pub ki: Option<Key>,
    /// The OPc, 32 hex digits, when the column is filled.
    pub opc: Option<Key>,
}

/// The pySim provisioning layout, or None when the file is not one: a file with a `command` column
/// is a command table, and the layout needs both an `iccid` and an `imsi` header (names are compared
/// lower-cased, as pySim does). Every row is checked; the first failure is returned with its record
/// number. A message never includes a cell value, so a key or PIN cannot leak through an error.
pub fn provisioning(text: &str) -> Result<Option<Vec<Provision>>, String> {
    let mut records = parse(text)?.into_iter();
    let header: Vec<String> = records
        .next()
        .ok_or("the CSV file is empty")?
        .iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    let has = |name: &str| header.iter().any(|h| h == name);
    if has("command") || !has("iccid") || !has("imsi") {
        return Ok(None);
    }
    let mut rows = Vec::new();
    for (index, record) in records.enumerate() {
        let number = index + 2;
        let cell = |name: &str| -> String {
            header
                .iter()
                .position(|h| h == name)
                .and_then(|i| record.get(i))
                .map(|value| value.trim().to_owned())
                .unwrap_or_default()
        };
        let (iccid, imsi, mcc, mnc) = (cell("iccid"), cell("imsi"), cell("mcc"), cell("mnc"));
        let (ki, opc) = (cell("ki"), cell("opc"));
        let problem: Option<&str> = if !is_digits(&iccid) {
            Some("iccid must be digits")
        } else if imsi.len() != 15 || !is_digits(&imsi) {
            Some("imsi must be 15 digits")
        } else if !mcc.is_empty() && (mcc.len() != 3 || !is_digits(&mcc)) {
            Some("mcc must be 3 digits")
        } else if !mnc.is_empty() && (!(2..=3).contains(&mnc.len()) || !is_digits(&mnc)) {
            Some("mnc must be 2 or 3 digits")
        } else if !ki.is_empty() && !is_hex_key(&ki) {
            Some("ki must be 32 hex digits")
        } else if !opc.is_empty() && !is_hex_key(&opc) {
            Some("opc must be 32 hex digits")
        } else {
            None
        };
        if let Some(problem) = problem {
            return Err(format!("row {number}: {problem}"));
        }
        let filled = ["name", "iccid", "imsi", "mcc", "mnc", "ki", "opc"]
            .into_iter()
            .filter(|column| !cell(column).is_empty())
            .collect();
        rows.push(Provision {
            record: number,
            filled,
            name: cell("name"),
            iccid,
            imsi,
            mcc: optional(mcc),
            mnc: optional(mnc),
            ki: optional(ki).map(Key),
            opc: optional(opc).map(Key),
        });
    }
    Ok(Some(rows))
}

fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn is_hex_key(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn optional(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_fields_keep_commas_quotes_and_line_breaks() {
        let rows = parse("a,\"b,c\",\"say \"\"hi\"\"\"\r\n\"x\ny\",,z\n").unwrap();
        assert_eq!(
            rows,
            vec![vec!["a", "b,c", "say \"hi\""], vec!["x\ny", "", "z"],]
        );
    }

    #[test]
    fn a_row_written_by_row_reads_back_unchanged() {
        let fields = ["open_channel", "true", "line one, \"two\"\nthree"];
        let text = format!("{}{}", row(&["command", "ok", "text"]), row(&fields));
        let rows = parse(&text).unwrap();
        assert_eq!(rows[1], fields);
    }

    #[test]
    fn cells_that_spreadsheets_read_as_formulas_get_a_leading_apostrophe() {
        let text = row(&[
            "=HYPERLINK(1)",
            "+1",
            "-2",
            "@x",
            "\tt",
            "\rr",
            "plain",
            "a=b",
        ]);
        assert_eq!(text, "'=HYPERLINK(1),'+1,'-2,'@x,'\tt,\"'\rr\",plain,a=b\n");
        // The reader does not strip the guard: the cell comes back exactly as written.
        assert_eq!(parse(&text).unwrap()[0][0], "'=HYPERLINK(1)");
    }

    #[test]
    fn commands_come_from_the_named_column_and_blank_rows_are_skipped() {
        let text = "note,command\nfirst,status\n,\nsecond,\"channel 1\"\n";
        assert_eq!(commands(text).unwrap(), vec!["status", "channel 1"]);
        assert!(commands("note,cmd\nx,status\n").is_err());
        assert!(commands("").is_err());
        assert!(parse("a,\"unclosed\n").is_err());
    }

    #[test]
    fn provisioning_rows_are_checked_and_no_key_is_shown() {
        let key = "0123456789ABCDEF0123456789ABCDEF";
        let text = format!(
            "name,iccid,imsi,ki,opc\n\"Smith, J\",8944500000000000001,123450123456789,{key},{key}\n"
        );
        let rows = provisioning(&text).unwrap().unwrap();
        assert_eq!(rows[0].record, 2);
        assert_eq!(rows[0].name, "Smith, J");
        assert_eq!(rows[0].filled, ["name", "iccid", "imsi", "ki", "opc"]);
        assert_eq!(format!("{:?}", rows[0].ki), "Some(Key(<redacted>))");
        let short = &key[..30];
        let text = format!("iccid,imsi,ki\n8944500000000000001,123450123456789,{short}\n");
        assert_eq!(
            provisioning(&text).unwrap_err(),
            "row 2: ki must be 32 hex digits"
        );
        assert!(provisioning("command\nstatus\n").unwrap().is_none());
        assert!(provisioning("iccid,command\n1,status\n").unwrap().is_none());
    }
}
