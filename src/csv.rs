//! A scan's results as a CSV log, in the layout SIMTester writes.
//!
//! SIMTester keeps one CSV file per scan mode (APDU, TAR, FUZZ, OTA, FILE), all
//! written by its own `CSVWriter`
//! (`srlabs/SIMTester`, `SIMTester/src/de/srlabs/simtester/CSVWriter.java`). The
//! file opens with two comment lines carrying the two version numbers
//! (CSVWriter.java:24-30), and from the first result onwards the header line
//!
//! ```text
//! # id,Command data,Response data
//! ```
//!
//! (CSVWriter.java:56-68), followed by one row per result: an identificator,
//! the command data and the response data, comma-joined and terminated by a
//! line break (CSVWriter.java:91-112). SIMTester escapes nothing at all.
//!
//! This module keeps SIMTester's *layout* - the comment preamble, the header
//! line and its three columns in that order - and adds the two things SIMTester
//! does not do: RFC 4180 quoting, and a guard on the cells a spreadsheet reads
//! as formulas. It is a result log, a sink beside the JSON and SARIF outputs: it
//! computes nothing, sorts nothing and filters nothing, and a severity or a
//! coverage statement stays in JSON and SARIF where the contract puts it.
//!
//! # The columns
//!
//! SIMTester's row is one exchange with the card, so its three cells are the
//! test that ran, what it sent and what came back. A sim-doctor finding is a
//! result rather than an exchange, and the same three cells say the same three
//! things about it: the rule that produced the result, the card location it is
//! about (SIMTester's hex spelling of a file), and what the card's answer turned
//! into.
//!
//! # Formula injection
//!
//! A cell starting with `=`, `+`, `-` or `@` is executed as a formula when the
//! file is opened in a spreadsheet, and card-supplied text is untrusted, so such
//! a cell is written with a leading apostrophe (see [`quote`]). The same guard
//! and the same RFC 4180 quoting are the ones `--write-csv` in the card shell
//! uses (issue #279), so a CSV from either command is read the same way.

use crate::contract;
use doctor_core::Finding;

/// The module name, as the module registry and the docs spell it.
pub const NAME: &str = "csv";

/// SIMTester's three column names, in its order (CSVWriter.java:59-63).
pub const COLUMNS: [&str; 3] = ["id", "Command data", "Response data"];

/// SIMTester's header line, verbatim: a comment, then the three column names in
/// its order (CSVWriter.java:56-64).
pub const HEADER: &str = "# id,Command data,Response data";

/// The whole file for `findings`: the comment preamble, the header line, then
/// one row per finding, in the order the report has them.
pub fn render(findings: &[Finding]) -> String {
    let mut out = String::new();
    // SIMTester's two version lines (CSVWriter.java:24-30), then the provenance.
    out.push_str(&format!("# sim-doctor {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str("# scan result log, the SIMTester CSV layout\n");
    out.push_str(HEADER);
    out.push('\n');
    for finding in findings {
        // The id is the rule table's own text. The location and the message can
        // carry whatever the card said, so they are sanitized first: the guard
        // below is about a spreadsheet, and sanitize is about a terminal.
        let cells: [&str; 3] = [
            &finding.id,
            &contract::sanitize(&finding.location.reference),
            &contract::sanitize(&finding.message),
        ];
        out.push_str(&row(&cells));
    }
    out
}

/// Writes [`render`] to `path` through a temporary file in the same directory
/// and a rename, the same way the SARIF file is written.
pub fn write(path: &std::path::Path, findings: &[Finding]) -> std::io::Result<()> {
    let text = render(findings);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(name);
    let result = std::fs::write(&temporary, text.as_bytes())
        .and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// One CSV row, terminated by a line break: RFC 4180 quoting for a field that
/// holds a comma, a quote or a line break, and a formula guard first.
///
/// THE ESCAPE RULE. A cell is guarded when its first character is one a
/// spreadsheet starts a formula with - `=`, `+`, `-`, `@`, a tab or a CR, the
/// six guards `--write-csv` uses - AND the cell is not something a spreadsheet
/// reads as a number whatever else it contains. [`is_number_or_hex`] is that
/// exemption: a plain signed number (`-2`, `+1`) and a pure hex literal
/// (`3F00`, `DEADBEEF`, which is what SIMTester's two data columns are made of)
/// are values, not formulas, so prefixing them would corrupt the very thing
/// this file is for. Everything else that starts with a guard character is
/// guarded, including `-2+3` and `=1`, which are not numbers. The guard
/// character is never inside the value, so a guarded cell still round trips.
pub fn row<S: AsRef<str>>(fields: &[S]) -> String {
    let mut out = fields
        .iter()
        .map(|field| quote(field.as_ref()))
        .collect::<Vec<_>>()
        .join(",");
    out.push('\n');
    out
}

/// The guarded, quoted form of one cell. See [`row`] for the rule.
pub fn quote(field: &str) -> String {
    let guarded = match field.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') if !is_number_or_hex(field) => {
            format!("'{field}")
        }
        _ => field.to_owned(),
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// Whether the cell is a value a spreadsheet reads as a number, so it needs no
/// formula guard: a plain signed decimal number, or a pure hex literal of whole
/// bytes (an even number of hex digits, the spelling `HexToolkit.toString`
/// writes into SIMTester's two data columns).
fn is_number_or_hex(field: &str) -> bool {
    let unsigned = field.strip_prefix(['+', '-']).unwrap_or(field);
    let digits = unsigned
        .split_once('.')
        .map_or(unsigned, |(whole, _)| whole);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    !field.is_empty()
        && field.len() % 2 == 0
        && field
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

/// Splits CSV text into records of fields, so a file this module wrote can be
/// read back and compared. A final line break does not add an empty record.
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

#[cfg(test)]
mod tests {
    use super::*;
    use doctor_core::{Location, LocationKind, Severity};
    use serde_json::Map;

    const QUOTE: char = '"';

    fn severity() -> Severity {
        Severity::parse("high").expect("a known severity")
    }

    /// A finding as the report carries it: only the three fields this sink reads
    /// hold anything a test cares about.
    fn finding(id: &str, reference: &str, message: &str) -> Finding {
        Finding {
            id: id.to_owned(),
            fingerprint: "0123456789abcdef".to_owned(),
            severity: severity(),
            confidence: None,
            category: "test".to_owned(),
            message: message.to_owned(),
            location: Location::new(LocationKind::CardPath, reference),
            evidence: Vec::new(),
            remedy: None,
            baseline_state: None,
            extra: Map::new(),
        }
    }

    /// The data rows of a rendered file, comment lines dropped.
    fn rows(text: &str) -> Vec<Vec<String>> {
        parse(text)
            .expect("the file this module wrote parses")
            .into_iter()
            .skip_while(|record| record.first().is_some_and(|cell| cell.starts_with('#')))
            .collect()
    }

    /// Text wrapped in double quotes: how a card that quotes its own file names
    /// shows up inside a rule message.
    fn quoted(text: &str) -> String {
        let mut out = String::from(QUOTE);
        out.push_str(text);
        out.push(QUOTE);
        out
    }

    #[test]
    fn the_header_line_and_the_column_order_are_simtesters() {
        assert_eq!(HEADER, "# id,Command data,Response data");
        assert_eq!(COLUMNS, ["id", "Command data", "Response data"]);
        let text = render(&[finding("gsma/x", "3F00", "IMSI is all ones")]);
        let preamble: Vec<&str> = text
            .lines()
            .take_while(|line| line.starts_with('#'))
            .collect();
        assert_eq!(preamble[2], "# id,Command data,Response data");
        let body = rows(&text);
        assert_eq!(body.len(), 1, "one row for one finding");
        assert_eq!(body[0].len(), 3, "three columns, in SIMTester's order");
        assert_eq!(body[0], vec!["gsma/x", "3F00", "IMSI is all ones"]);
    }

    #[test]
    fn a_run_with_no_findings_is_the_preamble_and_the_header_and_nothing_else() {
        let text = render(&[]);
        assert_eq!(
            text,
            format!(
                "# sim-doctor {}\n# scan result log, the SIMTester CSV layout\n{}\n",
                env!("CARGO_PKG_VERSION"),
                HEADER
            )
        );
        assert!(rows(&text).is_empty());
    }

    #[test]
    fn cells_a_spreadsheet_reads_as_formulas_get_a_leading_apostrophe() {
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
        // +1 and -2 are numbers, so they are left as they are; everything else
        // a spreadsheet would run is guarded.
        assert_eq!(text, "'=HYPERLINK(1),+1,-2,'@x,'\tt,\"'\rr\",plain,a=b\n");
        // The guard is never inside the value: the cell comes back as written.
        assert_eq!(parse(&text).unwrap()[0][0], "'=HYPERLINK(1)");
    }

    #[test]
    fn only_a_plain_number_or_a_pure_hex_value_is_left_unguarded() {
        for value in [
            "-2", "+1", "0", "-12.5", "3F00", "DEADBEEF", "00", "3F00 ", "ABC",
        ] {
            assert_eq!(quote(value), value, "{value} is a value, not a formula");
        }
        // These all START with a guard character and none of them is a number or
        // a hex literal, so every one of them is guarded.
        for value in [
            "-2+3", "=1", "-", "--1", "-3F00 ", "+1E5", "@", "=cmd", "@SUM(A1)",
        ] {
            assert!(quote(value).starts_with('\''), "{value} is guarded");
        }
    }

    #[test]
    fn a_commas_quotes_and_line_breaks_are_quoted_the_way_rfc4180_asks() {
        let fields = [
            "open_channel".to_owned(),
            "EF".to_owned() + &quoted("AID-3F00"),
            "line one, ".to_owned() + &quoted("two") + "\nthree",
        ];
        let cells: [&str; 3] = [&fields[0], &fields[1], &fields[2]];
        let text = row(&cells);
        assert_eq!(
            text,
            "open_channel,\"EF\"\"AID-3F00\"\"\",\"line one, \"\"two\"\"\nthree\"\n"
        );
        assert_eq!(parse(&text).unwrap()[0], fields);
    }

    #[test]
    fn every_finding_in_a_saved_report_survives_a_round_trip_through_the_csv() {
        let findings = vec![
            finding("gsma/imsi-all-ones", "2FE2", "IMSI is 111111111111111"),
            finding("gsma/weak-auth", "3F00", "AUTH = 0000"),
            finding(
                "gp/delete-file",
                "6F3A",
                &("a file under, ".to_owned() + &quoted("quoted") + " and\nsplit"),
            ),
        ];
        // What a saved doctor/1 envelope holds, read back through serde.
        let saved: Vec<serde_json::Value> = findings
            .iter()
            .map(|one| serde_json::to_value(one).expect("a finding serializes"))
            .collect();
        let text = render(&findings);
        let body = rows(&text);
        assert_eq!(body.len(), saved.len());
        for (row, report) in body.iter().zip(&saved) {
            assert_eq!(row.len(), 3);
            assert_eq!(row[0], report["id"].as_str().unwrap());
            assert_eq!(
                row[1],
                contract::sanitize(report["location"]["ref"].as_str().unwrap())
            );
            assert_eq!(
                row[2],
                contract::sanitize(report["message"].as_str().unwrap())
            );
        }
    }

    #[test]
    fn utf8_in_a_card_message_survives_the_round_trip() {
        let text = render(&[finding(
            "sms/unicode",
            "3F00",
            "IMSI 210 01: Unicode - \u{00dc}nic\u{00f8}d\u{00e9} - \u{6f22} \u{5b57} \u{624b}\u{673a}",
        )]);
        assert_eq!(
            rows(&text)[0][2],
            "IMSI 210 01: Unicode - \u{00dc}nic\u{00f8}d\u{00e9} - \u{6f22} \u{5b57} \u{624b}\u{673a}"
        );
    }

    #[test]
    fn no_secret_carried_by_a_finding_reaches_a_row() {
        let ki = "00112233445566778899AABBCCDDEEFF";
        let authenticator = "88312211223344556677889900AABB";
        let mut carrier = finding("gp/key", "3F00", "a key file is present");
        carrier.extra.insert("ki".to_owned(), serde_json::json!(ki));
        carrier
            .extra
            .insert("authenticator".to_owned(), serde_json::json!(authenticator));
        let text = render(&[carrier]);
        // Three cells per row is the structural half of this: the sink reads the
        // id, the location and the message and nothing else, so a secret held in
        // any other field of the finding has nowhere to go.
        assert_eq!(rows(&text)[0].len(), 3);
        assert!(!text.contains(ki), "no key in a row");
        assert!(!text.contains(authenticator), "no authenticator in a row");
    }

    #[test]
    fn card_text_is_sanitized_before_it_is_written() {
        let message = "EF named ".to_owned() + &quoted("\u{1b}[31mred\u{1b}[0m") + "\nsecond line";
        let text = render(&[finding("ef/name", "3F00\u{202e}", &message)]);
        let body = rows(&text);
        assert_eq!(body[0][1], "3F00 ");
        // A control character is a space, ESC included: sanitize is the point.
        assert_eq!(body[0][2], "EF named \" [31mred [0m\" second line");
    }
}
