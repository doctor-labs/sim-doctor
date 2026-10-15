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
}
