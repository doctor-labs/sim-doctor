//! Offline APDU trace decoder: command/response hex in, named exchanges out,
//! with the currently selected file tracked. Sends nothing, needs no card.
//!
//! **Owns.** Parsing a trace (stdin hex pairs, or our own `--trace` JSON) and
//! naming each command. The command set follows pySim's `pySim/apdu`
//! (osmocom/pysim@3c437d4: ISO 7816-4, TS 102 221, TS 31.102) plus
//! GlobalPlatform; the code is written here, not copied. Status words reuse
//! [`crate::apdu::StatusWord`].
//!
//! **Not done.** GSMTAP TPDU sub-types (see [`pcap`]). The selected
//! file is tracked from SELECT parameters only; whether a FID is a DF or an EF
//! is guessed from its first octet (3F/7F/5F are DFs), because the FCP is not
//! read.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "trace";

use serde_json::{json, Value};

pub mod pcap;

use crate::apdu::{Command, StatusWord};

/// One parsed exchange: optional label, command bytes, response bytes.
pub type Pair = (Option<String>, Vec<u8>, Vec<u8>);

/// One decoded command/response pair.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Optional label carried by our own trace JSON (`select`, `cplc`, ...).
    pub step: Option<String>,
    /// Command hex, upper case.
    pub command: String,
    /// Response hex, upper case; empty when the trace ended on a command.
    pub response: String,
    /// Instruction name, e.g. `SELECT`.
    pub name: String,
    /// Parameter and data summary.
    pub detail: String,
    /// Status word hex, when the response had one.
    pub status: Option<String>,
    /// What the status word means.
    pub meaning: String,
    /// The selected file after this exchange.
    pub selected: String,
}

impl Decoded {
    /// The machine-readable form (additive `data.exchanges[]` entries).
    pub fn to_json(&self, index: usize) -> Value {
        json!({
            "index": index,
            "step": self.step,
            "command": self.command,
            "response": self.response,
            "name": self.name,
            "detail": self.detail,
            "status": self.status,
            "status_meaning": self.meaning,
            "selected": self.selected,
        })
    }
}

/// Reads a trace file's bytes: a pcap or pcapng capture of GSMTAP SIM APDUs
/// (detected by magic number), otherwise the text formats of [`parse`].
///
/// # Errors
///
/// A sentence naming what is wrong with the capture or the text.
pub fn parse_bytes(input: &[u8]) -> Result<Vec<Pair>, String> {
    if pcap::is_capture(input) {
        return pcap::parse(input);
    }
    let text = std::str::from_utf8(input)
        .map_err(|_| "the trace is neither a pcap/pcapng capture nor UTF-8 text".to_owned())?;
    if is_tca_loader_log(text) {
        return parse_tca_loader_log(text);
    }
    parse(text)
}

/// Whether a text trace is a TCA Loader log. Hex lines never start with the words `Command` or
/// `Response`, so the check cannot take a hex trace for a log.
fn is_tca_loader_log(text: &str) -> bool {
    text.lines()
        .any(|line| matches!(line.split_whitespace().next(), Some("Command" | "Response")))
}

/// Reads a TCA Loader log the way pySim's `TcaLoaderLogApduSource` does: a `Command <hex>` line
/// followed by a `Response <hex>` line is one exchange, and every other line is ignored. A command
/// with no response (the next line is another `Command`, or the log ends) is kept with an empty
/// response, so the caller warns about it instead of dropping it.
///
/// # Errors
///
/// A missing or non-hex value on a `Command` or `Response` line, or a log with no such lines.
pub fn parse_tca_loader_log(input: &str) -> Result<Vec<Pair>, String> {
    let hex_value = |word: Option<&str>, n: usize| {
        let word = word.ok_or_else(|| format!("line {n}: Command or Response has no hex value"))?;
        hex::decode(word).map_err(|e| format!("line {n}: {e}"))
    };
    let mut pairs = Vec::new();
    let mut pending: Option<Vec<u8>> = None;
    for (i, line) in input.lines().enumerate() {
        let n = i + 1;
        let mut words = line.split_whitespace();
        match words.next() {
            Some("Command") => {
                if let Some(orphan) = pending.replace(hex_value(words.next(), n)?) {
                    pairs.push((None, orphan, Vec::new()));
                }
            }
            Some("Response") => {
                if let Some(command) = pending.take() {
                    pairs.push((None, command, hex_value(words.next(), n)?));
                }
            }
            _ => {}
        }
    }
    if let Some(orphan) = pending {
        pairs.push((None, orphan, Vec::new()));
    }
    if pairs.is_empty() {
        return Err("the TCA Loader log has no Command and Response lines".to_owned());
    }
    Ok(pairs)
}

/// Reads a trace: JSON (array of `{step,command,response}`, `{trace:[..]}` or a
/// full `gp info --json --trace` envelope), otherwise hex lines alternating
/// command, response. `#` starts a comment; spaces inside hex are ignored.
///
/// # Errors
///
/// A sentence naming the first thing that is not hex or not a trace.
pub fn parse(input: &str) -> Result<Vec<Pair>, String> {
    let text = input.trim_start();
    if text.starts_with('{') || text.starts_with('[') {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("trace JSON: {e}"))?;
        let steps = [
            &v,
            &v["trace"],
            &v["data"]["trace"],
            &v["payload"]["data"]["trace"],
        ]
        .into_iter()
        .find_map(Value::as_array)
        .ok_or("trace JSON has no trace array (expected [..], trace, or data.trace)")?;
        return steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let field = |k: &str| {
                    hex::decode(s[k].as_str().unwrap_or("").replace(' ', ""))
                        .map_err(|e| format!("trace[{i}].{k}: {e}"))
                };
                Ok((
                    s["step"].as_str().map(str::to_owned),
                    field("command")?,
                    field("response")?,
                ))
            })
            .collect();
    }
    let mut lines = Vec::new();
    for (n, line) in input.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        let compact: String = line.split_whitespace().collect();
        if compact.is_empty() {
            continue;
        }
        lines.push(hex::decode(&compact).map_err(|e| format!("line {}: {e}", n + 1))?);
    }
    Ok(lines
        .chunks(2)
        .map(|p| (None, p[0].clone(), p.get(1).cloned().unwrap_or_default()))
        .collect())
}

/// Decodes a parsed trace, carrying the selected file across exchanges.
pub fn decode(pairs: &[Pair]) -> Vec<Decoded> {
    let mut sel = Selected::default();
    pairs
        .iter()
        .map(|(step, cmd, rsp)| decode_one(&mut sel, step.clone(), cmd, rsp))
        .collect()
}

#[derive(Default)]
struct Selected {
    path: Vec<String>,
    last_is_ef: bool,
}

impl Selected {
    fn show(&self) -> String {
        if self.path.is_empty() {
            "(none)".into()
        } else {
            self.path.join("/")
        }
    }

    fn select_fid(&mut self, fid: u16) {
        let s = format!("{fid:04X}");
        match fid >> 8 {
            0x3F => {
                self.path = vec![s];
                self.last_is_ef = false;
            }
            hi @ (0x7F | 0x5F) => {
                if hi == 0x7F {
                    self.path.truncate(1);
                } else if self.last_is_ef {
                    self.path.pop();
                }
                if self.path.is_empty() {
                    self.path.push("3F00".into());
                }
                self.path.push(s);
                self.last_is_ef = false;
            }
            _ => {
                if self.last_is_ef {
                    self.path.pop();
                }
                self.path.push(s);
                self.last_is_ef = true;
            }
        }
    }
}

fn decode_one(sel: &mut Selected, step: Option<String>, cmd: &[u8], rsp: &[u8]) -> Decoded {
    let status =
        (rsp.len() >= 2).then(|| StatusWord::from_bytes([rsp[rsp.len() - 2], rsp[rsp.len() - 1]]));
    let body = &rsp[..rsp.len().saturating_sub(2)];
    let (name, detail) = match Command::decode(cmd) {
        Ok(c) => {
            let h = c.header();
            let head = [h.class(), h.instruction(), h.parameter_1(), h.parameter_2()];
            describe(sel, head, c.body().data(), body, status)
        }
        Err(e) => ("UNKNOWN".into(), format!("not a command APDU: {e}")),
    };
    Decoded {
        step,
        command: hex::encode_upper(cmd),
        response: hex::encode_upper(rsp),
        name,
        detail,
        status: status.map(|s| s.to_string()),
        meaning: status.map_or_else(|| "no status word".into(), sw_meaning),
        selected: sel.show(),
    }
}

/// What a status word means: specific values first, then the shared
/// [`StatusWord`] classification.
pub fn sw_meaning(sw: StatusWord) -> String {
    let (a, b) = (sw.sw1(), sw.sw2());
    let known = match (a, b) {
        (0x90, 0x00) => "success",
        (0x62, 0x83) => "selected file invalidated",
        (0x63, 0xC0..=0xCF) => return format!("verification failed, {} tries left", b & 0x0F),
        (0x67, 0x00) => "wrong length",
        (0x69, 0x82) => "security status not satisfied",
        (0x69, 0x83) => "authentication method blocked",
        (0x69, 0x84) => "referenced data invalidated",
        (0x69, 0x85) => "conditions of use not satisfied",
        (0x6A, 0x82) => "file or application not found",
        (0x6A, 0x83) => "record not found",
        (0x6A, 0x86) => "incorrect P1-P2",
        (0x6B, 0x00) => "wrong parameters P1-P2",
        (0x6D, 0x00) => "instruction not supported",
        (0x6E, 0x00) => "class not supported",
        (0x6F, 0x00) => "no precise diagnosis",
        (0x94, 0x00) => "no EF selected",
        (0x94, 0x04) => "file ID not found",
        (0x98, 0x04) => "access condition not fulfilled / auth failed",
        (0x98, 0x40) => "PIN blocked",
        (0x61 | 0x9F, n) => {
            let n = if n == 0 { 256 } else { u16::from(n) };
            return format!("{n} response bytes available (GET RESPONSE)");
        }
        (0x6C, n) => return format!("wrong Le, card wants {n:02X}"),
        (0x91, n) => return format!("success, proactive command pending, {n} bytes (FETCH)"),
        _ => "",
    };
    if known.is_empty() {
        format!("{:?} status", sw.class())
    } else {
        known.into()
    }
}

fn be16(d: &[u8]) -> Option<u16> {
    (d.len() == 2).then(|| u16::from_be_bytes([d[0], d[1]]))
}

/// PIN key reference (TS 102 221 clause 9.5.1, as used by VERIFY and friends).
fn key_ref(p2: u8) -> String {
    match p2 {
        0x01..=0x08 => format!("PIN appl {p2}"),
        0x0A..=0x0E => format!("ADM {}", p2 - 9),
        0x8A..=0x8E => format!("ADM {}", p2 - 0x84),
        0x11 => "universal PIN".into(),
        0x81..=0x88 => format!("2nd PIN appl {}", p2 - 0x80),
        _ => format!("key ref {p2:02X}"),
    }
}

/// Length-prefixed fields from the front of `d`, named in order, as hex.
fn lv_fields(d: &[u8], names: &[&str]) -> String {
    let mut rest = d;
    let mut out = Vec::new();
    for n in names {
        let Some((&l, tail)) = rest.split_first() else {
            break;
        };
        let l = usize::from(l);
        if tail.len() < l {
            break;
        }
        out.push(format!("{n}={}", hex::encode_upper(&tail[..l])));
        rest = &tail[l..];
    }
    out.join(" ")
}

fn proactive_type(t: u8) -> &'static str {
    match t {
        0x01 => "REFRESH",
        0x05 => "SET UP EVENT LIST",
        0x10 => "SET UP CALL",
        0x11 => "SEND SS",
        0x12 => "SEND USSD",
        0x13 => "SEND SHORT MESSAGE",
        0x14 => "SEND DTMF",
        0x15 => "LAUNCH BROWSER",
        0x20 => "PLAY TONE",
        0x21 => "DISPLAY TEXT",
        0x22 => "GET INKEY",
        0x23 => "GET INPUT",
        0x24 => "SELECT ITEM",
        0x25 => "SET UP MENU",
        0x26 => "PROVIDE LOCAL INFORMATION",
        0x27 => "TIMER MANAGEMENT",
        0x28 => "SET UP IDLE MODE TEXT",
        0x30 => "RUN AT COMMAND",
        0x40 => "OPEN CHANNEL",
        0x41 => "CLOSE CHANNEL",
        0x42 => "RECEIVE DATA",
        0x43 => "SEND DATA",
        0x44 => "GET CHANNEL STATUS",
        _ => "unknown proactive command",
    }
}

/// Command type from the command-details TLV (tag 01 or 81, length 3) at the
/// front of a proactive command (`D0 ..`) or a terminal response.
fn command_details_type(d: &[u8]) -> Option<u8> {
    let d = match d {
        [0xD0, 0x81, _, rest @ ..] | [0xD0, _, rest @ ..] => rest,
        _ => d,
    };
    match d {
        [0x01 | 0x81, 0x03, _, t, ..] => Some(*t),
        _ => None,
    }
}

fn describe(
    sel: &mut Selected,
    h: [u8; 4],
    data: &[u8],
    rsp: &[u8],
    sw: Option<StatusWord>,
) -> (String, String) {
    let [cla, ins, p1, p2] = h;
    let ok = sw.is_some_and(|s| s.is_normal_processing());
    // GET STATUS shares INS F2 with UICC STATUS; P1 tells them apart.
    // GP only at CLA 80/84; CLA 00 E2/E4/82 are ISO (APPEND RECORD, DELETE FILE, EXTERNAL AUTHENTICATE).
    let gp = matches!(cla, 0x80 | 0x84)
        && (matches!(ins, 0xE6 | 0xE8 | 0xD8 | 0xE2 | 0xE4 | 0xF0 | 0x50 | 0x82)
            || (ins == 0xF2 && matches!(p1, 0x80 | 0x40 | 0x20 | 0x10)));
    let n = |s: &str, d: String| (s.to_owned(), d);
    if gp {
        return match ins {
            0xE6 => {
                let (mode, fields): (&str, &[&str]) = match p1 & 0x7F {
                    0x02 => ("for load", &["load_file", "security_domain"]),
                    0x04 => ("for install", &["load_file", "module", "application"]),
                    0x08 => (
                        "for make selectable",
                        &["load_file", "module", "application"],
                    ),
                    0x0C => (
                        "for install and make selectable",
                        &["load_file", "module", "application"],
                    ),
                    0x10 => ("for personalization", &[]),
                    0x20 => ("for registry update", &[]),
                    0x40 => ("for extradition", &["security_domain"]),
                    _ => ("(unknown P1)", &[]),
                };
                n(
                    "GP INSTALL",
                    format!("{mode} {}", lv_fields(data, fields)).trim().into(),
                )
            }
            0xE8 => n(
                "GP LOAD",
                format!(
                    "block {p2}{}, {} bytes",
                    if p1 & 0x80 != 0 { "" } else { " (last)" },
                    data.len()
                ),
            ),
            0xD8 => n(
                "GP PUT KEY",
                format!(
                    "key set version {p1:02X}, key id {p2:02X}, key data {}",
                    hex::encode_upper(data)
                ),
            ),
            0xF2 => n(
                "GP GET STATUS",
                match p1 {
                    0x80 => "issuer security domain",
                    0x40 => "applications and SDs",
                    0x20 => "executable load files",
                    _ => "executable load files and modules",
                }
                .into(),
            ),
            0xE2 => n(
                "GP STORE DATA",
                format!("P1={p1:02X} block {p2}, {} bytes", data.len()),
            ),
            0xE4 => n("GP DELETE", hex::encode_upper(data)),
            0xF0 => n(
                "GP SET STATUS",
                format!("P1={p1:02X} P2={p2:02X} {}", hex::encode_upper(data)),
            ),
            0x50 => n(
                "GP INITIALIZE UPDATE",
                format!("host challenge {}", hex::encode_upper(data)),
            ),
            _ => n(
                "GP EXTERNAL AUTHENTICATE",
                format!("security level {p1:02X}, {} bytes", data.len()),
            ),
        };
    }
    match ins {
        0xA4 => {
            let mode = match p1 {
                0x00 => "by file id",
                0x01 => "child DF",
                0x02 => "EF under current DF",
                0x03 => "parent DF",
                0x04 => "by DF name",
                0x08 => "path from MF",
                0x09 => "path from current DF",
                _ => "(P1 unknown)",
            };
            let target = match p1 {
                0x00..=0x02 if data.is_empty() => "MF".to_owned(),
                0x04 => format!("AID {}", hex::encode_upper(data)),
                _ => hex::encode_upper(data),
            };
            if ok {
                match p1 {
                    0x00 if data.is_empty() => sel.select_fid(0x3F00),
                    0x00..=0x02 => {
                        if let Some(fid) = be16(data) {
                            sel.select_fid(fid);
                        }
                    }
                    0x03 => {
                        sel.path.pop();
                        sel.last_is_ef = false;
                    }
                    0x04 => {
                        sel.path = vec![format!("ADF {}", hex::encode_upper(data))];
                        sel.last_is_ef = false;
                    }
                    0x08 | 0x09 => {
                        if p1 == 0x08 {
                            sel.path = vec!["3F00".into()];
                            sel.last_is_ef = false;
                        }
                        for fid in data.chunks_exact(2) {
                            sel.select_fid(u16::from_be_bytes([fid[0], fid[1]]));
                        }
                    }
                    _ => {}
                }
            }
            n("SELECT", format!("{mode} {target}"))
        }
        0xB0 | 0xD6 => {
            let name = if ins == 0xB0 {
                "READ BINARY"
            } else {
                "UPDATE BINARY"
            };
            let d = if p1 & 0x80 != 0 {
                format!("SFI {:02X}, offset {p2}", p1 & 0x1F)
            } else {
                format!("offset {}", u16::from_be_bytes([p1, p2]))
            };
            n(
                name,
                if ins == 0xD6 {
                    format!("{d}, {} bytes", data.len())
                } else {
                    d
                },
            )
        }
        0xB2 | 0xDC => {
            let name = if ins == 0xB2 {
                "READ RECORD"
            } else {
                "UPDATE RECORD"
            };
            let mode = match p2 & 0x07 {
                2 => "next",
                3 => "previous",
                4 => "absolute/current",
                _ => "first/last",
            };
            let sfi = if p2 >> 3 == 0 {
                "current EF".to_owned()
            } else {
                format!("SFI {:02X}", p2 >> 3)
            };
            n(name, format!("record {p1} ({mode}), {sfi}"))
        }
        0x20 | 0x24 | 0x26 | 0x28 | 0x2C => {
            let name = match ins {
                0x20 => "VERIFY PIN",
                0x24 => "CHANGE PIN",
                0x26 => "DISABLE PIN",
                0x28 => "ENABLE PIN",
                _ => "UNBLOCK PIN",
            };
            let d = if data.is_empty() {
                "status query".into()
            } else {
                format!("value {}", hex::encode_upper(data))
            };
            n(name, format!("{}, {d}", key_ref(p2)))
        }
        0x88 => n(
            "AUTHENTICATE",
            format!(
                "{} context, {}",
                match p2 {
                    0x00 => "GSM",
                    0x80 => "UMTS",
                    _ => "other",
                },
                hex::encode_upper(data)
            ),
        ),
        0xC0 => n("GET RESPONSE", format!("{} bytes received", rsp.len())),
        0xF2 => n(
            "STATUS",
            format!(
                "{}, {}",
                match p1 {
                    0x00 => "no indication",
                    0x01 => "application initialized",
                    0x02 => "application terminated",
                    _ => "P1 unknown",
                },
                match p2 {
                    0x00 => "return FCP",
                    0x01 => "return DF name",
                    0x0C => "no data",
                    _ => "P2 unknown",
                }
            ),
        ),
        0xCA | 0xCB => {
            let tag = match (p1, p2) {
                (0x9F, 0x7F) => " (CPLC)",
                (0x00, 0x66) => " (card data)",
                (0x00, 0xE0) => " (key information)",
                (0x00, 0x42) => " (IIN)",
                (0x00, 0x45) => " (CIN)",
                _ => "",
            };
            n("GET DATA", format!("tag {p1:02X}{p2:02X}{tag}"))
        }
        0xDA | 0xDB => n(
            "PUT DATA",
            format!("tag {p1:02X}{p2:02X}, {} bytes", data.len()),
        ),
        0xC2 => {
            let kind = match data.first() {
                Some(0xD1) => "SMS-PP download",
                Some(0xD2) => "cell broadcast download",
                Some(0xD3) => "menu selection",
                Some(0xD4) => "call control",
                Some(0xD5) => "MO SMS control",
                Some(0xD6) => "event download",
                Some(0xD7) => "timer expiration",
                Some(0xD9) => "USSD download",
                _ => "unknown envelope",
            };
            n("ENVELOPE", format!("{kind}, {} bytes", data.len()))
        }
        0x12 => n(
            "FETCH",
            command_details_type(rsp).map_or_else(
                || format!("{} bytes", rsp.len()),
                |t| proactive_type(t).to_owned(),
            ),
        ),
        0x14 => {
            let t = command_details_type(data).map_or("unknown", proactive_type);
            n("TERMINAL RESPONSE", format!("to {t}"))
        }
        0x10 => n("TERMINAL PROFILE", format!("{} bytes", data.len())),
        0x70 => n(
            "MANAGE CHANNEL",
            format!("{} channel {p2}", if p1 == 0 { "open" } else { "close" }),
        ),
        0xE2 => n("APPEND RECORD", hex::encode_upper(data)),
        0xE4 => n("DELETE FILE", hex::encode_upper(data)),
        0x82 => n("EXTERNAL AUTHENTICATE", hex::encode_upper(data)),
        0x04 => n("DEACTIVATE FILE", String::new()),
        0x44 => n("ACTIVATE FILE", String::new()),
        0xA2 => n("SEARCH RECORD", hex::encode_upper(data)),
        0x32 => n("INCREASE", hex::encode_upper(data)),
        _ => n(
            "UNKNOWN",
            format!("CLA {cla:02X} INS {ins:02X} P1 {p1:02X} P2 {p2:02X}"),
        ),
    }
}

/// What the human table shows. Display only: [`decode`] and the JSON keep every exchange.
#[derive(Debug, Clone, Copy, Default)]
pub struct Display {
    /// Print each exchange's raw command and response hex under its row (`--show-raw-apdu`).
    pub show_raw_apdu: bool,
    /// Keep SELECT rows (`--no-suppress-select`). Hidden by default, as in pySim-trace.
    pub show_select: bool,
    /// Keep UICC STATUS rows (`--no-suppress-status`). Hidden by default, as in pySim-trace.
    /// GP GET STATUS (INS F2 under a GP class) is a different command and is never hidden.
    pub show_status: bool,
}

/// The human table: two lines per exchange. Row numbers are the trace positions, so a hidden
/// row leaves a gap rather than renumbering the ones after it.
pub fn render(rows: &[Decoded], display: Display) -> String {
    let mut out = String::new();
    for (i, r) in rows.iter().enumerate() {
        if (r.name == "SELECT" && !display.show_select)
            || (r.name == "STATUS" && !display.show_status)
        {
            continue;
        }
        out.push_str(&format!(
            "{:>3}  {:<22} {}\n     -> {} {}   [{}]\n",
            i + 1,
            r.name,
            r.detail,
            r.status.as_deref().unwrap_or("----"),
            r.meaning,
            r.selected,
        ));
        if display.show_raw_apdu {
            let raw = format!("     raw: {} {}", r.command, r.response);
            out.push_str(raw.trim_end());
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str) -> Vec<Decoded> {
        decode(&parse(input).unwrap())
    }

    #[test]
    fn tca_loader_log_pairs_each_command_with_its_response() {
        let log = "TCA Loader 1.2 started\n\
            Command A0A40000023F00\n\
            Response 9F16\n\
            Stray Response 9000\n\
            Command A0C0000016\n\
            Response 000000000000000000000000000000000000000000009000\n\
            Command A0A40000026F07\n";
        let pairs = parse_bytes(log.as_bytes()).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].1, hex::decode("A0A40000023F00").unwrap());
        assert_eq!(pairs[0].2, hex::decode("9F16").unwrap());
        assert_eq!(pairs[1].2.len(), 24);
        // A command the log ends on keeps an empty response, so it can be flagged.
        assert!(pairs[2].2.is_empty());
        let rows = decode(&pairs);
        assert_eq!(rows[0].name, "SELECT");
        assert_eq!(rows[0].selected, "3F00");
        assert_eq!(rows[1].name, "GET RESPONSE");
        // The SELECT the log ends on has no response, so the selection does not move.
        assert_eq!(rows[2].selected, "3F00");
    }

    #[test]
    fn tca_loader_log_refuses_bad_hex_and_empty_logs() {
        assert!(parse_tca_loader_log("Command A0A4\nResponse ZZ\n")
            .unwrap_err()
            .contains("line 2"));
        assert!(parse_tca_loader_log("Command\n")
            .unwrap_err()
            .contains("line 1"));
        assert!(parse_tca_loader_log("just a banner\n").is_err());
    }

    #[test]
    fn select_get_response_read_binary_track_the_file() {
        let rows = run("
            A0A40000023F00   # SELECT MF
            9F16
            A0C0000016
            000000000000000000000000000000000000000000009000
            A0A40000026F07
            9F0F
            A0B0000009
            0102030405060708099000
            A0A40000026F99
            9404
        ");
        assert_eq!(rows[0].name, "SELECT");
        assert_eq!(rows[0].selected, "3F00");
        assert!(rows[0].meaning.contains("response bytes"));
        assert_eq!(rows[1].name, "GET RESPONSE");
        assert_eq!(rows[2].selected, "3F00/6F07");
        assert_eq!(rows[3].name, "READ BINARY");
        assert_eq!(rows[3].detail, "offset 0");
        assert_eq!(rows[3].meaning, "success");
        // A refused SELECT leaves the selection alone.
        assert_eq!(rows[4].selected, "3F00/6F07");
        assert_eq!(rows[4].meaning, "file ID not found");
    }

    #[test]
    fn pin_values_are_shown_in_full_and_retries_decoded() {
        let rows = run("002000010831323334FFFFFFFF\n63C2");
        assert_eq!(rows[0].name, "VERIFY PIN");
        assert!(rows[0].detail.contains("31323334FFFFFFFF"));
        assert_eq!(rows[0].command, "002000010831323334FFFFFFFF");
        assert_eq!(rows[0].meaning, "verification failed, 2 tries left");
    }

    #[test]
    fn gp_install_and_load() {
        let rows = run("
            80E602000705AABBCCDDEE00
            9000
            80E80000 05 C403010203
            9000
        ");
        assert_eq!(rows[0].name, "GP INSTALL");
        assert!(rows[0].detail.starts_with("for load load_file=AABBCCDDEE"));
        assert_eq!(rows[1].name, "GP LOAD");
        assert_eq!(rows[1].detail, "block 0 (last), 5 bytes");
    }

    #[test]
    fn our_gp_trace_json_decodes() {
        let json = r#"{"data":{"trace":[
            {"step":"select","command":"00A4040008A000000151000000","response":"6A82"}]}}"#;
        let rows = run(json);
        assert_eq!(rows[0].step.as_deref(), Some("select"));
        assert_eq!(rows[0].detail, "by DF name AID A000000151000000");
        assert_eq!(rows[0].meaning, "file or application not found");
        assert_eq!(rows[0].selected, "(none)");
    }

    #[test]
    fn fetch_and_terminal_response_are_named() {
        let rows = run("
            801200000D
            D00B8103012100820281029100
            8014000009 810301210082028281
            9000
        ");
        assert_eq!(rows[0].detail, "DISPLAY TEXT");
        assert_eq!(rows[1].name, "TERMINAL RESPONSE");
        assert_eq!(rows[1].detail, "to DISPLAY TEXT");
    }

    #[test]
    fn bad_hex_is_an_error() {
        assert!(parse("zz").is_err());
        assert!(parse("A0A\n9000").is_err()); // odd-length hex
    }

    #[test]
    fn secrets_reach_json_in_full() {
        let rows = run("
            002000010831323334FFFFFFFF
            9000
            80D80000 04 CAFEBABE
            9000
            0082000008 DEADBEEF01020304
            9000
            008800 0010 AABBCCDDEEFF00112233445566778899
            DB08 C1C2C3C4C5C6C7C8 9000
        ");
        let out: String = rows
            .iter()
            .enumerate()
            .map(|(i, r)| r.to_json(i + 1).to_string())
            .collect();
        for secret in ["31323334", "CAFEBABE", "DEADBEEF", "C1C2C3C4"] {
            assert!(out.contains(secret), "{secret} missing: {out}");
        }
        assert!(!out.contains("redacted"));
        assert!(out.contains("AABBCCDD"));
    }

    #[test]
    fn iso_cla_00_is_not_labelled_gp() {
        let rows = run("00E2000002AABB\n9000\n00E4000002AABB\n9000\n0082000002AABB\n9000");
        assert_eq!(rows[0].name, "APPEND RECORD");
        assert_eq!(rows[1].name, "DELETE FILE");
        assert_eq!(rows[2].name, "EXTERNAL AUTHENTICATE");
    }

    #[test]
    fn truncated_apdu_is_an_unknown_row_and_does_not_desync() {
        let rows = run("00A4\n6700\n00A40000023F00\n9000");
        assert_eq!(rows[0].name, "UNKNOWN");
        assert_eq!(rows[1].selected, "3F00");
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    fn row(name: &str, status: Option<&str>) -> Decoded {
        Decoded {
            step: None,
            command: "00A40004023F00".into(),
            response: "9000".into(),
            name: name.into(),
            detail: "by file id 3F00".into(),
            status: status.map(str::to_owned),
            meaning: "success".into(),
            selected: "3F00".into(),
        }
    }

    fn rows() -> Vec<Decoded> {
        vec![
            row("SELECT", Some("9000")),
            row("READ BINARY", Some("9000")),
            row("STATUS", Some("9000")),
            row("GP GET STATUS", Some("9000")),
        ]
    }

    #[test]
    fn select_and_uicc_status_rows_are_hidden_by_default() {
        let text = render(&rows(), Display::default());
        assert!(!text.contains("SELECT"), "{text}");
        assert!(!text.contains("  STATUS "), "{text}");
        assert!(text.contains("READ BINARY"), "{text}");
        assert!(text.contains("GP GET STATUS"), "{text}");
    }

    #[test]
    fn no_suppress_select_keeps_select_rows() {
        let text = render(
            &rows(),
            Display {
                show_select: true,
                ..Display::default()
            },
        );
        assert!(text.contains("SELECT"), "{text}");
        assert!(!text.contains("  STATUS "), "{text}");
    }

    #[test]
    fn no_suppress_status_keeps_uicc_status_rows_only() {
        let text = render(
            &rows(),
            Display {
                show_status: true,
                ..Display::default()
            },
        );
        assert!(text.contains("  STATUS "), "{text}");
        assert!(!text.contains("SELECT"), "{text}");
    }

    #[test]
    fn rows_keep_their_trace_numbers_when_others_are_hidden() {
        let text = render(&rows(), Display::default());
        assert!(text.starts_with("  2  READ BINARY"), "{text}");
    }

    #[test]
    fn show_raw_apdu_prints_command_and_response_hex() {
        let text = render(
            &rows()[..1],
            Display {
                show_raw_apdu: true,
                show_select: true,
                ..Display::default()
            },
        );
        assert!(text.contains("     raw: 00A40004023F00 9000\n"), "{text}");
        let plain = render(
            &rows()[..1],
            Display {
                show_select: true,
                ..Display::default()
            },
        );
        assert!(!plain.contains("raw:"), "{plain}");
    }
}
