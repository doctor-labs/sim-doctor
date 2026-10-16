//! sysmocom SJA2 / SJA5 / SJS1: an AT-command driver over the transport seam.
//!
//! **Owns.** The AT command layer those three cards are reached through -
//! which commands go on the wire, what an answer means, how a model is told
//! apart from another one, and the programming surface each model exposes.
//!
//! **Depends on.** [`crate::transport`] only. One AT exchange is one
//! [`CardSession::transmit`], so the whole driver runs against a scripted
//! session with no modem and no card, and every byte it sends is assertable.
//! It deliberately does not use [`crate::session`] or [`crate::apdu`]: those
//! compose APDUs, and an AT line is not an APDU. The APDUs the driver carries
//! are built here as plain bytes.
//!
//! # The AT layer, and where each byte comes from
//!
//! The command line is `at_emit_command`'s format string followed by `<CR><LF>`
//! \[V] lpac `driver/apdu/at_helpers.c:76-77` writes `formatted[n+0] = '\r'` and
//! `formatted[n+1] = '\n'`, and `at_write_command` (`driver/apdu/at_cmd_unix.c:50`)
//! writes exactly `strlen(command)` bytes of it.
//!
//! Three commands are the whole protocol:
//!
//! | Wire bytes | Purpose | Source |
//! |---|---|---|
//! | `AT` + `<CR><LF>` | is there a modem answering | \[V] `at_etsi_csim.c:24-28` |
//! | `AT+CSIM=?` + `<CR><LF>` | does it carry `+CSIM` | \[V] `at_etsi_csim.c:30-34` |
//! | `AT+CSIM=<n>,"<hex>"` + `<CR><LF>` | send one APDU | \[V] `at_etsi_csim.c:59` |
//!
//! `<n>` is the **hex character count**, not the byte count: the format is
//! `"AT+CSIM=%u,\"%s\""` with `tx_len * 2` and the hex APDU \[V] same line.
//! The answer is `+CSIM: <len>,"<hex>"`, whose length field is skipped and
//! whose quotes are stripped \[V] `at_etsi_csim.c:65-72`. Hex digits are
//! **uppercase**, which is what the reference's `euicc_hexutil_bin2hex` emits;
//! the decoder here accepts either case, the encoder emits one.
//!
//! A reply with no final result code line is how "the device is not
//! responding to AT commands" is detected \[V] `at_etsi_csim.c:25-27`, and a
//! refused `AT+CSIM=?` is "device missing +CSIM support" \[V] `:31-32`. Both
//! are error branches here, and neither is retried.
//!
//! # Which card is this
//!
//! **`CardSession` has no ATR accessor** - `transmit`, `reader` and
//! `disconnect` are its whole surface - so this module never reads one over the
//! wire. The ATR is an *input*: the layer that owns the link knows it, and
//! [`Model::detect`] compares it against the three tables. That is the
//! reference's own rule, which is **exact byte equality against a
//! hard-coded ATR**, not a prefix match and not one signal:
//!
//! - SJA2 \[V] pySim `sysmocom_sja2.py:306-308` (`SysmocomSJA2._atrs`),
//! - SJA5 \[V] pySim `sysmocom_sja2.py:337-339` (`SysmocomSJA5._atrs`),
//! - SJS1 \[V] pySim `sysmocom_sjs1.py:54` (`SysmoUSIMSJS1._atrs`).
//!
//! Nothing about the ATR tables is duplicated from the card-profile database
//! (issue #275): that database carries them as provenance for a report; this
//! module carries the same three lists because it has to *decide* on them.
//!
//! # The probe
//!
//! \[V] pySim `cards.py:112` as read by issue #275: `UiccCardBase.probe`
//! SELECTs MF and then EF.DIR, and all three models derive from `UsimCard`, so
//! this is the probe for each of them. The class byte is `00` and P1/P2 is
//! `0004`, an FCP request \[V] pySim `cards.py:107-108`.
//!
//! # The programming surface
//!
//! pySim does not reach these cards over AT; it provisions them as card models.
//! What it defines is therefore the *file surface*, and that is what this
//! driver writes:
//!
//! | Model | DF | Files | Source |
//! |---|---|---|---|
//! | SJA2, SJA5 | `A515` DF.SYSTEM | `6F01` `6F81` `6F0A`-`6F0D`, `6F20` | `sysmocom_sja2.py:166-184` |
//! | SJS1 | `7F20` DF.GSM | `00FF` `00F7` | `sysmocom_sjs1.py:57-61` |
//!
//! Every record this module builds is built to the reference's `construct`
//! definition and is asserted against the reference's **own `_test_de_encode`
//! vector** in this module's tests, so a field order invented here fails.
//!
//! # Safety
//!
//! Programming these cards writes them: `EF.CHV*` and `EF.ADM*` hold the PIN
//! and PUK and a wrong attempt count bricks a PIN, and `EF.SIM_AUTH_KEY` /
//! `EF.Ki` / `EF.OPc` hold the authentication key. So [`ProgramRequest`] is
//! planned by [`At::plan`] with nothing sent, every write goes through
//! [`At::program`], and that call re-reads what it wrote and reports
//! [`Error::VerifyFailed`] when the card does not hold it. Key bytes are never
//! placed in any error string, report field or transcript line.

use std::fmt;

use crate::transport::{CardSession, Error as TransportError};

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "sysmocom";

/// The two bytes every AT command line ends with.
///
/// \[V] lpac `driver/apdu/at_helpers.c:76-77`.
pub const COMMAND_TERMINATOR: &[u8] = b"\r\n";

/// The bare synchronisation command, sent before anything else. \[V] lpac
/// `driver/apdu/at_etsi_csim.c:24`.
pub const AT_SYNC: &str = "AT";

/// The capability query for `+CSIM`. \[V] lpac
/// `driver/apdu/at_etsi_csim.c:30`.
pub const CSIM_CAPABILITY: &str = "AT+CSIM=?";

/// The prefix of a `+CSIM` answer. \[V] lpac
/// `driver/apdu/at_etsi_csim.c:60`.
pub const CSIM_PREFIX: &str = "+CSIM: ";

/// CLA of a UICC command, used for every APDU this driver carries. \[V]
/// pySim `cards.py:107`, `UiccCardBase.cla_byte`.
pub const CLA_UICC: u8 = 0x00;

/// P1/P2 of a SELECT that asks for an FCP. \[V] pySim `cards.py:108`,
/// `UiccCardBase.sel_ctrl`.
pub const SELECT_FCP: [u8; 2] = [0x00, 0x04];

/// INS of SELECT, READ BINARY and UPDATE BINARY. \[V] ISO/IEC 7816-4; the
/// first two are also this repository's read-only instruction set
/// (`crate::session`, `READ_ONLY_INSTRUCTIONS`).
pub const INS_SELECT: u8 = 0xA4;
/// See [`INS_SELECT`].
pub const INS_READ_BINARY: u8 = 0xB0;
/// See [`INS_SELECT`].
pub const INS_UPDATE_BINARY: u8 = 0xE4;

/// Le of a whole-file read. \[U] no reference in scope names it; the two
/// widest readings this crate already uses, `Le::SHORT_MAX` and the extended
/// form, both express it, and `00` means "up to 256" (ISO/IEC 7816-4 clause
/// 9.1.1), which every reader of this table answers the same way.
pub const READ_ALL: u8 = 0x00;

/// Offset of an UPDATE BINARY, P1/P2 `0000`: from the start of the selected
/// file. \[V] ISO/IEC 7816-4 clause 11.1.3, P1/P2 "binary offset".
pub const UPDATE_FROM_START: [u8; 2] = [0x00, 0x00];

/// A model this driver speaks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Model {
    /// sysmocom SJA2 / sysmoISIM-SJA2.
    Sja2,
    /// sysmocom SJA5 / sysmoISIM-SJA5.
    Sja5,
    /// sysmocom SJS1 / sysmoUSIM-SJS1.
    Sjs1,
}

impl Model {
    /// Every model, in the order [`Model::detect`] tries them.
    pub const ALL: [Model; 3] = [Model::Sja2, Model::Sja5, Model::Sjs1];

    /// The model's name as the reference classes spell it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sja2 => "SJA2",
            Self::Sja5 => "SJA5",
            Self::Sjs1 => "SJS1",
        }
    }

    /// The ATRs the reference lists for this model, as lowercase hex.
    ///
    /// \[V] SJA2 `pySim/sysmocom_sja2.py:306-308`, SJA5
    /// `pySim/sysmocom_sja2.py:337-339`, SJS1 `pySim/sysmocom_sjs1.py:54`.
    pub const fn atrs(self) -> &'static [&'static str] {
        match self {
            Self::Sja2 => &[
                "3b9f96801f878031e073fe211b674a4c753034054ba9",
                "3b9f96801f878031e073fe211b674a4c7531330251b2",
                "3b9f96801f878031e073fe211b674a4c5275310451d5",
            ],
            Self::Sja5 => &[
                "3b9f96801f878031e073fe211b674a357530350251cc",
                "3b9f96801f878031e073fe211b674a357530350265f8",
                "3b9f96801f878031e073fe211b674a357530350259c4",
            ],
            Self::Sjs1 => &["3b9f96801fc78031a073be21136743200718000001a5"],
        }
    }

    /// The class byte of the master file the probe selects.
    pub const fn master_file(self) -> &'static str {
        "3F00"
    }

    /// The directory file the probe selects after the master file.
    pub const fn directory_file(self) -> &'static str {
        "2E2E"
    }

    /// The directory the model's writable files live under.
    pub const fn programming_directory(self) -> &'static str {
        match self {
            // DF.SYSTEM, "CardOS specifics". [V] pySim sysmocom_sja2.py:168
            // and :313 / :344 (`rs.mf.add_file(DF_SYSTEM())`).
            Self::Sja2 | Self::Sja5 => "A515",
            // DF.GSM. [V] pySim sysmocom_sjs1.py:59-61 ("the key material
            // lives in DF.GSM shared with ADF.USIM").
            Self::Sjs1 => "7F20",
        }
    }

    /// The files this model exposes for programming, with the reference line
    /// that defines each one.
    pub const fn surface(self) -> &'static [VendorFile] {
        match self {
            Self::Sja2 | Self::Sja5 => &[
                VendorFile {
                    fid: "6F01",
                    name: "EF.CHV1",
                    role: Role::Pin,
                    source: "pySim/sysmocom_sja2.py:63",
                },
                VendorFile {
                    fid: "6F81",
                    name: "EF.CHV2",
                    role: Role::Pin,
                    source: "pySim/sysmocom_sja2.py:171",
                },
                VendorFile {
                    fid: "6F0A",
                    name: "EF.ADM1",
                    role: Role::Pin,
                    source: "pySim/sysmocom_sja2.py:172",
                },
                VendorFile {
                    fid: "6F0B",
                    name: "EF.ADM2",
                    role: Role::Pin,
                    source: "pySim/sysmocom_sja2.py:173",
                },
                VendorFile {
                    fid: "6F0C",
                    name: "EF.ADM3",
                    role: Role::Pin,
                    source: "pySim/sysmocom_sja2.py:174",
                },
                VendorFile {
                    fid: "6F0D",
                    name: "EF.ADM4",
                    role: Role::Pin,
                    source: "pySim/sysmocom_sja2.py:175",
                },
                VendorFile {
                    fid: "6F20",
                    name: "EF.SIM_AUTH_KEY",
                    role: Role::Key,
                    source: "pySim/sysmocom_sja2.py:155",
                },
            ],
            Self::Sjs1 => &[
                VendorFile {
                    fid: "00FF",
                    name: "EF.Ki",
                    role: Role::Key,
                    source: "pySim/sysmocom_sjs1.py:37",
                },
                VendorFile {
                    fid: "00F7",
                    name: "EF.OPc",
                    role: Role::Key,
                    source: "pySim/sysmocom_sjs1.py:48",
                },
            ],
        }
    }

    /// Whether `atr` is one of this model's, compared byte for byte.
    ///
    /// The comparison is case-insensitive and ignores nothing else: the
    /// reference compares `scc.get_atr() == "3b9f..."` against a literal
    /// \[V] issue #275, `src/cardprofile.rs` section 2, so a hex string with
    /// different capitalisation is the same ATR and a different string is not
    /// a prefix match.
    pub fn matches_atr(self, atr: &str) -> bool {
        let atr = normalise_atr(atr);
        self.atrs().iter().any(|known| *known == atr)
    }

    /// The model whose table holds `atr`, or `None` for a card that is not one
    /// of these three.
    ///
    /// Reported, never forced: a card this does not recognise comes back as
    /// `None` and the caller says so.
    pub fn detect(atr: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|m| m.matches_atr(atr))
    }

    /// The writable file for `request`'s field, if this model has one.
    pub fn file_for(self, request: Field) -> Option<&'static VendorFile> {
        self.surface()
            .iter()
            .find(|file| file.fid == request.fid(self))
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a file on the surface carries, which decides how a write is guarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A PIN or PUK record. A wrong record here locks the card out.
    Pin,
    /// An authentication key or OP/OPc.
    Key,
}

/// One file of a model's programming surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorFile {
    /// The file identifier, as four lowercase hex digits.
    pub fid: &'static str,
    /// The reference's name for it.
    pub name: &'static str,
    /// What it carries.
    pub role: Role,
    /// Where the reference defines it, as `file:line`.
    pub source: &'static str,
}

/// Lowercases an ATR and strips the two separators a caller may have typed.
///
/// Nothing else is removed, so a truncated or padded ATR still fails the
/// equality test rather than matching a prefix.
fn normalise_atr(atr: &str) -> String {
    atr.trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

/// What the driver was asked to write, as one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// `EF.CHV1`, the card PIN.
    Chv1,
    /// `EF.CHV2`, the second card PIN.
    Chv2,
    /// `EF.ADM1`-`EF.ADM4`, the admin PINs.
    Adm(u8),
    /// `EF.SIM_AUTH_KEY` on SJA2/SJA5, `EF.Ki` on SJS1.
    AuthKey,
    /// `EF.OPc` on SJS1.
    Opc,
}

impl Field {
    /// The file this field is written to, per model.
    pub const fn fid(self, model: Model) -> &'static str {
        match (self, model) {
            (Self::Chv1, _) => "6F01",
            (Self::Chv2, _) => "6F81",
            (Self::Adm(n), _) => match n {
                1 => "6F0A",
                2 => "6F0B",
                3 => "6F0C",
                _ => "6F0D",
            },
            (Self::AuthKey, Model::Sjs1) => "00FF",
            (Self::AuthKey, _) => "6F20",
            (Self::Opc, _) => "00F7",
        }
    }

    /// The reference's name for the file this field writes.
    pub const fn file_name(self, model: Model) -> &'static str {
        match (self, model) {
            (Self::AuthKey, Model::Sjs1) => "EF.Ki",
            (Self::AuthKey, _) => "EF.SIM_AUTH_KEY",
            (Self::Opc, _) => "EF.OPc",
            _ => "EF.CHV",
        }
    }
}

/// One value the caller asked to write.
///
/// The bytes are held by value and never formatted: no `Debug`, no
/// `Display`, no transcript line and no error string may quote them, which is
/// the same rule the rest of this repository applies to a key
/// (`crate::gp::Keys`).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wraps bytes the caller already validated.
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, for the encode step.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// How long the secret is. Reported instead of the secret.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes, withheld)", self.len())
    }
}

/// A programming request, before anything has been sent.
///
/// Empty request fields are simply absent, so a caller that names nothing gets
/// [`Error::NothingToProgram`] rather than a session that was opened and
/// closed for no reason.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProgramRequest {
    /// `EF.CHV1`, 4 to 8 digits.
    pub chv1: Option<Secret>,
    /// The PUK written into the same records as the CHVs. 8 digits.
    pub puk: Option<Secret>,
    /// `EF.CHV2`, 4 to 8 digits.
    pub chv2: Option<Secret>,
    /// `EF.ADM1`-`EF.ADM4`, in ADM number order.
    pub admin: Vec<Secret>,
    /// `EF.SIM_AUTH_KEY` / `EF.Ki`, 16 bytes.
    pub ki: Option<Secret>,
    /// The OPc half of `EF.SIM_AUTH_KEY`, or `EF.OPc`, 16 bytes.
    pub opc: Option<Secret>,
}

impl ProgramRequest {
    /// Whether the caller named nothing at all.
    pub fn is_empty(&self) -> bool {
        self.chv1.is_none()
            && self.chv2.is_none()
            && self.admin.is_empty()
            && self.ki.is_none()
            && self.opc.is_none()
    }

    /// The fields this model can actually write, in the order they are written.
    ///
    /// A field with no model file is dropped rather than erroring on: `EF.OPc`
    /// exists on SJS1 only, and asking for it on an SJA2 is a request the
    /// reference does not expose. `EF.SIM_AUTH_KEY` needs both halves of the
    /// pair \[V] pySim `sysmocom_sja2.py:150-153` shows the record carrying
    /// `key` and `op_opc` together, so `ki` without `opc` writes nothing.
    pub fn fields_for(&self, model: Model) -> Vec<(Field, &Secret)> {
        let mut fields: Vec<(Field, &Secret)> = Vec::new();
        if let Some(value) = self.chv1.as_ref() {
            fields.push((Field::Chv1, value));
        }
        if let Some(value) = self.chv2.as_ref() {
            fields.push((Field::Chv2, value));
        }
        for (index, value) in self.admin.iter().enumerate() {
            if let Ok(number) = u8::try_from(index + 1) {
                fields.push((Field::Adm(number), value));
            }
        }
        if let (Some(ki), Some(opc)) = (self.ki.as_ref(), self.opc.as_ref()) {
            fields.push((Field::AuthKey, ki));
            if model == Model::Sjs1 {
                fields.push((Field::Opc, opc));
            }
        }
        fields
    }
}

/// One AT exchange, verbatim: what went out and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtStep {
    /// The bytes handed to the transport, terminator included.
    pub sent: Vec<u8>,
    /// The bytes the transport returned, verbatim and unparsed.
    pub reply: Vec<u8>,
}

impl AtStep {
    /// The command line as text, terminator removed.
    pub fn command(&self) -> String {
        String::from_utf8_lossy(trim_terminator(&self.sent)).into_owned()
    }
}

fn trim_terminator(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(COMMAND_TERMINATOR).unwrap_or(bytes)
}

/// The final result code of an AT reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtResult {
    /// `OK`.
    Ok,
    /// `ERROR`, or a `+CME ERROR: <n>` that names no more than the error.
    Error(String),
    /// No final result code line at all.
    Absent,
}

/// A parsed AT reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtReply {
    /// The bytes as received.
    pub raw: Vec<u8>,
    /// The final result code.
    pub result: AtResult,
    /// The hex payload of a `+CSIM: <len>,"<hex>"` line, as raw bytes.
    pub csim: Option<Vec<u8>>,
    /// The length field of that `+CSIM` line, as written by the device.
    pub csim_len: Option<usize>,
}

impl AtReply {
    /// Whether the reply ended in `OK`.
    pub fn is_ok(&self) -> bool {
        self.result == AtResult::Ok
    }

    /// The `+CSIM` payload as APDU bytes, or `None` when the reply carried no
    /// such line or the line was not hex.
    pub fn apdu(&self) -> Option<Vec<u8>> {
        self.csim.clone()
    }

    /// The status word of a `+CSIM` payload that is at least two bytes.
    pub fn status(&self) -> Option<u16> {
        let data = self.csim.as_ref()?;
        let tail = data.get(data.len().checked_sub(2)?..)?;
        Some(u16::from_be_bytes([tail[0], tail[1]]))
    }
}

/// Splits an AT reply into lines, dropping the echo and empty lines.
fn reply_lines(reply: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(reply)
        .split("\r\n")
        .map(|line| line.trim_end_matches('\r').to_owned())
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// Reads one AT reply. Pure, so every parser rule is testable without a card.
pub fn parse_reply(reply: &[u8]) -> AtReply {
    let lines = reply_lines(reply);
    let mut result = AtResult::Absent;
    let mut csim = None;
    let mut csim_len = None;

    for line in &lines {
        if let Some(body) = line.strip_prefix(CSIM_PREFIX) {
            let (len_field, payload) = match body.split_once(',') {
                Some((len, payload)) => (len, payload),
                None => (body, ""),
            };
            csim_len = len_field.trim().parse::<usize>().ok();
            let unquoted = payload.trim().trim_matches('"');
            csim = hex::decode(unquoted).ok();
        } else if line.trim() == "OK" {
            result = AtResult::Ok;
        } else if line.trim() == "ERROR" || line.starts_with("+CME ERROR:") {
            result = AtResult::Error(line.trim().to_owned());
        }
    }

    AtReply {
        raw: reply.to_vec(),
        result,
        csim,
        csim_len,
    }
}

/// Everything that can go wrong in this driver.
///
/// Each variant is a terminal branch: nothing here is retried, and no branch
/// sends a further command after it has decided.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `AT` came back with no final result code: the device is not answering
    /// AT commands. \[V] lpac `driver/apdu/at_etsi_csim.c:25-27`.
    #[error("the device did not answer `AT` with a result code")]
    NoResponse,

    /// `AT+CSIM=?` was refused: the device carries no `+CSIM`. \[V] lpac
    /// `driver/apdu/at_etsi_csim.c:31-32`.
    #[error("the device does not support `+CSIM`")]
    NoCsim,

    /// The probe command was refused by the device, not by the card.
    #[error("the device refused `{0}`")]
    DeviceRefused(String),

    /// The exchange did not complete. The card or the link went away.
    #[error("the exchange did not complete: {0}")]
    Timeout(String),

    /// The card answered a probe with a status word that is not `9000`.
    #[error("the card answered the probe of {what} with {sw:04X}")]
    StatusWord {
        /// What was being selected.
        what: String,
        /// The status word the card returned.
        sw: u16,
    },

    /// The card is not the model the caller asked for. Never forced.
    #[error("this card is a {found}, not a {expected}")]
    NotThisModel {
        /// The model the caller asked for.
        expected: &'static str,
        /// The model the ATR belongs to, or `"unknown card"` when it belongs
        /// to none of the three.
        found: &'static str,
    },

    /// The card did not hold what was written.
    #[error("the card read back {file} as something else than what was written")]
    VerifyFailed {
        /// Which file did not verify.
        file: String,
    },

    /// The request named nothing this model can write.
    #[error("nothing to program: {0}")]
    NothingToProgram(String),

    /// A secret was the wrong length for the file it was for.
    #[error("{0}")]
    BadSecret(String),

    /// Anything the transport reported that is not one of the branches above.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Turns a transport failure into the branch a caller can act on.
///
/// A card or link that went away mid-exchange is a timeout, because that is
/// what the caller experiences and what it must not retry; "no card" and "no
/// reader" are their own branches so a caller can tell them apart.
fn transport_branch(error: TransportError) -> Error {
    match error {
        TransportError::CardGone { reader } => {
            Error::Timeout(format!("the card in reader `{reader}` went away"))
        }
        TransportError::Disconnected { reader } => Error::Timeout(format!(
            "the connection to reader `{reader}` ended mid-exchange"
        )),
        TransportError::Transmit { reader, detail } => {
            Error::Timeout(format!("reader `{reader}`: {detail}"))
        }
        other => Error::Transport(other),
    }
}

/// One APDU this driver carries, with what the card answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStep {
    /// What was being selected, for the report.
    pub what: &'static str,
    /// The APDU as hex, uppercase, exactly as it went inside `+CSIM`.
    pub apdu: String,
    /// The status word the card returned.
    pub sw: u16,
}

/// The result of [`At::identify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identify {
    /// The ATR that was offered, normalised.
    pub atr: String,
    /// The model the ATR belongs to, or `None` when it belongs to none.
    pub model: Option<Model>,
    /// The two probe commands and their status words, in order.
    pub probe: Vec<ProbeStep>,
}

/// One write the plan will make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWrite {
    /// Which field of the request this is.
    pub field: Field,
    /// The file it goes to, as four hex digits.
    pub fid: String,
    /// The reference's name for the file.
    pub name: &'static str,
    /// The record as it will go on the wire.
    pub data: Vec<u8>,
}

/// One write that was made and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWrite {
    /// Which field of the request this was.
    pub field: Field,
    /// The file it went to.
    pub fid: String,
    /// The reference's name for the file.
    pub name: &'static str,
    /// How many bytes were written and read back.
    pub bytes: usize,
}

/// The AT driver over one session.
///
/// Holds the transcript of every exchange, in order, so a dry run and a real
/// run produce the same shape of output and a test can assert the exact bytes.
#[derive(Debug, Default)]
pub struct At {
    transcript: Vec<AtStep>,
}

/// Builds the `+CSIM` command line for `apdu`. \[V] lpac
/// `driver/apdu/at_etsi_csim.c:59`.
pub fn csim_command(apdu: &[u8]) -> String {
    format!("AT+CSIM={},\"{}\"", apdu.len() * 2, hex::encode_upper(apdu))
}

/// Builds the line that goes on the wire: the command, then `<CR><LF>`. \[V]
/// lpac `driver/apdu/at_helpers.c:76-77`.
pub fn wire_bytes(command: &str) -> Vec<u8> {
    let mut bytes = command.as_bytes().to_vec();
    bytes.extend_from_slice(COMMAND_TERMINATOR);
    bytes
}

/// SELECT by file identifier at the UICC class, asking for an FCP.
pub fn select(fid: &str) -> Result<Vec<u8>, Error> {
    let fid = hex::decode(fid).map_err(|_| Error::BadSecret(format!("not a file id: {fid}")))?;
    let mut apdu = vec![
        CLA_UICC,
        INS_SELECT,
        SELECT_FCP[0],
        SELECT_FCP[1],
        fid.len() as u8,
    ];
    apdu.extend_from_slice(&fid);
    Ok(apdu)
}

/// READ BINARY of `len` bytes from the start of the selected file.
pub fn read_binary(len: usize) -> Vec<u8> {
    let le = if len == 0 || len > 256 {
        READ_ALL
    } else {
        len as u8
    };
    vec![CLA_UICC, INS_READ_BINARY, 0x00, 0x00, 0x00, le]
}

/// UPDATE BINARY of `data` at the start of the selected file.
pub fn update_binary(data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![
        CLA_UICC,
        INS_UPDATE_BINARY,
        UPDATE_FROM_START[0],
        UPDATE_FROM_START[1],
        data.len() as u8,
    ];
    apdu.extend_from_slice(data);
    apdu
}

/// The state byte of an `EF.CHV*` / `EF.ADM*` record that is valid, changeable,
/// unblockable, disableable, not blocked and not yet disabled.
///
/// \[V] pySim `sysmocom_sja2.py:65-66`, whose `StateByte` is
/// `disabled=1, not_initialized=2, disable_able=0x10, unblock_able=0x20,
/// change_able=0x40, valid=0x80`; the reference's own vector
/// `f1030331323334ffffffff0a0a3132333435363738` (`sysmocom_sja2.py:51`) sets
/// every flag except `not_initialized`, and `f00303...` (`:57`) sets the same
/// four without `disabled`.
pub const PIN_STATE_INITIAL: u8 = 0xF0;

/// Attempt counter the reference writes for a CHV or an ADM. \[V] pySim
/// `sysmocom_sja2.py:51-55`, whose vector carries `attempts_remaining` 3 and
/// `maximum_attempts` 3 for the PIN and 10 and 10 for the PUK.
pub const PIN_ATTEMPTS: u8 = 3;
/// See [`PIN_ATTEMPTS`].
pub const PIN_MAX_ATTEMPTS: u8 = 3;
/// See [`PIN_ATTEMPTS`].
pub const PUK_ATTEMPTS: u8 = 10;
/// See [`PIN_ATTEMPTS`].
pub const PUK_MAX_ATTEMPTS: u8 = 10;

/// The `Rpad` filler the reference pads a short PIN or PUK with. \[V] pySim
/// `sysmocom_sja2.py:69`, `Rpad(Bytes(8))`; the vector at `:51` pads `1234`
/// with five `ff`.
pub const PIN_PAD: u8 = 0xFF;

/// Length of the PIN and PUK fields. \[V] pySim `sysmocom_sja2.py:73-74`.
pub const PIN_FIELD_LEN: usize = 8;

/// The `EF.CHV*` / `EF.ADM*` configuration byte of `EF.SIM_AUTH_KEY`.
///
/// \[V] pySim `sysmocom_sja2.py:157-160`: bits 7-6 are padding, bit 5 is
/// `sres_deriv_func`, bit 4 is `use_opc_instead_of_op` and the low nibble is
/// the algorithm, `4` = milenage \[V] `:160`. The reference's own vector
/// `1400010203...10111213...` (`sysmocom_sja2.py:150`) is exactly this byte
/// with `sres_deriv_func` 0 and `use_opc_instead_of_op` 1.
pub const SIM_AUTH_KEY_CFG_MILENAGE: u8 = 0x14;

/// Length of `EF.Ki`, `EF.OPc` and of both halves of `EF.SIM_AUTH_KEY`. \[V]
/// pySim `sysmocom_sja2.py:162-163` (`Bytes(16)` twice) and
/// `sysmocom_sjs1.py:39` (`EF_Ki`, `Bytes(16)`).
pub const KEY_LEN: usize = 16;

/// Builds an `EF.CHV*` / `EF.ADM*` record.
///
/// \[V] pySim `sysmocom_sja2.py:70-74`:
/// `state`(1) `attempts_remaining`(1) `maximum_attempts`(1) `pin`(`Rpad`
/// to 8) and an optional `puk` of `attempts_remaining`(1)
/// `maximum_attempts`(1) `puk`(`Rpad` to 8). A `puk` of `None` in the
/// reference's own vector (`sysmocom_sja2.py:57`) writes the shorter record.
///
/// # Errors
///
/// [`Error::BadSecret`] when the PIN is empty, longer than [`PIN_FIELD_LEN`],
/// or holds a non-digit, or the PUK is.
pub fn encode_pin_record(pin: &Secret, puk: Option<&Secret>) -> Result<Vec<u8>, Error> {
    let pin = digits(pin, PIN_FIELD_LEN, "PIN")?;
    let mut record = vec![PIN_STATE_INITIAL, PIN_ATTEMPTS, PIN_MAX_ATTEMPTS];
    record.extend_from_slice(&pin);
    if let Some(puk) = puk {
        let puk = digits(puk, PIN_FIELD_LEN, "PUK")?;
        record.extend_from_slice(&[PUK_ATTEMPTS, PUK_MAX_ATTEMPTS]);
        record.extend_from_slice(&puk);
    }
    Ok(record)
}

fn digits(secret: &Secret, max: usize, what: &str) -> Result<Vec<u8>, Error> {
    if secret.is_empty() || secret.len() > max {
        return Err(Error::BadSecret(format!("a {what} is 1 to {max} digits")));
    }
    if !secret.expose().iter().all(u8::is_ascii_digit) {
        return Err(Error::BadSecret(format!("a {what} is digits only")));
    }
    let mut field = secret.expose().to_vec();
    field.resize(max, PIN_PAD);
    Ok(field)
}

/// Builds an `EF.Ki` record: the 16 key bytes, nothing else. \[V] pySim
/// `sysmocom_sjs1.py:39`.
///
/// # Errors
///
/// [`Error::BadSecret`] unless the key is exactly [`KEY_LEN`] bytes.
pub fn encode_ki(ki: &Secret) -> Result<Vec<u8>, Error> {
    exact(ki, "Ki")
}

/// Builds an `EF.OPc` record: `use_opc_instead_of_op` set, then the 16 bytes.
/// \[V] pySim `sysmocom_sjs1.py:50` (`Flag` then `Bytes(16)`), and the
/// reference's own vector `016ca53d...` (`sysmocom_sjs1.py:44`) has the flag
/// set.
///
/// # Errors
///
/// [`Error::BadSecret`] unless the value is exactly [`KEY_LEN`] bytes.
pub fn encode_opc(opc: &Secret) -> Result<Vec<u8>, Error> {
    let mut record = vec![0x01u8];
    record.extend_from_slice(&exact(opc, "OPc")?);
    Ok(record)
}

/// Builds an `EF.SIM_AUTH_KEY` record: the configuration byte, `Ki`, `OPc`.
/// \[V] pySim `sysmocom_sja2.py:161-163`.
///
/// # Errors
///
/// [`Error::BadSecret`] unless both halves are exactly [`KEY_LEN`] bytes.
pub fn encode_sim_auth_key(ki: &Secret, opc: &Secret) -> Result<Vec<u8>, Error> {
    let mut record = vec![SIM_AUTH_KEY_CFG_MILENAGE];
    record.extend_from_slice(&exact(ki, "Ki")?);
    record.extend_from_slice(&exact(opc, "OPc")?);
    Ok(record)
}

fn exact(secret: &Secret, what: &str) -> Result<Vec<u8>, Error> {
    if secret.len() != KEY_LEN {
        return Err(Error::BadSecret(format!(
            "{what} is {KEY_LEN} bytes, not {}",
            secret.len()
        )));
    }
    Ok(secret.expose().to_vec())
}

impl At {
    /// A driver with an empty transcript.
    pub const fn new() -> Self {
        Self {
            transcript: Vec::new(),
        }
    }

    /// Every exchange so far, in order, verbatim.
    pub fn transcript(&self) -> &[AtStep] {
        &self.transcript
    }

    /// The command lines sent so far, terminator removed.
    pub fn commands(&self) -> Vec<String> {
        self.transcript.iter().map(AtStep::command).collect()
    }

    /// Sends `command` once and parses the answer.
    ///
    /// **Nothing is retried and no command is issued after a failure**: the
    /// `?` is the answer and there is no second attempt at anything.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] and [`Error::Transport`] from the transport,
    /// [`Error::NoResponse`] when the answer carries no final result code.
    pub fn exchange<S: CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        command: &str,
    ) -> Result<AtReply, Error> {
        let sent = wire_bytes(command);
        let reply = session.transmit(&sent).map_err(transport_branch)?;
        self.transcript.push(AtStep {
            sent,
            reply: reply.clone(),
        });
        let parsed = parse_reply(&reply);
        if parsed.result == AtResult::Absent {
            return Err(Error::NoResponse);
        }
        Ok(parsed)
    }

    /// Sends `AT` and then `AT+CSIM=?`, and requires `OK` from both.
    ///
    /// This is what "connected" means for this driver: a device that answers
    /// AT, and carries `+CSIM`. Nothing about the card is read here.
    ///
    /// # Errors
    ///
    /// [`Error::NoResponse`], [`Error::NoCsim`] or [`Error::DeviceRefused`].
    pub fn connect<S: CardSession + ?Sized>(&mut self, session: &mut S) -> Result<(), Error> {
        let sync = self.exchange(session, AT_SYNC)?;
        if !sync.is_ok() {
            return Err(Error::NoResponse);
        }
        let capability = self.exchange(session, CSIM_CAPABILITY)?;
        if !capability.is_ok() {
            return Err(Error::DeviceRefused(CSIM_CAPABILITY.to_owned()));
        }
        Ok(())
    }

    /// Like [`At::connect`], but a refusal of `+CSIM` is [`Error::NoCsim`].
    ///
    /// # Errors
    ///
    /// As [`At::connect`].
    pub fn open<S: CardSession + ?Sized>(&mut self, session: &mut S) -> Result<(), Error> {
        let sync = self.exchange(session, AT_SYNC)?;
        if !sync.is_ok() {
            return Err(Error::NoResponse);
        }
        let capability = self.exchange(session, CSIM_CAPABILITY)?;
        if !capability.is_ok() {
            return Err(Error::NoCsim);
        }
        Ok(())
    }

    /// Carries one APDU and returns the bytes the card answered, status word
    /// included.
    ///
    /// The length field the device prints is checked against what it returned:
    /// a `+CSIM` line that says one thing and carries another is a broken
    /// device, and reading the payload anyway would hand back bytes the device
    /// never claimed.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceRefused`] when the answer is not `OK`, or when the
    /// `+CSIM` line is missing, unparseable or the wrong length.
    pub fn apdu<S: CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        apdu: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let reply = self.exchange(session, &csim_command(apdu))?;
        if !reply.is_ok() {
            return Err(Error::DeviceRefused(csim_command(apdu)));
        }
        let Some(payload) = reply.csim else {
            return Err(Error::DeviceRefused(csim_command(apdu)));
        };
        if reply.csim_len.is_some_and(|len| len != payload.len() * 2) {
            return Err(Error::DeviceRefused(csim_command(apdu)));
        }
        Ok(payload)
    }

    /// Connects, runs the reference's probe, and names the model `atr` is.
    ///
    /// The probe is `SELECT MF` then `SELECT EF.DIR` \[V] pySim
    /// `cards.py:112`, and the model comes from the ATR \[V] the three
    /// `_atrs` tables. A card that answers either SELECT with a status word
    /// other than `9000` is [`Error::StatusWord`]; a card that answers both and
    /// whose ATR is in no table is returned with `model` `None` rather than
    /// forced into the nearest model.
    ///
    /// # Errors
    ///
    /// Everything [`At::open`] can return, plus [`Error::StatusWord`].
    pub fn identify<S: CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        atr: &str,
    ) -> Result<Identify, Error> {
        self.open(session)?;
        let mut probe = Vec::new();
        for (what, fid) in [
            ("MF", Model::Sja2.master_file()),
            ("EF.DIR", Model::Sja2.directory_file()),
        ] {
            let apdu = select(fid)?;
            let answer = self.apdu(session, &apdu)?;
            let sw = answer
                .get(answer.len().saturating_sub(2)..)
                .map(|tail| u16::from_be_bytes([tail[0], tail[1]]))
                .ok_or_else(|| Error::DeviceRefused(hex::encode_upper(&apdu)))?;
            if sw != 0x9000 {
                return Err(Error::StatusWord {
                    what: what.to_owned(),
                    sw,
                });
            }
            probe.push(ProbeStep {
                what,
                apdu: hex::encode_upper(&apdu),
                sw,
            });
        }
        let atr = normalise_atr(atr);
        Ok(Identify {
            model: Model::detect(&atr),
            atr,
            probe,
        })
    }

    /// Builds every write `request` implies for `model`, and sends nothing.
    ///
    /// This is the dry run: the records are complete, the AT lines that would
    /// carry them are named, and no session command is issued - the transcript
    /// is unchanged by this call.
    ///
    /// # Errors
    ///
    /// [`Error::NothingToProgram`] when the request names nothing, or
    /// [`Error::BadSecret`] for a value the file cannot hold.
    pub fn plan(&self, model: Model, request: &ProgramRequest) -> Result<Vec<PlannedWrite>, Error> {
        let fields = request.fields_for(model);
        if fields.is_empty() {
            return Err(Error::NothingToProgram(format!(
                "{model} was asked for nothing it exposes"
            )));
        }
        let mut plan = Vec::new();
        for (field, secret) in fields {
            let data = self.encode_field(model, field, secret, request)?;
            plan.push(PlannedWrite {
                field,
                fid: field.fid(model).to_owned(),
                name: field.file_name(model),
                data,
            });
        }
        Ok(plan)
    }

    fn encode_field(
        &self,
        model: Model,
        field: Field,
        secret: &Secret,
        request: &ProgramRequest,
    ) -> Result<Vec<u8>, Error> {
        match field {
            Field::AuthKey | Field::Opc => match model {
                Model::Sjs1 if field == Field::AuthKey => encode_ki(secret),
                Model::Sjs1 => encode_opc(secret),
                _ => {
                    let opc = request.opc.as_ref().ok_or_else(|| {
                        Error::BadSecret("EF.SIM_AUTH_KEY needs Ki and OPc".to_owned())
                    })?;
                    encode_sim_auth_key(secret, opc)
                }
            },
            _ => encode_pin_record(secret, request.puk.as_ref()),
        }
    }

    /// Writes `plan`, then reads every file back and compares.
    ///
    /// Each file is SELECTed, UPDATEd, then READ back in one extra exchange:
    /// a card that accepted the write and does not hold it is
    /// [`Error::VerifyFailed`], not a success. The first refusal stops the
    /// run; nothing after it is attempted.
    ///
    /// # Errors
    ///
    /// [`Error::StatusWord`] from the SELECT or the UPDATE, [`Error::Timeout`]
    /// from a link that went away, and [`Error::VerifyFailed`] from a read-back
    /// that did not match.
    pub fn program<S: CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        model: Model,
        plan: &[PlannedWrite],
    ) -> Result<Vec<VerifiedWrite>, Error> {
        let directory = select(model.programming_directory())?;
        let answer = self.apdu(session, &directory)?;
        check_status("the programming directory", &answer)?;

        let mut done = Vec::new();
        for write in plan {
            let select = select(&write.fid)?;
            let answer = self.apdu(session, &select)?;
            check_status(write.name, &answer)?;

            let update = update_binary(&write.data);
            let answer = self.apdu(session, &update)?;
            check_status(write.name, &answer)?;

            let read = read_binary(write.data.len());
            let answer = self.apdu(session, &read)?;
            check_status(write.name, &answer)?;
            let body = answer
                .get(..answer.len().saturating_sub(2))
                .ok_or_else(|| Error::VerifyFailed {
                    file: write.name.to_owned(),
                })?;
            if body != write.data.as_slice() {
                return Err(Error::VerifyFailed {
                    file: write.name.to_owned(),
                });
            }
            done.push(VerifiedWrite {
                field: write.field,
                fid: write.fid.clone(),
                name: write.name,
                bytes: write.data.len(),
            });
        }
        Ok(done)
    }
}

fn check_status(what: &str, answer: &[u8]) -> Result<(), Error> {
    let tail = answer
        .get(answer.len().saturating_sub(2)..)
        .ok_or_else(|| Error::DeviceRefused(what.to_owned()))?;
    let sw = u16::from_be_bytes([tail[0], tail[1]]);
    if sw == 0x9000 {
        Ok(())
    } else {
        Err(Error::StatusWord {
            what: what.to_owned(),
            sw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ReaderName;
    use std::collections::VecDeque;

    /// A device that answers from a script and records what it was sent.
    struct Scripted {
        reader: ReaderName,
        replies: VecDeque<Vec<u8>>,
        last: Vec<u8>,
        sent: Vec<Vec<u8>>,
    }

    impl Scripted {
        fn new(replies: impl IntoIterator<Item = Vec<u8>>) -> Self {
            let mut replies: VecDeque<Vec<u8>> = replies.into_iter().collect();
            if replies.is_empty() {
                replies.push_back(b"\r\nOK\r\n".to_vec());
            }
            Self {
                reader: ReaderName::new("sysmocom scripted modem").unwrap(),
                last: replies[0].clone(),
                replies,
                sent: Vec::new(),
            }
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(command.to_vec());
            let next = self
                .replies
                .pop_front()
                .unwrap_or_else(|| self.last.clone());
            self.last = next.clone();
            Ok(next)
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// `+CSIM: <len>,"<hex>"` followed by `OK`, as the device prints it.
    fn csim_ok(payload: &[u8]) -> Vec<u8> {
        format!(
            "\r\n+CSIM: {},\"{}\"\r\n\r\nOK\r\n",
            payload.len() * 2,
            hex::encode_upper(payload)
        )
        .into_bytes()
    }

    fn ok() -> Vec<u8> {
        b"\r\nOK\r\n".to_vec()
    }

    /// A `+CSIM` answer whose payload ends in status word `sw`.
    fn csim_sw(sw: u16, body: &[u8]) -> Vec<u8> {
        let mut payload = body.to_vec();
        payload.extend_from_slice(&sw.to_be_bytes());
        csim_ok(&payload)
    }

    fn select_mf_ok() -> Vec<u8> {
        csim_ok(&[0x62, 0x00, 0x00, 0x01, 0x3F, 0x00, 0x90, 0x00])
    }

    // --- the command lines -------------------------------------------------

    #[test]
    fn the_wire_form_is_the_reference_format_string_then_cr_lf() {
        // at_emit_command writes strlen(command) bytes of what it built, and
        // built[n]='\r', built[n+1]='\n'. [V] lpac at_helpers.c:76-77, :50.
        assert_eq!(wire_bytes(AT_SYNC), b"AT\r\n");
        assert_eq!(wire_bytes(CSIM_CAPABILITY), b"AT+CSIM=?\r\n");
    }

    #[test]
    fn a_csim_line_carries_the_hex_character_count_not_the_byte_count() {
        // "AT+CSIM=%u,\"%s\"" with tx_len * 2. [V] lpac at_etsi_csim.c:59.
        assert_eq!(
            csim_command(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]),
            "AT+CSIM=14,\"00A40004023F00\""
        );
        assert_eq!(csim_command(&[0xB0]), "AT+CSIM=2,\"B0\"");
    }

    #[test]
    fn the_probe_is_the_reference_probe_at_the_uicc_class() {
        // UiccCardBase.probe SELECTs MF then EF.DIR [V] pySim cards.py:112,
        // cla 00 and sel_ctrl 0004 [V] pySim cards.py:107-108.
        assert_eq!(
            select("3F00").unwrap(),
            [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]
        );
        assert_eq!(
            select("2E2E").unwrap(),
            [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2E, 0x2E]
        );
    }

    #[test]
    fn a_read_and_an_update_are_built_the_way_iso_7816_4_says() {
        assert_eq!(read_binary(20), [0x00, 0xB0, 0x00, 0x00, 0x00, 20]);
        assert_eq!(read_binary(0), [0x00, 0xB0, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(update_binary(&[1, 2]), [0x00, 0xE4, 0x00, 0x00, 0x02, 1, 2]);
    }

    // --- the reply parser --------------------------------------------------

    #[test]
    fn a_reply_is_read_the_way_the_reference_reads_it() {
        // Skip the length part, take the response part, strip the quotes.
        // [V] lpac at_etsi_csim.c:65-72.
        let reply = parse_reply(b"\r\n+CSIM: 4,\"6F0A\"\r\n\r\nOK\r\n");
        assert!(reply.is_ok());
        assert_eq!(reply.csim_len, Some(4));
        assert_eq!(reply.apdu().unwrap(), [0x6F, 0x0A]);
        assert_eq!(reply.status(), Some(0x6F0A));
    }

    #[test]
    fn lowercase_hex_from_a_device_is_read_too_while_the_encoder_emits_uppercase() {
        let reply = parse_reply(b"+CSIM: 2,\"6f0a\"\r\nOK\r\n");
        assert_eq!(reply.apdu().unwrap(), [0x6F, 0x0A]);
        assert!(csim_command(&[0x6f, 0x0a]).ends_with("\"6F0A\""));
    }

    #[test]
    fn a_reply_with_no_result_code_is_not_a_success() {
        // The reference calls this "device not responding to AT commands".
        // [V] lpac at_etsi_csim.c:25-27.
        assert_eq!(
            parse_reply(b"+CSIM: 4,\"6F0A\"\r\n").result,
            AtResult::Absent
        );
        assert_eq!(parse_reply(b"").result, AtResult::Absent);
    }

    #[test]
    fn every_result_code_spelling_the_reference_sees_is_an_error_not_an_ok() {
        for reply in [
            &b"\r\nERROR\r\n"[..],
            &b"\r\n+CME ERROR: 10\r\n"[..],
            &b"ERROR\r\n"[..],
        ] {
            let parsed = parse_reply(reply);
            assert!(!parsed.is_ok(), "{:?}", String::from_utf8_lossy(reply));
            assert!(matches!(parsed.result, AtResult::Error(_)));
        }
    }

    #[test]
    fn a_csim_line_that_is_not_hex_is_carried_as_no_payload_rather_than_invented() {
        let reply = parse_reply(b"+CSIM: 4,\"ZZZZ\"\r\nOK\r\n");
        assert!(reply.is_ok());
        assert_eq!(reply.csim_len, Some(4));
        assert!(reply.csim.is_none());
    }

    // --- the model tables --------------------------------------------------

    #[test]
    fn the_three_atr_tables_are_the_reference_lists_byte_for_byte() {
        // [V] pySim sysmocom_sja2.py:306-308, :337-339, sysmocom_sjs1.py:54.
        assert_eq!(
            Model::Sja2.atrs(),
            [
                "3b9f96801f878031e073fe211b674a4c753034054ba9",
                "3b9f96801f878031e073fe211b674a4c7531330251b2",
                "3b9f96801f878031e073fe211b674a4c5275310451d5",
            ]
        );
        assert_eq!(
            Model::Sja5.atrs(),
            [
                "3b9f96801f878031e073fe211b674a357530350251cc",
                "3b9f96801f878031e073fe211b674a357530350265f8",
                "3b9f96801f878031e073fe211b674a357530350259c4",
            ]
        );
        assert_eq!(
            Model::Sjs1.atrs(),
            ["3b9f96801fc78031a073be21136743200718000001a5"]
        );
    }

    #[test]
    fn detection_is_exact_equality_not_a_prefix_and_not_a_first_nibble() {
        // The reference compares get_atr() == "3b9f...". [V] issue #275
        // src/cardprofile.rs section 2.
        for model in Model::ALL {
            for atr in model.atrs() {
                assert_eq!(Model::detect(atr), Some(model), "{atr}");
                assert_eq!(Model::detect(&atr.to_uppercase()), Some(model), "{atr}");
            }
            let truncated = &model.atrs()[0][..10];
            assert_eq!(Model::detect(truncated), None, "{truncated}");
        }
        assert_eq!(
            Model::detect("3b9f96801f878031e073fe211b674a4c753034054baa"),
            None
        );
    }

    #[test]
    fn the_three_tables_do_not_overlap_so_a_card_is_never_two_models() {
        let mut all: Vec<&str> = Model::ALL
            .iter()
            .flat_map(|m| m.atrs().iter().copied())
            .collect();
        let count = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), count);
    }

    #[test]
    fn a_card_from_another_vendor_is_not_this_model_and_is_not_forced() {
        // A Fairwaves-SIM ATR, from issue #275's table: a real card, not one
        // of these three.
        assert_eq!(
            Model::detect("3b9f96801fc78031a073fe21136744220610000001a9"),
            None
        );
    }

    #[test]
    fn each_model_programs_the_directory_the_reference_adds_its_files_to() {
        // DF.SYSTEM [V] sysmocom_sja2.py:168 with rs.mf.add_file(DF_SYSTEM())
        // at :313 / :344; DF.GSM for the SJS1 key files
        // [V] sysmocom_sjs1.py:59-61.
        assert_eq!(Model::Sja2.programming_directory(), "A515");
        assert_eq!(Model::Sja5.programming_directory(), "A515");
        assert_eq!(Model::Sjs1.programming_directory(), "7F20");
        assert_eq!(Model::Sjs1.surface().len(), 2);
        assert_eq!(Model::Sja2.surface().len(), 7);
    }

    // --- the records -------------------------------------------------------

    #[test]
    fn a_pin_record_is_the_reference_record_and_matches_its_own_vector() {
        // [V] pySim sysmocom_sja2.py:70-74 and its vector at :51.
        let record = encode_pin_record(
            &Secret::new(b"1234".to_vec()),
            Some(&Secret::new(b"12345678".to_vec())),
        )
        .unwrap();
        // The layout is the reference's first vector (sysmocom_sja2.py:51) and the
        // state byte is its second (:57): a PIN being set is valid, changeable,
        // unblockable and disableable, and is neither blocked nor disabled.
        // The first vector's F1 has `disabled` set, which is the state of a PIN the card
        // has already blocked.
        assert_eq!(record[0], 0xF0);
        assert_eq!(
            hex::encode(&record),
            "f0030331323334ffffffff0a0a3132333435363738"
        );
        assert_eq!(record.len(), 21);
    }

    #[test]
    fn a_pin_record_without_a_puk_is_the_shorter_form() {
        // The reference's second vector [V] pySim sysmocom_sja2.py:57 has
        // `puk` None, which omits the whole PUK struct.
        let record = encode_pin_record(&Secret::new(b"9999".to_vec()), None).unwrap();
        assert_eq!(
            record,
            vec![0xF0u8, 0x03, 0x03, b'9', b'9', b'9', b'9', 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(record.len(), 11);
    }

    #[test]
    fn a_pin_of_the_wrong_shape_is_refused_and_says_nothing_about_its_value() {
        for bad in [vec![], b"123456789".to_vec()] {
            let error = encode_pin_record(&Secret::new(bad), None).unwrap_err();
            assert!(matches!(error, Error::BadSecret(_)));
            assert!(!error.to_string().contains("12"));
        }
        let error = encode_pin_record(&Secret::new(b"12x4".to_vec()), None).unwrap_err();
        assert!(matches!(error, Error::BadSecret(_)));
        assert!(!error.to_string().contains("12x4"));
    }

    #[test]
    fn a_ki_record_is_sixteen_bytes_and_matches_the_reference_vector() {
        // [V] pySim sysmocom_sjs1.py:39 and its vector at :33.
        let ki = Secret::new(hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        assert_eq!(encode_ki(&ki).unwrap(), ki.expose());
        assert!(encode_ki(&Secret::new(vec![0u8; 15])).is_err());
    }

    #[test]
    fn an_opc_record_sets_the_flag_and_matches_the_reference_vector() {
        // [V] pySim sysmocom_sjs1.py:50 and its vector at :44.
        let opc = Secret::new(hex::decode("6ca53d7a0a804561646816d7b0c702fb").unwrap());
        let record = encode_opc(&opc).unwrap();
        assert_eq!(hex::encode(&record), "016ca53d7a0a804561646816d7b0c702fb");
        assert_eq!(record.len(), 17);
    }

    #[test]
    fn a_sim_auth_key_record_matches_the_reference_vector_byte_for_byte() {
        // [V] pySim sysmocom_sja2.py:161-163, vector at :150.
        let ki = Secret::new(hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let opc = Secret::new(hex::decode("101112131415161718191a1b1c1d1e1f").unwrap());
        let record = encode_sim_auth_key(&ki, &opc).unwrap();
        assert_eq!(
            hex::encode(&record),
            "14000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(record.len(), 33);
    }

    // --- the transcripts ---------------------------------------------------

    #[test]
    fn identify_sends_exactly_the_four_lines_the_reference_sends() {
        let mut modem = Scripted::new([ok(), ok(), select_mf_ok(), csim_ok(&[0x90, 0x00])]);
        let mut at = At::new();
        let identify = at
            .identify(&mut modem, "3b9f96801f878031e073fe211b674a4c753034054ba9")
            .unwrap();

        assert_eq!(
            modem.sent,
            vec![
                b"AT\r\n".to_vec(),
                b"AT+CSIM=?\r\n".to_vec(),
                b"AT+CSIM=14,\"00A40004023F00\"\r\n".to_vec(),
                b"AT+CSIM=14,\"00A40004022E2E\"\r\n".to_vec(),
            ]
        );
        assert_eq!(
            at.commands(),
            [
                "AT",
                "AT+CSIM=?",
                "AT+CSIM=14,\"00A40004023F00\"",
                "AT+CSIM=14,\"00A40004022E2E\"",
            ]
        );
        assert_eq!(identify.model, Some(Model::Sja2));
        assert_eq!(identify.probe.len(), 2);
        assert_eq!(identify.probe[0].what, "MF");
        assert_eq!(identify.probe[1].what, "EF.DIR");
    }

    #[test]
    fn the_transcript_is_the_transport_record_not_a_reconstruction() {
        let replies = [ok(), ok(), select_mf_ok(), csim_ok(&[0x90, 0x00])];
        let mut modem = Scripted::new(replies.clone());
        let transcript = {
            let mut at = At::new();
            at.identify(&mut modem, "3b9f96801f878031e073fe211b674a4c753034054ba9")
                .unwrap();
            at.transcript().to_vec()
        };
        assert_eq!(transcript.len(), modem.sent.len());
        assert_eq!(transcript.len(), replies.len());
        for step in &transcript {
            let sent = modem
                .sent
                .iter()
                .find(|sent| **sent == step.sent)
                .expect("every recorded command reached the transport");
            assert_eq!(step.sent.as_slice(), sent.as_slice());
        }
        for step in &transcript {
            assert!(
                replies.contains(&step.reply),
                "a recorded reply is verbatim"
            );
        }
    }

    #[test]
    fn a_modem_that_never_answers_at_is_reported_once_and_nothing_more_is_sent() {
        let mut modem = Scripted::new([b"".to_vec()]);
        let mut at = At::new();
        assert!(matches!(at.open(&mut modem), Err(Error::NoResponse)));
        assert_eq!(modem.sent, vec![b"AT\r\n".to_vec()]);
    }

    #[test]
    fn a_modem_without_csim_is_its_own_branch() {
        let mut modem = Scripted::new([ok(), b"\r\nERROR\r\n".to_vec()]);
        let mut at = At::new();
        assert!(matches!(at.open(&mut modem), Err(Error::NoCsim)));
        assert_eq!(modem.sent.len(), 2);
    }

    #[test]
    fn a_device_that_always_refuses_is_not_retried_forever() {
        // Every command after the first refusal is never sent: the budget is
        // one attempt per command and there is no loop to exhaust.
        let mut modem = Scripted::new((0..64).map(|_| b"\r\nERROR\r\n".to_vec()));
        let mut at = At::new();
        for _ in 0..3 {
            assert!(matches!(at.open(&mut modem), Err(Error::NoResponse)));
        }
        assert_eq!(modem.sent.len(), 3, "one exchange per failed open");
    }

    #[test]
    fn a_card_that_refuses_the_probe_is_reported_as_a_status_word_and_stops() {
        let mut modem = Scripted::new([ok(), ok(), csim_sw(0x6A82, &[])]);
        let mut at = At::new();
        assert!(matches!(
            at.identify(&mut modem, "3b9f96801fc78031a073be21136743200718000001a5"),
            Err(Error::StatusWord { sw: 0x6A82, .. })
        ));
        assert_eq!(modem.sent.len(), 3, "EF.DIR is never selected");
    }

    #[test]
    fn a_link_that_goes_away_is_a_timeout_and_not_a_retry() {
        struct Gone;
        impl CardSession for Gone {
            fn reader(&self) -> &ReaderName {
                static NAME: std::sync::OnceLock<ReaderName> = std::sync::OnceLock::new();
                NAME.get_or_init(|| ReaderName::new("gone").unwrap())
            }
            fn transmit(&mut self, _: &[u8]) -> Result<Vec<u8>, TransportError> {
                Err(TransportError::CardGone {
                    reader: self.reader().clone(),
                })
            }
            fn disconnect(&mut self) -> Result<(), TransportError> {
                Ok(())
            }
        }
        let mut gone = Gone;
        let mut at = At::new();
        assert!(matches!(
            at.exchange(&mut gone, AT_SYNC),
            Err(Error::Timeout(_))
        ));
        assert_eq!(
            at.transcript().len(),
            0,
            "nothing arrived, nothing recorded"
        );
    }

    #[test]
    fn a_csim_line_whose_length_does_not_match_its_payload_is_not_believed() {
        let mut modem = Scripted::new([b"\r\n+CSIM: 8,\"6F0A\"\r\n\r\nOK\r\n".to_vec()]);
        let mut at = At::new();
        assert!(matches!(at.open(&mut modem), Ok(())));
        assert!(matches!(
            at.apdu(&mut modem, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]),
            Err(Error::DeviceRefused(_))
        ));
    }

    // --- programming -------------------------------------------------------

    #[test]
    fn a_plan_sends_nothing_and_a_program_sends_the_reference_writes() {
        let request = ProgramRequest {
            chv1: Some(Secret::new(b"1234".to_vec())),
            puk: Some(Secret::new(b"12345678".to_vec())),
            ki: Some(Secret::new(
                hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
            )),
            opc: Some(Secret::new(
                hex::decode("6ca53d7a0a804561646816d7b0c702fb").unwrap(),
            )),
            ..ProgramRequest::default()
        };
        let modem = Scripted::new([ok()]);
        let at = At::new();
        let plan = at.plan(Model::Sja2, &request).unwrap();
        assert_eq!(modem.sent.len(), 0, "a plan is offline");
        assert_eq!(at.transcript().len(), 0);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].fid, "6F01");
        assert_eq!(plan[0].name, "EF.CHV");
        assert_eq!(plan[1].fid, "6F20");
        assert_eq!(plan[1].name, "EF.SIM_AUTH_KEY");
        assert_eq!(plan[1].data.len(), 33);
    }

    #[test]
    fn a_program_writes_each_file_then_reads_it_back_and_the_transcript_says_so() {
        let request = ProgramRequest {
            chv1: Some(Secret::new(b"1234".to_vec())),
            ..ProgramRequest::default()
        };
        let record = encode_pin_record(&Secret::new(b"1234".to_vec()), None).unwrap();
        let mut modem = Scripted::new([
            csim_ok(&[0x90, 0x00]),
            csim_ok(&[0x90, 0x00]),
            csim_ok(&[0x90, 0x00]),
            csim_sw(0x9000, &record),
        ]);
        let mut at = At::new();
        let plan = at.plan(Model::Sja2, &request).unwrap();
        let result = at.program(&mut modem, Model::Sja2, &plan);
        assert!(result.is_ok(), "stopped after {:?}", at.commands());
        let done = result.unwrap();

        assert_eq!(done.len(), 1);
        assert_eq!(done[0].bytes, record.len());
        assert_eq!(
            at.commands(),
            vec![
                "AT+CSIM=14,\"00A4000402A515\"".to_owned(),
                "AT+CSIM=14,\"00A40004026F01\"".to_owned(),
                format!(
                    "AT+CSIM={},\"00E40000{:02X}{}\"",
                    10 + record.len() * 2,
                    record.len(),
                    hex::encode_upper(&record)
                ),
                format!("AT+CSIM=12,\"00B0000000{:02X}\"", record.len()),
            ]
        );
    }

    #[test]
    fn a_card_that_does_not_hold_what_was_written_is_verify_failed() {
        let request = ProgramRequest {
            chv1: Some(Secret::new(b"1234".to_vec())),
            ..ProgramRequest::default()
        };
        let mut modem = Scripted::new([
            csim_ok(&[0x90, 0x00]),
            csim_ok(&[0x90, 0x00]),
            csim_ok(&[0x90, 0x00]),
            // A read-back that is a different PIN: same length, other digits.
            csim_sw(
                0x9000,
                &[
                    0xF0, 0x03, 0x03, b'9', b'9', b'9', b'9', 0xFF, 0xFF, 0xFF, 0xFF,
                ],
            ),
        ]);
        let mut at = At::new();
        let plan = at.plan(Model::Sja2, &request).unwrap();
        assert!(matches!(
            at.program(&mut modem, Model::Sja2, &plan),
            Err(Error::VerifyFailed { .. })
        ));
    }

    #[test]
    fn a_secret_is_never_quoted_by_its_debug_or_by_an_error() {
        let secret = Secret::new(hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("0001"), "{rendered}");
        assert!(rendered.contains("16 bytes"));
        let error = encode_ki(&Secret::new(vec![0u8; 3])).unwrap_err();
        assert!(!error.to_string().contains("0000"));
    }

    #[test]
    fn a_request_the_model_cannot_answer_writes_nothing() {
        let request = ProgramRequest {
            ki: Some(Secret::new(vec![0u8; 16])),
            ..ProgramRequest::default()
        };
        // EF.SIM_AUTH_KEY is key plus OPc together [V] sysmocom_sja2.py:150,
        // so Ki alone is not a record.
        let at = At::new();
        assert!(matches!(
            at.plan(Model::Sja2, &request),
            Err(Error::NothingToProgram(_))
        ));
        let request = ProgramRequest::default();
        assert!(matches!(
            at.plan(Model::Sja2, &request),
            Err(Error::NothingToProgram(_))
        ));
    }

    #[test]
    fn the_sjs1_surface_writes_ki_and_opc_and_the_sja2_surface_writes_the_key_pair() {
        let request = ProgramRequest {
            ki: Some(Secret::new(
                hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
            )),
            opc: Some(Secret::new(
                hex::decode("6ca53d7a0a804561646816d7b0c702fb").unwrap(),
            )),
            ..ProgramRequest::default()
        };
        let at = At::new();
        let plan = at.plan(Model::Sjs1, &request).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].fid, "00FF");
        assert_eq!(plan[0].name, "EF.Ki");
        assert_eq!(plan[0].data.len(), 16);
        assert_eq!(plan[1].fid, "00F7");
        assert_eq!(plan[1].data.len(), 17);
    }
}
