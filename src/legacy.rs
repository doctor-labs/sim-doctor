//! legacy magic-SIM, OpenCells, GrCard and sysmoSIMgr2: card drivers over the
//! existing AT seam.
//!
//! **Owns.** The four legacy card models pySim still carries in
//! `pySim/legacy/cards.py`: how each one is told apart from the others, the
//! probe that identifies it, and the exact APDU sequence its `program()` sends.
//!
//! **Depends on.** [`crate::sysmocom`] for the AT command layer - the same
//! three AT commands, the same `+CSIM` framing, the same transcript and the
//! same error enum. This module does **not** define a second driver framework:
//! it builds legacy-shaped APDUs and hands them to [`sysmocom::At`], which is
//! what puts them on the wire. The `AT`, `AT+CSIM=?` and
//! `AT+CSIM=<hex-char-count>,"<hex>"` exchanges are not repeated here.
//!
//! # These four are GSM SIMs, not UICC/USIMs
//!
//! That is the whole reason they need their own APDU shapes, and it is the
//! substantive difference from issue #283, whose three models are USIMs.
//!
//! | | legacy (this module) | #283 sysmocom |
//! |---|---|---|
//! | class byte | `A0` \[V] pySim `cards.py:94` (`SimCardBase.cla_byte`) | `00` \[V] `cards.py:107` |
//! | SELECT P1/P2 | `0000` \[V] `cards.py:95` (`sel_ctrl`) | `0004` \[V] `cards.py:108` |
//! | UPDATE BINARY | INS `D6`, two-byte offset \[V] pySim `commands.py:376-378` | INS `E4` |
//! | UPDATE RECORD | INS `DC`, P1 = record \[V] `commands.py:462` | not used |
//!
//! Two of the four also write a key with a **proprietary** INS `D4`, which has
//! no ISO 7816-4 meaning at all and is the only reason they are in scope:
//! `80 D4 02 00 10 <Ki>` \[V] `legacy/cards.py:755` and
//! `A0 D4 3A 05 08 <PIN>` \[V] `legacy/cards.py:853`.
//!
//! # The complete APDU vocabulary
//!
//! | APDU | Bytes | Source |
//! |---|---|---|
//! | SELECT | `A0 A4 0000 02 <fid> 00` | \[V] `commands.py:281`, `cards.py:94-95` |
//! | VERIFY CHV | `A0 20 00 <chv> 08 <8 bytes>` | \[V] `commands.py:676-677` |
//! | UPDATE BINARY | `A0 D6 <offset:2> <len> <data>` | \[V] `commands.py:376-378` |
//! | UPDATE RECORD | `A0 DC <rec> 04 <len> <data>` | \[V] `commands.py:462` |
//! | READ BINARY | `A0 B0 <offset:2> <len>` | \[V] `commands.py:317-318` |
//! | READ RECORD | `A0 B2 <rec> 04 <len>` | \[V] `commands.py:399` |
//! | GrCard proprietary Ki | `80 D4 02 00 10 <16 bytes>` | \[V] `legacy/cards.py:755` |
//! | sysmoSIMgr2 proprietary ADM PIN | `A0 D4 3A 05 08 <8 bytes>` | \[V] `legacy/cards.py:853` |
//!
//! A SELECT answer carries the file length in bytes 2..4 and the record length
//! in bytes 14..16, because `sel_ctrl` is `0000` and not `0004`
//! \[V] `commands.py:229-234` and `:224-225`. The card models read exactly
//! those two offsets, e.g. `tl = int(r[-1][4:8], 16)` \[V] `legacy/cards.py:598`
//! and `size = int(r[-1][4:8], 16)` \[V] `:760`. `program` parses them the same
//! way, which is what lets a plan be built offline and still write a
//! correctly sized `EF.HPLMN`.
//!
//! # No implicit padding
//!
//! `update_binary` calls `expand_hex` before it writes \[V]
//! `commands.py:352-353`, and `expand_hex` is a **dot** expander: it replaces
//! `.` and `..` with a filler derived from the neighbouring nibbles, and its
//! own docstring says that when the string cannot be expanded "the input string
//! is returned unmodified" \[V] `pySim/utils.py:475-488`, `:481`. Every input
//! here is a plain hex string, so the reference writes **exactly** the bytes
//! the card model built - this driver writes exactly the bytes it built, and
//! the `ff` padding that does appear is padding the reference asked for by
//! name, at `legacy/cards.py:559`, `:590`, `:601`, `:687`, `:762`, `:877`.
//!
//! # Safety
//!
//! These are the writes that hand a card its identity: ICCID, IMSI, `Ki` and
//! `OPc`. `At::plan` builds every write and sends nothing; `At::program` writes
//! and then re-reads each file with the reference's own verification exchange
//! \[V] `commands.py:386-387` (`__verify_binary`), `:464-465` and `:410-413`
//! (`__verify_record`), and reports `verify-failed` when the card does not hold
//! it. Key bytes live in [`Secret`], which has a redacting `Debug`, so a key
//! reaches no transcript line, report field or error string.

use std::fmt;

pub use crate::sysmocom::{At, AtReply, AtResult, AtStep, Error, Secret};

/// This module name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "legacy";

/// Class byte of every command these four cards are sent. \[V] pySim
/// `cards.py:94`, `SimCardBase.__init__` sets `self._scc.cla_byte = "A0"`.
pub const CLA_SIM: u8 = 0xA0;

/// P1/P2 of a SELECT on these cards: no FCP requested. \[V] pySim
/// `cards.py:95`, `self._scc.sel_ctrl = "0000"`.
pub const SELECT_CTRL: [u8; 2] = [0x00, 0x00];

/// Le of a whole-file SELECT, which the reference always appends. \[V] pySim
/// `commands.py:281`, `... + "02" + fid + "00"`.
pub const SELECT_LE: u8 = 0x00;

/// INS of SELECT, READ BINARY, UPDATE BINARY, UPDATE RECORD, READ RECORD and
/// VERIFY CHV. \[V] pySim `commands.py:281`, `:317-318`, `:376-378`, `:399`,
/// `:462`, `:676-677`.
pub const INS_SELECT: u8 = 0xA4;
/// See [`INS_SELECT`].
pub const INS_READ_BINARY: u8 = 0xB0;
/// See [`INS_SELECT`]. The extended-offset form, which is what the reference
/// sends and what a SIM answers, not the short `E4`.
pub const INS_UPDATE_BINARY: u8 = 0xD6;
/// See [`INS_SELECT`].
pub const INS_UPDATE_RECORD: u8 = 0xDC;
/// See [`INS_SELECT`].
pub const INS_READ_RECORD: u8 = 0xB2;
/// See [`INS_SELECT`].
pub const INS_VERIFY_CHV: u8 = 0x20;

/// P2 of a READ RECORD and of an UPDATE RECORD: absolute record addressing.
/// \[V] pySim `commands.py:399` and `:462`, `b2%02x04%02x` / `dc%02x04%02x`.
pub const RECORD_ABSOLUTE: u8 = 0x04;

/// P2 of the VERIFY CHV these cards use. \[V] pySim `commands.py:677`, which
/// hard-codes `"2000"` and moves only P1.
pub const VERIFY_P2: u8 = 0x00;

/// Byte offset in a SELECT answer that carries the **file** length. \[V] pySim
/// `commands.py:229-234`, the `sel_ctrl != 0004` branch, `int(r[-1][4:8],16)`.
pub const SELECT_FILE_LEN_AT: usize = 2;

/// Byte offset in a SELECT answer that carries the **record** length. \[V] pySim
/// `commands.py:224-225`, the `sel_ctrl != 0004` branch, `int(r[-1][28:30],16)`.
pub const SELECT_RECORD_LEN_AT: usize = 14;

/// The filler byte every `rpad` / `lpad` in the reference leaves behind.
///
/// **[U]** `rpad`, `lpad` and `swap_nibbles` come from `osmocom.utils`, pulled
/// in by `pySim/utils.py:13` (`from osmocom.utils import *`), and that
/// repository is not reachable from this box. What *is* in a reachable file:
/// `lpad(p["smsp"], 80)` is annotated "SMSP (padded with ff if needed)"
/// \[V] `legacy/cards.py:699`, and the erase path fills records with `"ff" * n`
/// \[V] `legacy/cards.py:708`. So `ff` is what the reference's own comments say
/// these paddings are, but the definition itself is unverified.
pub const PAD_FILL: u8 = 0xFF;

/// Width the reference pads an ICCID to before swapping nibbles. \[V] pySim
/// `utils.py:85-86`, `swap_nibbles(rpad(iccid, 20))`.
pub const ICCID_DIGITS: usize = 20;

/// Width the reference pads an IMSI to before swapping nibbles. \[V] pySim
/// `utils.py:58`, `rpad(imsi, 15)`.
pub const IMSI_DIGITS: usize = 15;

/// Length of `Ki` and `OPc`. \[V] pySim `legacy/cards.py:755` writes `Ki` with
/// Lc `10`, and `:1190` / `:1193` write 16 bytes of key material.
pub const KEY_LEN: usize = 16;

/// Length of a CHV in the VERIFY CHV these cards use. \[V] pySim
/// `commands.py:676-677`, `rpad(b2h(code), 16)` with Lc `08`.
pub const PIN_LEN: usize = 8;

/// The Super ADM key the reference falls back to on sysmoSIMgr2 when the caller
/// named no ADM PIN. \[V] pySim `legacy/cards.py:841`,
/// `verify_chv(0x0b, h2b("3838383838383838"))`.
pub const DEFAULT_SUPER_ADM: &str = "3838383838383838";

/// The ADM PIN GrCard and sysmoSIMgr2 fall back to. \[V] pySim
/// `legacy/cards.py:734` and `:851`, `h2b("4444444444444444")`.
pub const DEFAULT_ADM_PIN: &str = "4444444444444444";

/// A model this driver speaks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Model {
    /// pySim `MagicSim`, `legacy/cards.py:633`, `name = "magicsim"`.
    MagicSim,
    /// pySim `OpenCellsSim`, `legacy/cards.py:1153`, `name = "OpenCells-SIM"`.
    OpenCells,
    /// pySim `GrcardSim`, `legacy/cards.py:713`, `name = "grcardsim"`.
    GrCard,
    /// pySim `SysmoSIMgr2`, `legacy/cards.py:818`, `name = "sysmoSIM-GR2"`.
    SysmoSIMgr2,
}

impl Model {
    /// Every model, in the order [`Model::detect`] tries them.
    pub const ALL: [Model; 4] = [
        Model::MagicSim,
        Model::OpenCells,
        Model::GrCard,
        Model::SysmoSIMgr2,
    ];

    /// The model name the reference gives itself, byte for byte.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MagicSim => "magicsim",
            Self::OpenCells => "OpenCells-SIM",
            Self::GrCard => "grcardsim",
            Self::SysmoSIMgr2 => "sysmoSIM-GR2",
        }
    }

    /// The ATRs the reference compares for this model, lowercase hex.
    ///
    /// Two of the four have one and two have none, and that is the reference
    /// behaviour rather than a gap here: see [`Model::signals`].
    pub const fn atrs(self) -> &'static [&'static str] {
        match self {
            // [V] pySim legacy/cards.py:1169.
            Self::OpenCells => &["3b9f95801fc38031e073fe21135786810286984418a8"],
            // [V] pySim legacy/cards.py:829.
            Self::SysmoSIMgr2 => &["3b7d9400005555530a7486930b247c4d5468"],
            // MagicSimBase.autodetect never reads the ATR [V]
            // legacy/cards.py:520-531; GrcardSim.autodetect returns None
            // unconditionally [V] legacy/cards.py:722-724.
            Self::MagicSim | Self::GrCard => &[],
        }
    }

    /// What the reference checks to decide whether a card is this model.
    pub const fn signals(self) -> &'static [Signal] {
        match self {
            // MagicSimBase.autodetect SELECTs each entry of _files whose third
            // tuple element is true and compares the record size [V]
            // legacy/cards.py:520-527; _files at :637-641 marks 8f0c/18 and
            // 8f0d/130 true and 8f0e false, and :524-525 skips a false one.
            Self::MagicSim => &[
                Signal::RecordSize {
                    path: &["3f00", "7f4d", "8f0c"],
                    bytes: 18,
                    source: "pySim/legacy/cards.py:526, :638",
                },
                Signal::RecordSize {
                    path: &["3f00", "7f4d", "8f0d"],
                    bytes: 130,
                    source: "pySim/legacy/cards.py:526, :639",
                },
            ],
            // [V] legacy/cards.py:1168-1170, an ATR equality test.
            Self::OpenCells => &[Signal::Atr {
                atr: "3b9f95801fc38031e073fe21135786810286984418a8",
                source: "pySim/legacy/cards.py:1169",
            }],
            // autodetect is `return None` with no test at all [V]
            // legacy/cards.py:722-724.
            Self::GrCard => &[Signal::Never {
                source: "pySim/legacy/cards.py:722-724",
            }],
            // [V] legacy/cards.py:828-830, an ATR equality test.
            Self::SysmoSIMgr2 => &[Signal::Atr {
                atr: "3b7d9400005555530a7486930b247c4d5468",
                source: "pySim/legacy/cards.py:829",
            }],
        }
    }

    /// Whether the reference can tell this model apart on its own.
    ///
    /// GrCard cannot, and `False` here is the reference answer rather than a
    /// missing feature: it is what makes "not this model" the only honest
    /// report for a GrCard whose ATR is in nobody's table.
    pub const fn is_self_identifying(self) -> bool {
        !matches!(self.signals(), [Signal::Never { .. }])
    }

    /// The master file every one of these models is under.
    pub const fn master_file(self) -> &'static str {
        "3F00"
    }

    /// The directory the reference probes: `DF.GSM`. \[V] pySim
    /// `cards.py:97-99`, `SimCardBase.probe` is `file_exists(DF_GSM().fid)`,
    /// and the FID `7f20` is the one the same reference selects as DF.GSM at
    /// `legacy/cards.py:864`.
    pub const fn probe_directory(self) -> &'static str {
        "7F20"
    }

    /// The files this model writes, with the reference line for each.
    pub const fn surface(self) -> &'static [VendorFile] {
        match self {
            Self::MagicSim => &[
                VendorFile {
                    fid: "8F0C",
                    name: "EF.OPERATOR_NAME",
                    role: Role::Record,
                    source: "pySim/legacy/cards.py:558, :625",
                },
                VendorFile {
                    fid: "8F0D",
                    name: "EF.PROGRAMMABLE_BINARY",
                    role: Role::Record,
                    source: "pySim/legacy/cards.py:589, :639",
                },
                VendorFile {
                    fid: "6F30",
                    name: "EF.PLMNSEL",
                    role: Role::Plmn,
                    source: "pySim/legacy/cards.py:597-601",
                },
                VendorFile {
                    fid: "8F0E",
                    name: "EF.PROGRAMMABLE_RECORD",
                    role: Role::Record,
                    source: "pySim/legacy/cards.py:513, :627",
                },
            ],
            Self::OpenCells => &[
                VendorFile {
                    fid: "2FE2",
                    name: "EF.ICCID",
                    role: Role::Iccid,
                    source: "pySim/legacy/cards.py:1185",
                },
                VendorFile {
                    fid: "FF02",
                    name: "EF.Ki",
                    role: Role::Key,
                    source: "pySim/legacy/cards.py:1190",
                },
                VendorFile {
                    fid: "FF01",
                    name: "EF.OPc",
                    role: Role::Key,
                    source: "pySim/legacy/cards.py:1193",
                },
                VendorFile {
                    fid: "6F07",
                    name: "EF.IMSI",
                    role: Role::Imsi,
                    source: "pySim/legacy/cards.py:1199",
                },
            ],
            Self::GrCard => &[
                VendorFile {
                    fid: "2FE2",
                    name: "EF.ICCID",
                    role: Role::Iccid,
                    source: "pySim/legacy/cards.py:738-739",
                },
                VendorFile {
                    fid: "6F07",
                    name: "EF.IMSI",
                    role: Role::Imsi,
                    source: "pySim/legacy/cards.py:742-743",
                },
                VendorFile {
                    fid: "6F78",
                    name: "EF.ACC",
                    role: Role::Acc,
                    source: "pySim/legacy/cards.py:747",
                },
                VendorFile {
                    fid: "6F42",
                    name: "EF.SMSP",
                    role: Role::Smsp,
                    source: "pySim/legacy/cards.py:751-752",
                },
                VendorFile {
                    fid: "PROPRIETARY D4",
                    name: "EF.Ki (proprietary INS D4)",
                    role: Role::Key,
                    source: "pySim/legacy/cards.py:754-756",
                },
                VendorFile {
                    fid: "6F30",
                    name: "EF.PLMNSEL",
                    role: Role::Plmn,
                    source: "pySim/legacy/cards.py:759-762",
                },
            ],
            Self::SysmoSIMgr2 => &[
                VendorFile {
                    fid: "2FE2",
                    name: "EF.ICCID",
                    role: Role::Iccid,
                    source: "pySim/legacy/cards.py:861",
                },
                VendorFile {
                    fid: "6F07",
                    name: "EF.IMSI",
                    role: Role::Imsi,
                    source: "pySim/legacy/cards.py:867",
                },
                VendorFile {
                    fid: "6F78",
                    name: "EF.ACC",
                    role: Role::Acc,
                    source: "pySim/legacy/cards.py:871",
                },
                VendorFile {
                    fid: "6F30",
                    name: "EF.PLMNSEL",
                    role: Role::Plmn,
                    source: "pySim/legacy/cards.py:874-877",
                },
                VendorFile {
                    fid: "0001",
                    name: "EF.SIM_AUTH (COMP128 version, then Ki at offset 3)",
                    role: Role::Key,
                    source: "pySim/legacy/cards.py:880, :883",
                },
                VendorFile {
                    fid: "6F42",
                    name: "EF.SMSP",
                    role: Role::Smsp,
                    source: "pySim/legacy/cards.py:886-890",
                },
                VendorFile {
                    fid: "PROPRIETARY D4",
                    name: "ADM PIN (proprietary INS D4)",
                    role: Role::Pin,
                    source: "pySim/legacy/cards.py:853-854",
                },
            ],
        }
    }

    /// Whether `atr` is one of this model's, compared byte for byte.
    pub fn matches_atr(self, atr: &str) -> bool {
        let atr = normalise_atr(atr);
        self.atrs().iter().any(|known| *known == atr)
    }

    /// The model whose ATR table holds `atr`, or `None`.
    ///
    /// Reported, never forced. Two of these four have no ATR at all, so `None`
    /// is the answer for a GrCard and for a magic-SIM, and the caller has to
    /// decide from [`Model::signals`] instead.
    pub fn detect(atr: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|m| m.matches_atr(atr))
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing the reference checks to recognise a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// The reference compares `get_atr()` to one literal.
    Atr {
        /// The ATR it compares against, lowercase hex.
        atr: &'static str,
        /// Where it does so.
        source: &'static str,
    },
    /// The reference SELECTs `path` and compares the record length in the
    /// answer.
    RecordSize {
        /// The path it SELECTs, one exchange per element.
        path: &'static [&'static str],
        /// The record length it expects, in bytes.
        bytes: usize,
        /// Where it does so.
        source: &'static str,
    },
    /// The reference cannot recognise this model and returns `None`.
    Never {
        /// Where the unconditional `return None` is.
        source: &'static str,
    },
}

/// What a file on the surface carries, which decides how a write is guarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// `EF.ICCID`.
    Iccid,
    /// `EF.IMSI`.
    Imsi,
    /// A key: `Ki`, `OPc`, or a proprietary write.
    Key,
    /// A PIN record or a proprietary PIN write.
    Pin,
    /// `EF.ACC`, the access class.
    Acc,
    /// `EF.SMSP`.
    Smsp,
    /// `EF.PLMNSEL`, whose length comes off the card.
    Plmn,
    /// A record-structured file.
    Record,
}

/// One file of a model's programming surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorFile {
    /// The file identifier, four uppercase hex digits where there is one.
    pub fid: &'static str,
    /// The name the reference or TS 51.011 gives it.
    pub name: &'static str,
    /// What it carries.
    pub role: Role,
    /// Where the reference defines it, as `file:line`.
    pub source: &'static str,
}

/// Lowercases an ATR and strips the separators a caller may have typed.
fn normalise_atr(atr: &str) -> String {
    atr.trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

/// One value of a programming request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    /// `EF.ICCID`.
    Iccid,
    /// `EF.IMSI`.
    Imsi,
    /// `Ki`, written where the model puts it.
    Ki,
    /// `OPc`, which only OpenCells has a file for.
    Opc,
    /// The ADM PIN.
    AdmPin,
    /// The operator name in `EF.OPERATOR_NAME`.
    OperatorName,
    /// `EF.PLMNSEL`.
    Plmn,
    /// `EF.ACC`.
    Acc,
    /// `EF.SMSP`.
    Smsp,
    /// The COMP128 version byte, sysmoSIMgr2 only.
    Comp128,
}

impl Field {
    /// Whether the value belongs in a [`Secret`] rather than a plain string.
    ///
    /// Only the three that are key or PIN material. An ICCID and an IMSI are
    /// identifiers, not secrets, and the reference prints both of them in its
    /// own programming output, so they are not redacted here.
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::Ki | Self::Opc | Self::AdmPin)
    }
}

// --- record encoders ------------------------------------------------------

/// Right-pads a hex string to `width` characters with the reference filler.
///
/// This is the reference `rpad(hexstr, width)`: it works on the hex string,
/// not on bytes, so `width` is a number of hex characters \[V] pySim
/// `legacy/cards.py:559`, `:578`, `:590`, `:676`.
fn rpad_hex(text: &str, width: usize) -> Result<String, Error> {
    if text.len() > width {
        return Err(Error::BadSecret(format!(
            "{width} hex digits will not hold {}",
            text.len()
        )));
    }
    Ok(format!("{text}{}", PAD_FILL_STR.repeat(width - text.len())))
}

/// Left-pads a hex string to `width` characters with the reference filler.
///
/// This is the reference `lpad(hexstr, width)` \[V] pySim
/// `legacy/cards.py:587`, `:699`, `:747`, `:752`.
fn lpad_hex(text: &str, width: usize) -> Result<String, Error> {
    if text.len() > width {
        return Err(Error::BadSecret(format!(
            "{width} hex digits will not hold {}",
            text.len()
        )));
    }
    Ok(format!("{}{text}", PAD_FILL_STR.repeat(width - text.len())))
}

/// The filler as a hex character, which is `PAD_FILL` in hex.
const PAD_FILL_STR: &str = "f";

/// Swaps the two nibbles of every byte of a hex string.
///
/// \[V] pySim `utils.py:37-38` documents the layout this exists for - the IMSI
/// table, `2 upper | 2 lower | 3 upper | 3 lower ...` after the odd/even
/// byte - and `utils.py:58` and `:86` apply it to the ICCID and IMSI. The
/// `swap_nibbles` function itself lives in `osmocom.utils` and is unreachable
/// from this box, so its body is **[U]**, but the transform its callers apply
/// is documented in the file that calls it.
fn swap_nibbles(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() % 2 != 0 {
        return Err(Error::BadSecret(format!(
            "swap_nibbles needs an even number of hex digits, not {}",
            text.len()
        )));
    }
    let digits: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        out.push(
            u8::from_str_radix(&format!("{}{}", pair[1], pair[0]), 16)
                .map_err(|_| Error::BadSecret("not a hex string".to_owned()))?,
        );
    }
    Ok(out)
}

/// Right-pads bytes with [`PAD_FILL`].
fn rpad_bytes(bytes: &[u8], width: usize) -> Result<Vec<u8>, Error> {
    if bytes.len() > width {
        return Err(Error::BadSecret(format!(
            "{width} bytes will not hold {}",
            bytes.len()
        )));
    }
    let mut out = bytes.to_vec();
    out.resize(width, PAD_FILL);
    Ok(out)
}

/// Checks a decimal identifier and returns it unchanged.
fn digits<'a>(value: &'a str, what: &str, max: usize) -> Result<&'a str, Error> {
    if value.is_empty() || value.len() > max {
        return Err(Error::BadSecret(format!("a {what} is 1 to {max} digits")));
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::BadSecret(format!("a {what} is digits only")));
    }
    Ok(value)
}

/// `EF.ICCID` as 10 bytes. \[V] pySim `utils.py:85-86`,
/// `swap_nibbles(rpad(iccid, 20))`; the 20 is [`ICCID_DIGITS`].
///
/// # Errors
///
/// [`Error::BadSecret`] unless `iccid` is 1 to 20 decimal digits.
pub fn enc_iccid(iccid: &str) -> Result<Vec<u8>, Error> {
    let iccid = digits(iccid, "ICCID", ICCID_DIGITS)?;
    swap_nibbles(&rpad_hex(iccid, ICCID_DIGITS)?)
}

/// `EF.IMSI` as 9 bytes. \[V] pySim `utils.py:53-59`:
/// `l = half_round_up(len(imsi) + 1)`,
/// `ei = "%02x" % l + swap_nibbles("%01x%s" % ((oe << 3) | 1, rpad(imsi, 15)))`
/// with `oe = len(imsi) & 1`. The byte layout is documented in the same file
/// at `:34-47`.
///
/// # Errors
///
/// [`Error::BadSecret`] unless `imsi` is 1 to 15 decimal digits.
pub fn enc_imsi(imsi: &str) -> Result<Vec<u8>, Error> {
    let imsi = digits(imsi, "IMSI", IMSI_DIGITS)?;
    let odd_even = u8::try_from((imsi.len() & 1) << 3 | 1)
        .map_err(|_| Error::BadSecret("an IMSI is 1 to 15 digits".to_owned()))?;
    let length = (imsi.len() + 2) / 2;
    let mut out = vec![u8::try_from(length)
        .map_err(|_| Error::BadSecret("an IMSI is 1 to 15 digits".to_owned()))?];
    out.extend_from_slice(&swap_nibbles(&format!(
        "{odd_even:x}{}",
        rpad_hex(imsi, IMSI_DIGITS)?
    ))?);
    Ok(out)
}

/// `EF.PLMNSEL` leading three bytes. \[V] pySim `utils.py:113-137`: the MCC and
/// MNC are padded as that function pads them and the six hex digits are
/// returned as `mcc[1] + mcc[0] + mnc[2] + mcc[2] + mnc[1] + mnc[0]`.
pub fn enc_plmn(mcc: &str, mnc: &str) -> Result<[u8; 3], Error> {
    let mcc = mcc.trim();
    let mnc = mnc.trim();
    let mcc: Vec<char> = pad_plmn(mcc, true).chars().collect();
    let mnc: Vec<char> = pad_plmn(mnc, false).chars().collect();
    let text = format!(
        "{}{}{}{}{}{}",
        mcc[1], mcc[0], mnc[2], mcc[2], mnc[1], mnc[0]
    );
    let bytes = hex::decode(text).map_err(|_| Error::BadSecret("not a PLMN".to_owned()))?;
    let triple: [u8; 3] = bytes
        .try_into()
        .map_err(|_| Error::BadSecret("not a PLMN".to_owned()))?;
    Ok(triple)
}

/// The MCC and MNC padding of pySim `utils.py:121-135`.
fn pad_plmn(value: &str, is_mcc: bool) -> String {
    match (value.len(), is_mcc) {
        (0, _) => "FFF".to_owned(),
        (1, true) => format!("00{value}"),
        (1, false) => format!("0{value}F"),
        (2, true) => format!("0{value}"),
        (2, false) => format!("{value}F"),
        _ => value.to_owned(),
    }
}

/// `EF.ACC` as 2 bytes. \[V] pySim `legacy/cards.py:747`, `lpad(acc, 4)`.
///
/// # Errors
///
/// [`Error::BadSecret`] unless `acc` is 1 to 4 hex digits.
pub fn enc_acc(acc: &str) -> Result<Vec<u8>, Error> {
    hex::decode(lpad_hex(acc, 4)?).map_err(|_| Error::BadSecret("EF.ACC is not hex".to_owned()))
}

/// `EF.SMSP` as 40 bytes. \[V] pySim `legacy/cards.py:752`,
/// `lpad(p["smsp"], 80)`.
///
/// # Errors
///
/// [`Error::BadSecret`] unless `smsp` is 1 to 80 hex digits.
pub fn enc_smsp(smsp: &str) -> Result<Vec<u8>, Error> {
    hex::decode(lpad_hex(smsp, 80)?).map_err(|_| Error::BadSecret("EF.SMSP is not hex".to_owned()))
}

/// `EF.OPERATOR_NAME` record 2 on a magic-SIM: 16 bytes of name, the length,
/// and `01` for valid \[V] pySim `legacy/cards.py:558-561`, the record length
/// `18` is `_files["name"][1]` at `:625`.
///
/// # Errors
///
/// [`Error::BadSecret`] unless `name` is 1 to 16 bytes.
pub fn enc_magic_name(name: &str) -> Result<Vec<u8>, Error> {
    if name.is_empty() || name.len() > 16 {
        return Err(Error::BadSecret("an operator name is 1 to 16 bytes".into()));
    }
    let mut record = rpad_bytes(name.as_bytes(), 16)?;
    let length = u8::try_from(name.len())
        .map_err(|_| Error::BadSecret("an operator name is 1 to 16 bytes".into()))?;
    record.push(length);
    record.push(0x01);
    Ok(record)
}

/// The magic-SIM `EF.PROGRAMMABLE_BINARY` record 1, 130 bytes.
///
/// \[V] pySim `legacy/cards.py:563-591`, concatenated in this order:
/// `3f00 2fe2 0a <ICCID>`, `7f20 6f07 09 <IMSI>`,
/// `<_ki_file> 10 <Ki>` with `_ki_file = "6f1b"` \[V] `:643`,
/// `6f30 18 <PLMN padded to 18 bytes>`, optionally
/// `6f78 02 <ACC>`, and the whole thing `rpad` to
/// `_files["b_ef"][1] * 2 = 260` hex digits \[V] `:639`, i.e. 130 bytes.
pub fn enc_magic_provider(
    iccid: &str,
    imsi: &str,
    ki: &Secret,
    mcc: &str,
    mnc: &str,
    acc: Option<&str>,
) -> Result<Vec<u8>, Error> {
    let iccid = enc_iccid(iccid)?;
    let imsi = enc_imsi(imsi)?;
    let plmn = enc_plmn(mcc, mnc)?;
    let ki = exact_key(ki, "Ki")?;
    let mut record = Vec::new();
    record.extend_from_slice(&hex::decode("3f002fe20a").expect("a literal"));
    record.extend_from_slice(&iccid);
    record.extend_from_slice(&hex::decode("7f206f0709").expect("a literal"));
    record.extend_from_slice(&imsi);
    record.extend_from_slice(&hex::decode("6f1b10").expect("a literal"));
    record.extend_from_slice(&ki);
    record.extend_from_slice(&hex::decode("6f3018").expect("a literal"));
    record.extend_from_slice(&rpad_bytes(&plmn, 18)?);
    if let Some(acc) = acc {
        record.extend_from_slice(&hex::decode("6f7802").expect("a literal"));
        record.extend_from_slice(&enc_acc(acc)?);
    }
    rpad_bytes(&record, 130)
}

fn exact_key(secret: &Secret, what: &str) -> Result<Vec<u8>, Error> {
    if secret.len() != KEY_LEN {
        return Err(Error::BadSecret(format!(
            "{what} is {KEY_LEN} bytes, not {}",
            secret.len()
        )));
    }
    Ok(secret.expose().to_vec())
}

fn exact_pin(secret: &Secret, what: &str) -> Result<Vec<u8>, Error> {
    let bytes = secret.expose();
    if bytes.is_empty() || bytes.len() > PIN_LEN {
        return Err(Error::BadSecret(format!(
            "a {what} is 1 to {PIN_LEN} bytes"
        )));
    }
    if !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::BadSecret(format!("a {what} is hex digits only")));
    }
    let mut field = bytes.to_vec();
    field.resize(PIN_LEN, PAD_FILL);
    Ok(field)
}

// --- APDU builders --------------------------------------------------------

/// `A0 A4 0000 02 <fid> 00`. \[V] pySim `commands.py:281`, with the class byte
/// and P1/P2 of `cards.py:94-95`.
///
/// # Errors
///
/// [`Error::BadSecret`] when `fid` is not two bytes of hex.
pub fn select(fid: &str) -> Result<Vec<u8>, Error> {
    let fid = hex::decode(fid).map_err(|_| Error::BadSecret(format!("not a file id: {fid}")))?;
    if fid.len() != 2 {
        return Err(Error::BadSecret("a file id is 2 bytes".to_owned()));
    }
    Ok(vec![
        CLA_SIM,
        INS_SELECT,
        SELECT_CTRL[0],
        SELECT_CTRL[1],
        0x02,
        fid[0],
        fid[1],
        SELECT_LE,
    ])
}

/// `A0 20 00 <chv> 08 <8 bytes>`. \[V] pySim `commands.py:676-677`.
pub fn verify_chv(chv: u8, pin: &Secret) -> Result<Vec<u8>, Error> {
    let field = exact_pin(pin, "PIN")?;
    Ok(vec![CLA_SIM, INS_VERIFY_CHV, VERIFY_P2, chv, PIN_LEN as u8]).map(|mut apdu: Vec<u8>| {
        apdu.extend_from_slice(&field);
        apdu
    })
}

/// `A0 D6 <offset> <len> <data>`. \[V] pySim `commands.py:376-378`, whose
/// format is `d6%04x%02x` with the byte offset and the chunk length.
pub fn update_binary(offset: u16, data: &[u8]) -> Result<Vec<u8>, Error> {
    let length =
        u8::try_from(data.len()).map_err(|_| Error::BadSecret("more than 255 bytes".into()))?;
    let mut apdu = vec![CLA_SIM, INS_UPDATE_BINARY];
    apdu.extend_from_slice(&offset.to_be_bytes());
    apdu.push(length);
    apdu.extend_from_slice(data);
    Ok(apdu)
}

/// `A0 DC <record> 04 <len> <data>`. \[V] pySim `commands.py:462`.
pub fn update_record(record: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
    let length =
        u8::try_from(data.len()).map_err(|_| Error::BadSecret("more than 255 bytes".into()))?;
    let mut apdu = vec![CLA_SIM, INS_UPDATE_RECORD, record, RECORD_ABSOLUTE, length];
    apdu.extend_from_slice(data);
    Ok(apdu)
}

/// `A0 B0 <offset> <len>`. \[V] pySim `commands.py:317-318`, whose format is
/// `b0%04x%02x`: a two-byte offset and a length, and no Le.
pub fn read_binary(offset: u16, len: u8) -> Vec<u8> {
    let mut apdu = vec![CLA_SIM, INS_READ_BINARY];
    apdu.extend_from_slice(&offset.to_be_bytes());
    apdu.push(len);
    apdu
}

/// `A0 B2 <record> 04 <len>`. \[V] pySim `commands.py:399`, `b2%02x04%02x`.
pub fn read_record(record: u8, len: u8) -> Vec<u8> {
    vec![CLA_SIM, INS_READ_RECORD, record, RECORD_ABSOLUTE, len]
}

/// `80 D4 02 00 10 <Ki>`, the GrCard proprietary key write. \[V] pySim
/// `legacy/cards.py:755`, `pdu = "80d4020010" + p["ki"]`.
pub fn grcard_write_ki(ki: &Secret) -> Result<Vec<u8>, Error> {
    let mut apdu = vec![0x80, 0xD4, 0x02, 0x00, KEY_LEN as u8];
    apdu.extend_from_slice(&exact_key(ki, "Ki")?);
    Ok(apdu)
}

/// `A0 D4 3A 05 08 <PIN>`, the sysmoSIMgr2 proprietary ADM PIN write.
///
/// \[V] pySim `legacy/cards.py:844-853`: INS `D4`, P1 `3A` for a PIN, P2 `05`
/// the CHV number, P3 `08` the CHV length, and the comment notes the PUK is
/// also length `08` "instead of 10" \[V] `:847`.
pub fn gr2_set_adm_pin(pin: &Secret) -> Result<Vec<u8>, Error> {
    let mut apdu = vec![CLA_SIM, 0xD4, 0x3A, 0x05, PIN_LEN as u8];
    apdu.extend_from_slice(&exact_pin(pin, "PIN")?);
    Ok(apdu)
}

/// The CHV number GrCard authenticates with \[V] pySim `legacy/cards.py:735`.
pub const GRCARD_ADM_CHV: u8 = 0x05;
/// The CHV number OpenCells authenticates with \[V] pySim
/// `legacy/cards.py:1163` and `:1179`.
pub const OPENCELLS_ADM_CHV: u8 = 0x0A;
/// The CHV number sysmoSIMgr2 authenticates with after the super ADM \[V] pySim
/// `legacy/cards.py:858`.
pub const GR2_ADM_CHV: u8 = 0x05;
/// The super ADM CHV number sysmoSIMgr2 authenticates with first \[V] pySim
/// `legacy/cards.py:841`.
pub const GR2_SUPER_ADM_CHV: u8 = 0x0B;

// --- the request ----------------------------------------------------------

/// A programming request, before anything has been sent.
///
/// Empty fields are absent, so a request that names nothing this model writes
/// comes back as [`Error::NothingToProgram`] rather than a session that was
/// opened and closed for nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProgramRequest {
    /// `EF.ICCID`, 1 to 20 decimal digits.
    pub iccid: Option<String>,
    /// `EF.IMSI`, 1 to 15 decimal digits.
    pub imsi: Option<String>,
    /// `Ki`, 16 bytes.
    pub ki: Option<Secret>,
    /// `OPc`, 16 bytes. Only OpenCells has a file for it.
    pub opc: Option<Secret>,
    /// The ADM PIN, 1 to 8 hex digits.
    pub pin_adm: Option<Secret>,
    /// The operator name, 1 to 16 bytes. magic-SIM only.
    pub operator_name: Option<String>,
    /// `EF.SMSP`, 1 to 80 hex digits.
    pub smsp: Option<String>,
    /// `EF.ACC`, 1 to 4 hex digits.
    pub acc: Option<String>,
    /// MCC, 1 to 3 digits.
    pub mcc: Option<String>,
    /// MNC, 1 to 3 digits.
    pub mnc: Option<String>,
}

/// What one write puts on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// UPDATE BINARY of exactly these bytes at `offset`.
    Binary {
        /// Byte offset into the file \[V] pySim `commands.py:377`.
        offset: u16,
        /// The bytes.
        data: Vec<u8>,
    },
    /// The PLMN write: three bytes then `ff` up to the **file length the
    /// SELECT answer carries** \[V] pySim `legacy/cards.py:598-601`, `:760-762`
    /// and `:875-877`.
    Plmn {
        /// The three encoded PLMN bytes \[V] pySim `utils.py:137`.
        hplmn: [u8; 3],
    },
    /// UPDATE RECORD of exactly these bytes.
    Record {
        /// The record number \[V] pySim `legacy/cards.py:558`, `:589`.
        record: u8,
        /// The bytes.
        data: Vec<u8>,
    },
    /// A proprietary write the reference sends with `send_apdu`, with no SELECT
    /// in front of it \[V] pySim `legacy/cards.py:756` and `:854`.
    Proprietary(Vec<u8>),
    /// A VERIFY CHV the reference puts in front of the writes \[V] pySim
    /// `legacy/cards.py:735`, `:841`, `:858` and `:1179`.
    Auth {
        /// The CHV number.
        chv: u8,
        /// The PIN for it, held by value and never formatted.
        pin: Secret,
    },
}

/// The exchange that reads a write back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    /// READ BINARY of `len` bytes at `offset`.
    Binary {
        /// The offset to read from.
        offset: u16,
        /// How many bytes to read.
        len: u8,
    },
    /// READ RECORD `record`.
    Record {
        /// The record number.
        record: u8,
        /// How many bytes the record holds.
        len: u8,
    },
}

/// One write the plan will make, offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWrite {
    /// Which field of the request this is.
    pub field: Field,
    /// The file it goes to, as the reference spells it.
    pub fid: String,
    /// The name the reference gives the file.
    pub name: &'static str,
    /// The SELECT chain the reference puts in front of it, one exchange per
    /// element \[V] pySim `commands.py:257-272` and `legacy/cards.py:552`.
    pub path: Vec<String>,
    /// What goes on the wire.
    pub body: Body,
    /// How it is read back \[V] pySim `commands.py:386-387` and `:464-465`.
    pub verify: Verify,
}

/// One write that was made and confirmed by a read-back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWrite {
    /// Which field of the request this was.
    pub field: Field,
    /// The file it went to.
    pub fid: String,
    /// The name of the file.
    pub name: &'static str,
    /// How many bytes were written and read back.
    pub bytes: usize,
}

/// One SELECT of the identify probe, with what the card said about the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStep {
    /// What was selected.
    pub what: &'static str,
    /// The APDU as hex, uppercase, exactly as it went inside `+CSIM`.
    pub apdu: String,
    /// The status word.
    pub sw: u16,
    /// The file length the answer carried, at [`SELECT_FILE_LEN_AT`].
    pub file_len: u16,
    /// The record length the answer carried, when it has one.
    pub record_len: Option<u16>,
}

/// The result of [`Program::identify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identify {
    /// The ATR that was offered, normalised.
    pub atr: String,
    /// The model the ATR belongs to, or `None`.
    ///
    /// `None` is the answer for a GrCard and for a magic-SIM, because the
    /// reference has no ATR test for either; it is never a guess.
    pub model: Option<Model>,
    /// The probe exchange.
    pub probe: Vec<ProbeStep>,
}

/// One thing [`Program::recognise`] checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// An ATR equality test, answered without touching the card.
    Atr {
        /// The ATR the card reported.
        atr: String,
        /// The ATR the reference wants.
        wanted: &'static str,
        /// Whether they are equal.
        held: bool,
    },
    /// A record-length test, answered by SELECTing `path`.
    RecordSize {
        /// The path that was SELECTed, one exchange per element.
        path: Vec<String>,
        /// The record length the reference wants.
        wanted: usize,
        /// The record length the card reported.
        got: Option<u16>,
        /// Whether they are equal.
        held: bool,
    },
    /// The reference cannot run this test at all.
    Never {
        /// Where its unconditional `return None` is.
        source: &'static str,
    },
}

/// The result of [`Program::recognise`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recognition {
    /// The model that was tested for.
    pub model: Model,
    /// Every check the reference performs, in order.
    pub checks: Vec<Check>,
    /// Whether every check held.
    ///
    /// Always `false` for GrCard, because the reference answers `None` before
    /// it looks at anything \[V] pySim `legacy/cards.py:722-724`. A driver that
    /// said `true` there would be inventing the answer.
    pub recognised: bool,
}

/// The file length a SELECT answer carries.
fn file_len(answer: &[u8]) -> Option<u16> {
    let bytes = answer.get(SELECT_FILE_LEN_AT..SELECT_FILE_LEN_AT + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The record length a SELECT answer carries.
fn record_len(answer: &[u8]) -> Option<u16> {
    let bytes = answer.get(SELECT_RECORD_LEN_AT..SELECT_RECORD_LEN_AT + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Turns a non-`9000` answer into [`Error::StatusWord`].
fn check_sw(what: &str, answer: &[u8]) -> Result<(), Error> {
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

/// The driver for these four models, over the AT seam.
///
/// Holds the transcript of every exchange, in order, so a dry run and a real
/// run produce the same shape of output and a test can assert exact bytes.
#[derive(Debug, Default)]
pub struct Program {
    at: At,
}

impl Program {
    /// A driver with an empty transcript.
    pub fn new() -> Self {
        Self { at: At::new() }
    }

    /// Every exchange so far, in order, verbatim.
    pub fn transcript(&self) -> &[AtStep] {
        self.at.transcript()
    }

    /// The command lines sent so far, terminator removed.
    pub fn commands(&self) -> Vec<String> {
        self.at.commands()
    }

    /// The AT layer, for a caller that needs it directly.
    pub fn at(&mut self) -> &mut At {
        &mut self.at
    }

    /// Connects, runs the reference probe, and names the model `atr` is.
    ///
    /// "Connected" is the same as everywhere else in this crate: the device
    /// answers `AT` and then `AT+CSIM=?` with `OK` \[V] issue #283,
    /// `src/sysmocom.rs`, over lpac `driver/apdu/at_etsi_csim.c:24-34`. Nothing
    /// about the card is read here, because [`crate::sysmocom::At`] has no ATR
    /// accessor: the ATR is an input.
    ///
    /// The probe is the legacy one and it is one exchange: `SimCardBase.probe`
    /// is `file_exists(DF_GSM().fid)` \[V] pySim `cards.py:97-99`, so SELECT
    /// `7F20` at `A0 A4 0000 02 7F20 00` and nothing else. This is not #283
    /// probe, which SELECTs MF then EF.DIR, because these are SIMs and their
    /// probe is the DF.GSM existence check.
    ///
    /// # Errors
    ///
    /// Everything [`At::open`] can return, plus [`Error::StatusWord`] and
    /// [`Error::DeviceRefused`].
    pub fn identify<S: crate::transport::CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        atr: &str,
    ) -> Result<Identify, Error> {
        self.at.open(session)?;
        let apdu = select(Model::OpenCells.probe_directory())?;
        let answer = self.at.apdu(session, &apdu)?;
        check_sw("DF.GSM", &answer)?;
        let sw = u16::from_be_bytes([answer[answer.len() - 2], answer[answer.len() - 1]]);
        let probe = vec![ProbeStep {
            what: "DF.GSM",
            apdu: hex::encode_upper(&apdu),
            sw,
            file_len: file_len(&answer).unwrap_or(0),
            record_len: record_len(&answer),
        }];
        let atr = normalise_atr(atr);
        Ok(Identify {
            model: Model::detect(&atr),
            atr,
            probe,
        })
    }

    /// Runs the reference autodetect for `model` and reports every check.
    ///
    /// This is the second half of "which card is this", and for two of the
    /// four it is the only half there is: a magic-SIM has no ATR test, so it is
    /// recognised by the record length of `3f00/7f4d/8f0c` and then
    /// `3f00/7f4d/8f0d` \[V] pySim `legacy/cards.py:520-527`. GrCard has neither
    /// and `recognised` comes back `false` \[V] `legacy/cards.py:722-724`.
    ///
    /// # Errors
    ///
    /// Everything [`At::open`] can return, plus [`Error::StatusWord`] from a
    /// path that does not exist.
    pub fn recognise<S: crate::transport::CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        model: Model,
        atr: &str,
    ) -> Result<Recognition, Error> {
        let mut checks = Vec::new();
        for signal in model.signals() {
            match *signal {
                Signal::Atr { atr: wanted, .. } => {
                    let seen = normalise_atr(atr);
                    checks.push(Check::Atr {
                        held: seen == wanted,
                        atr: seen,
                        wanted,
                    });
                }
                Signal::RecordSize { path, bytes, .. } => {
                    let mut got = None;
                    for fid in path {
                        let apdu = select(fid)?;
                        let answer = self.at.apdu(session, &apdu)?;
                        check_sw("a record file", &answer)?;
                        got = record_len(&answer);
                    }
                    checks.push(Check::RecordSize {
                        path: path.iter().map(|f| f.to_string()).collect(),
                        wanted: bytes,
                        got,
                        held: got == Some(bytes as u16),
                    });
                }
                Signal::Never { source } => checks.push(Check::Never { source }),
            }
        }
        let recognised = !checks.is_empty()
            && checks.iter().all(|check| {
                !matches!(check, Check::Never { .. })
                    && match check {
                        Check::Atr { held, .. } | Check::RecordSize { held, .. } => *held,
                        Check::Never { .. } => false,
                    }
            });
        Ok(Recognition {
            model,
            checks,
            recognised,
        })
    }

    /// Builds every write `request` implies for `model`, and sends nothing.
    ///
    /// This is the dry run: the SELECT chain, the write APDU and the read-back
    /// are all complete before a session is touched, and `transcript()` is
    /// unchanged by this call.
    ///
    /// # Errors
    ///
    /// [`Error::NothingToProgram`] when the request names nothing this model
    /// writes, and [`Error::BadSecret`] for a value a file cannot hold.
    pub fn plan(&self, model: Model, request: &ProgramRequest) -> Result<Vec<PlannedWrite>, Error> {
        let mut writes = match model {
            Model::MagicSim => self.plan_magic(request)?,
            Model::OpenCells => self.plan_opencells(request)?,
            Model::GrCard => self.plan_grcard(request)?,
            Model::SysmoSIMgr2 => self.plan_gr2(request)?,
        };
        if !writes.iter().any(|w| !matches!(w.body, Body::Auth { .. })) {
            writes.clear();
        }
        if writes.is_empty() {
            return Err(Error::NothingToProgram(format!(
                "{model} was asked for nothing it exposes"
            )));
        }
        Ok(writes)
    }

    fn binary(
        &self,
        field: Field,
        fid: &str,
        name: &'static str,
        path: &[&str],
        data: Vec<u8>,
    ) -> Result<PlannedWrite, Error> {
        let len = u8::try_from(data.len())
            .map_err(|_| Error::BadSecret(format!("{name} is more than 255 bytes")))?;
        Ok(PlannedWrite {
            field,
            fid: fid.to_owned(),
            name,
            path: path
                .iter()
                .map(|f| f.to_ascii_lowercase())
                .chain(std::iter::once(fid.to_ascii_lowercase()))
                .collect(),
            body: Body::Binary { offset: 0, data },
            verify: Verify::Binary { offset: 0, len },
        })
    }

    fn record(
        &self,
        field: Field,
        fid: &str,
        name: &'static str,
        path: &[&str],
        record: u8,
        data: Vec<u8>,
    ) -> Result<PlannedWrite, Error> {
        let len = u8::try_from(data.len())
            .map_err(|_| Error::BadSecret(format!("{name} is more than 255 bytes")))?;
        Ok(PlannedWrite {
            field,
            fid: fid.to_owned(),
            name,
            path: path
                .iter()
                .map(|f| f.to_ascii_lowercase())
                .chain(std::iter::once(fid.to_ascii_lowercase()))
                .collect(),
            body: Body::Record { record, data },
            verify: Verify::Record { record, len },
        })
    }

    fn plmn(&self, field: Field, path: &[&str], hplmn: [u8; 3]) -> PlannedWrite {
        PlannedWrite {
            field,
            fid: "6F30".to_owned(),
            name: "EF.PLMNSEL",
            path: path.iter().map(|f| f.to_ascii_lowercase()).collect(),
            body: Body::Plmn { hplmn },
            verify: Verify::Binary { offset: 0, len: 0 },
        }
    }

    fn plan_magic(&self, request: &ProgramRequest) -> Result<Vec<PlannedWrite>, Error> {
        let mut writes = Vec::new();
        if let Some(name) = request.operator_name.as_deref() {
            writes.push(self.record(
                Field::OperatorName,
                "8F0C",
                "EF.OPERATOR_NAME",
                &["3f00", "7f4d"],
                2,
                enc_magic_name(name)?,
            )?);
        }
        if let (Some(iccid), Some(imsi), Some(ki)) = (
            request.iccid.as_deref(),
            request.imsi.as_deref(),
            request.ki.as_ref(),
        ) {
            let (mcc, mnc) = plmn_pair(request)?;
            writes.push(self.record(
                Field::Iccid,
                "8F0D",
                "EF.PROGRAMMABLE_BINARY",
                &["3f00", "7f4d"],
                1,
                enc_magic_provider(iccid, imsi, ki, mcc, mnc, request.acc.as_deref())?,
            )?);
        }
        if let (Some(mcc), Some(mnc)) = (request.mcc.as_deref(), request.mnc.as_deref()) {
            writes.push(self.plmn(Field::Plmn, &["3f00", "7f20", "6f30"], enc_plmn(mcc, mnc)?));
        }
        Ok(writes)
    }

    fn plan_opencells(&self, request: &ProgramRequest) -> Result<Vec<PlannedWrite>, Error> {
        // OpenCells has no default ADM PIN: the reference raises unless the
        // caller gave one \[V] pySim `legacy/cards.py:1176-1178`.
        let Some(pin) = request.pin_adm.clone() else {
            return Err(Error::BadSecret(
                "OpenCells-SIM has no default ADM PIN".to_owned(),
            ));
        };
        let mut writes = vec![PlannedWrite {
            field: Field::AdmPin,
            fid: "PROPRIETARY D4".to_owned(),
            name: "ADM PIN (proprietary INS D4)",
            path: Vec::new(),
            body: Body::Auth {
                chv: OPENCELLS_ADM_CHV,
                pin,
            },
            verify: Verify::Binary { offset: 0, len: 0 },
        }];
        let Some(iccid) = request.iccid.as_deref() else {
            return Ok(writes);
        };
        writes.push(self.binary(
            Field::Iccid,
            "2FE2",
            "EF.ICCID",
            &["3f00"],
            enc_iccid(iccid)?,
        )?);
        if let Some(ki) = request.ki.as_ref() {
            writes.push(self.binary(
                Field::Ki,
                "FF02",
                "EF.Ki",
                // The reference selects `7ff0` here [V] legacy/cards.py:1187.
                // That is a typo in the reference - DF.GSM is 7f20, the same
                // reference selects 7f20 four lines later at :1196 - and a
                // parity driver reproduces the reference, so this does too.
                &["7ff0"],
                exact_key(ki, "Ki")?,
            )?);
        }
        if let Some(opc) = request.opc.as_ref() {
            writes.push(self.binary(
                Field::Opc,
                "FF01",
                "EF.OPc",
                &["7ff0"],
                exact_key(opc, "OPc")?,
            )?);
        }
        if let Some(imsi) = request.imsi.as_deref() {
            writes.push(self.binary(Field::Imsi, "6F07", "EF.IMSI", &["7f20"], enc_imsi(imsi)?)?);
        }
        Ok(writes)
    }

    fn plan_grcard(&self, request: &ProgramRequest) -> Result<Vec<PlannedWrite>, Error> {
        let pin = adm_pin(request, Some(DEFAULT_ADM_PIN))?;
        let mut writes = vec![PlannedWrite {
            field: Field::AdmPin,
            fid: "PROPRIETARY D4".to_owned(),
            name: "ADM PIN (proprietary INS D4)",
            path: Vec::new(),
            body: Body::Auth {
                chv: GRCARD_ADM_CHV,
                pin,
            },
            verify: Verify::Binary { offset: 0, len: 0 },
        }];
        if let Some(iccid) = request.iccid.as_deref() {
            writes.push(self.binary(
                Field::Iccid,
                "2FE2",
                "EF.ICCID",
                &["3f00"],
                enc_iccid(iccid)?,
            )?);
        }
        if let Some(imsi) = request.imsi.as_deref() {
            writes.push(self.binary(
                Field::Imsi,
                "6F07",
                "EF.IMSI",
                &["3f00", "7f20"],
                enc_imsi(imsi)?,
            )?);
        }
        if let Some(acc) = request.acc.as_deref() {
            writes.push(self.binary(
                Field::Acc,
                "6F78",
                "EF.ACC",
                &["3f00", "7f20"],
                enc_acc(acc)?,
            )?);
        }
        if let Some(smsp) = request.smsp.as_deref() {
            writes.push(self.record(
                Field::Smsp,
                "6F42",
                "EF.SMSP",
                &["3f00", "7f10"],
                1,
                enc_smsp(smsp)?,
            )?);
        }
        if let Some(ki) = request.ki.as_ref() {
            writes.push(PlannedWrite {
                field: Field::Ki,
                fid: "PROPRIETARY D4".to_owned(),
                name: "EF.Ki (proprietary INS D4)",
                path: Vec::new(),
                body: Body::Proprietary(grcard_write_ki(ki)?),
                verify: Verify::Binary {
                    offset: 0,
                    len: KEY_LEN as u8,
                },
            });
        }
        if let (Some(mcc), Some(mnc)) = (request.mcc.as_deref(), request.mnc.as_deref()) {
            writes.push(self.plmn(Field::Plmn, &["3f00", "7f20", "6f30"], enc_plmn(mcc, mnc)?));
        }
        Ok(writes)
    }

    fn plan_gr2(&self, request: &ProgramRequest) -> Result<Vec<PlannedWrite>, Error> {
        let pin = adm_pin(request, Some(DEFAULT_ADM_PIN))?;
        let mut writes = vec![PlannedWrite {
            field: Field::AdmPin,
            fid: "PROPRIETARY D4".to_owned(),
            name: "SUPER ADM (VERIFY CHV 0x0B)",
            path: Vec::new(),
            body: Body::Auth {
                chv: GR2_SUPER_ADM_CHV,
                pin: Secret::new(hex::decode(DEFAULT_SUPER_ADM).expect("a literal")),
            },
            verify: Verify::Binary { offset: 0, len: 0 },
        }];
        if let Some(pin) = Some(pin) {
            writes.push(PlannedWrite {
                field: Field::AdmPin,
                fid: "PROPRIETARY D4".to_owned(),
                name: "ADM PIN (proprietary INS D4)",
                path: Vec::new(),
                body: Body::Proprietary(gr2_set_adm_pin(&pin)?),
                verify: Verify::Binary {
                    offset: 0,
                    len: PIN_LEN as u8,
                },
            });
            writes.push(PlannedWrite {
                field: Field::AdmPin,
                fid: "PROPRIETARY D4".to_owned(),
                name: "ADM PIN (VERIFY CHV 0x05)",
                path: Vec::new(),
                body: Body::Auth {
                    chv: GR2_ADM_CHV,
                    pin: adm_pin(request, Some(DEFAULT_ADM_PIN))?,
                },
                verify: Verify::Binary { offset: 0, len: 0 },
            });
        }
        if let Some(iccid) = request.iccid.as_deref() {
            writes.push(self.binary(
                Field::Iccid,
                "2FE2",
                "EF.ICCID",
                &["3f00"],
                enc_iccid(iccid)?,
            )?);
        }
        if let Some(imsi) = request.imsi.as_deref() {
            writes.push(self.binary(Field::Imsi, "6F07", "EF.IMSI", &["7f20"], enc_imsi(imsi)?)?);
        }
        if let Some(acc) = request.acc.as_deref() {
            writes.push(self.binary(Field::Acc, "6F78", "EF.ACC", &["7f20"], enc_acc(acc)?)?);
        }
        if let (Some(mcc), Some(mnc)) = (request.mcc.as_deref(), request.mnc.as_deref()) {
            writes.push(self.plmn(Field::Plmn, &["6f30"], enc_plmn(mcc, mnc)?));
        }
        if let Some(ki) = request.ki.as_ref() {
            // EF.0001 gets the COMP128 version first and then Ki at offset 3
            // [V] pySim legacy/cards.py:880 and :883. The version write is
            // unconditional in the reference, so it is unconditional here.
            writes.push(self.binary(
                Field::Comp128,
                "0001",
                "EF.SIM_AUTH (COMP128 version)",
                &["7f20"],
                hex::decode("001000").expect("a literal"),
            )?);
            writes.push(PlannedWrite {
                field: Field::Ki,
                fid: "0001".to_owned(),
                name: "EF.SIM_AUTH (Ki at offset 3)",
                path: vec!["7f20".to_owned(), "0001".to_owned()],
                body: Body::Binary {
                    offset: 3,
                    data: exact_key(ki, "Ki")?,
                },
                verify: Verify::Binary {
                    offset: 3,
                    len: KEY_LEN as u8,
                },
            });
        }
        if let Some(smsp) = request.smsp.as_deref() {
            writes.push(self.record(
                Field::Smsp,
                "6F42",
                "EF.SMSP",
                &["3f00", "7f10"],
                1,
                enc_smsp(smsp)?,
            )?);
        }
        Ok(writes)
    }

    /// Writes `plan`, then reads every file back and compares.
    ///
    /// Each write is SELECTed along the path the reference uses, written, then
    /// SELECTed again and read, which is the reference own verify sequence
    /// \[V] pySim `commands.py:386-387` calls `read_binary` which SELECTs the
    /// path again at `:305`. A card that accepted the write and does not hold
    /// it is [`Error::VerifyFailed`], not a success. The first refusal stops
    /// the run; nothing after it is attempted.
    ///
    /// # Errors
    ///
    /// [`Error::StatusWord`] from a SELECT or a write,
    /// [`Error::DeviceRefused`] from a length that is not on the wire, and
    /// [`Error::VerifyFailed`] from a read-back that did not match.
    pub fn run<S: crate::transport::CardSession + ?Sized>(
        &mut self,
        session: &mut S,
        _model: Model,
        plan: &[PlannedWrite],
    ) -> Result<Vec<VerifiedWrite>, Error> {
        let mut done = Vec::new();
        for write in plan {
            // A proprietary write and a VERIFY CHV both go out with nothing in
            // front of them and nothing read back: the reference sends them
            // with `send_apdu` and only reads the status word
            // \[V] pySim `legacy/cards.py:756`, `:854`.
            if let Body::Proprietary(data) = &write.body {
                let answer = self.at.apdu(session, data)?;
                check_sw(write.name, &answer)?;
                done.push(VerifiedWrite {
                    field: write.field,
                    fid: write.fid.clone(),
                    name: write.name,
                    bytes: data.len(),
                });
                continue;
            }
            if let Body::Auth { chv, pin } = &write.body {
                let answer = self.at.apdu(session, &verify_chv(*chv, pin)?)?;
                check_sw(write.name, &answer)?;
                done.push(VerifiedWrite {
                    field: write.field,
                    fid: write.fid.clone(),
                    name: write.name,
                    bytes: PIN_LEN,
                });
                continue;
            }
            let mut file_size = None;
            {
                for fid in &write.path {
                    let answer = self.at.apdu(session, &select(fid)?)?;
                    check_sw(write.name, &answer)?;
                    if let Some(size) = file_len(&answer) {
                        file_size = Some(size);
                    }
                }
            }
            let expected = match &write.body {
                Body::Binary { data, .. } => data.clone(),
                Body::Record { data, .. } => data.clone(),
                Body::Proprietary(_) | Body::Auth { .. } => Vec::new(),
                Body::Plmn { hplmn } => {
                    let size = file_size.ok_or_else(|| Error::DeviceRefused(write.name.into()))?;
                    if size < hplmn.len() as u16 {
                        return Err(Error::DeviceRefused(write.name.into()));
                    }
                    let mut data = hplmn.to_vec();
                    data.resize(size as usize, PAD_FILL);
                    data
                }
            };
            let apdu = match &write.body {
                Body::Binary { offset, .. } => update_binary(*offset, &expected)?,
                Body::Record { record, .. } => update_record(*record, &expected)?,
                Body::Proprietary(_) | Body::Auth { .. } => Vec::new(),
                Body::Plmn { .. } => update_binary(0, &expected)?,
            };
            let answer = self.at.apdu(session, &apdu)?;
            check_sw(write.name, &answer)?;

            let answer = self.at.apdu(session, &select(&write.fid)?)?;
            check_sw(write.name, &answer)?;
            let read = match write.verify {
                Verify::Binary { offset, len } if len != 0 => read_binary(offset, len),
                Verify::Record { record, len } => read_record(record, len),
                Verify::Binary { .. } => {
                    let size = file_size.ok_or_else(|| Error::DeviceRefused(write.name.into()))?;
                    read_binary(0, u8::try_from(size).unwrap_or(0))
                }
            };
            let answer = self.at.apdu(session, &read)?;
            check_sw(write.name, &answer)?;
            let body = answer
                .get(..answer.len().saturating_sub(2))
                .ok_or_else(|| Error::VerifyFailed {
                    file: write.name.to_owned(),
                })?;
            if body != expected.as_slice() {
                return Err(Error::VerifyFailed {
                    file: write.name.to_owned(),
                });
            }
            done.push(VerifiedWrite {
                field: write.field,
                fid: write.fid.clone(),
                name: write.name,
                bytes: expected.len(),
            });
        }
        Ok(done)
    }
}

/// The ADM PIN a request implies, or the reference default.
///
/// GrCard \[V] pySim `legacy/cards.py:731-734` and sysmoSIMgr2 \[V]
/// `:848-851` both fall back to [`DEFAULT_ADM_PIN`] when the caller named
/// none, so asking for one of those models is itself enough to have it set.
/// OpenCells does **not**: it raises unless a PIN was given \[V]
/// `legacy/cards.py:1176-1178`, which this driver reports as
/// [`Error::BadSecret`].
fn adm_pin(request: &ProgramRequest, default: Option<&str>) -> Result<Secret, Error> {
    match request.pin_adm.clone() {
        Some(pin) => Ok(pin),
        None => match default {
            Some(d) => {
                Ok(Secret::new(hex::decode(d).map_err(|_| {
                    Error::BadSecret("not a hex PIN".to_owned())
                })?))
            }
            None => Err(Error::BadSecret(
                "this model has no default ADM PIN".to_owned(),
            )),
        },
    }
}

/// The MCC and MNC of a request, or the reference error.
fn plmn_pair(request: &ProgramRequest) -> Result<(&str, &str), Error> {
    match (request.mcc.as_deref(), request.mnc.as_deref()) {
        (Some(mcc), Some(mnc)) => Ok((mcc, mnc)),
        _ => Err(Error::BadSecret(
            "EF.PLMNSEL needs both an MCC and an MNC".to_owned(),
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{CardSession, Error as TransportError, ReaderName};
    use std::collections::{BTreeSet, HashMap, VecDeque};

    /// A SIM that answers the eight legacy APDUs, remembers what it was sent,
    /// and holds what it was written so a read-back can succeed or not.
    struct MiniSim {
        reader: ReaderName,
        sent: Vec<Vec<u8>>,
        files: HashMap<String, Vec<u8>>,
        records: HashMap<(String, u8), Vec<u8>>,
        current: String,
        file_len: HashMap<String, u16>,
        record_len: HashMap<String, u16>,
        forced: VecDeque<Vec<u8>>,
    }

    impl MiniSim {
        fn new() -> Self {
            Self {
                reader: ReaderName::new("legacy scripted sim").unwrap(),
                sent: Vec::new(),
                files: HashMap::new(),
                records: HashMap::new(),
                current: String::new(),
                file_len: HashMap::new(),
                record_len: HashMap::new(),
                forced: VecDeque::new(),
            }
        }

        fn with_file(fid: &str, len: u16) -> Self {
            let mut sim = Self::new();
            sim.file_len.insert(fid.to_owned(), len);
            sim
        }

        fn with_record(fid: &str, len: u16) -> Self {
            let mut sim = Self::new();
            sim.record_len.insert(fid.to_owned(), len);
            sim.file_len.insert(fid.to_owned(), len);
            sim
        }

        fn fcp(&self, fid: &str) -> Vec<u8> {
            let file = *self.file_len.get(fid).unwrap_or(&0x20);
            let record = *self.record_len.get(fid).unwrap_or(&0);
            let mut body = vec![0x62, 0x0F];
            body.extend_from_slice(&file.to_be_bytes());
            body.resize(16, 0x00);
            body[SELECT_RECORD_LEN_AT..SELECT_RECORD_LEN_AT + 2]
                .copy_from_slice(&record.to_be_bytes());
            body.extend_from_slice(&[0x90, 0x00]);
            csim_ok(&body)
        }
    }

    impl CardSession for MiniSim {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(command.to_vec());

            if let Some(forced) = self.forced.pop_front() {
                return Ok(forced);
            }
            let line = String::from_utf8_lossy(command)
                .trim_end_matches("\r\n")
                .to_owned();
            if line == "AT" || line == "AT+CSIM=?" {
                return Ok(b"\r\nOK\r\n".to_vec());
            }
            let quoted = line
                .strip_prefix("AT+CSIM=")
                .expect("a +CSIM line")
                .split_once(",\"")
                .expect("a quoted payload")
                .1
                .trim_end_matches('"');
            let apdu = hex::decode(quoted).expect("hex on the wire");
            match apdu.get(1).copied() {
                Some(INS_SELECT) => {
                    self.current = hex::encode_upper(&apdu[5..7]);
                    let current = self.current.clone();
                    Ok(self.fcp(&current))
                }
                Some(INS_UPDATE_BINARY) => {
                    let offset = u16::from_be_bytes([apdu[2], apdu[3]]) as usize;
                    let len = apdu[4] as usize;
                    let entry = self.files.entry(self.current.clone()).or_default();
                    if entry.len() < offset + len {
                        entry.resize(offset + len, 0);
                    }
                    entry[offset..offset + len].copy_from_slice(&apdu[5..5 + len]);
                    Ok(csim_ok(&[0x90, 0x00]))
                }
                Some(INS_UPDATE_RECORD) => {
                    let record = apdu[2];
                    let len = apdu[4] as usize;
                    self.records
                        .insert((self.current.clone(), record), apdu[5..5 + len].to_vec());
                    Ok(csim_ok(&[0x90, 0x00]))
                }
                Some(INS_READ_BINARY) => {
                    let offset = u16::from_be_bytes([apdu[2], apdu[3]]) as usize;
                    let len = apdu[4] as usize;
                    let body = self
                        .files
                        .get(&self.current)
                        .map(|file| file[offset..offset + len].to_vec())
                        .unwrap_or_else(|| vec![0; len]);
                    Ok(csim_ok(&[body, vec![0x90, 0x00]].concat()))
                }
                Some(INS_READ_RECORD) => {
                    let body = self
                        .records
                        .get(&(self.current.clone(), apdu[2]))
                        .cloned()
                        .unwrap_or_default();
                    Ok(csim_ok(&[body, vec![0x90, 0x00]].concat()))
                }
                _ => Ok(csim_ok(&[0x90, 0x00])),
            }
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// `+CSIM: <len>,"<hex>"` then `OK`, as the device prints it.
    fn csim_ok(payload: &[u8]) -> Vec<u8> {
        format!(
            "\r\n+CSIM: {},\"{}\"\r\n\r\nOK\r\n",
            payload.len() * 2,
            hex::encode_upper(payload)
        )
        .into_bytes()
    }

    /// The exact bytes that go on the wire for an APDU written as hex: the
    /// `+CSIM` line with the hex character count, then CRLF.
    fn cs(apdu: &str) -> Vec<u8> {
        crate::sysmocom::wire_bytes(&format!(
            "AT+CSIM={},\"{}\"",
            apdu.len(),
            apdu.to_uppercase()
        ))
    }

    /// Asserts the exact command lines the scripted card was sent.
    ///
    /// Compares the wire bytes with CRLF stripped, element by element, so a
    /// mismatch names the exchange instead of printing two byte vectors.
    fn assert_transcript(sim: &MiniSim, expected: &[String]) {
        let want: Vec<String> = expected
            .iter()
            .map(|apdu| format!("AT+CSIM={},\"{}\"", apdu.len(), apdu))
            .collect();
        let got: Vec<String> = sim
            .sent
            .iter()
            .map(|bytes| {
                String::from_utf8_lossy(bytes)
                    .trim_end_matches("\r\n")
                    .to_owned()
            })
            .collect();
        assert_eq!(got.len(), expected.len(), "number of exchanges");
        for (index, (line, want)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(line, want, "exchange {index}");
        }
    }

    /// The parameters of the reference own programming fixtures, so every
    /// encoder below is checked against an input pySim itself used:
    /// `tests/pySim-prog_test/fakemagicsim.data:1-5`, which
    /// `fakemagicsim.ok:4-5` reads back unchanged.
    const ICCID: &str = "1122334455667788990";
    const IMSI: &str = "001010000000102";
    const MCC: &str = "001";
    const MNC: &str = "01";
    const KI: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    /// What `enc_iccid(ICCID)` and `enc_imsi(IMSI)` produce.
    const ICCID_ENC: &str = "112233445566778899F0";
    const IMSI_ENC: &str = "080910100000001020";
    /// `enc_plmn(MCC, MNC)`, the head of the reference own expected
    /// `EF.PLMNSEL` output: `sysmosim-gr1.ok:13` and `fakemagicsim.ok:13`.
    const PLMN_ENC: &str = "00F110";
    /// `enc_plmn` padded to the 18 byte `EF.PLMNSEL` [V] legacy/cards.py:601.
    const PLMN_FILE: &str = "00F110FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    fn request() -> ProgramRequest {
        ProgramRequest {
            iccid: Some(ICCID.to_owned()),
            imsi: Some(IMSI.to_owned()),
            ki: Some(Secret::new(hex::decode(KI).unwrap())),
            opc: None,
            pin_adm: None,
            operator_name: None,
            smsp: None,
            acc: None,
            mcc: Some(MCC.to_owned()),
            mnc: Some(MNC.to_owned()),
        }
    }

    // --- the APDU shapes ---------------------------------------------------

    #[test]
    fn the_legacy_apdus_are_the_reference_shapes() {
        // SELECT A0 A4 0000 02 <fid> 00 [V] commands.py:281, cards.py:94-95.
        assert_eq!(
            select("7f20").unwrap(),
            [0xA0, 0xA4, 0, 0, 2, 0x7F, 0x20, 0]
        );
        // VERIFY CHV A0 20 00 <chv> 08 <8> [V] commands.py:676-677.
        assert_eq!(
            verify_chv(0x0A, &Secret::new(b"12345678".to_vec())).unwrap(),
            [0xA0, 0x20, 0, 0x0A, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8']
        );
        // UPDATE BINARY is INS D6 with a two byte offset [V] commands.py:376-378.
        assert_eq!(
            update_binary(3, &[0xAA, 0xBB]).unwrap(),
            [0xA0, 0xD6, 0x00, 0x03, 0x02, 0xAA, 0xBB]
        );
        // UPDATE RECORD is INS DC, P1 the record, P2 04 [V] commands.py:462.
        assert_eq!(
            update_record(2, &[0x01]).unwrap(),
            [0xA0, 0xDC, 0x02, 0x04, 0x01, 0x01]
        );
        // READ BINARY A0 B0 <offset> <len>, no Le [V] commands.py:317-318.
        assert_eq!(read_binary(0, 0x12), [0xA0, 0xB0, 0x00, 0x00, 0x12]);
        // READ RECORD A0 B2 <rec> 04 <len> [V] commands.py:399.
        assert_eq!(read_record(1, 0x82), [0xA0, 0xB2, 0x01, 0x04, 0x82]);
    }

    #[test]
    fn the_two_proprietary_writes_are_the_reference_bytes() {
        // "80d4020010" + Ki [V] legacy/cards.py:755.
        assert_eq!(
            hex::encode_upper(grcard_write_ki(&Secret::new(hex::decode(KI).unwrap())).unwrap()),
            format!("80D4020010{}", KI.to_uppercase())
        );
        // "A0D43A0508" + pin [V] legacy/cards.py:844-853.
        assert_eq!(
            hex::encode_upper(gr2_set_adm_pin(&Secret::new(b"12345678".to_vec())).unwrap()),
            "A0D43A05083132333435363738"
        );
    }

    // --- the encoders ------------------------------------------------------

    #[test]
    fn an_iccid_is_the_reference_encoding_and_the_swap_is_visible() {
        // swap_nibbles(rpad(iccid, 20)) [V] utils.py:85-86.
        assert_eq!(hex::encode_upper(enc_iccid(ICCID).unwrap()), ICCID_ENC);
        assert_eq!(enc_iccid(ICCID).unwrap().len(), 10);
        // A value whose digits do not pair up shows the swap happening.
        assert_eq!(
            hex::encode_upper(enc_iccid("1234567890123456789").unwrap()),
            "214365870921436587F9"
        );
        assert!(matches!(
            enc_iccid("12345678901234567890a").unwrap_err(),
            Error::BadSecret(_)
        ));
    }

    #[test]
    fn an_imsi_is_the_reference_encoding_of_the_fixture_value() {
        // utils.py:53-59: the length byte, then the odd/even byte, which is
        // 9 for an odd number of digits, with the nibbles swapped.
        let encoded = enc_imsi(IMSI).unwrap();
        assert_eq!(hex::encode_upper(&encoded), IMSI_ENC);
        assert_eq!(encoded.len(), 9);
        assert_eq!(encoded[0], 0x08, "half_round_up(15 + 1)");
        // An even number of digits gets the odd/even byte 1 instead.
        assert_eq!(
            hex::encode_upper(enc_imsi("00101000000010").unwrap()),
            "0801101000000010F0"
        );
    }

    #[test]
    fn a_plmn_is_the_reference_encoding_and_agrees_with_the_reference_output() {
        // utils.py:113-137: mnc "01" becomes "01F", mcc "001" is unchanged,
        // and the six digits come out mcc[1] mcc[0] mnc[2] mcc[2] mnc[1]
        // mnc[0].
        assert_eq!(hex::encode_upper(enc_plmn(MCC, MNC).unwrap()), PLMN_ENC);
        assert_eq!(hex::encode_upper(enc_plmn("262", "01").unwrap()), "62F210");
        assert_eq!(hex::encode_upper(enc_plmn("262", "").unwrap()), "62F2FF");
        assert_eq!(hex::encode(enc_plmn("", "01").unwrap()), "ffff10");
    }

    #[test]
    fn the_operator_name_record_is_the_reference_record() {
        // rpad(b2h(name), 32) + "%02x" % len(name) + "01" [V]
        // legacy/cards.py:558-561, and the 18 byte record size is
        // _files["name"][1] at :625.
        let record = enc_magic_name("Magic").unwrap();
        assert_eq!(
            hex::encode(&record),
            format!("4d61676963{}0501", PAD_FILL_STR.repeat(22))
        );
        assert_eq!(record.len(), 18);
        assert!(matches!(
            enc_magic_name("").unwrap_err(),
            Error::BadSecret(_)
        ));
    }

    #[test]
    fn the_magic_sim_provider_record_is_the_reference_layout_at_its_own_length() {
        // legacy/cards.py:563-591 with _ki_file 6f1b [V] :643, padded to
        // _files["b_ef"][1] * 2 = 260 hex digits [V] :639, so 130 bytes.
        let record = enc_magic_provider(
            ICCID,
            IMSI,
            &Secret::new(hex::decode(KI).unwrap()),
            MCC,
            MNC,
            None,
        )
        .unwrap();
        assert_eq!(record.len(), 130);
        assert_eq!(&record[..5], &hex::decode("3f002fe20a").unwrap()[..]);
        assert_eq!(&record[5..15], &hex::decode(ICCID_ENC).unwrap()[..]);
        assert_eq!(&record[15..20], &hex::decode("7f206f0709").unwrap()[..]);
        assert_eq!(&record[20..29], &hex::decode(IMSI_ENC).unwrap()[..]);
        assert_eq!(&record[29..31], &hex::decode("6f1b").unwrap()[..]);
        assert_eq!(&record[32..48], &hex::decode(KI).unwrap()[..]);
        assert_eq!(&record[48..50], &hex::decode("6f30").unwrap()[..]);
        assert_eq!(&record[51..54], &hex::decode(PLMN_ENC).unwrap()[..]);
        assert_eq!(record.len() - 69, 61, "rpad to 130 with PAD_FILL");
        assert!(record[69..].iter().all(|b| *b == PAD_FILL));
        // With an ACC the reference appends 6f78 02 <lpad(acc, 4)>.
        let with_acc = enc_magic_provider(
            ICCID,
            IMSI,
            &Secret::new(hex::decode(KI).unwrap()),
            MCC,
            MNC,
            Some("8"),
        )
        .unwrap();
        assert_eq!(&with_acc[69..74], &hex::decode("6f7802fff8").unwrap()[..]);
        assert_eq!(with_acc.len(), 130);
    }

    #[test]
    fn a_value_the_file_cannot_hold_is_refused_and_never_quotes_itself() {
        let error = grcard_write_ki(&Secret::new(vec![0u8; 3])).unwrap_err();
        assert!(matches!(error, Error::BadSecret(_)));
        assert!(!error.to_string().contains("0000"));
        assert!(update_binary(0, &[0u8; 256]).is_err());
        assert!(verify_chv(1, &Secret::new(vec![0u8; 9])).is_err());
    }

    // --- identify ----------------------------------------------------------

    #[test]
    fn identify_sends_the_legacy_probe_and_not_the_usim_one() {
        let mut sim = MiniSim::new();
        let mut program = Program::new();
        let found = program
            .identify(&mut sim, "3b9f95801fc38031e073fe21135786810286984418a8")
            .unwrap();
        assert_eq!(
            sim.sent,
            vec![
                b"AT\r\n".to_vec(),
                b"AT+CSIM=?\r\n".to_vec(),
                b"AT+CSIM=16,\"A0A40000027F2000\"\r\n".to_vec(),
            ]
        );
        assert_eq!(program.commands()[2], "AT+CSIM=16,\"A0A40000027F2000\"");
        assert_eq!(found.model, Some(Model::OpenCells));
        assert_eq!(found.probe.len(), 1);
        assert_eq!(found.probe[0].what, "DF.GSM");
        assert_eq!(found.probe[0].file_len, 0x20);
    }

    #[test]
    fn the_probe_is_the_same_single_select_for_all_four_models() {
        for model in Model::ALL {
            let mut sim = MiniSim::new();
            let mut program = Program::new();
            let found = program.identify(&mut sim, "").unwrap();
            assert_eq!(program.commands().len(), 3, "{model}");
            assert_eq!(
                program.commands()[2],
                "AT+CSIM=16,\"A0A40000027F2000\"",
                "{model}"
            );
            assert_eq!(found.model, None, "{model} has no ATR to match");
        }
    }

    #[test]
    fn only_the_two_models_with_an_atr_are_detected_and_only_by_exact_equality() {
        // The two ATR literals [V] legacy/cards.py:1169 and :829.
        assert_eq!(
            Model::detect("3b9f95801fc38031e073fe21135786810286984418a8"),
            Some(Model::OpenCells)
        );
        assert_eq!(
            Model::detect("3B9F95801FC38031E073FE21135786810286984418A8"),
            Some(Model::OpenCells)
        );
        assert_eq!(
            Model::detect("3b7d9400005555530a7486930b247c4d5468"),
            Some(Model::SysmoSIMgr2)
        );
        // magic-SIM and GrCard have no ATR list at all, and no prefix match
        // and no near miss is invented for them.
        assert!(Model::MagicSim.atrs().is_empty());
        assert!(Model::GrCard.atrs().is_empty());
        assert_eq!(
            Model::detect("3b9f95801fc38031e073fe21135786810286984418a"),
            None
        );
        assert_eq!(
            Model::detect("3b9f95801fc38031e073fe21135786810286984418a9"),
            None
        );
    }

    #[test]
    fn a_card_from_another_vendor_is_not_this_model_and_is_not_forced() {
        // A sysmocom SJA2 ATR, from issue #283: a real card, not one of these.
        assert_eq!(
            Model::detect("3b9f96801f878031e073fe211b674a4c753034054ba9"),
            None
        );
        let error = Error::NotThisModel {
            expected: Model::GrCard.as_str(),
            found: Model::SysmoSIMgr2.as_str(),
        };
        assert_eq!(
            error.to_string(),
            "this card is a sysmoSIM-GR2, not a grcardsim"
        );
    }

    #[test]
    fn a_grcard_has_no_signal_and_says_so_instead_of_guessing() {
        // autodetect is `return None` with no test [V] legacy/cards.py:722-724.
        assert!(!Model::GrCard.is_self_identifying());
        let mut sim = MiniSim::new();
        let mut program = Program::new();
        let found = program.recognise(&mut sim, Model::GrCard, "").unwrap();
        assert!(!found.recognised);
        assert!(matches!(found.checks.as_slice(), [Check::Never { .. }]));
        assert_eq!(
            sim.sent.len(),
            0,
            "nothing is sent for a test that cannot run"
        );
    }

    #[test]
    fn a_magic_sim_is_recognised_by_the_two_record_sizes_the_reference_reads() {
        // MagicSimBase.autodetect [V] legacy/cards.py:520-527 with _files at
        // :637-641: 8f0c is 18 bytes, 8f0d is 130, and 8f0e is skipped because
        // its third tuple element is false (:624-525).
        let mut sim = MiniSim::with_record("8F0C", 18);
        sim.record_len.insert("8F0D".to_owned(), 130);
        let mut program = Program::new();
        let found = program.recognise(&mut sim, Model::MagicSim, "").unwrap();
        assert!(found.recognised);
        assert_eq!(found.checks.len(), 2);
        assert_eq!(
            found.checks[0],
            Check::RecordSize {
                path: vec!["3f00".into(), "7f4d".into(), "8f0c".into()],
                wanted: 18,
                got: Some(18),
                held: true,
            }
        );
        assert_eq!(sim.sent.len(), 6, "one SELECT per path element, twice");
        assert_eq!(sim.sent[2], cs("A0A40000028F0C00"));
    }

    #[test]
    fn a_record_size_that_does_not_hold_is_not_this_model() {
        let mut sim = MiniSim::with_record("8F0C", 17);
        sim.record_len.insert("8F0D".to_owned(), 130);
        let mut program = Program::new();
        let found = program.recognise(&mut sim, Model::MagicSim, "").unwrap();
        assert!(!found.recognised);
        assert!(matches!(
            found.checks[0],
            Check::RecordSize {
                wanted: 18,
                got: Some(17),
                held: false,
                ..
            }
        ));
    }

    // --- planning ----------------------------------------------------------

    #[test]
    fn a_plan_sends_nothing() {
        let program = Program::new();
        let sim = MiniSim::new();
        for model in Model::ALL {
            let _ = program.plan(model, &request());
        }
        assert_eq!(program.transcript().len(), 0);
        assert_eq!(sim.sent.len(), 0);
    }

    #[test]
    fn a_request_the_model_cannot_answer_writes_nothing() {
        let program = Program::new();
        assert!(matches!(
            program.plan(Model::GrCard, &ProgramRequest::default()),
            Err(Error::NothingToProgram(_))
        ));
        // OpenCells has no default ADM PIN [V] legacy/cards.py:1176-1178].
        assert!(matches!(
            program.plan(Model::OpenCells, &request()),
            Err(Error::BadSecret(_))
        ));
        // EF.PLMNSEL needs both halves of the PLMN.
        let mut half = request();
        half.mnc = None;
        assert!(matches!(
            program.plan(Model::MagicSim, &half),
            Err(Error::BadSecret(_))
        ));
        // The provider record needs the whole ICCID/IMSI/Ki triple, so without
        // the IMSI only EF.PLMNSEL survives.
        let mut pair = request();
        pair.imsi = None;
        assert_eq!(program.plan(Model::MagicSim, &pair).unwrap().len(), 1);
    }

    // --- the program transcripts ------------------------------------------

    #[test]
    fn the_opencells_program_transcript_is_exactly_the_reference_sequence() {
        let mut wanted = request();
        wanted.pin_adm = Some(Secret::new(b"12345678".to_vec()));
        wanted.opc = Some(Secret::new(
            hex::decode("6ca53d7a0a804561646816d7b0c702fb").unwrap(),
        ));
        let mut sim = MiniSim::with_file("FF02", 16);
        sim.file_len.insert("FF01".to_owned(), 16);
        let mut program = Program::new();
        let plan = program.plan(Model::OpenCells, &wanted).unwrap();
        let done = program.run(&mut sim, Model::OpenCells, &plan).unwrap();
        assert_eq!(done.len(), 5);
        assert_transcript(
            &sim,
            &[
                "A020000A083132333435363738".to_string(),
                "A0A40000023F0000".to_string(),
                "A0A40000022FE200".to_string(),
                format!("A0D600000A{ICCID_ENC}"),
                "A0A40000022FE200".to_string(),
                "A0B000000A".to_string(),
                "A0A40000027FF000".to_string(),
                "A0A4000002FF0200".to_string(),
                format!("A0D6000010{KI}"),
                "A0A4000002FF0200".to_string(),
                "A0B0000010".to_string(),
                "A0A40000027FF000".to_string(),
                "A0A4000002FF0100".to_string(),
                "A0D60000106CA53D7A0A804561646816D7B0C702FB".to_string(),
                "A0A4000002FF0100".to_string(),
                "A0B0000010".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A40000026F0700".to_string(),
                format!("A0D6000009{IMSI_ENC}"),
                "A0A40000026F0700".to_string(),
                "A0B0000009".to_string(),
            ],
        );
    }

    #[test]
    fn the_grcard_program_transcript_is_exactly_the_reference_sequence() {
        let mut sim = MiniSim::with_file("2FE2", 10);
        sim.file_len.insert("6F07".to_owned(), 9);
        sim.file_len.insert("6F30".to_owned(), 18);
        let mut program = Program::new();
        let plan = program.plan(Model::GrCard, &request()).unwrap();
        let done = program.run(&mut sim, Model::GrCard, &plan).unwrap();
        assert_eq!(done.len(), 5);
        assert_eq!(done[0].field, Field::AdmPin);
        assert_eq!(done[3].fid, "PROPRIETARY D4");
        assert_transcript(
            &sim,
            &[
                "A0200005084444444444444444".to_string(),
                "A0A40000023F0000".to_string(),
                "A0A40000022FE200".to_string(),
                format!("A0D600000A{ICCID_ENC}"),
                "A0A40000022FE200".to_string(),
                "A0B000000A".to_string(),
                "A0A40000023F0000".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A40000026F0700".to_string(),
                format!("A0D6000009{IMSI_ENC}"),
                "A0A40000026F0700".to_string(),
                "A0B0000009".to_string(),
                format!("80D4020010{KI}"),
                "A0A40000023F0000".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A40000026F3000".to_string(),
                format!("A0D6000012{PLMN_FILE}"),
                "A0A40000026F3000".to_string(),
                "A0B0000012".to_string(),
            ],
        );
    }

    #[test]
    fn the_gr2_program_transcript_is_exactly_the_reference_sequence() {
        let mut sim = MiniSim::with_file("2FE2", 10);
        sim.file_len.insert("6F07".to_owned(), 9);
        sim.file_len.insert("6F30".to_owned(), 18);
        sim.file_len.insert("0001".to_owned(), 19);
        let mut program = Program::new();
        let plan = program.plan(Model::SysmoSIMgr2, &request()).unwrap();
        let done = program.run(&mut sim, Model::SysmoSIMgr2, &plan).unwrap();
        assert_eq!(done.len(), plan.len());
        assert_transcript(
            &sim,
            &[
                "A020000B083838383838383838".to_string(),
                "A0D43A05084444444444444444".to_string(),
                "A0200005084444444444444444".to_string(),
                "A0A40000023F0000".to_string(),
                "A0A40000022FE200".to_string(),
                format!("A0D600000A{ICCID_ENC}"),
                "A0A40000022FE200".to_string(),
                "A0B000000A".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A40000026F0700".to_string(),
                format!("A0D6000009{IMSI_ENC}"),
                "A0A40000026F0700".to_string(),
                "A0B0000009".to_string(),
                "A0A40000026F3000".to_string(),
                format!("A0D6000012{PLMN_FILE}"),
                "A0A40000026F3000".to_string(),
                "A0B0000012".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A4000002000100".to_string(),
                "A0D6000003001000".to_string(),
                "A0A4000002000100".to_string(),
                "A0B0000003".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A4000002000100".to_string(),
                format!("A0D6000310{KI}"),
                "A0A4000002000100".to_string(),
                "A0B0000310".to_string(),
            ],
        );
    }

    #[test]
    fn the_magic_sim_program_transcript_is_exactly_the_reference_sequence() {
        let mut sim = MiniSim::with_record("8F0C", 18);
        sim.record_len.insert("8F0D".to_owned(), 130);
        sim.file_len.insert("6F30".to_owned(), 18);
        let mut wanted = request();
        wanted.operator_name = Some("Magic".to_owned());
        let mut program = Program::new();
        let plan = program.plan(Model::MagicSim, &wanted).unwrap();
        let done = program.run(&mut sim, Model::MagicSim, &plan).unwrap();
        assert_eq!(done.len(), 3);
        assert_eq!(done[0].fid, "8F0C");
        assert_eq!(done[1].fid, "8F0D");
        assert_eq!(done[2].fid, "6F30");
        let name = format!(
            "A0DC020412{}",
            hex::encode_upper(enc_magic_name("Magic").unwrap())
        );
        let provider = format!(
            "A0DC010482{}",
            hex::encode_upper(
                enc_magic_provider(
                    ICCID,
                    IMSI,
                    &Secret::new(hex::decode(KI).unwrap()),
                    MCC,
                    MNC,
                    None
                )
                .unwrap()
            )
        );
        assert_transcript(
            &sim,
            &[
                "A0A40000023F0000".to_string(),
                "A0A40000027F4D00".to_string(),
                "A0A40000028F0C00".to_string(),
                name.clone(),
                "A0A40000028F0C00".to_string(),
                "A0B2020412".to_string(),
                "A0A40000023F0000".to_string(),
                "A0A40000027F4D00".to_string(),
                "A0A40000028F0D00".to_string(),
                provider.clone(),
                "A0A40000028F0D00".to_string(),
                "A0B2010482".to_string(),
                "A0A40000023F0000".to_string(),
                "A0A40000027F2000".to_string(),
                "A0A40000026F3000".to_string(),
                format!("A0D6000012{PLMN_FILE}"),
                "A0A40000026F3000".to_string(),
                "A0B0000012".to_string(),
            ],
        );
    }

    #[test]
    fn a_driver_never_sends_an_apdu_outside_the_reference_vocabulary() {
        let mut sim = MiniSim::new();
        let mut wanted = request();
        wanted.pin_adm = Some(Secret::new(b"12345678".to_vec()));
        wanted.opc = Some(Secret::new(vec![0u8; 16]));
        wanted.acc = Some("8".to_owned());
        wanted.smsp = Some("0051555".to_owned());
        wanted.operator_name = Some("Magic".to_owned());
        let mut program = Program::new();
        for model in Model::ALL {
            let plan = program.plan(model, &wanted).unwrap();
            program.run(&mut sim, model, &plan).unwrap();
        }
        let mut used = BTreeSet::new();
        for sent in &sim.sent {
            let line = String::from_utf8_lossy(sent).into_owned();
            if !line.starts_with("AT+CSIM=") {
                continue;
            }
            let quoted = line
                .split_once(",\"")
                .expect("a quoted payload")
                .1
                .trim_end_matches("\"\r\n");
            let apdu = hex::decode(quoted).unwrap();
            let known_cla = apdu[0] == CLA_SIM || (apdu[1] == 0xD4 && apdu[0] == 0x80);
            assert!(known_cla, "a class byte the reference sends: {line}");

            used.insert(apdu[1]);
        }
        // Every INS that went out is one the reference sends, and the set is
        // exactly the reference vocabulary: 20 CHV, A4 SELECT, B0 and B2 read,
        // D4 proprietary, D6 and DC write. Nothing extra, nothing missing.
        assert_eq!(
            used,
            [0x20u8, 0xA4, 0xB0, 0xB2, 0xD4, 0xD6, 0xDC]
                .into_iter()
                .collect::<BTreeSet<u8>>()
        );
    }

    // --- the error branches ------------------------------------------------

    #[test]
    fn a_modem_that_never_answers_at_is_reported_once_and_nothing_more_is_sent() {
        let mut sim = MiniSim::new();
        sim.forced.push_back(Vec::new());
        let mut program = Program::new();
        assert!(matches!(
            program.identify(&mut sim, ""),
            Err(Error::NoResponse)
        ));
        assert_eq!(sim.sent, vec![b"AT\r\n".to_vec()]);
    }

    #[test]
    fn a_modem_without_csim_is_its_own_branch() {
        let mut sim = MiniSim::new();
        sim.forced.push_back(b"\r\nOK\r\n".to_vec());
        sim.forced.push_back(b"\r\nERROR\r\n".to_vec());
        let mut program = Program::new();
        assert!(matches!(program.identify(&mut sim, ""), Err(Error::NoCsim)));
        assert_eq!(sim.sent.len(), 2);
    }

    #[test]
    fn a_device_that_refuses_the_payload_is_a_device_refusal() {
        let mut sim = MiniSim::new();
        sim.forced.push_back(b"\r\nOK\r\n".to_vec());
        sim.forced.push_back(b"\r\nOK\r\n".to_vec());
        // A +CSIM line whose length field disagrees with its payload.
        sim.forced
            .push_back(b"\r\n+CSIM: 8,\"9000\"\r\n\r\nOK\r\n".to_vec());
        let mut program = Program::new();
        assert!(matches!(
            program.identify(&mut sim, ""),
            Err(Error::DeviceRefused(_))
        ));
        assert_eq!(sim.sent.len(), 3);
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
        let mut program = Program::new();
        assert!(matches!(
            program.identify(&mut gone, ""),
            Err(Error::Timeout(_))
        ));
        assert_eq!(
            program.transcript().len(),
            0,
            "nothing arrived, nothing recorded"
        );
    }

    #[test]
    fn a_card_that_refuses_a_write_is_a_status_word_and_the_run_stops() {
        let mut sim = MiniSim::new();
        sim.forced.push_back(csim_ok(&[0x90, 0x00]));
        sim.forced.push_back(csim_ok(&[0x90, 0x00]));
        sim.forced.push_back(csim_ok(&[0x6A, 0x82]));
        let mut program = Program::new();
        let mut wanted = request();
        wanted.pin_adm = Some(Secret::new(b"12345678".to_vec()));
        wanted.mcc = None;
        wanted.mnc = None;
        let plan = program.plan(Model::OpenCells, &wanted).unwrap();
        assert!(matches!(
            program.run(&mut sim, Model::OpenCells, &plan),
            Err(Error::StatusWord { sw: 0x6A82, .. })
        ));
        assert_eq!(sim.sent.len(), 3, "the run stops at the first refusal");
    }

    #[test]
    fn a_card_that_does_not_hold_what_was_written_is_verify_failed() {
        let mut sim = MiniSim::with_file("2FE2", 10);
        let mut program = Program::new();
        let mut wanted = ProgramRequest {
            iccid: Some(ICCID.to_owned()),
            pin_adm: Some(Secret::new(b"12345678".to_vec())),
            ..ProgramRequest::default()
        };
        wanted.imsi = None;
        let plan = program.plan(Model::OpenCells, &wanted).unwrap();
        let mut replies = vec![
            csim_ok(&[0x90, 0x00]),
            csim_ok(&[0x90, 0x00]),
            csim_ok(&[0x90, 0x00]),
            // A read-back of a different ICCID: same length, other digits.
            csim_ok(
                &[
                    hex::decode("99887766554433221100").unwrap(),
                    vec![0x90, 0x00],
                ]
                .concat(),
            ),
        ];
        replies.reverse();
        for reply in replies {
            sim.forced.push_back(reply);
        }
        assert!(matches!(
            program.run(&mut sim, Model::OpenCells, &plan),
            Err(Error::VerifyFailed { .. })
        ));
    }

    #[test]
    fn a_refusal_is_never_retried_forever() {
        let mut sim = MiniSim::new();
        for _ in 0..8 {
            sim.forced.push_back(b"\r\nERROR\r\n".to_vec());
        }
        let mut program = Program::new();
        for _ in 0..3 {
            assert!(program.identify(&mut sim, "").is_err());
        }
        assert_eq!(sim.sent.len(), 3, "one exchange per refused open");
    }

    #[test]
    fn a_secret_is_never_quoted_by_its_debug_or_by_an_error() {
        let secret = Secret::new(hex::decode(KI).unwrap());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("ffff"), "{rendered}");
        assert!(rendered.contains("16 bytes"));
        let error = grcard_write_ki(&Secret::new(vec![0u8; 3]))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("0000"), "{error}");
        // And no key reaches a transcript line.
        let mut sim = MiniSim::with_file("FF02", 16);
        let mut wanted = request();
        wanted.pin_adm = Some(Secret::new(b"12345678".to_vec()));
        let mut program = Program::new();
        let plan = program.plan(Model::OpenCells, &wanted).unwrap();
        program.run(&mut sim, Model::OpenCells, &plan).unwrap();
        // The key is on the wire by design, but a request is printable and
        // must not print it.
        let printed = format!("{wanted:?}");
        assert!(printed.contains("withheld"), "{printed}");
        assert!(!printed.contains(KI), "{printed}");
    }
}
