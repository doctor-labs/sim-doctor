//! A card-profile database derived from pySim, and a probe that matches a card
//! against it. Issue #275.
//!
//! **Owns.** The table of card profiles ([`DB`]), the provenance every entry
//! carries, and the matching that turns a probe run into a verdict.
//!
//! **Does not own.** The reader/session ([`crate::transport`]), the envelope
//! ([`crate::contract`]) or the walk ([`crate::walk`]).
//!
//! # What the reference actually probes
//!
//! The gap was filed against `pysim:pySim-prog.py:57-63`, the `-t`/`--type`
//! and `-T`/`--probe` pair. The catalogue it selects from is `_cards_classes`
//! at `pySim/legacy/cards.py:1635-1638`.
//!
//! pySim has **two different** notions of "this card", and they are not the
//! same test. Reporting them as one is how a wrong match becomes invisible.
//!
//! ## 1. The family probe - a SELECT, not a prefix
//!
//! `pySim/cards.py` decides **which kind of card** it is looking at with a
//! SELECT of a file identifier plus a life-cycle check. It is *not* a prefix
//! match on the IMSI, the ICCID or the ATR.
//!
//! * `SimCardBase.probe` (`pySim/cards.py:97-99`) SELECTs **DF.GSM**, `7F20`
//!   (`pySim/ts_51_011.py:1121`).
//! * `UiccCardBase.probe` (`pySim/cards.py:112-117`) SELECTs the **master file**
//!   and then **EF.DIR**, `2F00`. The comment on `pySim/cards.py:113` is why
//!   this is a UICC test: "EF.DIR is a mandatory EF on all ICCIDs; however it
//!   *may* also exist on a TS 51.011 SIM". The master-file answer is
//!   deliberately **discarded** - `pySim/cards.py:116` calls `file_exists` for
//!   its selection effect and returns the EF.DIR answer only.
//!
//! The class bytes differ with the family and are not cosmetic:
//! `SimCardBase` sets `cla_byte` `A0` and `sel_ctrl` `0000`
//! (`pySim/cards.py:94-95`); `UiccCardBase` sets `cla_byte` `00` and
//! `sel_ctrl` `0004`, i.e. an FCP is requested (`pySim/cards.py:107-108`).
//!
//! Both go through `CardBase.file_exists` (`pySim/cards.py:57-69`), a
//! **two-part** test: every SELECT on the path answered `9000`
//! (`pySim/cards.py:60-62`), and the decoded select response carries
//! `life_cycle_status_integer == operational_activated`
//! (`pySim/cards.py:64-66`). A SELECT that answers `9000` on a terminated or
//! deactivated file is therefore *not* a match. A response that does not
//! decode is not a failure: `pySim/cards.py:67-68` swallows the exception and
//! the file counts as present.
//!
//! `life_cycle_status_integer` is tag `8A` (`pySim/ts_102_221.py:236`) and
//! `operational_activated` is `lcsi & 0x05 == 0x05`
//! (`pySim/ts_102_221.py:248-249`) - a mask, not equality against `05`.
//!
//! **Order.** `pySim/cards.py:182-193` probes **UICC first** and returns at the
//! first match, with the reason on line 183: "UICC always has higher
//! preference, as a UICC might also contain a SIM application". The SIM probe
//! is therefore never sent once the UICC probe matched, and this module does
//! the same and records why in [`Run::not_probed`].
//!
//! ## 2. The per-model autodetection - exact ATR equality
//!
//! `pySim/legacy/cards.py` does **not** override `probe`. What it overrides is
//! `autodetect`, and for most classes that is **byte equality against a
//! hard-coded ATR**: `sysmosim-gr1` at `pySim/legacy/cards.py:784`,
//! `sysmoSIM-GR2` at `:829`, `sysmoUSIM-SJS1` at `:907`, `Fairwaves-SIM` at
//! `:1035`, `OpenCells-SIM` at `:1169`, `Wavemobile-SIM` at `:1218`,
//! `sysmoISIM-SJA2` at `:1308`, `:1313`, `:1318`, `sysmoISIM-SJA5` at `:1557`,
//! `:1561`, `:1565`, `gialersim` at `:1595`. Two classes read a record size
//! instead (`MagicSimBase.autodetect` at `:521-531`, `FakeMagicSim.autodetect`
//! at `:656-660`) and two declare no autodetection at all (`GrcardSim` at
//! `:723-724` returns `None`; `SysmoUSIMgr1` at `:798-800` returns `None`).
//!
//! **So the reference matches a named card model on exact historical ATR bytes,
//! and decides SIM-versus-UICC with a SELECT.** It is not a prefix match, and
//! it is not one signal either.
//!
//! ## 3. What this module can and cannot evaluate
//!
//! [`crate::transport::CardSession`] has no ATR accessor - `transmit`,
//! `reader` and `disconnect` are its whole surface - so **no ATR is read and
//! no ATR is compared here**. The ATRs are carried in [`DB`] as provenance, and
//! every report says which signals were evaluated and which were not. A named
//! model therefore cannot be *named* from a probe: a probe returns the
//! **family**, and within a family the candidates are indistinguishable.
//! [`Detection::candidates`] lists all of them and
//! [`Detection::distinct_signals`] is the number of genuinely different pieces
//! of evidence behind them, which is 1.
//!
//! # The winner rule
//!
//! `card_detect` (`pySim/legacy/cards.py:1641-1659`) iterates `_cards_classes`
//! in order and breaks on the first class that answers. This module keeps that
//! order and that rule, with the one necessary restriction that a class pySim
//! never autodetects (`grcardsim`, `sysmoUSIM-GR1`) cannot be an `-t auto`
//! winner - so it is listed as a candidate and excluded from the winner.
//!
//! # Duplicated `-t` names
//!
//! `card_detect` resolves `-t` through `dict([(kls.name, kls) for kls in
//! _cards_classes])` (`pySim/legacy/cards.py:1644`), so a name spelled by two
//! classes resolves to the last of them. As of the pinned tree no two classes
//! in `_cards_classes` share a name - `UsimCard` would have inherited `UICC`
//! from `UiccCardBase` (`pySim/cards.py:103`) but is not itself in the list -
//! and [`DB::names_are_unique`] asserts it, so the day pySim duplicates a name
//! this module refuses to guess.
//!
//! # Provenance is the data, not a comment
//!
//! Every entry carries a [`Source`] for its family probe and a [`Source`] for
//! its autodetection: the reference file, the line inside it, and a sentence
//! saying what is on that line. A copied table with no provenance is not
//! portable data - a reader cannot check it and neither can a test, so
//! `every_entry_carries_provenance` fails if one goes missing.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "cardprofile";

/// The envelope `type` of every `sim-doctor profile` subcommand.
pub const KIND: &str = "profile";

/// The reference this database is derived from.
pub const REFERENCE: &str = "osmocom/pysim, branch master";

/// The reference file holding the catalogue.
pub const CATALOGUE: &str = "pySim/legacy/cards.py";

/// The reference file holding the probes.
pub const PROBES: &str = "pySim/cards.py";

/// The line in [`CATALOGUE`] the order of [`DB`] comes from.
pub const CATALOGUE_LINE: u32 = 1635;

/// The master file, `3F00`; `pySim/cards.py:116`.
pub const MF: u16 = 0x3F00;

/// EF.DIR under the master file, `2F00`; `pySim/cards.py:114`.
pub const EF_DIR: u16 = 0x2F00;

/// DF.GSM, `7F20`; `pySim/ts_51_011.py:1121`.
pub const DF_GSM: u16 = 0x7F20;

/// FCP template tags accepted when hunting for the life-cycle status.
const FCP_TAGS: [u8; 2] = [0x62, 0x6F];

/// Life cycle status integer, `pySim/ts_102_221.py:236`.
const LIFE_CYCLE_TAG: u8 = 0x8A;

/// What a probe run says when nothing matched.
///
/// A card that matches nothing is **not** reported as the nearest profile:
/// `pySim/cards.py:192-193` returns `None` for exactly this case and prints
/// "Autodetection failed" (`pySim/legacy/cards.py:1655`). A closest-match
/// answer is not in the reference and is not invented here.
pub const NO_MATCH: &str = "no profile matched";

/// The message for a run where nothing matched.
pub const NOTHING_MATCHED: &str = "no profile matched; this is not a closest-match answer";

/// The message for a matched run.
pub const FAMILY_ONLY: &str = "the family probe cannot tell these candidates apart; only the \
per-model signal can, and this crate sends no ATR";

/// The winner rule, `pySim/legacy/cards.py:1646-1652`.
pub const FIRST_IN_CATALOGUE: &str =
    "first entry in pySim/legacy/cards.py:1635-1638 order that pySim can autodetect";

/// Which of the two probe families a profile belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// `UiccCardBase`, `pySim/cards.py:102-117`.
    Uicc,
    /// `SimCardBase`, `pySim/cards.py:87-99`.
    Sim,
}

impl Family {
    /// The probe this family is recognised by.
    pub const fn probe(self) -> Probe {
        match self {
            Family::Uicc => Probe::EfDirPresent,
            Family::Sim => Probe::DfGsmPresent,
        }
    }

    /// The spelling pySim uses (`pySim/cards.py:90`, `:103`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Family::Uicc => "UICC",
            Family::Sim => "SIM",
        }
    }
}

/// The file-existence probe a family is recognised by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Probe {
    /// SELECT the master file, then EF.DIR; `pySim/cards.py:112-117`.
    EfDirPresent,
    /// SELECT DF.GSM; `pySim/cards.py:97-99`.
    DfGsmPresent,
}

impl Probe {
    /// A sentence for the human report and for the JSON.
    pub const fn describe(self) -> &'static str {
        match self {
            Probe::EfDirPresent => {
                "SELECT MF (3F00) then SELECT EF.DIR (2F00), life cycle operational activated"
            }
            Probe::DfGsmPresent => "SELECT DF.GSM (7F20), life cycle operational activated",
        }
    }

    /// The APDUs this probe sends, in order.
    pub fn apdus(self) -> Vec<Vec<u8>> {
        match self {
            // UiccCardBase: cla 00, sel_ctrl 0004 (pySim/cards.py:107-108).
            Probe::EfDirPresent => vec![select(0x00, 0x04, MF), select(0x00, 0x04, EF_DIR)],
            // SimCardBase: cla A0, sel_ctrl 0000 (pySim/cards.py:94-95).
            Probe::DfGsmPresent => vec![select(0xA0, 0x00, DF_GSM)],
        }
    }

    /// The file identifiers this probe SELECTs, in order.
    pub const fn file_ids(self) -> &'static [u16] {
        match self {
            Probe::EfDirPresent => &[MF, EF_DIR],
            Probe::DfGsmPresent => &[DF_GSM],
        }
    }

    /// The file identifier whose answer decides the probe.
    ///
    /// For the UICC probe that is EF.DIR and *not* the master file:
    /// `pySim/cards.py:116` calls `file_exists` for the selection it performs
    /// and returns the EF.DIR answer only.
    pub const fn deciding_file_id(self) -> u16 {
        match self {
            Probe::EfDirPresent => EF_DIR,
            Probe::DfGsmPresent => DF_GSM,
        }
    }
}

/// Builds `SELECT <fid>` with pySim's class byte and P1/P2 for this probe.
fn select(cla: u8, p2: u8, fid: u16) -> Vec<u8> {
    let fid = fid.to_be_bytes();
    vec![cla, 0xA0, 0x00, p2, 0x02, fid[0], fid[1]]
}

/// Where one claim in this module comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// The reference file, relative to the repository root.
    pub file: &'static str,
    /// The line inside that file.
    pub line: u32,
    /// What is actually on that line.
    pub note: &'static str,
}

const fn source(file: &'static str, line: u32, note: &'static str) -> Source {
    Source { file, line, note }
}

/// How pySim decides this particular card model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Autodetect {
    /// Byte equality against these historical ATRs.
    Atr(&'static [&'static str]),
    /// Every known EF under `7F4D` must have its recorded record size.
    KnownEfRecordSizes,
    /// `3F00/000C` must hold `0x5A` bytes.
    Ef000cRecordSize,
    /// pySim declares no autodetection, so this can never be an `-t auto` winner.
    None,
}

impl Autodetect {
    /// A sentence for the human report and for the JSON.
    pub fn describe(self) -> String {
        match self {
            Autodetect::Atr(atrs) => format!("exact ATR equals one of {}", atrs.join(", ")),
            Autodetect::KnownEfRecordSizes => "record size of every known EF under 7F4D".to_owned(),
            Autodetect::Ef000cRecordSize => "record size of 3F00/000C is 0x5A".to_owned(),
            Autodetect::None => "none: pySim never autodetects this class".to_owned(),
        }
    }

    /// Can this signal ever name the card?
    ///
    /// `None` is the one that cannot, which is why `grcardsim` and
    /// `sysmoUSIM-GR1` can never be an `-t auto` winner.
    pub const fn names_a_card(self) -> bool {
        !matches!(self, Autodetect::None)
    }

    /// Can this crate evaluate it?
    ///
    /// None of them. `CardSession` exposes no ATR and this module sends no
    /// record-size read, so every per-model signal is carried as provenance
    /// and reported as not evaluated.
    pub const fn evaluated_here(self) -> bool {
        false
    }
}

/// One card model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The name `-t` takes (`kls.name`, printed at `pySim-prog.py:196-199`).
    pub name: &'static str,
    /// The pySim class this entry is (`kls` in `_cards_classes`).
    pub class: &'static str,
    /// Which probe family it belongs to, and therefore which probe it needs.
    pub family: Family,
    /// The signal that would name this card.
    pub autodetect: Autodetect,
    /// Where the family probe is defined.
    pub probe_source: Source,
    /// Where `autodetect` is defined for this class.
    pub autodetect_source: Source,
}

impl Entry {
    /// The family probe, which is [`Family::probe`].
    pub const fn probe(&self) -> Probe {
        self.family.probe()
    }
}

/// The card-profile database.
///
/// One entry per class in `_cards_classes` (`pySim/legacy/cards.py:1635-1638`)
/// **in that order**, because the order is the winner rule
/// (`pySim/legacy/cards.py:1646-1652`).
pub const DB: &[Entry] = &[
    Entry {
        name: "fakemagicsim",
        class: "FakeMagicSim",
        family: Family::Sim,
        autodetect: Autodetect::Ef000cRecordSize,
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; FakeMagicSim derives from SimCard and overrides only autodetect"),
        autodetect_source: source(CATALOGUE, 658, "FakeMagicSim.autodetect: record_size(['3f00','000c']) must be 0x5a"),
    },
    Entry {
        name: "supersim",
        class: "SuperSim",
        family: Family::Sim,
        autodetect: Autodetect::KnownEfRecordSizes,
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; SuperSim derives from MagicSimBase, which derives from SimCard"),
        autodetect_source: source(CATALOGUE, 521, "MagicSimBase.autodetect: every known EF under 7F4D must have its recorded record size"),
    },
    Entry {
        name: "magicsim",
        class: "MagicSim",
        family: Family::Sim,
        autodetect: Autodetect::KnownEfRecordSizes,
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; MagicSim derives from MagicSimBase, which derives from SimCard"),
        autodetect_source: source(CATALOGUE, 521, "MagicSimBase.autodetect: every known EF under 7F4D must have its recorded record size"),
    },
    Entry {
        name: "grcardsim",
        class: "GrcardSim",
        family: Family::Sim,
        autodetect: Autodetect::None,
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; GrcardSim derives from SimCard"),
        autodetect_source: source(CATALOGUE, 723, "GrcardSim.autodetect returns None: pySim has no test for this card"),
    },
    Entry {
        name: "sysmosim-gr1",
        class: "SysmoSIMgr1",
        family: Family::Sim,
        autodetect: Autodetect::Atr(&["3b991800118822334455667760"]),
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; SysmoSIMgr1 derives from GrcardSim, which derives from SimCard"),
        autodetect_source: source(CATALOGUE, 784, "SysmoSIMgr1.autodetect: scc.get_atr() == 3b991800118822334455667760"),
    },
    Entry {
        name: "sysmoSIM-GR2",
        class: "SysmoSIMgr2",
        family: Family::Sim,
        autodetect: Autodetect::Atr(&["3b7d9400005555530a7486930b247c4d5468"]),
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; SysmoSIMgr2 derives from SimCard"),
        autodetect_source: source(CATALOGUE, 829, "SysmoSIMgr2.autodetect: scc.get_atr() == 3b7d9400005555530a7486930b247c4d5468"),
    },
    Entry {
        name: "sysmoUSIM-GR1",
        class: "SysmoUSIMgr1",
        family: Family::Uicc,
        autodetect: Autodetect::None,
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; SysmoUSIMgr1 derives from UsimCard"),
        autodetect_source: source(CATALOGUE, 798, "SysmoUSIMgr1.autodetect returns None (a TODO in the reference): pySim has no test for this card"),
    },
    Entry {
        name: "sysmoUSIM-SJS1",
        class: "SysmoUSIMSJS1",
        family: Family::Uicc,
        autodetect: Autodetect::Atr(&["3b9f96801fc78031a073be21136743200718000001a5"]),
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; SysmoUSIMSJS1 derives from UsimCard"),
        autodetect_source: source(CATALOGUE, 907, "SysmoUSIMSJS1.autodetect: scc.get_atr() == 3b9f96801fc78031a073be21136743200718000001a5"),
    },
    Entry {
        name: "Fairwaves-SIM",
        class: "FairwavesSIM",
        family: Family::Uicc,
        autodetect: Autodetect::Atr(&["3b9f96801fc78031a073be21136744220610000001a9"]),
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; FairwavesSIM derives from UsimCard"),
        autodetect_source: source(CATALOGUE, 1035, "FairwavesSIM.autodetect: scc.get_atr() == 3b9f96801fc78031a073be21136744220610000001a9"),
    },
    Entry {
        name: "OpenCells-SIM",
        class: "OpenCellsSim",
        family: Family::Sim,
        autodetect: Autodetect::Atr(&["3b9f95801fc38031e073fe21135786810286984418a8"]),
        probe_source: source(PROBES, 97, "SimCardBase.probe SELECTs DF.GSM; OpenCellsSim derives from SimCard"),
        autodetect_source: source(CATALOGUE, 1169, "OpenCellsSim.autodetect: scc.get_atr() == 3b9f95801fc38031e073fe21135786810286984418a8"),
    },
    Entry {
        name: "Wavemobile-SIM",
        class: "WavemobileSim",
        family: Family::Uicc,
        autodetect: Autodetect::Atr(&["3b9f95801fc78031e073f62113674d4516004301008f"]),
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; WavemobileSim derives from UsimCard"),
        autodetect_source: source(CATALOGUE, 1218, "WavemobileSim.autodetect: scc.get_atr() == 3b9f95801fc78031e073f62113674d4516004301008f"),
    },
    Entry {
        name: "sysmoISIM-SJA2",
        class: "SysmoISIMSJA2",
        family: Family::Uicc,
        autodetect: Autodetect::Atr(&[
            "3b9f96801f878031e073fe211b674a4c753034054ba9",
            "3b9f96801f878031e073fe211b674a4c7531330251b2",
            "3b9f96801f878031e073fe211b674a4c5275310451d5",
        ]),
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; SysmoISIMSJA2 derives from UsimCard and IsimCard"),
        autodetect_source: source(CATALOGUE, 1308, "SysmoISIMSJA2.autodetect: three card models, ATR at :1308, :1313 and :1318"),
    },
    Entry {
        name: "sysmoISIM-SJA5",
        class: "SysmoISIMSJA5",
        family: Family::Uicc,
        autodetect: Autodetect::Atr(&[
            "3b9f96801f878031e073fe211b674a357530350251cc",
            "3b9f96801f878031e073fe211b674a357530350265f8",
            "3b9f96801f878031e073fe211b674a357530350259c4",
        ]),
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; SysmoISIMSJA5 derives from SysmoISIMSJA2"),
        autodetect_source: source(CATALOGUE, 1557, "SysmoISIMSJA5.autodetect: three card models, ATR at :1557, :1561 and :1565"),
    },
    Entry {
        name: "gialersim",
        class: "GialerSim",
        family: Family::Uicc,
        autodetect: Autodetect::Atr(&["3b9f95801fc78031a073b6a10067cf3215ca9cd70920"]),
        probe_source: source(PROBES, 112, "UiccCardBase.probe SELECTs MF then EF.DIR; GialerSim derives from UsimCard"),
        autodetect_source: source(CATALOGUE, 1595, "GialerSim.autodetect: scc.get_atr() == 3b9f95801fc78031a073b6a10067cf3215ca9cd70920"),
    },
];

/// The table, as a type so its helpers can be inherent.
pub struct Database;

impl Database {
    /// Looks a `-t` name up, as `card_detect` does (`pySim/legacy/cards.py:1658`).
    pub fn find(name: &str) -> Option<&'static Entry> {
        DB.iter().find(|entry| entry.name == name)
    }

    /// Every name, in catalogue order.
    pub fn names() -> impl Iterator<Item = &'static str> {
        DB.iter().map(|entry| entry.name)
    }

    /// The index of the first entry of `family` pySim could actually autodetect.
    pub fn winner_of(family: Family) -> Option<usize> {
        DB.iter()
            .position(|entry| entry.family == family && entry.autodetect.names_a_card())
    }

    /// `true` when no two entries share a `-t` name.
    pub fn names_are_unique() -> bool {
        let mut names: Vec<&str> = names().collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        names.len() == before
    }
}

/// Module-level alias, so callers do not have to name [`Database`].
pub fn find(name: &str) -> Option<&'static Entry> {
    Database::find(name)
}

/// Every `-t` name, in catalogue order.
pub fn names() -> impl Iterator<Item = &'static str> {
    Database::names()
}

/// The index of the first entry of `family` pySim could actually autodetect.
pub fn winner_of(family: Family) -> Option<usize> {
    Database::winner_of(family)
}

/// `true` when no two entries share a `-t` name.
pub fn names_are_unique() -> bool {
    Database::names_are_unique()
}

/// One SELECT the probe sent, and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The file identifier that was SELECTed.
    pub file_id: u16,
    /// The exact bytes sent.
    pub apdu: Vec<u8>,
    /// The status word the card answered.
    pub sw: [u8; 2],
    /// `false` for the master-file SELECT of the UICC probe, whose answer
    /// `pySim/cards.py:116` throws away.
    pub judged: bool,
    /// The verdict for this step.
    pub present: bool,
    /// The life-cycle status the select response carried, when it carried one.
    pub life_cycle: Option<u8>,
    /// Whether the response held an FCP template at all.
    pub fcp_present: bool,
}

impl Step {
    /// The life-cycle octet in words, `None` when the card sent no FCP.
    pub fn life_cycle_label(&self) -> Option<String> {
        self.life_cycle.map(|byte| {
            if operational_activated(byte) {
                format!("{byte:02X} operational activated")
            } else {
                format!("{byte:02X} not operational activated")
            }
        })
    }
}

/// What a probe run decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The UICC probe matched.
    Uicc,
    /// The SIM probe matched.
    Sim,
    /// Neither probe matched.
    None,
}

impl Outcome {
    /// The JSON spelling.
    pub const fn as_json(self) -> &'static str {
        match self {
            Outcome::Uicc => "uicc",
            Outcome::Sim => "sim",
            Outcome::None => "no-profile-matched",
        }
    }
}

/// A family whose probe was not sent, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotProbed {
    /// The family.
    pub family: Family,
    /// The reason, in the reference's terms.
    pub reason: &'static str,
}

/// A completed probe run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// What the run decided.
    pub outcome: Outcome,
    /// Every APDU sent and every answer, in order.
    pub steps: Vec<Step>,
    /// The family whose probe was skipped, if any.
    pub not_probed: Option<NotProbed>,
}

/// `operational_activated` is `lcsi & 0x05 == 0x05` (`pySim/ts_102_221.py:248-249`).
///
/// It is a mask test, not equality against `05`, so this module does not use
/// the repository's named `crate::fcp::LifeCycleStatus` values: those are the
/// TS 51.011 spellings and would silently drop `0D`, which this rule accepts.
pub const fn operational_activated(byte: u8) -> bool {
    byte & 0x05 == 0x05
}

/// Reads a BER-TLV length. `None` for the indefinite form and for anything
/// this probe cannot bound.
fn read_len(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 || count > 2 || input.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for byte in &input[1..1 + count] {
        len = (len << 8) | usize::from(*byte);
    }
    Some((len, 1 + count))
}

/// The life cycle status integer out of a select response body.
///
/// Tag `8A` inside the FCP template (`62`, or `6F` when an FCP was requested),
/// `pySim/ts_102_221.py:236`. `None` when there is no FCP, no `8A`, or the
/// bytes do not parse - the case `pySim/cards.py:67-68` swallows, and which
/// this module reports rather than hides.
pub fn life_cycle_status(body: &[u8]) -> Option<u8> {
    let mut template = None;
    let mut offset = 0usize;
    while offset + 2 <= body.len() {
        let tag = body[offset];
        let (len, header) = read_len(&body[offset + 1..])?;
        let start = offset + 1 + header;
        let end = start.checked_add(len)?;
        if end > body.len() {
            return None;
        }
        if FCP_TAGS.contains(&tag) {
            template = Some(&body[start..end]);
            break;
        }
        offset = end;
    }
    let mut inner = template?;
    while inner.len() >= 2 {
        let tag = inner[0];
        let (len, header) = read_len(&inner[1..])?;
        let start = 1 + header;
        let end = start.checked_add(len)?;
        if end > inner.len() {
            return None;
        }
        if tag == LIFE_CYCLE_TAG {
            let value = &inner[start..end];
            return value.first().copied().filter(|_| value.len() == 1);
        }
        inner = &inner[end..];
    }
    None
}

/// `file_exists` (`pySim/cards.py:57-69`) over one select response.
///
/// Returns `(present, life_cycle, fcp_present)`. The status word must be `9000`
/// and, when the response carried an FCP template, the life-cycle status must be
/// `operational_activated` too.
pub fn file_exists(body: &[u8], sw: [u8; 2]) -> (bool, Option<u8>, bool) {
    let life_cycle = life_cycle_status(body);
    let fcp_present = life_cycle.is_some();
    let present = sw == [0x90, 0x00] && life_cycle.is_none_or(operational_activated);
    (present, life_cycle, fcp_present)
}

/// Runs the probes in pySim's order over a session.
///
/// UICC first, and the SIM probe is not sent once the UICC probe matched
/// (`pySim/cards.py:182-193`). Every APDU here is a SELECT; nothing is written.
pub fn probe(
    session: &mut dyn crate::transport::CardSession,
) -> Result<Run, crate::transport::Error> {
    let mut steps = Vec::new();
    if send_family(session, Family::Uicc, &mut steps)? {
        return Ok(Run {
            outcome: Outcome::Uicc,
            steps,
            not_probed: Some(NotProbed {
                family: Family::Sim,
                reason: "pySim/cards.py:185-186 returns on the first match, so the SIM probe is never sent",
            }),
        });
    }
    let sim = send_family(session, Family::Sim, &mut steps)?;
    Ok(Run {
        outcome: if sim { Outcome::Sim } else { Outcome::None },
        steps,
        not_probed: None,
    })
}

/// Sends one family's probe and records every answer.
fn send_family(
    session: &mut dyn crate::transport::CardSession,
    family: Family,
    steps: &mut Vec<Step>,
) -> Result<bool, crate::transport::Error> {
    let probe = family.probe();
    let deciding = probe.deciding_file_id();
    let mut matched = false;
    for (index, apdu) in probe.apdus().iter().enumerate() {
        let file_id = probe.file_ids()[index];
        let response = session.transmit(apdu)?;
        let body = if response.len() >= 2 {
            &response[..response.len() - 2]
        } else {
            &[][..]
        };
        let sw = [
            response
                .get(response.len().wrapping_sub(2))
                .copied()
                .unwrap_or(0),
            response.last().copied().unwrap_or(0),
        ];
        let (present, life_cycle, fcp_present) = file_exists(body, sw);
        let judged = file_id == deciding;
        if judged {
            matched = present;
        }
        steps.push(Step {
            file_id,
            apdu: apdu.clone(),
            sw,
            judged,
            present,
            life_cycle,
            fcp_present,
        });
    }
    Ok(matched)
}

/// The evidence behind one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Index into [`DB`].
    pub index: usize,
    /// Whether the family probe matched for this entry.
    pub probe_matched: bool,
}

/// The verdict over the whole database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// What the probe decided.
    pub outcome: Outcome,
    /// The `-t` name of the winner, `None` when nothing matched.
    pub winner: Option<&'static str>,
    /// How the winner was chosen, in words.
    pub winner_rule: &'static str,
    /// How many genuinely different pieces of evidence the candidates rest on.
    pub distinct_signals: usize,
    /// Every entry the evidence is compatible with, in catalogue order.
    pub candidates: Vec<Candidate>,
    /// The sentence a reader should take away.
    pub message: &'static str,
}

/// Turns a [`Run`] into a verdict over the whole database.
///
/// Every compatible entry is reported. A winner is named only when pySim could
/// have autodetected one, and it is named with the family it was picked from,
/// never as a card model: the ATR that would name the model
/// (`pySim/legacy/cards.py:784` and onwards) is recorded but not evaluated.
pub fn detect(run: &Run) -> Detection {
    let family = match run.outcome {
        Outcome::Uicc => Family::Uicc,
        Outcome::Sim => Family::Sim,
        Outcome::None => {
            return Detection {
                outcome: Outcome::None,
                winner: None,
                winner_rule: "",
                distinct_signals: 0,
                candidates: Vec::new(),
                message: NOTHING_MATCHED,
            }
        }
    };
    let candidates: Vec<Candidate> = DB
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.family == family)
        .map(|(index, _)| Candidate {
            index,
            probe_matched: true,
        })
        .collect();
    Detection {
        outcome: run.outcome,
        winner: winner_of(family).map(|index| DB[index].name),
        winner_rule: FIRST_IN_CATALOGUE,
        distinct_signals: 1,
        candidates,
        message: FAMILY_ONLY,
    }
}

/// Whether `name` is a `-t` name this database carries.
pub fn is_known(name: &str) -> bool {
    find(name).is_some()
}

/// The known `-t` names, joined for an error message.
pub fn known_names() -> String {
    names().collect::<Vec<_>>().join(", ")
}

/// Lowercase hex, for the JSON.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn source_json(src: &Source) -> serde_json::Value {
    serde_json::json!({ "file": src.file, "line": src.line, "note": src.note })
}

fn entry_json(entry: &Entry) -> serde_json::Value {
    serde_json::json!({
        "name": entry.name,
        "class": entry.class,
        "family": entry.family.as_str(),
        "probe": entry.probe().describe(),
        "probe_source": source_json(&entry.probe_source),
        "autodetect": entry.autodetect.describe(),
        "autodetect_evaluated": entry.autodetect.evaluated_here(),
        "autodetect_names_a_card": entry.autodetect.names_a_card(),
        "autodetect_source": source_json(&entry.autodetect_source),
    })
}

/// The database as JSON, provenance included.
pub fn database_json() -> serde_json::Value {
    serde_json::json!({
        "reference": REFERENCE,
        "catalogue": CATALOGUE,
        "catalogue_line": CATALOGUE_LINE,
        "count": DB.len(),
        "signals_evaluated_here": [],
        "note": "the per-model signal of every entry is carried as provenance and is not \
                 evaluated by this tool; CardSession has no ATR accessor",
        "entries": DB.iter().map(entry_json).collect::<Vec<_>>(),
    })
}

/// A probe run as JSON, every APDU and every answer included.
pub fn run_json(run: &Run, detection: &Detection) -> serde_json::Value {
    serde_json::json!({
        "probe": run.outcome.as_json(),
        "probe_description": match run.outcome {
            Outcome::Uicc => Probe::EfDirPresent.describe(),
            Outcome::Sim => Probe::DfGsmPresent.describe(),
            Outcome::None => "neither EF.DIR nor DF.GSM answered for a live file",
        },
        "exchanges": run.steps.iter().map(|step| serde_json::json!({
            "file_id": format!("{:04X}", step.file_id),
            "apdu": hex(&step.apdu),
            "sw": format!("{:02X}{:02X}", step.sw[0], step.sw[1]),
            "judged": step.judged,
            "present": step.present,
            "life_cycle": step.life_cycle.map(|byte| format!("{byte:02X}")),
            "life_cycle_detail": step.life_cycle_label(),
            "fcp_present": step.fcp_present,
        })).collect::<Vec<_>>(),
        "not_probed": run.not_probed.map(|skip| serde_json::json!({
            "family": skip.family.as_str(),
            "reason": skip.reason,
        })),
        "life_cycle_rule": "operational_activated is lcsi & 0x05 == 0x05 (pySim/ts_102_221.py:248-249)",
        "life_cycle_source": source_json(&source(PROBES, 64, "file_exists: life_cycle_status_integer must be operational_activated")),
        "status_word_source": source_json(&source(PROBES, 60, "file_exists: every SELECT on the path must answer 9000")),
        "winner": detection.winner,
        "winner_rule": if detection.winner.is_some() { detection.winner_rule } else { "" },
        "distinct_signals": detection.distinct_signals,
        "message": detection.message,
        "candidates": detection.candidates.iter().map(|candidate| entry_json(&DB[candidate.index])).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{CardSession, Error, ReaderName};

    /// A card that answers from a script and records what it was asked.
    struct Scripted {
        answers: Vec<Vec<u8>>,
        asked: Vec<Vec<u8>>,
        next: usize,
    }

    impl Scripted {
        fn new(answers: Vec<Vec<u8>>) -> Self {
            Self {
                answers,
                asked: Vec::new(),
                next: 0,
            }
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            static NAME: std::sync::OnceLock<ReaderName> = std::sync::OnceLock::new();
            NAME.get_or_init(|| ReaderName::new("scripted").expect("a valid reader name"))
        }
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
            self.asked.push(command.to_vec());
            let answer = self
                .answers
                .get(self.next)
                .cloned()
                .unwrap_or_else(|| panic!("the script ran out after {} exchanges", self.next));
            self.next += 1;
            Ok(answer)
        }
        fn disconnect(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    /// A `62` FCP template carrying `8A 01 <life cycle>`, an SFI and a file id.
    fn fcp(life_cycle: u8) -> Vec<u8> {
        let value = [0x8A, 0x01, life_cycle, 0x83, 0x02, 0x2F, 0x00];
        let mut body = vec![0x62, value.len() as u8];
        body.extend_from_slice(&value);
        body.extend_from_slice(&[0x90, 0x00]);
        body
    }

    fn not_found() -> Vec<u8> {
        vec![0x6A, 0x82]
    }

    // -- provenance -----------------------------------------------------

    #[test]
    fn every_entry_carries_provenance() {
        assert!(!DB.is_empty());
        for entry in DB {
            for (what, src) in [
                ("probe_source", entry.probe_source),
                ("autodetect_source", entry.autodetect_source),
            ] {
                assert!(!src.note.is_empty(), "{}/{what} has no note", entry.name);
                assert!(src.line > 0, "{}/{what} has no line", entry.name);
                assert!(
                    src.file == PROBES || src.file == CATALOGUE,
                    "{}/{what} cites {}, not a reference file of this database",
                    entry.name,
                    src.file
                );
            }
            assert_ne!(
                entry.probe_source, entry.autodetect_source,
                "{} cites one line for two different signals",
                entry.name
            );
        }
    }

    #[test]
    fn every_probe_source_points_at_the_probe_it_names() {
        for entry in DB {
            let expected = match entry.probe() {
                Probe::EfDirPresent => 112,
                Probe::DfGsmPresent => 97,
            };
            assert_eq!(entry.probe_source.line, expected, "{}", entry.name);
        }
    }

    #[test]
    fn the_database_is_the_reference_catalogue_in_its_order() {
        assert_eq!(
            DB.len(),
            14,
            "pySim/legacy/cards.py:1635-1638 lists fourteen classes"
        );
        assert!(names_are_unique(), "two entries share a -t name");
        assert_eq!(names().next(), Some("fakemagicsim"));
        assert_eq!(names().last(), Some("gialersim"));
    }

    #[test]
    fn both_families_have_a_winner() {
        assert!(DB.iter().any(|entry| entry.family == Family::Uicc));
        assert!(DB.iter().any(|entry| entry.family == Family::Sim));
        for family in [Family::Uicc, Family::Sim] {
            assert!(
                winner_of(family).is_some(),
                "{family:?} has no entry pySim could autodetect"
            );
        }
    }

    #[test]
    fn the_two_classes_py_sim_cannot_detect_are_marked() {
        let undetectable: Vec<&str> = DB
            .iter()
            .filter(|entry| !entry.autodetect.names_a_card())
            .map(|entry| entry.name)
            .collect();
        assert_eq!(undetectable, vec!["grcardsim", "sysmoUSIM-GR1"]);
    }

    #[test]
    fn no_per_model_signal_is_claimed_to_be_evaluated() {
        for entry in DB {
            assert!(
                !entry.autodetect.evaluated_here(),
                "{} claims an evaluation this crate does not do",
                entry.name
            );
        }
    }

    #[test]
    fn the_json_carries_the_provenance_of_every_entry() {
        let json = database_json();
        let entries = json["entries"].as_array().expect("an entries array");
        assert_eq!(entries.len(), DB.len());
        for entry in entries {
            for key in ["probe_source", "autodetect_source"] {
                let src = &entry[key];
                assert!(src["file"].is_string(), "{key} lost its file");
                assert!(
                    src["line"].as_u64().is_some_and(|line| line > 0),
                    "{key} lost its line"
                );
                assert!(
                    !src["note"].as_str().unwrap_or_default().is_empty(),
                    "{key} lost its note"
                );
            }
            assert_eq!(entry["autodetect_evaluated"], false);
        }
    }

    // -- the life-cycle rule --------------------------------------------

    #[test]
    fn operational_activated_is_a_mask_not_an_equality() {
        assert!(operational_activated(0x05));
        assert!(operational_activated(0x0D));
        assert!(!operational_activated(0x04));
        assert!(!operational_activated(0x0C));
        assert!(!operational_activated(0x00));
    }

    #[test]
    fn the_life_cycle_status_is_read_out_of_the_fcp_template() {
        assert_eq!(life_cycle_status(&fcp(0x05)), Some(0x05));
        assert_eq!(life_cycle_status(&fcp(0x0C)), Some(0x0C));
        assert_eq!(life_cycle_status(&[0x9F, 0x17]), None);
    }

    #[test]
    fn file_exists_needs_both_9000_and_a_live_file() {
        assert!(file_exists(&fcp(0x05), [0x90, 0x00]).0);
        assert!(!file_exists(&fcp(0x0C), [0x90, 0x00]).0);
        assert!(!file_exists(&fcp(0x05), [0x6A, 0x82]).0);
        // No FCP at all: pySim/cards.py:67-68 swallows the decode error.
        assert!(file_exists(&[], [0x90, 0x00]).0);
    }

    // -- the probe -------------------------------------------------------

    #[test]
    fn a_uicc_card_probes_ef_dir_and_stops_before_the_sim_probe() {
        let mut card = Scripted::new(vec![fcp(0x05), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        assert_eq!(run.outcome, Outcome::Uicc);
        assert_eq!(card.asked, Probe::EfDirPresent.apdus());
        let skip = run.not_probed.expect("the SIM probe was skipped");
        assert_eq!(skip.family, Family::Sim);
    }

    #[test]
    fn the_master_file_answer_is_recorded_but_not_judged() {
        let mut card = Scripted::new(vec![not_found(), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        // pySim/cards.py:116 discards the MF answer and returns the EF.DIR one.
        assert_eq!(run.outcome, Outcome::Uicc);
        assert!(!run.steps[0].judged);
        assert_eq!(run.steps[0].sw, [0x6A, 0x82]);
        assert!(run.steps[1].judged);
    }

    #[test]
    fn a_sim_card_is_found_when_ef_dir_is_absent() {
        let mut card = Scripted::new(vec![not_found(), not_found(), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        assert_eq!(run.outcome, Outcome::Sim);
        assert_eq!(card.asked.len(), 3, "both families were probed");
        assert_eq!(card.asked.last(), Probe::DfGsmPresent.apdus().last());
        assert!(run.not_probed.is_none());
    }

    #[test]
    fn a_deactivated_ef_dir_is_not_a_uicc() {
        let mut card = Scripted::new(vec![fcp(0x05), fcp(0x04), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        assert_eq!(run.outcome, Outcome::Sim);
        assert_eq!(run.steps[1].life_cycle, Some(0x04));
        assert!(!run.steps[1].present);
    }

    #[test]
    fn a_card_that_matches_nothing_says_so() {
        let mut card = Scripted::new(vec![fcp(0x05), not_found(), not_found()]);
        let run = probe(&mut card).expect("the script answers");
        assert_eq!(run.outcome, Outcome::None);
        let detection = detect(&run);
        assert!(detection.candidates.is_empty());
        assert!(detection.winner.is_none());
        assert_eq!(detection.message, NOTHING_MATCHED);
        assert!(NO_MATCH.starts_with("no profile matched"));
        assert!(detection.message.contains("not a closest-match"));
    }

    // -- the matching ---------------------------------------------------

    #[test]
    fn a_uicc_run_lists_every_uicc_candidate_and_names_one() {
        let mut card = Scripted::new(vec![fcp(0x05), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        let detection = detect(&run);
        assert_eq!(detection.distinct_signals, 1);
        assert_eq!(
            detection
                .candidates
                .iter()
                .map(|c| DB[c.index].name)
                .collect::<Vec<_>>(),
            vec![
                "sysmoUSIM-GR1",
                "sysmoUSIM-SJS1",
                "Fairwaves-SIM",
                "Wavemobile-SIM",
                "sysmoISIM-SJA2",
                "sysmoISIM-SJA5",
                "gialersim",
            ]
        );
        // sysmoUSIM-GR1 is first, but pySim never autodetects it.
        assert_eq!(detection.winner, Some("sysmoUSIM-SJS1"));
    }

    #[test]
    fn a_sim_run_lists_every_sim_candidate_and_names_one() {
        let mut card = Scripted::new(vec![fcp(0x05), not_found(), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        let detection = detect(&run);
        assert_eq!(
            detection
                .candidates
                .iter()
                .map(|c| DB[c.index].name)
                .collect::<Vec<_>>(),
            vec![
                "fakemagicsim",
                "supersim",
                "magicsim",
                "grcardsim",
                "sysmosim-gr1",
                "sysmoSIM-GR2",
                "OpenCells-SIM",
            ]
        );
        assert_eq!(detection.winner, Some("fakemagicsim"));
    }

    #[test]
    fn every_candidate_carries_its_own_provenance() {
        let mut card = Scripted::new(vec![fcp(0x05), fcp(0x05)]);
        let run = probe(&mut card).expect("the script answers");
        let json = run_json(&run, &detect(&run));
        let candidates = json["candidates"].as_array().expect("a candidates array");
        assert!(!candidates.is_empty());
        for candidate in candidates {
            assert!(candidate["probe_source"]["line"]
                .as_u64()
                .is_some_and(|line| line > 0));
            assert!(candidate["autodetect_source"]["line"]
                .as_u64()
                .is_some_and(|line| line > 0));
        }
    }

    #[test]
    fn an_unknown_name_is_not_in_the_database() {
        assert!(is_known("gialersim"));
        assert!(!is_known("nosuchcard"));
        assert!(find("nosuchcard").is_none());
        assert!(known_names().contains("gialersim"));
    }
}
