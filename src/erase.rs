//! Erase before programming: the reference programming tool flag -e / --erase.
//!
//! WHAT THIS ERASES. pySim-prog.py defines -e/--erase at lines 71-74 and calls
//! card.erase() at line 730, under the comment "Erase if requested (not in dry
//! run mode!)" at line 726. That method is a per-record overwrite of the
//! provisioning records of the card. It is NOT a GlobalPlatform DELETE, NOT an
//! application delete, and NOT a filesystem delete:
//!
//!   - MagicSimBase.erase() (pySim/legacy/cards.py:603-617, commented "Dummy")
//!     builds an 0xFF-filled image of every provisioning EF and writes it with
//!     update_record on the path 3f00/7f4d/fid, record n+ofs, for every record
//!     slot n of the count read from EF 8F0C. name starts at record 2 and its
//!     last two bytes are written 00 00 instead of FF FF (lines 607-608); b_ef
//!     and r_ef start at record 1.
//!   - MagicSim.erase() (pySim/legacy/cards.py:703-711) writes FF times rec_len
//!     to every record 1..count of EF 3f00/000c.
//!
//! The two APDUs are from pySim itself: SELECT by FID is CLA A4 00 02 FID 00
//! (pySim/commands.py:274-283) and UPDATE RECORD is CLA DC record 04 len data
//! (pySim/commands.py:462): P1 is the record number, P2 04 is first and only
//! record with replaced data, Lc is the record length. The erase is therefore
//! only UPDATE RECORD DC against the named provisioning EFs under DF
//! 3f00/7f4d.
//!
//! Because an interrupted overwrite leaves records half-erased and the
//! provisioned identity of the card unreadable, the dry run and the help carry
//! one WARNING, and a failed step is reported and never retried.

use crate::{apdu, ef, gp, scp03, transport::CardSession};

/// The envelope kind this report is published under.
pub const KIND: &str = "program-erase";

/// The WARNING the help and the dry run both carry verbatim.
pub const WARNING: &str = "WARNING: this erase is PERMANENT. It overwrites the provisioning records of the card with 0xFF and there is no undo. An interrupted erase leaves some records erased and some not, which is an undefined state the card may not come back from. Only the records named below are touched: no application, ISD, load file or other file is deleted.";

/// Which pySim card class the erase targets. The record EFs and their lengths
/// are the _files table of that class (pySim/legacy/cards.py:620-643).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardClass {
    /// DF 3f00/7f4d, EFs 8F0C/8F0D/8F0E.
    MagicSim,
    /// The same DF and EFs with shorter records.
    SuperSim,
    /// One record EF, 3f00/000c.
    FakeMagicSim,
}

impl CardClass {
    /// The --card spelling.
    pub fn id(self) -> &'static str {
        match self {
            Self::MagicSim => "magicsim",
            Self::SuperSim => "supersim",
            Self::FakeMagicSim => "fakemagicsim",
        }
    }

    /// Every class, in the order the help lists them.
    pub fn all() -> &'static [(CardClass, &'static str)] {
        &[
            (Self::MagicSim, "magicsim"),
            (Self::SuperSim, "supersim"),
            (Self::FakeMagicSim, "fakemagicsim"),
        ]
    }

    /// The named record EFs of the erase: FID, record length in bytes, and the
    /// record number that the first erased record carries.
    pub fn files(self) -> Vec<ProvisioningEf> {
        match self {
            // legacy/cards.py:631-637
            Self::MagicSim => vec![
                ProvisioningEf {
                    fid: "8f0c",
                    rec_len: 18,
                    first_record: 2,
                },
                ProvisioningEf {
                    fid: "8f0d",
                    rec_len: 130,
                    first_record: 1,
                },
                ProvisioningEf {
                    fid: "8f0e",
                    rec_len: 102,
                    first_record: 1,
                },
            ],
            // legacy/cards.py:624-629
            Self::SuperSim => vec![
                ProvisioningEf {
                    fid: "8f0c",
                    rec_len: 18,
                    first_record: 2,
                },
                ProvisioningEf {
                    fid: "8f0d",
                    rec_len: 74,
                    first_record: 1,
                },
                ProvisioningEf {
                    fid: "8f0e",
                    rec_len: 50,
                    first_record: 1,
                },
            ],
            // legacy/cards.py:703-711: the records start at 1
            Self::FakeMagicSim => vec![ProvisioningEf {
                fid: "000c",
                rec_len: 0,
                first_record: 1,
            }],
        }
    }

    /// The DF the provisioning EFs live under, selected before each EF.
    fn parent(self) -> Option<&'static str> {
        match self {
            Self::MagicSim | Self::SuperSim => Some("7f4d"),
            Self::FakeMagicSim => None,
        }
    }
}

/// One record EF the erase overwrites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisioningEf {
    /// The file identifier of the EF, 2 bytes.
    pub fid: &'static str,
    /// The record length in bytes; 0 when the card is asked for it.
    pub rec_len: usize,
    /// The record number of the first erased record (name starts at 2).
    pub first_record: u8,
}

impl ProvisioningEf {
    /// The path select_path walks: 3f00/7f4d/fid, or 3f00/fid.
    pub fn path(&self, class: CardClass) -> String {
        match class.parent() {
            Some(df) => format!("3f00/{df}/{}", self.fid),
            None => format!("3f00/{}", self.fid),
        }
    }

    /// The bytes one erased record of this EF holds: 0xFF throughout, except the
    /// last two bytes of the name record, which the reference writes as 00 00
    /// (legacy/cards.py:607-608).
    pub fn erased_record(&self) -> Vec<u8> {
        if self.rec_len == 0 {
            return Vec::new();
        }
        let mut record = vec![0xFF; self.rec_len];
        if self.first_record == 2 && self.rec_len >= 2 {
            let last = record.len();
            record[last - 2] = 0x00;
            record[last - 1] = 0x00;
        }
        record
    }

    /// Whether a re-read of this EF shows the erased image.
    pub fn is_erased(&self, record: &[u8]) -> bool {
        !record.is_empty() && record == self.erased_record()
    }
}

/// SELECT a file by FID: 00 A4 00 02 fid 00 (pySim/commands.py:279).
pub fn select_by_fid(fid: &str) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x00, 0x02];
    apdu.extend_from_slice(&hex_bytes(fid));
    apdu.push(0x00);
    apdu
}

/// UPDATE RECORD, P1 the record number, P2 04, Lc the record length
/// (pySim/commands.py:462).
pub fn update_record(record: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xDC, record, 0x04, data.len() as u8];
    apdu.extend_from_slice(data);
    apdu
}

/// READ RECORD, P1 the record number: the post-write re-read.
pub fn read_record(record: u8) -> Vec<u8> {
    vec![0x00, 0xB2, record, 0x04, 0x00]
}

/// One thing the erase sends, and what it erases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The APDU bytes as sent.
    pub apdu: Vec<u8>,
    /// What this step erases, in one line: the path, the record, the instruction.
    pub what: String,
}

impl Step {
    /// The APDU as uppercase hex, the form the dry run prints.
    pub fn apdu_hex(&self) -> String {
        self.apdu.iter().map(|b| format!("{b:02X}")).collect()
    }
}

/// The whole erase as an ordered plan: every APDU, with nothing sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasePlan {
    /// The card class this plan targets.
    pub class: CardClass,
    /// The EFs, in the order the reference erases them.
    pub files: Vec<ProvisioningEf>,
    /// How many record slots per EF are erased.
    pub records: u8,
    /// The ordered steps.
    pub steps: Vec<Step>,
}

/// The default number of record slots: the one pySim always writes, and the
/// minimum a card can hold (rec_cnt below 1 raises, legacy/cards.py:545).
pub const DEFAULT_RECORDS: u8 = 1;

/// Builds the plan for class, erasing records record slots of each EF.
///
/// The order is the order of the reference, not a convenient one: the outer loop
/// is the record index n and the inner loop is the file table, "for n in range
/// (0, count): for k, (msg, ofs) in df.items():" (legacy/cards.py:615-617). The
/// first write after the first SELECT is therefore record 2 of EF 8f0c, and MF
/// is re-selected before every single file.
pub fn plan(class: CardClass, records: u8) -> ErasePlan {
    let files = class.files();
    let mut steps = Vec::new();
    for n in 0..records {
        for file in &files {
            let record = n.saturating_add(file.first_record);
            let data = file.erased_record();
            for fid in [Some("3f00"), class.parent(), Some(file.fid)]
                .into_iter()
                .flatten()
            {
                steps.push(Step {
                    apdu: select_by_fid(fid),
                    what: format!("select {fid} on the way to {}", file.path(class)),
                });
            }
            steps.push(Step {
                apdu: update_record(record, &data),
                what: format!(
                    "UPDATE RECORD {} record {record} in {}, {} bytes of 0xFF: this instruction overwrites the record and deletes nothing",
                    file.fid,
                    file.path(class),
                    data.len()
                ),
            });
        }
    }
    ErasePlan {
        class,
        files,
        records,
        steps,
    }
}

/// Whether the card accepted the command: a status word of 90 00.
pub fn accepted(response: &[u8]) -> bool {
    response.len() >= 2 && response[response.len() - 2..] == [0x90, 0x00]
}

/// Why a run stopped, and what it stopped after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The index of the first step that was not sent, or that was refused.
    pub stopped_at: usize,
    /// The APDU that stopped the run.
    pub apdu: String,
    /// The response of the card to it, or why it could not be sent.
    pub response: String,
    /// How many written records were re-read and confirmed.
    pub confirmed: usize,
    /// Whether the run stopped because it was interrupted.
    pub interrupted: bool,
}

/// A card to send the plan over. Implemented for every CardSession, and for the
/// scripted double the tests drive, so the plan and the run are both pure byte
/// vectors until something is really sent.
pub trait Exchange {
    /// Sends one APDU and returns the response verbatim. Implementations must
    /// not retry: a repeated write is a second write to a card mid-erase.
    fn send(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String>;
}

impl<T: CardSession + ?Sized> Exchange for T {
    fn send(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        CardSession::transmit(self, apdu).map_err(|err| err.to_string())
    }
}

/// Runs plan against card: every step once, in order, stopping at the first
/// refusal, transport error or interrupt. Nothing is retried and nothing is
/// sent after a failure, because the card is then half erased and a second
/// attempt would only add to it.
///
/// After a write is accepted the record is re-read (READ RECORD) and compared
/// with the image that was written, so a card that acknowledged a write it did
/// not perform is reported rather than counted as erased.
pub fn erase<E: Exchange + ?Sized>(
    card: &mut E,
    plan: &ErasePlan,
    interrupted: &mut dyn FnMut() -> bool,
) -> Applied {
    let mut applied = Applied {
        stopped_at: plan.steps.len(),
        apdu: String::new(),
        response: String::new(),
        confirmed: 0,
        interrupted: false,
    };
    let mut index = 0;
    while index < plan.steps.len() {
        if interrupted() {
            applied.stopped_at = index;
            applied.apdu = plan.steps[index].apdu_hex();
            applied.interrupted = true;
            applied.response = "interrupted before this step: nothing after it was sent, and the card is left with some records erased and some not (undefined state)".to_owned();
            return applied;
        }
        let step = &plan.steps[index];
        match card.send(&step.apdu) {
            Ok(response) if accepted(&response) => {}
            Ok(response) => {
                let end = response.len();
                applied.stopped_at = index;
                applied.apdu = step.apdu_hex();
                applied.response = format!(
                    "refused {} (SW {:02X}{:02X}); it was sent once and not retried, and nothing after it was sent",
                    step.what, response[end - 2], response[end - 1]
                );
                return applied;
            }
            Err(message) => {
                applied.stopped_at = index;
                applied.apdu = step.apdu_hex();
                applied.response = format!(
                    "transport error on {}: {message}; it was not retried",
                    step.what
                );
                return applied;
            }
        }
        if step.apdu[1] == 0xDC {
            let record = step.apdu[2];
            let file = plan
                .files
                .iter()
                .find(|f| step.what.starts_with(&format!("UPDATE RECORD {}", f.fid)))
                .copied();
            if let Some(file) = file {
                match card.send(&read_record(record)) {
                    Ok(response)
                        if response.len() > 2
                            && accepted(&response)
                            && file.is_erased(&response[..response.len() - 2]) =>
                    {
                        applied.confirmed += 1;
                    }
                    Ok(_) => {
                        applied.stopped_at = index;
                        applied.apdu = step.apdu_hex();
                        applied.response = format!(
                            "the write to {} was acknowledged but the re-read (READ RECORD {record}) does not show the erased image; the card is in an undefined state and nothing after it was sent",
                            file.path(plan.class)
                        );
                        return applied;
                    }
                    Err(message) => {
                        applied.stopped_at = index;
                        applied.apdu = step.apdu_hex();
                        applied.response = format!(
                            "the write to {} was acknowledged but the re-read failed: {message}; nothing after it was sent",
                            file.path(plan.class)
                        );
                        return applied;
                    }
                }
            }
        }
        index += 1;
    }
    applied
}

/// The order the dry run prints and the operator has to agree to, as text.
pub fn dry_run_text(plan: &ErasePlan) -> String {
    let mut text = format!("Erase before programming: dry run, nothing was sent.\n{WARNING}\n");
    for file in &plan.files {
        let first = file.first_record;
        let last = plan
            .records
            .saturating_add(file.first_record)
            .saturating_sub(1);
        text.push_str(&format!(
            "  would erase {} record(s) {}..{} of {} with UPDATE RECORD (INS DC), {} bytes each\n",
            plan.records,
            first,
            last,
            file.path(plan.class),
            file.rec_len
        ));
    }
    text.push_str(&format!(
        "  {} step(s) in this order (SELECT by FID is 00 A4 00 02 fid 00, UPDATE RECORD is 00 DC record 04 len data)\n",
        plan.steps.len()
    ));
    for (index, step) in plan.steps.iter().enumerate() {
        text.push_str(&format!(
            "  {index:>2} {}  {}\n",
            step.apdu_hex(),
            step.what
        ));
    }
    text.push('\n');
    text
}

/// What the acknowledgements of the operator add up to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// --yes: send, instead of printing the plan.
    pub yes: bool,
    /// --confirm-iccid: the ICCID of the card to erase. The second
    /// acknowledgement, in the shape euicc reset uses with --confirm-eid.
    pub confirm_iccid: Option<String>,
    /// --dry-run: asked for explicitly, so a --yes beside it is ambiguous.
    pub dry_run: bool,
}

/// What the command line asked for, once validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Print the plan, send nothing.
    DryRun(ErasePlan),
    /// Send it, having been acknowledged twice.
    Apply {
        /// The plan to send.
        plan: ErasePlan,
        /// The ICCID the operator confirmed, matched against EF.ICCID of the card.
        confirm_iccid: String,
    },
}

/// Validates the command line before a reader is even listed.
///
/// Dry run unless --yes; --yes needs --confirm-iccid; --confirm-iccid without
/// --yes, and --yes beside --dry-run, are both refused, because each of them
/// says two things at once about whether anything is sent.
pub fn validate(
    class: CardClass,
    records: u8,
    options: &Options,
) -> Result<Request, (String, String)> {
    let plan = plan(class, records);
    if options.dry_run && options.yes {
        return Err((
            "ambiguous-erase".to_owned(),
            "--yes and --dry-run cannot be combined: the first asks for the erase to be sent and the second asks for it not to be. Pick one.".to_owned(),
        ));
    }
    match (&options.confirm_iccid, options.yes) {
        (Some(_), false) => Err((
            "ambiguous-erase".to_owned(),
            "--confirm-iccid without --yes asks for nothing to be sent: drop it, or add --yes to erase this card.".to_owned(),
        )),
        (None, true) => Err((
            "confirm-required".to_owned(),
            "erasing a card before programming needs both --yes and --confirm-iccid ICCID, the ICCID of the card from card info. The operation is permanent and an interrupted one leaves the card undefined.".to_owned(),
        )),
        (Some(iccid), true) => {
            if iccid.len() < 6 || !iccid.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err((
                    "bad-iccid".to_owned(),
                    format!("--confirm-iccid must be the ICCID of the card in hex (at least 6 hex digits, read from card info), got {iccid:?}"),
                ));
            }
            Ok(Request::Apply { plan, confirm_iccid: iccid.clone() })
        }
        (None, false) => Ok(Request::DryRun(plan)),
    }
}

/// The ICCID as a re-read sees it: EF.ICCID with the nibbles swapped, which is
/// the encoding the card stores it in.
pub fn decode_iccid(swapped: &[u8]) -> String {
    swapped
        .iter()
        .rev()
        .map(|b| format!("{:X}{:X}", b & 0x0F, b >> 4))
        .collect()
}

/// The dry-run report: what would be erased, by which instruction, in which
/// order, and that nothing was sent.
pub fn dry_run_json(plan: &ErasePlan) -> serde_json::Value {
    serde_json::json!({
        "card_touched": false,
        "class": plan.class.id(),
        "records": plan.records,
        "files": plan.files.iter().map(|f| serde_json::json!({
            "path": f.path(plan.class),
            "instruction": "UPDATE RECORD",
            "ins": "DC",
            "first_record": f.first_record,
            "last_record": plan.records.saturating_add(f.first_record).saturating_sub(1),
            "record_len": f.rec_len,
        })).collect::<Vec<_>>(),
        "steps": plan.steps.iter().map(|s| serde_json::json!({
            "apdu": s.apdu_hex(),
            "what": s.what,
        })).collect::<Vec<_>>(),
        "warning": WARNING,
    })
}

/// The outcome of a sent erase, as JSON.
pub fn applied_json(plan: &ErasePlan, applied: &Applied, iccid: &str) -> serde_json::Value {
    let writes = plan.records as usize * plan.files.len();
    serde_json::json!({
        "card_touched": true,
        "class": plan.class.id(),
        "iccid": iccid,
        "confirmed": applied.confirmed,
        "steps_sent": applied.stopped_at,
        "complete": applied.stopped_at == plan.steps.len() && applied.confirmed == writes,
        "error": if applied.stopped_at == plan.steps.len() {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "apdu": applied.apdu,
                "message": applied.response,
                "interrupted": applied.interrupted,
            })
        },
        "warning": WARNING,
    })
}

/// The outcome of a sent erase, as text.
pub fn applied_human(plan: &ErasePlan, applied: &Applied, iccid: &str) -> String {
    let mut text = String::new();
    if applied.stopped_at == plan.steps.len() {
        text.push_str(&format!(
            "erased {} record(s) of {} EF(s) on card {iccid}; {} re-read(s) confirmed the 0xFF image",
            plan.records, plan.files.len(), applied.confirmed
        ));
    } else {
        text.push_str(&format!(
            "erase STOPPED after {} of {} step(s) on card {iccid}; {} record(s) were re-read and confirmed, stopped at {}, {}",
            applied.stopped_at, plan.steps.len(), applied.confirmed, applied.apdu, applied.response
        ));
        text.push_str(WARNING);
    }
    text.push('\n');
    text
}

fn hex_bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .filter_map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|t| u8::from_str_radix(t, 16).ok())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    fn ff(count: usize) -> String {
        "FF".repeat(count)
    }

    /// Strips the spaces a byte-vector is written with for readability, without
    /// depending on a character literal.
    fn tight(text: &str) -> String {
        text.split_whitespace().collect::<String>()
    }

    /// A scripted card: it counts what it was sent and answers from a script,
    /// so a test can prove the dry run sends nothing and that a stopped erase
    /// sends nothing after the refusal.
    struct Scripted {
        seen: Vec<String>,
        refuse_at: Option<usize>,
        readback: Option<Vec<u8>>,
        last_write: Option<Vec<u8>>,
    }

    impl Scripted {
        fn new() -> Self {
            Self {
                seen: Vec::new(),
                refuse_at: None,
                readback: None,
                last_write: None,
            }
        }

        fn refusing_at(mut self, index: usize) -> Self {
            self.refuse_at = Some(index);
            self
        }

        fn not_erased(mut self) -> Self {
            self.readback = Some(vec![0x11; 130]);
            self
        }
    }

    impl Exchange for Scripted {
        fn send(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
            let index = self.seen.len();
            self.seen.push(hex(apdu));
            if self.refuse_at == Some(index) {
                return Ok(vec![0x69, 0x82]);
            }
            let mut response = if apdu[1] == 0xB2 {
                match &self.readback {
                    Some(data) => data.clone(),
                    None => self.last_write.clone().unwrap_or_default(),
                }
            } else {
                self.last_write = Some(apdu[5..].to_vec());
                Vec::new()
            };
            response.extend_from_slice(&[0x90, 0x00]);
            Ok(response)
        }
    }

    /// The exact APDUs of the reference and their order for MagicSim, one record
    /// slot: SELECT MF, SELECT 7f4d, SELECT 8f0c, UPDATE RECORD 2 with 16 bytes
    /// of 0xFF then 00 00, then the same path for 8f0d and 8f0e at record 1.
    /// Bytes from pySim/commands.py:279 and :462, order from
    /// legacy/cards.py:615-617.
    #[test]
    fn magicsim_erase_is_the_reference_apdu_sequence_in_order() {
        let apdus: Vec<String> = plan(CardClass::MagicSim, 1)
            .steps
            .iter()
            .map(|s| s.apdu_hex())
            .collect();
        assert_eq!(
            apdus,
            [
                "00A400023F0000".to_owned(),
                "00A400027F4D00".to_owned(),
                "00A400028F0C00".to_owned(),
                format!("00DC0204 12 {}", ff(16) + "0000"),
                "00A400023F0000".to_owned(),
                "00A400027F4D00".to_owned(),
                "00A400028F0D00".to_owned(),
                format!("00DC0104 82 {}", ff(130)),
                "00A400023F0000".to_owned(),
                "00A400027F4D00".to_owned(),
                "00A400028F0E00".to_owned(),
                format!("00DC0104 66 {}", ff(102)),
            ]
            .iter()
            .map(|s| tight(s))
            .collect::<Vec<String>>()
        );
    }

    /// Two record slots: the outer loop of the reference is the record index, so
    /// record 2 of 8f0c is written, then record 1 of 8f0d and 8f0e, and only
    /// then record 3 of 8f0c, not file by file.
    #[test]
    fn the_record_index_is_the_outer_loop() {
        let writes: Vec<String> = plan(CardClass::MagicSim, 2)
            .steps
            .iter()
            .filter(|s| s.apdu[1] == 0xDC)
            .map(|s| s.apdu_hex())
            .collect();
        assert_eq!(writes.len(), 6);
        assert!(writes[0].starts_with("00DC0204"), "{}", writes[0]);
        assert!(writes[1].starts_with("00DC0104"), "{}", writes[1]);
        assert!(writes[2].starts_with("00DC0104"), "{}", writes[2]);
        assert!(writes[3].starts_with("00DC0304"), "{}", writes[3]);
        assert!(writes[4].starts_with("00DC0204"), "{}", writes[4]);
        assert!(writes[5].starts_with("00DC0204"), "{}", writes[5]);
    }

    /// SuperSim uses the same path and order with its own record lengths.
    #[test]
    fn supersim_uses_its_own_record_lengths() {
        let files = CardClass::SuperSim.files();
        assert_eq!(
            (files[0].rec_len, files[1].rec_len, files[2].rec_len),
            (18, 74, 50)
        );
        let apdus: Vec<String> = plan(CardClass::SuperSim, 1)
            .steps
            .iter()
            .filter(|s| s.apdu[1] == 0xDC)
            .map(|s| s.apdu_hex())
            .collect();
        assert_eq!(apdus[0], tight(&format!("00DC0204 12 {}", ff(16) + "0000")));
        assert_eq!(apdus[1], tight(&format!("00DC0104 4A {}", ff(74))));
        assert_eq!(apdus[2], tight(&format!("00DC0104 32 {}", ff(50))));
    }

    /// FakeMagicSim has no 7f4d: its single EF is 3f00/000c, records from 1.
    #[test]
    fn fakemagicsim_selects_000c_under_mf_only() {
        let p = plan(CardClass::FakeMagicSim, 1);
        let selects: Vec<String> = p
            .steps
            .iter()
            .filter(|s| s.apdu[1] == 0xA4)
            .map(|s| s.apdu_hex())
            .collect();
        assert_eq!(
            selects,
            vec!["00A400023F0000".to_owned(), "00A40002000C00".to_owned()]
        );
        assert_eq!(p.files[0].path(CardClass::FakeMagicSim), "3f00/000c");
        assert_eq!(p.files[0].first_record, 1);
    }

    /// The erase is never a GlobalPlatform DELETE and never names a deletion.
    #[test]
    fn the_erase_is_never_a_delete() {
        for (class, _) in CardClass::all() {
            for step in plan(*class, 1).steps {
                assert_ne!(step.apdu[1], 0xE0, "a GP DELETE slipped into the plan");
                assert_ne!(step.apdu[1], 0xE2, "a GP DELETE slipped into the plan");
                if step.apdu[1] == 0xDC {
                    assert!(
                        step.what.contains("deletes nothing"),
                        "a step that claims to delete: {}",
                        step.what
                    );
                }
            }
        }
    }

    /// The dry run sends nothing, names what it would erase and by which
    /// instruction, and carries the WARNING.
    #[test]
    fn the_dry_run_sends_nothing_and_says_what_it_would_erase() {
        let card = Scripted::new();
        let p = plan(CardClass::MagicSim, 1);
        let text = dry_run_text(&p);
        assert!(card.seen.is_empty(), "the dry run opened a session");
        assert!(text.contains("dry run, nothing was sent"));
        assert!(text.contains("3f00/7f4d/8f0c"), "{text}");
        assert!(text.contains("record(s) 2..2"));
        assert!(text.contains("UPDATE RECORD (INS DC)"));
        assert!(text.contains(&tight(&format!("00DC0204 12 {}", ff(16)))));
        assert!(text.contains(WARNING));
        let report = dry_run_json(&p);
        assert_eq!(report["card_touched"], false);
        assert_eq!(report["files"].as_array().map(Vec::len), Some(3));
        assert_eq!(report["files"][0]["instruction"], "UPDATE RECORD");
        assert_eq!(report["files"][0]["ins"], "DC");
    }

    /// --yes alone is refused: the second acknowledgement is required, the shape
    /// euicc reset uses with --confirm-eid.
    #[test]
    fn yes_without_the_second_acknowledgement_is_refused() {
        let options = Options {
            yes: true,
            ..Options::default()
        };
        let (kind, message) = validate(CardClass::MagicSim, 1, &options).unwrap_err();
        assert_eq!(kind, "confirm-required");
        assert!(message.contains("--confirm-iccid"));
    }

    /// The second acknowledgement is the ICCID of the card, not any string.
    #[test]
    fn the_second_acknowledgement_must_be_a_hex_iccid() {
        let options = Options {
            yes: true,
            confirm_iccid: Some("not-an-iccid".to_owned()),
            dry_run: false,
        };
        assert_eq!(
            validate(CardClass::MagicSim, 1, &options).unwrap_err().0,
            "bad-iccid"
        );
    }

    /// Both acknowledgements given: the plan is to be sent, and the ICCID is
    /// what the card is checked against.
    #[test]
    fn both_acknowledgements_send_the_plan() {
        let options = Options {
            yes: true,
            confirm_iccid: Some("8944500000000000000".to_owned()),
            ..Options::default()
        };
        match validate(CardClass::MagicSim, 1, &options).unwrap() {
            Request::Apply {
                plan,
                confirm_iccid,
            } => {
                assert_eq!(confirm_iccid, "8944500000000000000");
                assert!(!plan.steps.is_empty());
            }
            other => panic!("expected an apply, got {other:?}"),
        }
    }

    /// Without --yes it is a dry run.
    #[test]
    fn no_yes_is_a_dry_run() {
        match validate(CardClass::MagicSim, 1, &Options::default()).unwrap() {
            Request::DryRun(plan) => assert!(!plan.steps.is_empty()),
            other => panic!("expected a dry run, got {other:?}"),
        }
    }

    /// Combinations that make the meaning of the flag ambiguous are refused
    /// rather than guessed.
    #[test]
    fn the_flag_cannot_be_combined_with_anything_ambiguous() {
        let yes_and_dry = Options {
            yes: true,
            dry_run: true,
            ..Options::default()
        };
        assert_eq!(
            validate(CardClass::MagicSim, 1, &yes_and_dry)
                .unwrap_err()
                .0,
            "ambiguous-erase"
        );
        let confirm_without_yes = Options {
            confirm_iccid: Some("8944500000000000000".to_owned()),
            ..Options::default()
        };
        assert_eq!(
            validate(CardClass::MagicSim, 1, &confirm_without_yes)
                .unwrap_err()
                .0,
            "ambiguous-erase"
        );
        let all_three = Options {
            yes: true,
            dry_run: true,
            confirm_iccid: Some("8944500000000000000".to_owned()),
        };
        assert_eq!(
            validate(CardClass::MagicSim, 1, &all_three).unwrap_err().0,
            "ambiguous-erase"
        );
    }

    /// A refused step stops the erase at once: sent once, nothing after it sent,
    /// never retried.
    #[test]
    fn a_refused_step_stops_the_erase_and_is_never_retried() {
        let p = plan(CardClass::MagicSim, 1);
        let write = p.steps.iter().position(|s| s.apdu[1] == 0xDC).unwrap();
        let mut card = Scripted::new().refusing_at(write);
        let applied = erase(&mut card, &p, &mut || false);
        assert_eq!(applied.stopped_at, write);
        assert_eq!(
            card.seen.len(),
            write + 1,
            "something was sent after the refusal"
        );
        assert_eq!(
            card.seen.iter().filter(|s| *s == &card.seen[write]).count(),
            1
        );
        assert!(applied.response.contains("not retried"));
        assert_eq!(
            applied_json(&p, &applied, "8944500000000000000")["complete"],
            false
        );
        assert!(applied_human(&p, &applied, "8944500000000000000").contains("erase STOPPED"));
    }

    /// An interrupted erase stops at the step it was interrupted before and says
    /// the card is left undefined.
    #[test]
    fn an_interrupted_erase_is_reported_and_never_resumes() {
        let p = plan(CardClass::MagicSim, 1);
        let mut card = Scripted::new();
        let mut calls = 0;
        let applied = erase(&mut card, &p, &mut || {
            calls += 1;
            calls == 4
        });
        assert_eq!(applied.stopped_at, 3);
        assert!(applied.interrupted);
        assert!(applied.response.contains("undefined state"));
        assert_eq!(card.seen.len(), 3, "the interrupted step was sent anyway");
    }

    /// A write the card acknowledged but did not perform is reported: the
    /// post-write re-read decides, not the status word.
    #[test]
    fn a_write_the_card_did_not_perform_is_reported_by_the_re_read() {
        let p = plan(CardClass::MagicSim, 1);
        let mut card = Scripted::new().not_erased();
        let applied = erase(&mut card, &p, &mut || false);
        assert!(applied.stopped_at > 0);
        assert_eq!(applied.confirmed, 0);
        assert!(applied.response.contains("re-read"));
    }

    /// Every accepted write is re-read and the erased image confirmed.
    #[test]
    fn every_written_record_is_re_read_and_confirmed() {
        let p = plan(CardClass::MagicSim, 1);
        let mut card = Scripted::new();
        let applied = erase(&mut card, &p, &mut || false);
        assert_eq!(applied.stopped_at, p.steps.len());
        assert_eq!(applied.confirmed, 3);
        assert_eq!(
            card.seen.iter().filter(|s| s.starts_with("00B2")).count(),
            3
        );
        assert_eq!(
            applied_json(&p, &applied, "8944500000000000000")["complete"],
            true
        );
    }

    /// The WARNING says the two things the brief requires: permanent, and an
    /// interrupted erase leaves the card undefined.
    #[test]
    fn the_warning_says_permanent_and_undefined() {
        assert!(WARNING.contains("PERMANENT"));
        assert!(WARNING.contains("no undo"));
        assert!(WARNING.contains("undefined state"));
    }

    /// The erased image is 0xFF, except the last two bytes of the name record,
    /// which the reference writes as 00 00.
    #[test]
    fn the_erased_image_is_ff_and_the_name_record_ends_in_00() {
        let files = CardClass::MagicSim.files();
        assert_eq!(
            files[0].erased_record(),
            [vec![0xFF; 16], vec![0x00, 0x00]].concat()
        );
        assert_eq!(files[1].erased_record(), vec![0xFF; 130]);
        assert!(files[1].is_erased(&[0xFF; 130]));
        assert!(!files[1].is_erased(&[0xFE; 130]));
    }

    /// The ICCID the re-read confirms against: EF.ICCID with the nibbles swapped.
    #[test]
    fn the_iccid_is_the_swapped_reading_of_ef_iccid() {
        assert_eq!(decode_iccid(&[0x98, 0x10, 0x32, 0x54, 0x76]), "6745230189");
    }
}

// ---------------------------------------------------------------------------
// The live half: an SCP03 channel, EF.ICCID, and the plan actually sent.
// ---------------------------------------------------------------------------

/// EF.ICCID, read to check that this is the card the operator named.
const ICCID_FID: &str = "2f00";

/// READ BINARY of the first ten octets of EF.ICCID (ETSI TS 102 221 clause
/// 13.2), the length `ef::decode_iccid` insists on.
const READ_ICCID: [u8; 5] = [0x00, 0xB0, 0x00, 0x00, 0x0A];

/// The octets a C-MAC channel adds to a response: the MAC, between the data and
/// the status word (GlobalPlatform Card Specification Amendment D (SCP03)
/// v1.2, 6.2.3).
const C_MAC_OCTETS: usize = 4;

/// Why an authenticated erase never reached the provisioning EFs.
pub struct AuthStop {
    /// The kind, named as `gp` names its own authentication refusals
    /// (`initialize-update-refused`, `keys-do-not-match`, ...).
    pub kind: &'static str,
    /// What the card answered, or why the run stopped. Never a key or a
    /// cryptogram.
    pub message: String,
}

/// A sent erase, and the card it was sent to.
pub struct Ran {
    /// What ran, and where it stopped.
    pub applied: Applied,
    /// EF.ICCID of the card as a re-read sees it. The run refuses to start
    /// unless this equals what the operator confirmed, so the two agreeing is
    /// the whole point of reading it.
    pub iccid: String,
}

/// An [`Applied`] that sent nothing: what a refusal before the first write looks
/// like to the reporting code, which already knows how to say "stopped at step
/// 0" and already carries the [`WARNING`] for a run that stopped.
fn refused_before_the_first_write(message: String) -> Applied {
    Applied {
        stopped_at: 0,
        apdu: "none".to_owned(),
        response: message,
        confirmed: 0,
        interrupted: false,
    }
}

/// Runs plan on a card over an SCP03 secure channel: pySim's `-e/--erase`, with
/// the credentials to reach the provisioning records.
///
/// The order is deliberate and it is the order of the write shape the crate
/// uses everywhere else: authenticate ONCE, then read what the operator claimed
/// and check it, then send. Nothing reaches a provisioning EF before EF.ICCID
/// has been read and matched against `--confirm-iccid`, so an operator who named
/// the wrong card has not half-erased the right one.
///
/// # Errors
///
/// [`AuthStop`] when the ONE authentication attempt ([`gp::authenticate`], reused
/// rather than reimplemented: two authentication paths are two sets of keys to
/// get wrong) did not produce a channel. A refusal there has sent nothing to any
/// provisioning EF.
pub fn erase_authenticated<S: CardSession + ?Sized>(
    session: &mut S,
    plan: &ErasePlan,
    auth: &gp::Auth<'_>,
    confirm_iccid: &str,
    interrupted: &mut dyn FnMut() -> bool,
) -> Result<Ran, AuthStop> {
    let mut authentication = Vec::new();
    let established = match gp::authenticate(session, &mut authentication, auth) {
        Ok(Ok(established)) => established,
        Ok(Err(stop)) => {
            return Err(AuthStop {
                kind: stop.kind,
                message: stop.message,
            })
        }
        Err(err) => {
            return Err(AuthStop {
                kind: "erase-exchange-failed",
                message: err.to_string(),
            })
        }
    };
    let mut card = Secured {
        session,
        channel: established.channel,
    };
    let iccid = match read_iccid(&mut card) {
        Ok(iccid) => iccid,
        Err(message) => {
            return Ok(Ran {
                applied: refused_before_the_first_write(message),
                iccid: confirm_iccid.to_owned(),
            })
        }
    };
    if !iccid.eq_ignore_ascii_case(confirm_iccid) {
        return Ok(Ran {
            applied: refused_before_the_first_write(format!(
                "--confirm-iccid names {confirm_iccid} and this card is {iccid}; the provisioning \
                 records were not touched"
            )),
            iccid,
        });
    }
    Ok(Ran {
        applied: erase(&mut card, plan, interrupted),
        iccid,
    })
}

/// EF.ICCID as the operator names it on the command line: ten octets, swapped
/// nibbles, trailing padding dropped (the same decode `card` uses, so the value
/// can be copied out of a report rather than re-derived).
fn read_iccid<E: Exchange + ?Sized>(card: &mut E) -> Result<String, String> {
    let selected = card.send(&select_by_fid(ICCID_FID))?;
    if !accepted(&selected) {
        return Err(format!(
            "SELECT EF.ICCID ({ICCID_FID}) was refused with {}; nothing was erased",
            status_word(&selected)
        ));
    }
    let response = card.send(&READ_ICCID)?;
    if !accepted(&response) {
        return Err(format!(
            "READ BINARY of EF.ICCID was refused with {}; nothing was erased",
            status_word(&response)
        ));
    }
    let end = response.len();
    ef::decode_iccid(&response[..end - 2])
        .map(|digits| digits.as_str().to_owned())
        .map_err(|err| format!("EF.ICCID did not decode: {err}; nothing was erased"))
}

/// The status word of a response, as `6a 82`.
fn status_word(response: &[u8]) -> String {
    let end = response.len();
    if end < 2 {
        return "no status word".to_owned();
    }
    format!("{:02x} {:02x}", response[end - 2], response[end - 1])
}

/// A card to send over an established secure channel.
///
/// The plan is bytes and an SCP03 command is a header, a data field and an Le,
/// so [`parts_of`] splits the first into those three and refuses an instruction
/// it does not recognise rather than guessing a shape. The chaining value is the
/// channel's, which is why this borrows the session and the channel separately:
/// the card is mid-sequence and a retry is not available.
struct Secured<'a, S: CardSession + ?Sized> {
    /// The session to transmit on.
    session: &'a mut S,
    /// The established SCP03 channel: one per run, never re-established.
    channel: scp03::Channel,
}

impl<S: CardSession + ?Sized> Exchange for Secured<'_, S> {
    fn send(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let (header, data, le) = parts_of(apdu)?;
        let secured = self
            .channel
            .wrap_bytes(header, data, le)
            .map_err(|e| e.to_string())?;
        // ONE exchange per step, which is the rule this crate follows for a card
        // mid-sequence: no retry, and no second command either. A card that
        // chains a long read with 61 xx is therefore reported as a refusal here
        // rather than followed - the run stops there, having re-read nothing and
        // written nothing after it, which is the safe way round.
        let response = self.session.transmit(&secured).map_err(|e| e.to_string())?;
        // Every response of a C-MAC channel carries the MAC the card computed
        // over the rest of the response, after the data and before the status
        // word. So the status word the run judges a step by is the last two
        // octets and the record image it re-reads is what came before the MAC.
        //
        // The MAC is not recomputed here: what is verified is the card
        // cryptogram at authentication, exactly as `gp` verifies it, and then
        // every write is re-read against the image the plan asked for.
        // Re-computing the response MAC would need the chaining state this crate
        // has never exposed for `gp` either.
        let (body, sw) = unmac(&response).ok_or_else(|| {
            format!(
                "the card answered {} on a secured channel, which is not a MAC'd response",
                hex_of(&response)
            )
        })?;
        let mut assembled = body.to_vec();
        assembled.extend_from_slice(&sw);
        Ok(assembled)
    }
}

/// A response off a C-MAC channel, split into its data and its status word, by
/// taking the four MAC octets off the front of the status word.
fn unmac(response: &[u8]) -> Option<(&[u8], [u8; 2])> {
    let data_end = response.len().checked_sub(2 + C_MAC_OCTETS)?;
    let end = response.len();
    Some((
        &response[..data_end],
        [response[end - 2], response[end - 1]],
    ))
}

/// The three parts of one plan APDU: its header, its data field and its short
/// Le, told apart by the instruction rather than guessed from the length.
///
/// The plan is byte vectors so that the dry run and the run cannot disagree
/// about what is sent, and every APDU in it is one of three instructions with
/// one shape each, all three from the reference:
///
///   - SELECT by FID, `00 A4 00 02 <FID> 00` (pySim/commands.py:284): case 4
///     with NO Lc octet. The file identifier sits where a data field would be and
///     the trailing `00` is the Le.
///   - UPDATE RECORD, `00 DC <record> 04 <len> <image>` (:462): case 3. Lc
///     counts the record image and there is no Le.
///   - READ RECORD, `00 B2 <record> 04 <le>` (:190): case 2. No data, the Le is
///     the last octet.
///
/// The length cannot decide this: the erased name record ends in `00 00`, so a
/// trailing `00` is data in one of these and an Le in the others. An instruction
/// this module does not produce is refused rather than guessed at.
fn parts_of(apdu: &[u8]) -> Result<(apdu::Header, &[u8], Option<u8>), String> {
    if apdu.len() < 5 {
        return Err(format!(
            "{} is not an APDU this plan produces: it has no header and a length field",
            hex_of(apdu)
        ));
    }
    let header = apdu::Header::new(apdu[0], apdu[1], apdu[2], apdu[3]);
    match apdu[1] {
        0xA4 => Ok((header, &apdu[4..apdu.len() - 1], Some(apdu[apdu.len() - 1]))),
        // The Lc octet counts the image and is not part of the MAC input, so it
        // comes off here. Leaving it on would be a command the card could not
        // verify, and the mismatch would only show up as a silent bad MAC.
        0xDC => {
            let data = apdu.get(5..).unwrap_or_default();
            if usize::from(apdu[4]) != data.len() {
                return Err(format!(
                    "{} declares {} data octets and carries {}",
                    hex_of(apdu),
                    apdu[4],
                    data.len()
                ));
            }
            Ok((header, data, None))
        }
        0xB2 => Ok((header, &[], Some(apdu[4]))),
        other => Err(format!(
            "INS {other:02X} is not one of this plan's three instructions"
        )),
    }
}

/// Bytes as the uppercase hex the reports use.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod authenticated {
    use super::*;

    /// A card that answers with a fixed script and records nothing else, so the
    /// reads around a write can be asserted on their own.
    struct Scripted {
        answers: Vec<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Scripted {
        fn new(answers: Vec<Vec<u8>>) -> Self {
            Self {
                answers,
                sent: Vec::new(),
            }
        }
    }

    impl Exchange for Scripted {
        fn send(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
            self.sent.push(apdu.to_vec());
            if self.answers.is_empty() {
                return Err("the script ran out of answers".to_owned());
            }
            Ok(self.answers.remove(0))
        }
    }

    fn ok(data: &[u8]) -> Vec<u8> {
        let mut response = data.to_vec();
        response.extend_from_slice(&[0x90, 0x00]);
        response
    }

    /// The ten octets EF.ICCID of 89 14 11 22 33 44 55 66 77 88, stored swapped.
    const ICCID: [u8; 10] = [0x98, 0x41, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    #[test]
    fn every_plan_apdu_splits_into_the_three_parts_it_is_made_of() {
        for (class, _) in CardClass::all() {
            for step in plan(*class, 3).steps {
                let (header, data, le) = parts_of(&step.apdu)
                    .unwrap_or_else(|e| panic!("{} step {}: {e}", class.id(), step.apdu_hex()));
                // Every octet of the plan APDU is accounted for by exactly one
                // part, which is the whole reason the split is by instruction
                // rather than by a length heuristic: nothing is dropped (the Lc
                // octet is checked against the image it counts) and nothing is
                // inserted.
                assert_eq!(
                    &header.to_bytes()[..],
                    &step.apdu[..4],
                    "{} {}",
                    class.id(),
                    step.apdu_hex()
                );
                match step.apdu[1] {
                    0xA4 => {
                        assert_eq!(data, &step.apdu[4..step.apdu.len() - 1]);
                        assert_eq!(le, Some(step.apdu[step.apdu.len() - 1]));
                    }
                    0xDC => {
                        assert_eq!(usize::from(step.apdu[4]), data.len());
                        assert_eq!(data, &step.apdu[5..]);
                        assert_eq!(le, None);
                    }
                    other => panic!("INS {other:02X} is not a plan instruction"),
                }
            }
        }
    }

    #[test]
    fn bytes_that_are_not_one_of_three_instructions_are_refused() {
        for bytes in [
            &[][..],
            &[0x00][..],
            &[0x00, 0xA4, 0x00][..],
            // A GlobalPlatform DELETE is not something this plan ever sends.
            &[0x00, 0xE0, 0x00, 0x00, 0x04, 0xFF][..],
            // An UPDATE RECORD whose Lc does not count the rest of the command.
            &[0x00, 0xDC, 0x02, 0x04, 0x12, 0xFF, 0xFF][..],
            // An UPDATE RECORD with no image at all.
            &[0x00, 0xDC, 0x02, 0x04][..],
        ] {
            assert!(parts_of(bytes).is_err(), "{} was accepted", hex_of(bytes));
        }
    }

    #[test]
    fn a_secured_command_is_the_plain_one_with_the_mac_after_the_data() {
        // Real keys, derived the way a run derives them, so this is a byte test
        // and not a shape test.
        let keys = scp03::derive_session_keys(&[0x11; 16], &[0x22; 16], &[0x33; 8], &[0x44; 8]);
        let mut channel = scp03::Channel::new(&keys);
        let select = select_by_fid("3f00");
        let (header, data, le) = parts_of(&select).expect("a select");
        let secured = channel.wrap_bytes(header, data, le).expect("wraps");
        // The secure messaging bit is set in CLA and the Le stays last.
        assert_eq!(secured[0], 0x04, "{}", hex_of(&secured));
        assert_eq!(&secured[1..4], &[0xA4, 0x00, 0x02], "{}", hex_of(&secured));
        assert_eq!(&secured[4..6], &[0x3F, 0x00], "{}", hex_of(&secured));
        assert_eq!(secured.len(), 4 + 2 + 8 + 1);
        assert_eq!(secured[secured.len() - 1], 0x00);
        // An UPDATE RECORD goes out with no Le: image first, MAC after it.
        let image = vec![0xFF; 18];
        let update = update_record(2, &image);
        let (header, data, le) = parts_of(&update).expect("an update");
        let second = channel.wrap_bytes(header, data, le).expect("wraps");
        assert_eq!(second.len(), 4 + 18 + 8, "{}", hex_of(&second));
        assert_eq!(&second[4..22], &image[..]);
        // The chain advanced, so two commands never carry the same MAC.
        let other = select_by_fid("2f00");
        let (header, data, le) = parts_of(&other).expect("a select");
        let third = channel.wrap_bytes(header, data, le).expect("wraps");
        assert_ne!(second[22..30], third[6..14]);
    }

    #[test]
    fn the_mac_comes_off_every_round_trip_and_the_status_word_stays() {
        let response = [0x01, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x90, 0x00];
        let (data, sw) = unmac(&response).expect("a MAC'd response");
        assert_eq!(data, &[0x01, 0x02, 0xAA, 0xBB]);
        assert_eq!(sw, [0x90, 0x00]);
        // Too short to carry data, MAC and status word.
        assert_eq!(unmac(&[0x90, 0x00]), None);
        assert_eq!(unmac(&[]), None);
    }

    #[test]
    fn the_iccid_is_read_over_the_same_exchange_the_erase_uses() {
        let mut card = Scripted::new(vec![ok(&[0x62, 0x00, 0x09]), ok(&ICCID)]);
        let iccid = read_iccid(&mut card).expect("EF.ICCID reads");
        assert_eq!(iccid, "89141122334455667788");
        assert_eq!(card.sent[0], select_by_fid(ICCID_FID));
        assert_eq!(card.sent[1], READ_ICCID);
    }

    #[test]
    fn a_card_that_will_not_name_its_iccid_is_reported_and_erases_nothing() {
        let mut card = Scripted::new(vec![vec![0x6A, 0x82]]);
        let message = read_iccid(&mut card).expect_err("refused");
        assert!(message.contains("6a 82"), "{message}");
        assert!(message.contains("nothing was erased"), "{message}");
        assert_eq!(
            card.sent.len(),
            1,
            "no read was attempted after the refusal"
        );
    }

    #[test]
    fn a_stopped_run_says_the_card_is_left_undefined() {
        let mut plan = plan(CardClass::MagicSim, 1);
        plan.steps.truncate(3);
        let mut card = Scripted::new(vec![ok(&[]), ok(&[]), vec![0x69, 0x82]]);
        let applied = erase(&mut card, &plan, &mut || false);
        assert_eq!(applied.stopped_at, 2);
        assert!(
            applied.response.contains("not retried"),
            "{}",
            applied.response
        );
        assert_eq!(card.sent.len(), 3, "nothing was sent after the refusal");
    }
}
