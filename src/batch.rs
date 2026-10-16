//! Batch programming: N cards, one state file, one automaton.
//!
//! pySim programs a stack of cards with `--batch`, `--batch-state FILE`,
//! `--card_handler FILE` and `--dry-run` [V pySim-prog.py:169-191]. This module
//! is the parity build of that loop, and it exists to close the two gaps pySim
//! leaves in exactly the places a factory run can hurt somebody:
//!
//! 1. **pySim's state file is not crash-safe.** `save_batch` opens it `"w"`
//!    (truncating) and writes one line of JSON [V pySim-prog.py:700-708], and
//!    `init_batch` reads it back with a bare `json.loads` and no guard
//!    [V pySim-prog.py:687-696]. A process killed between the two leaves an empty
//!    file, which the next run cannot parse.
//! 2. **pySim's state file records no card identity.** `BATCH_STATE` is
//!    `["name","country","mcc","mnc","smsp","secret","num"]` [V pySim-prog.py:669]:
//!    the parameters for the *next* card plus a counter. Nothing ties a slot to
//!    an ICCID, so a swapped card is invisible.
//!
//! What is copied rather than replaced: the handler shape (`get` / `done` /
//! `error` [V pySim/card_handler.py:39-61]), the ordering of the state write
//! (pySim programs the card at pySim-prog.py:757 and only then calls
//! `save_batch` at :767), and the "any non-zero rc moves the card to the error
//! bin" rule (pySim-prog.py:826-828).
//!
//! # The crash-safety rule
//!
//! **Write-ahead intent, commit-after-confirmation, atomic replacement.**
//!
//! * What is written: the whole [`State`] - the plan fingerprint, a monotone
//!   sequence number, and one [`Record`] per card that has been reached. A record
//!   carries the slot, the ICCID the plan expects, the ICCID the card actually
//!   said, the state, the steps done out of the steps planned, and the failure if
//!   there was one.
//! * When it is flushed: three times per programmed card, and nowhere else.
//!   `in-progress` immediately BEFORE the first command that changes the card
//!   (the write-ahead record: it claims nothing about the card); `programmed`
//!   immediately AFTER the card answered its verification and still reports the
//!   expected ICCID (the commit); `released` after the handler took the card
//!   away.
//! * What happens if the process dies between a flush and the card operation: a
//!   run interrupted at card 7 of 20 leaves cards 1-6 `programmed` or `released`
//!   and card 7 `in-progress`. The next run skips 1-6, and card 7 is done again
//!   from its first command, because an `in-progress` record asserts nothing
//!   about what reached the card. That is the safe direction to be wrong in: a
//!   repeated write is recoverable, a skipped write is not.
//! * Why success is never recorded early: a state file that says `programmed`
//!   before the card confirmed is worse than no state file, because the next
//!   run reads it as a promise. `programmed` is therefore written only after the
//!   verification command answered `90 00` AND the identity re-read still
//!   matched. A slot that writes must therefore declare a `verify` command
//!   ([`Plan::validate`] refuses the plan otherwise, kind `plan-invalid`): there
//!   is no such thing as a committed unverified write.
//! * Why replacement is atomic: the state goes to `<state>.tmp`, is `fsync`ed,
//!   is `rename`d over the state file, and the directory is `fsync`ed. A reader
//!   therefore sees either the previous complete state or the next one, never a
//!   partial file - and an unreadable one is refused with `state-unreadable`
//!   rather than treated as "no state yet", because restarting a factory run at
//!   card 1 on the strength of a parse error is the one thing worse than
//!   stopping.
//!
//! # Re-running the same steps
//!
//! Resume repeats a slot's commands from the start, so a plan must be written in
//! absolute terms. The commands this batch is meant to carry are already of that
//! shape: `update_binary` addresses an absolute offset (`update_binary_command`
//! puts it in P1P2 as a 16-bit big-endian value, src/cardsh.rs:2156) and
//! `set_data` replaces one tag of a BER-TLV EF, so re-sending a step writes the
//! same octets. A plan that adds a step which is not idempotent must say so with
//! `"idempotent": false`, and the warning then says a batch may write twice.
//!
//! # The automaton
//!
//! One [`CardState`] per slot. `first` in the `get` column is the handler's
//! "first card" argument [V pySim/card_handler.py:41-48]: the reader API cannot
//! recognise a card that was already inserted.
//!
//! | State | Trigger | Next | Handler | Terminal | Failure kind |
//! |---|---|---|---|---|---|
//! | `pending` | state file has no record for the slot, or one that is not done | `awaiting-card` | `get(first)` | no | - |
//! | `pending` | the record is `failed` and the kind is not retryable | `pending` (skipped) | - | yes | - |
//! | `awaiting-card` | `get` returned | `identifying` | - | no | - |
//! | `awaiting-card` | `get` failed | `failed` (retryable: re-runs next invocation) | `error()` | no | `handler-get-failed` |
//! | `identifying` | ICCID equals the plan's | `ready` | - | no | - |
//! | `identifying` | ICCID differs | `swapped` | `error()` | yes | `card-swapped` |
//! | `identifying` | no card in the reader | `failed` (retryable) | `error()` | no | `no-card` |
//! | `identifying` | card present, ICCID unreadable | `failed` (retryable) | `error()` | no | `identity-unreadable` |
//! | `ready` | no `--yes` | `planned` | `done()` | yes, nothing sent | - |
//! | `ready` | `--yes`, and the write-ahead record is flushed | `in-progress` | - | no | - |
//! | `in-progress` | every command ok, verification ok, ICCID still the same | `programmed` | - | no | - |
//! | `in-progress` | a command was refused | `failed` | `error()` | yes | `command-failed` |
//! | `in-progress` | verification refused, or the ICCID changed while writing | `failed` | `error()` | yes | `verify-failed` |
//! | `programmed` | commit flushed, then the handler took the card | `released` | `done()` | yes | - |
//! | `programmed` | commit flushed but `done()` failed | `programmed` in the file | - | yes | `handler-release-failed` |
//! | any | a hard stop | the run ends | - | yes | the kind that stopped it |
//! | `failed` | `--on-failure continue` and the kind is not a hard stop | next slot `pending` | - | yes | - |
//!
//! `released` versus `programmed` is a statement about the card, not about the
//! feeder: a card recorded `programmed` after a `handler-release-failed` is
//! programmed and verified, and its physical whereabouts are unknown. Both count
//! as done on a re-run.
//!
//! **Terminal** means the slot stops there: a new invocation is what moves it
//! again, and only for the kinds [`FailureKind::retryable`] (retried by default)
//! or with `--retry-failed` (everything else, a swap included - which will simply
//! be caught again if the same card is still in the reader).
//!
//! **Hard stops** never continue to the next card whatever `--on-failure` says:
//! `plan-invalid`, `state-unreadable`, `plan-mismatch`, `state-unwritable`,
//! `card-swapped`, `handler-release-failed` and `interrupted`. The first four
//! mean the run is no longer talking about the batch the operator asked for, the
//! swap means the card in the reader is not the card this slot is for, and a
//! release failure means the card is programmed but not where we left it.
//!
//! # Safety
//!
//! * Dry run by default: the plan for every card is printed and **not one byte is
//!   sent** - no handler call, no reader, no card. `--yes` sends.
//! * One gate: `--yes` goes into the shell's own `Opts::yes`, which is what
//!   `cardsh::may_change_card` reads (src/cardsh.rs:2974), so the plan's commands
//!   must NOT carry their own `--yes` - the batch owns that gate.
//! * Each card gets its own verification and its own failure kind; one failure
//!   does not continue to the next card unless `--on-failure continue` says so,
//!   and even then the report says which cards were skipped and why.
//! * [`WARNING`] is carried in the text and the JSON of every run, dry or not.
//!
//! # Idempotence
//!
//! Running the same plan twice is safe and says so: a slot recorded as done is
//! skipped with `skipped: "already-programmed"` and is not even offered to the
//! handler, so a second run over a finished batch sends nothing at all.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cardsh::{self, Shell};
use crate::contract::{self, ExitCode};

/// The `type` of the envelope, and the contract kind reported with a refusal.
pub const KIND: &str = "batch";

/// The `kind` a batch state file carries. A file saying anything else is not
/// this tool's state and is refused rather than guessed at.
pub const STATE_KIND: &str = "sim-doctor-batch-state/1";

/// The `kind` a batch plan file carries.
pub const PLAN_KIND: &str = "sim-doctor-batch-plan/1";

/// Carried in the text and the JSON of every run, dry or not.
pub const WARNING: &str = "a batch is N card writes: it can stop with some cards programmed and others not, and this state file is the only record of which - a card the file calls programmed has been programmed AND verified, a card it does not call programmed may or may not have been, so read the file before the next card goes in the reader, and expect a resumed slot to be written a second time";

/// Where a card is in the run. Serialised kebab-case, which is the spelling
/// used in the state file, in the report and in the table in the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CardState {
    /// No record, or a record that is not done: this slot is about to run.
    Pending,
    /// The write-ahead record is on disk: the identity was read and matched, and
    /// the card's commands have not all been confirmed. Claims nothing.
    InProgress,
    /// The handler has been asked for a card and has answered.
    AwaitingCard,
    /// The card is open and its ICCID is being read.
    Identifying,
    /// The card is open and its ICCID is the one the plan expects.
    Ready,
    /// A dry run: the plan was printed and nothing was sent.
    Planned,
    /// Committed: the commands and the verification succeeded and the identity
    /// re-read matched. This is the only state that means "the card is done".
    Programmed,
    /// Committed, and the handler has taken the card away.
    Released,
    /// A failure, with a kind.
    Failed,
    /// The card in the reader was not the card this slot is for.
    Swapped,
}

impl CardState {
    /// The spelling used in the state file and the report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in-progress",
            Self::AwaitingCard => "awaiting-card",
            Self::Identifying => "identifying",
            Self::Ready => "ready",
            Self::Planned => "planned",
            Self::Programmed => "programmed",
            Self::Released => "released",
            Self::Failed => "failed",
            Self::Swapped => "swapped",
        }
    }

    /// Every state, for the doc-agreement test.
    pub const ALL: [Self; 10] = [
        Self::Pending,
        Self::AwaitingCard,
        Self::Identifying,
        Self::Ready,
        Self::InProgress,
        Self::Planned,
        Self::Programmed,
        Self::Released,
        Self::Failed,
        Self::Swapped,
    ];

    /// Whether the slot's processing ends in this state.
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Programmed | Self::Released | Self::Failed | Self::Swapped
        )
    }

    /// Whether the card is programmed and verified: a re-run skips such a slot.
    pub fn is_done(self) -> bool {
        matches!(self, Self::Programmed | Self::Released)
    }
}

/// Why a slot stopped. Serialised kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKind {
    /// The plan file is not a plan, or a slot is not programmable (no `verify`).
    PlanInvalid,
    /// The state file is not JSON of this `kind`, or is not readable.
    StateUnreadable,
    /// The state file belongs to a different plan, so resuming it would program
    /// the wrong thing.
    PlanMismatch,
    /// The state file could not be replaced (read-only directory, full disk).
    StateUnwritable,
    /// No card in the reader.
    NoCard,
    /// A card is there and its ICCID could not be read.
    IdentityUnreadable,
    /// The card's ICCID is not the one the slot expects.
    CardSwapped,
    /// A command of the plan was refused by the card or by the shell.
    CommandFailed,
    /// The verification did not confirm the write, or the identity changed.
    VerifyFailed,
    /// The handler's `get` failed: no card arrived, so nothing was written.
    HandlerGetFailed,
    /// The handler's `done` or `error` failed: the card is programmed (or not)
    /// and is not where this process left it.
    HandlerReleaseFailed,
    /// The operator interrupted the run.
    Interrupted,
}

impl FailureKind {
    /// The spelling used in the state file and the report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlanInvalid => "plan-invalid",
            Self::StateUnreadable => "state-unreadable",
            Self::PlanMismatch => "plan-mismatch",
            Self::StateUnwritable => "state-unwritable",
            Self::NoCard => "no-card",
            Self::IdentityUnreadable => "identity-unreadable",
            Self::CardSwapped => "card-swapped",
            Self::CommandFailed => "command-failed",
            Self::VerifyFailed => "verify-failed",
            Self::HandlerGetFailed => "handler-get-failed",
            Self::HandlerReleaseFailed => "handler-release-failed",
            Self::Interrupted => "interrupted",
        }
    }

    /// Every kind, for the doc-agreement test.
    pub const ALL: [Self; 12] = [
        Self::PlanInvalid,
        Self::StateUnreadable,
        Self::PlanMismatch,
        Self::StateUnwritable,
        Self::NoCard,
        Self::IdentityUnreadable,
        Self::CardSwapped,
        Self::CommandFailed,
        Self::VerifyFailed,
        Self::HandlerGetFailed,
        Self::HandlerReleaseFailed,
        Self::Interrupted,
    ];

    /// Whether a re-run repeats the slot without being told to.
    ///
    /// Transient facts (no card, a feeder that did not deliver, an ICCID that
    /// could not be read) are retried; a card that refused a write, or that was
    /// not the card this slot is for, is not - that one wants a human.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::NoCard | Self::IdentityUnreadable | Self::HandlerGetFailed
        )
    }

    /// Whether the run stops whatever `--on-failure` says.
    pub fn hard_stop(self) -> bool {
        matches!(
            self,
            Self::PlanInvalid
                | Self::StateUnreadable
                | Self::PlanMismatch
                | Self::StateUnwritable
                | Self::CardSwapped
                | Self::HandlerReleaseFailed
                | Self::Interrupted
        )
    }
}

/// A failure, with the step it happened at (0-based over the slot's commands)
/// and the status word when there was one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// The machine-readable kind. One per cause, never "error".
    pub kind: FailureKind,
    /// Which command of the slot, when the failure is a command's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<usize>,
    /// The sentence a person reads, sanitised on the way out.
    pub detail: String,
    /// The status word the card answered, when it answered one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sw: Option<String>,
}

impl Failure {
    fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            step: None,
            detail: detail.into(),
            sw: None,
        }
    }

    /// A failure at a step of the slot's command list.
    fn at(kind: FailureKind, step: usize, detail: impl Into<String>, sw: Option<String>) -> Self {
        Self {
            step: Some(step),
            sw,
            ..Self::new(kind, detail)
        }
    }

    /// The JSON an agent reads.
    pub fn data(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "step": self.step,
            "detail": contract::sanitize(&self.detail),
            "sw": self.sw,
            "retryable": self.kind.retryable(),
            "hard_stop": self.kind.hard_stop(),
        })
    }
}

/// What the state file remembers about one card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The slot number from the plan. The join key; never inferred from order.
    pub slot: u32,
    /// The ICCID this slot must present.
    pub expected_iccid: String,
    /// The ICCID the card actually said, once it was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_iccid: Option<String>,
    /// Where the card got to.
    pub state: CardState,
    /// How many commands the slot has, verification included.
    #[serde(default)]
    pub steps_planned: usize,
    /// How many of them the card confirmed.
    #[serde(default)]
    pub steps_done: usize,
    /// Whether the verification confirmed the write. Only a committed record
    /// sets it, and only [`CardState::is_done`] records count as done.
    #[serde(default)]
    pub verified: bool,
    /// Why it stopped, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
    /// The state file's sequence number this record was last written at, so the
    /// commit can be shown to come after the write-ahead flush.
    #[serde(default)]
    pub seq: u64,
}

/// The whole state file: what the run is doing and what it has already done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Always [`STATE_KIND`]. Anything else is refused.
    pub kind: String,
    /// The state format version, so a future change is visible rather than
    /// silently misread.
    pub version: u32,
    /// The batch's name, from `--batch-name` or the plan's `batch`.
    pub batch: String,
    /// FNV-1a over the plan's canonical JSON. A change detector for "is this
    /// state file about this plan", not a security digest: the per-card swap
    /// check is a byte-for-byte comparison of the ICCID, never a hash.
    pub plan_fingerprint: String,
    /// Monotone; the number of the flush this file holds.
    #[serde(default)]
    pub seq: u64,
    /// One entry per card reached, in the order they were reached.
    pub cards: Vec<Record>,
}

impl State {
    /// A fresh state for `batch` and this plan.
    pub fn new(batch: &str, fingerprint: &str) -> Self {
        Self {
            kind: STATE_KIND.to_owned(),
            version: 1,
            batch: batch.to_owned(),
            plan_fingerprint: fingerprint.to_owned(),
            seq: 0,
            cards: Vec::new(),
        }
    }

    /// Reads the state file, or starts a fresh one when there is none.
    ///
    /// An existing file that is unreadable, of another `kind`, or of another
    /// plan is an error, never a reason to start again: silently re-programming
    /// cards 1..n is the failure mode this module exists to prevent.
    pub fn load(path: &Path, batch: &str, fingerprint: &str) -> Result<Self, Failure> {
        if !path.exists() {
            return Ok(Self::new(batch, fingerprint));
        }
        let text = std::fs::read_to_string(path).map_err(|err| {
            Failure::new(
                FailureKind::StateUnreadable,
                format!("{}: {err}", path.display()),
            )
        })?;
        let state: Self = serde_json::from_str(&text).map_err(|err| {
            Failure::new(
                FailureKind::StateUnreadable,
                format!(
                    "{}: {} (the file is left as it is; it is the only record of what was programmed)",
                    path.display(),
                    err
                ),
            )
        })?;
        if state.kind != STATE_KIND {
            return Err(Failure::new(
                FailureKind::StateUnreadable,
                format!(
                    "{}: this is a `{}` state file, not `{}`",
                    path.display(),
                    state.kind,
                    STATE_KIND
                ),
            ));
        }
        if state.version != 1 {
            return Err(Failure::new(
                FailureKind::StateUnreadable,
                format!(
                    "{}: state version {} is not this build's version 1",
                    path.display(),
                    state.version
                ),
            ));
        }
        if state.plan_fingerprint != fingerprint {
            return Err(Failure::new(
                FailureKind::PlanMismatch,
                format!(
                    "{}: this state file is for a different plan (fingerprint {} here, {} in the plan). Start a new state file for the new plan rather than resuming this one",
                    path.display(),
                    state.plan_fingerprint,
                    fingerprint
                ),
            ));
        }
        Ok(state)
    }

    /// The record for `slot`, if the run reached it.
    pub fn record(&self, slot: u32) -> Option<&Record> {
        self.cards.iter().find(|r| r.slot == slot)
    }

    /// Adds or replaces the record for a slot, keeping the order of first reach.
    fn upsert(&mut self, record: Record) {
        match self.cards.iter_mut().find(|r| r.slot == record.slot) {
            Some(existing) => *existing = record,
            None => self.cards.push(record),
        }
    }

    /// Replaces the state file atomically: temp file, `fsync`, `rename`,
    /// directory `fsync`. A reader sees the whole previous state or the whole
    /// next one; never half of either.
    pub fn flush(&mut self, path: &Path) -> Result<u64, Failure> {
        self.seq += 1;
        let seq = self.seq;
        for record in &mut self.cards {
            record.seq = seq;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|err| Failure::new(FailureKind::StateUnwritable, err.to_string()))?;
        write_atomic(path, json.as_bytes())
            .map_err(|err| Failure::new(FailureKind::StateUnwritable, err))
            .map(|()| seq)
    }
}

/// Writes `bytes` at `path` so that `path` is never observed half-written.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut file = File::create(&tmp).map_err(|err| format!("{}: {err}", tmp.display()))?;
        file.write_all(bytes)
            .map_err(|err| format!("{}: {err}", tmp.display()))?;
        file.sync_all()
            .map_err(|err| format!("{}: {err}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|err| format!("{} -> {}: {err}", tmp.display(), path.display()))?;
    // The rename is atomic, but the directory entry still has to reach the disk
    // or a power cut can lose the rename itself.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| format!("{}: {err}", parent.display()))
}

/// One row of the automaton, so the table in the module docs is also data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The state the card is in.
    pub from: CardState,
    /// What is observed.
    pub trigger: &'static str,
    /// Where it goes.
    pub to: CardState,
    /// The handler method this transition calls, if any (`get` takes `first`).
    pub handler: &'static str,
    /// Whether the slot stops here.
    pub terminal: bool,
    /// The failure kind this transition records, if it is a failure.
    pub failure: Option<FailureKind>,
}

/// Every transition of the automaton, in the order of the table in the module
/// docs. `tests::the_documented_table_and_this_one_agree` reads the docs and
/// fails if a state, a trigger or a kind is missing from one of the two.
pub const TRANSITIONS: &[Transition] = &[
    Transition {
        from: CardState::Pending,
        trigger: "no record for the slot",
        to: CardState::AwaitingCard,
        handler: "get",
        terminal: false,
        failure: None,
    },
    Transition {
        from: CardState::Pending,
        trigger: "a record that is not done",
        to: CardState::AwaitingCard,
        handler: "get",
        terminal: false,
        failure: None,
    },
    Transition {
        from: CardState::Pending,
        trigger: "failed and not retryable",
        to: CardState::Pending,
        handler: "",
        terminal: true,
        failure: None,
    },
    Transition {
        from: CardState::AwaitingCard,
        trigger: "get returned",
        to: CardState::Identifying,
        handler: "",
        terminal: false,
        failure: None,
    },
    Transition {
        from: CardState::AwaitingCard,
        trigger: "get failed",
        to: CardState::Failed,
        handler: "error",
        terminal: false,
        failure: Some(FailureKind::HandlerGetFailed),
    },
    Transition {
        from: CardState::Identifying,
        trigger: "ICCID equals the plan's",
        to: CardState::Ready,
        handler: "",
        terminal: false,
        failure: None,
    },
    Transition {
        from: CardState::Identifying,
        trigger: "ICCID differs",
        to: CardState::Swapped,
        handler: "error",
        terminal: true,
        failure: Some(FailureKind::CardSwapped),
    },
    Transition {
        from: CardState::Identifying,
        trigger: "no card in the reader",
        to: CardState::Failed,
        handler: "error",
        terminal: false,
        failure: Some(FailureKind::NoCard),
    },
    Transition {
        from: CardState::Identifying,
        trigger: "ICCID unreadable",
        to: CardState::Failed,
        handler: "error",
        terminal: false,
        failure: Some(FailureKind::IdentityUnreadable),
    },
    Transition {
        from: CardState::Ready,
        trigger: "dry run",
        to: CardState::Planned,
        handler: "done",
        terminal: true,
        failure: None,
    },
    Transition {
        from: CardState::Ready,
        trigger: "the write-ahead record is flushed",
        to: CardState::InProgress,
        handler: "",
        terminal: false,
        failure: None,
    },
    Transition {
        from: CardState::InProgress,
        trigger: "every command ok",
        to: CardState::Programmed,
        handler: "",
        terminal: false,
        failure: None,
    },
    Transition {
        from: CardState::InProgress,
        trigger: "a command was refused",
        to: CardState::Failed,
        handler: "error",
        terminal: true,
        failure: Some(FailureKind::CommandFailed),
    },
    Transition {
        from: CardState::InProgress,
        trigger: "verification refused",
        to: CardState::Failed,
        handler: "error",
        terminal: true,
        failure: Some(FailureKind::VerifyFailed),
    },
    Transition {
        from: CardState::InProgress,
        trigger: "identity changed while writing",
        to: CardState::Failed,
        handler: "error",
        terminal: true,
        failure: Some(FailureKind::VerifyFailed),
    },
    Transition {
        from: CardState::Programmed,
        trigger: "commit flushed and the card taken",
        to: CardState::Released,
        handler: "done",
        terminal: true,
        failure: None,
    },
    Transition {
        from: CardState::Programmed,
        trigger: "done failed",
        to: CardState::Programmed,
        handler: "",
        terminal: true,
        failure: Some(FailureKind::HandlerReleaseFailed),
    },
    Transition {
        from: CardState::Failed,
        trigger: "on-failure continue",
        to: CardState::Pending,
        handler: "",
        terminal: true,
        failure: None,
    },
];

/// What a batch run needs to know beyond the plan.
#[derive(Debug, Clone)]
pub struct Options {
    /// The batch's name, recorded in the state file.
    pub batch: String,
    /// Where the state file is. The parent directory must exist; the file need
    /// not, and its absence means "this batch has not started".
    pub state_path: PathBuf,
    /// The one gate. Without it the run is a dry run and sends nothing.
    pub yes: bool,
    /// Whether a slot's failure lets the run go on to the next card.
    pub on_failure: OnFailure,
    /// Whether a slot that failed before, and did not fail for a retryable
    /// reason, is attempted again.
    pub retry_failed: bool,
    /// The reader to use, matched against the driver's own name.
    pub reader: Option<String>,
}

/// What happens to a slot that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Stop the run. The default: a batch that stops with some cards programmed
    /// must be noticed by a person, not walked past.
    Stop,
    /// Go on to the next card, and say in the report which card was left behind
    /// and why. Hard stops are still hard stops.
    Continue,
}

impl OnFailure {
    /// The spelling used on the command line and in the report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Continue => "continue",
        }
    }

    /// Parses `--on-failure`.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "stop" => Ok(Self::Stop),
            "continue" => Ok(Self::Continue),
            other => Err(format!(
                "`{other}` is not an --on-failure value: `stop` or `continue`"
            )),
        }
    }
}

/// The card handler: the thing that presents a card to the reader and takes it
/// away again, which for a bench is a person and for a feeder is a machine.
///
/// The three methods and their order are pySim's [V pySim/card_handler.py:39-61]:
/// `get` before the card is read, and then exactly one of `done` (the card
/// reached the good batch) or `error` (anything else) - pySim-prog.py:826-828
/// calls `ch.error()` for every non-zero return, and so does this.
pub trait Handler {
    /// A card should be in the reader. `first` is true for the first card of
    /// the run, so a handler that waits for a *change* of card does not wait
    /// for one that was already there.
    fn get(&mut self, first: bool) -> Result<(), String>;
    /// The card is programmed and verified; take it away.
    fn done(&mut self) -> Result<(), String>;
    /// The card is not in the good batch; take it away.
    fn error(&mut self) -> Result<(), String>;
}

/// The handler a bench uses: a person. Says what pySim's [`Prompt`] counterpart
/// says [V pySim/card_handler.py:73-86] and sends nothing.
pub struct Prompt;

impl Handler for Prompt {
    fn get(&mut self, first: bool) -> Result<(), String> {
        if first {
            println!("Ready for Programming: a card is already in the reader.");
        } else {
            println!("Ready for Programming: insert the next card.");
        }
        Ok(())
    }

    fn done(&mut self) -> Result<(), String> {
        println!("Programming successful: remove the card.");
        Ok(())
    }

    fn error(&mut self) -> Result<(), String> {
        println!("Programming failed: remove this card. It is NOT in the good batch.");
        Ok(())
    }
}

/// The handler a feeder uses: three programs, one per method, as
/// [`Prompt`]'s automatic counterpart reads them from a config file
/// [V pySim/card_handler.py:94-99, :132-145].
///
/// Two departures from pySim, both deliberate:
///
/// * The command is **not** run through a shell. pySim passes the string to
///   `subprocess.Popen([command], shell=True)`, which is a feeder config running
///   as the operator; this one is split on whitespace and executed directly.
/// * A non-zero exit is a [`FailureKind::HandlerReleaseFailed`] the automaton
///   routes, not `sys.exit` [V pySim/card_handler.py:127-130]. The state flush
///   that precedes it has already happened, so a feeder that fails cannot lose
///   the record of the card it was holding.
#[derive(Debug, Clone, Default)]
pub struct External {
    programs: BTreeMap<String, String>,
}

impl External {
    /// The keys a handler config file must define.
    pub const KEYS: [&'static str; 3] = ["get", "done", "error"];

    /// Reads a handler config: one `key = command` or `key: command` per line,
    /// `#` starting a comment. All three of [`External::KEYS`] must be there.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut programs = BTreeMap::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(['=', ':'])
                .ok_or_else(|| format!("line {}: expected `get = command`", number + 1))?;
            let (key, value) = (key.trim(), value.trim());
            if !value.is_empty() {
                programs.insert(key.to_ascii_lowercase(), value.to_owned());
            }
        }
        for key in Self::KEYS {
            if !programs.contains_key(key) {
                return Err(format!(
                    "the handler config has no `{key}` command (get, done and error are all required)"
                ));
            }
        }
        Ok(Self { programs })
    }

    /// Runs one method's program. The arguments after the program name are
    /// passed to it as they are; no shell, no glob, no redirection.
    pub fn program(&self, key: &str) -> Option<&str> {
        self.programs.get(key).map(String::as_str)
    }

    fn exec(&mut self, key: &str) -> Result<(), String> {
        let line = self
            .program(key)
            .ok_or_else(|| format!("the handler has no `{key}` command"))?;
        let mut words = line.split_whitespace();
        let program = words
            .next()
            .ok_or_else(|| format!("the handler's `{key}` command is empty"))?;
        let status = std::process::Command::new(program)
            .args(words)
            .status()
            .map_err(|err| format!("the handler's `{key}` command `{program}`: {err}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "the handler's `{key}` command `{program}` answered {}",
                status
                    .code()
                    .map_or_else(|| "a signal".to_owned(), |code| format!("exit {code}"))
            ))
        }
    }
}

impl Handler for External {
    fn get(&mut self, _first: bool) -> Result<(), String> {
        self.exec("get")
    }

    fn done(&mut self) -> Result<(), String> {
        self.exec("done")
    }

    fn error(&mut self) -> Result<(), String> {
        self.exec("error")
    }
}

/// One card of the plan: which card, what it must answer to, and what to send.
///
/// A slot that writes MUST carry a `verify` command: the commit in the state
/// file is only written after that command confirms the write, so a plan that
/// writes without one has nothing to commit on and is refused
/// ([`Plan::validate`], kind `plan-invalid`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    /// The slot number: the join key with the state file, never the list order.
    pub slot: u32,
    /// The ICCID this slot must present, as `cardinfo` spells it. Compared
    /// byte for byte.
    pub iccid: String,
    /// Anything the operator wants to recognise the slot by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `uicc` (class 00) or `sim` (class A0, GSM 11.11).
    #[serde(default = "uicc")]
    pub profile: String,
    /// The card-shell commands to send, in order. `;` separates, as in the
    /// shell's own `-c`.
    #[serde(default)]
    pub commands: Vec<String>,
    /// The command that confirms the writes. Required when `commands` is not
    /// empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
    /// The plan author's claim that re-sending every command writes the same
    /// octets. Defaults to true, which every command this batch is meant to
    /// carry does (an absolute-offset UPDATE BINARY, a tag-keyed SET DATA). Set
    /// it false when a command is not, and the report then says a resumed slot
    /// may be written twice.
    #[serde(default = "idempotent")]
    pub idempotent: bool,
}

fn uicc() -> String {
    "uicc".to_owned()
}

fn idempotent() -> bool {
    true
}

impl Slot {
    /// The commands with `;` expanded, blanks dropped: the order they are sent.
    pub fn steps(&self) -> Vec<String> {
        self.commands
            .iter()
            .flat_map(|line| cardsh::split_commands(line))
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    }

    /// The command set this slot carries, verification included.
    pub fn step_count(&self) -> usize {
        self.steps().len() + usize::from(self.verify.is_some())
    }

    /// The class byte set this slot is programmed with.
    pub fn card_profile(&self) -> cardsh::Profile {
        if self.profile == "sim" {
            cardsh::Profile::Sim
        } else {
            cardsh::Profile::Uicc
        }
    }
}

/// The batch: the slots, in the order they are to be fed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The batch's name, when the plan gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<String>,
    /// The slots. Slot numbers are unique and 1-based.
    pub cards: Vec<Slot>,
}

impl Plan {
    /// Parses a plan file's text.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        let plan: Self = serde_json::from_str(text).map_err(|err| {
            Failure::new(
                FailureKind::PlanInvalid,
                format!("the plan is not a {PLAN_KIND} document: {err}"),
            )
        })?;
        plan.validate()?;
        Ok(plan)
    }

    /// Reads and parses a plan file.
    pub fn load(path: &Path) -> Result<Self, Failure> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            Failure::new(
                FailureKind::PlanInvalid,
                format!("{}: {err}", path.display()),
            )
        })?;
        Self::parse(&text)
    }

    /// The rules a plan has to satisfy before a card is touched.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.cards.is_empty() {
            return Err(Failure::new(
                FailureKind::PlanInvalid,
                "the plan has no cards",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for slot in &self.cards {
            let bad = |message: &str| {
                Failure::new(
                    FailureKind::PlanInvalid,
                    format!("slot {}: {message}", slot.slot),
                )
            };
            if slot.slot == 0 {
                return Err(bad("slot numbers start at 1"));
            }
            if !seen.insert(slot.slot) {
                return Err(bad("two slots share this number"));
            }
            if slot.iccid.is_empty() || !slot.iccid.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("`iccid` is the decimal spelling `cardinfo` prints"));
            }
            if slot.iccid.len() > 32 {
                return Err(bad("`iccid` is longer than any ICCID can be"));
            }
            if slot.profile != "uicc" && slot.profile != "sim" {
                return Err(bad("`profile` is `uicc` or `sim`"));
            }
            let steps = slot.steps();
            if !slot.commands.is_empty() && steps.is_empty() {
                return Err(bad("`commands` holds only blanks"));
            }
            if !steps.is_empty() && slot.verify.is_none() {
                return Err(bad(
                    "a slot that writes must declare `verify`: the state file is only committed after the card confirms it, so there would be nothing to commit on",
                ));
            }
        }
        Ok(())
    }

    /// FNV-1a over the plan's canonical JSON: "is this state file about this
    /// plan". A change detector, not a security digest - the swap check compares
    /// the ICCID as text and never a hash of it.
    pub fn fingerprint(&self) -> String {
        let text = serde_json::to_string(self).unwrap_or_default();
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in text.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{hash:016x}")
    }

    /// The plan's JSON, as the dry run prints it.
    pub fn json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// What one card did, or did not do, in this run.
#[derive(Debug, Clone, Serialize)]
pub struct CardReport {
    /// The slot number.
    pub slot: u32,
    /// The label, when the plan gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The ICCID the slot expects.
    pub expected_iccid: String,
    /// The ICCID the card said, when a card was read.
    pub observed_iccid: Option<String>,
    /// Where it got to.
    pub state: &'static str,
    /// The class byte set it was programmed with.
    pub profile: String,
    /// Every command line that would be, or was, sent, in order.
    pub planned: Vec<String>,
    /// How many of them the card confirmed.
    pub steps_done: usize,
    /// Whether the verification confirmed the writes.
    pub verified: bool,
    /// Whether any byte reached this card in this run.
    pub touched: bool,
    /// The plan's own idempotence claim; false means a resume may write twice.
    pub idempotent: bool,
    /// Why this card was not programmed, when it was not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<&'static str>,
    /// Why it stopped, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

impl CardReport {
    /// A card this run did not touch, and why not.
    fn skipped(slot: &Slot, record: &Record, reason: &'static str) -> Self {
        Self {
            slot: slot.slot,
            label: slot.label.clone(),
            expected_iccid: slot.iccid.clone(),
            observed_iccid: record.observed_iccid.clone(),
            state: record.state.as_str(),
            profile: slot.profile.clone(),
            planned: slot.steps(),
            steps_done: record.steps_done,
            verified: record.verified,
            touched: false,
            idempotent: slot.idempotent,
            skipped: Some(reason),
            failure: record.failure.clone(),
        }
    }
}

/// The counts a reader needs before reading the cards.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// Cards in the plan.
    pub planned: usize,
    /// Cards a byte was sent to.
    pub touched: usize,
    /// Cards this run programmed and verified.
    pub programmed: usize,
    /// Cards an earlier run had already programmed.
    pub already_done: usize,
    /// Cards this run skipped for a stated reason.
    pub skipped: usize,
    /// Cards that failed.
    pub failed: usize,
    /// Cards that were not the card the slot was for.
    pub swapped: usize,
}

/// What the whole run did. Serialised as the envelope's `data`.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Always [`KIND`].
    pub kind: &'static str,
    /// The batch's name.
    pub batch: String,
    /// Whether this was a dry run. A dry run sends nothing at all.
    pub dry_run: bool,
    /// Where the state file is.
    pub state_file: String,
    /// The plan's fingerprint, as recorded in the state file.
    pub plan_fingerprint: String,
    /// The number of state-file writes this run made.
    pub flushes: u64,
    /// [`WARNING`], in every run.
    pub warning: &'static str,
    /// One entry per card, in plan order.
    pub cards: Vec<CardReport>,
    /// The counts.
    pub summary: Summary,
    /// Why the run ended, when it did not simply finish.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Failure>,
}

impl Report {
    /// The exit code this run earned: a failure of any kind is 1, as it is
    /// everywhere else in this crate (`contract::ExitCode::Findings`).
    pub fn exit(&self) -> ExitCode {
        if self.stop.is_some() || self.summary.failed > 0 {
            ExitCode::Findings
        } else {
            ExitCode::Success
        }
    }

    /// The one-line JSON document `--json` prints.
    pub fn envelope(&self) -> String {
        let code = self.exit();
        let message = if code == ExitCode::Success {
            contract::OK_MESSAGE
        } else {
            "a card did not finish"
        };
        contract::Envelope::new(
            KIND,
            code,
            message,
            serde_json::to_value(self).unwrap_or(Value::Null),
        )
        .to_json()
        .unwrap_or_else(|err| format!("{{\"type\":\"{KIND}\",\"error\":\"{err}\"}}"))
    }

    /// What a person reads: the warning, then one line per card, then the
    /// counts, then what the state file holds.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "sim-doctor batch: {} ({} of {} card(s), {})\n",
            self.batch,
            self.summary.programmed + self.summary.already_done,
            self.summary.planned,
            if self.dry_run { "DRY RUN" } else { "sending" }
        ));
        out.push_str(&format!("WARNING: {}\n", WARNING));
        if self.dry_run {
            out.push_str("dry run: nothing was sent to any card; add --yes to program the batch\n");
        }
        for card in &self.cards {
            let mut line = format!(
                "slot {} [{}] {}",
                card.slot, card.state, card.expected_iccid
            );
            if let Some(label) = &card.label {
                line.push_str(&format!(" ({label})"));
            }
            if let Some(observed) = &card.observed_iccid {
                if observed != &card.expected_iccid {
                    line.push_str(&format!("  CARD SAYS {observed}"));
                }
            }
            if let Some(skipped) = card.skipped {
                line.push_str(&format!("  skipped: {skipped}"));
            }
            if let Some(failure) = &card.failure {
                line.push_str(&format!("  {}: {}", failure.kind.as_str(), failure.detail));
                if let (Some(step), Some(sw)) = (failure.step, failure.sw.as_ref()) {
                    line.push_str(&format!(" (step {step}, {sw})"));
                }
            }
            line.push_str(if card.verified { "  verified" } else { "" });
            out.push_str(&line);
            out.push('\n');
            for command in &card.planned {
                out.push_str(&format!("      would send: {command}\n"));
            }
            if !card.idempotent {
                out.push_str(
                    "      note: this slot is not idempotent, so a resume may write it twice\n",
                );
            }
        }
        if let Some(stop) = &self.stop {
            out.push_str(&format!(
                "stopped: {}: {}\n",
                stop.kind.as_str(),
                contract::sanitize(&stop.detail)
            ));
        }
        out.push_str(&format!(
            "planned {}  touched {}  programmed {}  already done {}  skipped {}  failed {}  swapped {}\n",
            self.summary.planned,
            self.summary.touched,
            self.summary.programmed,
            self.summary.already_done,
            self.summary.skipped,
            self.summary.failed,
            self.summary.swapped
        ));
        if self.dry_run {
            out.push_str("no state file was written: the batch was not run\n");
        } else {
            out.push_str(&format!(
                "state file {} is the record of which cards are programmed ({} write(s) this run)\n",
                self.state_file, self.flushes
            ));
        }
        out
    }
}

/// A run that could not start: the plan or the state file is wrong, so no card
/// is touched and there is nothing to report about cards.
fn refusal(opts: &Options, plan: &Plan, failure: Failure) -> (ExitCode, Report) {
    let report = Report {
        kind: KIND,
        batch: opts.batch.clone(),
        dry_run: !opts.yes,
        state_file: opts.state_path.display().to_string(),
        plan_fingerprint: plan.fingerprint(),
        flushes: 0,
        warning: WARNING,
        cards: Vec::new(),
        summary: Summary {
            planned: plan.cards.len(),
            ..Summary::default()
        },
        stop: Some(failure),
    };
    (ExitCode::Findings, report)
}

/// What a slot's processing ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Programmed and verified, or already was.
    Done,
    /// Not run, and the report says why.
    Skipped,
    /// Failed, and the run went on to the next card.
    Failed,
    /// Failed, and the run ended.
    Stopped,
}

/// Runs the batch: one automaton over every slot, one state file, one report.
///
/// `shells` builds a fresh [`Shell`] per card - that is the seam a test scripts
/// a card with, and the production opener behind the PC/SC reader. Nothing is
/// sent unless [`Options::yes`].
pub fn execute(
    plan: &Plan,
    opts: &Options,
    shells: &mut dyn FnMut() -> Shell,
    handler: &mut dyn Handler,
) -> (ExitCode, Report) {
    if let Err(failure) = plan.validate() {
        return refusal(opts, plan, failure);
    }
    let fingerprint = plan.fingerprint();
    let state = match State::load(&opts.state_path, &opts.batch, &fingerprint) {
        Ok(state) => state,
        Err(failure) => return refusal(opts, plan, failure),
    };
    let mut runner = Runner {
        plan,
        opts,
        shells,
        handler,
        state,
        cards: Vec::new(),
        stop: None,
        asked: 0,
        flushes: 0,
    };
    runner.run();
    let report = runner.report();
    let code = report.exit();
    (code, report)
}

struct Runner<'a> {
    plan: &'a Plan,
    opts: &'a Options,
    shells: &'a mut dyn FnMut() -> Shell,
    handler: &'a mut dyn Handler,
    state: State,
    cards: Vec<CardReport>,
    stop: Option<Failure>,
    /// How many cards the handler has been asked for, so `first` is true once.
    asked: usize,
    /// How many times the state file was replaced.
    flushes: u64,
}

impl Runner<'_> {
    fn flush(&mut self) -> Result<(), Failure> {
        self.state.flush(&self.opts.state_path)?;
        self.flushes += 1;
        Ok(())
    }

    fn run(&mut self) {
        for slot in &self.plan.cards {
            if !self.opts.yes {
                self.dry_run_card(slot);
                continue;
            }
            if self.card(slot) == Outcome::Stopped {
                return;
            }
        }
    }

    /// A dry run: the plan for every card, the state file read (never written)
    /// so an already-programmed card can be reported, and not one byte sent.
    fn dry_run_card(&mut self, slot: &Slot) {
        let done = self
            .state
            .record(slot.slot)
            .filter(|record| record.state.is_done())
            .cloned();
        let report = match &done {
            Some(record) => CardReport::skipped(slot, record, "already-programmed"),
            None => CardReport {
                slot: slot.slot,
                label: slot.label.clone(),
                expected_iccid: slot.iccid.clone(),
                observed_iccid: None,
                state: CardState::Planned.as_str(),
                profile: slot.profile.clone(),
                planned: slot.steps(),
                steps_done: 0,
                verified: false,
                touched: false,
                idempotent: slot.idempotent,
                skipped: None,
                failure: None,
            },
        };
        self.cards.push(report);
    }

    /// One card, through the automaton.
    fn card(&mut self, slot: &Slot) -> Outcome {
        // What the state file already knows. `in-progress` and the retryable
        // failures are redone: a record that claims nothing must not be read as
        // a skip, and a card that was merely not there is not a verdict.
        if let Some(record) = self.state.record(slot.slot).cloned() {
            if record.state.is_done() {
                self.cards
                    .push(CardReport::skipped(slot, &record, "already-programmed"));
                return Outcome::Skipped;
            }
            let retryable = record
                .failure
                .as_ref()
                .is_some_and(|failure| failure.kind.retryable());
            if record.state == CardState::Failed && !retryable && !self.opts.retry_failed {
                self.cards
                    .push(CardReport::skipped(slot, &record, "failed-earlier"));
                return Outcome::Skipped;
            }
        }

        let steps = slot.steps();
        let planned_len = steps.len() + usize::from(slot.verify.is_some());

        // Awaiting card.
        let first = self.asked == 0;
        self.asked += 1;
        if let Err(message) = self.handler.get(first) {
            return self.fail(
                slot,
                None,
                0,
                planned_len,
                Failure::new(FailureKind::HandlerGetFailed, message),
            );
        }

        // Identifying.
        let mut shell = (self.shells)();
        if let Err(message) = shell.equip(self.opts.reader.as_deref(), slot.card_profile()) {
            return self.fail(
                slot,
                None,
                0,
                planned_len,
                Failure::new(FailureKind::NoCard, message),
            );
        }
        let info = shell.exec("cardinfo");
        let observed = if info.ok {
            info.data
                .get("iccid")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        };
        let Some(observed) = observed else {
            let detail = if info.ok {
                "the card did not report an ICCID (EF.ICCID is unreadable)".to_owned()
            } else {
                info.text.clone()
            };
            return self.fail(
                slot,
                None,
                0,
                planned_len,
                Failure::new(FailureKind::IdentityUnreadable, detail),
            );
        };
        if observed != slot.iccid {
            let failure = Failure::new(
                FailureKind::CardSwapped,
                format!(
                    "the card in the reader reports ICCID {observed}; slot {} expects {}: nothing was sent to it and the run stopped",
                    slot.slot, slot.iccid
                ),
            );
            self.state.upsert(Record {
                slot: slot.slot,
                expected_iccid: slot.iccid.clone(),
                observed_iccid: Some(observed.clone()),
                state: CardState::Swapped,
                steps_planned: planned_len,
                steps_done: 0,
                verified: false,
                failure: Some(failure.clone()),
                seq: 0,
            });
            if let Err(written) = self.flush() {
                self.stop.get_or_insert(written);
            }
            let _ = self.handler.error();
            self.cards.push(CardReport {
                slot: slot.slot,
                label: slot.label.clone(),
                expected_iccid: slot.iccid.clone(),
                observed_iccid: Some(observed),
                state: CardState::Swapped.as_str(),
                profile: slot.profile.clone(),
                planned: steps,
                steps_done: 0,
                verified: false,
                touched: false,
                idempotent: slot.idempotent,
                skipped: None,
                failure: Some(failure.clone()),
            });
            self.stop = Some(failure);
            return Outcome::Stopped;
        }

        // Ready, and the write-ahead record goes down BEFORE the first command
        // that changes the card.
        self.state.upsert(Record {
            slot: slot.slot,
            expected_iccid: slot.iccid.clone(),
            observed_iccid: Some(observed.clone()),
            state: CardState::InProgress,
            steps_planned: planned_len,
            steps_done: 0,
            verified: false,
            failure: None,
            seq: 0,
        });
        if let Err(failure) = self.flush() {
            // Nothing has been written to the card yet, so refusing here costs
            // nothing and keeps the state file the record of what happened.
            self.cards.push(CardReport {
                slot: slot.slot,
                label: slot.label.clone(),
                expected_iccid: slot.iccid.clone(),
                observed_iccid: Some(observed),
                state: CardState::Ready.as_str(),
                profile: slot.profile.clone(),
                planned: steps,
                steps_done: 0,
                verified: false,
                touched: false,
                idempotent: slot.idempotent,
                skipped: None,
                failure: Some(failure.clone()),
            });
            let _ = self.handler.error();
            self.stop = Some(failure);
            return Outcome::Stopped;
        }

        // Programming.
        let mut done = 0usize;
        for (index, line) in steps.iter().enumerate() {
            let reply = shell.exec(line);
            if !reply.ok {
                let sw = reply
                    .data
                    .get("sw")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                return self.fail(
                    slot,
                    Some(observed),
                    done,
                    planned_len,
                    Failure::at(
                        FailureKind::CommandFailed,
                        index,
                        contract::sanitize(&reply.text),
                        sw,
                    ),
                );
            }
            done += 1;
        }
        if let Some(line) = &slot.verify {
            let reply = shell.exec(line);
            if !reply.ok {
                let sw = reply
                    .data
                    .get("sw")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                return self.fail(
                    slot,
                    Some(observed),
                    done,
                    planned_len,
                    Failure::at(
                        FailureKind::VerifyFailed,
                        done,
                        contract::sanitize(&reply.text),
                        sw,
                    ),
                );
            }
            done += 1;
        }
        // The card has to still be the card this slot is for.
        let after = shell.exec("cardinfo");
        let still = if after.ok {
            after
                .data
                .get("iccid")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        };
        if still.as_deref() != Some(slot.iccid.as_str()) {
            let now = still.clone().unwrap_or_default();
            return self.fail(
                slot,
                Some(now.clone()),
                done,
                planned_len,
                Failure::new(
                    FailureKind::VerifyFailed,
                    format!(
                        "after programming, the card reports ICCID {now} instead of {}",
                        slot.iccid
                    ),
                ),
            );
        }

        // The commit: after the verification and after the identity re-read, and
        // never before. If this write fails the file still holds `in-progress`,
        // so a re-run does the slot again rather than skipping it.
        self.state.upsert(Record {
            slot: slot.slot,
            expected_iccid: slot.iccid.clone(),
            observed_iccid: Some(observed.clone()),
            state: CardState::Programmed,
            steps_planned: planned_len,
            steps_done: done,
            verified: true,
            failure: None,
            seq: 0,
        });
        if let Err(failure) = self.flush() {
            let mut failure = failure;
            failure.detail = format!(
                "{}: the card IS programmed and verified, but this is not recorded - verify it by hand before inserting another card",
                failure.detail
            );
            self.cards.push(CardReport {
                slot: slot.slot,
                label: slot.label.clone(),
                expected_iccid: slot.iccid.clone(),
                observed_iccid: Some(observed),
                state: CardState::Programmed.as_str(),
                profile: slot.profile.clone(),
                planned: steps,
                steps_done: done,
                verified: true,
                touched: true,
                idempotent: slot.idempotent,
                skipped: None,
                failure: Some(failure.clone()),
            });
            let _ = self.handler.done();
            self.stop = Some(failure);
            return Outcome::Stopped;
        }

        // Released.
        if let Err(message) = self.handler.done() {
            let failure = Failure::new(
                FailureKind::HandlerReleaseFailed,
                format!(
                    "{message}: slot {} is programmed and verified, but the card was not taken away",
                    slot.slot
                ),
            );
            self.state.upsert(Record {
                slot: slot.slot,
                expected_iccid: slot.iccid.clone(),
                observed_iccid: Some(observed.clone()),
                state: CardState::Programmed,
                steps_planned: planned_len,
                steps_done: done,
                verified: true,
                failure: Some(failure.clone()),
                seq: 0,
            });
            if let Err(written) = self.flush() {
                self.stop = Some(written);
            }
            self.cards.push(CardReport {
                slot: slot.slot,
                label: slot.label.clone(),
                expected_iccid: slot.iccid.clone(),
                observed_iccid: Some(observed),
                state: CardState::Programmed.as_str(),
                profile: slot.profile.clone(),
                planned: steps,
                steps_done: done,
                verified: true,
                touched: true,
                idempotent: slot.idempotent,
                skipped: None,
                failure: Some(failure.clone()),
            });
            self.stop = Some(failure);
            return Outcome::Stopped;
        }
        self.state.upsert(Record {
            slot: slot.slot,
            expected_iccid: slot.iccid.clone(),
            observed_iccid: Some(observed),
            state: CardState::Released,
            steps_planned: planned_len,
            steps_done: done,
            verified: true,
            failure: None,
            seq: 0,
        });
        if let Err(failure) = self.flush() {
            // The file still says `programmed`, which is done, so this is not a
            // lost record - but it is reported rather than swallowed.
            self.stop = Some(failure);
            return Outcome::Stopped;
        }
        self.cards.push(CardReport {
            slot: slot.slot,
            label: slot.label.clone(),
            expected_iccid: slot.iccid.clone(),
            observed_iccid: self
                .state
                .record(slot.slot)
                .and_then(|r| r.observed_iccid.clone()),
            state: CardState::Released.as_str(),
            profile: slot.profile.clone(),
            planned: steps,
            steps_done: done,
            verified: true,
            touched: true,
            idempotent: slot.idempotent,
            skipped: None,
            failure: None,
        });
        Outcome::Done
    }

    /// Records a failure, ejects the card, and decides whether the run goes on.
    fn fail(
        &mut self,
        slot: &Slot,
        observed: Option<String>,
        done: usize,
        planned_len: usize,
        failure: Failure,
    ) -> Outcome {
        self.state.upsert(Record {
            slot: slot.slot,
            expected_iccid: slot.iccid.clone(),
            observed_iccid: observed.clone(),
            state: CardState::Failed,
            steps_planned: planned_len,
            steps_done: done,
            verified: false,
            failure: Some(failure.clone()),
            seq: 0,
        });
        if let Err(written) = self.flush() {
            self.stop.get_or_insert(written);
        }
        // pySim-prog.py:826-828: any non-zero result moves the card out.
        let _ = self.handler.error();
        let touched = done > 0;
        self.cards.push(CardReport {
            slot: slot.slot,
            label: slot.label.clone(),
            expected_iccid: slot.iccid.clone(),
            observed_iccid: observed,
            state: CardState::Failed.as_str(),
            profile: slot.profile.clone(),
            planned: slot.steps(),
            steps_done: done,
            verified: false,
            touched,
            idempotent: slot.idempotent,
            skipped: None,
            failure: Some(failure.clone()),
        });
        if failure.kind.hard_stop() || self.opts.on_failure == OnFailure::Stop {
            self.stop = Some(failure);
            Outcome::Stopped
        } else {
            Outcome::Failed
        }
    }

    fn report(&self) -> Report {
        let mut summary = Summary {
            planned: self.plan.cards.len(),
            ..Summary::default()
        };
        for card in &self.cards {
            if card.touched {
                summary.touched += 1;
            }
            if let Some(reason) = card.skipped {
                summary.skipped += 1;
                if reason == "already-programmed" {
                    summary.already_done += 1;
                }
            }
            if card.failure.is_some() {
                summary.failed += 1;
            }
            if card.state == CardState::Swapped.as_str() {
                summary.swapped += 1;
            }
            if card.state == CardState::Released.as_str() && card.skipped.is_none() {
                summary.programmed += 1;
            }
        }
        Report {
            kind: KIND,
            batch: self.state.batch.clone(),
            dry_run: !self.opts.yes,
            state_file: self.opts.state_path.display().to_string(),
            plan_fingerprint: self.state.plan_fingerprint.clone(),
            flushes: self.flushes,
            warning: WARNING,
            cards: self.cards.clone(),
            summary,
            stop: self.stop.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::cardsh::testcard::TestCard;
    use crate::cardsh::{Opts, Profile, Shell};
    use crate::transport::CardSession;

    /// ICCID octets BCD, nibble-swapped: `89 01 23 45 67 89 01 23 45 4F`.
    const CARD_A: [u8; 10] = [0x98, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0xF4];
    /// A second card, a different one: `89 01 23 45 67 89 01 23 45 5F`.
    const CARD_B: [u8; 10] = [0x98, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0xF5];

    /// A directory under the build tree. Never `/tmp`: the box has a rule about it, and a
    /// test's scratch files are no different from a worker's.
    fn scratch(tag: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("target/batch-tests-{}-{tag}", std::process::id()))
    }

    fn clear(tag: &str) -> PathBuf {
        let dir = scratch(tag);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory under target/");
        dir
    }

    /// A [`TestCard`] whose EF.ICCID holds `bytes`.
    fn card_with_iccid(bytes: &[u8]) -> TestCard {
        let mut card = TestCard::usim();
        let file = card
            .files
            .iter_mut()
            .find(|f| f.path == vec![0x3F00, 0x2FE2])
            .expect("the test card has EF.ICCID");
        file.content = vec![bytes.to_vec()];
        card
    }

    /// A [`TestCard`] with no EF.ICCID at all: SELECT answers `6A82`, so its identity cannot be
    /// read. That is the `identity-unreadable` case, not a swap.
    fn card_without_iccid() -> TestCard {
        let mut card = TestCard::usim();
        card.files.retain(|f| f.path != vec![0x3F00, 0x2FE2]);
        card
    }

    /// The ICCID `cardinfo` will print for a card holding `bytes`, read out of the card's own
    /// bytes by this repository's decoder rather than spelled out by hand here.
    fn iccid_of(bytes: &[u8]) -> String {
        let card = card_with_iccid(bytes);
        let file = card
            .files
            .iter()
            .find(|f| f.path == vec![0x3F00, 0x2FE2])
            .expect("EF.ICCID");
        crate::ef::decode_iccid(&file.content[0])
            .map(|digits| digits.as_str().to_owned())
            .expect("a decodable ICCID")
    }

    /// The wire log one scripted card was sent, shared with the card itself.
    type WireLog = Rc<RefCell<Vec<Vec<u8>>>>;

    /// What the scripted reader gives back for one card.
    enum Behaviour {
        Card(Box<TestCard>),
        NoCard,
    }

    /// A shell factory that scripts the cards, counting how many times a card was asked for and
    /// keeping each card's own wire log. Zero asks and zero bytes is what a dry run has to leave.
    struct Script {
        factory: Box<dyn FnMut() -> Shell>,
        opens: Rc<Cell<usize>>,
        logs: Rc<RefCell<Vec<WireLog>>>,
    }

    impl Script {
        fn new(behaviours: Vec<Behaviour>) -> Self {
            let queue: Rc<RefCell<VecDeque<Behaviour>>> = Rc::new(RefCell::new(behaviours.into()));
            let opens = Rc::new(Cell::new(0usize));
            let logs: Rc<RefCell<Vec<WireLog>>> = Rc::default();
            let counter = opens.clone();
            let drawn = queue.clone();
            let collected = logs.clone();
            let factory = Box::new(move || {
                counter.set(counter.get() + 1);
                let queue = drawn.clone();
                let collected = collected.clone();
                Shell::new(
                    Box::new(move |_| {
                        let behaviour = queue.borrow_mut().pop_front().unwrap_or(Behaviour::NoCard);
                        let log: WireLog = Rc::default();
                        collected.borrow_mut().push(log.clone());
                        match behaviour {
                            Behaviour::Card(mut card) => {
                                card.sent = log;
                                Ok((
                                    card as Box<dyn CardSession>,
                                    "test card".to_owned(),
                                    Some(vec![0x3B, 0x9F]),
                                ))
                            }
                            Behaviour::NoCard => Err("no card in the reader".to_owned()),
                        }
                    }),
                    Opts {
                        yes: true,
                        dialect: crate::scan::Dialect::Ts102221.tag_set(),
                        secrets: None,
                    },
                )
            });
            Self {
                factory,
                opens,
                logs,
            }
        }

        /// Every octet every card was sent, in order.
        fn sent(&self) -> Vec<Vec<u8>> {
            self.logs
                .borrow()
                .iter()
                .flat_map(|log| log.borrow().clone())
                .collect()
        }
    }

    fn card_a() -> Vec<Behaviour> {
        vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]
    }

    fn card_b() -> Vec<Behaviour> {
        vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_B)))]
    }

    fn no_card() -> Vec<Behaviour> {
        vec![Behaviour::NoCard]
    }

    fn no_iccid() -> Vec<Behaviour> {
        vec![Behaviour::Card(Box::new(card_without_iccid()))]
    }

    /// A handler that records the calls, so a test can see the automaton asked for a card and
    /// then took it away exactly once.
    #[derive(Default)]
    struct Recording {
        calls: Vec<String>,
        fail_get: bool,
        fail_done: bool,
    }

    impl Recording {
        fn failing_get() -> Self {
            Self {
                fail_get: true,
                ..Self::default()
            }
        }

        fn failing_done() -> Self {
            Self {
                fail_done: true,
                ..Self::default()
            }
        }
    }

    impl Handler for Recording {
        fn get(&mut self, first: bool) -> Result<(), String> {
            self.calls.push(if first {
                "get:first".to_owned()
            } else {
                "get".to_owned()
            });
            if self.fail_get {
                Err("the feeder did not deliver".to_owned())
            } else {
                Ok(())
            }
        }

        fn done(&mut self) -> Result<(), String> {
            self.calls.push("done".to_owned());
            if self.fail_done {
                Err("the collector is jammed".to_owned())
            } else {
                Ok(())
            }
        }

        fn error(&mut self) -> Result<(), String> {
            self.calls.push("error".to_owned());
            Ok(())
        }
    }

    /// The commands a happy slot carries: select an EF, write one octet at an absolute offset,
    /// then read it back. Every one of them is idempotent, which is what a resume relies on.
    const WRITE: [&str; 3] = [
        "select ADF.USIM",
        "select EF.IMSI",
        "update_binary --offset 0 --data 0102",
    ];
    const VERIFY: &str = "read_binary --offset 0 --length 4";
    /// A command the card refuses: there is no 9999 under the MF.
    const REFUSED: &str = "select 3F00/9999";

    fn slot(number: u32, iccid: &str, commands: &[&str], verify: Option<&str>) -> Slot {
        Slot {
            slot: number,
            iccid: iccid.to_owned(),
            label: None,
            profile: "uicc".to_owned(),
            commands: commands.iter().map(|c| (*c).to_owned()).collect(),
            verify: verify.map(str::to_owned),
            idempotent: true,
        }
    }

    fn plan_of(cards: Vec<Slot>) -> Plan {
        Plan {
            batch: Some("test-batch".to_owned()),
            cards,
        }
    }

    fn options(state: &Path, yes: bool, on_failure: OnFailure) -> Options {
        Options {
            batch: "test-batch".to_owned(),
            state_path: state.to_owned(),
            yes,
            on_failure,
            retry_failed: false,
            reader: None,
        }
    }

    fn read_state(path: &Path) -> State {
        let text = std::fs::read_to_string(path).expect("a state file");
        serde_json::from_str(&text).expect("a state file this build wrote")
    }

    #[test]
    fn a_dry_run_prints_the_plan_for_every_card_and_sends_nothing() {
        let dir = clear("dry");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
        ]);
        let mut script = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_B))),
        ]);
        let mut handler = Recording::default();

        let (code, report) = execute(
            &plan,
            &options(&state, false, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );

        assert_eq!(code, ExitCode::Success);
        assert_eq!(
            script.opens.get(),
            0,
            "a dry run must not even ask the reader for a card"
        );
        assert!(script.sent().is_empty(), "a dry run sends no octet");
        assert!(handler.calls.is_empty(), "a dry run calls no handler");
        assert!(!state.exists(), "a dry run writes no state file");
        assert!(report.dry_run);
        assert_eq!(report.summary.touched, 0);
        assert_eq!(report.cards.len(), 2);
        assert!(report.cards.iter().all(|c| c.state == "planned"));
        assert_eq!(report.cards[0].planned.len(), 3);

        let text = report.to_text();
        assert!(text.contains("DRY RUN"));
        assert!(text.contains("WARNING"));
        assert!(text.contains("dry run: nothing was sent"));
        assert!(text.contains(&plan.cards[0].iccid));
        assert!(text.contains("would send: update_binary"));
        assert!(report.envelope().contains("\"dry_run\":true"));
        assert!(report.envelope().contains("\"state\":\"planned\""));
        assert!(report.envelope().contains("\"kind\":\"batch\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One row per path through the automaton, over a scripted card. Every state a card can
    /// reach, both terminal outcomes and both retryable ones, is a row here.
    #[test]
    fn the_automaton_is_a_table_over_a_scripted_session() {
        struct Case {
            what: &'static str,
            behaviours: fn() -> Vec<Behaviour>,
            commands: Vec<&'static str>,
            verify: Option<&'static str>,
            handler: fn() -> Recording,
            state: &'static str,
            failure: Option<FailureKind>,
            calls: &'static [&'static str],
            done: bool,
        }
        let iccid_a = iccid_of(&CARD_A);
        let cases = [
            Case {
                what: "every command confirmed",
                behaviours: card_a,
                commands: WRITE.to_vec(),
                verify: Some(VERIFY),
                handler: Recording::default,
                state: "released",
                failure: None,
                calls: &["get:first", "done"],
                done: true,
            },
            Case {
                what: "no card in the reader",
                behaviours: no_card,
                commands: WRITE.to_vec(),
                verify: Some(VERIFY),
                handler: Recording::default,
                state: "failed",
                failure: Some(FailureKind::NoCard),
                calls: &["get:first", "error"],
                done: false,
            },
            Case {
                what: "a card whose ICCID cannot be read",
                behaviours: no_iccid,
                commands: WRITE.to_vec(),
                verify: Some(VERIFY),
                handler: Recording::default,
                state: "failed",
                failure: Some(FailureKind::IdentityUnreadable),
                calls: &["get:first", "error"],
                done: false,
            },
            Case {
                what: "a card that is not the card the slot is for",
                behaviours: card_b,
                commands: WRITE.to_vec(),
                verify: Some(VERIFY),
                handler: Recording::default,
                state: "swapped",
                failure: Some(FailureKind::CardSwapped),
                calls: &["get:first", "error"],
                done: false,
            },
            Case {
                what: "a command the card refuses",
                behaviours: card_a,
                commands: vec![REFUSED],
                verify: Some(VERIFY),
                handler: Recording::default,
                state: "failed",
                failure: Some(FailureKind::CommandFailed),
                calls: &["get:first", "error"],
                done: false,
            },
            Case {
                what: "a verification that does not confirm",
                behaviours: card_a,
                commands: WRITE.to_vec(),
                verify: Some(REFUSED),
                handler: Recording::default,
                state: "failed",
                failure: Some(FailureKind::VerifyFailed),
                calls: &["get:first", "error"],
                done: false,
            },
            Case {
                what: "a feeder that delivers nothing",
                behaviours: card_a,
                commands: WRITE.to_vec(),
                verify: Some(VERIFY),
                handler: Recording::failing_get,
                state: "failed",
                failure: Some(FailureKind::HandlerGetFailed),
                calls: &["get:first", "error"],
                done: false,
            },
            Case {
                what: "a collector that jams after the card is programmed",
                behaviours: card_a,
                commands: WRITE.to_vec(),
                verify: Some(VERIFY),
                handler: Recording::failing_done,
                state: "programmed",
                failure: Some(FailureKind::HandlerReleaseFailed),
                calls: &["get:first", "done"],
                done: true,
            },
        ];

        for case in &cases {
            let dir = clear("table");
            let state = dir.join("batch.json");
            let plan = plan_of(vec![slot(1, &iccid_a, &case.commands, case.verify)]);
            let mut script = Script::new((case.behaviours)());
            let mut handler = (case.handler)();
            let (code, report) = execute(
                &plan,
                &options(&state, true, OnFailure::Stop),
                &mut script.factory,
                &mut handler,
            );

            assert_eq!(
                report.cards[0].state, case.state,
                "{}: {:?}",
                case.what, report.cards[0].failure
            );
            assert_eq!(
                handler.calls,
                case.calls
                    .iter()
                    .map(|c| (*c).to_owned())
                    .collect::<Vec<_>>(),
                "handler calls: {}",
                case.what
            );
            assert_eq!(
                report.cards[0].verified, case.done,
                "verified: {}",
                case.what
            );
            assert_eq!(
                report.cards[0].failure.as_ref().map(|f| f.kind),
                case.failure,
                "failure kind: {}",
                case.what
            );
            assert_eq!(
                code,
                if case.failure.is_some() {
                    ExitCode::Findings
                } else {
                    ExitCode::Success
                },
                "exit: {}",
                case.what
            );
            // The state file says the same thing as the report, and it is the record.
            let written = read_state(&state);
            assert_eq!(
                written.record(1).map(|r| r.state.as_str()),
                Some(case.state),
                "state file: {}",
                case.what
            );
            assert_eq!(
                written
                    .record(1)
                    .and_then(|r| r.failure.as_ref().map(|f| f.kind)),
                case.failure,
                "state file failure: {}",
                case.what
            );
            // A card that is never verified is never called programmed.
            assert_eq!(
                written.record(1).is_some_and(|r| r.state.is_done()),
                matches!(case.failure, None | Some(FailureKind::HandlerReleaseFailed)),
                "done: {}",
                case.what
            );
            if case.failure == Some(FailureKind::CardSwapped) {
                assert!(report.stop.is_some(), "a swap ends the run");
                assert!(case.failure.unwrap().hard_stop());
            }
            if let Some(kind) = case.failure {
                assert_eq!(
                    report.stop.as_ref().map(|s| s.kind),
                    Some(kind),
                    "the run stops on {} by default",
                    case.what
                );
            }
            assert!(
                !PathBuf::from(format!("{}.tmp", state.display())).exists(),
                "the atomic replacement left its temporary behind: {}",
                case.what
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_second_card_is_not_asked_to_be_the_first() {
        let dir = clear("first");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
        ]);
        let mut script = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_B))),
        ]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Success);
        assert_eq!(
            handler.calls,
            vec!["get:first", "done", "get", "done"],
            "only the first card of the process is the first card"
        );
        assert_eq!(script.opens.get(), 2);
        assert_eq!(report.summary.programmed, 2);
        assert_eq!(report.summary.touched, 2);
        // Each card got its own session, its own verification and its own identity.
        assert_eq!(script.logs.borrow().len(), 2);
        let state = read_state(&state);
        assert_eq!(state.cards.len(), 2);
        assert!(state.cards.iter().all(|r| r.verified));
        assert_eq!(
            state.cards[0].observed_iccid.as_deref(),
            Some(iccid_of(&CARD_A).as_str()),
            "the record carries the identity the card reported"
        );
        assert_ne!(state.cards[0].observed_iccid, state.cards[1].observed_iccid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_swapped_card_stops_the_run_and_nothing_is_written_to_it() {
        let dir = clear("swapped");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
            slot(3, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
        ]);
        // The feeder puts card A in twice: slot 2 wants B and slot 3 never gets asked.
        let mut script = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
        ]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );

        assert_eq!(code, ExitCode::Findings);
        assert_eq!(script.opens.get(), 2, "the run stops at the swap");
        assert_eq!(report.summary.swapped, 1);
        assert_eq!(report.cards[1].state, "swapped");
        assert_eq!(
            report.cards[1].failure.as_ref().map(|f| f.kind),
            Some(FailureKind::CardSwapped)
        );
        assert_eq!(
            report.cards[1].observed_iccid.as_deref(),
            Some(iccid_of(&CARD_A).as_str()),
            "the record says which card was actually there"
        );
        assert_eq!(report.cards.len(), 2, "slot 3 was never reached");
        assert_eq!(
            report.stop.as_ref().map(|s| s.kind),
            Some(FailureKind::CardSwapped)
        );

        // The swapped card was identified and ejected, never written: no UPDATE BINARY
        // (INS D6) reached it.
        let writes = script
            .sent()
            .into_iter()
            .filter(|apdu| apdu.len() > 3 && apdu[1] == 0xD6)
            .count();
        let per_card = script.sent().len();
        assert!(per_card > 0);
        assert_eq!(
            writes, 1,
            "exactly one card of the two opened was written to, and it was the first"
        );
        let written = read_state(&state);
        assert_eq!(
            written.record(1).map(|r| r.state.as_str()),
            Some("released")
        );
        assert_eq!(written.record(2).map(|r| r.state.as_str()), Some("swapped"));
        assert_eq!(written.record(3), None);
        // `--on-failure continue` does not talk a swap out of stopping the run.
        let mut handler = Recording::default();
        let mut script2 = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
        ]);
        let (_, report2) = execute(
            &plan,
            &options(&state, true, OnFailure::Continue),
            &mut script2.factory,
            &mut handler,
        );
        assert_eq!(
            report2.stop.as_ref().map(|s| s.kind),
            Some(FailureKind::CardSwapped)
        );
        assert_eq!(
            script2.opens.get(),
            1,
            "slot 1 is already programmed, and the swapped slot is asked for again and caught again"
        );
        assert_eq!(
            report2.stop.as_ref().map(|s| s.kind),
            Some(FailureKind::CardSwapped)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_run_interrupted_at_a_card_resumes_at_that_card() {
        let dir = clear("crash");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
            slot(3, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
        ]);
        // What a process killed while slot 2 was being programmed leaves behind: slot 1
        // committed, slot 2 an intent record that claims nothing, slot 3 never reached.
        let mut seed = State::new("test-batch", &plan.fingerprint());
        seed.upsert(Record {
            slot: 1,
            expected_iccid: iccid_of(&CARD_A),
            observed_iccid: Some(iccid_of(&CARD_A)),
            state: CardState::Released,
            steps_planned: 4,
            steps_done: 4,
            verified: true,
            failure: None,
            seq: 0,
        });
        seed.upsert(Record {
            slot: 2,
            expected_iccid: iccid_of(&CARD_B),
            observed_iccid: Some(iccid_of(&CARD_B)),
            state: CardState::InProgress,
            steps_planned: 4,
            steps_done: 1,
            verified: false,
            failure: None,
            seq: 0,
        });
        seed.flush(&state).expect("a state file");
        let before = read_state(&state);
        assert_eq!(before.seq, 1);
        assert_eq!(before.record(2).map(|r| r.steps_done), Some(1));

        let mut script = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_B))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
        ]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );

        assert_eq!(code, ExitCode::Success);
        assert_eq!(
            script.opens.get(),
            2,
            "the committed card is not asked for again"
        );
        assert_eq!(
            report.cards[0].skipped,
            Some("already-programmed"),
            "card 1 is skipped, not reprogrammed"
        );
        assert_eq!(report.summary.already_done, 1);
        assert_eq!(report.summary.programmed, 2);
        assert!(report.cards[1].verified, "the interrupted card is done");
        assert!(report.cards[2].verified);
        let after = read_state(&state);
        assert!(
            after.seq > before.seq,
            "the resume wrote the state file rather than trusting the crash"
        );
        assert!(after
            .cards
            .iter()
            .all(|r| r.state == CardState::Released && r.verified));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_commit_comes_after_the_write_ahead_and_after_the_card_confirmed() {
        let dir = clear("order");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY))]);
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let (code, _) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Success);
        let written = read_state(&state);
        // Three flushes: intent, commit, release.
        assert_eq!(written.seq, 3);
        assert_eq!(written.cards.len(), 1);
        assert!(written.cards[0].verified);
        assert_eq!(written.cards[0].seq, 3);
        assert_eq!(written.batch, "test-batch");
        assert_eq!(written.kind, STATE_KIND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn running_the_same_batch_twice_reports_already_done_and_sends_nothing() {
        let dir = clear("twice");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
        ]);
        let mut first = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_B))),
        ]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut first.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Success);
        assert_eq!(report.summary.programmed, 2);

        let mut second = Script::new(Vec::new());
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut second.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Success);
        assert_eq!(second.opens.get(), 0, "no card is even asked for");
        assert!(second.sent().is_empty());
        assert!(handler.calls.is_empty());
        assert_eq!(report.summary.programmed, 0);
        assert_eq!(report.summary.already_done, 2);
        assert_eq!(report.summary.touched, 0);
        assert!(report
            .cards
            .iter()
            .all(|c| c.skipped == Some("already-programmed")));
        let text = report.to_text();
        assert!(text.contains("skipped: already-programmed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_card_that_failed_is_skipped_until_it_is_told_to_be_retried() {
        let dir = clear("retry");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![slot(1, &iccid_of(&CARD_A), &[REFUSED], Some(VERIFY))]);
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Findings);
        assert_eq!(
            report.cards[0].failure.as_ref().unwrap().kind,
            FailureKind::CommandFailed
        );
        assert!(
            report.cards[0].failure.as_ref().unwrap().sw.is_some(),
            "the card's status word is recorded"
        );

        // A second run does not touch it...
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let (_, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(script.opens.get(), 0);
        assert_eq!(report.cards[0].skipped, Some("failed-earlier"));
        assert_eq!(
            report.summary.failed, 1,
            "the card is still reported as failed"
        );

        // ...until it is told to be retried, and then it is done.
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let mut opts = options(&state, true, OnFailure::Stop);
        opts.retry_failed = true;
        let (code, report) = execute(&plan, &opts, &mut script.factory, &mut handler);
        assert_eq!(
            code,
            ExitCode::Findings,
            "the same refused command fails again"
        );
        assert_eq!(script.opens.get(), 1);
        assert!(report.cards[0].skipped.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failure_continues_only_when_the_plan_says_so() {
        let dir = clear("continue");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &[REFUSED], Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
        ]);
        let mut script = Script::new(vec![
            Behaviour::Card(Box::new(card_with_iccid(&CARD_A))),
            Behaviour::Card(Box::new(card_with_iccid(&CARD_B))),
        ]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Continue),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Findings, "one card failing is still exit 1");
        assert_eq!(
            script.opens.get(),
            2,
            "the second card was still programmed"
        );
        assert_eq!(report.summary.programmed, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.cards[1].state, "released");
        assert!(report.stop.is_none(), "continuing is not a stop");
        let written = read_state(&state);
        assert_eq!(
            written.record(2).map(|r| r.state.as_str()),
            Some("released")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_file_that_cannot_be_read_stops_the_run_instead_of_restarting_it() {
        let dir = clear("corrupt");
        let state = dir.join("batch.json");
        std::fs::write(&state, "{\"kind\": \"sim-doctor-batch-state/1\", \"car")
            .expect("a torn file");
        let plan = plan_of(vec![slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY))]);
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Findings);
        assert_eq!(
            report.stop.as_ref().map(|s| s.kind),
            Some(FailureKind::StateUnreadable)
        );
        assert_eq!(script.opens.get(), 0, "no card is touched");
        assert!(script.sent().is_empty());
        assert!(handler.calls.is_empty());
        assert_eq!(
            std::fs::read_to_string(&state).unwrap(),
            "{\"kind\": \"sim-doctor-batch-state/1\", \"car",
            "the file that could not be read is left exactly as it was"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_file_for_another_plan_is_refused_rather_than_resumed() {
        let dir = clear("mismatch");
        let state = dir.join("batch.json");
        let first = plan_of(vec![slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY))]);
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        execute(
            &first,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        let other = plan_of(vec![slot(
            1,
            &iccid_of(&CARD_A),
            &[WRITE[0], REFUSED],
            Some(VERIFY),
        )]);
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &other,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Findings);
        assert_eq!(
            report.stop.as_ref().map(|s| s.kind),
            Some(FailureKind::PlanMismatch)
        );
        assert_eq!(script.opens.get(), 0);
        assert_eq!(
            read_state(&state).record(1).map(|r| r.steps_planned),
            Some(4),
            "the old state file is untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_slot_that_writes_without_a_verification_is_refused_before_any_card_is_touched() {
        let dir = clear("noverify");
        let state = dir.join("batch.json");
        let plan = plan_of(vec![slot(1, &iccid_of(&CARD_A), &WRITE, None)]);
        assert_eq!(plan.validate().unwrap_err().kind, FailureKind::PlanInvalid);
        let mut script = Script::new(vec![Behaviour::Card(Box::new(card_with_iccid(&CARD_A)))]);
        let mut handler = Recording::default();
        let (code, report) = execute(
            &plan,
            &options(&state, true, OnFailure::Stop),
            &mut script.factory,
            &mut handler,
        );
        assert_eq!(code, ExitCode::Findings);
        assert_eq!(
            report.stop.as_ref().map(|s| s.kind),
            Some(FailureKind::PlanInvalid)
        );
        assert_eq!(script.opens.get(), 0);
        assert!(!state.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plan_is_refused_when_two_slots_share_a_number_or_an_iccid_is_not_digits() {
        let twice = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(1, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
        ]);
        assert_eq!(twice.validate().unwrap_err().kind, FailureKind::PlanInvalid);
        let text = serde_json::to_string(&twice).unwrap();
        assert_eq!(
            Plan::parse(&text).unwrap_err().kind,
            FailureKind::PlanInvalid
        );
        let bad = plan_of(vec![slot(1, "89 01", &WRITE, Some(VERIFY))]);
        assert_eq!(bad.validate().unwrap_err().kind, FailureKind::PlanInvalid);
        let empty = plan_of(vec![]);
        assert_eq!(empty.validate().unwrap_err().kind, FailureKind::PlanInvalid);
    }

    #[test]
    fn a_plan_round_trips_through_its_own_json() {
        let plan = plan_of(vec![
            slot(1, &iccid_of(&CARD_A), &WRITE, Some(VERIFY)),
            slot(2, &iccid_of(&CARD_B), &WRITE, Some(VERIFY)),
        ]);
        let text = serde_json::to_string(&plan).unwrap();
        let parsed = Plan::parse(&text).expect("the plan it wrote");
        assert_eq!(parsed, plan);
        assert_eq!(parsed.fingerprint(), plan.fingerprint());
        assert_ne!(
            parsed.fingerprint(),
            plan_of(vec![slot(1, &iccid_of(&CARD_A), &WRITE, None)]).fingerprint(),
            "a plan that cannot be committed has its own fingerprint"
        );
    }

    #[test]
    fn the_feeder_handler_runs_its_programs_and_reports_a_failure_as_a_kind() {
        let handler = External::parse(
            "get = /bin/true\ndone = /bin/true # the good bin\nerror: /bin/false\n",
        )
        .expect("a handler config with all three commands");
        assert_eq!(handler.program("get"), Some("/bin/true"));
        assert_eq!(handler.program("done"), Some("/bin/true"));
        assert_eq!(handler.program("error"), Some("/bin/false"));
        let mut handler = handler;
        assert!(handler.get(false).is_ok());
        assert!(handler.done().is_ok());
        let failure = handler.error().expect_err("a feeder that answers non-zero");
        assert!(failure.contains("error"), "{failure}");
        assert!(failure.contains("exit 1"), "{failure}");

        assert!(
            External::parse("get = /bin/true").is_err(),
            "done and error are required"
        );
        assert!(External::parse("").is_err());
        let mut missing =
            External::parse("get = /bin/nowhere\ndone = /bin/true\nerror = /bin/true\n")
                .expect("a config");
        let failure = missing
            .get(false)
            .expect_err("a program that is not there is a handler failure, not a card failure");
        assert!(failure.contains("/bin/nowhere"), "{failure}");
    }

    #[test]
    fn the_warning_says_a_batch_can_leave_cards_partly_programmed() {
        assert!(WARNING.contains("some cards programmed and others not"));
        assert!(WARNING.contains("only record of which"));
        assert!(WARNING.contains("written a second time"));
        assert!(KIND.starts_with("batch"));
    }

    /// The table in the module docs and [`TRANSITIONS`] are the same table: a state, a kind or a
    /// transition added to one and not the other fails here.
    #[test]
    fn the_documented_table_and_the_transition_list_agree() {
        let source = include_str!("batch.rs");
        let docs = source
            .split("use std::collections")
            .next()
            .expect("the module docs");
        for state in CardState::ALL {
            assert!(
                docs.contains(&format!("| `{}` |", state.as_str()))
                    || docs.contains(&format!("`{}`", state.as_str())),
                "the docs do not mention `{}`",
                state.as_str()
            );
        }
        for kind in FailureKind::ALL {
            assert!(
                docs.contains(kind.as_str()),
                "the docs do not mention `{}`",
                kind.as_str()
            );
        }
        for transition in TRANSITIONS {
            let rows: Vec<&str> = docs
                .lines()
                .map(|line| line.strip_prefix("//! ").unwrap_or(line))
                .filter(|line| line.starts_with(&format!("| `{}` |", transition.from.as_str())))
                .collect();
            assert!(
                !rows.is_empty(),
                "no documented row starts at `{}`",
                transition.from.as_str()
            );
            assert!(
                rows.iter()
                    .any(|row| row.contains(&format!("`{}`", transition.to.as_str()))
                        && transition
                            .failure
                            .is_none_or(|kind| row.contains(kind.as_str()))
                        && (transition.handler.is_empty()
                            || rows.iter().any(|row| {
                                row.contains(&format!("`{}`", transition.handler))
                                    || row.contains(&format!("`{}(", transition.handler))
                            }))),
                "no documented row for `{}` reaches `{}` with its handler and kind: {rows:?}",
                transition.from.as_str(),
                transition.to.as_str()
            );
        }
        // A state is terminal exactly when no transition leaves it for more of the run.
        for state in CardState::ALL {
            let leaves = TRANSITIONS.iter().any(|t| t.from == state && !t.terminal);
            assert_eq!(state.terminal(), !leaves, "{:?}", state);
        }
    }

    #[test]
    fn the_profile_set_and_the_split_of_a_slot_are_what_the_run_sends() {
        let slot = slot(1, &iccid_of(&CARD_A), &["a; b", "  ", "c"], Some(VERIFY));
        assert_eq!(slot.steps(), vec!["a", "b", "c"]);
        assert_eq!(slot.step_count(), 4);
        assert_eq!(slot.card_profile(), Profile::Uicc);
        let mut sim = slot.clone();
        sim.profile = "sim".to_owned();
        assert_eq!(sim.card_profile(), Profile::Sim);
    }
}
