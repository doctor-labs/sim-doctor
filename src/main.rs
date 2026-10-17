//! `sim-doctor` as a binary.
//!
//! Every line here is a view: parse arguments, ask the library for a value,
//! put it on stdout, exit. Nothing in this file decides what a module owns,
//! what the JSON looks like, or which exit code means what - those live in
//! the library, where they can be tested without a terminal.
//!
//! This is also the only place in the crate that writes to stdout, and AGENTS.md
//! section 3 makes that a hard rule: under `--json`, stdout carries one JSON
//! envelope and not one byte else. Three things enforce it structurally here:
//!
//! - **Every diagnostic goes to stderr.** [`eprintln!`] for anything a human
//!   reads, [`init_diagnostics`] for anything a library module logs. There is
//!   no path from this file to `println!` any more: [`emit_stdout`] returns its
//!   error instead of panicking, which is what `tests/process_contract.rs` uses
//!   to reach exit code 1.
//! - **Output is assembled, then written once.** Nothing is printed while it is
//!   being built, so a half-formed envelope cannot reach stdout.
//! - **An interrupted run still emits exactly one envelope**, carrying code 130.
//!   See [`report_interrupted`] and `contract::INTERRUPTED_MESSAGE`.

use std::env;
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::aot::generate;
mod card_cmd;
mod kit;

use sim_doctor::{
    apdu_fuzz, apdu_scan, cat, cert, ci, contract, euicc, fix, fuzz, gp, notif, ota_expanded,
    otacrypto, rules, saip, scan, session, sms, tar, trace,
    transport::{
        pcsc::{share_mode, Pcsc, PcscSession},
        replay, CardSession, Error as TransportError, ReaderName, ReaderProvider,
    },
    ts48,
    walk::{self, Limits},
    MODULES,
};

/// The `type` every `modules` envelope carries.
///
/// Named once so the interrupted envelope cannot drift from the successful
/// one. `modules` is a self-description rather than a scan, but it is the
/// discriminator the crate has always emitted for it (see
/// `contract::DEFAULT_KIND`); changing it is a contract change and not this
/// issue's business.
const MODULES_KIND: &str = contract::DEFAULT_KIND;

/// Set by `tests/process_contract.rs` to park the process at its first
/// interrupt checkpoint, in milliseconds.
///
/// A SIGINT can only be tested by sending one, and a signal can only be sent to
/// a process that is still running. `modules` finishes in well under a
/// millisecond and `scan` spends most of its time on the wire, so without this
/// the test would be a race between the signal and the exit - and a race that
/// passes on a fast machine fails on a loaded CI runner. With it, the process is
/// provably parked when the signal arrives.
///
/// Unset in every normal invocation. When unset this costs one failed
/// environment lookup and nothing else, and the checkpoint behaves exactly as
/// it would without it.
#[cfg(feature = "test-seams")]
const SIGNAL_HOLD_ENV: &str = "SIM_DOCTOR_TEST_SIGNAL_HOLD_MS";

/// The phrase [`SIGNAL_HOLD_ENV`] announces on stderr once the process is
/// parked with its handler installed.
///
/// The test waits for this line before sending SIGINT. That handshake is the
/// whole reason the SIGINT test is deterministic rather than merely usually
/// right: a signal delivered before `install()` returns hits the kernel's
/// default disposition and kills the process, which is indistinguishable in a
/// shell from the exit status we are trying to prove but is a different thing
/// entirely.
#[cfg(feature = "test-seams")]
const PARKED_MARKER: &str = "parked at the interrupt checkpoint";

/// Whether this process has already parked at a checkpoint.
///
/// `scan` has more than one checkpoint, and a test that sets
/// [`SIGNAL_HOLD_ENV`] and does not get its signal through in time would
/// otherwise wait out the whole hold at every one of them - two checkpoints
/// multiplied by thirty seconds, on a run that was going to be interrupted at
/// the first. Parking once makes the hold mean "the first checkpoint", which is
/// what the tests that set it actually mean.
#[cfg(feature = "test-seams")]
static PARKED_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test-only, and only honoured together with [`SIGNAL_HOLD_ENV`]: after parking,
/// block this thread forever instead of polling the interrupt flag, standing in
/// for a PC/SC transmit that never returns. Unset in every normal invocation.
#[cfg(feature = "test-seams")]
const WEDGE_ENV: &str = "SIM_DOCTOR_TEST_WEDGE";

/// How long a card command gets to unwind on its own after SIGINT/SIGTERM
/// before [`guard_exchange`] ends the process (issue #88).
///
/// Long enough for a transmit in flight to return and reach a checkpoint
/// (the safe order, see `doctor_kit::interrupt::install`), short enough to be "within seconds".
const INTERRUPT_GRACE: Duration = Duration::from_secs(3);

/// Set once an interrupted envelope has been written, so the watchdog and the
/// normal checkpoint path can never both write one.
static INTERRUPT_REPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Parser)]
#[command(
    name = "sim-doctor",
    version,
    about = "CLI-first SIM/UICC security testing tool",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Describe the crate module roots and the layering between them.
    Modules(ModulesArgs),

    /// List the PC/SC readers by name and index, for --reader or --reader-index.
    ///
    /// Needs no card. Indices run from 0 in the order PC/SC reports the readers.
    /// Exit 2 when the PC/SC service cannot be reached.
    Readers(ReadersArgs),

    /// Select a card's master file, walk everything under it, and report.
    ///
    /// Opens a real PC/SC session against one reader, selects the master file
    /// (3F00), probes every candidate file identifier underneath it, descends
    /// into the directories the card itself describes, and reports what it
    /// found - as a table for a person, or as one JSON envelope under --json.
    ///
    /// # What a clean result does and does not mean
    ///
    /// Truncation is always reported. A walk that hit one of its bounds did
    /// not see the whole card, and the output says so in three places: the
    /// "TRUNCATED" banner is the first line of the human report, and the JSON
    /// carries "complete", "truncated", "truncated_by" and the full "limits_hit"
    /// list. A file list without those is a file list an agent could read as the
    /// card's complete contents, which is a silent under-report of the attack
    /// surface.
    ///
    /// The default dialect and the default candidate set can both
    /// under-report. Both are reported in the output, and --dialect exists so
    /// the choice is yours rather than this tool's. See --dialect and the note
    /// under --max-children.
    ///
    /// Exit codes (doctor/1): 0 no finding at or above --fail-on, 1 at least
    /// one, 2 usage error or the scan could not run, 3 a new finding against
    /// --baseline, 130 if you interrupt it.
    #[command(long_about = SCAN_LONG_ABOUT)]
    Scan(ScanArgs),

    /// Compare a card against the public GSMA TS.48 test profile.
    Ts48(Ts48Args),

    /// Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project.
    ///
    /// Teaches a coding agent to run `sim-doctor scan --json` and read the
    /// envelope. Writes `.claude/skills/sim-doctor/SKILL.md`,
    /// `.cursor/rules/sim-doctor.mdc` and a marked block in `AGENTS.md`
    /// (replaced in place on re-run; the rest of the file is untouched).
    Install(InstallArgs),

    /// Write the GitHub Actions workflow that runs this repo's action on pull requests.
    Ci(CiArgs),

    /// Write a shell completion script to stdout.
    ///
    /// The script names every subcommand and flag this binary has, including
    /// the ones whose behaviour is not implemented yet: an agent completing
    /// "sim-doctor scan --" should be able to see the whole contract, not the
    /// half of it that works today.
    ///
    ///     sim-doctor completions zsh > ~/.local/share/zsh/completions/_sim-doctor
    ///     sim-doctor completions bash > /etc/bash_completion.d/sim-doctor
    ///
    /// The script IS the document here, so it is written to stdout and nothing
    /// else is. It is not JSON, so --json does not apply to this subcommand.
    Completions(CompletionsArgs),

    /// Serve the scan and the rules as MCP tools over stdio.
    ///
    /// Needs no card to start. stdout carries JSON-RPC lines and nothing else.
    Mcp,

    /// List the rules a scan runs, or explain one, without a card.
    ///
    /// With no subcommand this is `rules list`.
    Rules(RulesArgs),

    /// Explain a rule, or every rule in a saved `scan --json` envelope.
    ///
    /// The argument is a rule id (like `rules explain`) or the path of an
    /// existing file holding a saved `sim-doctor scan --json` envelope. There
    /// is no persisted "last scan": save one with `scan --json > scan.json`.
    Why(WhyArgs),

    /// Hand one finding from a saved scan to a coding agent.
    ///
    /// Prints a prompt as plain text on stdout (not JSON) and exits 0. With
    /// --agent it also starts that agent with the prompt; the agent keeps its own
    /// approval prompts unless --skip-approvals (or SIM_DOCTOR_HANDOFF_SKIP_APPROVALS=1).
    /// Nothing is launched when already inside a coding agent. FILE is a saved
    /// `sim-doctor scan --json` envelope, like `why` reads.
    Fix(FixArgs),

    /// Read-only GlobalPlatform queries.
    ///
    /// Sends SELECT, GET RESPONSE and GET DATA only. Never an authenticating
    /// or writing command.
    Gp(GpArgs),

    /// Decode a captured APDU trace offline (no card, no reader).
    ///
    /// Reads hex lines (alternating command, response), our own `--trace`
    /// JSON, or a pcap/pcapng capture of GSMTAP SIM APDUs (UDP 4729, as from
    /// SIMtrace2 or pySim-trace; detected automatically) from FILE or stdin,
    /// names each command, tracks the selected file and explains each status
    /// word.
    Trace(TraceArgs),

    /// Decode Card Application Toolkit data offline (no card, no reader).
    ///
    /// `cat decode` names and decodes a proactive command (a FETCH response, starts with D0), an
    /// ENVELOPE (D1..DF), a TERMINAL RESPONSE or a bare run of comprehension TLVs: 44 command types,
    /// 14 envelope tags, 90 information elements, result codes and devices; the fields of the
    /// elements a review reads are decoded and the rest are shown as hex, named.
    Cat(CatArgs),
    /// `sms decode` decodes SMS TPDUs offline (TS 23.040): SMS-DELIVER, SMS-SUBMIT and STATUS-REPORT,
    /// addresses, DCS, the user-data header and concatenation, GSM 7-bit and UCS2 text. Sends nothing.
    Sms(SmsArgs),

    /// `saip parse` decodes a SIMalliance eUICC profile package (SAIP, the DER ProfileElement
    /// sequence) offline into JSON: each element named by its PE type, the rest a bounded TLV
    /// tree. Parse only, no personalization. Sends nothing.
    Saip(SaipArgs),

    /// Offline OTA ciphers and checksums (DES, 3DES, AES-CBC encrypt/decrypt,
    /// CBC-MAC / AES-CMAC sign and check), as pySim's OTA layer uses them.
    /// No card and no reader: pure crypto over hex given on the command line.
    #[command(name = "ota-crypto")]
    OtaCrypto(OtaCryptoArgs),

    /// Verify an eSIM certificate chain offline, up to a CI root you supply.
    ///
    /// Checks each certificate's signature under the next certificate in the chain (the last one under
    /// --root), that each issuer name matches, and reports every certificate's validity period and KeyUsage.
    /// Input is PEM with CERTIFICATE blocks or concatenated DER, leaf first; each file is capped at 1 MiB and
    /// must be a regular file. Touches no card and no network.
    ///
    /// Only ecdsa-with-SHA256 over NIST P-256 is verified. A brainpool certificate (GSMA CIs often use
    /// BrainpoolP256r1) or an RSA one is reported as unsupported, never as verified, so a chain that uses one
    /// fails the verdict until a verifier for that algorithm is added.
    ///
    /// Exit 0 only when every signature verifies and every certificate is inside its validity period at the
    /// check time. A chain that verifies but is expired or not yet valid exits 1 with verdict
    /// verified-but-out-of-validity.
    #[command(name = "esim-cert")]
    EsimCert(EsimCertArgs),
    /// Offline OTA expanded-command and Proof-of-Response decoder, as pySim's OTA layer uses them.
    /// No card and no reader: hex in, hex out.
    ///
    /// `ota-expanded encode` builds a Command Scripting template (TS 102 226 5.2.1) around one or
    /// more C-APDUs, in the definite (tag AA) or the indefinite (AE 80 ... 00 00) length coding,
    /// adding no Le and changing no C-APDU. `ota-expanded decode` reads a Response Scripting
    /// template (5.2.2) of either coding, names every R-APDU, the Bad format, Immediate Action
    /// and Script Chaining TLVs, and says whether the card truncated the response. `ota-expanded
    /// por` reads a Proof-of-Response Response Packet (TS 102 225 table 5, TS 31.115), with or
    /// without the SMS `02 71 00` user data header. Nothing is deciphered and no CC/RC is
    /// verified: this command takes no key.
    #[command(name = "ota-expanded")]
    OtaExpanded(OtaExpandedArgs),

    /// APDU discovery and the OTA/SMS fuzz sweep.
    ///
    /// REFUSES to run unless BOTH --i-understand-this-can-brick-the-card is
    /// given AND the reader's name matches the software card (swicc-pcsc
    /// names its reader with "swICC"; see docs/swsim-fixture.md), or
    /// --allow-real-hardware is also given. A fuzz run sends ENVELOPE and
    /// undocumented CLA/INS combinations, either of which can brick a real
    /// SIM; this crate will not run one against hardware by accident.
    ///
    /// Exit codes: 0 when the run finished, 1 when it could not (including
    /// the opt-in refusal, error kind fuzz-needs-opt-in), 129 for a bad
    /// command line, 130 if interrupted.
    Fuzz(FuzzArgs),

    /// eUICC queries over ES10 (lpac: chip info, profile list, notification list), and the profile and notification writes.
    ///
    /// Opens a logical channel, selects the ISD-R by AID, sends STORE DATA
    /// requests, and closes the channel. info, profiles and notifications only
    /// read. `nickname`, `enable`, `disable`, `delete`, `reset` and
    /// `notifications remove` are the writes: dry runs unless --yes (`reset` also
    /// needs --confirm-eid). `notifications dump` retrieves (read-only), `notifications
    /// replay` reaches the network (dry run unless --yes). The output is the
    /// lpac envelope under --json. Exit codes: 0 answered, 1 the card is not an
    /// eUICC, refused, or answered something malformed (the envelope carries
    /// `data.error.kind`), 129 for a bad command line, 130 if interrupted.
    Euicc(EuiccArgs),

    /// A pySim-shell style shell over the card: select files, read them, send APDUs.
    ///
    /// The shell keeps the equipped card, the logical channel and the selected file between
    /// commands. Interactive on a terminal; `-c "a; b"` or `--script FILE` for scripts; `--json`
    /// prints one record per command. Reads are sent; every command that changes the card is a
    /// dry run (it prints the APDU it would send) unless `--yes`. Type `help` inside.
    /// Exit codes: 0 every command worked, 1 at least one failed, 2 the card could not be opened,
    /// 129 for a bad command line.
    Card(card_cmd::CardShellArgs),
}

/// Everything `sim-doctor euicc` takes.
#[derive(Args)]
struct EuiccArgs {
    #[command(subcommand)]
    action: EuiccAction,
}

#[derive(Subcommand)]
enum EuiccAction {
    /// EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`).
    Info(EuiccFlags),
    /// Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`).
    Profiles(EuiccFlags),
    /// GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7): the 16-byte challenge a
    /// profile download signs over (pySim `get_euicc_challenge`). Read-only.
    Challenge(EuiccFlags),
    /// Pending notification metadata (lpac `notification list`); `dump` and `replay` below;
    /// `notifications remove <seq>` removes one.
    Notifications(NotificationsArgs),
    /// Set a profile's nickname (lpac `profile nickname`). A write: a dry
    /// run unless `--yes`, never exposed over MCP.
    Nickname(NicknameArgs),
    /// Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH).
    /// A dry run unless `--yes`: switches the active profile and the device
    /// loses its connection until it re-attaches. Never exposed over MCP.
    Enable(StateArgs),
    /// Disable a profile (lpac `profile disable`, ES10c DisableProfile with
    /// REFRESH). A dry run unless `--yes`: disabling the only enabled profile
    /// leaves no active profile. Never exposed over MCP.
    Disable(StateArgs),
    /// Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run
    /// unless `--yes`: the profile is erased permanently and can only come back
    /// by downloading it again from the operator. An enabled profile is refused.
    /// Never exposed over MCP.
    Delete(DeleteArgs),
    /// Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can
    /// erase every profile: nothing is selected by default, and sending needs
    /// both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP.
    Reset(ResetArgs),
    /// Set the default SM-DP+ address (ES10a SetDefaultDpAddress, SGP.22
    /// v2.5 clause 5.7.4). A write: a dry run that opens no reader unless
    /// `--yes`, and it changes where the eUICC looks for profiles. Never
    /// exposed over MCP.
    #[command(after_help = euicc::DEFAULT_DP_WARNING)]
    SetDefaultDp(DefaultDpArgs),
}

/// Everything `sim-doctor euicc notifications` takes: the list, or `remove`.
#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
struct NotificationsArgs {
    #[command(subcommand)]
    action: Option<NotificationAction>,
    #[command(flatten)]
    flags: EuiccFlags,
}

#[derive(Subcommand)]
enum NotificationAction {
    /// Remove a notification from the eUICC's list (lpac `notification remove`,
    /// ES10b RemoveNotificationFromList). A dry run unless `--yes`: a removed
    /// notification is never sent to the operator's server. Never exposed over MCP.
    Remove(RemoveArgs),
    /// Read the full signed pending notifications (lpac `notification dump`,
    /// ES10b RetrieveNotificationsList) as a re-loadable JSON document: hex of
    /// the signed bytes plus the decoded sequence number, operation, address
    /// and ICCID. Read-only: nothing is removed. Without `-o` and `--json` the
    /// document itself is printed. Never exposed over MCP.
    Dump(DumpArgs),
    /// Send the notifications of a dump file to their operators (ES9+
    /// HandleNotification over HTTPS). A dry run unless `--yes`: this reaches
    /// the network and tells the operator's server about a profile event. Needs
    /// no card and removes nothing. Never exposed over MCP.
    Replay(ReplayArgs),
}

/// Everything `sim-doctor euicc notifications dump` takes.
#[derive(Args)]
struct DumpArgs {
    /// Only the notification with this sequence number (default: all pending).
    #[arg(long, value_name = "N")]
    seq: Option<u32>,
    /// Write the dump document to FILE (must not exist) instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<std::path::PathBuf>,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc notifications replay` takes.
#[derive(Args)]
struct ReplayArgs {
    /// A dump file written by `notifications dump` (or its `--json` output).
    #[arg(long, value_name = "FILE")]
    from: std::path::PathBuf,
    /// Actually send. Without it nothing leaves this machine: the targets and
    /// what would be sent are printed.
    #[arg(long)]
    yes: bool,
    /// Emit one lpac envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor euicc notifications remove` takes.
#[derive(Args)]
struct RemoveArgs {
    /// Sequence number of the notification, as `euicc notifications` lists it.
    seq: u32,
    /// Send the request, then re-read the list and confirm. Without it
    /// nothing is changed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc delete` takes.
#[derive(Args)]
struct DeleteArgs {
    /// ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile.
    id: String,
    /// Send DeleteProfile, then re-read the profile list and confirm. Without
    /// it nothing is changed: the profile and its consequence are printed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc reset` takes.
#[derive(Args)]
struct ResetArgs {
    /// Delete the operational profiles (resetOptions bit 0).
    #[arg(long)]
    operational: bool,
    /// Delete the field-loaded test profiles (resetOptions bit 1).
    #[arg(long)]
    test: bool,
    /// Reset the default SM-DP+ address (resetOptions bit 2).
    #[arg(long)]
    smdp_address: bool,
    /// The card's EID (32 hex digits); must match the EID read from the card.
    #[arg(long, value_name = "EID")]
    confirm_eid: Option<String>,
    /// Send the reset (needs `--confirm-eid`), then re-read and confirm.
    /// Without it nothing is changed: the profiles that would be erased are listed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc set-default-dp` takes.
#[derive(Args)]
struct DefaultDpArgs {
    /// The new default SM-DP+ address, as a UTF-8 string.
    #[arg(value_name = "ADDRESS", allow_hyphen_values = true)]
    address: String,
    /// Send SetDefaultDpAddress, then re-read the configured addresses and
    /// confirm. Without it nothing is sent and no reader is opened: the exact
    /// request bytes are printed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc enable` and `disable` take.
#[derive(Args)]
struct StateArgs {
    /// ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile.
    id: String,
    /// Send the request, then re-read the profile list and confirm. Without
    /// it nothing is changed: the plan and its consequence are printed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc nickname` takes.
#[derive(Args)]
struct NicknameArgs {
    /// ICCID of the profile (18 to 20 digits).
    iccid: String,
    /// The new nickname, at most 64 bytes of UTF-8; "" clears it.
    #[arg(allow_hyphen_values = true)]
    name: String,
    /// Send SetNickname, then re-read the profile list and confirm. Without
    /// it nothing is changed: the target EID and ICCID, the current and the
    /// new nickname are printed and the command exits.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Flags every `euicc` subcommand shares.
#[derive(Args)]
struct EuiccFlags {
    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,
    /// Emit one lpac envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,
    /// ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100).
    #[arg(long, value_name = "HEX")]
    aid: Option<String>,
    /// Most data bytes in one STORE DATA block, 1 to 255 (default 120, as
    /// lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks.
    #[arg(long, value_name = "BYTES", default_value_t = 120, value_parser = clap::value_parser!(u16).range(1..=255))]
    max_segment: u16,
}

/// Everything `sim-doctor fuzz` takes.
#[derive(Args)]
struct FuzzArgs {
    #[command(subcommand)]
    action: FuzzAction,
}

#[derive(Subcommand)]
enum FuzzAction {
    /// CLA discovery (level 1) or CLA+INS discovery (level 2) over a session.
    ///
    /// Every candidate is sent as a CASE 1 header (CLA INS 00 00, no data):
    /// discovery never carries a payload. Classified by status word: 6E00 is
    /// "class not supported", 6D00 is "instruction not supported", anything
    /// else reached a handler and is reported interesting.
    Apdu(FuzzApduArgs),

    /// The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR
    /// scanner's ENVELOPE builder.
    Ota(FuzzOtaArgs),

    /// Allowlist-only APDU mutation fuzzer, against a replay log or the
    /// built-in mock card only (no reader).
    ///
    /// Generates malformed variations of SELECT, READ BINARY, READ RECORD,
    /// STATUS, GET DATA, GET RESPONSE and unassigned INS values; nothing else
    /// can be generated. Every APDU and status word is in the report; a card
    /// answering success to a command the spec says to reject is a
    /// fuzz/malformed-command-accepted finding. --dry-run prints the plan and
    /// sends nothing. Running this against a real reader is not implemented.
    Mutate(FuzzMutateArgs),

    /// Compares two or more `fuzz ota` JSON results: keysets ranked by how
    /// often the card accepted under them, and the (TAR, keyset, mechanism)
    /// triples the runs disagree on. Offline and read-only: it reads result
    /// files and sends nothing. Only triples every run probed are compared.
    Compare(FuzzCompareArgs),
}

/// Everything `sim-doctor fuzz compare` takes.
#[derive(Args)]
struct FuzzCompareArgs {
    /// Two or more `fuzz ota --json` result files, each at most 8 MiB.
    #[arg(required = true, num_args = 2.., value_name = "RESULT_FILE")]
    files: Vec<std::path::PathBuf>,

    /// Emit one JSON envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor fuzz mutate` takes.
#[derive(Args)]
struct FuzzMutateArgs {
    /// Answer from a recorded exchange log (one {"command","response"} JSON
    /// object per line, as SIM_DOCTOR_RECORD writes) instead of a card.
    #[arg(long, value_name = "FILE", conflicts_with = "mock")]
    replay: Option<std::path::PathBuf>,

    /// Answer from the built-in strict mock card.
    #[arg(long)]
    mock: bool,

    /// Cases to send (1 to 10000).
    #[arg(long, default_value_t = apdu_fuzz::DEFAULT_MAX_CASES, value_name = "N")]
    max_cases: usize,

    /// Stop sending after this many seconds.
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// PRNG seed. The same seed gives the same APDUs.
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Print the planned APDUs and the allowlist/denylist; send nothing.
    #[arg(long)]
    dry_run: bool,

    /// Stop after the first finding.
    #[arg(long)]
    stop_on_first_finding: bool,

    /// Emit one JSON envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,
}

/// Flags every `fuzz` subcommand shares: the safety interlock and the reader.
#[derive(Args, Clone)]
struct FuzzSafety {
    /// Required. Without it, `fuzz` refuses to run at all (exit 1, error
    /// kind fuzz-needs-opt-in).
    #[arg(long = "i-understand-this-can-brick-the-card")]
    i_understand: bool,

    /// Required in addition to the opt-in above when the reader's name does
    /// not match the software card (swicc-pcsc names its reader with
    /// "swICC"). Without it, `fuzz` refuses to run against anything that is
    /// not recognisably the software card.
    #[arg(long = "allow-real-hardware")]
    allow_real_hardware: bool,

    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// Emit one JSON envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,

    /// Probe a small, documented subset instead of the full space.
    #[arg(long)]
    quick: bool,
}

/// Everything `sim-doctor fuzz apdu` takes.
#[derive(Args)]
struct FuzzApduArgs {
    #[command(flatten)]
    safety: FuzzSafety,

    /// 1 for CLA discovery, 2 for CLA+INS discovery.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=2))]
    level: u8,

    /// The CLA level 2 probes INS values at, as two hex digits (e.g. A0).
    /// Required for --level 2.
    #[arg(long, value_name = "HEX")]
    class: Option<String>,
}

/// Everything `sim-doctor fuzz ota` takes.
#[derive(Args)]
struct FuzzOtaArgs {
    #[command(flatten)]
    safety: FuzzSafety,

    /// Like `--quick`, but probes only the three TARs SIMTester's `-poke`
    /// probes: 000000, B00001 and B00010 - the quick keysets and mechanisms
    /// still apply, so a run finishes in milliseconds.
    #[arg(long, conflicts_with = "quick")]
    poke: bool,
}

/// Everything `sim-doctor gp` takes.
#[derive(Args)]
struct GpArgs {
    #[command(subcommand)]
    action: GpAction,
}

#[derive(Subcommand)]
enum GpAction {
    /// Select the issuer security domain and read CPLC, card data, key
    /// information, IIN and CIN with GET DATA.
    ///
    /// Exit 0 when an ISD answered, 1 when none did (the envelope still carries
    /// the status words), 129 for a bad command line.
    Info {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        channel: GpChannelArg,
    },
    /// Select the ARA-M (Access Rule Application Master) and read every access
    /// rule with GET DATA [all], decoded (read-only, no keys).
    ///
    /// Exit 0 when the ARA-M answered, 1 when it did not.
    Ara {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        channel: GpChannelArg,
    },
    /// GlobalPlatform registry inventory: GET STATUS for the ISD, applications
    /// and load files, plus Card Recognition Data (read-only). A scope
    /// the card only gives over a secure channel is reported as requiring
    /// authentication.
    ///
    /// With --keys-file or --keys-env the registry is read over an SCP03 secure
    /// channel (C-MAC) opened with ONE authentication attempt.
    ///
    /// The key text is `ENC [MAC [DEK]]`, 32 hex digits each (AES-128), split by
    /// spaces, commas or newlines; one key means ENC = MAC. A key may be written
    /// KEY/KCV (6 hex digits); a wrong KCV stops the run before the card is
    /// touched. Keys are never taken from the command line and never printed.
    /// Failed attempts count toward locking the ISD, so there is no retry, and the
    /// card cryptogram is checked locally first: wrong keys stop with "keys do not
    /// match this card" and EXTERNAL AUTHENTICATE is not sent.
    ///
    /// --list prints the registry as a table and --info one block per entry
    /// (read-only text over the same GET STATUS data; no new APDUs). Neither
    /// combines with --json.
    ///
    /// Exit 0 when an ISD answered, 1 when none did or authentication stopped.
    Status {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long, conflicts_with_all = ["list", "info"])]
        json: bool,
        /// Print the registry as a table: scope, AID, lifecycle, privileges.
        #[arg(long, conflicts_with = "info")]
        list: bool,
        /// Print each registry entry in detail, with its raw lifecycle and privilege bytes.
        #[arg(long)]
        info: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        channel: GpChannelArg,
        #[command(flatten)]
        keys: GpKeyArgs,
    },
    /// SELECT a GlobalPlatform (or any) application by AID and report the status
    /// word and the FCI. Read-only, no keys; it only changes the card's current
    /// selection.
    ///
    /// Exit 0 when the application answered 90 00, 1 when it did not.
    Select {
        /// The application AID, 5 to 16 bytes of hex.
        #[arg(long, value_name = "HEX")]
        aid: String,
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        channel: GpChannelArg,
    },
    /// Contactless Registry Service (CRS, GlobalPlatform Amendment C): list the
    /// applications held for contactless, read the service version and event
    /// counter, and activate or deactivate one application for contactless.
    ///
    /// The reads need no keys. activate and deactivate CHANGES CARD STATE: a
    /// dry run unless --yes, which needs --keys-file or --keys-env.
    Crs {
        #[command(subcommand)]
        action: CrsAction,
    },
    /// Open or close a supplementary logical channel (MANAGE CHANNEL). A channel
    /// stays open on the card until it is closed or the card loses power, and
    /// the other gp commands can then run on it with --channel N.
    Channel {
        #[command(subcommand)]
        action: GpChannelAction,
    },
    /// Delete an application or an executable load file over an SCP03 channel
    /// (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT.
    ///
    /// A dry run unless --yes: it prints the target and the exact APDUs and
    /// sends nothing. With --keys-file/--keys-env the dry run also makes the one
    /// SCP03 authentication attempt and reads the registry, and the command
    /// refuses (nothing sent) when the AID is not present, is the issuer security
    /// domain, or the registry cannot be read. --yes needs keys. The ISD keys are
    /// read from a file or environment variable, never the command line, and are
    /// never printed. Not available over MCP.
    ///
    /// Exit 0 for a dry run or a verified delete, 1 for a refusal, a card error or
    /// a delete the registry does not confirm.
    Delete {
        /// The AID to delete, 5 to 16 bytes of hex.
        #[arg(long, value_name = "HEX")]
        aid: String,
        /// Also delete related objects (P2 80): for a load file, its applications.
        #[arg(long)]
        related: bool,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Make an installed application Default Selected over an SCP03 channel:
    /// INSTALL [for make selectable] with the Card Reset privilege (GlobalPlatform
    /// Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT.
    ///
    /// A dry run unless --yes (offline without keys), with the same safeguards as
    /// delete: one authentication attempt, a registry pre-read that refuses an AID
    /// that is absent, is the issuer security domain or is not an application.
    /// --yes needs keys. Keys come from a file or environment variable, never the
    /// command line. Not available over MCP.
    MakeDefault {
        /// The application AID, 5 to 16 bytes of hex.
        #[arg(long, value_name = "HEX")]
        aid: String,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Rename the Issuer Security Domain over an SCP03 channel: STORE DATA `4F LEN
    /// AID` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT.
    ///
    /// WARNING: this can lock you out. The old ISD AID no longer selects the ISD,
    /// so a mistyped or unrecorded new AID leaves administrative access reachable
    /// only by the new AID. A dry run unless --yes (offline without keys), which
    /// prints the warning and the exact APDU; the pre-read refuses an AID already
    /// in the registry. --yes needs keys, read from a file or environment variable,
    /// never the command line. Not available over MCP.
    RenameIsd {
        /// The new ISD AID, 5 to 16 bytes of hex.
        #[arg(long, value_name = "HEX")]
        new_aid: String,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Delete a key from the issuer security domain over an SCP03 channel
    /// (DELETE KEY, GlobalPlatform Card Spec v2.3.1 11.2.2). CHANGES CARD
    /// STATE.
    ///
    /// At least one of --key-id or --key-version must be given: with both, one
    /// key is deleted; with either, every matching key is deleted. CAN
    /// PERMANENTLY LOCK THE CARD'S ADMINISTRATIVE ACCESS — deleting the key
    /// version this session authenticated with, or the only key of a type the
    /// card expects, has no recovery.
    ///
    /// A dry run unless --yes: it prints the target and the exact APDUs and
    /// sends nothing. With --keys-file/--keys-env the dry run also makes the one
    /// SCP03 authentication attempt and reads the key information, and the
    /// command refuses (nothing sent) when the key is not present or the key
    /// information cannot be read. --yes needs keys. The ISD keys are read from
    /// a file or environment variable, never the command line, and are never
    /// printed. Not available over MCP.
    ///
    /// Exit 0 for a dry run or a verified delete, 1 for a refusal, a card error
    /// or a delete the key information does not confirm.
    DeleteKey {
        /// The Key Identifier to delete (GP tag D0). If absent, every key id
        /// matches and only --key-version narrows the delete.
        #[arg(long, value_name = "HEX", value_parser = parse_hex_byte)]
        key_id: Option<u8>,
        /// The Key Version Number to delete (GP tag D2). If absent, every
        /// version matches and only --key-id narrows the delete.
        #[arg(long, value_name = "HEX", value_parser = parse_hex_byte)]
        key_version: Option<u8>,
        /// Also delete related objects (P2 80).
        #[arg(long)]
        related: bool,
        /// Send a delete that would remove the key set this session authenticated
        /// with, or every key on the card, as a WARNING instead of refusing it.
        /// Still needs --yes; without it nothing is sent.
        #[arg(long)]
        allow_lockout: bool,
        #[command(flatten)]
        dk: GpDeleteKeyFlags,
    },
    /// Load a CAP file and install an applet over an SCP03 channel: INSTALL [for
    /// load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card
    /// Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT.
    ///
    /// Same safeguards as delete: a dry run unless --yes (offline without keys),
    /// one authentication attempt, a registry pre-read that refuses a load file or
    /// application AID that is already on the card, every command sent once and
    /// in order, stopping at the first refusal, and a registry re-read to confirm.
    /// For a Security Domain that verifies a DAP, --dap-key-file/--dap-key-env
    /// (one AES key, hex, optionally KEY/KCV) sign the Load File Data Block Hash
    /// with AES-CMAC and send the DAP block in front of the load file (GP Card Spec
    /// v2.3.1 C.2, C.3, B.2.2); the Security Domain must be in the registry with
    /// the DAP Verification privilege, else nothing is sent. The DAP key is never
    /// printed. DES, RSA and ECC DAP keys and tokens are not supported. Not
    /// available over MCP.
    ///
    /// Exit 0 for a dry run or a verified install, 1 otherwise.
    Install {
        /// The CAP file (a zip of javacard/*.cap components).
        #[arg(long, value_name = "CAP")]
        load: std::path::PathBuf,
        /// The Executable Module AID (the applet class). Optional when the CAP has
        /// one applet.
        #[arg(long, value_name = "HEX")]
        module: Option<String>,
        /// The application (instance) AID. Defaults to the module AID.
        #[arg(long, value_name = "HEX")]
        app: Option<String>,
        /// The Install Parameters field as TLV with the mandatory C9 tag (default
        /// C900: none).
        #[arg(long, value_name = "HEX", default_value = "C900")]
        params: String,
        /// Privileges, 1 or 3 bytes of hex (default 000000). Card Lock and Card
        /// Terminate are refused.
        #[arg(long, value_name = "HEX", default_value = "000000")]
        privileges: String,
        /// Make the applet default selected: sets the Card Reset privilege, 0x04 in
        /// the first privilege byte (GP Card Spec v2.3.1 table 11-7, the bit
        /// GlobalPlatformPro's --make-default sets). The card then selects this
        /// applet by default after reset, so it changes what the card runs first.
        #[arg(long)]
        make_default: bool,
        /// Data bytes per LOAD block, 1 to 247 (default 240; 255 minus the 8-byte SCP03 C-MAC). The load file is cut
        /// into blocks of this size, so a smaller one sends more, shorter LOAD
        /// commands. Changes only how the file is split: the bytes loaded are the
        /// same. Shown in the dry run's APDUs.
        #[arg(
            long = "bs",
            value_name = "BYTES",
            default_value_t = 240,
            value_parser = clap::value_parser!(u16).range(1..=247)
        )]
        block_size: u16,
        #[command(flatten)]
        dap: GpDapArgs,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer
    /// security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec
    /// v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'S ADMINISTRATIVE ACCESS.
    ///
    /// Replacing the card's own SCP03 keys with values you do not hold, or have
    /// mistyped, locks administrative access for good. A dry run unless --yes
    /// (--yes needs --keys-file/--keys-env, the CURRENT keys with their DEK).
    /// The new key set is read from --new-keys-file/--new-keys-env, never the
    /// command line: three AES-128 keys `ENC MAC DEK`, each optionally KEY/KCV; a
    /// wrong KCV refuses the run before the card is touched. The key check value
    /// of each new key is shown; the keys are never printed, and the PUT KEY data
    /// (the keys encrypted under the DEK) is withheld from the plan and the
    /// trace. The command refuses to add, replace or overwrite the key version it
    /// authenticated with unless --replace-current-keyset is given. After 90 00
    /// the card's returned key check values and its key information are checked
    /// against the request. One authentication attempt, not available over MCP.
    ///
    /// Exit 0 for a dry run or a verified key change, 1 otherwise.
    PutKey {
        /// The Key Version Number of the new keys, 01 to 7F.
        #[arg(long, value_name = "HEX", value_parser = parse_hex_byte)]
        new_key_version: u8,
        /// P1: 00 (default) adds the key set; 01 to 7F replaces the key set with that
        /// version.
        #[arg(long, value_name = "HEX", default_value = "00", value_parser = parse_hex_byte)]
        replace_key_version: u8,
        /// The Key Identifier of the first key (the other two follow at +1 and +2).
        #[arg(long, value_name = "HEX", default_value = "01", value_parser = parse_hex_byte)]
        key_id: u8,
        #[command(flatten)]
        new_keys: GpNewKeyArgs,
        /// Allow the request to add, replace or overwrite the key version this
        /// session authenticated with. Without it such a request is refused.
        #[arg(long)]
        replace_current_keyset: bool,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Write the CPLC pre-personalization or personalization block (STORE DATA
    /// with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso)
    /// over SCP03. WARNING: this writes card-identifying CPLC data, and the change
    /// can be permanent on a card that locks its CPLC.
    ///
    /// The block is eight bytes: the personalizer (2), the date (2) and the
    /// equipment ID (4). --today writes today's date (UTC) into the date bytes. A
    /// dry run unless --yes (--yes needs --keys-file/--keys-env); the dry run
    /// prints the APDU. One STORE DATA, MAC'd; a refusal is reported and not
    /// retried.
    ///
    /// Exit 0 for a dry run or a sent write, 1 otherwise.
    CplcSet {
        /// pre-perso (DGI 9F67) or perso (DGI 9F66).
        #[arg(long, value_enum)]
        kind: GpCplcKind,
        /// The eight data bytes of the block as 16 hex digits.
        #[arg(long, value_name = "HEX")]
        data: String,
        /// Write today's date (UTC) into the date bytes, overriding those in --data.
        #[arg(long)]
        today: bool,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Personalize an application or Security Domain over an SCP03 channel:
    /// INSTALL [for personalization] (P1 20) for the AID, then one STORE DATA with
    /// the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified
    /// against the spec text, see the source). CHANGES CARD CONTENT.
    ///
    /// WARNING: personalization writes data the application reads on the card. A
    /// wrong value can break it, and this tool cannot read the stored value back.
    ///
    /// Same safeguards as delete: a dry run unless --yes (offline without keys,
    /// printing the exact APDUs), one authentication attempt, a registry pre-read
    /// that refuses an AID that is not on the card, every command sent once and in
    /// order, stopping at the first refusal, and a registry re-read that confirms
    /// the AID is still present. The data is printed as given, so do not put key
    /// material in it. Not available over MCP.
    ///
    /// Exit 0 for a dry run or a verified personalization, 1 otherwise.
    Personalize {
        /// The application or Security Domain AID, 5 to 16 bytes of hex.
        #[arg(long, value_name = "HEX")]
        aid: String,
        /// The BER-TLV personalization data, as hex; sent as the STORE DATA body.
        #[arg(long, value_name = "HEX")]
        data: String,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Add, delete or lock the secure element access rules the ARA-M holds:
    /// STORE DATA [Command-Store-REF-AR-DO], [Command-Delete] and the fork's
    /// lock, all over an SCP03 channel. CHANGES THE CARD'S ACCESS RULES.
    ///
    /// A dry run unless --yes; --yes needs --keys-file/--keys-env. One SCP03
    /// authentication attempt, the card cryptogram checked locally before
    /// EXTERNAL AUTHENTICATE, keys from a file or environment variable only and
    /// never printed. The rules are read over the secure channel before the
    /// write and again after it; a card that does not show the change fails
    /// `verify-failed`. `delete-all` removes EVERY rule on the card, not one,
    /// and needs --confirm-delete-all DELETE-ALL on top of --yes. `lock` is the
    /// proprietary STORE DATA lock of pySim's sysmocom ARA-M fork, not a
    /// GlobalPlatform command, and is permanent. `config` is the read-only
    /// configuration handshake and writes nothing. Not available over MCP.
    ///
    /// Exit 0 for a dry run or a verified write, 1 otherwise.
    Aram {
        #[command(subcommand)]
        action: AramAction,
    },
}

#[derive(Subcommand)]
enum CrsAction {
    /// List the applications the Contactless Registry Service holds for
    /// contactless, with their lifecycle, contactless state and registry data.
    /// Read-only, no keys.
    List {
        /// Narrow the listing to applications whose AID starts with these bytes.
        #[arg(long, value_name = "HEX")]
        aid: Option<String>,
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        channel: GpChannelArg,
    },
    /// Read the Contactless Registry Service version and event counter
    /// (GET DATA [A5]). Read-only, no keys.
    Info {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        channel: GpChannelArg,
    },
    /// Activate one application for contactless (CRS SET STATUS with P2 01).
    /// CHANGES CARD STATE.
    ///
    /// WARNING: activating an application for contactless changes what the card
    /// answers in a reader from that moment on; deactivating one can leave it
    /// unreachable to every terminal that relies on contactless. This is not
    /// undone by this tool. It is a dry run unless --yes, which needs
    /// --keys-file or --keys-env.
    Activate {
        /// The application AID, 5 to 16 bytes of hex.
        #[arg(value_name = "AID")]
        aid: String,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Deactivate one application for contactless (CRS SET STATUS with P2 00).
    /// CHANGES CARD STATE.
    ///
    /// WARNING: deactivating an application can leave it unreachable to every
    /// terminal that relies on contactless, and this tool does not undo it. It
    /// is a dry run unless --yes, which needs --keys-file or --keys-env.
    Deactivate {
        /// The application AID, 5 to 16 bytes of hex.
        #[arg(value_name = "AID")]
        aid: String,
        #[command(flatten)]
        write: GpWriteFlags,
    },
}

/// Which CPLC block `gp cplc-set` writes.
#[derive(clap::ValueEnum, Clone, Copy)]
enum GpCplcKind {
    PrePerso,
    Perso,
}

#[derive(Subcommand)]
enum AramAction {
    /// Add or replace one access rule: STORE DATA [Command-Store-REF-AR-DO],
    /// `F0 { E2 { E1 { 4F|C0, C1, CA }, E3 { D0, D1, DB } } }`.
    Add {
        /// The application the rule is for: 5 to 16 bytes of hex, or the empty
        /// string for the empty AID-REF-DO that names every application.
        #[arg(long, value_name = "HEX")]
        aid: Option<String>,
        /// No specific application: the implicitly selected one on every
        /// channel (AID-REF-EMPTY-DO, C0).
        #[arg(long, conflicts_with = "aid")]
        aid_empty: bool,
        /// The device application's certificate hash or UUID, 20 or 32 bytes of
        /// hex. Empty (the default) matches any device application.
        #[arg(long, value_name = "HEX", default_value = "")]
        device_app_id: String,
        /// The Android package name (PKG-REF-DO, an AOSP extension).
        #[arg(long, value_name = "NAME")]
        pkg_ref: Option<String>,
        /// Never allow the application's APDUs (APDU-AR-DO D0 01 00).
        #[arg(long, conflicts_with_all = ["apdu_always", "apdu_filter"])]
        apdu_never: bool,
        /// Always allow the application's APDUs (APDU-AR-DO D0 01 01).
        #[arg(long, conflicts_with_all = ["apdu_never", "apdu_filter"])]
        apdu_always: bool,
        /// An APDU filter: groups of 16 hex digits, 4 for CLA INS P1 P2 then 4
        /// for the mask, repeated.
        #[arg(long, value_name = "HEX", conflicts_with_all = ["apdu_never", "apdu_always"])]
        apdu_filter: Option<String>,
        /// Never deliver the application's NFC events (NFC-AR-DO D1 01 00).
        #[arg(long, conflicts_with_all = ["nfc_always"])]
        nfc_never: bool,
        /// Always deliver the application's NFC events (NFC-AR-DO D1 01 01).
        #[arg(long, conflicts_with_all = ["nfc_never"])]
        nfc_always: bool,
        /// The eight Android UICC Carrier Privilege permission bytes
        /// (PERM-AR-DO, an AOSP extension).
        #[arg(long, value_name = "HEX")]
        android_permissions: Option<String>,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Delete EVERY access rule the ARA-M holds: STORE DATA [Command-Delete]
    /// with an empty body (F1 00).
    DeleteAll {
        /// Required acknowledgement beyond --yes: the literal DELETE-ALL.
        #[arg(long, value_name = "TEXT")]
        confirm_delete_all: Option<String>,
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// Lock the ARA-M's STORE DATA (the single byte A1), so no rule can ever be
    /// added, changed or deleted again. pySim's sysmocom ARA-M fork only.
    Lock {
        #[command(flatten)]
        write: GpWriteFlags,
    },
    /// The configuration handshake: GET DATA [Config] (80 CA DF 21) offering
    /// the device's interface version. Read-only, no --yes.
    Config {
        /// The major part of the device interface version to offer.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8))]
        major: u8,
        /// The minor part of the device interface version to offer.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8))]
        minor: u8,
        /// The patch part of the device interface version to offer.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8))]
        patch: u8,
        #[command(flatten)]
        read: GpReadWriteFlags,
    },
}

/// What `gp aram config` shares with the writes, minus `--yes`: the handshake
/// writes nothing, so there is nothing to confirm.
#[derive(Args)]
struct GpReadWriteFlags {
    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,
    /// Emit one JSON envelope of kind "gp" on stdout.
    #[arg(long)]
    json: bool,
    /// Add every APDU exchange (command and response hex) as data.trace.
    #[arg(long)]
    trace: bool,
    #[command(flatten)]
    keys: GpKeyArgs,
    #[command(flatten)]
    channel: GpChannelArg,
}

#[derive(Subcommand)]
enum GpChannelAction {
    /// MANAGE CHANNEL open: the card picks the number and it is printed.
    Open {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
    },
    /// MANAGE CHANNEL close of a channel opened earlier.
    Close {
        /// The channel to close, 1 to 19.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=19))]
        channel: u8,
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
    },
}

/// Runs a gp command on a supplementary logical channel (opened with `gp
/// channel open`) instead of the basic channel.
#[derive(Args, Clone, Copy)]
struct GpChannelArg {
    /// Logical channel number, 0 (the basic channel, default) to 19. The SELECT
    /// and every following command, and the secure channel, use it.
    #[arg(long, value_name = "N", default_value_t = 0,
          value_parser = clap::value_parser!(u8).range(0..=19))]
    channel: u8,
}

/// What `gp delete-key` shares with the other gp commands: reader, output
/// toggles, logical channel, key source and the `--yes` write gate.
#[derive(Args)]
struct GpDeleteKeyFlags {
    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,
    /// Emit one JSON envelope of kind "gp" on stdout.
    #[arg(long)]
    json: bool,
    /// Add every APDU exchange (command and response hex) as data.trace.
    #[arg(long)]
    trace: bool,
    #[command(flatten)]
    channel: GpChannelArg,
    #[command(flatten)]
    keys: GpKeySourceArgs,
    /// Send the commands. Without it nothing is written. Needs --keys-file or
    /// --keys-env.
    #[arg(long, requires = "delete_key_source")]
    yes: bool,
}

/// What `gp delete` and `gp install` share.
#[derive(Args)]
struct GpWriteFlags {
    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,
    /// Emit one JSON envelope of kind "gp" on stdout.
    #[arg(long)]
    json: bool,
    /// Add every APDU exchange (command and response hex) as data.trace.
    #[arg(long)]
    trace: bool,
    #[command(flatten)]
    keys: GpKeyArgs,
    #[command(flatten)]
    channel: GpChannelArg,
    /// Send the commands. Without it nothing is written. Needs --keys-file or
    /// --keys-env.
    #[arg(long, requires = "key_source")]
    yes: bool,
}

/// Where `gp delete-key` gets ISD keys (keys only, no INITIALIZE UPDATE key
/// version — the version to delete is its own `--key-version` flag). Never a
/// value on the command line: it would land in shell history and the process
/// list.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("delete_key_source").args(["keys_file", "keys_env"])))]
struct GpKeySourceArgs {
    /// File holding the keys (keep it chmod 600).
    #[arg(long, value_name = "PATH")]
    keys_file: Option<std::path::PathBuf>,
    /// Environment variable holding the keys.
    #[arg(long, value_name = "VAR")]
    keys_env: Option<String>,
}

/// Where `gp status` gets ISD keys. Never a value on the command line: it would
/// land in shell history and the process list.
///
/// The text is `ENC [MAC [DEK]]`, each 32 hex digits (AES-128),
/// separated by spaces, commas or newlines; one key means ENC = MAC. A key may
/// be written `KEY/KCV` (6 hex digits); a wrong KCV stops the run before the
/// card is touched. The channel is C-MAC only. Exactly ONE authentication attempt
/// is made per run and it is never retried, because failed attempts count toward
/// locking the ISD. The card cryptogram is checked locally first: wrong keys stop
/// with "keys do not match this card" and EXTERNAL AUTHENTICATE is not sent.
/// Keys are never printed.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("key_source").args(["keys_file", "keys_env"])))]
struct GpKeyArgs {
    /// File holding the keys (keep it chmod 600).
    #[arg(long, value_name = "PATH")]
    keys_file: Option<std::path::PathBuf>,
    /// Environment variable holding the keys.
    #[arg(long, value_name = "VAR")]
    keys_env: Option<String>,
    /// Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets
    /// the card choose its first key set.
    #[arg(long, value_name = "HEX", default_value = "00", requires = "key_source",
          value_parser = parse_hex_byte)]
    key_version: u8,
}

/// Where `gp put-key` gets the NEW key set. Never a value on the command line.
/// Text: `ENC MAC DEK`, 32 hex digits each, optionally `KEY/KCV`.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("new_key_source").required(true)
    .args(["new_keys_file", "new_keys_env"])))]
struct GpNewKeyArgs {
    /// File holding the new keys (keep it chmod 600).
    #[arg(long, value_name = "PATH")]
    new_keys_file: Option<std::path::PathBuf>,
    /// Environment variable holding the new keys.
    #[arg(long, value_name = "VAR")]
    new_keys_env: Option<String>,
}

/// The DAP key of `gp install`. Never a value on the command line.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("dap_key_source").args(["dap_key_file", "dap_key_env"])))]
struct GpDapArgs {
    /// File holding the AES DAP key (hex, optionally KEY/KCV; chmod 600).
    #[arg(long, value_name = "PATH")]
    dap_key_file: Option<std::path::PathBuf>,
    /// Environment variable holding the AES DAP key.
    #[arg(long, value_name = "VAR")]
    dap_key_env: Option<String>,
    /// The Security Domain that verifies the DAP, 5 to 16 bytes of hex (default:
    /// the issuer security domain being authenticated).
    #[arg(long, value_name = "HEX", requires = "dap_key_source")]
    dap_sd: Option<String>,
    /// The Load File Data Block Hash the DAP signs.
    #[arg(
        long,
        value_enum,
        default_value = "sha256",
        requires = "dap_key_source"
    )]
    dap_hash: DapHash,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum DapHash {
    Sha256,
    Sha384,
    Sha512,
}

fn parse_hex_byte(text: &str) -> Result<u8, String> {
    u8::from_str_radix(text, 16).map_err(|_| "expected one byte as hex, like 30".into())
}

/// The long description of `sim-doctor scan`.
///
/// A constant rather than a literal in the derive so
/// [`tests/process_contract.rs`] can assert the exact sentence that warns about
/// under-reporting. A warning that lives only in prose is a warning that gets
/// reworded out of existence by the next person to tidy a doc comment; one that
/// a test quotes is a warning that has to keep meaning what it says.
const SCAN_LONG_ABOUT: &str = concat!(
    "Select a card's master file, walk everything under it, and report.\n\n",
    "Opens a real PC/SC session against one reader, selects the master file\n",
    "(3F00), probes every candidate file identifier underneath it, descends into\n",
    "the directories the card itself describes, and reports what it found.\n\n",
    "WHAT A CLEAN RESULT DOES AND DOES NOT MEAN\n",
    "  * Truncation is always reported. A walk that hit one of its bounds did\n",
    "    not see the whole card: the human report opens with a TRUNCATED banner,\n",
    "    and --json carries \"complete\", \"truncated\", \"truncated_by\" and the\n",
    "    full \"limits_hit\" list. A file list without those is a file list an\n",
    "    agent could read as the card's complete contents.\n",
    "  * The default dialect is an assumption, not a fact. Reading a card's\n",
    "    capabilities template with the wrong tag table produces a file size the\n",
    "    card never sent. Pass --dialect to declare which table is in use; the\n",
    "    one actually used is named in both output modes.\n",
    "  * The default candidate set can MISS a file. See --max-children.\n",
    "  * A default TAR scan does NOT prove MSL != 0. See TAR AND MSL 0.\n\n",
    "OUTPUT: doctor/1\n",
    "  --json prints the shared doctor/1 envelope (docs/doctor-contract.md):\n",
    "  schema, tool, version, exit_code, score, findings and data. Findings are\n",
    "  top-level (id, fingerprint, severity, category, message, location,\n",
    "  evidence, remedy); the walk, the TAR audit and everything else this report\n",
    "  carries are under data.\n\n",
    "READ data.complete BEFORE TRUSTING A CLEAN RESULT\n",
    "  The exit code is decided by findings, not by whether the walk finished: a\n",
    "  walk cut short at a bound exits 0 when its findings are below --fail-on.\n",
    "  An agent gating a build should also require data.complete to be true, or\n",
    "  score.coverage_gaps to be 0 (the score label is `incomplete`, not `good`,\n",
    "  while there is a gap).\n\n",
    "TAR AND MSL 0\n",
    "  A TAR is a three-octet value a network uses to route an SMS payload to one\n",
    "  application on a card. A card running at MSL 0 accepts ANY command under\n",
    "  ANY TAR with no cryptographic verification, so the security question is\n",
    "  which TARs the card will act on. --tar selects them: off (none), focused\n",
    "  (592 TARs, the default), full (from 000000), range:FIRST-LAST, or\n",
    "  regex:PATTERN over the six-hex-digit spelling.\n",
    "  THE PROBE COUNT IS CAPPED AT 4096 WHATEVER YOU ASK FOR. The full TAR\n",
    "  space is 16 777 216 values and this tool will not send them all to a\n",
    "  card. A selection larger than the cap stops at it; data.tar.stopped says\n",
    "  so, and any finding it carries is marked partial rather than read as an\n",
    "  exhaustive audit of the card's TAR accept-list.\n",
    "  A TAR is reported as ACCEPTED when the card answers it DIFFERENTLY from\n",
    "  the way it answers TARs it has no opinion about. That is a measurement,\n",
    "  not a status word this tool guesses at: no 3GPP TS 31.111 text has been\n",
    "  read here, and the one card this crate has talked to answers 94 04 for\n",
    "  something else entirely. data.tar.baseline carries the measurement, and\n",
    "  every probe's status word is in data.tar.probes.\n",
    "  A CARD THAT ANSWERS EVERY TAR IDENTICALLY REPORTS NOTHING ACCEPTED. On\n",
    "  a card with no TAR check that is the correct answer, not a miss. A scan\n",
    "  whose baseline could not be established says so in data.tar.blind_spot\n",
    "  and raises nothing. So does a baseline that is only a generic error\n",
    "  (6F00, 6D00, 6E00, 6985, 6A81): the card did not process the envelopes,\n",
    "  the sweep is not sent, and the blind spot names --terminal-profile.\n\n",
    "SEVERITY AND SCORE\n",
    "  --severity <level> REMOVES findings below that level from the report.\n",
    "  Not marked, not counted, absent from the JSON entirely, so a count or a\n",
    "  grep sees only what survived. The level in force is reported as\n",
    "  data.findings_detail.severity_threshold. It does not filter the walk:\n",
    "  complete, truncated and limits_hit are unaffected by it.\n",
    "  The top-level score is an INTEGER 0-100 (model sim/1), always present;\n",
    "  --score adds it to the human report. It is computed as\n",
    "    max(0, 100 - sum of one penalty per finding)\n",
    "  with a penalty of info 1, low 3, medium 10, high 25, critical 50. The\n",
    "  block carries the formula, that penalty table, the penalty total and\n",
    "  the number of findings scored, so the number can be recomputed from\n",
    "  the report (data.score_detail). It scores the findings this report\n",
    "  carries, so --severity\n",
    "  and --score compose rather than contradict each other.\n",
    "  A rules_run OF 0 means no rule was evaluated, and the block then carries\n",
    "  a warning beside the 100 saying so in words. A rules_run above 0 with a\n",
    "  score of 100 means a rule looked and found nothing, which is a verdict.\n",
    "  The two are different numbers wearing the same digits, and warning is\n",
    "  what tells them apart.\n\n",
    "EXIT CODES\n",
    "  0  ran; no finding at or above --fail-on (default critical)\n",
    "  1  ran; at least one finding at or above --fail-on\n",
    "  2  usage error, bad input (including an unusable --baseline), or the\n",
    "     scan could not run (no reader, no card, a failed walk)\n",
    "  3  --baseline given; at least one NEW finding at or above --fail-on.\n",
    "     Under --baseline only new findings count: 3 or 0, never 1\n",
    "  130  interrupted\n",
);
/// Everything `sim-doctor ts48` takes.
#[derive(Args)]
struct Ts48Args {
    #[command(subcommand)]
    action: Ts48Action,
}

#[derive(Subcommand)]
enum Ts48Action {
    /// Walk the card and diff its file system against the GSMA TS.48 test profile.
    ///
    /// Read-only: the same SELECT / GET RESPONSE walk as `scan`, and nothing
    /// else (no TAR probes, no ENVELOPE). The expected file list is derived from
    /// the public TS.48 v7.0 SAIP profile (Apache-2.0, pinned commit) and is
    /// compiled into this binary.
    ///
    /// Reports files the profile defines that the card lacks (ts48/file-missing),
    /// files the card has that the profile does not (ts48/file-extra) and files
    /// present in both that differ in type, layout, size or record length
    /// (ts48/file-different). An operator SIM is not a TS.48 card, so many
    /// differences are the expected answer: they are findings, exit code 0.
    ///
    /// MATCHING THE TS.48 FILE STRUCTURE IS NOT GCF OR PTCRB CONFORMANCE. This
    /// compares a file system with a public test profile and certifies nothing.
    ///
    /// Exit codes: 0 when the walk finished, 1 when it could not run (no reader,
    /// no card), 129 for a bad command line, 130 if interrupted.
    Compare(Ts48CompareArgs),
}

/// The walk bounds, shared by `scan` and `ts48 compare` so they cannot drift.
#[derive(Args)]
struct WalkLimitArgs {
    /// Deepest path below the master file the walk descends into.
    ///
    /// The default (16) leaves room for a real card. Lowering it is how you
    /// force a truncation on purpose, which is the supported way to see what a
    /// truncated report looks like.
    #[arg(long, value_name = "N")]
    max_depth: Option<usize>,

    /// Identifiers probed per directory.
    ///
    /// THE DEFAULT CANDIDATE SET CAN MISS A FILE. By default the walk probes
    /// the five GSM 11.11 identifier families 2Fxx/4Fxx/5Fxx/6Fxx/7Fxx, 1280 of
    /// them. Every file on the swSIM USIM profile falls inside one of those, so
    /// it cost no coverage there. On a card that puts a file anywhere else, that
    /// file is INVISIBLE to the scan - never probed, so it cannot even be
    /// reported missing - and a clean result is not proof the card holds nothing
    /// else. The output reports which candidate set ran and whether it covered
    /// the whole identifier space; an exhaustive --candidates range is not
    /// offered on this flag yet, which is itself an under-reporting default
    /// rather than a documented way out.
    #[arg(long, value_name = "N")]
    max_children: Option<usize>,

    /// Files the card selected across the whole walk (default 16384).
    ///
    /// Absent probes do not count, so this is a bound on files found, not on
    /// identifiers tried. How long a walk can run is bounded by
    /// --max-directories times --max-children.
    #[arg(long, value_name = "N")]
    max_nodes: Option<usize>,

    /// Directories whose children are enumerated.
    #[arg(long, value_name = "N")]
    max_directories: Option<usize>,

    /// Break after finding all files the card claims to have (DF count matches).
    ///
    /// A 2G-format directory response reports its child DFs and EFs (TS 51.011
    /// clause 9.2.1). Once the scan has found that many under a directory, it stops
    /// probing that directory's remaining identifiers. The flag is ignored for a
    /// directory whose response does not report counts (for example 3GPP FCP).
    #[arg(short = 'b', long = "scan-file-break", visible_alias = "sfb")]
    break_after_count_match: bool,
}

#[derive(Args)]
struct Ts48CompareArgs {
    /// Emit one JSON envelope (type "ts48") on stdout, and nothing else.
    #[arg(long)]
    json: bool,

    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// Which FCP tag table this card answers SELECT with (see `scan --help`).
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = parse_dialect
    )]
    dialect: scan::Dialect,

    #[command(flatten)]
    walk_limits: WalkLimitArgs,
}

/// Everything `sim-doctor scan` takes.
#[derive(Args)]
struct ScanArgs {
    /// Emit one JSON envelope on stdout, and nothing else.
    ///
    /// Implemented. stdout carries the envelope and not one byte else; every
    /// diagnostic goes to stderr in this mode and in every other.
    #[arg(long)]
    json: bool,

    /// Show the findings in an interactive terminal view instead of the report.
    ///
    /// A view over the same data `--json` carries: nothing is shown that the
    /// envelope does not contain. Needs a terminal on stdin and stdout; without
    /// one the plain report is printed and a line on stderr says so. Keys:
    /// up/down or j/k, PgUp/PgDn, Home/End, q or Esc to quit.
    #[arg(long, conflicts_with = "json")]
    tui: bool,

    /// Which FCP tag table this card answers SELECT with.
    ///
    /// Defaults to ts-102-221. This is an assumption and the output says which
    /// one was used; the chosen table's name appears in the human report and
    /// under "dialect" in the JSON, so the assumption is never invisible.
    ///
    /// ts-102-221 is the ETSI TS 102 221 clause 11.1.1.3 layout that real UICCs
    /// and swSIM both write: file size in 80, descriptor in 82, file id in 83,
    /// DF name in 84. swicc has the same tags and exists only so a baseline
    /// taken under that name stays comparable. iec-7816-4-table-42 is a
    /// deprecated alias for ts-102-221.
    ///
    /// A card nobody has characterised needs a hand-built TagSet, which this
    /// flag cannot express yet. That is a real gap rather than a missing third
    /// value: an "unknown" dialect would render an empty table as though it
    /// meant something.
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = parse_dialect
    )]
    dialect: scan::Dialect,

    /// The reader to use, matched against the driver's own name.
    ///
    /// Defaults to the first reader PC/SC reports. Pass this when more than one
    /// is attached, or to get an explicit error naming what is available
    /// instead of scanning whichever reader happened to be first.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// The reader to use, by its index in `sim-doctor readers` (counted from 0).
    ///
    /// For when two readers share a name, which --reader cannot tell apart.
    /// Conflicts with --reader.
    #[arg(long, value_name = "N", conflicts_with = "reader")]
    reader_index: Option<usize>,

    #[command(flatten)]
    walk_limits: WalkLimitArgs,

    /// Follow standard identifiers only (ETSI TS 102 221 / 3GPP TS 31.102 / 31.103 / 31.104 / 51.011).

    /// When set, the walk probes only the file identifiers defined in the
    /// ETSI and 3GPP specifications, plus the files pySim can decode with
    /// standard names. This is stricter than the default (SimFamilies), which
    /// probes the broader GSM 11.11 family ranges (2Fxx, 4Fxx, 5Fxx, 6Fxx, 7Fxx).

    /// Corresponds to SIMTester's `-sffs` flag.
    #[arg(long)]
    sffs: bool,

    /// Add one quality score for this card, for CI gating.
    ///
    /// Implemented. The score is an INTEGER from 0 to 100, and it is
    /// reproducible rather than merely present: 100 minus the penalty of every
    /// finding in this report, where a finding costs info 1, low 3, medium 10,
    /// high 25 or critical 50, floored at 0. AGENTS.md section 3 states the
    /// formula in full, and the JSON repeats it - the formula, the penalty
    /// table, the penalty total and how many findings were scored - so an
    /// agent can recompute the number from the document it is holding.
    ///
    /// It scores what this report carries, so --severity and --score compose:
    /// `--severity high --score` scores the high and critical findings and
    /// nothing else, and `data.score_detail.scored_findings` says how many that was.
    /// The top-level `score` of the JSON envelope is always present; this flag
    /// only adds the score to the human report.
    ///
    /// WHILE NO RULE IS IMPLEMENTED the score is 100 with `rules_run` 0 and a
    /// warning beside it. A 100 that means "nothing was checked" is not a
    /// clean card, and the report says so rather than leaving a CI gate to
    /// work that out from the absence of findings.
    #[arg(long)]
    score: bool,

    /// Drop findings below this severity.
    ///
    /// Implemented. Accepted and validated as one of info, low, medium, high,
    /// critical, so a typo is still a usage error (exit 2) rather than being
    /// silently ignored.
    ///
    /// A finding below the level is REMOVED, not marked: it is absent from
    /// the top-level `findings`, absent from `data.findings_detail.count`, and its
    /// rule ID appears nowhere in the document. An agent counting findings
    /// therefore gets the count that survived the filter, and an agent
    /// grepping for a dropped rule finds nothing rather than an empty shell
    /// carrying the ID.
    ///
    /// The level in force is reported as `data.findings_detail.severity_threshold`,
    /// because a short list is otherwise indistinguishable from a quiet card.
    ///
    /// It does not filter the WALK. `complete`, `truncated`, `truncated_by`
    /// and `limits_hit` are unchanged by it, so raising the level can never
    /// make a truncated scan look like a whole one.
    #[arg(long, value_name = "LEVEL")]
    severity: Option<rules::Severity>,

    /// Compare this run against a previous `scan --json` envelope (doctor/1).
    ///
    /// The file is a saved envelope: `sim-doctor scan --json > baseline.json`.
    /// Findings are matched by `fingerprint` only. Every finding in the report
    /// gets a `baseline_state` (`new` or `unchanged`), the envelope gets a
    /// top-level `baseline` block with `new`, `unchanged` and `fixed` counts,
    /// and `data.diff` carries the lists.
    ///
    /// UNDER A BASELINE ONLY NEW FINDINGS GATE. The exit code is 3 when at least
    /// one new finding is at or above --fail-on, else 0; the findings the
    /// baseline already had never fail the run.
    ///
    /// THE COMPARISON REFUSES RATHER THAN GUESSES (exit 2, `data.error`, no
    /// findings). A baseline written by a truncated scan, by a scan that ran
    /// fewer rules, at a different --severity, --dialect or --tar, or by a scan
    /// in which a rule had no evidence, cannot be honestly compared with this
    /// run. `--tar off` is the default, so the usual baseline never checked
    /// MSL 0 and the first `--tar focused` scan cannot be read as a regression
    /// against it. A file that is not a doctor/1 envelope of a finished scan is
    /// refused too, as is a hand-edited or hostile one (strings and arrays are
    /// bounded before parsing).
    ///
    /// A RENAMED RULE READS AS A RENAME. An ID in exactly one of the two runs is
    /// listed under `data.diff.rules` with a warning; the gate does not count
    /// it, though its findings carry `baseline_state: new`.
    ///
    /// THE BASELINE IS A FULL ENVELOPE. It carries the ATR and the decoded EF
    /// contents (`data.ef_contents`, key files included) that the report
    /// carries. Treat it as sensitive; do not commit one taken from a card with
    /// real keys.
    #[arg(long, value_name = "FILE")]
    baseline: Option<std::path::PathBuf>,

    /// Exit 1 (3 under --baseline) when a finding is at or above this severity.
    ///
    /// One of info, low, medium, high, critical. The default is `critical`:
    /// before doctor/1 a scan with findings exited 0, so the default fails only
    /// on the worst finding rather than on every report. Use `--fail-on info`
    /// to fail on any finding, `--fail-on high` for a stricter CI gate. This is
    /// the gate only; --severity is what REMOVES findings from the report.
    #[arg(long, value_name = "LEVEL", default_value = "critical")]
    fail_on: rules::Severity,

    /// Also write the findings to FILE as SARIF 2.1.0.
    ///
    /// A card has no files on disk, so each result carries a logical location
    /// (the card path) and never a physical one. Partial coverage is stated in
    /// the run's properties. Written after the normal output, so a failure to
    /// write it (exit 2, a message on stderr) never costs you the report. Each
    /// result carries `partialFingerprints["doctorFinding/v1"]`, the same value
    /// as the finding's JSON `fingerprint`, and the run carries `properties.score`. The
    /// file is written only after a completed scan: a refused or interrupted
    /// scan leaves any existing file untouched. It must not be the --baseline path.
    /// stdout is unchanged. Whether GitHub code scanning accepts the file is
    /// not verified.
    #[arg(long, value_name = "FILE")]
    sarif: Option<std::path::PathBuf>,

    /// Which TARs to probe for MSL 0, and how many.
    ///
    /// Implemented. Defaults to `focused`, which is 592 TARs chosen from
    /// SIMTester's own ranged-scan bands; `off` probes nothing, `full`
    /// starts at 000000, `range:FIRST-LAST` scans a band and
    /// `regex:PATTERN` scans everything matching a pattern over the
    /// six-hex-digit spelling (SIMTester's `-str` and `-stre`).
    ///
    /// THE PROBE COUNT IS BOUNDED AT 4096 WHATEVER YOU ASK FOR. The full TAR
    /// space is 16 777 216 values; sending them all to a card is not
    /// something this tool will do behind a flag. A selection larger than the
    /// bound stops at it and the report says so, under
    /// `data.tar.stopped`, and the finding it carries is marked partial
    /// rather than read as an exhaustive audit of the card's TAR accept-list.
    ///
    /// A TAR is accepted when the card's answer to it differs from the answer
    /// it gives to TARs it has no opinion about - the `-stbs` differential
    /// from SIMTester, reimplemented in src/tar.rs with the reasoning. A card
    /// that answers every TAR identically therefore reports nothing, which on
    /// a card with no TAR check is the correct answer rather than a miss.
    #[arg(long, value_name = "SELECTION", default_value_t = tar::Selection::default())]
    tar: tar::Selection,

    /// SIMTester's `-stre`: skip TAR probes whose response matches this regex.
    ///
    /// The response is spelled as uppercase hex, data first and the status word last
    /// (`6D00`, `9000`). A matching sweep probe is neither accepted nor raised, and
    /// shows as `filtered` under data.tar.probes. The calibration pass is never
    /// filtered, since the baseline is measured from it. Ignored under `--tar off`.
    #[arg(long, value_name = "REGEX")]
    tar_filter: Option<tar::ResponseFilter>,

    /// Send a TERMINAL PROFILE to the card before the TAR audit.
    ///
    /// Only meaningful with --tar other than `off`; without it the command
    /// line is refused (exit 2).
    ///
    /// WHAT IS SENT: `80 10 00 00 01 13` (TS 102 221 clause 11.2.1), a
    /// one-octet profile with three bits set, all in byte 1 (TS 102 223 /
    /// TS 31.111 clause 5.2): b1 profile download, b2 and b5 SMS-PP data
    /// download. No proactive command, menu, event or display capability is
    /// declared. A card that answers `91 xx` anyway has that command fetched
    /// and answered with TERMINAL RESPONSE `30` (command beyond terminal's
    /// capabilities); nothing it asks for is executed.
    ///
    /// WHY: a card that ignores CAT traffic until it has seen a profile
    /// answers every ENVELOPE `6F 00`, and the TAR audit then says nothing
    /// (data.tar.blind_spot). This is the handset's own first CAT step.
    ///
    /// WHAT IT CHANGES: the card's CAT session state for this power cycle.
    /// It writes no file. It is off by default for that reason. The exchange
    /// is reported as data.tar.terminal_profile.
    #[arg(long)]
    terminal_profile: bool,

    /// Ask for SMS-DELIVER-REPORT as the proof-of-receipt mode of the TAR probes, not SMS-SUBMIT.
    ///
    /// SIMTester's `-sdr`. Only meaningful with --tar other than `off`; without it the command
    /// line is refused (exit 2).
    ///
    /// WHAT CHANGES: one octet of the Command Packet inside each ENVELOPE. The PoR mode is bit 5
    /// of SPI2, which is `29` for SMS-SUBMIT (the default) and `09` for SMS-DELIVER-REPORT, as
    /// SIMTester's `CommandPacket.POR_MODE_*` writes it. It names the mode the card is asked to
    /// answer the proof of receipt with. The mode is reported as data.tar.por_mode.
    #[arg(long = "sms-deliver-report", alias = "sdr")]
    sms_deliver_report: bool,
    /// Scan reserved file identifiers 7FF0-7FFF inside an application.
    ///
    /// By default, these identifiers are treated as aliases of the current
    /// application and are not probed. When this flag is set, they are
    /// probed like any other file identifier during the walk.
    ///
    /// Assumed to match SIMTester's `-sfrv` ("user reserved IDs"): assumed 7FF0-7FFF,
    /// the range this tool otherwise treats as application aliases (ETSI TS 102 221 8.3).
    /// Not confirmed against SIMTester's source.
    #[arg(long, visible_alias = "sfrv")]
    reserved_file_ids: bool,

    /// The human report: a doctor-kit face (rich, plain or compact), or the full legacy report.
    ///
    /// The default is the kit's face (rich on a terminal, plain otherwise): the findings, the
    /// score, and first of all notes for everything that makes the result partial (a truncated
    /// walk, an unfinished TAR audit, the candidate-set warning). `legacy` is the report that also
    /// lists the files and the TAR evidence. --json and --tui have their own output.
    #[arg(long, value_name = "FACE", value_parser = ["rich", "plain", "compact", "legacy"], conflicts_with_all = ["json", "tui"])]
    face: Option<String>,

    /// The face's colours: mono, clinical or contrast (default: the tool's own).
    #[arg(long, value_name = "THEME", conflicts_with_all = ["json", "tui"])]
    theme: Option<String>,

    /// Colour the face: auto (a terminal and no NO_COLOR), always or never.
    #[arg(long, value_enum, conflicts_with_all = ["json", "tui"])]
    color: Option<doctor_kit::output::Color>,

    /// A face in plain text without colour, for CI and pipes.
    #[arg(long, conflicts_with_all = ["json", "tui", "face"])]
    headless: bool,
}

/// `readers` takes no card, only the switch for a JSON envelope.
#[derive(Args)]
struct ReadersArgs {
    /// Emit one JSON envelope (type "readers") on stdout, and nothing else.
    #[arg(long)]
    json: bool,
}

// What `shell` and `explore` read from the card: a scan's reader, dialect and bounds.
#[derive(Args)]
struct CardArgs {
    /// The reader to use, matched against the driver's own name.
    ///
    /// Defaults to the first reader PC/SC reports.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// The reader to use, by its index in `sim-doctor readers` (counted from 0).
    ///
    /// For when two readers share a name, which --reader cannot tell apart.
    /// Conflicts with --reader.
    #[arg(long, value_name = "N", conflicts_with = "reader")]
    reader_index: Option<usize>,

    /// Which FCP tag table this card answers SELECT with (see `scan --help`).
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = parse_dialect
    )]
    dialect: scan::Dialect,

    #[command(flatten)]
    walk_limits: WalkLimitArgs,

    /// Which TARs to probe for MSL 0 before the session opens (default: none; see `scan --help`).
    #[arg(long, value_name = "SELECTION", default_value_t = tar::Selection::default())]
    tar: tar::Selection,
}

// `shell`: a REPL over the card (its about line is set where the command is mounted).
#[derive(Args)]
struct ShellArgs {
    #[command(flatten)]
    card: CardArgs,

    /// Run these `;`-separated commands and exit.
    #[arg(short = 'c', value_name = "COMMANDS")]
    command: Option<String>,

    /// Print every reply as one JSON record (for agents).
    #[arg(long)]
    json: bool,
}

// `explore`: the full-screen version of `shell`.
#[derive(Args)]
struct ExploreArgs {
    #[command(flatten)]
    card: CardArgs,
}

/// Everything `sim-doctor rules` takes.
#[derive(Args)]
struct RulesArgs {
    #[command(subcommand)]
    action: Option<RulesAction>,
}

#[derive(Subcommand)]
enum RulesAction {
    /// One row per rule: id, severity, summary.
    List {
        /// Emit one JSON envelope of kind "rules" on stdout.
        #[arg(long)]
        json: bool,
    },
    /// What a rule means and how to fix it.
    Explain {
        /// The rule id, such as gsma/msl-zero-allowed.
        id: String,
        /// Emit one JSON envelope of kind "rules" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Everything `sim-doctor sms` takes.
#[derive(Args)]
struct SmsArgs {
    #[command(subcommand)]
    action: SmsAction,
}

#[derive(Subcommand)]
enum SmsAction {
    /// Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin.
    Decode {
        /// Hex of a PDU (spaces and `0x` allowed); stdin, one per line, when none is given or for "-".
        hex: Vec<String>,
        /// The hex is a bare TPDU, without the leading SMSC address the PDU format carries.
        #[arg(long)]
        tpdu: bool,
        /// Emit one JSON envelope of kind "sms" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Everything `sim-doctor cat` takes.
#[derive(Args)]
struct CatArgs {
    #[command(subcommand)]
    action: CatAction,
}

#[derive(Subcommand)]
enum CatAction {
    /// Decode CAT data given as hex arguments, or one object per line on stdin.
    Decode {
        /// Hex of a proactive command, envelope, terminal response or comprehension TLVs
        /// (spaces and `0x` allowed); stdin, one per line, when none is given or for "-".
        hex: Vec<String>,
        /// Emit one JSON envelope of kind "cat" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Everything `sim-doctor esim-cert` takes.
#[derive(Args)]
struct EsimCertArgs {
    #[command(subcommand)]
    action: EsimCertAction,
}

#[derive(Subcommand)]
enum EsimCertAction {
    /// Verify a certificate chain (leaf first) up to a CI root.
    Verify {
        /// The chain file: PEM with CERTIFICATE blocks, or concatenated DER, leaf first.
        chain: String,
        /// The CI root you trust: a file holding exactly one certificate, PEM or DER.
        #[arg(long)]
        root: String,
        /// Check validity at this UTC time, YYYYMMDDHHMMSS, instead of now.
        #[arg(long, value_name = "YYYYMMDDHHMMSS")]
        at: Option<String>,
        /// Emit one JSON envelope of kind "esim-cert" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Everything `sim-doctor ota-crypto` takes.
#[derive(Args)]
struct OtaCryptoArgs {
    #[command(subcommand)]
    action: OtaCryptoAction,
}

#[derive(Subcommand)]
enum OtaCryptoAction {
    /// Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex.
    Encrypt {
        /// DES (8-byte key), 3DES (16- or 24-byte key) or AES (16/24/32-byte key).
        #[arg(long, value_enum)]
        alg: OtaAlg,
        /// The key as hex; length selects the AES variant (16/24/32) or must
        /// match the algorithm (DES 8, 3DES 16 or 24).
        #[arg(long, value_name = "HEX")]
        key: String,
        /// The IV as hex (one block); all zeros when absent.
        #[arg(long, value_name = "HEX")]
        iv: Option<String>,
        /// The data to encrypt, as hex.
        data: String,
        /// Emit one JSON envelope of kind "ota-crypto" on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex.
    Decrypt {
        #[arg(long, value_enum)]
        alg: OtaAlg,
        #[arg(long, value_name = "HEX")]
        key: String,
        /// The IV as hex (one block); all zeros when absent.
        #[arg(long, value_name = "HEX")]
        iv: Option<String>,
        /// The ciphertext to decrypt, as hex.
        data: String,
        #[arg(long)]
        json: bool,
    },
    /// Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES).
    Sign {
        #[arg(long, value_enum)]
        alg: OtaAlg,
        #[arg(long, value_name = "HEX")]
        key: String,
        /// The data to sign, as hex.
        data: String,
        /// Length of the MAC to return (default 8, the OTA checksum length).
        #[arg(long, value_name = "N", default_value_t = 8)]
        mac_len: usize,
        #[arg(long)]
        json: bool,
    },
    /// Recompute the checksum and compare it to --mac in constant time.
    Check {
        #[arg(long, value_enum)]
        alg: OtaAlg,
        #[arg(long, value_name = "HEX")]
        key: String,
        /// The data that was signed, as hex.
        data: String,
        /// The expected MAC as hex; its length sets the MAC length.
        #[arg(long, value_name = "HEX")]
        mac: String,
        #[arg(long)]
        json: bool,
    },
}

/// `--alg` accepts the three OTA cipher families.
#[derive(Clone, Copy, clap::ValueEnum)]
enum OtaAlg {
    #[value(name = "des")]
    Des,
    /// 2-key (16-byte) or 3-key (24-byte) Triple DES.
    #[value(name = "3des")]
    Tdes,
    /// AES-128, AES-192 or AES-256 from the key length.
    #[value(name = "aes")]
    Aes,
}

impl From<OtaAlg> for otacrypto::Alg {
    fn from(a: OtaAlg) -> Self {
        match a {
            OtaAlg::Des => otacrypto::Alg::Des,
            OtaAlg::Tdes => otacrypto::Alg::Tdes,
            OtaAlg::Aes => otacrypto::Alg::Aes,
        }
    }
}

/// Everything `sim-doctor ota-expanded` takes.
#[derive(Args)]
struct OtaExpandedArgs {
    #[command(subcommand)]
    action: OtaExpandedAction,
}

#[derive(Subcommand)]
enum OtaExpandedAction {
    /// Wrap one or more C-APDUs (hex each) in a Command Scripting template.
    Encode {
        /// The C-APDUs to script, hex (spaces and `0x` allowed), one per argument.
        c_apdu: Vec<String>,
        /// Use the indefinite length coding (tag AE 80 ... 00 00, TS 102 226 table 5.2a) instead
        /// of the default definite one (tag AA, table 5.2). TS 102 226 recommends the indefinite
        /// coding only for HTTPS and CoAP, not for SMS.
        #[arg(long)]
        indefinite: bool,
        /// Emit one JSON envelope of kind "ota-expanded" on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Decode a Response Scripting template (TS 102 226 5.2.2), definite or indefinite.
    Decode {
        /// Hex of the template (spaces and `0x` allowed); stdin when omitted or "-".
        hex: Option<String>,
        /// Emit one JSON envelope of kind "ota-expanded" on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Decode a Proof-of-Response Response Packet (TS 102 225 table 5, TS 31.115), with or
    /// without the SMS `02 71 00` user data header.
    Por {
        /// Hex of the Response Packet, or of `02 71 00` followed by it; stdin when omitted or "-".
        hex: Option<String>,
        /// Read the secure data as a compact (TS 102 226 5.1.2) or expanded (5.2.2) Remote
        /// Application response.
        #[arg(long, value_enum, default_value_t = RemoteFormatArg::Compact)]
        remote_format: RemoteFormatArg,
        /// Emit one JSON envelope of kind "ota-expanded" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// `--remote-format` accepts the two Remote Application structures of TS 102 226.
#[derive(Clone, Copy, clap::ValueEnum)]
enum RemoteFormatArg {
    /// TS 102 226 clause 5.1.2.
    #[value(name = "compact")]
    Compact,
    /// TS 102 226 clause 5.2.2, a Response Scripting template.
    #[value(name = "expanded")]
    Expanded,
}

impl From<RemoteFormatArg> for ota_expanded::RemoteFormat {
    fn from(f: RemoteFormatArg) -> Self {
        match f {
            RemoteFormatArg::Compact => ota_expanded::RemoteFormat::Compact,
            RemoteFormatArg::Expanded => ota_expanded::RemoteFormat::Expanded,
        }
    }
}

/// Everything `sim-doctor trace` takes.
#[derive(Args)]
struct TraceArgs {
    /// A trace file; stdin when omitted or "-".
    file: Option<String>,
    /// Emit one JSON envelope of kind "trace" on stdout.
    #[arg(long)]
    json: bool,
    /// Also print each exchange's raw command and response hex in the table.
    #[arg(long)]
    show_raw_apdu: bool,
    /// Keep SELECT rows in the table. They are hidden by default, as in pySim-trace.
    #[arg(long)]
    no_suppress_select: bool,
    /// Keep UICC STATUS rows in the table. They are hidden by default, as in pySim-trace.
    #[arg(long)]
    no_suppress_status: bool,
}

/// Everything `sim-doctor why` takes.
#[derive(Args)]
struct WhyArgs {
    /// A rule id, or the path of a saved `sim-doctor scan --json` envelope.
    target: String,
    /// Emit one JSON envelope of kind "rules" on stdout.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor fix` takes.
#[derive(Args)]
struct FixArgs {
    /// The rule id to fix, such as gsma/msl-zero-allowed.
    rule_id: String,
    /// A saved `sim-doctor scan --json` envelope holding a finding for that rule.
    #[arg(long, value_name = "FILE")]
    from: String,
    /// Start this coding agent with the prompt instead of only printing it.
    #[arg(long, value_parser = ["claude", "codex", "cursor"])]
    agent: Option<String>,
    /// Pass the agent its flag that skips approval prompts (unverified for every CLI version).
    #[arg(long)]
    skip_approvals: bool,
}

#[derive(Args)]
struct ModulesArgs {
    /// Emit the JSON envelope on stdout instead of a human-readable table.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor install` takes.
#[derive(Args)]
struct InstallArgs {
    /// Install for one agent only; omit for all of them.
    #[arg(long, value_parser = ["claude", "cursor", "codex", "opencode"])]
    agent: Option<String>,

    /// Print what would be written instead of writing it.
    #[arg(long)]
    print_only: bool,

    /// Project root to write under (default: the current directory).
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: std::path::PathBuf,
}

/// Everything `sim-doctor ci` takes.
#[derive(Args)]
struct CiArgs {
    #[command(subcommand)]
    action: CiAction,
}

#[derive(Subcommand)]
enum CiAction {
    /// Write .github/workflows/sim-doctor.yml, pinned to this version's tag.
    ///
    /// Refuses to write through a symlink, keeps a differing existing file
    /// unless --force, and validates every value before writing anything.
    Install {
        /// Build the software card on the runner (CI has no card otherwise).
        #[arg(long, value_parser = ["true", "false"], default_value = "true")]
        swsim: String,
        /// Committed baseline path (letters, digits and . _ / - only).
        #[arg(long, value_name = "PATH", default_value = ".sim-doctor/baseline.json")]
        baseline: String,
        /// Fail the job when the baseline file is missing.
        #[arg(long, value_parser = ["true", "false"], default_value = "true")]
        require_baseline: String,
        /// Pass --severity to the scan.
        #[arg(long)]
        severity: Option<rules::Severity>,
        /// The action ref to pin (default: v<this version>; it exists once that release is cut).
        #[arg(long = "ref", value_name = "REF")]
        ref_: Option<String>,
        /// Project root to write under (default: the current directory).
        #[arg(long, value_name = "DIR", default_value = ".")]
        dir: std::path::PathBuf,
        /// Overwrite a differing existing workflow.
        #[arg(long)]
        force: bool,
        /// Print the workflow instead of writing it.
        #[arg(long)]
        print_only: bool,
    },
}

/// Everything `sim-doctor completions` takes.
#[derive(Args)]
struct CompletionsArgs {
    /// The shell to generate for.
    ///
    /// One of bash, elvish, fish, powershell or zsh.
    #[arg(value_name = "SHELL")]
    shell: clap_complete::Shell,
}

/// Parses `--dialect`, saying once on stderr when the deprecated spelling is used.
fn parse_dialect(text: &str) -> Result<scan::Dialect, scan::UnknownDialect> {
    if text.eq_ignore_ascii_case(scan::DEPRECATED_TABLE_42) {
        eprintln!(
            "sim-doctor: --dialect {} is deprecated: that mapping was wrong for real cards; using ts-102-221",
            scan::DEPRECATED_TABLE_42
        );
    }
    text.parse()
}

fn main() -> process::ExitCode {
    init_diagnostics();

    // Installed before clap runs, so even a command line this process has not
    // finished reading can be interrupted. A refusal is a diagnostic and not a
    // failed run: see doctor_kit::interrupt::install.
    doctor_kit::interrupt::install();

    kit::run()
}

/// Runs the parsed command and returns its exit code.
fn dispatch(d: &kit::SimDoctor, command: Command) -> contract::ExitCode {
    match command {
        Command::Modules(args) => run_modules(args),
        Command::Readers(args) => run_readers(&args),
        Command::Scan(args) => kit::scan(d, args),
        Command::Ts48(args) => match args.action {
            Ts48Action::Compare(args) => run_ts48_compare(args),
        },
        Command::Install(args) => kit::install(d, args),
        Command::Card(args) => card_cmd::run(args),
        Command::Cat(args) => match args.action {
            CatAction::Decode { hex, json } => run_cat_decode(&hex, json),
        },
        Command::OtaCrypto(args) => run_otacrypto(args),
        Command::EsimCert(args) => match args.action {
            EsimCertAction::Verify {
                chain,
                root,
                at,
                json,
            } => run_esim_cert_verify(&chain, &root, at.as_deref(), json),
        },
        Command::OtaExpanded(args) => run_ota_expanded(args),
        Command::Sms(args) => match args.action {
            SmsAction::Decode { hex, tpdu, json } => run_sms_decode(&hex, tpdu, json),
        },
        Command::Saip(args) => match args.action {
            SaipAction::Parse { file, json } => run_saip_parse(&file, json),
        },
        Command::Completions(args) => run_completions(args),
        Command::Ci(args) => run_ci(args),
        Command::Rules(args) => match args.action {
            None => run_rules_list(false),
            Some(RulesAction::List { json }) => run_rules_list(json),
            Some(RulesAction::Explain { id, json }) => run_why_rule(&id, json),
        },
        Command::Why(args) => run_why(&args.target, args.json),
        Command::Fix(args) => run_fix(&args),
        Command::Gp(args) => match args.action {
            GpAction::Aram { action } => run_gp_aram(action),
            GpAction::Info {
                reader,
                json,
                trace,
                channel,
            } => run_gp(
                "gp info",
                reader.as_deref(),
                json,
                trace,
                channel.channel,
                |s, t| gp::info(s, t),
            ),
            GpAction::Ara {
                reader,
                json,
                trace,
                channel,
            } => run_gp(
                "gp ara",
                reader.as_deref(),
                json,
                trace,
                channel.channel,
                |s, t| gp::ara(s, t),
            ),
            GpAction::Status {
                reader,
                json,
                list,
                info,
                trace,
                channel,
                keys,
            } => {
                let view = match (list, info) {
                    (true, _) => Some("list"),
                    (_, true) => Some("info"),
                    _ => None,
                };
                run_gp_status(reader.as_deref(), json, trace, channel.channel, &keys, view)
            }
            GpAction::Select {
                aid,
                reader,
                json,
                trace,
                channel,
            } => match parse_aid(&aid) {
                Some(aid) => run_gp(
                    "gp select",
                    reader.as_deref(),
                    json,
                    trace,
                    channel.channel,
                    |s, t| gp::select(s, &aid, t),
                ),
                None => report_refusal(
                    "gp",
                    "--aid must be 5 to 16 bytes of hex",
                    serde_json::json!({ "error": { "kind": "bad-aid" } }),
                    json,
                ),
            },
            GpAction::Channel { action } => match action {
                GpChannelAction::Open {
                    reader,
                    json,
                    trace,
                } => run_gp(
                    "gp channel open",
                    reader.as_deref(),
                    json,
                    trace,
                    0,
                    |s, t| gp::channel_open(s, t),
                ),
                GpChannelAction::Close {
                    channel,
                    reader,
                    json,
                    trace,
                } => run_gp(
                    "gp channel close",
                    reader.as_deref(),
                    json,
                    trace,
                    0,
                    |s, t| gp::channel_close(s, channel, t),
                ),
            },
            GpAction::Crs { action } => match action {
                CrsAction::List {
                    aid,
                    reader,
                    json,
                    trace,
                    channel,
                } => run_gp_crs_list(
                    aid.as_deref(),
                    reader.as_deref(),
                    json,
                    trace,
                    channel.channel,
                ),
                CrsAction::Info {
                    reader,
                    json,
                    trace,
                    channel,
                } => run_gp_crs_info(reader.as_deref(), json, trace, channel.channel),
                CrsAction::Activate { aid, write } => run_gp_crs_set(&aid, true, &write),
                CrsAction::Deactivate { aid, write } => run_gp_crs_set(&aid, false, &write),
            },
            GpAction::Delete {
                aid,
                related,
                write,
            } => run_gp_delete(&aid, related, &write),
            GpAction::MakeDefault { aid, write } => run_gp_make_default(&aid, &write),
            GpAction::RenameIsd { new_aid, write } => run_gp_rename_isd(&new_aid, &write),
            GpAction::DeleteKey {
                key_id,
                key_version,
                related,
                allow_lockout,
                dk,
            } => run_gp_delete_key(key_id, key_version, related, allow_lockout, &dk),
            GpAction::Install {
                load,
                module,
                app,
                params,
                privileges,
                make_default,
                block_size,
                dap,
                write,
            } => {
                // Unparsable hex is left for run_gp_install to refuse.
                let privileges = match (make_default, hex::decode(&privileges)) {
                    (true, Ok(p)) => gp::with_default_selected(&p).map_or(privileges, hex::encode),
                    _ => privileges,
                };
                run_gp_install(
                    &load,
                    module,
                    app,
                    &params,
                    &privileges,
                    usize::from(block_size),
                    &dap,
                    &write,
                )
            }
            GpAction::PutKey {
                new_key_version,
                replace_key_version,
                key_id,
                new_keys,
                replace_current_keyset,
                write,
            } => run_gp_put_key(
                new_key_version,
                replace_key_version,
                key_id,
                &new_keys,
                replace_current_keyset,
                &write,
            ),
            GpAction::CplcSet {
                kind,
                data,
                today,
                write,
            } => run_gp_cplc_set(kind, &data, today, &write),
            GpAction::Personalize { aid, data, write } => run_gp_personalize(&aid, &data, &write),
        },
        Command::Euicc(args) => match args.action {
            EuiccAction::Info(f) => run_euicc(euicc::Query::Info, &f),
            EuiccAction::Profiles(f) => run_euicc(euicc::Query::Profiles, &f),
            EuiccAction::Challenge(f) => run_euicc(euicc::Query::Challenge, &f),
            EuiccAction::Notifications(n) => match n.action {
                None => run_euicc(euicc::Query::Notifications, &n.flags),
                Some(NotificationAction::Remove(a)) => run_euicc_remove(&a),
                Some(NotificationAction::Dump(a)) => run_euicc_dump(&a),
                Some(NotificationAction::Replay(a)) => run_euicc_replay(&a),
            },
            EuiccAction::Nickname(n) => run_euicc_nickname(&n),
            EuiccAction::Enable(a) => run_euicc_state(euicc::Action::Enable, &a),
            EuiccAction::Disable(a) => run_euicc_state(euicc::Action::Disable, &a),
            EuiccAction::Delete(a) => run_euicc_delete(&a),
            EuiccAction::Reset(a) => run_euicc_reset(&a),
            EuiccAction::SetDefaultDp(a) => run_euicc_default_dp(&a),
        },
        Command::Trace(args) => run_trace(&args),
        Command::Mcp => run_mcp(d),
        Command::Fuzz(args) => match args.action {
            FuzzAction::Apdu(args) => run_fuzz_apdu(args),
            FuzzAction::Ota(args) => run_fuzz_ota(args),
            FuzzAction::Mutate(args) => run_fuzz_mutate(args),
            FuzzAction::Compare(args) => run_fuzz_compare(args),
        },
    }
}

/// Routes every `tracing` event to stderr, at a level quiet enough to leave it
/// silent on a clean run.
///
/// `tracing-subscriber` is already a dependency and was, before this issue,
/// installed nowhere - which is the same thing as saying no library module had
/// a safe place to log from. Its default writer is **stdout**, the one stream
/// `--json` reserves for the envelope, so the wiring has to say `stderr`
/// explicitly or the first `tracing::warn!` in a future module silently breaks
/// every agent consuming this tool.
///
/// `with_max_level(WARN)` rather than `EnvFilter`: honouring `RUST_LOG` needs
/// tracing-subscriber's `env-filter` feature, and taking a dependency feature
/// for a log level nothing in the repo sets yet is the kind of speculative
/// change AGENTS.md section 4 warns about. The issue that first needs
/// per-module levels records that decision instead.
///
/// `with_ansi(false)` because stderr is read by CI logs and by `2>` files as
/// often as by a terminal, and escape codes are noise in both.
fn init_diagnostics() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .init();
}

/// Runs `modules` and returns the exit code for it.
///
/// The interrupt checkpoint lives here rather than inside `emit_modules` so that
/// `emit_modules` stays a function that renders data and nothing else. [`run_scan`]
/// copies this shape and adds a second checkpoint after the walk; see its own
/// documentation for why there are exactly two.
/// The readers PC/SC reports, in driver order. Under the replay seam, the one
/// reader the log was recorded from, so the listing is testable with no service.
fn list_readers() -> Result<Vec<ReaderName>, String> {
    #[cfg(feature = "test-seams")]
    if let Some(path) = env::var_os(REPLAY_ENV) {
        let log = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
        let replay = replay::Replay::from_log(&log)?;
        return Ok(vec![replay.reader().clone()]);
    }
    Pcsc::readers().map_err(|err| {
        format!(
            "cannot list PC/SC readers: {err}. Is the PC/SC service running (pcscd on Linux, \
             the Smart Card service on Windows)?"
        )
    })
}

/// `readers`: every PC/SC reader with its index, for `--reader-index`. Needs no card.
fn run_readers(args: &ReadersArgs) -> contract::ExitCode {
    let (code, readers) = match list_readers() {
        Ok(readers) => (contract::ExitCode::Success, readers),
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            if args.json {
                let line = contract::Envelope::new(
                    "readers",
                    contract::ExitCode::Error,
                    message,
                    serde_json::json!({ "readers": [] }),
                )
                .to_json();
                match line {
                    Ok(line) => {
                        if let Err(err) = emit_stdout(&line, "the readers envelope") {
                            eprintln!("sim-doctor: {err}");
                        }
                    }
                    Err(err) => eprintln!("sim-doctor: {err}"),
                }
            }
            return contract::ExitCode::Error;
        }
    };
    if readers.is_empty() {
        eprintln!("sim-doctor: no PC/SC reader is attached");
    }

    if args.json {
        let rows: Vec<serde_json::Value> = readers
            .iter()
            .enumerate()
            .map(|(index, name)| serde_json::json!({ "index": index, "name": name.as_str() }))
            .collect();
        let message = format!("{} reader(s) attached", readers.len());
        let line = contract::Envelope::new(
            "readers",
            code,
            message,
            serde_json::json!({ "readers": rows }),
        )
        .to_json();
        match line {
            Ok(line) => {
                if let Err(err) = emit_stdout(&line, "the readers envelope") {
                    eprintln!("sim-doctor: {err}");
                }
            }
            Err(err) => eprintln!("sim-doctor: {err}"),
        }
    } else if !readers.is_empty() {
        let text = readers
            .iter()
            .enumerate()
            .map(|(index, name)| format!("{index}  {name}"))
            .collect::<Vec<_>>()
            .join("\n");
        if let Err(err) = emit_stdout(&text, "the reader list") {
            eprintln!("sim-doctor: {err}");
        }
    }
    code
}

fn run_modules(args: ModulesArgs) -> contract::ExitCode {
    if checkpoint() {
        return report_interrupted(MODULES_KIND, args.json);
    }

    match emit_modules(args.json) {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            // No rule produces findings yet (issue #13), so the only way a run
            // fails today is by being unable to deliver its result. AGENTS.md
            // section 3 shares code 1 between findings and a failed check, and
            // a run that could not write its answer is a failed run.
            contract::ExitCode::Findings
        }
    }
}

/// The interrupt checkpoint: have we been asked to stop, and is it safe to?
///
/// Checkpoints go *before* output is produced, never after. A run that has
/// already written its envelope has finished, and retroactively converting a
/// complete, correct answer into "interrupted" would either need a second
/// envelope on stdout or would break the documented promise that `payload.code`
/// is the value the process exits with. Both are worse than a Ctrl-C that
/// arrives microseconds too late.
fn checkpoint() -> bool {
    hold_for_the_signal_test();
    doctor_kit::interrupt::interrupted()
}

/// Parks at the checkpoint so a test can deliver a real SIGINT to a process
/// that is known to still be alive. See [`SIGNAL_HOLD_ENV`].
///
/// The announcement on stderr is the handshake. The test reads it before
/// signalling, which is what makes the SIGINT test a test rather than a race:
/// by the time that line exists the handler is installed, so the signal cannot
/// land in the window between `execve` and the first instruction of `main` and
/// kill the process through the kernel's default disposition. Sleeping a fixed
/// interval instead is what made this flaky - four tests spawn children in
/// parallel and a cold exec on a loaded CI runner outlived any fixed delay.
///
/// **Once per process**, through [`PARKED_ONCE`]. `scan` takes two checkpoints
/// and a walk can take minutes; a test whose signal never landed would
/// otherwise sit out the full hold at each of them. Parking only at the first
/// keeps the hold meaning what the tests that set it mean.
#[cfg(feature = "test-seams")]
fn hold_for_the_signal_test() {
    let Ok(milliseconds) = env::var(SIGNAL_HOLD_ENV) else {
        return;
    };
    let Ok(milliseconds) = milliseconds.parse::<u64>() else {
        return;
    };
    if PARKED_ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }

    eprintln!("sim-doctor: {PARKED_MARKER} for {milliseconds}ms");

    if env::var_os(WEDGE_ENV).is_some() {
        loop {
            thread::park();
        }
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(milliseconds);
    while std::time::Instant::now() < deadline {
        if doctor_kit::interrupt::interrupted() {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Release builds have no such seam: the hold does not exist there.
#[cfg(not(feature = "test-seams"))]
fn hold_for_the_signal_test() {}

/// Makes a card command interruptible even while it is stuck inside an exchange
/// (issue #88).
///
/// The signal handler only sets a flag, and the flag is read between steps, so a
/// PC/SC transmit that never returns would block the run forever. This starts a
/// watchdog thread: once the flag is set it waits [`INTERRUPT_GRACE`] for the
/// command to unwind through its own checkpoints, and if the process is still
/// alive it writes the interrupted envelope and exits 130 itself. Process exit
/// closes the PC/SC socket, which releases the reader.
///
/// Why not `SCardCancel` (`pcsc::Context::cancel`): pcsc-lite documents it as
/// cancelling pending `SCardGetStatusChange` calls only, and a transmit made
/// through a `Card` is not on that path, so it would not unblock this. The
/// watchdog is correct on both macOS and Linux without depending on either
/// daemon's behaviour.
fn guard_exchange(kind: &'static str, json: bool) {
    let _ = thread::Builder::new()
        .name("interrupt-watchdog".into())
        .spawn(move || {
            while !doctor_kit::interrupt::interrupted() {
                thread::sleep(Duration::from_millis(50));
            }
            thread::sleep(INTERRUPT_GRACE);
            let code = report_interrupted(kind, json);
            process::exit(i32::from(code.process_code()));
        });
}

/// Reports an interrupted run and returns [`contract::ExitCode::Interrupted`].
///
/// Exactly one envelope under `--json`, carrying code 130 and an empty `data`,
/// and a note on stderr in either mode. Never a partial result: the reasoning is
/// on [`contract::INTERRUPTED_MESSAGE`], and `tests/process_contract.rs` pins
/// both halves of it.
fn report_interrupted(kind: &str, json: bool) -> contract::ExitCode {
    if INTERRUPT_REPORTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return contract::ExitCode::Interrupted;
    }
    if json {
        // `scan` speaks doctor/1; every other command keeps the lpa envelope.
        let line = if kind == scan::KIND {
            serde_json::to_string(&contract::doctor_failure(
                contract::ExitCode::Interrupted,
                contract::interrupted_data(),
            ))
            .map_err(|err| err.to_string())
        } else {
            contract::Envelope::new(
                kind,
                contract::ExitCode::Interrupted,
                contract::INTERRUPTED_MESSAGE,
                contract::interrupted_data(),
            )
            .to_json()
            .map_err(|err| err.to_string())
        };
        match line {
            Ok(line) => {
                // A failure here does not change the exit code. The operator
                // asked to stop and stopping is what happened; reporting 130
                // while also reporting that stdout was unwritable is the
                // truthful answer, where reporting 1 would claim the run got
                // far enough to have a result.
                if let Err(message) = emit_stdout(&line, "the interrupted envelope") {
                    eprintln!("sim-doctor: {message}");
                }
            }
            Err(err) => eprintln!("sim-doctor: {err}"),
        }
    }

    eprintln!("sim-doctor: interrupted");
    contract::ExitCode::Interrupted
}

/// Renders the module table, as a table or as the JSON envelope.
///
/// `--json` puts the envelope and nothing else on stdout, which is the
/// AGENTS.md section 3 rule. Without it the same data is printed as a table
/// for a person, and the distinction is why the flag is checked here rather
/// than inside the library: formatting for a terminal is the binary job.
///
/// Both branches render into a `String` first and hand it to [`emit_stdout`]
/// as a single write. That keeps a failure halfway through from putting half
/// an envelope on stdout, and it is the reason this function can return the
/// message that explains a write error instead of panicking like `println!`.
fn emit_modules(json: bool) -> Result<(), String> {
    let rendered = if json {
        let data = serde_json::json!({
            "modules": MODULES
                .iter()
                .map(|module| {
                    serde_json::json!({
                        "name": module.name,
                        "owns": module.owns,
                        "depends_on": module.depends_on,
                    })
                })
                .collect::<Vec<_>>(),
        });
        let envelope = contract::Envelope::success(data);
        envelope.to_json().map_err(|e| e.to_string())?
    } else {
        let mut table = String::new();
        table.push_str(&format!("{:<10}  {:<5}  DEPENDS ON\n", "MODULE", "LAYER"));
        for (layer, module) in MODULES.iter().enumerate() {
            let depends = if module.depends_on.is_empty() {
                "-".to_owned()
            } else {
                module.depends_on.join(", ")
            };
            table.push_str(&format!("{:<10}  {:<5}  {}\n", module.name, layer, depends));
        }
        for module in MODULES {
            table.push_str(&format!("\n{}: {}\n", module.name, module.owns));
        }
        table
    };

    emit_stdout(rendered.trim_end_matches('\n'), "the module report")
}

/// Writes one line to stdout, returning the error instead of panicking on it.
///
/// `println!` panics when stdout cannot be written - a closed pipe from
/// `sim-doctor modules --json | head -5` is enough - and a panic is exit code
/// 101, which is not one of the four numbers AGENTS.md section 3 promises. Going
/// through `write_all` is what makes that failure reach a caller as
/// [`contract::ExitCode::Findings`] instead.
///
/// **The `flush` is load-bearing, and its absence is a silent zero.** `stdout()`
/// is a line-buffered writer, so `write_all` returning `Ok` means "accepted into
/// the buffer", not "the bytes reached the stream". Anything still buffered when
/// the command returns is flushed by the standard library's exit-time cleanup,
/// which runs after `main` has already chosen the process exit code and
/// discards the error. A caller of a run whose envelope was never written would
/// therefore get exit 0 and nothing on stdout: the pipe closed, the answer was
/// never delivered, and the status said everything was fine. That is strictly
/// worse for an agent than the `println!` panic this function exists to replace,
/// and it is exactly what
/// `a_run_that_cannot_write_its_report_exits_1_and_explains_itself_on_stderr`
/// exists to catch.
///
/// Whether the buffer happens to be flushed inside `write_all` is not this
/// crate's to rely on. It depends on the payload's size against the buffer's
/// capacity and on how the standard library flushes a completed line, and that
/// has moved between releases and between platforms. Observed both ways: the
/// Ubuntu runner returned 0 where the same binary on macOS returned 1. Flushing
/// explicitly is what makes the property hold on every toolchain.
fn emit_stdout(text: &str, what: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    handle
        .write_all(line.as_bytes())
        // Checked rather than chained blindly: a write that failed must not be
        // reported as a flush failure, and a write that succeeded must not be
        // allowed to hide a flush that did not.
        .and_then(|()| handle.flush())
        .map_err(|e| format!("cannot write {what} to stdout: {e}"))
}

/// Runs `sim-doctor ci install`: plain text, no envelope.
fn run_ci(args: CiArgs) -> contract::ExitCode {
    let CiAction::Install {
        swsim,
        baseline,
        require_baseline,
        severity,
        ref_,
        dir,
        force,
        print_only,
    } = args.action;
    let options = ci::Options {
        swsim: swsim == "true",
        baseline,
        require_baseline: require_baseline == "true",
        severity,
    };
    let ref_ = ref_.unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    match ci::install(&dir, &options, &ref_, force, print_only) {
        Ok(ci::InstallOutcome::Printed(text)) => {
            match emit_stdout(text.trim_end_matches('\n'), "the workflow") {
                Ok(()) => contract::ExitCode::Success,
                Err(message) => {
                    eprintln!("sim-doctor: {message}");
                    contract::ExitCode::Findings
                }
            }
        }
        Ok(ci::InstallOutcome::Wrote(path)) => {
            println!("wrote {}", path.display());
            eprintln!(
                "next: commit a baseline first (`sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > {}`), because require-baseline fails the first run without one.",
                options.baseline
            );
            eprintln!("next: the pinned ref {ref_} only exists once that release is tagged.");
            contract::ExitCode::Success
        }
        Ok(ci::InstallOutcome::Unchanged(path)) => {
            println!("unchanged {}", path.display());
            contract::ExitCode::Success
        }
        Err(err @ ci::CiError::Invalid(_)) => {
            eprintln!("sim-doctor: {err}");
            contract::ExitCode::InvalidUsage
        }
        Err(err) => {
            eprintln!("sim-doctor: {err}");
            contract::ExitCode::Findings
        }
    }
}

/// Runs `sim-doctor completions` and returns the exit code for it.
///
/// The script goes to stdout because a completion script *is* the output of
/// this command, exactly as the module table is the output of `modules`. The
/// stdout-purity rule is about `--json`, which this subcommand does not have:
/// a caller piping this into a file wants the script and nothing else.
///
/// Regenerated from [`Cli::command`] on every run rather than shipped as a
/// static file, so a flag that exists and refuses is completable. An agent that
/// types `sim-doctor scan --` and hits tab has to see `--score` - a flag that
/// exists and says "not yet" is the whole point - and a checked-in script would
/// go stale the moment a flag is added.
fn run_completions(args: CompletionsArgs) -> contract::ExitCode {
    let mut command = Cli::command();
    // Read before the mutable borrow: `generate` takes `&mut Command` and calls
    // `build()` on it, so asking it for its own name at the same time is two
    // borrows of one value.
    let bin_name = command.get_name().to_owned();
    let mut script: Vec<u8> = Vec::new();
    generate(args.shell, &mut command, bin_name, &mut script);
    let script = String::from_utf8(script).unwrap_or_else(|_| {
        eprintln!("sim-doctor: the generated completion script is not UTF-8");
        String::new()
    });

    match emit_stdout(script.trim_end_matches('\n'), "the completion script") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// What `SIM_DOCTOR_TEST_REPLAY` names: a `SIM_DOCTOR_RECORD` log that `scan`
/// answers from instead of a reader. Test seam only (tests/golden_scan.rs): it
/// lets the real binary's whole scan path run, deterministically, on a machine
/// with no PC/SC service. Compiled only with the `test-seams` feature, which `cargo test`
/// turns on and a release build never has (tests/release_seams.rs proves it).
#[cfg(feature = "test-seams")]
const REPLAY_ENV: &str = "SIM_DOCTOR_TEST_REPLAY";

/// What [`open_scan_session`] hands `scan`: the session, its reader and the ATR.
type ScanSession = (Box<dyn CardSession>, ReaderName, Option<Vec<u8>>);

/// Opens the card session `scan` reads: its reader name, the ATR when the
/// transport can say, and the session itself (wrapped in the record log when
/// `SIM_DOCTOR_RECORD` is set).
fn open_scan_session(
    requested: Option<&str>,
    exclusive: bool,
    index: Option<usize>,
) -> Result<ScanSession, scan::Failure> {
    #[cfg(feature = "test-seams")]
    if let Some(path) = env::var_os(REPLAY_ENV) {
        let log = std::fs::read_to_string(&path)
            .map_err(|err| scan::Failure::new("reader-unavailable", err.to_string()))?;
        let replay = replay::Replay::from_log(&log)
            .map_err(|err| scan::Failure::new("reader-unavailable", err))?;
        let reader = replay.reader().clone();
        // The index is still checked against the one replayed reader, so an
        // out-of-range --reader-index is refused here as it would be for real.
        pick_reader(std::slice::from_ref(&reader), None, index)?;
        return Ok((Box::new(replay), reader, None));
    }
    let readers = Pcsc::readers()
        .map_err(|err| scan::Failure::new("context-unavailable", err.to_string()))?;
    let reader = pick_reader(&readers, requested, index)?.clone();
    let session = PcscSession::open_with(&reader, share_mode(exclusive)).map_err(|err| {
        let kind = match err {
            TransportError::NoCard { .. } => "no-card",
            _ => "reader-unavailable",
        };
        scan::Failure::new(kind, err.to_string())
    })?;
    // Best effort. An ATR this transport could not read is a fact about the
    // session, not a reason to refuse to scan a card that is otherwise
    // answering, so it is Option rather than an error.
    let atr = session.atr().ok();

    // Opt-in capture for issue #120: SIM_DOCTOR_RECORD=<path> logs every
    // exchange of this scan (JSON lines, see transport::replay). The log is
    // raw card output; it is never written unless the operator asks.
    let session: Box<dyn CardSession> = match env::var_os("SIM_DOCTOR_RECORD") {
        Some(path) => {
            let file = record_log_file(&path).map_err(|err| {
                scan::Failure::new(
                    "record-log-unwritable",
                    format!("SIM_DOCTOR_RECORD {}: {err}", path.to_string_lossy()),
                )
            })?;
            Box::new(replay::Record::new(session, file))
        }
        None => Box::new(session),
    };
    Ok((session, reader, atr))
}

/// 5 to 16 bytes of hex.
fn parse_aid(text: &str) -> Option<Vec<u8>> {
    hex::decode(text)
        .ok()
        .filter(|a| (5..=16).contains(&a.len()))
}

/// `sim-doctor gp ...`: one GlobalPlatform pass over one card, on logical
/// channel `channel` (0 is the basic channel).
fn run_gp(
    what: &str,
    reader: Option<&str>,
    json: bool,
    trace: bool,
    channel: u8,
    pass: impl FnOnce(&mut dyn CardSession, bool) -> Result<gp::Report, session::Error>,
) -> contract::ExitCode {
    const KIND: &str = "gp";
    guard_exchange(KIND, json);
    let refuse =
        |failure: scan::Failure| report_refusal(KIND, &failure.message, failure.data(), json);
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => return refuse(scan::Failure::new("context-unavailable", err.to_string())),
    };
    let reader = match pick_reader(&readers, reader, None) {
        Ok(reader) => reader,
        Err(failure) => return refuse(failure),
    };
    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return refuse(scan::Failure::new(kind, err.to_string()));
        }
    };
    let result = if channel == 0 {
        pass(&mut session, trace)
    } else {
        pass(&mut gp::OnChannel::new(&mut session, channel), trace)
    };
    let report = match result {
        Ok(report) => report,
        Err(err) => return refuse(scan::Failure::new("gp-exchange-failed", err.to_string())),
    };
    let mut data = report.data;
    data["reader"] = serde_json::json!(reader.as_str());
    if channel != 0 {
        data["logical_channel"] = serde_json::json!(channel);
        gp::retarget_channel(&mut data, channel);
    }
    // An error the pass itself recorded (an authentication that stopped, a
    // refused write) wins.
    if let Some(message) = data["error"]["message"].as_str().map(str::to_owned) {
        return report_refusal(KIND, &message, data, json);
    }
    if !report.isd_found {
        let (kind, message) = match what {
            "gp ara" => ("ara-m-not-found", "no ARA-M answered SELECT at its AID"),
            "gp select" => (
                "aid-not-found",
                "no application answered SELECT at that AID",
            ),
            _ => (
                "isd-not-found",
                "no issuer security domain answered SELECT at either AID",
            ),
        };
        data["error"] = serde_json::json!({ "kind": kind, "message": message });
        return report_refusal(KIND, message, data, json);
    }
    emit_gp(what, data, json)
}

/// Prints a successful `gp` `data`: the envelope with --json, text otherwise.
fn emit_gp(what: &str, data: serde_json::Value, json: bool) -> contract::ExitCode {
    let rendered = if json {
        match contract::Envelope::new(
            "gp",
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else if what == "gp info" {
        serde_json::to_string_pretty(&data).unwrap_or_default()
    } else if let Some(view) = data["view"].as_str() {
        gp::render_registry(&data, view == "info")
    } else {
        gp::render_text(&data)
    };
    if let Err(err) = emit_stdout(&rendered, &format!("the {what} report")) {
        eprintln!("sim-doctor: {err}");
        return contract::ExitCode::Findings;
    }
    contract::ExitCode::Success
}

/// Loads the ISD keys named by `--keys-file` / `--keys-env`, if any. The keys are
/// read and checked (format, stated KCVs) before a reader is opened, so a typo
/// costs the card nothing. `Err` is the exit code of the refusal already printed.
fn load_gp_keys(args: &GpKeyArgs, json: bool) -> Result<Option<gp::Keys>, contract::ExitCode> {
    let source = match (&args.keys_file, &args.keys_env) {
        (Some(path), _) => gp::KeySource::File(path),
        (None, Some(name)) => gp::KeySource::Env(name),
        (None, None) => return Ok(None),
    };
    gp::Keys::load(source).map(Some).map_err(|err| {
        let kind = match err {
            gp::KeyError::Kcv { .. } => "key-kcv-mismatch",
            _ => "keys-unusable",
        };
        let message = err.to_string();
        let data = serde_json::json!({ "error": { "kind": kind, "message": message } });
        report_refusal("gp", &message, data, json)
    })
}

/// A fresh host challenge for one authentication attempt.
fn gp_auth<'a>(keys: &'a gp::Keys, args: &GpKeyArgs, channel: u8) -> gp::Auth<'a> {
    let mut host_challenge = [0u8; 8];
    rand::fill(&mut host_challenge);
    gp::Auth {
        keys,
        key_version: args.key_version,
        host_challenge,
        logical_channel: channel,
    }
}

/// `sim-doctor gp status [--keys-file PATH | --keys-env VAR]`.
fn run_gp_status(
    reader: Option<&str>,
    json: bool,
    trace: bool,
    channel: u8,
    args: &GpKeyArgs,
    view: Option<&'static str>,
) -> contract::ExitCode {
    // --list / --info: the text view is picked in emit_gp from data["view"]; the
    // marker only exists on these text runs, never on the --json envelope.
    let mark = |mut r: gp::Report| {
        if let Some(view) = view {
            r.data["view"] = serde_json::json!(view);
        }
        r
    };
    let keys = match load_gp_keys(args, json) {
        Ok(Some(keys)) => keys,
        Ok(None) => {
            return run_gp("gp status", reader, json, trace, channel, |s, t| {
                gp::status(s, t).map(mark)
            })
        }
        Err(code) => return code,
    };
    let auth = gp_auth(&keys, args, channel);
    run_gp("gp status", reader, json, trace, channel, |s, t| {
        gp::status_authenticated(s, t, &auth).map(mark)
    })
}

/// `sim-doctor gp delete`: a dry run unless `--yes`, offline without keys.
fn run_gp_delete(aid: &str, related: bool, w: &GpWriteFlags) -> contract::ExitCode {
    let Some(aid) = parse_aid(aid) else {
        return report_refusal(
            "gp",
            "--aid must be 5 to 16 bytes of hex",
            serde_json::json!({ "error": { "kind": "bad-aid" } }),
            w.json,
        );
    };
    let req = gp::DeleteRequest { aid, related };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::delete_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp delete", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp delete",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::delete(s, t, &req, &auth, w.yes),
    )
}

/// `sim-doctor gp cplc-set`: a dry run unless `--yes`, offline without keys. The
/// block is checked (hex, eight bytes, the date in range) before a reader is opened.
fn run_gp_cplc_set(
    kind: GpCplcKind,
    data: &str,
    today: bool,
    w: &GpWriteFlags,
) -> contract::ExitCode {
    let set = match kind {
        GpCplcKind::PrePerso => gp::CplcSet::PrePerso,
        GpCplcKind::Perso => gp::CplcSet::Perso,
    };
    let Ok(bytes) = hex::decode(data.trim()) else {
        return report_refusal(
            "gp",
            "--data must be hex",
            serde_json::json!({ "error": { "kind": "bad-cplc-data" } }),
            w.json,
        );
    };
    let today = today.then(|| chrono::Utc::now().date_naive());
    let req = match gp::cplc_request(set, &bytes, today) {
        Ok(req) => req,
        Err(e) => return bad_gp_request(&e, w.json),
    };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::cplc_set_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp cplc-set", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp cplc-set",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::cplc_set(s, t, &req, &auth, w.yes),
    )
}

fn run_gp_make_default(aid: &str, w: &GpWriteFlags) -> contract::ExitCode {
    let Some(aid) = parse_aid(aid) else {
        return report_refusal(
            "gp",
            "--aid must be 5 to 16 bytes of hex",
            serde_json::json!({ "error": { "kind": "bad-aid" } }),
            w.json,
        );
    };
    let req = gp::MakeDefaultRequest { aid };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::make_default_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp make-default", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp make-default",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::make_default(s, t, &req, &auth, w.yes),
    )
}

fn run_gp_rename_isd(new_aid: &str, w: &GpWriteFlags) -> contract::ExitCode {
    let Some(new_aid) = parse_aid(new_aid) else {
        return report_refusal(
            "gp",
            "--new-aid must be 5 to 16 bytes of hex",
            serde_json::json!({ "error": { "kind": "bad-aid" } }),
            w.json,
        );
    };
    let req = gp::RenameIsdRequest { new_aid };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::rename_isd_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp rename-isd", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp rename-isd",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::rename_isd(s, t, &req, &auth, w.yes),
    )
}

/// `--aid` of `gp aram add`: an AID of 5 to 16 bytes, or the empty string for
/// the empty AID-REF-DO that names every application (pySim's `--aid ""`).
fn parse_ara_aid(text: &str) -> Option<Vec<u8>> {
    let bytes = hex::decode(text.trim()).ok()?;
    (bytes.is_empty() || (5..=16).contains(&bytes.len())).then_some(bytes)
}

/// `sim-doctor gp aram add`: the rule's own fields are parsed and range-checked
/// before a reader is opened.
#[allow(clippy::too_many_arguments)]
fn aram_add_request(
    aid: Option<String>,
    aid_empty: bool,
    device_app_id: String,
    pkg_ref: Option<String>,
    apdu_never: bool,
    apdu_always: bool,
    apdu_filter: Option<String>,
    nfc_never: bool,
    nfc_always: bool,
    android_permissions: Option<String>,
    json: bool,
) -> Result<gp::StoreRefArDo, contract::ExitCode> {
    let refuse = |kind: &str, message: String| {
        report_refusal(
            "gp",
            &message,
            serde_json::json!({ "error": { "kind": kind, "message": message } }),
            json,
        )
    };
    let aid = match &aid {
        None => None,
        Some(text) => Some(parse_ara_aid(text).ok_or_else(|| {
            refuse(
                "bad-aid",
                "--aid must be 5 to 16 bytes of hex, or the empty string for every application"
                    .into(),
            )
        })?),
    };
    let Some(bytes) = hex::decode(device_app_id.trim()).ok() else {
        return Err(refuse(
            "bad-hex",
            "--device-app-id must be hex, 0, 20 or 32 bytes".into(),
        ));
    };
    let apdu = if apdu_never {
        Some(gp::ApduRule::Never)
    } else if apdu_always {
        Some(gp::ApduRule::Always)
    } else if let Some(text) = apdu_filter {
        let bytes = hex::decode(text.replace([' ', ':'], "")).map_err(|_| {
            refuse(
                "bad-hex",
                "--apdu-filter must be groups of 16 hex digits: 4 for CLA INS P1 P2 then 4 for the mask".into(),
            )
        })?;
        if bytes.is_empty() || bytes.len() % 8 != 0 {
            return Err(refuse(
                "bad-apdu-filter",
                format!("--apdu-filter is {} bytes, it is groups of 8", bytes.len()),
            ));
        }
        Some(gp::ApduRule::Filters(
            bytes
                .chunks(8)
                .map(|c| <[u8; 8]>::try_from(c).expect("8 bytes"))
                .collect(),
        ))
    } else {
        None
    };
    let nfc = match (nfc_never, nfc_always) {
        (true, _) => Some(gp::NfcRule::Never),
        (_, true) => Some(gp::NfcRule::Always),
        _ => None,
    };
    let permissions = match &android_permissions {
        None => None,
        Some(text) => Some(hex::decode(text.trim()).map_err(|_| {
            refuse(
                "bad-hex",
                "--android-permissions must be eight hex bytes".into(),
            )
        })?),
    };
    Ok(gp::StoreRefArDo {
        aid,
        aid_empty,
        device_app_id: bytes,
        package: pkg_ref,
        apdu,
        nfc,
        permissions,
    })
}

/// `sim-doctor gp aram <add|delete-all|lock>`: a dry run unless `--yes`,
/// offline without keys, and the delete-all acknowledgement is asked for
/// before any reader is opened.
fn run_gp_aram(action: AramAction) -> contract::ExitCode {
    match action {
        AramAction::Add {
            aid,
            aid_empty,
            device_app_id,
            pkg_ref,
            apdu_never,
            apdu_always,
            apdu_filter,
            nfc_never,
            nfc_always,
            android_permissions,
            write,
        } => match aram_add_request(
            aid,
            aid_empty,
            device_app_id,
            pkg_ref,
            apdu_never,
            apdu_always,
            apdu_filter,
            nfc_never,
            nfc_always,
            android_permissions,
            write.json,
        ) {
            Ok(rule) => run_aram_write(gp::AramAction::Add(Box::new(rule)), &write),
            Err(code) => code,
        },
        AramAction::DeleteAll {
            confirm_delete_all,
            write,
        } => {
            if let Err(message) =
                gp::check_delete_all_acknowledgement(confirm_delete_all.as_deref())
            {
                return report_refusal(
                    "gp",
                    &message,
                    serde_json::json!({
                        "error": { "kind": "delete-all-not-confirmed", "message": message }
                    }),
                    write.json,
                );
            }
            run_aram_write(gp::AramAction::DeleteAll, &write)
        }
        AramAction::Lock { write } => run_aram_write(gp::AramAction::Lock, &write),
        AramAction::Config {
            major,
            minor,
            patch,
            read,
        } => run_aram_config(major, minor, patch, &read),
    }
}

fn run_aram_write(action: gp::AramAction, w: &GpWriteFlags) -> contract::ExitCode {
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::aram_dry_run(&action) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp aram", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp aram",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::aram(s, t, &action, &auth, w.yes),
    )
}

fn run_aram_config(major: u8, minor: u8, patch: u8, r: &GpReadWriteFlags) -> contract::ExitCode {
    let plain = gp::aram_config_command(major, minor, patch)
        .encode()
        .expect("a built command encodes");
    let keys = match load_gp_keys(&r.keys, r.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        let mut data = serde_json::json!({
            "card_touched": false,
            "operation": "aram-config",
            "dry_run": true,
            "sent": false,
            "device_interface_version": format!("{major}.{minor}.{patch}"),
            "plan": {
                "apdus": [{ "step": "get_config", "apdu": hex::encode_upper(&plain) }],
                "note": "each APDU is sent with the class byte set for secure messaging and an 8-byte C-MAC appended (SCP03, C-MAC); shown here before that",
            },
            "note": "no keys were given, so the card was not contacted; add --keys-file or --keys-env to run the handshake",
        });
        if r.channel.channel != 0 {
            data["logical_channel"] = serde_json::json!(r.channel.channel);
            gp::retarget_channel(&mut data, r.channel.channel);
        }
        return emit_gp("gp aram config", data, r.json);
    };
    let auth = gp_auth(&keys, &r.keys, r.channel.channel);
    run_gp(
        "gp aram config",
        r.reader.as_deref(),
        r.json,
        r.trace,
        r.channel.channel,
        |s, t| gp::aram_config(s, t, major, minor, patch, &auth),
    )
}

fn run_gp_crs_list(
    aid: Option<&str>,
    reader: Option<&str>,
    json: bool,
    trace: bool,
    channel: u8,
) -> contract::ExitCode {
    let prefix = match aid {
        None => None,
        Some(a) => match gp::parse_crs_prefix(a) {
            Some(v) => Some(v),
            None => {
                return report_refusal(
                    "gp crs list",
                    "--aid must be 1 to 16 bytes of hex",
                    serde_json::json!({ "error": { "kind": "bad-aid" } }),
                    json,
                );
            }
        },
    };
    run_gp("gp crs list", reader, json, trace, channel, |s, t| {
        gp::crs_list(s, t, prefix.as_deref())
    })
}

fn run_gp_crs_info(
    reader: Option<&str>,
    json: bool,
    trace: bool,
    channel: u8,
) -> contract::ExitCode {
    run_gp("gp crs info", reader, json, trace, channel, |s, t| {
        gp::crs_info(s, t)
    })
}

fn run_gp_crs_set(aid: &str, activate: bool, w: &GpWriteFlags) -> contract::ExitCode {
    let name = if activate {
        "gp crs activate"
    } else {
        "gp crs deactivate"
    };
    let Some(aid) = parse_aid(aid) else {
        return report_refusal(
            name,
            "the AID must be 5 to 16 bytes of hex",
            serde_json::json!({ "error": { "kind": "bad-aid" } }),
            w.json,
        );
    };
    let req = gp::CrsRequest { aid, activate };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::crs_set_status_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp(name, data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        name,
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::crs_set_status(s, t, &req, &auth, w.yes),
    )
}

fn bad_gp_request(e: &gp::BuildError, json: bool) -> contract::ExitCode {
    report_refusal(
        "gp",
        &e.to_string(),
        serde_json::json!({ "error": { "kind": "bad-request", "message": e.to_string() } }),
        json,
    )
}

/// `sim-doctor gp delete-key`: a dry run unless `--yes`, offline without keys.
fn run_gp_delete_key(
    key_id: Option<u8>,
    key_version: Option<u8>,
    related: bool,
    allow_lockout: bool,
    delete_key: &GpDeleteKeyFlags,
) -> contract::ExitCode {
    let req = gp::DeleteKeyRequest {
        key_id,
        key_version,
        related,
        allow_lockout,
    };
    // INITIALIZE UPDATE key version defaults to 00 (card chooses).
    let kvn_args = GpKeyArgs {
        keys_file: delete_key.keys.keys_file.clone(),
        keys_env: delete_key.keys.keys_env.clone(),
        key_version: 0,
    };
    let keys = match load_gp_keys(&kvn_args, delete_key.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::delete_key_dry_run(&req) {
            Ok(mut data) => {
                if delete_key.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(delete_key.channel.channel);
                    gp::retarget_channel(&mut data, delete_key.channel.channel);
                }
                emit_gp("gp delete-key", data, delete_key.json)
            }
            Err(e) => bad_gp_request(&e, delete_key.json),
        };
    };
    let auth = gp_auth(&keys, &kvn_args, delete_key.channel.channel);
    run_gp(
        "gp delete-key",
        delete_key.reader.as_deref(),
        delete_key.json,
        delete_key.trace,
        delete_key.channel.channel,
        |s, t| gp::delete_key(s, t, &req, &auth, delete_key.yes),
    )
}

/// `sim-doctor gp install`: a dry run unless `--yes`, offline without keys. The
/// CAP is read and checked, and every AID validated, before a reader is opened.
#[allow(clippy::too_many_arguments)]
fn run_gp_install(
    load: &std::path::Path,
    module: Option<String>,
    app: Option<String>,
    params: &str,
    privileges: &str,
    block_size: usize,
    dap: &GpDapArgs,
    w: &GpWriteFlags,
) -> contract::ExitCode {
    let refuse = |kind: &str, message: String| {
        let data = serde_json::json!({ "error": { "kind": kind, "message": message } });
        report_refusal("gp", &message, data, w.json)
    };
    let bytes = match std::fs::read(load) {
        Ok(bytes) => bytes,
        Err(e) => {
            return refuse(
                "cap-unreadable",
                format!("cannot read {}: {e}", load.display()),
            )
        }
    };
    let cap = match sim_doctor::cap::Cap::parse(&bytes) {
        Ok(cap) => cap,
        Err(e) => return refuse("cap-invalid", e.to_string()),
    };
    let (package, applets) = match (cap.header_package_aid(), cap.applet_aids()) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => return refuse("cap-invalid", e.to_string()),
    };
    let aid_arg = |name: &str, text: &str| {
        parse_aid(text).ok_or_else(|| format!("--{name} must be 5 to 16 bytes of hex"))
    };
    let module_aid = match module {
        Some(text) => match aid_arg("module", &text) {
            Ok(aid) if applets.contains(&aid) => aid,
            Ok(_) => {
                return refuse(
                    "module-not-in-cap",
                    "--module is not an applet AID of this CAP".into(),
                )
            }
            Err(m) => return refuse("bad-aid", m),
        },
        None => match applets.as_slice() {
            [only] => only.clone(),
            _ => {
                return refuse(
                    "module-required",
                    format!(
                        "the CAP has {} applets; choose one with --module",
                        applets.len()
                    ),
                )
            }
        },
    };
    let app_aid = match app {
        Some(text) => match aid_arg("app", &text) {
            Ok(aid) => aid,
            Err(m) => return refuse("bad-aid", m),
        },
        None => module_aid.clone(),
    };
    let (Ok(params), Ok(privileges)) = (hex::decode(params), hex::decode(privileges)) else {
        return refuse("bad-hex", "--params and --privileges must be hex".into());
    };
    let dap = match load_dap(dap) {
        Ok(dap) => dap,
        Err((kind, message)) => return refuse(kind, message),
    };
    let req = gp::InstallRequest {
        load_file: cap.load_file(),
        load_file_aid: package,
        module_aid,
        app_aid,
        privileges,
        params,
        dap,
        block_size,
    };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::install_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp install", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp install",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::install(s, t, &req, &auth, w.yes),
    )
}

/// Reads and checks the DAP key and Security Domain of `gp install`, before a
/// reader is opened. `Err` is `(kind, message)`; the message never holds the key.
fn load_dap(args: &GpDapArgs) -> Result<Option<gp::DapRequest>, (&'static str, String)> {
    let source = match (&args.dap_key_file, &args.dap_key_env) {
        (Some(path), _) => gp::KeySource::File(path),
        (None, Some(name)) => gp::KeySource::Env(name),
        (None, None) => return Ok(None),
    };
    let key = gp::DapKey::load(source).map_err(|e| {
        let kind = match e {
            gp::KeyError::Kcv { .. } => "key-kcv-mismatch",
            _ => "keys-unusable",
        };
        (kind, format!("DAP key: {e}"))
    })?;
    let security_domain = match &args.dap_sd {
        Some(text) => Some(parse_aid(text).ok_or((
            "bad-aid",
            "--dap-sd must be 5 to 16 bytes of hex".to_string(),
        ))?),
        None => None,
    };
    let hash = match args.dap_hash {
        DapHash::Sha256 => gp::Lfdbh::Sha256,
        DapHash::Sha384 => gp::Lfdbh::Sha384,
        DapHash::Sha512 => gp::Lfdbh::Sha512,
    };
    Ok(Some(gp::DapRequest {
        key,
        security_domain,
        hash,
    }))
}

/// `sim-doctor gp put-key`: a dry run unless `--yes`, offline without keys. The
/// new key set is read and checked (format, stated KCVs) before a reader is opened.
fn run_gp_put_key(
    new_key_version: u8,
    replace_key_version: u8,
    key_id: u8,
    new: &GpNewKeyArgs,
    replace_current: bool,
    w: &GpWriteFlags,
) -> contract::ExitCode {
    let refuse = |kind: &str, message: String| {
        let data = serde_json::json!({ "error": { "kind": kind, "message": message } });
        report_refusal("gp", &message, data, w.json)
    };
    let source = match (&new.new_keys_file, &new.new_keys_env) {
        (Some(path), _) => gp::KeySource::File(path),
        (None, Some(name)) => gp::KeySource::Env(name),
        (None, None) => unreachable!("clap requires one of the two"),
    };
    let new_keys = match gp::Keys::load(source) {
        Ok(keys) if keys.is_key_set() => keys,
        Ok(_) => {
            return refuse(
                "keys-unusable",
                "the new key set is three keys, ENC MAC DEK".into(),
            )
        }
        Err(e) => {
            let kind = match e {
                gp::KeyError::Kcv { .. } => "key-kcv-mismatch",
                _ => "keys-unusable",
            };
            return refuse(kind, format!("new keys: {e}"));
        }
    };
    let req = gp::PutKeyRequest {
        new_version: new_key_version,
        replace_version: replace_key_version,
        key_id,
        new_keys,
        replace_current,
    };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::put_key_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp put-key", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    if !keys.has_dek() {
        return bad_gp_request(&gp::BuildError::DekMissing, w.json);
    }
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp put-key",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::put_key(s, t, &req, &auth, w.yes),
    )
}

/// `sim-doctor gp personalize`: a dry run unless `--yes`, offline without keys.
/// The AID and the BER-TLV data are checked before a reader is opened.
fn run_gp_personalize(aid: &str, data: &str, w: &GpWriteFlags) -> contract::ExitCode {
    let Some(aid) = parse_aid(aid) else {
        return report_refusal(
            "gp",
            "--aid must be 5 to 16 bytes of hex",
            serde_json::json!({ "error": { "kind": "bad-aid" } }),
            w.json,
        );
    };
    let Ok(data) = hex::decode(data) else {
        return report_refusal(
            "gp",
            "--data must be hex",
            serde_json::json!({ "error": { "kind": "bad-request" } }),
            w.json,
        );
    };
    let req = gp::PersonalizeRequest { aid, data };
    let keys = match load_gp_keys(&w.keys, w.json) {
        Ok(keys) => keys,
        Err(code) => return code,
    };
    let Some(keys) = keys else {
        return match gp::personalize_dry_run(&req) {
            Ok(mut data) => {
                if w.channel.channel != 0 {
                    data["logical_channel"] = serde_json::json!(w.channel.channel);
                    gp::retarget_channel(&mut data, w.channel.channel);
                }
                emit_gp("gp personalize", data, w.json)
            }
            Err(e) => bad_gp_request(&e, w.json),
        };
    };
    let auth = gp_auth(&keys, &w.keys, w.channel.channel);
    run_gp(
        "gp personalize",
        w.reader.as_deref(),
        w.json,
        w.trace,
        w.channel.channel,
        |s, t| gp::personalize(s, t, &req, &auth, w.yes),
    )
}

/// `sim-doctor euicc <info|profiles|notifications>`: one read-only ES10 query.
fn run_euicc(query: euicc::Query, flags: &EuiccFlags) -> contract::ExitCode {
    let max = usize::from(flags.max_segment);
    run_euicc_op(
        flags,
        |session, aid| euicc::run_with(session, aid, query, max),
        |data| euicc::to_human(query, data),
    )
}

/// `sim-doctor euicc nickname <iccid> <name> [--yes]`: SetNickname, a dry run
/// unless `--yes`. The ICCID and name are checked before a reader is opened.
fn run_euicc_nickname(args: &NicknameArgs) -> contract::ExitCode {
    let request = match euicc::Nickname::new(&args.iccid, &args.name, args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::nickname(session, aid, max, &request),
        euicc::nickname_to_human,
    )
}

/// `sim-doctor euicc <enable|disable> <iccid|aid> [--yes]`: a dry run unless
/// `--yes`. The identifier is checked before a reader is opened.
fn run_euicc_state(action: euicc::Action, args: &StateArgs) -> contract::ExitCode {
    let request = match euicc::StateChange::new(action, &args.id, args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::set_state(session, aid, max, &request),
        euicc::state_to_human,
    )
}

/// `sim-doctor euicc delete <iccid|aid> [--yes]`: a dry run unless `--yes`.
fn run_euicc_delete(args: &DeleteArgs) -> contract::ExitCode {
    let request = match euicc::ProfileDelete::new(&args.id, args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::delete_profile(session, aid, max, &request),
        euicc::erase_to_human,
    )
}

/// `sim-doctor euicc reset [--operational] [--test] [--smdp-address]
/// [--confirm-eid EID] [--yes]`. Options and confirmation are checked before a
/// reader is opened.
fn run_euicc_reset(args: &ResetArgs) -> contract::ExitCode {
    let options = sim_doctor::es10::ResetOptions {
        delete_operational_profiles: args.operational,
        delete_field_loaded_test_profiles: args.test,
        reset_default_smdp_address: args.smdp_address,
    };
    let request = match euicc::MemoryReset::new(options, args.confirm_eid.as_deref(), args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::memory_reset(session, aid, max, &request),
        euicc::erase_to_human,
    )
}

/// `sim-doctor euicc set-default-dp <ADDRESS> [--yes]`: ES10a
/// SetDefaultDpAddress. The address is validated before any reader is opened,
/// and the dry run opens none at all - it is built from the library alone and
/// reports `card_touched: false`.
fn run_euicc_default_dp(args: &DefaultDpArgs) -> contract::ExitCode {
    const KIND: &str = contract::DEFAULT_KIND;
    let json = args.flags.json;
    guard_exchange(KIND, json);
    let refuse = |f: euicc::Failure| report_refusal(KIND, &f.message, f.data, json);
    let request = match euicc::DefaultDp::new(&args.address, args.yes) {
        Ok(request) => request,
        Err(f) => return refuse(f),
    };
    if !request.apply {
        return match euicc::default_dp_plan(&request) {
            Ok(data) => emit_offline_euicc(data, euicc::default_dp_to_human, json),
            Err(f) => refuse(f),
        };
    }
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::set_default_dp(session, aid, max, &request),
        euicc::default_dp_to_human,
    )
}

/// Prints one lpac envelope, or the human report, for `data` that was built
/// without a card in sight: the offline half of [`run_euicc_op`].
fn emit_offline_euicc(
    data: serde_json::Value,
    human: fn(&serde_json::Value) -> String,
    json: bool,
) -> contract::ExitCode {
    const KIND: &str = contract::DEFAULT_KIND;
    let rendered = if json {
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        human(&data).trim_end().to_owned()
    };
    if let Err(err) = emit_stdout(&rendered, "the euicc report") {
        eprintln!("sim-doctor: {err}");
        return contract::ExitCode::Findings;
    }
    contract::ExitCode::Success
}

/// `sim-doctor euicc notifications remove <seq> [--yes]`: a dry run unless `--yes`.
fn run_euicc_remove(args: &RemoveArgs) -> contract::ExitCode {
    let request = euicc::NotificationRemoval {
        seq_number: args.seq,
        apply: args.yes,
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::remove_notification(session, aid, max, request),
        euicc::erase_to_human,
    )
}

/// `sim-doctor euicc notifications dump [--seq N] [-o FILE]`: read-only.
fn run_euicc_dump(args: &DumpArgs) -> contract::ExitCode {
    let max = usize::from(args.flags.max_segment);
    let output = args.output.clone();
    let to_file = output.is_some();
    run_euicc_op(
        &args.flags,
        |session, aid| {
            let mut data = euicc::dump_notifications(session, aid, max, args.seq)?;
            if let Some(path) = &output {
                let doc = serde_json::json!({
                    "format": data["format"], "eid": data["eid"],
                    "notifications": data["notifications"],
                });
                let text = serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n";
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .and_then(|mut f| io::Write::write_all(&mut f, text.as_bytes()))
                    .map_err(|e| {
                        euicc::Failure::new(
                            "write-failed",
                            format!("cannot write {}: {e}", path.display()),
                            serde_json::json!({}),
                        )
                    })?;
                data["written_to"] = serde_json::json!(path.display().to_string());
            }
            Ok(data)
        },
        |data| {
            if to_file {
                euicc::dump_to_human(data)
            } else {
                // The document itself, re-loadable by `notifications replay`.
                serde_json::to_string_pretty(&serde_json::json!({
                    "format": data["format"], "eid": data["eid"],
                    "notifications": data["notifications"],
                }))
                .unwrap_or_default()
            }
        },
    )
}

/// `sim-doctor euicc notifications replay --from FILE [--yes]`: a dry run
/// unless `--yes`. Touches no card; opens a transport only when sending.
fn run_euicc_replay(args: &ReplayArgs) -> contract::ExitCode {
    const KIND: &str = contract::DEFAULT_KIND;
    let refuse = |f: euicc::Failure| report_refusal(KIND, &f.message, f.data, args.json);
    let text = match std::fs::read_to_string(&args.from) {
        Ok(text) => text,
        Err(e) => {
            return refuse(euicc::Failure::new(
                "bad-dump",
                format!("cannot read {}: {e}", args.from.display()),
                serde_json::json!({}),
            ))
        }
    };
    let mut transport = if args.yes {
        match sim_doctor::backend::HttpBackend::open_from_env() {
            Ok(t) => Some(t),
            Err(e) => {
                return refuse(euicc::Failure::new(
                    "transport-unavailable",
                    e,
                    serde_json::json!({}),
                ))
            }
        }
    } else {
        None
    };
    let data = match notif::replay(
        &text,
        transport
            .as_mut()
            .map(|t| &mut **t as &mut dyn sim_doctor::es9::Es9Transport),
    ) {
        Ok(data) => data,
        Err(f) => return refuse(f),
    };
    let rendered = if args.json {
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        notif::to_human(&data).trim_end().to_owned()
    };
    if let Err(err) = emit_stdout(&rendered, "the replay report") {
        eprintln!("sim-doctor: {err}");
        return contract::ExitCode::Findings;
    }
    contract::ExitCode::Success
}

/// Connects to the reader and card named by `flags`, runs `op` against the
/// ISD-R, and prints its data (lpac envelope under `--json`, else `human`).
fn run_euicc_op(
    flags: &EuiccFlags,
    op: impl FnOnce(&mut PcscSession, &[u8]) -> Result<serde_json::Value, euicc::Failure>,
    human: impl FnOnce(&serde_json::Value) -> String,
) -> contract::ExitCode {
    const KIND: &str = contract::DEFAULT_KIND;
    let json = flags.json;
    guard_exchange(KIND, json);
    let refuse =
        |failure: scan::Failure| report_refusal(KIND, &failure.message, failure.data(), json);
    let aid = match flags.aid.as_deref() {
        None => euicc::ISDR_AID.to_vec(),
        Some(text) => match hex::decode(text) {
            Ok(aid) if (5..=16).contains(&aid.len()) => aid,
            _ => {
                return refuse(scan::Failure::new(
                    "bad-aid",
                    format!("--aid must be 5 to 16 bytes of hex, got {text:?}"),
                ))
            }
        },
    };
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => return refuse(scan::Failure::new("context-unavailable", err.to_string())),
    };
    let reader = match pick_reader(&readers, flags.reader.as_deref(), None) {
        Ok(reader) => reader,
        Err(failure) => return refuse(failure),
    };
    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return refuse(scan::Failure::new(kind, err.to_string()));
        }
    };
    let mut data = match op(&mut session, &aid) {
        Ok(data) => data,
        Err(failure) => {
            let mut data = failure.data;
            data["reader"] = serde_json::json!(reader.as_str());
            return report_refusal(KIND, &failure.message, data, json);
        }
    };
    data["reader"] = serde_json::json!(reader.as_str());
    let rendered = if json {
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        human(&data).trim_end().to_owned()
    };
    if let Err(err) = emit_stdout(&rendered, "the euicc report") {
        eprintln!("sim-doctor: {err}");
        return contract::ExitCode::Findings;
    }
    contract::ExitCode::Success
}

/// `sim-doctor trace`: decode a saved APDU trace. Touches no card.
fn run_trace(args: &TraceArgs) -> contract::ExitCode {
    use std::io::Read;
    const KIND: &str = "trace";
    let refuse = |m: String| report_refusal(KIND, &m, serde_json::json!({ "error": m }), args.json);
    let mut input = Vec::new();
    if let Some(path) = args.file.as_deref().filter(|p| *p != "-") {
        // A FIFO, device or directory is refused before it is opened, so nothing can block the read.
        if std::fs::metadata(path).is_ok_and(|m| !m.is_file()) {
            return refuse(format!(
                "cannot read the trace: {path} is not a regular file"
            ));
        }
    }
    let read = match args.file.as_deref() {
        None | Some("-") => io::stdin().take(MAX_WHY_FILE_BYTES).read_to_end(&mut input),
        Some(path) => std::fs::File::open(path)
            .and_then(|f| f.take(MAX_WHY_FILE_BYTES).read_to_end(&mut input)),
    };
    if let Err(err) = read {
        return refuse(format!("cannot read the trace: {err}"));
    }
    let rows = match trace::parse_bytes(&input) {
        Ok(pairs) => trace::decode(&pairs),
        Err(message) => return refuse(message),
    };
    if rows.last().is_some_and(|r| r.response.is_empty()) {
        eprintln!("sim-doctor: warning: the trace ends on a command with no response (odd number of hex lines?)");
    }
    let rendered = if args.json {
        let exchanges: Vec<_> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| r.to_json(i + 1))
            .collect();
        let data = serde_json::json!({
            "card_touched": false,
            "count": rows.len(),
            "selected": rows.last().map(|r| r.selected.clone()),
            "exchanges": exchanges,
        });
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => return refuse(err.to_string()),
        }
    } else {
        let display = trace::Display {
            show_raw_apdu: args.show_raw_apdu,
            show_select: args.no_suppress_select,
            show_status: args.no_suppress_status,
        };
        trace::render(&rows, display).trim_end().to_owned()
    };
    match emit_stdout(&rendered, "the decoded trace") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => refuse(message),
    }
}

/// `sim-doctor sms decode`: offline SMS TPDU decoding, text or one `sms` envelope. A bad hex string or a
/// malformed PDU is a refusal with exit 2 (it could not run), never a finding.
fn run_sms_decode(args: &[String], tpdu: bool, json: bool) -> contract::ExitCode {
    use std::io::Read;
    const KIND: &str = "sms";
    let refuse = |m: String| {
        eprintln!("sim-doctor: {m}");
        if json {
            let data = serde_json::json!({ "error": m });
            if let Ok(line) =
                contract::Envelope::new(KIND, contract::ExitCode::Error, &m, data).to_json()
            {
                let _ = emit_stdout(&line, "the sms error");
            }
        }
        contract::ExitCode::Error
    };
    let mut items: Vec<String> = args.iter().filter(|a| a.as_str() != "-").cloned().collect();
    if args.is_empty() || args.iter().any(|a| a == "-") {
        let mut input = Vec::new();
        if let Err(err) = io::stdin().take(MAX_WHY_FILE_BYTES).read_to_end(&mut input) {
            return refuse(format!("cannot read stdin: {err}"));
        }
        items.extend(
            String::from_utf8_lossy(&input)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned),
        );
    }
    if items.is_empty() {
        return refuse("no SMS PDU given".to_owned());
    }
    let mut messages = Vec::new();
    for item in &items {
        let bytes = match cat::parse_hex(item) {
            Ok(b) => b,
            Err(e) => return refuse(format!("`{item}`: {e}")),
        };
        match sms::decode(&bytes, !tpdu) {
            Ok(m) => messages.push(m),
            Err(e) => return refuse(format!("`{item}`: {e}")),
        }
    }
    let reassembled = sms::reassemble(&messages);
    let rendered = if json {
        let data = serde_json::json!({ "card_touched": false, "count": messages.len(), "messages": messages, "reassembled": reassembled });
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => return refuse(err.to_string()),
        }
    } else {
        let mut blocks: Vec<String> = messages
            .iter()
            .map(|m| {
                m.as_object()
                    .map(|o| {
                        o.iter()
                            .map(|(k, v)| format!("{k} {v}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default()
            })
            .collect();
        for g in &reassembled {
            let reference = g
                .get("reference")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let address = g.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let total = g.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
            let parts: Vec<String> = g
                .get("parts")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|v| v.as_u64().unwrap_or(0).to_string())
                        .collect()
                })
                .unwrap_or_default();
            let missing: Vec<String> = g
                .get("missing")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|v| v.as_u64().unwrap_or(0).to_string())
                        .collect()
                })
                .unwrap_or_default();
            let text = g.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let mut block = format!("reassembled {reference} {address}\n");
            block.push_str(&format!("parts {} of {}", parts.join(","), total));
            if !missing.is_empty() {
                block.push_str(&format!(" (missing {})", missing.join(",")));
            }
            block.push_str(&format!("\ntext {}", text));
            blocks.push(block);
        }
        blocks.join("\n\n")
    };
    match emit_stdout(&rendered, "the decoded SMS") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => refuse(message),
    }
}

/// `sim-doctor cat decode`: offline CAT decoding, text or one `cat` envelope.
fn run_cat_decode(args: &[String], json: bool) -> contract::ExitCode {
    use std::io::Read;
    const KIND: &str = "cat";
    let refuse = |m: String| report_refusal(KIND, &m, serde_json::json!({ "error": m }), json);
    let mut items: Vec<String> = args.iter().filter(|a| a.as_str() != "-").cloned().collect();
    if args.is_empty() || args.iter().any(|a| a == "-") {
        let mut input = Vec::new();
        if let Err(err) = io::stdin().take(MAX_WHY_FILE_BYTES).read_to_end(&mut input) {
            return refuse(format!("cannot read stdin: {err}"));
        }
        items.extend(
            String::from_utf8_lossy(&input)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned),
        );
    }
    if items.is_empty() {
        return refuse("no CAT data given".to_owned());
    }
    let mut decoded = Vec::new();
    for item in &items {
        let bytes = match cat::parse_hex(item) {
            Ok(b) => b,
            Err(e) => return refuse(format!("`{item}`: {e}")),
        };
        match cat::decode(&bytes) {
            Ok(d) => decoded.push(d),
            Err(e) => return refuse(format!("`{item}`: {e}")),
        }
    }
    let rendered = if json {
        let data = serde_json::json!({
            "card_touched": false,
            "count": decoded.len(),
            "objects": decoded.iter().map(|d| d.json.clone()).collect::<Vec<_>>(),
        });
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => return refuse(err.to_string()),
        }
    } else {
        decoded
            .iter()
            .map(cat::render)
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_owned()
    };
    match emit_stdout(&rendered, "the decoded CAT data") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => refuse(message),
    }
}

/// Runs `sim-doctor ota-crypto`: offline DES/3DES/AES-CBC encrypt, decrypt,
/// checksum sign and check. The envelope kind is "ota-crypto"; its `data` carries
/// the algorithm, operation, key length and input/output bytes, never the key
/// itself.
///
/// Exit codes: 0 on a completed operation; 1 only when `check`'s MAC does not
/// match (still a delivered answer, so `valid` is `false`); 2 for bad hex, a
/// wrong key length, a wrong IV length or data that is not a whole number of
/// blocks - the same refusal shape [`run_cat_decode`] uses.
/// `sim-doctor esim-cert verify`: offline chain check. Reads two files, touches no card.
fn run_esim_cert_verify(
    chain: &str,
    root: &str,
    at: Option<&str>,
    json: bool,
) -> contract::ExitCode {
    const KIND: &str = "esim-cert";
    let refuse = |m: String| report_refusal(KIND, &m, serde_json::json!({ "error": m }), json);
    let now = match at {
        None => cert::now_stamp(),
        Some(t) if t.len() == 14 && t.bytes().all(|b| b.is_ascii_digit()) => t.to_owned(),
        Some(t) => return refuse(format!("--at `{t}` is not YYYYMMDDHHMMSS")),
    };
    let load = |path: &str| {
        cert::read_regular_file(std::path::Path::new(path))
            .and_then(|bytes| cert::parse_chain(&bytes).map_err(|e| format!("{path}: {e}")))
    };
    let chain_certs = match load(chain) {
        Ok(certs) => certs,
        Err(m) => return refuse(m),
    };
    let root_cert = match load(root) {
        Ok(mut certs) if certs.len() == 1 => certs.remove(0),
        Ok(certs) => {
            return refuse(format!(
                "--root must hold exactly one certificate, found {}",
                certs.len()
            ))
        }
        Err(m) => return refuse(m),
    };
    let report = match cert::verify_chain(&chain_certs, &root_cert, &now) {
        Ok(report) => report,
        Err(e) => return refuse(e.to_string()),
    };
    let verdict = cert::verdict(&report);
    let code = match verdict {
        cert::Verdict::Verified => contract::ExitCode::Success,
        _ => contract::ExitCode::Findings,
    };
    let data = cert::to_json(&report, &root_cert, &now);
    let text = if json {
        let message = if code == contract::ExitCode::Success {
            contract::OK_MESSAGE
        } else {
            verdict.as_str()
        };
        match contract::Envelope::new(KIND, code, message, data).to_json() {
            Ok(line) => line,
            Err(err) => return refuse(err.to_string()),
        }
    } else {
        let mut lines = Vec::new();
        for c in &report.certs {
            lines.push(format!(
                "[{}] serial {} sha256 {} valid {} to {} ({}) signature {} issuer {}",
                c.index,
                c.serial,
                &c.fingerprint[..16],
                c.not_before,
                c.not_after,
                match c.validity {
                    cert::Validity::Valid => "in period",
                    cert::Validity::NotYetValid => "NOT YET VALID",
                    cert::Validity::Expired => "EXPIRED",
                },
                match c.signature {
                    cert::SignatureCheck::Valid => "valid",
                    cert::SignatureCheck::Invalid => "INVALID",
                    cert::SignatureCheck::Unsupported(_) => "unsupported",
                },
                if c.issuer_name_matches {
                    "ok"
                } else {
                    "MISMATCH"
                },
            ));
        }
        for f in cert::findings(&report) {
            lines.push(format!(
                "{}: {}",
                f["severity"].as_str().unwrap_or(""),
                f["message"].as_str().unwrap_or("")
            ));
        }
        lines.push(format!(
            "verdict: {} (at {now}, CI root {})",
            verdict.as_str(),
            &root_cert.fingerprint[..16]
        ));
        lines.join("\n")
    };
    match emit_stdout(&text, "the esim-cert report") {
        Ok(()) => code,
        Err(message) => refuse(message),
    }
}

fn run_otacrypto(args: OtaCryptoArgs) -> contract::ExitCode {
    const KIND: &str = "ota-crypto";

    // Pull the operation apart so the hex parsing and the crypto dispatch share
    // one pair of hands on each field.
    let (alg, op, key, iv, data, mac_len, mac, json) = match args.action {
        OtaCryptoAction::Encrypt {
            alg,
            key,
            iv,
            data,
            json,
        } => (alg.into(), "encrypt", key, iv, data, None, None, json),
        OtaCryptoAction::Decrypt {
            alg,
            key,
            iv,
            data,
            json,
        } => (alg.into(), "decrypt", key, iv, data, None, None, json),
        OtaCryptoAction::Sign {
            alg,
            key,
            data,
            mac_len,
            json,
        } => (
            alg.into(),
            "sign",
            key,
            None,
            data,
            Some(mac_len),
            None,
            json,
        ),
        OtaCryptoAction::Check {
            alg,
            key,
            data,
            mac,
            json,
        } => (alg.into(), "check", key, None, data, None, Some(mac), json),
    };

    let refuse = |m: String| report_refusal(KIND, &m, serde_json::json!({ "error": m }), json);

    let key_bytes = match cat::parse_hex(&key) {
        Ok(b) => b,
        Err(e) => return refuse(format!("`--key`: {e}")),
    };
    let input_bytes = match cat::parse_hex(&data) {
        Ok(b) => b,
        Err(e) => return refuse(format!("DATA: {e}")),
    };
    let iv_bytes = match iv {
        Some(s) => Some(match cat::parse_hex(&s) {
            Ok(b) => b,
            Err(e) => return refuse(format!("`--iv`: {e}")),
        }),
        None => None,
    };
    let mac_bytes = match mac {
        Some(s) => match cat::parse_hex(&s) {
            Ok(b) => b,
            Err(e) => return refuse(format!("`--mac`: {e}")),
        },
        None => Vec::new(),
    };

    let outcome: Result<serde_json::Value, otacrypto::Error> = match op {
        "encrypt" => otacrypto::encrypt(alg, &key_bytes, iv_bytes.as_deref(), &input_bytes)
            .map(|out| serde_json::json!({ "output": hex::encode(&out) })),
        "decrypt" => otacrypto::decrypt(alg, &key_bytes, iv_bytes.as_deref(), &input_bytes)
            .map(|out| serde_json::json!({ "output": hex::encode(&out) })),
        "sign" => otacrypto::sign(alg, &key_bytes, &input_bytes, mac_len)
            .map(|out| serde_json::json!({ "mac": hex::encode(&out) })),
        "check" => otacrypto::check(alg, &key_bytes, &input_bytes, &mac_bytes)
            .map(|ok| serde_json::json!({ "valid": ok })),
        _ => unreachable!(),
    };

    match outcome {
        Err(e) => {
            // Crypto preconditions (bad key length, bad IV length, a partial
            // block): exit 2, the same refusal shape run_cat_decode uses.
            let m = e.to_string();
            let data = serde_json::json!({ "error": m });
            let envelope = contract::Envelope::new(KIND, contract::ExitCode::Error, &m, data);
            let line = match envelope.to_json() {
                Ok(l) => l,
                Err(e) => return refuse(e.to_string()),
            };
            match emit_stdout(&line, "the ota-crypto error") {
                Ok(()) => contract::ExitCode::Error,
                Err(message) => refuse(message),
            }
        }
        Ok(inner) => {
            let mut data = serde_json::json!({
                "alg": format!("{alg:?}").to_lowercase(),
                "op": op,
                "key_bytes": key_bytes.len(),
                "input_bytes": input_bytes.len(),
            });
            if let serde_json::Value::Object(more) = inner {
                for (k, v) in more {
                    data[k] = v;
                }
            }
            // `check` with a wrong MAC is a delivered answer (exit 1), not a
            // refusal: the MAC is valid input, it just did not match.
            let code = match (op, data["valid"].as_bool()) {
                ("check", Some(false)) => contract::ExitCode::Findings,
                _ => contract::ExitCode::Success,
            };
            let envelope = contract::Envelope::new(KIND, code, contract::OK_MESSAGE, data);
            let line = match envelope.to_json() {
                Ok(l) => l,
                Err(e) => return refuse(e.to_string()),
            };
            match emit_stdout(&line, "the ota-crypto result") {
                Ok(()) => code,
                Err(message) => refuse(message),
            }
        }
    }
}

/// Everything `sim-doctor saip` takes.
#[derive(Args)]
struct SaipArgs {
    #[command(subcommand)]
    action: SaipAction,
}

#[derive(Subcommand)]
enum SaipAction {
    /// Decode a SAIP profile package (DER, the concatenated ProfileElements) offline.
    Parse {
        /// Path to the profile package. Read-only; the file is capped at 8 MiB.
        file: std::path::PathBuf,
        /// Emit one JSON envelope of kind "saip" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Runs `sim-doctor saip parse`: reads the file under a size cap and decodes it with
/// [`saip::decode`]. The envelope kind is "saip"; `data` is `{pe_count, elements}`.
///
/// Exit codes: 0 when decoded; 2 when the file cannot be read or is not a well-formed
/// package (a refusal, with the offset in the message). Nothing is sent to a card.
fn run_saip_parse(path: &std::path::Path, json: bool) -> contract::ExitCode {
    use std::io::Read;
    const KIND: &str = "saip";
    let refuse = |m: String| {
        eprintln!("sim-doctor: {m}");
        if json {
            let data = serde_json::json!({ "error": m });
            if let Ok(line) =
                contract::Envelope::new(KIND, contract::ExitCode::Error, &m, data).to_json()
            {
                let _ = emit_stdout(&line, "the saip error");
            }
        }
        contract::ExitCode::Error
    };
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(err) => return refuse(format!("cannot read {}: {err}", path.display())),
    };
    let mut bytes = Vec::new();
    // One byte past the cap, so an over-long file is refused by `saip::decode`, not truncated.
    let cap = saip::MAX_FILE_BYTES as u64 + 1;
    if let Err(err) = file.take(cap).read_to_end(&mut bytes) {
        return refuse(format!("cannot read {}: {err}", path.display()));
    }
    let decoded = match saip::decode(&bytes) {
        Ok(value) => value,
        Err(err) => return refuse(err.to_string()),
    };
    if json {
        let envelope = contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            decoded,
        );
        let line = match envelope.to_json() {
            Ok(l) => l,
            Err(e) => return refuse(e.to_string()),
        };
        return match emit_stdout(&line, "the saip result") {
            Ok(()) => contract::ExitCode::Success,
            Err(message) => refuse(message),
        };
    }
    let mut out = String::new();
    for element in decoded["elements"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "{:>3}  {:<22} tag {:<6} length {}\n",
            element["index"],
            element["type"].as_str().unwrap_or("?"),
            element["tag"].as_str().unwrap_or("?"),
            element["length"],
        ));
    }
    out.push_str(&format!("{} profile elements\n", decoded["pe_count"]));
    match emit_stdout(out.trim_end(), "the saip result") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => refuse(message),
    }
}

/// Every rule `rules list`, `rules explain`, `why` and `fix` know: the scan's,
/// then the TS.48 comparison's. A scan still runs and scores only its own.
fn all_specs() -> Vec<rules::RuleSpec> {
    scan::all_specs()
}

/// Runs `sim-doctor ts48 compare`: the scan's walk, then the diff.
///
/// The walk is the one `run_scan` does (same candidates, same status meaning,
/// same default bounds, same walk-limit flags) and nothing after it touches the card: no TAR audit.
fn run_ts48_compare(args: Ts48CompareArgs) -> contract::ExitCode {
    guard_exchange(ts48::KIND, args.json);
    let fixture = match ts48::Fixture::bundled() {
        Ok(fixture) => fixture,
        Err(err) => {
            return report_refusal(
                ts48::KIND,
                &format!("the bundled TS.48 file list is unreadable: {err}"),
                serde_json::json!({ "error": { "kind": "fixture-unreadable" } }),
                args.json,
            )
        }
    };
    let refuse = |failure: scan::Failure| {
        report_refusal(ts48::KIND, &failure.message, failure.data(), args.json)
    };

    if checkpoint() {
        return report_interrupted(ts48::KIND, args.json);
    }
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => return refuse(scan::Failure::new("context-unavailable", err.to_string())),
    };
    let reader = match pick_reader(&readers, args.reader.as_deref(), None) {
        Ok(reader) => reader,
        Err(failure) => return refuse(failure),
    };
    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return refuse(scan::Failure::new(kind, err.to_string()));
        }
    };

    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        candidates: walk::Candidates::SimFamilies,
        meaning: walk::StatusMeaning::default(),
        limits: limits_from(&args.walk_limits),
        reserved_file_ids: false,
        break_after_count_match: args.walk_limits.break_after_count_match,
        session: session::Policy::default(),
    };
    let tree = match walk::walk(&mut session, &args.dialect.tag_set(), &options) {
        Ok(tree) => tree,
        Err(err) => return refuse(scan::Failure::new("walk-failed", err.to_string())),
    };
    if checkpoint() {
        return report_interrupted(ts48::KIND, args.json);
    }

    let comparison = ts48::compare(&fixture.files, &ts48::observe(&tree));
    let complete = tree.is_complete();
    let findings = ts48::findings(
        &comparison,
        (!complete).then_some("the walk stopped at a bound, so this list may be short"),
    );
    if !complete {
        eprintln!("sim-doctor: warning: the walk stopped early, so this is not the whole card");
    }

    let (rendered, what) = if args.json {
        let data = ts48::to_json(
            &fixture,
            &comparison,
            &findings,
            reader.as_str(),
            args.dialect.id(),
            complete,
        );
        let envelope = contract::Envelope::new(
            ts48::KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        );
        match envelope.to_json() {
            Ok(line) => (line, "the ts48 envelope"),
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        (
            ts48::to_human(&comparison, &findings, complete),
            "the ts48 report",
        )
    };
    match emit_stdout(rendered.trim_end_matches('\n'), what) {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// The fragment swicc-pcsc names its reader with.
///
/// \[V] docs/swsim-fixture.md: "Expect a reader whose name contains swICC",
/// and every other place in this crate that matches the software card's
/// reader (`tests/card_fixture.rs`) does it the same way: a case-insensitive
/// substring match, because the exact spelling is not part of swicc-pcsc's
/// contract and this crate does not own it.
const SWICC_READER_FRAGMENT: &str = "swicc";

/// Error kind every `fuzz` opt-in refusal carries.
const FUZZ_OPT_IN_KIND: &str = "fuzz-needs-opt-in";

/// The mandatory safety interlock on every `fuzz` subcommand (issue #16).
///
/// Refuses, with [`FUZZ_OPT_IN_KIND`], unless BOTH
/// `--i-understand-this-can-brick-the-card` is given AND the reader's name
/// matches the software card, or `--allow-real-hardware` is also given.
///
/// **Deterministic, and never touches PC/SC.** `reader` is the raw
/// `--reader` string the command line carried, not a name read back from an
/// opened session - so this decision never depends on what hardware happens
/// to be attached to the machine running it, only on what was typed. An
/// omitted `--reader` is treated as "not recognisably the software card",
/// the same as a name that does not match: this is the side to be wrong on,
/// since the alternative is listing readers to find out what the default
/// would have been, which is exactly the PC/SC round trip this check exists
/// to run only once the interlock has already passed.
fn fuzz_opt_in(safety: &FuzzSafety, reader: Option<&str>) -> Result<(), String> {
    if !safety.i_understand {
        return Err(
            "fuzz refuses to run without --i-understand-this-can-brick-the-card: a fuzz run \
             sends undocumented CLA/INS values and OTA envelopes that can brick a SIM"
                .to_owned(),
        );
    }
    let is_software =
        reader.is_some_and(|name| name.to_ascii_lowercase().contains(SWICC_READER_FRAGMENT));
    if !is_software && !safety.allow_real_hardware {
        return Err(format!(
            "fuzz refuses to run against {:?}: it does not look like the software card \
             (swicc-pcsc names its reader with \"swICC\", see docs/swsim-fixture.md); pass \
             --allow-real-hardware to run against it anyway",
            reader.unwrap_or("(no --reader given)")
        ));
    }
    Ok(())
}

/// Opens the reader `safety` and `kind` agree to open, or returns the exit
/// code of a refusal.
///
/// Shared by `fuzz apdu` and `fuzz ota`: the opt-in check, then the same
/// reader-listing and reader-opening path `run_scan` and `run_ts48_compare`
/// use, so a fuzz refusal is the same shape as every other refusal in this
/// crate - `data.error`, exit 1, no `data.findings`.
///
/// **The interlock runs once, first, against the raw `--reader` string.**
/// [`fuzz_opt_in`] never needs PC/SC to answer, so it is checked - and can
/// refuse - before [`Pcsc::readers`] is even called, which is what makes the
/// refusal deterministic: it depends only on the command line, never on
/// which readers happen to be attached to the machine running it.
fn open_fuzz_session(
    kind: &str,
    safety: &FuzzSafety,
) -> Result<(ReaderName, PcscSession), contract::ExitCode> {
    if let Err(message) = fuzz_opt_in(safety, safety.reader.as_deref()) {
        return Err(report_refusal(
            kind,
            &message,
            serde_json::json!({ "error": { "kind": FUZZ_OPT_IN_KIND, "message": message } }),
            safety.json,
        ));
    }
    if checkpoint() {
        return Err(report_interrupted(kind, safety.json));
    }
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => {
            return Err(report_failure(
                &scan::Failure::new("context-unavailable", err.to_string()),
                safety.json,
            ))
        }
    };
    let reader = match pick_reader(&readers, safety.reader.as_deref(), None) {
        Ok(reader) => reader.clone(),
        Err(failure) => return Err(report_failure(&failure, safety.json)),
    };
    let session = match PcscSession::open(&reader) {
        Ok(session) => session,
        Err(err) => {
            let failure_kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return Err(report_failure(
                &scan::Failure::new(failure_kind, err.to_string()),
                safety.json,
            ));
        }
    };
    Ok((reader, session))
}

/// Creates (truncating) the `SIM_DOCTOR_RECORD` log. Its content is sensitive
/// raw card data (ICCID, IMSI, file contents), so on unix it is owner-only 0600.
fn record_log_file(path: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Runs `sim-doctor fuzz apdu`: CLA discovery (level 1) or CLA+INS discovery
/// (level 2), behind the safety interlock.
fn run_fuzz_apdu(args: FuzzApduArgs) -> contract::ExitCode {
    // The opt-in flag is the very first gate: a run missing it is refused
    // before any other flag, including --class, is even looked at. The
    // reader-matches-the-software-card half of the interlock needs a reader
    // to check against, so it waits for `open_fuzz_session`.
    if !args.safety.i_understand {
        return report_refusal(
            apdu_scan::KIND,
            &fuzz_opt_in(&args.safety, None).unwrap_err(),
            serde_json::json!({ "error": { "kind": FUZZ_OPT_IN_KIND } }),
            args.safety.json,
        );
    }

    let mode = if args.safety.quick {
        apdu_scan::Mode::Quick
    } else {
        apdu_scan::Mode::Full
    };

    // A bad or missing --class is a command-line mistake, not a card fact, so
    // it is caught before a reader is even listed - the same reason
    // `pick_reader` is exit 1 rather than 129 but a flag's own shape is
    // caught before either runs.
    let class = if args.level == 2 {
        let Some(class_text) = &args.class else {
            return report_refusal(
                apdu_scan::KIND,
                "--level 2 needs --class HEX, the CLA to probe INS values at",
                serde_json::json!({ "error": { "kind": "missing-class" } }),
                args.safety.json,
            );
        };
        match u8::from_str_radix(class_text.trim_start_matches("0x"), 16) {
            Ok(class) => Some(class),
            Err(_) => {
                return report_refusal(
                    apdu_scan::KIND,
                    &format!("{class_text:?} is not a CLA byte; expected two hex digits, e.g. A0"),
                    serde_json::json!({ "error": { "kind": "bad-class" } }),
                    args.safety.json,
                )
            }
        }
    } else {
        None
    };

    let (reader, mut session) = match open_fuzz_session(apdu_scan::KIND, &args.safety) {
        Ok(opened) => opened,
        Err(code) => return code,
    };

    // A single candidate can leave the PC/SC transaction unusable without
    // the card itself having gone anywhere - observed against the real
    // swSIM fixture - so discovery survives that rather than aborting the
    // whole run: `reconnect` re-opens the session in place, bounded by
    // `apdu_scan::MAX_RECONNECTS`. See `apdu_scan::sweep`.
    let mut reconnect = |session: &mut PcscSession| -> Result<(), TransportError> {
        *session = PcscSession::open(&reader)?;
        Ok(())
    };

    if let Some(class) = class {
        let audit =
            apdu_scan::ins_discovery(&mut session, class, mode, &mut reconnect, &mut || {
                doctor_kit::interrupt::interrupted()
            });
        let findings = apdu_scan::ins_findings(&audit);
        emit_fuzz_report(
            apdu_scan::KIND,
            reader.as_str(),
            audit.to_json(),
            &findings,
            args.safety.json,
        )
    } else {
        let audit = apdu_scan::cla_discovery(&mut session, mode, &mut reconnect, &mut || {
            doctor_kit::interrupt::interrupted()
        });
        let findings = apdu_scan::cla_findings(&audit);
        emit_fuzz_report(
            apdu_scan::KIND,
            reader.as_str(),
            audit.to_json(),
            &findings,
            args.safety.json,
        )
    }
}

/// Runs `sim-doctor fuzz compare`: reads each result file, then compares them.
///
/// A file that cannot be read or is not a `fuzz ota` result refuses the whole
/// comparison with exit 2 and names the file; nothing is compared from a
/// partial set.
fn run_fuzz_compare(args: FuzzCompareArgs) -> contract::ExitCode {
    let mut runs = Vec::with_capacity(args.files.len());
    for path in &args.files {
        match fuzz::read_run(path) {
            Ok(run) => runs.push(run),
            Err(message) => {
                eprintln!("sim-doctor: {message}");
                if args.json {
                    let envelope = contract::Envelope::new(
                        fuzz::KIND,
                        contract::ExitCode::Error,
                        message.as_str(),
                        serde_json::json!({ "error": { "kind": "bad-result" } }),
                    );
                    if let Ok(line) = envelope.to_json() {
                        println!("{line}");
                    }
                }
                return contract::ExitCode::Error;
            }
        }
    }
    let comparison = fuzz::compare(runs);
    if args.json {
        let envelope = contract::Envelope::new(
            fuzz::KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            serde_json::json!({ "compare": comparison.to_json() }),
        );
        match envelope.to_json() {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Error;
            }
        }
        contract::ExitCode::Success
    } else {
        match emit_stdout(&comparison.text(), "the fuzz comparison") {
            Ok(()) => contract::ExitCode::Success,
            Err(message) => {
                eprintln!("sim-doctor: {message}");
                contract::ExitCode::Error
            }
        }
    }
}

/// Runs `sim-doctor fuzz mutate`: replay log or mock card only.
fn run_fuzz_mutate(args: FuzzMutateArgs) -> contract::ExitCode {
    let config = match apdu_fuzz::Config::new(
        args.seed,
        args.max_cases,
        args.timeout.map(Duration::from_secs),
        args.stop_on_first_finding,
    ) {
        Ok(config) => config,
        Err(message) => {
            return report_refusal(
                apdu_fuzz::KIND,
                &message,
                serde_json::json!({ "error": { "kind": "bad-max-cases" } }),
                args.json,
            )
        }
    };
    if args.dry_run && !args.json {
        let plan = apdu_fuzz::plan_json(&config);
        let mut text = String::from("fuzz mutate dry run: nothing is sent\n");
        text.push_str(&format!("allowed INS: {}\n", plan["allowed_ins"]));
        for case in plan["planned"].as_array().into_iter().flatten() {
            text.push_str(&format!(
                "{} {} {}\n",
                case["index"], case["kind"], case["command"]
            ));
        }
        return match emit_stdout(text.trim_end_matches('\n'), "the fuzz plan") {
            Ok(()) => contract::ExitCode::Success,
            Err(message) => {
                eprintln!("sim-doctor: {message}");
                contract::ExitCode::Findings
            }
        };
    }
    if args.dry_run {
        return emit_fuzz_report(
            apdu_fuzz::KIND,
            "(dry run)",
            apdu_fuzz::plan_json(&config),
            &[],
            args.json,
        );
    }
    let run = if args.mock {
        apdu_fuzz::run(&mut apdu_fuzz::MockCard::strict(), &config, &mut || {
            doctor_kit::interrupt::interrupted()
        })
    } else if let Some(path) = &args.replay {
        let log = match std::fs::read_to_string(path) {
            Ok(log) => log,
            Err(err) => {
                return report_refusal(
                    apdu_fuzz::KIND,
                    &format!("cannot read {}: {err}", path.display()),
                    serde_json::json!({ "error": { "kind": "bad-replay" } }),
                    args.json,
                )
            }
        };
        let mut replay = match replay::Replay::from_log(&log) {
            Ok(replay) => replay,
            Err(err) => {
                return report_refusal(
                    apdu_fuzz::KIND,
                    &err,
                    serde_json::json!({ "error": { "kind": "bad-replay" } }),
                    args.json,
                )
            }
        };
        apdu_fuzz::run(&mut replay, &config, &mut || {
            doctor_kit::interrupt::interrupted()
        })
    } else {
        return report_refusal(
            apdu_fuzz::KIND,
            "fuzz mutate needs --replay FILE, --mock or --dry-run; it has no real-reader path",
            serde_json::json!({ "error": { "kind": "no-source" } }),
            args.json,
        );
    };
    let findings = apdu_fuzz::findings(&run);
    emit_fuzz_report(
        apdu_fuzz::KIND,
        if args.mock { "mock" } else { "replay" },
        run.to_json(),
        &findings,
        args.json,
    )
}

/// Runs `sim-doctor fuzz ota`: the TAR x keyset x mechanism sweep, behind the
/// safety interlock.
fn run_fuzz_ota(args: FuzzOtaArgs) -> contract::ExitCode {
    let (reader, mut session) = match open_fuzz_session(fuzz::KIND, &args.safety) {
        Ok(opened) => opened,
        Err(code) => return code,
    };

    let sweep = fuzz::Sweep {
        quick: args.safety.quick,
        poke: args.poke,
        class: tar::Class::Etsi,
    };
    let audit = match fuzz::audit(
        &mut session,
        sweep,
        &session::Policy::default(),
        &mut || doctor_kit::interrupt::interrupted(),
    ) {
        Ok(audit) => audit,
        Err(err) => {
            return report_failure(
                &scan::Failure::new("fuzz-sweep-failed", err.to_string()),
                args.safety.json,
            )
        }
    };
    let findings = fuzz::findings(&audit);
    emit_fuzz_report(
        fuzz::KIND,
        reader.as_str(),
        audit.to_json(),
        &findings,
        args.safety.json,
    )
}

/// One `fuzz` report, in both modes: the reader name, the raw audit block
/// (named `data` under its own key per subcommand) and the findings, through
/// the same [`rules::Finding::to_json`] contract every other rule uses.
fn emit_fuzz_report(
    kind: &str,
    reader: &str,
    audit: serde_json::Value,
    findings: &[rules::Finding],
    json: bool,
) -> contract::ExitCode {
    let data = serde_json::json!({
        "reader": reader,
        "audit": audit,
        "findings": {
            "count": findings.len(),
            "findings": findings.iter().map(rules::Finding::to_json).collect::<Vec<_>>(),
        },
    });
    let rendered = if json {
        let envelope = contract::Envelope::new(
            kind,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        );
        match envelope.to_json() {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        let mut text = format!("{kind} on {reader}: {} finding(s)\n", findings.len());
        for finding in findings {
            text.push_str(&format!("{finding}\n"));
        }
        text
    };
    match emit_stdout(rendered.trim_end_matches('\n'), "the fuzz report") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// Picks the reader to scan, or says why there is not one.
///
/// Exit code 1 rather than 129 for both refusals. A reader name that matches
/// nothing and a machine with no reader are conditions of the environment, not
/// a malformed command line, and an operator who gets 129 for them will go
/// looking for a typo in a command line that is perfectly correct. The message
/// lists what *is* attached either way, because "no reader named X" on its own
/// sends the next person looking at the driver rather than the machine.
fn pick_reader<'a>(
    readers: &'a [ReaderName],
    requested: Option<&str>,
    index: Option<usize>,
) -> Result<&'a ReaderName, scan::Failure> {
    if readers.is_empty() {
        return Err(scan::Failure::new(
            "no-reader",
            "no PC/SC reader is attached. Start pcscd and attach a card, or see \
             docs/swsim-fixture.md for the software SIM this project tests against",
        ));
    }

    if let Some(index) = index {
        return readers.get(index).ok_or_else(|| {
            scan::Failure::new(
                "unknown-reader",
                format!(
                    "no reader at index {index}: {} reader(s) attached, numbered from 0 \
                     (see `sim-doctor readers`)",
                    readers.len()
                ),
            )
        });
    }

    let Some(requested) = requested else {
        return Ok(&readers[0]);
    };

    readers
        .iter()
        .find(|reader| reader.as_str() == requested)
        .ok_or_else(|| {
            let available: Vec<&str> = readers.iter().map(ReaderName::as_str).collect();
            scan::Failure::new(
                "unknown-reader",
                scan::unknown_reader(requested, &available).to_string(),
            )
        })
}

/// The bounds this run asked for, on top of [`Limits::default`].
///
/// Every one is an override rather than a positional, so a run that changes
/// one bound still reports the other three: a report that silently used a
/// different depth bound than the last run is not comparable to it.
fn limits_from(args: &WalkLimitArgs) -> Limits {
    let mut limits = Limits::default();
    if let Some(value) = args.max_depth {
        limits.max_depth = value;
    }
    if let Some(value) = args.max_children {
        limits.max_children = value;
    }
    if let Some(value) = args.max_nodes {
        limits.max_nodes = value;
    }
    if let Some(value) = args.max_directories {
        limits.max_directories = value;
    }
    limits
}

const RULES_KIND: &str = "rules";

/// The largest saved envelope `why` will read: 16 MiB.
const MAX_WHY_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Strips control and invisible characters so untrusted file text cannot drive
/// the terminal: the shared [`contract::sanitize`].
fn printable(text: &str) -> String {
    contract::sanitize(text)
}

/// One rule's page, as JSON.
fn rule_json(spec: &sim_doctor::rules::RuleSpec) -> serde_json::Value {
    serde_json::json!({
        "id": spec.id().as_str(),
        "severity": spec.severity().id(),
        "summary": spec.summary(),
        "remediation": spec.remediation(),
        "cwe": spec.cwe(),
        "reference": spec.reference(),
    })
}

/// One rule's page, as text.
fn rule_page(spec: &sim_doctor::rules::RuleSpec) -> String {
    format!(
        "{}  [{}]\n\nWhat it means\n  {}\n\nHow to fix\n  {}\n\nWeakness\n  {}\n\nSpecification\n  {}\n",
        spec.id().as_str(),
        spec.severity().id(),
        spec.summary(),
        spec.remediation().unwrap_or("(none declared)"),
        spec.cwe().unwrap_or("(not a weakness class)"),
        spec.reference().unwrap_or("(none cited)"),
    )
}

/// Prints one success document: the envelope under --json, else `text`.
fn emit_rules(json: bool, data: serde_json::Value, text: String) -> contract::ExitCode {
    let rendered = if json {
        match contract::Envelope::new(
            RULES_KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        text.trim_end().to_owned()
    };
    match emit_stdout(&rendered, "the rules document") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// `sim-doctor mcp`: the stdio server, handed the real clap `scan` command.
fn run_mcp(d: &kit::SimDoctor) -> contract::ExitCode {
    // main() installed the SIGINT/SIGTERM flag handler, which this server never polls
    // and which would swallow Ctrl-C and `kill`; restore the default for both so either
    // ends the server (chosen deliberately for SIGTERM: no cleanup is owed). Each child
    // scan installs its own handler.
    // SAFETY: SIG_DFL is a valid disposition for these signals; no handler pointer is involved.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    match doctor_kit::mcp::serve(d) {
        Ok(()) => contract::ExitCode::Success,
        Err(err) => {
            eprintln!("sim-doctor: mcp: {err}");
            contract::ExitCode::Findings
        }
    }
}

fn run_rules_list(json: bool) -> contract::ExitCode {
    let specs = all_specs();
    let mut text = format!("{:<28}  {:<8}  SUMMARY\n", "RULE", "SEVERITY");
    for spec in &specs {
        text.push_str(&format!(
            "{:<28}  {:<8}  {}\n",
            spec.id().as_str(),
            spec.severity().id(),
            spec.summary()
        ));
    }
    let data = serde_json::json!({ "rules": specs.iter().map(rule_json).collect::<Vec<_>>() });
    emit_rules(json, data, text)
}

/// Edit distance between two short ids, for did-you-mean.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}

/// The nearest known id to `id`, if it is close enough to be a typo.
fn nearest_rule(specs: &[sim_doctor::rules::RuleSpec], id: &str) -> Option<String> {
    specs
        .iter()
        .map(|spec| (edit_distance(spec.id().as_str(), id), spec.id().as_str()))
        .min()
        .filter(|(distance, _)| *distance <= 3)
        .map(|(_, name)| name.to_owned())
}

fn unknown_rule(specs: &[sim_doctor::rules::RuleSpec], id: &str, json: bool) -> contract::ExitCode {
    let near = nearest_rule(specs, id);
    let mut message = format!("unknown rule `{id}`");
    if let Some(near) = &near {
        message.push_str(&format!("; did you mean `{near}`?"));
    }
    report_refusal(
        RULES_KIND,
        &message,
        serde_json::json!({ "error": message, "did_you_mean": near }),
        json,
    )
}

fn run_why_rule(id: &str, json: bool) -> contract::ExitCode {
    let specs = all_specs();
    match specs.iter().find(|spec| spec.id().as_str() == id) {
        Some(spec) => emit_rules(
            json,
            serde_json::json!({ "rule": rule_json(spec) }),
            rule_page(spec),
        ),
        None => unknown_rule(&specs, id, json),
    }
}

/// Reads a saved `scan --json` envelope: a file, within the size limit, UTF-8, an envelope.
/// Shared by `why` and `fix`; the error is the refusal sentence.
fn read_saved_envelope(target: &str) -> Result<serde_json::Value, String> {
    let path = std::path::Path::new(target);
    let meta = std::fs::metadata(path).map_err(|err| format!("cannot read {target}: {err}"))?;
    if !meta.is_file() {
        return Err(format!("{target} is not a file"));
    }
    if meta.len() > MAX_WHY_FILE_BYTES {
        return Err(format!(
            "{target} is {} bytes, over the {MAX_WHY_FILE_BYTES}-byte limit for a saved envelope",
            meta.len()
        ));
    }
    let raw =
        std::fs::read_to_string(path).map_err(|err| format!("cannot read {target}: {err}"))?;
    let envelope: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| format!("{target} is not a saved sim-doctor envelope: {err}"))?;
    if envelope["schema"] != contract::DOCTOR_SCHEMA {
        return Err(format!(
            "{target} is not a doctor/1 envelope; was it saved from `scan --json`?"
        ));
    }
    Ok(envelope)
}

/// Explains a rule id, or every rule in a saved scan envelope.
fn run_why(target: &str, json: bool) -> contract::ExitCode {
    let path = std::path::Path::new(target);
    let looks_like_path = target.contains(['/', '\\']) || target.ends_with(".json");
    let refuse = |message: String| {
        report_refusal(
            RULES_KIND,
            &message,
            serde_json::json!({ "error": message }),
            json,
        )
    };
    if !path.is_file() && !looks_like_path && !path.exists() {
        return run_why_rule(target, json);
    }
    let envelope = match read_saved_envelope(target) {
        Ok(envelope) => envelope,
        Err(message) => return refuse(message),
    };
    let Some(findings) = envelope["findings"].as_array() else {
        return refuse(format!(
            "{target} carries no findings array; was it saved from `scan --json`?"
        ));
    };

    // (rule id, severity, count), in first-seen order.
    let mut seen: Vec<(String, String, usize)> = Vec::new();
    for finding in findings {
        let rule = finding["id"].as_str().unwrap_or("(unnamed)");
        match seen.iter_mut().find(|(id, _, _)| id == rule) {
            Some(entry) => entry.2 += 1,
            None => seen.push((
                rule.to_owned(),
                finding["severity"].as_str().unwrap_or("?").to_owned(),
                1,
            )),
        }
    }

    let specs = all_specs();
    let mut text = String::new();
    let mut rules = Vec::new();
    for (id, severity, count) in &seen {
        text.push_str(&format!(
            "{}  [{}]  {count} finding(s)\n",
            printable(id),
            printable(severity)
        ));
        let spec = specs.iter().find(|spec| spec.id().as_str() == id);
        match spec {
            Some(spec) => text.push_str(&rule_page(spec)),
            None => text.push_str("  no catalog entry for this rule in this build\n"),
        }
        text.push('\n');
        rules.push(serde_json::json!({
            "id": id, "severity": severity, "count": count,
            "rule": spec.map(rule_json),
        }));
    }
    if seen.is_empty() {
        text.push_str("no findings in this envelope\n");
    }
    emit_rules(json, serde_json::json!({ "rules": rules }), text)
}

/// Runs `sim-doctor fix`: print the prompt, and with `--agent` launch that agent.
fn run_fix(args: &FixArgs) -> contract::ExitCode {
    let specs = all_specs();
    let Some(spec) = specs.iter().find(|s| s.id().as_str() == args.rule_id) else {
        return unknown_rule(&specs, &args.rule_id, false);
    };
    let refuse = |message: String| {
        report_refusal(
            RULES_KIND,
            &message,
            serde_json::json!({ "error": message }),
            false,
        )
    };
    let envelope = match read_saved_envelope(&args.from) {
        Ok(envelope) => envelope,
        Err(message) => return refuse(message),
    };
    let Some(all) = envelope["findings"].as_array() else {
        return refuse(format!(
            "{} carries no findings array; was it saved from `scan --json`?",
            args.from
        ));
    };
    let findings: Vec<(String, String)> = all
        .iter()
        .filter(|f| f["id"].as_str() == Some(spec.id().as_str()))
        // Cap before collecting: a 16 MiB file of matches must not allocate per finding.
        .take(fix::MAX_FINDINGS)
        .map(|f| {
            (
                f["severity"].as_str().unwrap_or("?").to_owned(),
                f["message"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    if findings.is_empty() {
        return refuse(format!(
            "rule `{}` has no finding in {}",
            args.rule_id, args.from
        ));
    }
    let prompt = fix::build_prompt(
        spec.id().as_str(),
        spec.summary(),
        spec.remediation().unwrap_or("(none declared)"),
        &findings,
        env!("CARGO_PKG_VERSION"),
    );
    if let Err(message) = emit_stdout(&prompt, "the prompt") {
        eprintln!("sim-doctor: {message}");
        return contract::ExitCode::Findings;
    }
    let Some(name) = &args.agent else {
        return contract::ExitCode::Success;
    };
    if fix::in_agent(|k| std::env::var(k).ok()) {
        eprintln!(
            "sim-doctor: already inside a coding agent: not launching another; use the prompt above"
        );
        return contract::ExitCode::Success;
    }
    let agent = doctor_kit::fix::AGENTS
        .iter()
        .find(|a| a.name == name)
        .expect("clap restricts --agent to the table");
    let skip = args.skip_approvals
        || std::env::var("SIM_DOCTOR_HANDOFF_SKIP_APPROVALS").is_ok_and(|v| v == "1");
    let argv = fix::launch_argv(agent, &prompt, skip);
    eprintln!("$ {} <prompt>", argv[..argv.len() - 1].join(" "));
    // `.status()` blocks while the agent runs and the flag handler would swallow
    // Ctrl-C and `kill`; restore the default for both, as run_mcp does, so either
    // ends this process (the agent shares the terminal's process group for Ctrl-C).
    // SAFETY: SIG_DFL is a valid disposition for these signals; no handler pointer is involved.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    // Spawned directly: the OS resolves PATH, so the path run is the path checked.
    match std::process::Command::new(agent.bin)
        .args(&argv[1..])
        .status()
    {
        Ok(status) if status.success() => contract::ExitCode::Success,
        Ok(status) => {
            eprintln!("sim-doctor: {} exited with {status}", agent.bin);
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    // The shell convention (130 for SIGINT); the child's own code is
                    // lost to the kernel here, so report the signal instead.
                    eprintln!("sim-doctor: {} was killed by signal {signal}", agent.bin);
                    process::exit(128 + signal);
                }
            }
            contract::ExitCode::Findings
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "sim-doctor: {} is not installed (not found on PATH)",
                agent.bin
            );
            contract::ExitCode::Findings
        }
        Err(err) => {
            eprintln!("sim-doctor: could not launch {}: {err}", agent.bin);
            contract::ExitCode::Findings
        }
    }
}

/// Reports a refusal of a lpa-style command that shares `scan`'s failure shape
/// (the fuzz commands), and returns exit code 1. `scan` itself uses
/// [`report_scan_failure`] and exits 2.
///
/// The same shape as every other refusal: AGENTS.md
/// section 3 shares code 1 between "findings present" and "a check failed", and
/// a run that could not reach a card is a check that failed. Under `--json` an
/// agent reads the envelope and learns why; without it the sentence is on
/// stderr and stdout stays empty, because there is no report to give.
fn report_failure(failure: &scan::Failure, json: bool) -> contract::ExitCode {
    report_refusal(scan::KIND, &failure.message, failure.data(), json)
}

/// One refusal in both modes: a sentence on stderr always, and one envelope on
/// stdout under `--json`.
///
/// The stderr line is printed first and unconditionally. It is a diagnostic,
/// and AGENTS.md section 3 puts every diagnostic on stderr in every mode; the
/// envelope is the machine-readable copy of the same sentence, not a
/// replacement for it.
fn report_refusal(
    kind: &str,
    message: &str,
    data: serde_json::Value,
    json: bool,
) -> contract::ExitCode {
    eprintln!("sim-doctor: {message}");

    if json {
        let line = contract::Envelope::new(kind, contract::ExitCode::Findings, message, data)
            .to_json()
            .map_err(|e| e.to_string());
        match line {
            Ok(line) => {
                // A write failure does not change the exit code, for the same
                // reason it does not in report_interrupted: the run genuinely
                // failed, and "could not report the failure" is not a different
                // answer.
                if let Err(err) = emit_stdout(&line, "the failure envelope") {
                    eprintln!("sim-doctor: {err}");
                }
            }
            Err(err) => eprintln!("sim-doctor: {err}"),
        }
    }

    contract::ExitCode::Findings
}

/// Runs `sim-doctor ota-expanded`: the offline Command Scripting template encoder, the Response
/// Scripting template decoder and the Proof-of-Response Response Packet decoder.
///
/// The envelope kind is "ota-expanded" and its `data` carries `card_touched: false`, so an agent
/// can tell from the document alone that nothing was sent. Every value that came off a card
/// reaches the human table through `contract::sanitize`.
///
/// Exit codes: 0 on a completed encode or decode; 2 for input that is not hex, not the structure
/// it claims to be, or a Response Packet whose own lengths disagree - a malformed template is an
/// error, never a partial answer. `clap` itself answers 129 for a bad command line.
fn run_ota_expanded(args: OtaExpandedArgs) -> contract::ExitCode {
    const KIND: &str = "ota-expanded";

    let (json, outcome): (bool, Result<(serde_json::Value, String), String>) = match args.action {
        OtaExpandedAction::Encode {
            c_apdu,
            indefinite,
            json,
        } => {
            let coding = if indefinite {
                ota_expanded::LengthCoding::Indefinite
            } else {
                ota_expanded::LengthCoding::Definite
            };
            let parsed = c_apdu
                .iter()
                .map(|c| cat::parse_hex(c).map_err(|e| format!("`{c}`: {e}")))
                .collect::<Result<Vec<Vec<u8>>, String>>();
            (
                json,
                parsed.and_then(|apdus| {
                    ota_expanded::command_scripting(&apdus, coding)
                        .map(|script| (script.json(), script.render()))
                        .map_err(|e| e.to_string())
                }),
            )
        }
        OtaExpandedAction::Decode { hex, json } => {
            let parsed = read_ota_expanded_hex(hex.as_deref());
            (
                json,
                parsed.and_then(|bytes| {
                    ota_expanded::decode_response_scripting(&bytes)
                        .map(|t| (t.json(), t.render()))
                        .map_err(|e| e.to_string())
                }),
            )
        }
        OtaExpandedAction::Por {
            hex,
            remote_format,
            json,
        } => {
            let format = remote_format.into();
            let parsed = read_ota_expanded_hex(hex.as_deref());
            (
                json,
                parsed.and_then(|bytes| {
                    ota_expanded::decode_por(&bytes, format)
                        .map(|p| (p.json(), p.render()))
                        .map_err(|e| e.to_string())
                }),
            )
        }
    };

    match outcome {
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            if json {
                let data = serde_json::json!({ "card_touched": false, "error": message });
                match contract::Envelope::new(KIND, contract::ExitCode::Error, &message, data)
                    .to_json()
                {
                    Ok(line) => {
                        let _ = emit_stdout(&line, "the ota-expanded error envelope");
                    }
                    Err(err) => eprintln!("sim-doctor: {err}"),
                }
            }
            contract::ExitCode::Error
        }
        Ok((data, rendered)) => {
            let written = if json {
                match contract::Envelope::new(
                    KIND,
                    contract::ExitCode::Success,
                    contract::OK_MESSAGE,
                    data,
                )
                .to_json()
                {
                    Ok(line) => emit_stdout(&line, "the ota-expanded result"),
                    Err(err) => Err(err.to_string()),
                }
            } else {
                emit_stdout(&rendered, "the decoded OTA data")
            };
            match written {
                Ok(()) => contract::ExitCode::Success,
                Err(message) => {
                    eprintln!("sim-doctor: {message}");
                    contract::ExitCode::Error
                }
            }
        }
    }
}

/// The hex an `ota-expanded` decode or por verb was given: the argument, or stdin when it was
/// omitted or is `-`. Whitespace, newlines and `0x` prefixes are ignored.
fn read_ota_expanded_hex(hex: Option<&str>) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let text = match hex {
        Some("-") | None => {
            let mut buffer = Vec::new();
            if let Err(err) = io::stdin()
                .take(MAX_WHY_FILE_BYTES)
                .read_to_end(&mut buffer)
            {
                return Err(format!("cannot read stdin: {err}"));
            }
            String::from_utf8_lossy(&buffer).into_owned()
        }
        Some(text) => text.to_owned(),
    };
    let joined: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        return Err("no OTA data given".to_owned());
    }
    cat::parse_hex(&joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--fail-on` defaults to `critical`: the choice that keeps a scan with
    /// only lower findings at exit 0, as it was before doctor/1. Documented in
    /// `scan --help`, the README and AGENTS.md section 3.
    #[test]
    fn fail_on_defaults_to_critical() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert_eq!(args.fail_on, rules::Severity::Critical);
    }

    /// `scan` no longer has `--diff`: `--baseline` alone gates (doctor/1).
    #[test]
    fn scan_has_no_diff_flag() {
        use clap::Parser;
        assert!(Cli::try_parse_from(["sim-doctor", "scan", "--diff"]).is_err());
    }

    /// `--sffs` parses correctly and sets the flag.
    #[test]
    fn sffs_flag_parses_correctly() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan", "--sffs"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert!(args.sffs);
    }

    /// `--sffs` is not set by default.
    #[test]
    fn sffs_defaults_to_false() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert!(!args.sffs);
    }

    /// `--scan-file-break` (or `-b`) is accepted by the scan command.
    #[test]
    fn scan_accepts_scan_file_break_flag() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan", "--scan-file-break"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert!(args.walk_limits.break_after_count_match);
    }

    /// `--sfb` is the visible alias of `--scan-file-break` (SIMTester's name).
    #[test]
    fn scan_accepts_sfb_alias() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan", "--sfb"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert!(args.walk_limits.break_after_count_match);
    }

    /// `-b` is a short alias for `--scan-file-break`.
    #[test]
    fn scan_accepts_b_short_flag() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan", "-b"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert!(args.walk_limits.break_after_count_match);
    }
}
