//! The OTA passthrough sweep: TP-PID, TP-DCS, TP-UDHI and the Command Packet
//! Header, varied inside one SMS-PP-DOWNLOAD.
//!
//! This is SIMTester's `OTAFuzzer` (`srlabs/SIMTester` at `d197fef`, GPL: read
//! and cited, never copied). It is **not** a second sweep of keysets.
//! `fuzzOTA` is handed one keyset, one TAR and one mechanism, builds the same
//! `CommandPacket` from them, and then varies exactly four things inside the
//! envelope:
//!
//! | This module | Where the value lands |
//! |---|---|
//! | [`PIDS`] | TP-PID, octet 7 of the SMS-DELIVER TPDU (1-based) |
//! | [`DCS`] | TP-DCS, octet 8 of the SMS-DELIVER TPDU (1-based) |
//! | [`UDHI`] | the TP-UDHI flag of the TPDU's first octet |
//! | [`CPH`] | the Command Packet Header, the octets the Command Packet starts with |
//!
//! **The loop order is pid -> dcs -> cph -> udhi** and it is part of the
//! contract: the reference's `for` nesting is exactly that, so a report that
//! listed the same combinations in another order would not be comparable to
//! SIMTester row for row.
//!
//! # A hit is "longer than two octets"
//!
//! `fuzzOTA` keeps a combination only when the response it ends up holding -
//! after `Helpers.handleSIMResponse` has followed a `61 xx` / `6C xx` / `91 xx`
//! and drained the proactive commands - is **more than two octets long**:
//!
//! > `// response is not 2 bytes long and 9000 (those are the non-responsive
//! > combinations, we only display the interesting (responsive) ones)`
//!
//! \[V] `OTAFuzzer.java` lines 126-127. `9000` and nothing else is the
//! non-responsive answer and is not recorded, so that is exactly what
//! [`Hit`] means here: nothing softer stands in for it. The octets compared are
//! [`tar::Reply::response`], which is the same handled response the reference
//! writes into its CSV row.
//!
//! # The bound, and why bruteforce is a partial sweep
//!
//! [`MAX_ENVELOPES`] is [`super::MAX_PROBES`], unchanged and not raised. The
//! default plan holds [`FOCUSED_ENVELOPES`] envelopes and runs whole. The
//! bruteforce plan holds [`BRUTEFORCE_ENVELOPES`] and does not fit any budget
//! this tool will ship, so **a bruteforce run is a capped partial sweep and is
//! labelled one**: it stops at the bound, reports `complete: false` and
//! `capped: true`, and says in words how many of the planned combinations were
//! not sent ([`Report::to_human`]).
//!
//! # Card contact
//!
//! An OTA envelope delivered to a live card is a real CAT operation. The
//! `--i-understand-this-can-brick-the-card` interlock is `sim-doctor fuzz`'s,
//! not this module's, and this mode adds no way around it: it sends through
//! [`tar::probe_envelope`], the same path as every other envelope in the crate.
//! Nothing here writes to the card's filesystem.
//!
//! # Hits are reported, not raised
//!
//! A hit is a row in the reference's CSV, not a verdict: "the card answered
//! with more than a status word" is true of plenty of cards that are perfectly
//! correct, and a rule for it would fire once per combination of a sweep this
//! tool refuses to run without an opt-in. So the hits live in the report's
//! `passthrough` block and in the human output, and this issue adds no rule id
//! - `sim-doctor rules list` is unchanged.

use serde_json::{json, Value};

use crate::apdu::StatusWord;
use crate::session::Policy;
use crate::tar;
use crate::transport::CardSession;

use super::{MAX_PROBES, MECHANISMS};

/// The most envelopes one passthrough sweep may send.
///
/// [`super::MAX_PROBES`], published and unchanged, for the reason that bound
/// exists: this tool does not put an unbounded loop behind a flag.
pub const MAX_ENVELOPES: usize = MAX_PROBES;

/// The TP-PID octets the default plan probes: `00 41 7C 7F`.
///
/// \[V] `OTAFuzzer.fuzzOTA`, the `else` branch of the `bruteforce` test:
/// `pid_values = new byte[]{(byte) 0, (byte) 65, (byte) 124, (byte) 127}`,
/// which is `00 41 7C 7F`.
pub const PIDS: [u8; 4] = [0x00, 0x41, 0x7C, 0x7F];

/// The TP-DCS octets the default plan probes: `00 16 36 56 76 96 B6 D6 F6`.
///
/// \[V] same statement:
/// `(byte) 0, (byte) 22, (byte) 54, (byte) 86, (byte) 118, (byte) 150,
/// (byte) 182, (byte) 214, (byte) 246`, which is this list.
pub const DCS: [u8; 9] = [0x00, 0x16, 0x36, 0x56, 0x76, 0x96, 0xB6, 0xD6, 0xF6];

/// The TP-UDHI values: flag unset, flag set.
///
/// \[V] `boolean[] udhi_values = new boolean[]{false, true};`
pub const UDHI: [bool; 2] = [false, true];

/// The six Command Packet Headers, in the order `fuzzOTA` builds them.
///
/// \[V] the reference builds them in two steps. The loop
/// `for (int i = 0; i <= CPH_fuzz_count; i++)` with `CPH_fuzz_count = 2`
/// writes `String.format("%02X%02X%02X", 2 + i, 0x70, i)` followed by `i` zero
/// octets, giving `027000` (i=0), `03700100` (i=1) and `0470020000` (i=2).
/// Three more are then appended by hand, in this order: `027100` ("standard
/// security header for OTA response"), `027F00` ("non-standard security
/// header") and `""` ("test also with no security header").
///
/// `CPI` is the first octet and `0x70` the second, so these are the octets
/// that replace [`crate::tar`]'s own `02 70 00` probe header. The last one is
/// empty and is not an error: the Command Packet then begins at its CPL.
pub const CPH: [&[u8]; 6] = [
    &[0x02, 0x70, 0x00],
    &[0x03, 0x70, 0x01, 0x00],
    &[0x04, 0x70, 0x02, 0x00, 0x00],
    &[0x02, 0x71, 0x00],
    &[0x02, 0x7F, 0x00],
    &[],
];

/// How many envelopes the default plan holds: `4 * 9 * 6 * 2`, **432**.
///
/// \[V] the reference's own arithmetic:
/// `loopUntil = pid_values.length * dcs_values.length * CPH_values.size() *
/// udhi_values.length`, and `This scan will go over` prints it.
pub const FOCUSED_ENVELOPES: usize = PIDS.len() * DCS.len() * CPH.len() * UDHI.len();

/// How many envelopes the bruteforce plan holds: `256 * 256 * 6 * 2`,
/// **786432**.
///
/// \[V] the same statement with `pid_values[i] = (byte) i` and
/// `dcs_values[i] = (byte) i` for `i` in `0..=0xFF`. **This does not fit under
/// [`MAX_ENVELOPES`]**, which is the whole reason the bound exists.
pub const BRUTEFORCE_ENVELOPES: usize = 256 * 256 * CPH.len() * UDHI.len();

/// Which value sets one passthrough sweep probes.
///
/// SIMTester's `-of` and `-ofbf` (`bruteforce` in `fuzzOTA`) \[V].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// `-of`: four PIDs, nine DCS values, six CPHs, UDHI both ways.
    #[default]
    Default,
    /// `-ofbf`: every PID octet and every DCS octet. Capped, and reported as a
    /// partial sweep because the plan does not fit the bound.
    Bruteforce,
}

impl Mode {
    /// The mode's spelling, as reported and as `--passthrough <MODE>` takes it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Bruteforce => "bruteforce",
        }
    }

    /// How many envelopes this mode's plan holds.
    pub const fn planned(self) -> usize {
        match self {
            Self::Default => FOCUSED_ENVELOPES,
            Self::Bruteforce => BRUTEFORCE_ENVELOPES,
        }
    }

    /// The TP-PID octets this mode sweeps.
    fn pids(self) -> Vec<u8> {
        match self {
            Self::Default => PIDS.to_vec(),
            Self::Bruteforce => (u8::MIN..=u8::MAX).collect(),
        }
    }

    /// The TP-DCS octets this mode sweeps.
    fn dcs(self) -> Vec<u8> {
        match self {
            Self::Default => DCS.to_vec(),
            Self::Bruteforce => (u8::MIN..=u8::MAX).collect(),
        }
    }

    /// How this mode's PID (or DCS) space is spelled in the report.
    ///
    /// The 256-value space is written `00..FF` rather than 256 separate
    /// strings: [`Mode::planned`] already carries the count, and a report
    /// nobody reads is not a better report.
    fn spelled(self, default: &[u8]) -> String {
        match self {
            Self::Default => spell(default),
            Self::Bruteforce => "00..FF".to_owned(),
        }
    }
}

/// Uppercase hexadecimal, no separators - the spelling the reference's CSV
/// rows use (`String.format("%02X", pid)`).
fn spell(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The `passthrough` block of one sweep's report.
pub type Block = Value;

/// Uppercase hexadecimal octets with no separators.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// One passthrough sweep's fixed choices.
///
/// Every field is the value the reference holds still while it varies the four
/// passthrough dimensions: `fuzzOTA(int keyset, String TAR, FuzzerData
/// fuzzer, CSVWriter writer, boolean bruteforce)` builds
/// `Fuzzer.generateCommandPacket(keyset, counter, kic, kid, TAR, requestPoR,
/// cipherPoR)` inside the innermost loop, so all four of the header-varying
/// envelopes of one plan carry the *same* TAR, keyset and mechanism \[V].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sweep {
    /// Which value sets to sweep.
    pub mode: Mode,
    /// The ENVELOPE class, same meaning as [`tar::Class`].
    pub class: tar::Class,
    /// The TAR every Command Packet of this sweep carries.
    ///
    /// \[U] `fuzzOTA` is handed the TAR by its caller and nothing in the
    /// reference fixes it. This sweep holds the TAR audit's own first
    /// calibration TAR, which is inside the focused `000000`-`0000FF` band a
    /// TAR scan probes by default, so the two sweeps ask the same card about
    /// the same identifier.
    pub tar: u32,
    /// The keyset every Command Packet of this sweep carries.
    ///
    /// \[U] as above: the caller passes it and the reference does not fix it.
    /// Keyset `0` is the one the TAR probe already sends
    /// ([`tar::command_packet`]), so a passthrough envelope differs from a TAR
    /// audit envelope only in the four fields this module varies.
    pub keyset: u8,
    /// The (SPI1, SPI2) mechanism every Command Packet of this sweep carries.
    ///
    /// \[U] as above. [`super::MECHANISMS`]'s first pair, `00 00`: neither
    /// ciphering nor Proof-of-Response, so the card's answer is about the
    /// passthrough fields and not about a security mechanism it refused.
    pub mechanism: (u8, u8),
}

impl Default for Sweep {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            class: tar::Class::Etsi,
            tar: tar::CALIBRATION_TARS[0],
            keyset: 0,
            mechanism: MECHANISMS[0],
        }
    }
}

/// One combination the card answered with more than a status word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The TP-PID octet that was probed.
    pub pid: u8,
    /// The TP-DCS octet that was probed.
    pub dcs: u8,
    /// Whether the TP-UDHI flag was set.
    pub udhi: bool,
    /// The Command Packet Header that was probed, verbatim (may be empty).
    pub cph: Vec<u8>,
    /// The status word the card answered with, when it gave one.
    pub status: Option<StatusWord>,
    /// The response octets verbatim, the same bytes the reference writes into
    /// its `response` CSV column.
    pub response: Vec<u8>,
}

impl Hit {
    /// One `fuzz.passthrough.hits[]` row.
    pub fn to_json(&self) -> Value {
        json!({
            "pid": format!("{:02X}", self.pid),
            "dcs": format!("{:02X}", self.dcs),
            "udhi": self.udhi,
            "cph": hex(&self.cph),
            "status": self.status.map(|status| status.to_string()),
            "response_hex": hex(&self.response),
        })
    }
}

/// Everything one passthrough sweep sent, and everything it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What was asked for.
    pub sweep: Sweep,
    /// How many combinations the plan held.
    pub planned: usize,
    /// How many envelopes were actually sent.
    pub sent: usize,
    /// Whether the bound fired with combinations left over.
    pub capped: bool,
    /// Why the sweep stopped early, when it did.
    pub stopped: Option<String>,
    /// Every combination the card answered with more than a status word.
    pub hits: Vec<Hit>,
}

impl Report {
    /// The published bound one sweep may not pass.
    pub const fn bound() -> usize {
        MAX_ENVELOPES
    }

    /// Whether this sweep sent every combination it planned.
    pub fn complete(&self) -> bool {
        !self.capped && self.stopped.is_none()
    }

    /// How many planned combinations were **not** sent.
    pub fn unsent(&self) -> usize {
        self.planned.saturating_sub(self.sent)
    }

    /// How many combinations the card answered with data.
    pub fn hit_count(&self) -> usize {
        self.hits.len()
    }

    /// The `fuzz.passthrough` block a report carries.
    pub fn to_json(&self) -> Value {
        json!({
            "mode": self.sweep.mode.id(),
            "class": self.sweep.class.id(),
            "tar": tar::hex(self.sweep.tar),
            "keyset": self.sweep.keyset,
            "mechanism": {
                "spi1": format!("{:02X}", self.sweep.mechanism.0),
                "spi2": format!("{:02X}", self.sweep.mechanism.1),
            },
            "pid_values": self.sweep.mode.spelled(&PIDS),
            "dcs_values": self.sweep.mode.spelled(&DCS),
            "udhi_values": UDHI,
            "cph_values": CPH.iter().map(|cph| hex(cph)).collect::<Vec<_>>(),
            "planned": self.planned,
            "sent": self.sent,
            "unsent": self.unsent(),
            "bound": MAX_ENVELOPES,
            "capped": self.capped,
            "complete": self.complete(),
            "stopped": self.stopped,
            "hit_count": self.hit_count(),
            "hits": self.hits.iter().map(Hit::to_json).collect::<Vec<_>>(),
        })
    }

    /// The whole human report: one line of totals, then one line per hit.
    pub fn to_human(&self) -> String {
        let mut out = self.summary();
        if self.capped {
            out.push_str(&format!(
                "\n  CAPPED PARTIAL SWEEP: {} of the {} planned combinations were NOT sent, \
                 because one sweep may send at most {}.",
                self.unsent(),
                self.planned,
                MAX_ENVELOPES
            ));
        }
        if let Some(reason) = &self.stopped {
            out.push_str(&format!("\n  stopped: {reason}"));
        }
        if self.hits.is_empty() {
            out.push_str(
                "\n  no combination was answered with more than a status word, so this card \
                 recorded no hit.",
            );
        }
        for hit in &self.hits {
            out.push_str(&format!(
                "\n  PID {:02X} DCS {:02X} UDHI {} CPH {:<10} -> {}",
                hit.pid,
                hit.dcs,
                u8::from(hit.udhi),
                hex(&hit.cph),
                hex(&hit.response),
            ));
        }
        out
    }

    /// One line saying how much was sent and how much was found.
    pub fn summary(&self) -> String {
        format!(
            "passthrough {}: {} of {} planned envelope(s) sent, bound {}, {} hit(s)",
            self.sweep.mode.id(),
            self.sent,
            self.planned,
            MAX_ENVELOPES,
            self.hits.len(),
        )
    }
}

/// Runs the OTA passthrough sweep over one card.
///
/// Bounded by [`MAX_ENVELOPES`], and stopped by the same rules the rest of the
/// crate follows: a card that stops answering envelopes, or a reader that
/// stops answering, ends the sweep and is reported rather than guessed past.
/// `interrupt` is polled before every envelope.
///
/// Sends nothing but envelopes: this mode reads and writes no card file, and
/// the caller has already enforced the `fuzz` opt-in interlock.
pub fn audit<S: CardSession + ?Sized>(
    session: &mut S,
    sweep: Sweep,
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<Report, tar::Error> {
    let pids = sweep.mode.pids();
    let dcs_values = sweep.mode.dcs();
    let planned = sweep.mode.planned();

    let mut sent = 0usize;
    let mut hits: Vec<Hit> = Vec::new();
    let mut capped = false;
    let mut stopped: Option<String> = None;

    // The reference's own nesting: pid, then dcs, then cph, then udhi.
    'sweep: for &pid in &pids {
        for &dcs in &dcs_values {
            for cph in CPH {
                for &udhi in &UDHI {
                    if sent == MAX_ENVELOPES {
                        capped = true;
                        stopped = Some(format!(
                            "the envelope budget of {MAX_ENVELOPES} was reached with \
                             combinations still planned"
                        ));
                        break 'sweep;
                    }
                    if interrupt() {
                        stopped = Some("the sweep was interrupted".to_owned());
                        break 'sweep;
                    }
                    let Some(apdu) = tar::envelope_apdu_passthrough(
                        sweep.tar,
                        sweep.class,
                        sweep.keyset,
                        sweep.mechanism,
                        cph,
                        tar::Passthrough { pid, dcs, udhi },
                    ) else {
                        stopped = Some(
                            "the SMS-PP-DOWNLOAD envelope for this combination does not fit a \
                             short APDU data field"
                                .to_owned(),
                        );
                        break 'sweep;
                    };
                    match tar::probe_envelope(session, &apdu, policy) {
                        Ok(Ok(reply)) => {
                            sent += 1;
                            // "response is not 2 bytes long and 9000 (those are
                            // the non-responsive combinations ...)".
                            if reply.response.len() > 2 {
                                hits.push(Hit {
                                    pid,
                                    dcs,
                                    udhi,
                                    cph: cph.to_vec(),
                                    status: reply.signature.status(),
                                    response: reply.response,
                                });
                            }
                        }
                        Ok(Err(reason)) => {
                            stopped =
                                Some(format!("the card stopped answering envelopes: {reason}"));
                            break 'sweep;
                        }
                        Err(tar::Error::Transport(reason)) => {
                            stopped = Some(format!(
                                "the reader stopped answering part way through: {reason}"
                            ));
                            break 'sweep;
                        }
                        Err(other) => return Err(other),
                    }
                }
            }
        }
    }

    Ok(Report {
        sweep,
        planned,
        sent,
        capped,
        stopped,
        hits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::transport::{Error as TransportError, ReaderName};

    /// The 3GPP TS 23.040 clause 9.1.2.1 field offsets, as indices.
    const FIRST_OCTET: usize = 0;
    const PID: usize = 6;
    const DCS_AT: usize = 7;
    const UDL: usize = 15;
    const UD: usize = 16;

    /// The envelope's fixed preamble: the `D1` tag, its short-form length, the
    /// four device identities and the ten-octet originating address.
    const PREAMBLE: usize = 1 + 1 + 4 + 10;

    /// The SMS-DELIVER TPDU inside an envelope data field.
    fn tpdu(data: &[u8]) -> &[u8] {
        assert_eq!(data[0], tar::TAG_SMS_PP_DOWNLOAD);
        assert!(data[1] < 0x80, "this envelope is short-form");
        &data[PREAMBLE..]
    }

    /// A card that answers every envelope from a script.
    ///
    /// The reader is not named swicc-pcsc, so [`tar::probe_envelope`] takes the
    /// one-`SCardTransmit` path and every envelope this sweep sends is exactly
    /// the APDU the builder produced, which is what the byte-level tests below
    /// read.
    struct Scripted {
        reader: ReaderName,
        replies: RefCell<VecDeque<Result<Vec<u8>, TransportError>>>,
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl Scripted {
        fn new(replies: Vec<Result<Vec<u8>, TransportError>>) -> Self {
            Self {
                reader: ReaderName::new("Replay Transport 1.0").expect("a reader name"),
                replies: RefCell::new(replies.into()),
                sent: RefCell::new(Vec::new()),
            }
        }

        /// Answers `times` envelopes with `reply`, then whatever `tail` says.
        fn answering(
            times: usize,
            reply: Vec<u8>,
            tail: Vec<Result<Vec<u8>, TransportError>>,
        ) -> Self {
            let mut replies = VecDeque::new();
            for _ in 0..times {
                replies.push_back(Ok(reply.clone()));
            }
            replies.extend(tail);
            Self::new(replies.into())
        }

        /// A card that answers every envelope with a bare `90 00`.
        fn silent() -> Self {
            Self::answering(BRUTEFORCE_ENVELOPES + 8, vec![0x90, 0x00], Vec::new())
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.borrow().clone()
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.borrow_mut().push(command.to_vec());
            self.replies
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(vec![0x90, 0x00]))
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn sweep(mode: Mode) -> Sweep {
        Sweep {
            mode,
            ..Sweep::default()
        }
    }

    #[test]
    fn value_sets_are_the_reference_sets() {
        assert_eq!(PIDS, [0x00, 0x41, 0x7C, 0x7F]);
        assert_eq!(DCS, [0x00, 0x16, 0x36, 0x56, 0x76, 0x96, 0xB6, 0xD6, 0xF6]);
        assert_eq!(UDHI, [false, true]);
        assert_eq!(
            CPH,
            [
                &[0x02, 0x70, 0x00][..],
                &[0x03, 0x70, 0x01, 0x00][..],
                &[0x04, 0x70, 0x02, 0x00, 0x00][..],
                &[0x02, 0x71, 0x00][..],
                &[0x02, 0x7F, 0x00][..],
                &[][..],
            ]
        );
        assert_eq!(FOCUSED_ENVELOPES, 432);
        assert_eq!(
            FOCUSED_ENVELOPES,
            PIDS.len() * DCS.len() * CPH.len() * UDHI.len()
        );
        assert_eq!(BRUTEFORCE_ENVELOPES, 786_432);
        assert_eq!(BRUTEFORCE_ENVELOPES, 256 * 256 * CPH.len() * UDHI.len());
    }

    #[test]
    fn the_first_envelope_carries_the_first_combination_in_loop_order() {
        // pid 00, dcs 00, cph 027000, udhi 0: the innermost-first corner of the
        // reference's own loop order.
        let apdu = tar::envelope_apdu_passthrough(
            sweep(Mode::Default).tar,
            tar::Class::Etsi,
            0,
            MECHANISMS[0],
            CPH[0],
            tar::Passthrough {
                pid: 0x00,
                dcs: 0x00,
                udhi: false,
            },
        )
        .expect("the envelope fits");
        let data = &apdu[5..];
        assert_eq!(data.len() + 5, apdu.len());
        let tpdu = tpdu(data);
        assert_eq!(tpdu[FIRST_OCTET] & tar::TP_UDHI, 0, "UDHI must be clear");
        assert_eq!(tpdu[PID], 0x00);
        assert_eq!(tpdu[DCS_AT], 0x00);
        assert_eq!(&tpdu[UD..UD + CPH[0].len()], CPH[0]);
    }

    #[test]
    fn the_tpdu_carries_the_chosen_pid_dcs_and_udhi() {
        for &pid in &PIDS {
            for &dcs in &DCS {
                for &udhi in &UDHI {
                    let data = tar::envelope_data_passthrough(
                        0x000042,
                        tar::Class::Etsi,
                        0,
                        MECHANISMS[0],
                        CPH[0],
                        tar::Passthrough { pid, dcs, udhi },
                    )
                    .expect("the envelope fits");
                    let tpdu = tpdu(&data);
                    assert_eq!(tpdu[PID], pid, "TP-PID must be TPDU octet 7");
                    assert_eq!(tpdu[DCS_AT], dcs, "TP-DCS must be TPDU octet 8");
                    assert_eq!(
                        tpdu[FIRST_OCTET] & tar::TP_UDHI != 0,
                        udhi,
                        "TP-UDHI must be the flag the reference toggles"
                    );
                    // The rest of the TPDU is the probe's own and does not move.
                    assert_eq!(usize::from(tpdu[UDL]), tpdu.len() - UD);
                }
            }
        }
    }

    #[test]
    fn the_command_packet_carries_the_chosen_cph_and_keeps_cpl_chl() {
        for cph in CPH {
            let packet =
                tar::command_packet_with_cph(0x000042, 0, MECHANISMS[0].0, MECHANISMS[0].1, cph);
            assert_eq!(
                &packet[..cph.len()],
                cph,
                "the CPH leads the Command Packet"
            );
            // CPL is two octets counting from CHL to the end of the user data
            // (3GPP TS 31.115 clause 7.1), so it does not move with the CPH.
            let cpl = u16::from_be_bytes([packet[cph.len()], packet[cph.len() + 1]]);
            assert_eq!(cpl, 21);
            assert_eq!(packet[cph.len() + 2], 13, "CHL is the probe's own");
            assert_eq!(
                &packet[packet.len() - tar::PROBE_USER_DATA.len()..],
                &tar::PROBE_USER_DATA[..],
                "the user data is the probe's own and does not move either"
            );
        }
    }

    #[test]
    fn a_quiet_card_records_no_hits_and_says_so_in_one_line() {
        let mut card = Scripted::silent();
        let report = audit(
            &mut card,
            sweep(Mode::Default),
            &Policy::default(),
            &mut || false,
        )
        .expect("the sweep runs");
        assert_eq!(report.sent, FOCUSED_ENVELOPES);
        assert_eq!(report.planned, 432);
        assert_eq!(report.unsent(), 0);
        assert!(!report.capped);
        assert!(report.complete());
        assert_eq!(report.hit_count(), 0);
        assert_eq!(
            report.summary(),
            "passthrough default: 432 of 432 planned envelope(s) sent, bound 4096, 0 hit(s)"
        );
        assert!(report.to_human().contains("recorded no hit"));
        assert_eq!(card.sent().len(), FOCUSED_ENVELOPES);
    }

    #[test]
    fn a_card_that_answers_with_data_is_reported_as_a_hit_with_that_hex() {
        // body 81 03 9F, then 90 00: four octets, so more than the two the
        // reference filters on.
        let mut card = Scripted::answering(
            FOCUSED_ENVELOPES + 8,
            vec![0x81, 0x03, 0x9F, 0x90, 0x00],
            Vec::new(),
        );
        let report = audit(
            &mut card,
            sweep(Mode::Default),
            &Policy::default(),
            &mut || false,
        )
        .expect("the sweep runs");
        assert_eq!(report.hit_count(), FOCUSED_ENVELOPES);
        let first = &report.hits[0];
        assert_eq!(first.pid, PIDS[0]);
        assert_eq!(first.dcs, DCS[0]);
        assert!(!first.udhi);
        assert_eq!(first.cph, CPH[0]);
        assert_eq!(first.status.unwrap().to_string(), "9000");
        assert_eq!(hex(&first.response), "81039F9000");
        let json = report.to_json();
        assert_eq!(json["hits"][0]["response_hex"], "81039F9000");
        assert_eq!(json["hit_count"], 432);
    }

    #[test]
    fn the_udhi_flag_and_the_cph_move_through_the_whole_loop() {
        let mut card = Scripted::silent();
        let report = audit(
            &mut card,
            sweep(Mode::Default),
            &Policy::default(),
            &mut || false,
        )
        .expect("the sweep runs");
        let sent = card.sent();
        let mut index = 0usize;
        for &pid in &PIDS {
            for &dcs in &DCS {
                for cph in CPH {
                    for &udhi in &UDHI {
                        let tpdu = tpdu(&sent[index][5..]);
                        assert_eq!(tpdu[PID], pid);
                        assert_eq!(tpdu[DCS_AT], dcs);
                        assert_eq!(tpdu[FIRST_OCTET] & tar::TP_UDHI != 0, udhi);
                        assert_eq!(&tpdu[UD..UD + cph.len()], cph);
                        index += 1;
                    }
                }
            }
        }
        assert_eq!(index, report.sent);
        assert_eq!(index, FOCUSED_ENVELOPES);
    }

    #[test]
    fn the_bruteforce_plan_is_a_capped_partial_sweep() {
        const { assert!(BRUTEFORCE_ENVELOPES > MAX_ENVELOPES) };
        let mut card = Scripted::silent();
        let report = audit(
            &mut card,
            sweep(Mode::Bruteforce),
            &Policy::default(),
            &mut || false,
        )
        .expect("the sweep runs");
        assert_eq!(report.sent, MAX_ENVELOPES);
        assert_eq!(report.planned, BRUTEFORCE_ENVELOPES);
        assert_eq!(report.unsent(), BRUTEFORCE_ENVELOPES - MAX_ENVELOPES);
        assert!(report.capped);
        assert!(!report.complete());
        assert!(report.stopped.is_some());
        let json = report.to_json();
        assert_eq!(json["mode"], "bruteforce");
        assert_eq!(json["bound"], MAX_ENVELOPES);
        assert_eq!(json["capped"], true);
        assert_eq!(json["complete"], false);
        assert_eq!(json["unsent"], BRUTEFORCE_ENVELOPES - MAX_ENVELOPES);
        assert!(report.to_human().contains("CAPPED PARTIAL SWEEP"));
    }

    #[test]
    fn a_card_that_leaves_mid_sweep_still_reports_what_it_sent() {
        let reader = ReaderName::new("Replay Transport 1.0").expect("a reader name");
        let mut card = Scripted::new(vec![
            Ok(vec![0x90, 0x00]),
            Ok(vec![0x90, 0x00]),
            Ok(vec![0x90, 0x00]),
            Err(TransportError::CardGone {
                reader: reader.clone(),
            }),
        ]);
        let report = audit(
            &mut card,
            sweep(Mode::Default),
            &Policy::default(),
            &mut || false,
        )
        .expect("a transport error is reported, not raised");
        assert_eq!(report.sent, 3);
        assert_eq!(report.planned, FOCUSED_ENVELOPES);
        assert_eq!(report.unsent(), FOCUSED_ENVELOPES - 3);
        assert!(!report.complete());
        assert!(!report.capped);
        let reason = report
            .stopped
            .as_ref()
            .expect("the reader stopping is reported");
        assert!(reason.contains("reader stopped answering"), "{reason}");
        assert_eq!(report.to_json()["sent"], 3);
        assert_eq!(report.to_json()["complete"], false);
    }

    #[test]
    fn an_interrupt_stops_the_sweep_and_marks_it_incomplete() {
        let mut card = Scripted::silent();
        let mut calls = 0usize;
        let report = audit(
            &mut card,
            sweep(Mode::Default),
            &Policy::default(),
            &mut || {
                calls += 1;
                calls > 10
            },
        )
        .expect("the sweep runs");
        assert!(report.sent <= 10);
        assert!(!report.complete());
        assert!(report.stopped.is_some());
    }

    #[test]
    fn the_envelope_is_one_apdu_carrying_the_envelope_instruction() {
        let mut card = Scripted::silent();
        audit(
            &mut card,
            sweep(Mode::Default),
            &Policy::default(),
            &mut || false,
        )
        .expect("the sweep runs");
        let first = &card.sent()[0];
        assert_eq!(first[0], tar::Class::Etsi.octet());
        assert_eq!(first[1], tar::INS_ENVELOPE);
        assert_eq!(first[2], 0x00);
        assert_eq!(first[3], 0x00);
        assert_eq!(first.len() - 5, usize::from(first[4]), "Lc counts the data");
    }
}
