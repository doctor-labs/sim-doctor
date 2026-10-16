//! OTA/SMS fuzzing: a bounded TAR x keyset x mechanism sweep.
//!
//! **Owns.** The sweep loop and its bound, built directly on
//! [`crate::tar`]'s envelope builder ([`crate::tar::envelope_apdu_with`])
//! and wire mechanics ([`crate::tar::probe_envelope`]), and the differential
//! ([`crate::tar::Baseline`]) that decides whether a (TAR, keyset, mechanism)
//! triple got a response unlike the one this card gives to combinations it
//! has no opinion about.
//!
//! **Does not own.** APDU discovery - that is [`crate::apdu_scan`], a
//! different scanner entirely; see its module documentation for the
//! SIMTester distinction (`APDUScanner.java` vs `FuzzerFactory.java`) this
//! crate keeps apart. This module is the latter: AGENTS.md 5.2's "Base
//! fuzzer: ~130 TARs x 15 keysets x 16 mechanisms".
//!
//! # Why this reuses `tar.rs` rather than re-deriving the wire format
//!
//! Every fact [`crate::tar`]'s module documentation records about the
//! ENVELOPE protocol - one complete APDU per probe (the swicc-pcsc-only
//! header/data split included), a `91 xx` recorded as the answer, abandoning
//! the scan rather than continuing mid-command - applies here unchanged. The only thing
//! an OTA fuzz sweep varies that a TAR audit does not is the keyset and the
//! SPI1/SPI2 "mechanism" octets inside the Command Packet, so [`tar`] exposes
//! that as parameters ([`tar::command_packet_with`],
//! [`tar::envelope_data_with`], [`tar::envelope_apdu_with`]) instead of
//! this module rebuilding the TS 03.48 / TS 23.040 / `D1` chain a second time.
//!
//! # The mechanism table is unverified, and says so
//!
//! AGENTS.md section 2 forbids silent protocol facts. SIMTester's own
//! `FuzzerFactory.java` was **not** read in this session - unlike
//! [`crate::tar`], which cites `TARScanner.java` line for line - so
//! [`MECHANISMS`] is `[U]`: sixteen SPI1/SPI2 combinations chosen to span the
//! bit space [`crate::tar::command_packet`] leaves fixed at zero (RC
//! requested or not, Proof-of-Response requested or not, PoR security and PoR
//! mode varied), not sixteen values copied out of SIMTester's own table. A
//! later issue that reads `FuzzerFactory.java` at a pinned commit should
//! replace this table and upgrade this note to `[V]`.
//!
//! # Bounded exactly like `tar.rs`
//!
//! [`MAX_PROBES`] caps one sweep, whatever `--quick` or the TAR selection
//! asks for, for the same reason [`crate::tar::MAX_PROBES`] exists: this tool
//! will not put an unbounded loop behind a flag. A sweep that hit the cap
//! reports [`Audit::is_complete`] as false and marks every finding partial.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "fuzz";

/// The `type` every `fuzz ota` envelope carries.
pub const KIND: &str = "fuzz";

use serde_json::{json, Value};

use crate::apdu::StatusWord;
use crate::otacrypto;
use crate::session::Policy;
use crate::tar::{self, Baseline, Class, Signature};
use crate::transport::CardSession;

/// The most (TAR, keyset, mechanism) triples one sweep may probe.
///
/// Same number as [`crate::tar::MAX_PROBES`], for the same reason: a bound
/// that is a constant, published, rather than invented per call site.
pub const MAX_PROBES: usize = 4096;

/// The keysets a full sweep probes: `0`..=`14`, fifteen values.
///
/// \[V] AGENTS.md 5.2, citing SIMTester's own base fuzzer: "~130 TARs x 15
/// keysets x 16 mechanisms". [`crate::tar::command_packet_with`] writes
/// `keyset << 4` into both KIC and KID, the same encoding
/// `CommandPacket.setKeyset` uses.
pub const KEYSETS: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Keysets `--quick` probes: `0`, `1`, `2`.
pub const QUICK_KEYSETS: [u8; 3] = [0, 1, 2];

/// Sixteen (SPI1, SPI2) combinations a full sweep probes.
///
/// `[U]` - see the module documentation's "mechanism table is unverified"
/// section. Spans: SPI1 bits 1-0 (RC is 0x01; ciphering is SPI1 bit 2, 0x04, not used here), and SPI2's PoR-requested
/// bit (0x01) combined with PoR security 0 vs 2 (bits 2-3) and PoR mode 0 vs
/// 1 (bit 5) - the same fields [`crate::tar::SPI2_PROBE`]'s doc comment
/// derives the TAR probe's own fixed value from.
pub const MECHANISMS: [(u8, u8); 16] = [
    (0x00, 0x00),
    (0x00, 0x01),
    (0x00, 0x08),
    (0x00, 0x09),
    (0x00, 0x20),
    (0x00, 0x21),
    (0x00, 0x28),
    (0x00, 0x29),
    (0x01, 0x00),
    (0x01, 0x01),
    (0x01, 0x08),
    (0x01, 0x09),
    (0x01, 0x20),
    (0x01, 0x21),
    (0x01, 0x28),
    (0x01, 0x29),
];

/// Mechanisms `--quick` probes: the first four of [`MECHANISMS`].
pub const QUICK_MECHANISMS: [(u8, u8); 4] =
    [MECHANISMS[0], MECHANISMS[1], MECHANISMS[2], MECHANISMS[3]];

// CNTR (counter management), SPI1 bits 3-4. \[V] SIMTester `d197fef`,
// `CommandPacket.java:44-47` (`CNTR_*`), written by `setCounterManegement`
// as `SPI1 |= (value << 3) & 0x18` (`CommandPacket.java:143-145`).
/// `CNTR_NO_CNTR_AVAILABLE`: no counter.
pub const CNTR_NO_CNTR_AVAILABLE: u8 = 0x0;
/// `CNTR_CNTR_AVAILABLE`: counter present.
pub const CNTR_CNTR_AVAILABLE: u8 = 0x1;
/// `CNTR_CNTR_HIGHER`: counter higher than the card's.
pub const CNTR_CNTR_HIGHER: u8 = 0x2;
/// `CNTR_CNTR_ONE_HIGHER`: counter one higher than the card's.
pub const CNTR_CNTR_ONE_HIGHER: u8 = 0x3;

// KIC and KID algorithm selectors, the low nibble of each octet. \[V] SIMTester
// `d197fef`, `CommandPacket.java:49-60` (constants) and `setKICAlgo` /
// `setKIDAlgo` (`CommandPacket.java:250-340`): KIC `0x1` DES-CBC, `0x5` 3DES
// 2-key, `0x9` 3DES 3-key; KID `0x1`, `0x5`, `0x9` likewise. KIC also has
// DES-ECB (`0xD`), which the table does not use.
/// `KIC_ALGO_IMPLICIT`: no KIC.
pub const KIC_ALGO_IMPLICIT: u8 = 0;
/// `KIC_ALGO_DES_CBC`.
pub const KIC_ALGO_DES_CBC: u8 = 1;
/// `KIC_ALGO_3DES_CBC_2KEYS`.
pub const KIC_ALGO_3DES_CBC_2KEYS: u8 = 0x5;
/// `KIC_ALGO_3DES_CBC_3KEYS`.
pub const KIC_ALGO_3DES_CBC_3KEYS: u8 = 0x9;
/// `KID_ALGO_IMPLICIT`: no KID.
pub const KID_ALGO_IMPLICIT: u8 = 0;
/// `KID_ALGO_DES_CBC`.
pub const KID_ALGO_DES_CBC: u8 = 1;
/// `KID_ALGO_3DES_CBC_2KEYS`.
pub const KID_ALGO_3DES_CBC_2KEYS: u8 = 0x5;
/// `KID_ALGO_3DES_CBC_3KEYS`.
pub const KID_ALGO_3DES_CBC_3KEYS: u8 = 0x9;

/// One row of SIMTester's fuzzer table, `FuzzerFactory.java` at `d197fef`
/// (`put(n, new FuzzerData(...))`, lines 16-66).
///
/// The row's `FuzzerData` constructor is `(name, counter, kic, kid,
/// requestPoR, cipherPoR)` (`FuzzerData.java`); the table's sixth argument is
/// `cipherPoR`, not a ciphering flag for the Command Packet. Whether the
/// Command Packet is ciphered follows from the KIC algorithm alone
/// (`Fuzzer.generateCommandPacket`, `Fuzzer.java:216-222`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzerSpec {
    /// The table key, `0` to `16`.
    pub id: u8,
    /// A `CNTR_*` value, see [`CNTR_NO_CNTR_AVAILABLE`] and friends.
    pub counter: u8,
    /// A `KIC_ALGO_*` value.
    pub kic_algo: u8,
    /// A `KID_ALGO_*` value.
    pub kid_algo: u8,
    /// Request a Proof of Receipt (`SPI2` bit 0).
    pub request_por: bool,
    /// Cipher the PoR instead of signing it (`SPI2` bit 4, not bits 2-3).
    pub cipher_por: bool,
}

/// SIMTester's seventeen fuzzers, `FuzzerFactory` keys `0` to `16`, in key
/// order. \[V] `FuzzerFactory.java` at `d197fef`.
pub const FUZZERS: [FuzzerSpec; 17] = [
    spec(
        0,
        CNTR_NO_CNTR_AVAILABLE,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        false,
        false,
    ),
    spec(
        1,
        CNTR_NO_CNTR_AVAILABLE,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        false,
    ),
    spec(
        2,
        CNTR_CNTR_AVAILABLE,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        false,
    ),
    spec(
        3,
        CNTR_CNTR_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        false,
    ),
    spec(
        4,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        false,
    ),
    spec(
        5,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_DES_CBC,
        true,
        false,
    ),
    spec(
        6,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_3DES_CBC_2KEYS,
        true,
        false,
    ),
    spec(
        7,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_3DES_CBC_3KEYS,
        true,
        false,
    ),
    spec(
        8,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_3DES_CBC_3KEYS,
        KID_ALGO_3DES_CBC_3KEYS,
        true,
        false,
    ),
    spec(
        9,
        CNTR_NO_CNTR_AVAILABLE,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        10,
        CNTR_CNTR_AVAILABLE,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        11,
        CNTR_CNTR_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        12,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_IMPLICIT,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        13,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_DES_CBC,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        14,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_3DES_CBC_2KEYS,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        15,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_3DES_CBC_3KEYS,
        KID_ALGO_IMPLICIT,
        true,
        true,
    ),
    spec(
        16,
        CNTR_CNTR_ONE_HIGHER,
        KIC_ALGO_3DES_CBC_3KEYS,
        KID_ALGO_3DES_CBC_3KEYS,
        true,
        true,
    ),
];

const fn spec(
    id: u8,
    counter: u8,
    kic_algo: u8,
    kid_algo: u8,
    request_por: bool,
    cipher_por: bool,
) -> FuzzerSpec {
    FuzzerSpec {
        id,
        counter,
        kic_algo,
        kid_algo,
        request_por,
        cipher_por,
    }
}

impl FuzzerSpec {
    /// Whether this fuzzer needs a cryptographic checksum (KID algorithm) or
    /// ciphering (KIC algorithm). Those need the CC octets and encrypted CNTR
    /// and UD fields, which [`Self::command_packet`] does not build; [`Self::secured_command_packet`] does.
    pub fn needs_crypto(&self) -> bool {
        self.kic_algo != KIC_ALGO_IMPLICIT || self.kid_algo != KID_ALGO_IMPLICIT
    }

    /// The Command Packet this fuzzer sends for `tar` under `keyset`, or `None`
    /// when [`Self::needs_crypto`].
    ///
    /// Only the header octets change from the TAR probe: SPI1 gets the counter
    /// management bits, SPI2 gets the PoR request (bit 0), PoR security `CC`
    /// (bits 2-3, `0x08`) or PoR ciphering (bit 4, `0x10`) and the PoR mode
    /// `SMS_SUBMIT` (bit 5, `0x20`), which is what `FuzzerFactory` uses
    /// (`Fuzzer.use_sms_submit = true`). The counter value is `0` for
    /// `CNTR_NO_CNTR_AVAILABLE` and `1` otherwise (`Fuzzer.java:225-229`).
    ///
    /// \[V] SIMTester `d197fef`: `Fuzzer.generateCommandPacket`
    /// (`Fuzzer.java:195-245`), `CommandPacket.setPoR` (SPI2 bit 0),
    /// `setPoRSecurity` (bits 2-3), `setPoRCiphering` (bit 4) and `setPoRMode`
    /// (bit 5). Clause numbers in TS 102 225 are not checked against the
    /// standard text here.
    pub fn command_packet(&self, tar: u32, keyset: u8) -> Option<Vec<u8>> {
        if self.needs_crypto() {
            return None;
        }
        let spi1 = (self.counter << 3) & 0x18;
        let spi2 = self.spi2();
        let counter = u8::from(self.counter != CNTR_NO_CNTR_AVAILABLE);
        let key = keyset << 4;
        Some(tar::command_packet_octets(
            tar, spi1, spi2, key, key, counter,
        ))
    }
}

/// Length of the cryptographic checksum (CC) octets the KID algorithm writes.
const SIG_LEN: usize = 8;

impl FuzzerSpec {
    /// The SPI2 octet: PoR request (bit 0), PoR security CC (bits 2-3) or PoR
    /// ciphering (bit 4), and the PoR mode SMS_SUBMIT (bit 5).
    fn spi2(&self) -> u8 {
        if self.request_por {
            let security_or_cipher = if self.cipher_por { 0x10 } else { 0x08 };
            0x01 | security_or_cipher | 0x20
        } else {
            0x00
        }
    }

    /// The Command Packet for this fuzzer with the cryptographic checksum (KID
    /// algorithm) and ciphering (KIC algorithm) filled in. `kic_key` and
    /// `kid_key` are the key octets for those algorithms: 8 bytes for DES, 16
    /// for two-key 3DES, 24 for three-key 3DES. A key the algorithm does not
    /// take is refused; a key for an implicit algorithm is not read. `counter`
    /// is the one-octet CNTR value.
    ///
    /// Layout and order follow the OtaDialectSms encode_cmd function in the
    /// pySim ota.py file (its comments cite TS 102 225 section 5.1): the CC
    /// covers CPL, the header, CNTR, PCNTR and the padded user data; ciphering
    /// covers CNTR, PCNTR, CC and the padded user data, and the outer CPL is
    /// then the header plus the ciphertext. Bytes only: nothing here is sent to
    /// a card.
    pub fn secured_command_packet(
        &self,
        tar: u32,
        keyset: u8,
        kic_key: &[u8],
        kid_key: &[u8],
        counter: u8,
    ) -> Result<Vec<u8>, otacrypto::Error> {
        let kic_on = self.kic_algo != KIC_ALGO_IMPLICIT;
        let kid_on = self.kid_algo != KID_ALGO_IMPLICIT;
        let kic_alg = kic_on
            .then(|| ota_alg(self.kic_algo, kic_key))
            .transpose()?;
        let kid_alg = kid_on
            .then(|| ota_alg(self.kid_algo, kid_key))
            .transpose()?;

        let sig_len = if kid_on { SIG_LEN } else { 0 };
        let chl = tar::COMMAND_HEADER_LEN + if kid_on { SIG_LEN as u8 } else { 0 };
        let spi1 = ((self.counter << 3) & 0x18)
            | if kic_on { 0x04 } else { 0 }
            | if kid_on { 0x02 } else { 0 };
        let key = keyset << 4;
        let kic_octet = key | if kic_on { self.kic_algo } else { 0 };
        let kid_octet = key | if kid_on { self.kid_algo } else { 0 };
        let mut head = vec![chl, spi1, self.spi2(), kic_octet, kid_octet];
        head.extend_from_slice(&tar.to_be_bytes()[1..]);

        // Ciphering pads CNTR, PCNTR, CC and the user data to the KIC block size.
        let mut user_data = tar::PROBE_USER_DATA.to_vec();
        let mut pcntr = 0u8;
        if let Some(alg) = kic_alg {
            let block = alg.block_size();
            let fill = (6 + sig_len + user_data.len()) % block;
            if fill != 0 {
                pcntr = u8::try_from(block - fill).expect("a block is at most 16 octets");
                user_data.resize(user_data.len() + usize::from(pcntr), 0);
            }
        }
        let cntr_pcntr = [0x00, 0x00, 0x00, 0x00, counter, pcntr];

        let cpl = u16::try_from(head.len() + cntr_pcntr.len() + user_data.len() + sig_len)
            .expect("a fuzzer packet is far below 64 KiB");
        let mut cc = Vec::new();
        if let Some(alg) = kid_alg {
            let mut signed = cpl.to_be_bytes().to_vec();
            signed.extend_from_slice(&head);
            signed.extend_from_slice(&cntr_pcntr);
            signed.extend_from_slice(&user_data);
            cc = otacrypto::sign(alg, kid_key, &signed, Some(SIG_LEN))?;
        }

        let inner = [cntr_pcntr.as_slice(), cc.as_slice(), user_data.as_slice()].concat();
        let mut out = tar::COMMAND_PACKET_HEADER.to_vec();
        match kic_alg {
            Some(alg) => {
                let ciphered = otacrypto::encrypt(alg, kic_key, None, &inner)?;
                let body = [head.as_slice(), ciphered.as_slice()].concat();
                let outer = u16::try_from(body.len()).expect("a fuzzer packet is far below 64 KiB");
                out.extend_from_slice(&outer.to_be_bytes());
                out.extend_from_slice(&body);
            }
            None => {
                out.extend_from_slice(&cpl.to_be_bytes());
                out.extend_from_slice(&head);
                out.extend_from_slice(&inner);
            }
        }
        Ok(out)
    }
}

/// The OTA primitive and the key length a KIC or KID algorithm nibble names:
/// 1 is single DES, 5 two-key 3DES, 9 three-key 3DES.
fn ota_alg(nibble: u8, key: &[u8]) -> Result<otacrypto::Alg, otacrypto::Error> {
    let (alg, want) = match nibble {
        KIC_ALGO_DES_CBC => (otacrypto::Alg::Des, 8),
        KIC_ALGO_3DES_CBC_2KEYS => (otacrypto::Alg::Tdes, 16),
        _ => (otacrypto::Alg::Tdes, 24),
    };
    if key.len() == want {
        Ok(alg)
    } else {
        Err(otacrypto::Error::KeyLength {
            alg,
            got: key.len(),
        })
    }
}

/// TARs a full sweep probes: [`crate::tar::FOCUSED_BANDS`], the same
/// bounded default a TAR audit uses, for the same reason - the full
/// 16 777 216-value space does not fit any budget this tool will ship.
pub fn tars(quick: bool) -> Vec<u32> {
    if quick {
        tar::CALIBRATION_TARS[..5].to_vec()
    } else {
        let (candidates, _) = tar::candidates(&tar::Selection::focused(), tar::MAX_PROBES);
        candidates
    }
}

/// One sweep's selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sweep {
    /// Fewer TARs, keysets and mechanisms, so a run finishes in milliseconds.
    pub quick: bool,
    /// The ENVELOPE class, same meaning as [`crate::tar::Class`].
    pub class: Class,
}

impl Default for Sweep {
    fn default() -> Self {
        Self {
            quick: false,
            class: Class::Etsi,
        }
    }
}

/// One (TAR, keyset, mechanism) probe and what the card said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The TAR probed.
    pub tar: u32,
    /// The keyset probed.
    pub keyset: u8,
    /// The (SPI1, SPI2) mechanism probed.
    pub mechanism: (u8, u8),
    /// Whether the card's answer differed from its baseline answer.
    pub accepted: bool,
    /// The status word the card answered with, when it gave one.
    pub status: Option<StatusWord>,
}

impl Probe {
    fn to_json(&self) -> Value {
        json!({
            "tar": tar::hex(self.tar),
            "tar_decimal": self.tar,
            "keyset": self.keyset,
            "mechanism": { "spi1": format!("{:02X}", self.mechanism.0), "spi2": format!("{:02X}", self.mechanism.1) },
            "outcome": if self.accepted { "accepted" } else { "refused" },
            "status": self.status.map(|s| s.to_string()),
        })
    }
}

/// Everything one OTA fuzz sweep found, and everything it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    /// What was asked for.
    pub sweep: Sweep,
    /// Every triple probed, in probe order.
    pub probes: Vec<Probe>,
    /// The response this card gives to a triple it has no opinion about.
    pub baseline: Baseline,
    /// False when [`MAX_PROBES`] fired with triples left over.
    pub exhausted: bool,
    /// Why the sweep stopped early, when it did.
    pub stopped: Option<String>,
    /// The TERMINAL PROFILE the sweep sent itself, when calibration hit a
    /// generic error (issue #211). `None` when the baseline was established
    /// without one.
    pub terminal_profile: Option<tar::TerminalProfile>,
}

impl Audit {
    /// Whether this audit looked at everything it was asked to.
    pub fn is_complete(&self) -> bool {
        self.stopped.is_none() && self.exhausted
    }

    /// The triples the card accepted.
    pub fn accepted(&self) -> impl Iterator<Item = &Probe> {
        self.probes.iter().filter(|probe| probe.accepted)
    }

    /// The `fuzz.ota` block a report carries.
    pub fn to_json(&self) -> Value {
        json!({
            "quick": self.sweep.quick,
            "class": self.sweep.class.id(),
            "max_probes": MAX_PROBES,
            "probed": self.probes.len(),
            "exhausted": self.exhausted,
            "complete": self.is_complete(),
            "stopped": self.stopped,
            "baseline_established": self.baseline.is_established(),
            "terminal_profile": self.terminal_profile.as_ref().map(tar::TerminalProfile::to_json),
            "accepted": self.accepted().map(Probe::to_json).collect::<Vec<_>>(),
            "probes": self.probes.iter().map(Probe::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Sends one (TAR, keyset, mechanism) triple and reads the signature.
fn probe_triple<S: CardSession + ?Sized>(
    session: &mut S,
    tar: u32,
    keyset: u8,
    mechanism: (u8, u8),
    class: Class,
    policy: &Policy,
) -> Result<Result<(Signature, usize), String>, tar::Error> {
    let (spi1, spi2) = mechanism;
    let Some(apdu) = tar::envelope_apdu_with(tar, class, keyset, spi1, spi2) else {
        return Err(tar::Error::UnbuildableEnvelope(
            "the SMS-PP-DOWNLOAD envelope for this triple does not fit a short APDU data field",
        ));
    };
    match tar::probe_envelope(session, &apdu, policy) {
        Ok(Ok(reply)) => Ok(Ok((reply.signature, reply.exchanges))),
        Ok(Err(reason)) => Ok(Err(reason)),
        Err(err) => Err(err),
    }
}

/// Runs the OTA/SMS fuzz sweep over one card.
///
/// Bounded twice, same contract as [`crate::tar::audit`]: by `sweep` and by
/// [`MAX_PROBES`]. `interrupt` is polled before every probe including the
/// calibration pass.
pub fn audit<S: CardSession + ?Sized>(
    session: &mut S,
    sweep: Sweep,
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<Audit, tar::Error> {
    let tar_list = tars(sweep.quick);
    let keysets: &[u8] = if sweep.quick {
        &QUICK_KEYSETS
    } else {
        &KEYSETS
    };
    let mechanisms: &[(u8, u8)] = if sweep.quick {
        &QUICK_MECHANISMS
    } else {
        &MECHANISMS
    };

    // 1. Calibration: the TAR audit's own baseline TARs, at keyset 0 and the
    // first mechanism, which is enough to tell "this card answers everything
    // alike" apart from "this card has an opinion" before the sweep spends
    // its budget finding out triple by triple.
    let mut calibration = calibrate(session, sweep.class, mechanisms[0], policy, interrupt)?;
    let mut baseline = Baseline::of(&calibration);

    // 1b. Issue #211: a generic error (`6F 00` and kin) is a blind spot, the
    // card has not processed the envelopes because no TERMINAL PROFILE was
    // sent yet. So the sweep sends one itself, once, and calibrates again.
    // Only on that blind spot: a card that already judges envelopes is swept
    // exactly as before, with no CAT state change.
    let mut terminal_profile = None;
    if baseline.generic_error().is_some() {
        terminal_profile = Some(tar::send_terminal_profile(session, policy)?);
        calibration = calibrate(session, sweep.class, mechanisms[0], policy, interrupt)?;
        baseline = Baseline::of(&calibration);
    }

    // 2. The sweep itself, TAR outer, keyset middle, mechanism inner, capped
    // and halted on the first sign the card is not answering coherently -
    // the same "abandon rather than guess" rule tar.rs's probe loop follows.
    let mut probes = Vec::new();
    let mut stopped: Option<String> = None;
    let mut triples_seen = 0usize;
    'sweep: for &tar_value in &tar_list {
        for &keyset in keysets {
            for &mechanism in mechanisms {
                triples_seen += 1;
                if probes.len() == MAX_PROBES {
                    stopped = Some(format!(
                        "the probe budget of {MAX_PROBES} triples was reached"
                    ));
                    break 'sweep;
                }
                if interrupt() {
                    stopped = Some("the sweep was interrupted".to_owned());
                    break 'sweep;
                }
                match probe_triple(session, tar_value, keyset, mechanism, sweep.class, policy) {
                    Ok(Ok((signature, _))) => {
                        let accepted = !baseline.refuses(&signature);
                        probes.push(Probe {
                            tar: tar_value,
                            keyset,
                            mechanism,
                            accepted,
                            status: signature.status(),
                        });
                    }
                    Ok(Err(reason)) => {
                        stopped = Some(format!("the card stopped answering envelopes: {reason}"));
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

    let total_triples = tar_list.len() * keysets.len() * mechanisms.len();
    let exhausted = stopped.is_none() && triples_seen >= total_triples;

    Ok(Audit {
        sweep,
        probes,
        baseline,
        exhausted,
        stopped,
        terminal_profile,
    })
}

/// The calibration pass: [`tar::CALIBRATION_TARS`] at one keyset and mechanism.
/// Stops quietly on a card that stops answering, like the sweep does.
fn calibrate<S: CardSession + ?Sized>(
    session: &mut S,
    class: Class,
    mechanism: (u8, u8),
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<Vec<Option<Signature>>, tar::Error> {
    let mut calibration: Vec<Option<Signature>> = Vec::with_capacity(tar::CALIBRATION_PROBES);
    for &tar_value in &tar::CALIBRATION_TARS {
        if interrupt() {
            break;
        }
        match probe_triple(session, tar_value, 0, mechanism, class, policy) {
            Ok(Ok((signature, _))) => calibration.push(Some(signature)),
            Ok(Err(_)) => break,
            Err(tar::Error::Transport(_)) => break,
            Err(other) => return Err(other),
        }
    }
    Ok(calibration)
}

/// A namespaced rule ID: `fuzz/ota-mechanism-accepted`.
pub const OTA_MECHANISM_ACCEPTED_RULE: &str = "fuzz/ota-mechanism-accepted";

/// The [`crate::rules::RuleSpec`] for [`OTA_MECHANISM_ACCEPTED_RULE`], so
/// `sim-doctor rules list`/`rules explain` know about it without a card.
pub fn specs() -> Vec<crate::rules::RuleSpec> {
    vec![crate::rules::RuleSpec::new(
        crate::rules::RuleId::new(OTA_MECHANISM_ACCEPTED_RULE).expect("a validated constant"),
        crate::rules::Severity::High,
        "the card answered a (TAR, keyset, mechanism) OTA triple differently from the way it \
         answers triples it has no opinion about, under an explicit opt-in sweep",
    )
    .with_remediation(
        "confirm this TAR/keyset/mechanism combination is one this card is meant to accept; if \
         not, tighten the TAR allow-list or the keyset's SPI requirements and re-run with \
         --i-understand-this-can-brick-the-card against the software card only",
    )
    .with_cwe("CWE-757")
    .with_reference("ETSI TS 102 225 clauses 5.1.1 and 5.1.2 (SPI, security mechanisms)")]
}

/// Findings for every accepted triple in `audit`.
///
/// One finding per accepted triple, [`crate::rules::Location::tar`] addressed
/// (the TAR is the part of the triple a baseline and a TAR audit both already
/// address), with the keyset and mechanism folded into the message so a
/// reader does not have to cross-reference `data.fuzz.ota.accepted` to know
/// which one fired.
pub fn findings(audit: &Audit) -> Vec<crate::rules::Finding> {
    use crate::rules::{Evidence, Finding, Location, RuleId, Severity};
    let rule = RuleId::new(OTA_MECHANISM_ACCEPTED_RULE).expect("a validated constant");
    let mut found: Vec<Finding> = audit
        .accepted()
        .map(|probe| {
            let message = format!(
                "TAR {} accepted a mechanism SPI1={:02X} SPI2={:02X} under keyset {} that \
                 differs from this card's baseline answer",
                tar::hex(probe.tar),
                probe.mechanism.0,
                probe.mechanism.1,
                probe.keyset,
            );
            let evidence = match probe.status {
                Some(status) => Evidence::text(status.to_string()),
                None => Evidence::None,
            };
            Finding::new(
                rule.clone(),
                Severity::High,
                message,
                Location::tar(probe.tar),
                evidence,
            )
        })
        .collect();
    if !audit.is_complete() {
        found = found
            .into_iter()
            .map(|finding| {
                finding.partial(
                    audit
                        .stopped
                        .clone()
                        .unwrap_or_else(|| "the sweep did not finish".to_owned()),
                )
            })
            .collect();
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::transport::{Error as TransportError, ReaderName};

    struct Scripted {
        reader: ReaderName,
        replies: RefCell<VecDeque<Vec<u8>>>,
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl Scripted {
        fn cycling(script: &[&[u8]]) -> Self {
            let mut replies: VecDeque<Vec<u8>> = VecDeque::new();
            for _ in 0..2048 {
                for item in script {
                    replies.push_back(item.to_vec());
                }
            }
            Self {
                reader: ReaderName::new("swICC PC/SC IFD Driver v1.2.0 00 00")
                    .expect("a reader name"),
                replies: RefCell::new(replies),
                sent: RefCell::new(Vec::new()),
            }
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.borrow_mut().push(command.to_vec());
            Ok(self
                .replies
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| vec![0x90, 0x00]))
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// A card like swSIM behind swicc-pcsc (header and data apart): it has no notion of a TAR at all and answers every
    /// envelope `61 Lc` then `90 00`, so every probe looks alike and nothing
    /// is reported accepted. Mirrors `tar.rs`'s own fixture-shaped test.
    fn swsim_like() -> Scripted {
        Scripted::cycling(&[&[0x61, 0x3A], &[0x90, 0x00]])
    }

    #[test]
    fn quick_sweep_stays_within_its_own_small_budget() {
        let mut card = swsim_like();
        let audit = audit(
            &mut card,
            Sweep {
                quick: true,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        let expected = tars(true).len() * QUICK_KEYSETS.len() * QUICK_MECHANISMS.len();
        assert_eq!(audit.probes.len(), expected);
        assert!(expected < MAX_PROBES);
    }

    #[test]
    fn a_card_with_no_tar_check_reports_nothing_accepted() {
        let mut card = swsim_like();
        let audit = audit(
            &mut card,
            Sweep {
                quick: true,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        assert_eq!(audit.accepted().count(), 0);
        assert!(findings(&audit).is_empty());
    }

    #[test]
    fn interrupt_halts_the_sweep_and_marks_it_incomplete() {
        let mut card = swsim_like();
        let mut calls = 0;
        let audit = audit(
            &mut card,
            Sweep {
                quick: false,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || {
                calls += 1;
                calls > 40
            },
        )
        .unwrap();
        assert!(!audit.is_complete());
        assert!(audit.stopped.is_some());
    }

    #[test]
    fn full_sweep_never_exceeds_max_probes() {
        let mut card = swsim_like();
        let audit = audit(
            &mut card,
            Sweep {
                quick: false,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        assert!(audit.probes.len() <= MAX_PROBES);
    }

    /// A card that answers every envelope `6F 00` until a TERMINAL PROFILE
    /// has been sent, then `94 04` for everything (no TAR is refused or
    /// accepted differently, so the baseline is established and nothing is
    /// accepted).
    struct GatedCard {
        reader: ReaderName,
        profiled: bool,
        sent: Vec<Vec<u8>>,
    }

    impl CardSession for GatedCard {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(command.to_vec());
            Ok(match command.get(1) {
                Some(0x10) => {
                    self.profiled = true;
                    vec![0x90, 0x00]
                }
                _ if self.profiled => vec![0x94, 0x04],
                _ => vec![0x6F, 0x00],
            })
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// Issue #211: a generic-error calibration is a blind spot, so the sweep
    /// sends the TERMINAL PROFILE itself, once, and calibrates again.
    #[test]
    fn a_generic_error_calibration_sends_the_profile_before_the_sweep() {
        let mut card = GatedCard {
            reader: ReaderName::new("loopback").expect("a reader name"),
            profiled: false,
            sent: Vec::new(),
        };
        let sweep = Sweep {
            quick: true,
            ..Sweep::default()
        };
        let audit =
            audit(&mut card, sweep, &Policy::default(), &mut || false).expect("no transport error");

        // Calibrate (blind spot), then the profile, then calibrate again.
        let calibrations = tar::CALIBRATION_PROBES;
        assert_eq!(
            card.sent[calibrations],
            vec![0x80, 0x10, 0x00, 0x00, 0x01, 0x13]
        );
        assert!(card.sent[..calibrations].iter().all(|c| c[1] != 0x10));
        assert_eq!(card.sent.iter().filter(|c| c[1] == 0x10).count(), 1);
        assert!(audit.terminal_profile.is_some());
        assert!(audit.baseline.is_established());
        assert_eq!(audit.to_json()["terminal_profile"]["profile"], "13");
    }

    /// The sequence is conditional: a card with an established baseline is
    /// swept exactly as before, with no profile sent.
    #[test]
    fn an_established_calibration_sends_no_profile() {
        let mut card = Scripted::cycling(&[&[0x94, 0x04]]);
        let sweep = Sweep {
            quick: true,
            ..Sweep::default()
        };
        let audit =
            audit(&mut card, sweep, &Policy::default(), &mut || false).expect("no transport error");

        assert!(card.sent.borrow().iter().all(|c| c[1] != 0x10));
        assert!(audit.terminal_profile.is_none());
        assert_eq!(audit.to_json()["terminal_profile"], Value::Null);
    }

    #[test]
    fn specs_register_the_rule_id() {
        let specs = specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id().as_str(), OTA_MECHANISM_ACCEPTED_RULE);
    }
}

#[cfg(test)]
mod fuzzer_table_tests {
    use super::*;

    const TAR: u32 = 0x00_00_01;

    #[test]
    fn table_has_seventeen_rows_keyed_zero_to_sixteen() {
        assert_eq!(FUZZERS.len(), 17);
        for (index, row) in FUZZERS.iter().enumerate() {
            assert_eq!(usize::from(row.id), index);
        }
    }

    #[test]
    fn fuzzer_zero_is_the_plain_probe_header() {
        // SPI1 00, SPI2 00, KIC 00, KID 00, TAR 00 00 01, CNTR 00 00 00 00 00.
        let packet = FUZZERS[0]
            .command_packet(TAR, 0)
            .expect("implicit algorithms");
        assert_eq!(&packet[6..10], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&packet[10..13], &[0x00, 0x00, 0x01]);
        assert_eq!(&packet[13..18], &[0x00; 5]);
    }

    #[test]
    fn counter_modes_land_in_spi1_bits_three_and_four() {
        let spi1 = |id: usize| FUZZERS[id].command_packet(TAR, 0).unwrap()[6];
        assert_eq!(spi1(0), 0x00);
        assert_eq!(spi1(2), 0x08);
        assert_eq!(spi1(3), 0x10);
        assert_eq!(spi1(4), 0x18);
        assert_eq!(spi1(10), 0x08);
    }

    #[test]
    fn counter_value_is_zero_only_without_counter() {
        let cntr_last = |id: usize| FUZZERS[id].command_packet(TAR, 0).unwrap()[17];
        assert_eq!(cntr_last(0), 0x00);
        assert_eq!(cntr_last(1), 0x00);
        assert_eq!(cntr_last(2), 0x01);
        assert_eq!(cntr_last(4), 0x01);
    }

    #[test]
    fn por_bits_follow_request_and_cipher_flags() {
        let spi2 = |id: usize| FUZZERS[id].command_packet(TAR, 0).unwrap()[7];
        assert_eq!(spi2(0), 0x00);
        assert_eq!(spi2(1), 0x29, "request, CC security, SMS_SUBMIT");
        assert_eq!(spi2(9), 0x31, "request, PoR ciphering, SMS_SUBMIT");
    }

    #[test]
    fn keyset_goes_into_both_kic_and_kid_high_nibbles() {
        let packet = FUZZERS[2].command_packet(TAR, 7).unwrap();
        assert_eq!(packet[8], 0x70);
        assert_eq!(packet[9], 0x70);
    }

    #[test]
    fn crypto_fuzzers_are_not_encoded_yet() {
        for id in [5usize, 6, 7, 8, 13, 14, 15, 16] {
            assert!(FUZZERS[id].needs_crypto(), "fuzzer {id}");
            assert_eq!(FUZZERS[id].command_packet(TAR, 0), None, "fuzzer {id}");
        }
        for id in [0usize, 1, 2, 3, 4, 9, 10, 11, 12] {
            assert!(!FUZZERS[id].needs_crypto(), "fuzzer {id}");
            assert!(FUZZERS[id].command_packet(TAR, 0).is_some(), "fuzzer {id}");
        }
    }

    #[test]
    fn raw_octet_builder_matches_the_probe_for_counter_one() {
        // command_packet_with keeps the probe's CNTR of one; the octet builder
        // with the same arguments must produce the same bytes.
        let via_keyset = tar::command_packet_with(TAR, 0, 0x00, 0x29);
        let via_octets = tar::command_packet_octets(TAR, 0x00, 0x29, 0x00, 0x00, 1);
        assert_eq!(via_keyset, via_octets);
    }
}

#[cfg(test)]
mod secured_packet_tests {
    use super::*;

    const TAR: u32 = 0x00_00_01;
    const DES_KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
    const KEY_2: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const KEY_3: [u8; 24] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    // Known answers, keyset 0, counter 1, TAR 00 00 01, probe user data. The
    // MAC and the cipher were run by OpenSSL 3.5 over the pySim layout (single
    // DES as des-ede-cbc with the key twice); they are not from a card or the
    // TS 102 225 text, which is not on the box.

    #[test]
    fn des_checksum_fuzzer_matches_the_known_answer() {
        let packet = FUZZERS[5]
            .secured_command_packet(TAR, 0, &[], &DES_KEY, 1)
            .unwrap();
        assert_eq!(
            hex::encode(packet),
            "027000001d151a290001000001000000000100a296102e31a9acffa0a40000023f00"
        );
    }

    #[test]
    fn two_key_3des_checksum_fuzzer_matches_the_known_answer() {
        let packet = FUZZERS[6]
            .secured_command_packet(TAR, 0, &[], &KEY_2, 1)
            .unwrap();
        assert_eq!(
            hex::encode(packet),
            "027000001d151a290005000001000000000100e36b3e401da3ff9ca0a40000023f00"
        );
    }

    #[test]
    fn des_ciphering_fuzzer_matches_the_known_answer() {
        let packet = FUZZERS[13]
            .secured_command_packet(TAR, 0, &DES_KEY, &[], 1)
            .unwrap();
        assert_eq!(
            hex::encode(packet),
            "02700000180d1c31010000000191cf5a580e426c21bbebf903fb457d97"
        );
    }

    #[test]
    fn two_key_3des_ciphering_fuzzer_matches_the_known_answer() {
        let packet = FUZZERS[14]
            .secured_command_packet(TAR, 0, &KEY_2, &[], 1)
            .unwrap();
        assert_eq!(
            hex::encode(packet),
            "02700000180d1c310500000001c4e11e628bf49cb9c957f9425b7878f6"
        );
    }

    #[test]
    fn three_key_fuzzer_ciphers_and_signs_together() {
        let packet = FUZZERS[16]
            .secured_command_packet(TAR, 0, &KEY_3, &KEY_3, 1)
            .unwrap();
        assert_eq!(
            hex::encode(packet),
            "0270000020151e310909000001fa62b8ad09a21c4f94f76e48ae301b4ae9a2a847f664560a"
        );
    }

    #[test]
    fn plain_fuzzers_build_the_same_bytes_either_way() {
        for id in [0usize, 1, 2, 3, 4, 9, 10, 11, 12] {
            let spec = FUZZERS[id];
            let counter = u8::from(spec.counter != CNTR_NO_CNTR_AVAILABLE);
            let secured = spec.secured_command_packet(TAR, 0, &[], &[], counter);
            assert_eq!(secured.ok(), spec.command_packet(TAR, 0), "fuzzer {id}");
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let err = FUZZERS[6]
            .secured_command_packet(TAR, 0, &[], &DES_KEY, 1)
            .unwrap_err();
        assert_eq!(
            err,
            otacrypto::Error::KeyLength {
                alg: otacrypto::Alg::Tdes,
                got: 8,
            }
        );
    }
}
