//! The OTA "expanded remote application data format", offline: the Command Scripting template
//! **encoder**, the Response Scripting template **decoder** and the Proof-of-Response (PoR)
//! Response Packet **decoder**. Hex in, hex and named fields out. Sends nothing, opens no reader.
//!
//! **Owns.** The ETSI TS 102 226 clause 5.2 expanded templates in both length codings, the five
//! item tags a Response Scripting template may carry, the TS 102 225 table 5 response status
//! codes, the 3GPP TS 31.115 Response Packet header, and the choice between the compact
//! (TS 102 226 clause 5.1.2) and expanded (clause 5.2.2) Remote Application structure a PoR
//! carries.
//!
//! **Does not own.** Any cryptography. This layer sits *above* the TS 102 225 security layer: a
//! PoR whose secure data was ciphered is reported as the ciphered octets it is, and neither
//! deciphering nor verifying the CC/RC is attempted, because that needs a key this command never
//! takes. Every decode is total: an input that is not the structure it claims to be is an error,
//! never a guess. That includes a Proof-of-Response whose RPL does not count exactly the octets
//! that follow RPL: it is refused with `RpLLength`, because the span RPL is required to count is
//! itself **[U]** (see [`Por::rpl`]) and a bad span is not worth guessing at.
//!
//! The tag values and the field layouts were read out of `osmocom/pysim` `pySim/ota.py` (GPL:
//! values and layouts read and cited here, the code below written from the specification) and
//! checked against the clauses it names. Every constant carries its clause and a `[V]`/`[U]`
//! marker as AGENTS.md section 2 requires; the `[U]` ones are listed in the commit message.
//!
//! BER-TLV is [`crate::tlv`], the one BER-TLV parser in this crate. This module does not have a
//! second one: the long length forms (`81`, `82`) are accepted and the indefinite `80` is rejected
//! as a length, which is exactly what these templates need and what `tlv::Error::IndefiniteLength`
//! exists for.

use serde_json::{json, Value};

use crate::contract;
use crate::tlv;
use crate::tlv::{Length, Tlv};

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "ota_expanded";

// ---------------------------------------------------------------------------------------------
// Constants. Every one is cited at its definition.
// ---------------------------------------------------------------------------------------------

/// C-APDU TLV identifier octet: `22`. [V]
///
/// ETSI TS 102 226 V19.0.0 clause 5.2.1.1 (C-APDU TLV), the value laid out by TS 102 223 clause
/// 8.35 (C-APDU COMPREHENSION-TLV): the value is the C-APDU octets and nothing else. Bit 6
/// (constructed) is set because the value holds a structure, and the CR flag of the tag is 0 per
/// TS 101 220 V19.0.0 tables 7.18 and 7.19, so the identifier octet is `0x22` and **not** `0xA2`.
/// Verified against `osmocom/pysim` `pySim/ota.py` `ExpandedC_APDU`
/// (`Struct('_tag'/Const(b'\x22'), 'c_apdu'/Prefixed(BerTlvLen, ...))`), which carries that note.
pub const C_APDU_TAG: u8 = 0x22;

/// R-APDU TLV identifier octet: `23`. [V]
///
/// ETSI TS 102 226 V19.0.0 clause 5.2.2 (R-APDU TLV), the value laid out by TS 102 223 clause
/// 8.36 (R-APDU COMPREHENSION-TLV): `[R-APDU data (n-2 bytes)] SW1 SW2`. The CR flag of the tag
/// is 0 per TS 101 220 table 7.20, so `0x23` and **not** `0xA3`. Verified against `pySim/ota.py`
/// `ExpandedR_APDU` (`Const(b'\x23')`).
pub const R_APDU_TAG: u8 = 0x23;

/// Command Scripting template, definite length coding: `AA`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.2. The value is one or more C-APDU TLVs, each of which uses
/// definite length coding. This is the default coding. Verified against `pySim/ota.py`
/// `ExpandedCmd` (`Const(b'\xaa')`).
pub const CMD_DEFINITE_TAG: u8 = 0xAA;

/// Command Scripting template, indefinite length coding: `AE`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.2a: `AE 80 <C-APDU TLVs> 00 00`. The `80` after the tag is the
/// indefinite length; the inner C-APDU TLVs are still definite. Verified against `pySim/ota.py`
/// `ExpandedCmdIndef` (`Const(b'\xae')`, `Const(b'\x80')`, `Const(b'\x00\x00')`).
pub const CMD_INDEFINITE_TAG: u8 = 0xAE;

/// Response Scripting template, definite length coding: `AB`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.10. The value opens with the "number of executed command TLV
/// objects" TLV (table 5.11) and then carries the R-APDU TLVs and any of the error TLVs of
/// tables 5.12, 5.14 and 5.16. Verified against `pySim/ota.py` `ExpandedRemoteResp`
/// (`Const(b'\xab')`).
pub const RESP_DEFINITE_TAG: u8 = 0xAB;

/// Response Scripting template, indefinite length coding: `AF`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.10a: `AF 80 <items> 00 00`. **There is no number-of-executed
/// TLV in this coding**, so a decoder reports the number of returned R-APDU TLVs instead and says
/// which coding it saw. Verified against `pySim/ota.py` `ExpandedRemoteRespIndef`
/// (`Const(b'\xaf')`, `Const(b'\x80')`, `Const(b'\x00\x00')`, and `num_executed = None`).
pub const RESP_INDEFINITE_TAG: u8 = 0xAF;

/// "Number of executed command TLV objects" TLV identifier octet: `80`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.11: an integer with a definite BER length. Only the definite
/// Response Scripting template carries it. Verified against `pySim/ota.py` `ExpandedNumExecuted`
/// (`Const(b'\x80')`, `Prefixed(BerTlvLen, GreedyInteger())`).
pub const NUM_EXECUTED_TAG: u8 = 0x80;

/// Bad format TLV identifier octet: `90`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.12.
pub const BAD_FORMAT_TAG: u8 = 0x90;

/// Immediate Action Response TLV identifier octet: `81`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.14.
pub const IMMEDIATE_ACTION_TAG: u8 = 0x81;

/// Script Chaining Response TLV identifier octet: `83`. [V]
///
/// ETSI TS 102 226 V19.0.0 table 5.16.
pub const SCRIPT_CHAINING_TAG: u8 = 0x83;

/// The end-of-contents marker that closes an indefinite template: `00 00`. [V]
///
/// ETSI TS 102 226 V19.0.0 tables 5.2a (command) and 5.10a (response), each of which opens with
/// the indefinite marker `80`. Verified against `pySim/ota.py`, both `Const(b'\x80')` and
/// `Const(b'\x00\x00')`.
pub const EOC: [u8; 2] = [0x00, 0x00];

/// The indefinite length marker itself: `80`. [V]
///
/// TS 102 226 V19.0.0 tables 5.2a and 5.10a. It is a marker, not a length: inside a definite
/// template the same octet is a length and this crate's `tlv` module refuses it as one
/// (`tlv::Error::IndefiniteLength`), which is what keeps a truncated template from being answered.
pub const INDEFINITE: u8 = 0x80;

/// The status word that means the card truncated a C-APDU's response data. [V]
///
/// ETSI TS 102 226 V19.0.0 clause 5.2.1.1: the card sets `62F1` when it had to truncate the
/// response of a C-APDU and **shall terminate the processing of the command list**. So the
/// response is short *and* the commands after it never ran. Verified against `pySim/ota.py`
/// `decode_expanded_resp`, which carries the same note and tests every returned status word
/// against it.
pub const TRUNCATION_STATUS_WORD: [u8; 2] = [0x62, 0xF1];

/// The octets of a Response Packet header that follow RPL and RHL: `10`. [V]
///
/// TAR (3) + CNTR (5) + PCNTR (1) + response status (1), the header of the PoR Response Packet.
/// The CC/RC/DS that may follow is `RHL - 10` octets long, which is how `osmocom/pysim`
/// `pySim/ota.py` `OtaDialectSms.SmsResponsePacket` reads it (`'cc_rc'/Bytes(this.rhl - 10)`).
/// **[U]** The specification's own wording for RHL, and its clause number, were not read here;
/// the octet accounting is verified against the pySim parser and against the two worked PoR
/// examples in that file's `decode_resp` comment (`027100 000e 0a b00011 ...`, RPL `0x000e` with
/// 14 octets following it, and `027100 0016 12 b00011 ...`, RPL `0x0016` with 22 following).
/// Those same two examples are the whole of the evidence for the span RPL counts; see
/// [`Por::rpl`], where that span is marked **[U]** and where the refusal a mismatch causes is
/// stated.
pub const RESPONSE_HEADER_FIXED: usize = 10;

/// The number of octets of a Response Packet up to and including the response status: `13`. [V]
///
/// RPL (2) + RHL (1) + the ten of [`RESPONSE_HEADER_FIXED`], per the `SmsResponsePacket` field
/// order `rpl, rhl, tar, cntr, pcntr, response_status` in `pySim/ota.py`. A Response Packet
/// shorter than this cannot carry a response status at all.
pub const RESPONSE_PACKET_HEADER: usize = 13;

/// The 3GPP TS 31.115 SMS user data header that carries a PoR: `02 71 00`. [V]
///
/// UDHL `02`, then the Remote Packet Identifier information element, IEI `71` with length 0.
/// `pySim/ota.py` `decode_resp` opens with `if data[0] != 0x02: raise ValueError` and then
/// requires `udhd.has_ie(0x71)`; its first worked example is commented
/// `UDHL RPI IEDLa  RPL ...` / `02   71  00     000e ...`.
pub const SMS_UOH_RPI: [u8; 3] = [0x02, 0x71, 0x00];

/// Why a caller is told not to reach for the indefinite coding on SMS. [V]
///
/// ETSI TS 102 226 V19.0.0 recommends the indefinite length coding only for the HTTPS and CoAP
/// transports; over SMS the definite coding is the one to use. `pySim/ota.py` `BerTlvLength`
/// carries the same note ("only recommended for HTTPS/CoAP transport, not SMS") and refuses to
/// *build* an indefinite length because of it, leaving `encode_expanded_cmd`'s `indefinite`
/// branch to write it explicitly.
pub const INDEFINITE_CODING_NOTE: &str = "the indefinite length coding (TS 102 226 tables 5.2a \
and 5.10a) is only recommended for the HTTPS and CoAP transports, not for SMS; the definite \
coding is the default";

/// What this decoder does not do to a PoR. [V]
///
/// The secure data of a PoR may be ciphered under the TS 102 225 security layer and the header
/// may carry a CC or RC. Deciphering needs a key and verifying the CC/RC needs the same key, and
/// this command takes neither, so it reports the octets exactly as they arrived.
pub const NO_CRYPTO_NOTE: &str =
    "the ciphered part was not deciphered and no CC/RC was verified: this decoder takes no key";

/// What happens to a Proof-of-Response whose RPL does not add up. **[U]**
///
/// `decode_por` reads RPL as the count of the octets that follow RPL itself and requires it to
/// match exactly; that span is **[U]**, because the 3GPP TS 31.115 clause defining it was not
/// read. What the evidence is: the two worked PoR examples in the `decode_resp` comment of
/// `osmocom/pysim` `pySim/ota.py`, `027100 000e 0a b00011 0000000000 00 00 01 612f` (RPL
/// `0x000e`, 14 octets following) and `027100 0016 12 b00011 ...` (RPL `0x0016`, 22 following).
/// Requiring the match is a choice and not a derived fact, so a PoR whose RPL means something
/// else - counting itself, or only the header - is **refused** with [`Error::RpLLength`] instead
/// of being decoded on a guess. See [`Por::rpl`].
pub const RPL_SPAN_NOTE: &str = "RPL is read as the count of the octets that follow RPL itself, \
and `decode_por` requires it to match exactly, so a Proof-of-Response that disagrees is refused \
with RpLLength instead of being decoded on a guess. [U] the span RPL counts was not read out of \
TS 31.115; it rests on the two worked PoR examples in osmocom/pysim pySim/ota.py";

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Why a buffer is not the structure it was handed as.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input held no octets at all.
    #[error("empty input")]
    Empty,

    /// A Command Scripting template was asked for with no C-APDU in it.
    #[error("no C-APDU was given; a Command Scripting template carries one or more (TS 102 226 table 5.2)")]
    NoCommand,

    /// The first identifier octet is not a template tag this decoder accepts.
    #[error("not a Response Scripting template: identifier octet {tag:02X}, expected {expected} (definite length coding) or {indefinite} (indefinite length coding); TS 102 226 tables 5.10 and 5.10a")]
    WrongTemplate {
        /// The identifier octet that was found.
        tag: u8,
        /// `AB`, the definite length coding.
        expected: u8,
        /// `AF`, the indefinite length coding.
        indefinite: u8,
    },

    /// An indefinite template that does not carry the `80` length marker.
    #[error("the indefinite length Response Scripting template is not followed by the 80 length marker (TS 102 226 table 5.10a)")]
    MissingIndefiniteMarker,

    /// An item inside a template whose tag is none of the five this format defines.
    #[error("TLV {tag:02X} inside the Response Scripting template is not one of the tags TS 102 226 tables 5.11, 5.12, 5.14 and 5.16 define ({R_APDU_TAG:02X} R-APDU, {NUM_EXECUTED_TAG:02X} number executed, {BAD_FORMAT_TAG:02X} Bad format, {IMMEDIATE_ACTION_TAG:02X} Immediate Action Response, {SCRIPT_CHAINING_TAG:02X} Script Chaining Response)")]
    UnexpectedItem {
        /// The identifier octet that was found.
        tag: u8,
    },

    /// An indefinite template whose `00 00` end-of-contents marker is absent.
    #[error("the indefinite length Response Scripting template ends without the 00 00 end-of-contents marker (TS 102 226 table 5.10a)")]
    MissingEndOfContents,

    /// Octets remained after a complete template.
    #[error("{remaining} octet(s) after the end-of-contents marker at offset {at}")]
    TrailingData {
        /// Where the unconsumed octets start.
        at: usize,
        /// How many were left over.
        remaining: usize,
    },

    /// An R-APDU TLV whose value cannot hold a status word.
    #[error("an R-APDU TLV (tag {R_APDU_TAG:02X}) has a {length}-octet value; TS 102 223 clause 8.36 puts SW1 SW2 after the response data, so at least 2 are required")]
    ShortRApdu {
        /// The declared value length.
        length: usize,
    },

    /// An integer TLV with no octets, where every writer emits at least one.
    #[error("the number-of-executed TLV (TS 102 226 table 5.11) has an empty value; an integer needs at least one octet")]
    EmptyInteger,

    /// An integer too wide to be a count.
    #[error("the number-of-executed TLV carries {octets} octets, more than a count needs")]
    IntegerTooLarge {
        /// How many octets the integer occupies.
        octets: usize,
    },

    /// A PoR shorter than the header that carries its response status.
    #[error("the Response Packet is {have} octets; {RESPONSE_PACKET_HEADER} are needed to reach the response status (TS 31.115)")]
    ShortPor {
        /// How many octets arrived.
        have: usize,
    },

    /// RHL shorter than the fixed header it must cover.
    #[error("RHL {rhl} is below the {RESPONSE_HEADER_FIXED} octets of fixed Response Packet header it has to cover (TS 31.115)")]
    ShortRhl {
        /// The RHL value found.
        rhl: u8,
    },

    /// RPL does not describe what actually followed it.
    #[error("RPL says {rpl} octet(s) but {actual} follow it")]
    RpLLength {
        /// The RPL field.
        rpl: u16,
        /// How many octets followed.
        actual: usize,
    },

    /// The compact Remote Application structure is too short to hold a status word.
    #[error("the compact Remote Application response is {length} octets; TS 102 226 clause 5.1.2 needs 1 for the command count and 2 for the status word")]
    ShortCompact {
        /// How many octets arrived.
        length: usize,
    },

    /// RHL is at least as large as RPL, leaving nothing for the secure data.
    #[error("RHL {rhl} leaves no room for the secure data inside the {rpl} octets RPL declares (TS 31.115)")]
    RhlOverflow {
        /// The RPL field.
        rpl: u16,
        /// The RHL value found.
        rhl: u8,
    },

    /// The BER-TLV layer refused the bytes.
    #[error("{0}")]
    Tlv(#[from] tlv::Error),
}

// ---------------------------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------------------------

/// Which of the two length codings a template used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthCoding {
    /// One length octet (`81`/`82` for a long value), the value following it. TS 102 226 tables
    /// 5.2 and 5.10.
    Definite,
    /// `80`, the items, then `00 00`. TS 102 226 tables 5.2a and 5.10a.
    Indefinite,
}

impl LengthCoding {
    /// The name this coding is reported under.
    pub const fn name(self) -> &'static str {
        match self {
            LengthCoding::Definite => "definite",
            LengthCoding::Indefinite => "indefinite",
        }
    }
}

/// A one-octet code a specification names, kept as its number and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// The wire value.
    pub code: u8,
    /// The name the specification gives it, or `unassigned` for a value no table names.
    pub name: &'static str,
}

impl Code {
    fn json(&self) -> Value {
        json!({ "code": self.code, "name": self.name })
    }
}

/// The Bad format code (ETSI TS 102 226 V19.0.0 table 5.12). [V]
///
/// Verified against `pySim/ota.py` `ExpandedBadFormat`
/// (`Enum(Int8ub, unknown_tag=1, wrong_length=2, length_not_found=3)`).
pub fn bad_format_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("unknown_tag"),
        2 => Some("wrong_length"),
        3 => Some("length_not_found"),
        _ => None,
    }
}

/// The Immediate Action Response code (ETSI TS 102 226 V19.0.0 table 5.14). [V]
///
/// Verified against `pySim/ota.py` `ExpandedImmediateActionResp`
/// (`Enum(Int8ub, suspension_error=1)`).
pub fn immediate_action_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("suspension_error"),
        _ => None,
    }
}

/// The Script Chaining Response code (ETSI TS 102 226 V19.0.0 table 5.16). [V]
///
/// Verified against `pySim/ota.py` `ExpandedScriptChainingResp`
/// (`Enum(Int8ub, no_previous_script=1, not_supported=2, unable_to_process=3)`).
pub fn script_chaining_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("no_previous_script"),
        2 => Some("not_supported"),
        3 => Some("unable_to_process"),
        _ => None,
    }
}

/// The ResponseStatus code (ETSI TS 102 225 table 5; 3GPP TS 31.115 clause 4.2). [V]
///
/// `None` for a value no table names: an unknown code is reported as an extension with its
/// number kept, never guessed at. Verified against `pySim/ota.py` `ResponseStatus`
/// (`por_ok=0 ... actual_response_ussd=0x0C`).
pub fn response_status_name(code: u8) -> Option<&'static str> {
    match code {
        0x00 => Some("por_ok"),
        0x01 => Some("rc_cc_ds_failed"),
        0x02 => Some("cntr_low"),
        0x03 => Some("cntr_high"),
        0x04 => Some("cntr_blocked"),
        0x05 => Some("ciphering_error"),
        0x06 => Some("undefined_security_error"),
        0x07 => Some("insufficient_memory"),
        0x08 => Some("more_time_needed"),
        0x09 => Some("tar_unknown"),
        0x0A => Some("insufficient_security_level"),
        0x0B => Some("actual_response_sms_submit"),
        0x0C => Some("actual_response_ussd"),
        _ => None,
    }
}

fn hex_upper(b: &[u8]) -> String {
    hex::encode_upper(b)
}

/// The octets as text for a human renderer.
///
/// Card-supplied, so every character goes through [`contract::sanitize`]: an ESC byte, a bidi
/// override or a zero-width character a card chose is stripped before it reaches the terminal.
/// This is the one place in the module where card bytes become a `String`, and it exists only for
/// the human table; JSON keeps the octets as hex.
fn preview(bytes: &[u8]) -> String {
    let text = contract::sanitize(&String::from_utf8_lossy(bytes));
    if text.chars().count() <= PREVIEW_CHARS {
        return text;
    }
    // A binary response data field can be thousands of octets; the table shows enough of it to
    // recognise and says that it stopped, rather than filling the terminal.
    let mut out: String = text.chars().take(PREVIEW_CHARS).collect();
    out.push_str("...");
    out
}

/// How many characters of card-supplied text a human renderer shows. [V]
///
/// This module's choice, not a specification's: enough to recognise a string and to see that a
/// control sequence was there, short enough not to flood a terminal.
const PREVIEW_CHARS: usize = 256;

// ---------------------------------------------------------------------------------------------
// Part 1: the Command Scripting template encoder
// ---------------------------------------------------------------------------------------------

fn too_wide(octets: usize) -> Error {
    Error::Tlv(tlv::Error::LengthTooLarge {
        octets,
        max: 0xFFFF,
    })
}

/// Wraps `c_apdus` in a Command Scripting template.
///
/// ETSI TS 102 226 V19.0.0 clause 5.2.1. Each C-APDU is wrapped in a C-APDU TLV ([`C_APDU_TAG`],
/// TS 102 223 clause 8.35) with a definite BER length, and the TLVs become the value of the
/// template: tag [`CMD_DEFINITE_TAG`] (table 5.2), or tag [`CMD_INDEFINITE_TAG`] then the `80`
/// marker, the TLVs, then the `00 00` end-of-contents marker (table 5.2a).
///
/// The encoder **adds no Le and changes no C-APDU**: what is handed in goes on the wire unchanged,
/// because a command script is a list of commands, not one command with a length byte.
///
/// # Errors
///
/// [`Error::NoCommand`] when the list is empty, and [`Error::Tlv`] carrying
/// `tlv::Error::LengthTooLarge` when the assembled value would be wider than one APDU data field
/// can carry.
pub fn encode_command_scripting(
    c_apdus: &[Vec<u8>],
    coding: LengthCoding,
) -> Result<Vec<u8>, Error> {
    if c_apdus.is_empty() {
        return Err(Error::NoCommand);
    }
    let mut items = Vec::new();
    for c_apdu in c_apdus {
        let len = u16::try_from(c_apdu.len()).map_err(|_| too_wide(c_apdu.len()))?;
        items.push(C_APDU_TAG);
        items.extend(Length::new(len).encode());
        items.extend_from_slice(c_apdu);
    }

    let mut out = Vec::with_capacity(items.len() + 4);
    match coding {
        LengthCoding::Definite => {
            let total = u16::try_from(items.len()).map_err(|_| too_wide(items.len()))?;
            out.push(CMD_DEFINITE_TAG);
            out.extend(Length::new(total).encode());
            out.extend_from_slice(&items);
        }
        LengthCoding::Indefinite => {
            out.push(CMD_INDEFINITE_TAG);
            out.push(INDEFINITE);
            out.extend_from_slice(&items);
            out.extend_from_slice(&EOC);
        }
    }
    Ok(out)
}

/// One C-APDU of an encoded script, for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandItem {
    /// Position in the script, from 0.
    pub index: usize,
    /// The C-APDU exactly as it was given, upper-case hex.
    pub c_apdu: String,
    /// The same octets as a complete C-APDU TLV, so the wire bytes are checkable.
    pub tlv: String,
}

impl CommandItem {
    fn new(index: usize, c_apdu: &[u8]) -> Self {
        let mut tlv_bytes = vec![C_APDU_TAG];
        tlv_bytes.extend(Length::new(c_apdu.len() as u16).encode());
        tlv_bytes.extend_from_slice(c_apdu);
        Self {
            index,
            c_apdu: hex_upper(c_apdu),
            tlv: hex_upper(&tlv_bytes),
        }
    }

    fn json(&self) -> Value {
        json!({
            "index": self.index,
            "c_apdu": self.c_apdu,
            "c_apdu_tlv": self.tlv,
        })
    }
}

/// Everything an encode produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandScripting {
    /// Which length coding was used.
    pub length_coding: LengthCoding,
    /// The template identifier octet.
    pub template_tag: u8,
    /// One entry per C-APDU, in order.
    pub commands: Vec<CommandItem>,
    /// The whole template as upper-case hex.
    pub template: String,
}

impl CommandScripting {
    /// The one JSON object for this encode.
    pub fn json(&self) -> Value {
        json!({
            "card_touched": false,
            "length_coding": self.length_coding.name(),
            "template_tag": format!("{:02X}", self.template_tag),
            "command_count": self.commands.len(),
            "commands": self.commands.iter().map(CommandItem::json).collect::<Vec<_>>(),
            "template": self.template,
            "note": INDEFINITE_CODING_NOTE,
        })
    }

    /// The human table.
    pub fn render(&self) -> String {
        let mut out = format!(
            "Command Scripting template, {} length coding, tag {:02X} (TS 102 226 {})\n",
            self.length_coding.name(),
            self.template_tag,
            if self.template_tag == CMD_DEFINITE_TAG {
                "table 5.2"
            } else {
                "table 5.2a"
            }
        );
        for c in &self.commands {
            out.push_str(&format!("  {}  {}\n", c.index, c.c_apdu));
        }
        out.push_str(&format!("template {}\n", self.template));
        out.push_str(INDEFINITE_CODING_NOTE);
        out.push('\n');
        contract::sanitize_lines(&out)
    }
}

/// Encodes a script and keeps the parts the report needs.
///
/// # Errors
///
/// Whatever [`encode_command_scripting`] raises.
pub fn command_scripting(
    c_apdus: &[Vec<u8>],
    coding: LengthCoding,
) -> Result<CommandScripting, Error> {
    let template = encode_command_scripting(c_apdus, coding)?;
    let template_tag = match coding {
        LengthCoding::Definite => CMD_DEFINITE_TAG,
        LengthCoding::Indefinite => CMD_INDEFINITE_TAG,
    };
    Ok(CommandScripting {
        length_coding: coding,
        template_tag,
        commands: c_apdus
            .iter()
            .enumerate()
            .map(|(index, c)| CommandItem::new(index, c))
            .collect(),
        template: hex_upper(&template),
    })
}

// ---------------------------------------------------------------------------------------------
// Part 2: the Response Scripting template decoder
// ---------------------------------------------------------------------------------------------

/// One R-APDU TLV: the response data and the status word behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    /// Position among the returned R-APDU TLVs, from 0.
    pub index: usize,
    /// The R-APDU data, i.e. the TLV value without the trailing SW1 SW2 (TS 102 223 clause 8.36).
    pub response_data: String,
    /// SW1 SW2 as four upper-case hex digits.
    pub status_word: String,
    /// Whether this status word is the truncation status word, [`TRUNCATION_STATUS_WORD`].
    pub truncated: bool,
    /// The response data as text, through [`contract::sanitize`], for the human table only.
    pub text: String,
}

impl ResponseApdu {
    fn json(&self) -> Value {
        json!({
            "index": self.index,
            "response_data": self.response_data,
            "data_length": self.response_data.len() / 2,
            "status_word": self.status_word,
            "truncated": self.truncated,
        })
    }
}

/// A decoded Response Scripting template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseScripting {
    /// Which length coding the template used.
    pub length_coding: LengthCoding,
    /// The template identifier octet.
    pub template_tag: u8,
    /// The "number of executed command TLV objects" (TS 102 226 table 5.11) of the definite
    /// coding. `None` for the indefinite coding, which carries no such TLV; [`Self::executed`]
    /// is then the count of returned R-APDU TLVs.
    pub number_of_executed: Option<u64>,
    /// Every R-APDU TLV, in wire order.
    pub responses: Vec<ResponseApdu>,
    /// The Bad format TLV (table 5.12), when the card sent one.
    pub bad_format: Option<Code>,
    /// The Immediate Action Response TLV (table 5.14), when the card sent one.
    pub immediate_action: Option<Code>,
    /// The Script Chaining Response TLV (table 5.16), when the card sent one.
    pub script_chaining: Option<Code>,
    /// True when any R-APDU carries [`TRUNCATION_STATUS_WORD`]. See that constant: TS 102 226
    /// clause 5.2.1.1 has the card terminate the command list, so the commands after the
    /// truncating one never ran.
    pub truncated: bool,
}

impl ResponseScripting {
    /// The number the caller-facing field is filled from: the TLV of table 5.11 for the definite
    /// coding, the count of returned R-APDU TLVs for the indefinite one, which has no such TLV.
    pub fn executed(&self) -> u64 {
        match self.number_of_executed {
            Some(n) => n,
            None => self.responses.len() as u64,
        }
    }

    /// Where [`Self::executed`] came from, spelled out because the two are not the same claim.
    pub const fn executed_source(&self) -> &'static str {
        match self.number_of_executed {
            Some(_) => "number-of-executed TLV (TS 102 226 table 5.11)",
            None => "counted R-APDU TLVs: the indefinite length coding carries no number-of-executed TLV (TS 102 226 table 5.10a)",
        }
    }

    /// The status word of the last R-APDU, or `None` when the card returned none.
    pub fn last_status_word(&self) -> Option<&str> {
        self.responses.last().map(|r| r.status_word.as_str())
    }

    /// The response data of the last R-APDU, or an empty string when the card returned none.
    pub fn last_response_data(&self) -> &str {
        self.responses
            .last()
            .map_or("", |r| r.response_data.as_str())
    }

    fn code_json(v: &Option<Code>) -> Value {
        v.as_ref().map_or(Value::Null, Code::json)
    }

    /// The one JSON object for this decode.
    pub fn json(&self) -> Value {
        json!({
            "card_touched": false,
            "length_coding": self.length_coding.name(),
            "template_tag": format!("{:02X}", self.template_tag),
            "number_of_executed": self.executed(),
            "number_of_executed_declared": self.number_of_executed,
            "number_of_executed_source": self.executed_source(),
            "response_count": self.responses.len(),
            "responses": self.responses.iter().map(ResponseApdu::json).collect::<Vec<_>>(),
            "last_status_word": self.last_status_word(),
            "last_response_data": self.last_response_data(),
            "last_response_text": self.responses.last().map_or("", |r| r.text.as_str()),
            "truncated": self.truncated,
            "truncation_rule": "a 62F1 status word means the card truncated that C-APDU's response and, TS 102 226 clause 5.2.1.1, terminated the command list, so the commands after it never ran",
            "bad_format": Self::code_json(&self.bad_format),
            "immediate_action_response": Self::code_json(&self.immediate_action),
            "script_chaining_response": Self::code_json(&self.script_chaining),
        })
    }

    /// The human table.
    pub fn render(&self) -> String {
        let mut out = format!(
            "Response Scripting template, {} length coding, tag {:02X} (TS 102 226 {})\n",
            self.length_coding.name(),
            self.template_tag,
            if self.template_tag == RESP_DEFINITE_TAG {
                "table 5.10"
            } else {
                "table 5.10a"
            }
        );
        out.push_str(&format!("executed {}\n", self.executed()));
        out.push_str(&format!("source   {}\n", self.executed_source()));
        if self.responses.is_empty() {
            out.push_str("no R-APDU TLV was returned\n");
        }
        for r in &self.responses {
            out.push_str(&format!(
                "  {}  SW {}  data {}{}\n",
                r.index,
                r.status_word,
                if r.response_data.is_empty() {
                    "(none)"
                } else {
                    r.response_data.as_str()
                },
                if r.truncated {
                    "  TRUNCATED: 62F1, the command list was terminated here (TS 102 226 5.2.1.1)"
                } else {
                    ""
                }
            ));
            if !r.text.trim().is_empty() {
                out.push_str(&format!("     text {}\n", r.text));
            }
        }
        for (label, code, table) in [
            ("bad format", &self.bad_format, "table 5.12"),
            (
                "immediate action response",
                &self.immediate_action,
                "table 5.14",
            ),
            (
                "script chaining response",
                &self.script_chaining,
                "table 5.16",
            ),
        ] {
            if let Some(c) = code {
                out.push_str(&format!("{label} {} {} ({})\n", c.code, c.name, table));
            }
        }
        contract::sanitize_lines(&out)
    }
}

fn code_from(value: &[u8], names: fn(u8) -> Option<&'static str>) -> Code {
    // A one-octet value is what all three of these TLVs carry (TS 102 226 tables 5.12, 5.14 and
    // 5.16). A value of some other width cannot name a code, so it is reported unassigned with
    // the first octet kept rather than guessed into one of the named codes.
    let code = value.first().copied().unwrap_or_default();
    Code {
        code,
        name: names(code).unwrap_or("unassigned"),
    }
}

/// A non-negative BER-TLV integer as ISO/IEC 8825-1 defines one: big-endian base 256.
///
/// A leading `00` keeps the value positive, which is legal BER, so it is accepted. An empty
/// value is refused rather than read as zero: every writer emits at least one octet, and "this
/// is a count" is not something to assume.
fn be_integer(value: &[u8]) -> Result<u64, Error> {
    let Some((&first, rest)) = value.split_first() else {
        return Err(Error::EmptyInteger);
    };
    let mut n = u64::from(first);
    for &octet in rest {
        n = n
            .checked_mul(256)
            .and_then(|v| v.checked_add(u64::from(octet)))
            .ok_or(Error::IntegerTooLarge { octets: 8 })?;
    }
    Ok(n)
}

/// Decodes a Response Scripting template, in either length coding.
///
/// ETSI TS 102 226 V19.0.0 clause 5.2.2. The definite form (table 5.10) opens with the "number of
/// executed command TLV objects" TLV (table 5.11); the indefinite form (table 5.10a) carries no
/// such TLV, so [`ResponseScripting::executed`] counts the returned R-APDU TLVs instead and
/// [`ResponseScripting::executed_source`] says which of the two it is.
///
/// # Errors
///
/// [`Error::Empty`], [`Error::WrongTemplate`], [`Error::MissingIndefiniteMarker`],
/// [`Error::UnexpectedItem`], [`Error::MissingEndOfContents`], [`Error::TrailingData`],
/// [`Error::ShortRApdu`], [`Error::EmptyInteger`], [`Error::IntegerTooLarge`] and [`Error::Tlv`].
/// Anything this cannot place is an error: a decoder that answers a question instead of saying it
/// cannot is the failure mode `tlv.rs` was written to prevent.
pub fn decode_response_scripting(bytes: &[u8]) -> Result<ResponseScripting, Error> {
    let Some((&tag, after_tag)) = bytes.split_first() else {
        return Err(Error::Empty);
    };
    let (coding, template_tag, body) = match tag {
        RESP_DEFINITE_TAG => {
            let (atom, consumed) = Tlv::decode(bytes)?;
            if consumed != bytes.len() {
                return Err(Error::TrailingData {
                    at: consumed,
                    remaining: bytes.len() - consumed,
                });
            }
            (LengthCoding::Definite, RESP_DEFINITE_TAG, atom.value())
        }
        RESP_INDEFINITE_TAG => {
            if after_tag.first() != Some(&INDEFINITE) {
                return Err(Error::MissingIndefiniteMarker);
            }
            (
                LengthCoding::Indefinite,
                RESP_INDEFINITE_TAG,
                &after_tag[1..],
            )
        }
        other => {
            return Err(Error::WrongTemplate {
                tag: other,
                expected: RESP_DEFINITE_TAG,
                indefinite: RESP_INDEFINITE_TAG,
            })
        }
    };

    let mut out = ResponseScripting {
        length_coding: coding,
        template_tag,
        number_of_executed: None,
        responses: Vec::new(),
        bad_format: None,
        immediate_action: None,
        script_chaining: None,
        truncated: false,
    };

    let mut stream = tlv::Stream::new(body);
    loop {
        // The end-of-contents marker is where the item stream stops, so it is recognised at an
        // item boundary and never parsed as a tag. Looking for the last `00 00` in the body
        // instead would let response data that happens to contain those octets end the template.
        if coding == LengthCoding::Indefinite && stream.remaining().starts_with(&EOC) {
            break;
        }
        let Some(atom) = stream.next_atom()? else {
            break;
        };
        match atom.tag().octet() {
            R_APDU_TAG => {
                let value = atom.value();
                if value.len() < 2 {
                    return Err(Error::ShortRApdu {
                        length: value.len(),
                    });
                }
                let (data, sw) = value.split_at(value.len() - 2);
                let sw = [sw[0], sw[1]];
                let truncated = sw == TRUNCATION_STATUS_WORD;
                out.truncated |= truncated;
                out.responses.push(ResponseApdu {
                    index: out.responses.len(),
                    response_data: hex_upper(data),
                    status_word: hex_upper(&sw),
                    truncated,
                    text: preview(data),
                });
            }
            NUM_EXECUTED_TAG => out.number_of_executed = Some(be_integer(atom.value())?),
            BAD_FORMAT_TAG => out.bad_format = Some(code_from(atom.value(), bad_format_name)),
            IMMEDIATE_ACTION_TAG => {
                out.immediate_action = Some(code_from(atom.value(), immediate_action_name));
            }
            SCRIPT_CHAINING_TAG => {
                out.script_chaining = Some(code_from(atom.value(), script_chaining_name));
            }
            other => return Err(Error::UnexpectedItem { tag: other }),
        }
    }

    if coding == LengthCoding::Indefinite {
        let rest = stream.remaining();
        if rest.len() < EOC.len() {
            return Err(Error::MissingEndOfContents);
        }
        if rest[..EOC.len()] != EOC {
            return Err(Error::MissingEndOfContents);
        }
        if rest.len() > EOC.len() {
            return Err(Error::TrailingData {
                at: 1 + 1 + stream.offset() + EOC.len(),
                remaining: rest.len() - EOC.len(),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Part 3: the Proof-of-Response Response Packet
// ---------------------------------------------------------------------------------------------

/// Which Remote Application structure the secure data of a PoR is read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteFormat {
    /// ETSI TS 102 226 V19.0.0 clause 5.1.2: one octet of command count, two of status word, the
    /// rest is the response data of the last command.
    Compact,
    /// ETSI TS 102 226 V19.0.0 clause 5.2.2: a Response Scripting template, decoded by
    /// [`decode_response_scripting`].
    Expanded,
}

impl RemoteFormat {
    /// The name this format is reported under.
    pub const fn name(self) -> &'static str {
        match self {
            RemoteFormat::Compact => "compact",
            RemoteFormat::Expanded => "expanded",
        }
    }
}

/// The compact Remote Application response (ETSI TS 102 226 V19.0.0 clause 5.1.2). [V]
///
/// Verified against `osmocom/pysim` `pySim/ota.py` `CompactRemoteResp`
/// (`'number_of_commands'/Int8ub, 'last_status_word'/HexAdapter(Bytes(2)),
/// 'last_response_data'/HexAdapter(GreedyBytes)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactRemote {
    /// The number of commands the card says it executed.
    pub number_of_commands: u8,
    /// SW1 SW2 of the last command, four upper-case hex digits.
    pub last_status_word: String,
    /// The response data of the last command.
    pub last_response_data: String,
    /// That data as text, through [`contract::sanitize`], for the human table only.
    pub text: String,
}

impl CompactRemote {
    /// The one JSON object for a compact Remote Application response.
    pub fn json(&self) -> Value {
        json!({
            "format": "compact",
            "number_of_commands": self.number_of_commands,
            "last_status_word": self.last_status_word,
            "last_response_data": self.last_response_data,
        })
    }

    fn render(&self) -> String {
        let mut out = format!(
            "Remote Application response, compact (TS 102 226 clause 5.1.2)\ncommands {}\nstatus  {}\ndata    {}\n",
            self.number_of_commands,
            self.last_status_word,
            if self.last_response_data.is_empty() {
                "(none)"
            } else {
                self.last_response_data.as_str()
            }
        );
        if !self.text.trim().is_empty() {
            out.push_str(&format!("text    {}\n", self.text));
        }
        out
    }
}

/// The Remote Application structure a PoR carried, in whichever format it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    /// The compact structure of clause 5.1.2.
    Compact(CompactRemote),
    /// The expanded Response Scripting template of clause 5.2.2.
    Expanded(ResponseScripting),
}

impl Remote {
    /// The one JSON object for a Remote Application response, whichever format it is.
    pub fn json(&self) -> Value {
        match self {
            Remote::Compact(c) => c.json(),
            Remote::Expanded(e) => {
                let mut v = e.json();
                if let Value::Object(m) = &mut v {
                    m.insert("format".to_owned(), Value::String("expanded".to_owned()));
                }
                v
            }
        }
    }

    fn render(&self) -> String {
        match self {
            Remote::Compact(c) => c.render(),
            Remote::Expanded(e) => e.render(),
        }
    }
}

/// A decoded PoR Response Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Por {
    /// The TS 31.115 SMS user data header that preceded the packet, upper-case hex, or `None`
    /// when the input was the bare Response Packet.
    pub uoh: Option<String>,
    /// RPL, the number of octets the Response Packet takes after RPL itself. **[U]**
    ///
    /// The field order `rpl, rhl, tar, cntr, pcntr, response_status` is [V] against
    /// `osmocom/pysim` `pySim/ota.py` `SmsResponsePacket`. The **span** RPL counts is **[U]**,
    /// because the 3GPP TS 31.115 clause that defines it was not read here. The evidence is the
    /// two worked PoR examples in that file's `decode_resp` comment: `027100 000e 0a b00011
    /// 0000000000 00 00 01 612f` carries RPL `0x000e` with 14 octets following it, and `027100
    /// 0016 12 b00011 ...` carries RPL `0x0016` with 22 following it. Both count the octets
    /// *after* RPL, which is what [`decode_por`] requires.
    ///
    /// Requiring exactly that is a **choice**, not something those two examples prove. Refusing
    /// beats guessing, so a card whose RPL counts RPL itself, or only the header, has its
    /// Proof-of-Response refused with [`Error::RpLLength`] rather than decoded on a bad span.
    /// There is deliberately no permissive fallback.
    pub rpl: u16,
    /// RHL, which covers the ten header octets after RPL/RHL plus any CC/RC/DS.
    pub rhl: u8,
    /// The three-octet TAR as six upper-case hex digits.
    pub tar: String,
    /// The five-octet counter as ten upper-case hex digits.
    pub cntr: String,
    /// PCNTR, the padding counter.
    pub pcntr: u8,
    /// The ResponseStatus code (TS 102 225 table 5), by name and by number. A code no table names
    /// is reported as `unassigned` with the number kept.
    pub response_status: Code,
    /// The CC/RC/DS octets, `RHL - 10` of them, as upper-case hex.
    pub cc_rc: String,
    /// The secure data, as upper-case hex.
    pub secured_data: String,
    /// The secure data as text, through [`contract::sanitize`], for the human table only.
    pub secured_text: String,
    /// The Remote Application structure, present only when the response status is `por_ok` and
    /// the secure data is not empty. See [`Self::remote_absent_reason`] when it is `None`.
    pub remote: Option<Remote>,
}

impl Por {
    /// Why there is no Remote Application structure, when there is none. `None` when there is one.
    pub fn remote_absent_reason(&self) -> Option<&'static str> {
        if self.remote.is_some() {
            return None;
        }
        if self.response_status.code != 0 {
            return Some(
                "the response status is not por_ok, so TS 102 225 carries no Remote Application \
structure for this Proof-of-Response",
            );
        }
        Some("the secure data is empty, so there is no Remote Application structure to decode")
    }

    /// The one JSON object for a decoded Proof-of-Response.
    pub fn json(&self) -> Value {
        json!({
            "card_touched": false,
            "uoh": self.uoh,
            "uoh_note": "02 71 00 is the TS 31.115 SMS user data header: UDHL 02 and the Remote Packet Identifier IE 71 of length 0. Absent means the input was the bare Response Packet.",
            "rpl": self.rpl,
            "rhl": self.rhl,
            "tar": self.tar,
            "cntr": self.cntr,
            "pcntr": self.pcntr,
            "response_status": self.response_status.json(),
            "cc_rc": self.cc_rc,
            "cc_rc_length": self.cc_rc.len() / 2,
            "secured_data": self.secured_data,
            "secured_data_length": self.secured_data.len() / 2,
            "secured_data_text": self.secured_text,
            "remote": self.remote.as_ref().map(Remote::json),
            "remote_absent_reason": self.remote_absent_reason(),
            "rpl_note": RPL_SPAN_NOTE,
            "note": NO_CRYPTO_NOTE,
        })
    }

    /// The human table.
    pub fn render(&self) -> String {
        let mut out =
            String::from("Proof-of-Response Response Packet (TS 31.115, TS 102 225 table 5)\n");
        match &self.uoh {
            Some(u) => out.push_str(&format!("uoh      {u} (UDHL 02, RPI IE 71 length 0)\n")),
            None => out.push_str("uoh      none: the bare Response Packet was given\n"),
        }
        out.push_str(&format!("rpl      {}\n", self.rpl));
        out.push_str(&format!("rhl      {}\n", self.rhl));
        out.push_str(&format!("tar      {}\n", self.tar));
        out.push_str(&format!("cntr     {}\n", self.cntr));
        out.push_str(&format!("pcntr    {}\n", self.pcntr));
        out.push_str(&format!(
            "status   {} {} (TS 102 225 table 5)\n",
            self.response_status.code, self.response_status.name
        ));
        out.push_str(&format!(
            "cc/rc    {} ({} octet(s))\n",
            if self.cc_rc.is_empty() {
                "(none)"
            } else {
                self.cc_rc.as_str()
            },
            self.cc_rc.len() / 2
        ));
        out.push_str(&format!("secure   {}\n", self.secured_data));
        if !self.secured_text.trim().is_empty() {
            out.push_str(&format!("secure text {}\n", self.secured_text));
        }
        match &self.remote {
            Some(r) => out.push_str(&r.render()),
            None => {
                if let Some(why) = self.remote_absent_reason() {
                    out.push_str(&format!("remote   none: {why}\n"));
                }
            }
        }
        out.push_str(NO_CRYPTO_NOTE);
        out.push('\n');
        out.push_str(RPL_SPAN_NOTE);
        out.push('\n');
        contract::sanitize_lines(&out)
    }
}

/// Decodes a PoR Response Packet, with or without the SMS user data header in front of it.
///
/// The input is either the bare Response Packet or the TS 31.115 user data header
/// [`SMS_UOH_RPI`] (`02 71 00`) followed by it; which one arrived is reported in
/// [`Por::uoh`] rather than guessed. The header layout is RPL (2), RHL (1), TAR (3), CNTR (5),
/// PCNTR (1) and the response status (1), then `RHL - 10` octets of CC/RC/DS, then the secure
/// data - the field order of `osmocom/pysim` `pySim/ota.py` `OtaDialectSms.SmsResponsePacket`.
///
/// The Remote Application structure is decoded **only** when the response status is `por_ok` and
/// the secure data is not empty, because only then is there one: TS 102 225 carries no response
/// data for any other status. It is read as [`RemoteFormat::Compact`] by default, which is what
/// the secure data holds when the command script used the compact format.
///
/// # Errors
///
/// [`Error::ShortPor`], [`Error::RpLLength`], [`Error::ShortRhl`], [`Error::RhlOverflow`],
/// [`Error::ShortCompact`] and, for `--remote-format expanded`, whatever
/// [`decode_response_scripting`] raises on the secure data.
pub fn decode_por(bytes: &[u8], remote_format: RemoteFormat) -> Result<Por, Error> {
    let (uoh, body) = match bytes.strip_prefix(&SMS_UOH_RPI) {
        Some(rest) => (Some(hex_upper(&SMS_UOH_RPI)), rest),
        None => (None, bytes),
    };
    if body.len() < RESPONSE_PACKET_HEADER {
        return Err(Error::ShortPor { have: body.len() });
    }

    let rpl = u16::from_be_bytes([body[0], body[1]]);
    let actual = body.len() - 2;
    if usize::from(rpl) != actual {
        return Err(Error::RpLLength { rpl, actual });
    }
    let rhl = body[2];
    if usize::from(rhl) < RESPONSE_HEADER_FIXED {
        return Err(Error::ShortRhl { rhl });
    }
    let secured_len = usize::from(rpl)
        .checked_sub(usize::from(rhl))
        .and_then(|n| n.checked_sub(1))
        .ok_or(Error::RhlOverflow { rpl, rhl })?;

    let cc_len = usize::from(rhl) - RESPONSE_HEADER_FIXED;
    let cc_rc = &body[RESPONSE_PACKET_HEADER..RESPONSE_PACKET_HEADER + cc_len];
    let secured = &body[RESPONSE_PACKET_HEADER + cc_len..];
    debug_assert_eq!(secured.len(), secured_len);

    let sts = body[RESPONSE_PACKET_HEADER - 1];
    let remote = if sts == 0 && !secured.is_empty() {
        Some(match remote_format {
            RemoteFormat::Compact => {
                if secured.len() < 3 {
                    return Err(Error::ShortCompact {
                        length: secured.len(),
                    });
                }
                Remote::Compact(CompactRemote {
                    number_of_commands: secured[0],
                    last_status_word: hex_upper(&secured[1..3]),
                    last_response_data: hex_upper(&secured[3..]),
                    text: preview(&secured[3..]),
                })
            }
            RemoteFormat::Expanded => Remote::Expanded(decode_response_scripting(secured)?),
        })
    } else {
        None
    };

    Ok(Por {
        uoh,
        rpl,
        rhl,
        tar: hex_upper(&body[3..6]),
        cntr: hex_upper(&body[6..11]),
        pcntr: body[11],
        response_status: Code {
            code: sts,
            name: response_status_name(sts).unwrap_or("unassigned"),
        },
        cc_rc: hex_upper(cc_rc),
        secured_data: hex_upper(secured),
        secured_text: preview(secured),
        remote,
    })
}
