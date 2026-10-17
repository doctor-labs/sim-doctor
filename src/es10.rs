//! ES10x, the eUICC-side local interface of SGP.22: the generic STORE DATA
//! transport, and the request encoders and response decoders of ES10b and
//! ES10c. Library only: **nothing here sends a byte unless a caller hands it
//! a session**, and no command in this module is ever issued by the CLI.
//!
//! **Owns.** STORE DATA segmentation ([`blocks`], [`bpp_blocks`]), sending
//! and response reassembly through [`crate::session::send`] ([`store_data`],
//! [`load_bound_profile_package`]), the request encoders, and the typed
//! response decoders.
//!
//! **Does not own.** Signature or certificate checking, BPP construction or
//! protection (that is [`crate::scp03t`]), the ES9+ HTTPS half, or any
//! decision to talk to a card. The live card used during development is a
//! plain operator USIM, not an eUICC, so every test here is encode/decode
//! only.
//!
//! **Why this does not use [`crate::tlv`].** [`crate::tlv`] reads a one-octet
//! tag by design. ES10x payloads are full of two-octet tags (`BF 2D`,
//! `9F 70`), so this module carries its own small BER reader and writer with
//! tags up to four octets.
//!
//! # Provenance
//!
//! Every clause below is `[V] SGP.22 v2.5` checked against the public PDF
//! (`https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/05/SGP.22-v2.5.pdf`,
//! page numbers per the PDF) on 2026-10-07. The earlier "section numbers
//! come from euicc-rsp" provenance note on issue #18 is superseded by that
//! primary check (blocker 2 in AGENTS.md section 6).
//!
//! | Function | Clause | Request tag | Response tag |
//! |---|---|---|---|
//! | STORE DATA transport | 5.7.2 (Tables 47, 48), 2.5.5 | | |
//! | PrepareDownload | 5.7.5 | `BF21` | `BF21` |
//! | LoadBoundProfilePackage | 5.7.6, 2.5.5 | BPP segments | none or `BF37` |
//! | GetEUICCChallenge | 5.7.7 | `BF2E` | `BF2E` |
//! | GetEUICCInfo (EUICCInfo1, EUICCInfo2) | 5.7.8 | `BF20`, `BF22` | `BF20`, `BF22` |
//! | AuthenticateServer | 5.7.13 | `BF38` | `BF38` |
//! | CancelSession | 5.7.14 | `BF41` | `BF41` |
//! | GetEuiccConfiguredAddresses (ES10a) | 5.7.3 | `BF3C` | `BF3C` |
//! | SetDefaultDpAddress (ES10a) | 5.7.4 | `BF3F` | `BF3F` |
//! | GetProfilesInfo | 5.7.15 | `BF2D` | `BF2D` |
//! | EnableProfile | 5.7.16 | `BF31` | `BF31` |
//! | DisableProfile | 5.7.17 | `BF32` | `BF32` |
//! | DeleteProfile | 5.7.18 | `BF33` | `BF33` |
//! | SetNickname | 5.7.21 | `BF29` | `BF29` |
//! | RemoveNotificationFromList | 5.7.12 | `BF30` | `BF30` |
//! | eUICCMemoryReset | 5.7.19 | `BF34` | `BF34` |
//!
//! # SGP.32 (IoT eUICC), issue #229: two more ES10b functions
//!
//! | Function | Clause | Request tag | Response tag |
//! |---|---|---|---|
//! | GetCerts | 5.9.10 (`[U]`) | `BF56` | `BF56` |
//! | GetEimConfigurationData | 5.9.18 (`[U]`) | `BF55` | `BF55` |
//!
//! **This pair rests on pySim alone, and the two clause numbers are `[U]`.**
//! SGP.22 v2.5 above was checked against its PDF; SGP.32 was **not reachable
//! offline** while issue #229 was built, so no page of it was read. Every
//! tag and every enumeration value below is `[V]` against osmocom/pysim
//! (`master`, the 3c437d4 of AGENTS.md section 5.1), file `pySim/euicc.py`:
//! `GetCertsReq` `BF56` (line 318) and `GetCertsResp` `BF56` (line 326),
//! `EumCertificate` `A5` (line 319) and `EuiccCertificate` `A6` (line 322),
//! `GetCertsError` `81` with `invalidCiPKId=1` and `undefinedError=127`
//! (lines 324-325), `GetEimConfigurationData` `BF55` (line 349) over
//! `EimConfigurationDataSeq` `A0` (line 348) and the fields inside it:
//! `EimId` `80`, `EimFqdn` `81`, `EimIdType` `82`, `CounterValue` `83`,
//! `AssociationToken` `84`, `EimSupportedProtocol` `87` (lines 330-342),
//! `eimIdTypeOid=1` / `eimIdTypeFqdn=2` / `eimIdTypeProprietary=3`
//! (line 335) and `eimRetrieveHttps=0`, `eimRetrieveCoaps=1`,
//! `eimInjectHttps=2`, `eimInjectCoaps=3`, `eimProprietary=4`
//! (lines 341-342).
//!
//! Two gaps in that reference, both carried as `[U]` in the code below. The
//! clause numbers are pySim's own comment (lines 317 and 329), not the
//! document. And `counterValue` / `associationToken` are read by pySim with
//! `Asn1DerInteger()` (lines 339-340, from `osmocom.construct`, which is not
//! on this machine), so what is enforced here is the strict DER INTEGER rule
//! of X.690 clause 8.3 rather than an observation of pySim's output. The
//! certificate TLVs stay opaque: `GreedyBytes` at `pySim/euicc.py` lines 320
//! and 323, and this crate parses X.509 elsewhere, so a certificate is
//! reported by its length and its bytes.
//!
//! One further discrepancy, and the one that shapes the decoder: pySim's
//! `EimConfigurationData` is itself a tag-`80` TLV nested inside its `A0`
//! (`pySim/euicc.py` line 344, inside `EimConfigurationDataSeq` line 347),
//! so the wire form pySim decodes carries one level more nesting than
//! SGP.32's `SEQUENCE` tag alone accounts for:
//!
//! ```text
//! BF55 { A0 { 80 { 80 <eimId> 81 <eimFqdn> 82 <idType> ... } } }
//! ```
//!
//! SGP.32 was not reachable offline, so which of the two shapes a card
//! answers with could not be settled from the document. The reference the
//! issue names is the wrapped one, so
//! [`decode_get_eim_configuration_data`] reads it as primary, still
//! accepts the fields sitting directly in the `A0`, and reports which one
//! it saw in [`EimConfigurationData::shape`] rather than guessing.
//!
//! Where issue #18 differs from the spec: the issue says "`<=255` data bytes"
//! under 5.7.2, but Table 47 gives Lc as "Var." and the 255-byte rule is
//! stated in 5.7.6 and 2.5.5 (blocks of 255 bytes, a last block that MAY be
//! shorter). The numbers are otherwise as the issue lists them.
//!
//! # Tagging
//!
//! Annex H is `AUTOMATIC TAGS`. A CHOICE or SEQUENCE none of whose members is
//! tagged gets context tags `[0]`, `[1]`, ... on its members, which is why
//! `ProfileInfoListResponse` carries its list under `A0` and its error under
//! `81`, and why `CancelSessionRequest` is `80 <transactionId> 81 <reason>`.
//! Where a member is tagged explicitly (`[APPLICATION 55]`, `[0]`), the
//! untagged ones keep their universal tags (`30`, `04`, `02`). The expected
//! bytes in the tests were produced by an ASN.1 compiler over the module text,
//! not by this code.
//!
//! # Not implemented
//!
//! The "alternative case 3" form of EnableProfile and DeleteProfile (P1 `90`,
//! no response data, 5.7.16 and 5.7.18) is the only ES10x function still
//! missing; SetDefaultDpAddress (5.7.4) arrived with issue #227, and
//! HandleNotification is ES9+, in [`crate::es9`]. Decoders preserve tags they
//! do not know in `unknown` fields instead of dropping them.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "es10";

use std::fmt;

use crate::apdu::{Command, Header, Le};
use crate::session::{self, Exchange, Policy};
use crate::transport::CardSession;

/// STORE DATA, the one instruction every ES10x function rides on
/// ([SGP.22 v2.5 §5.7.2], Table 47).
pub const INS_STORE_DATA: u8 = 0xE2;

/// P1 of a STORE DATA block with more blocks to follow: BER-TLV data, case 4
/// ([SGP.22 v2.5 §5.7.2], Table 48).
pub const P1_MORE_BLOCKS: u8 = 0x11;

/// P1 of the last STORE DATA block ([SGP.22 v2.5 §5.7.2], Table 48).
pub const P1_LAST_BLOCK: u8 = 0x91;

/// Largest data field of one STORE DATA block
/// ([SGP.22 v2.5 §5.7.6] and §2.5.5: "blocks of 255 bytes or less").
pub const MAX_BLOCK_DATA: usize = 255;

/// Whether `cla` is one STORE DATA may use: `80`-`83` or `C0`-`CF`
/// ([SGP.22 v2.5 §5.7.2], Table 47).
pub const fn is_valid_class(cla: u8) -> bool {
    matches!(cla, 0x80..=0x83 | 0xC0..=0xCF)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A request that cannot be put on the wire.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// A field is outside the size its ASN.1 type allows.
    #[error("{field} must be {min} to {max} bytes, got {got}")]
    FieldLength {
        /// The ASN.1 field name.
        field: &'static str,
        /// Smallest allowed length.
        min: usize,
        /// Largest allowed length.
        max: usize,
        /// The length supplied.
        got: usize,
    },
    /// The class byte is not `80`-`83` or `C0`-`CF`.
    #[error("STORE DATA class {0:02X} is not 80-83 or C0-CF")]
    BadClass(u8),
    /// STORE DATA with no data.
    #[error("a STORE DATA block needs at least one data byte")]
    EmptyData,
    /// P2 is one byte, so one segment can hold at most 256 blocks.
    #[error("{bytes} bytes need {blocks} blocks, more than the 256 P2 can number")]
    TooManyBlocks {
        /// Bytes in the segment.
        bytes: usize,
        /// Blocks it would take.
        blocks: usize,
    },
}

/// Everything that can go wrong sending a STORE DATA sequence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The data could not be segmented.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// The exchange failed below the level this module reasons about.
    #[error(transparent)]
    Session(#[from] session::Error),
}

/// A response that is not what the function's ASN.1 says.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The data ended inside a field.
    #[error("response ends inside a field: needed {needed} more bytes, {available} left")]
    Truncated {
        /// Bytes the field still wanted.
        needed: usize,
        /// Bytes left.
        available: usize,
    },
    /// A length of `80` (indefinite), or one wider than three octets.
    #[error("unsupported BER length form {0:02X}")]
    UnsupportedLength(u8),
    /// A tag wider than four octets.
    #[error("tag wider than four octets")]
    UnsupportedTag,
    /// Bytes after the one TLV the response consists of.
    #[error("{0} bytes of trailing data")]
    TrailingData(usize),
    /// The outer tag is not the function's response tag.
    #[error("expected tag {expected:X}, found {found:X}")]
    WrongTag {
        /// The tag the function defines.
        expected: u32,
        /// The tag found.
        found: u32,
    },
    /// A tag that is not allowed at this position.
    #[error("unexpected tag {found:X} in {context}")]
    UnexpectedTag {
        /// Where it was found.
        context: &'static str,
        /// The tag found.
        found: u32,
    },
    /// A mandatory field is absent.
    #[error("mandatory field {0} is missing")]
    MissingField(&'static str),
    /// A field has a size its ASN.1 type does not allow.
    #[error("{field} must be {expected} bytes, got {got}")]
    BadLength {
        /// The ASN.1 field name.
        field: &'static str,
        /// What the type requires.
        expected: &'static str,
        /// The length found.
        got: usize,
    },
    /// A UTF8String that is not UTF-8.
    #[error("{0} is not valid UTF-8")]
    BadUtf8(&'static str),
    /// A BIT STRING whose unused-bits octet is impossible.
    #[error("{0} is not a valid BIT STRING")]
    BadBitString(&'static str),
    /// A field that must hold a DER INTEGER holds another type.
    #[error("{field} is not a DER INTEGER (identifier octet {found:02X})")]
    NotAnInteger {
        /// The ASN.1 field name.
        field: &'static str,
        /// The identifier octet found.
        found: u8,
    },
    /// A DER INTEGER that is negative, or carries no value octet at all.
    #[error("{field} is not a non-negative DER INTEGER with value octets")]
    NegativeInteger {
        /// The ASN.1 field name.
        field: &'static str,
    },
    /// A DER INTEGER whose value is not written in the shortest form.
    #[error("{field} is a DER INTEGER whose value octets are not minimal")]
    NonMinimalInteger {
        /// The ASN.1 field name.
        field: &'static str,
    },
    /// A DER INTEGER wider than the 64 bits this reports.
    #[error("{field} is a DER INTEGER wider than the 64 bits reported here")]
    IntegerTooWide {
        /// The ASN.1 field name.
        field: &'static str,
    },
    /// Bytes that are not one strictly encoded DER value.
    #[error("{field} is not a strict DER encoding: {message}")]
    BadDerEncoding {
        /// The ASN.1 field name.
        field: &'static str,
        /// What the strict decoder said.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// STORE DATA segmentation and sending
// ---------------------------------------------------------------------------

/// Cuts one data object into STORE DATA blocks: 255 bytes each, a last block
/// that may be shorter, P1 `11` on every block but the last and `91` on the
/// last, P2 counting from 0 ([SGP.22 v2.5 §5.7.2] Tables 47 and 48, §5.7.6,
/// §2.5.5). Every block is case 4 with Le `00`, as Table 47 gives.
///
/// A data object of exactly 255 bytes is one block with P1 `91`, not a full
/// block followed by an empty one.
///
/// # Errors
///
/// [`EncodeError::BadClass`], [`EncodeError::EmptyData`], and
/// [`EncodeError::TooManyBlocks`] above 256 blocks (65280 bytes).
pub fn blocks(cla: u8, data: &[u8]) -> Result<Vec<Command>, EncodeError> {
    blocks_sized(cla, data, MAX_BLOCK_DATA)
}

/// [`blocks`] with a smaller data field per block, for a reader or card that
/// cannot take 255 bytes at once (lpac's `--apdu-max`-style segment size).
/// `max` is the most data bytes in one block; the spec's own limit stays the
/// ceiling ([`MAX_BLOCK_DATA`]).
///
/// # Errors
///
/// [`EncodeError::FieldLength`] when `max` is 0 or above 255, otherwise as
/// [`blocks`] (a small `max` reaches the 256-block limit sooner).
pub fn blocks_sized(cla: u8, data: &[u8], max: usize) -> Result<Vec<Command>, EncodeError> {
    if !(1..=MAX_BLOCK_DATA).contains(&max) {
        return Err(EncodeError::FieldLength {
            field: "maxBlockData",
            min: 1,
            max: MAX_BLOCK_DATA,
            got: max,
        });
    }
    if !is_valid_class(cla) {
        return Err(EncodeError::BadClass(cla));
    }
    if data.is_empty() {
        return Err(EncodeError::EmptyData);
    }
    let count = data.len().div_ceil(max);
    if count > 256 {
        return Err(EncodeError::TooManyBlocks {
            bytes: data.len(),
            blocks: count,
        });
    }
    Ok(data
        .chunks(max)
        .enumerate()
        .map(|(index, chunk)| {
            let p1 = if index + 1 == count {
                P1_LAST_BLOCK
            } else {
                P1_MORE_BLOCKS
            };
            // `index` < 256 was checked above.
            let header = Header::new(cla, INS_STORE_DATA, p1, index as u8);
            Command::case4(header, chunk, Le::Short(0x00))
        })
        .collect())
}

/// Cuts a Bound Profile Package, already split into segments by the caller,
/// into STORE DATA blocks: each segment is its own sequence, ending in P1
/// `91`, with the block number reset to 0 at its start ([SGP.22 v2.5 §5.7.6],
/// §2.5.5). Where the segment boundaries fall is the caller's job (and
/// [`crate::scp03t`]'s); this does not parse the BPP.
///
/// # Errors
///
/// Whatever [`blocks`] raises for any segment.
pub fn bpp_blocks<T: AsRef<[u8]>>(
    cla: u8,
    segments: &[T],
) -> Result<Vec<Vec<Command>>, EncodeError> {
    segments
        .iter()
        .map(|segment| blocks(cla, segment.as_ref()))
        .collect()
}

/// What sending one data object as a STORE DATA sequence did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// One logical exchange per block sent, in order. Each already includes
    /// the card's `61 xx` GET RESPONSE follow-ups.
    pub exchanges: Vec<Exchange>,
    /// Whether every block was sent. `false` means the card did not answer a
    /// non-final block with normal processing and the rest were **not** sent.
    pub complete: bool,
}

impl Sent {
    /// The response data of the last block sent. Intermediate blocks carry
    /// none ([SGP.22 v2.5 §5.7.6]); the last block carries the whole
    /// function response, reassembled across `61 xx` by [`session::send`].
    pub fn data(&self) -> &[u8] {
        self.exchanges.last().map_or(&[], Exchange::data)
    }
}

/// Sends one data object as a STORE DATA sequence and returns what the card
/// said. Nothing is retried; a non-final block the card does not accept with
/// normal processing (`90 00` or `91 xx`) ends the sequence early.
///
/// `policy.get_response_class` should match the channel the card is on;
/// the default is the GSM class, which an ISD-R on a logical channel will not
/// answer. This function does no card-safety checking: do not call it on a
/// card that is not an eUICC.
///
/// # Errors
///
/// [`Error::Encode`] from [`blocks`], [`Error::Session`] from
/// [`session::send`].
pub fn store_data<S: CardSession + ?Sized>(
    session: &mut S,
    cla: u8,
    data: &[u8],
    policy: &Policy,
) -> Result<Sent, Error> {
    send_blocks(session, blocks(cla, data)?, policy)
}

/// [`store_data`] with at most `max` data bytes per block ([`blocks_sized`]).
///
/// # Errors
///
/// As [`store_data`], plus [`blocks_sized`]'s `max` check.
pub fn store_data_sized<S: CardSession + ?Sized>(
    session: &mut S,
    cla: u8,
    data: &[u8],
    max: usize,
    policy: &Policy,
) -> Result<Sent, Error> {
    send_blocks(session, blocks_sized(cla, data, max)?, policy)
}

/// Sends a Bound Profile Package segment by segment ([`bpp_blocks`]) and
/// returns one [`Sent`] per segment sent. Stops at the first segment the card
/// does not accept; the Profile Installation Result, if any, is in the last
/// [`Sent::data`] ([SGP.22 v2.5 §5.7.6], §2.5.6).
///
/// # Errors
///
/// As [`store_data`]. All segments are cut before the first is sent, so a bad
/// segment sends nothing.
pub fn load_bound_profile_package<S: CardSession + ?Sized, T: AsRef<[u8]>>(
    session: &mut S,
    cla: u8,
    segments: &[T],
    policy: &Policy,
) -> Result<Vec<Sent>, Error> {
    let mut sent = Vec::new();
    for segment in bpp_blocks(cla, segments)? {
        let one = send_blocks(session, segment, policy)?;
        let done = one.complete
            && one
                .exchanges
                .last()
                .is_some_and(Exchange::is_normal_processing);
        sent.push(one);
        if !done {
            break;
        }
    }
    Ok(sent)
}

fn send_blocks<S: CardSession + ?Sized>(
    session: &mut S,
    commands: Vec<Command>,
    policy: &Policy,
) -> Result<Sent, Error> {
    let total = commands.len();
    let mut exchanges = Vec::with_capacity(total);
    for (index, command) in commands.iter().enumerate() {
        let exchange = session::send(session, command, policy)?;
        let accepted = exchange.is_normal_processing();
        exchanges.push(exchange);
        if !accepted && index + 1 < total {
            return Ok(Sent {
                exchanges,
                complete: false,
            });
        }
    }
    Ok(Sent {
        exchanges,
        complete: true,
    })
}

// ---------------------------------------------------------------------------
// BER writer and reader (multi-octet tags)
// ---------------------------------------------------------------------------

pub(crate) fn push_tlv(out: &mut Vec<u8>, tag: u32, value: &[u8]) {
    let bytes = tag.to_be_bytes();
    let skip = bytes.iter().take(3).take_while(|b| **b == 0).count();
    out.extend_from_slice(&bytes[skip..]);
    match value.len() {
        0..=0x7F => out.push(value.len() as u8),
        0x80..=0xFF => out.extend_from_slice(&[0x81, value.len() as u8]),
        0x100..=0xFFFF => {
            out.push(0x82);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        n => {
            out.push(0x83);
            out.extend_from_slice(&(n as u32).to_be_bytes()[1..]);
        }
    }
    out.extend_from_slice(value);
}

fn tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    push_tlv(&mut out, tag, value);
    out
}

/// One TLV found in a response: its tag, its contents, and its whole encoding.
#[derive(Clone, Copy)]
pub(crate) struct Node<'a> {
    pub tag: u32,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

pub(crate) fn parse(mut input: &[u8]) -> Result<Vec<Node<'_>>, DecodeError> {
    let mut nodes = Vec::new();
    while !input.is_empty() {
        let whole = input;
        let mut tag = u32::from(input[0]);
        let mut at = 1;
        if input[0] & 0x1F == 0x1F {
            loop {
                let next = *input.get(at).ok_or(DecodeError::Truncated {
                    needed: 1,
                    available: 0,
                })?;
                at += 1;
                if at > 4 {
                    return Err(DecodeError::UnsupportedTag);
                }
                tag = (tag << 8) | u32::from(next);
                if next & 0x80 == 0 {
                    break;
                }
            }
        }
        let first = *input.get(at).ok_or(DecodeError::Truncated {
            needed: 1,
            available: 0,
        })?;
        at += 1;
        let len = match first {
            0x00..=0x7F => usize::from(first),
            0x81..=0x83 => {
                let count = usize::from(first & 0x7F);
                let bytes = input.get(at..at + count).ok_or(DecodeError::Truncated {
                    needed: count,
                    available: input.len().saturating_sub(at),
                })?;
                at += count;
                bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b))
            }
            other => return Err(DecodeError::UnsupportedLength(other)),
        };
        let value = input.get(at..at + len).ok_or(DecodeError::Truncated {
            needed: len,
            available: input.len().saturating_sub(at),
        })?;
        nodes.push(Node {
            tag,
            value,
            raw: &whole[..at + len],
        });
        input = &input[at + len..];
    }
    Ok(nodes)
}

/// The contents of the one TLV `data` consists of, which must carry `tag`.
fn only<'a>(data: &'a [u8], tag: u32) -> Result<Vec<Node<'a>>, DecodeError> {
    let outer = parse(data)?;
    let Some(node) = outer.first() else {
        return Err(DecodeError::Truncated {
            needed: 1,
            available: 0,
        });
    };
    if outer.len() > 1 {
        return Err(DecodeError::TrailingData(data.len() - node.raw.len()));
    }
    if node.tag != tag {
        return Err(DecodeError::WrongTag {
            expected: tag,
            found: node.tag,
        });
    }
    parse(node.value)
}

/// The value of the one TLV `data` consists of, which must carry `tag`. For
/// the ES9+ layer ([`crate::es9`]), which gets whole TLVs inside base64.
pub(crate) fn single_value(data: &[u8], tag: u32) -> Result<&[u8], DecodeError> {
    let outer = parse(data)?;
    let Some(node) = outer.first() else {
        return Err(DecodeError::Truncated {
            needed: 1,
            available: 0,
        });
    };
    if outer.len() > 1 {
        return Err(DecodeError::TrailingData(data.len() - node.raw.len()));
    }
    if node.tag != tag {
        return Err(DecodeError::WrongTag {
            expected: tag,
            found: node.tag,
        });
    }
    Ok(node.value)
}

/// A TLV a decoder did not recognise, kept whole so nothing is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// The tag, as read (`0xBF22`, `0x99`, ...).
    pub tag: u32,
    /// The value octets.
    pub value: Vec<u8>,
}

fn keep(unknown: &mut Vec<Unknown>, node: Node<'_>) {
    unknown.push(Unknown {
        tag: node.tag,
        value: node.value.to_vec(),
    });
}

fn exact<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], DecodeError> {
    value.try_into().map_err(|_| DecodeError::BadLength {
        field,
        expected: match N {
            3 => "3",
            16 => "16",
            _ => "a fixed number of",
        },
        got: value.len(),
    })
}

fn ranged(
    value: &[u8],
    field: &'static str,
    expected: &'static str,
    ok: std::ops::RangeInclusive<usize>,
) -> Result<Vec<u8>, DecodeError> {
    if ok.contains(&value.len()) {
        Ok(value.to_vec())
    } else {
        Err(DecodeError::BadLength {
            field,
            expected,
            got: value.len(),
        })
    }
}

fn utf8(value: &[u8], field: &'static str) -> Result<String, DecodeError> {
    String::from_utf8(value.to_vec()).map_err(|_| DecodeError::BadUtf8(field))
}

/// A one-octet INTEGER, which is all any code or enumeration here needs.
fn small_int(value: &[u8], field: &'static str) -> Result<u8, DecodeError> {
    match value {
        [byte] => Ok(*byte),
        _ => Err(DecodeError::BadLength {
            field,
            expected: "1",
            got: value.len(),
        }),
    }
}

fn require<T>(value: Option<T>, field: &'static str) -> Result<T, DecodeError> {
    value.ok_or(DecodeError::MissingField(field))
}

/// A decoded ASN.1 BIT STRING: the unused-bit count and the octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitString {
    /// Unused low bits of the last octet, 0 to 7.
    pub unused_bits: u8,
    /// The octets after the unused-bits octet.
    pub bytes: Vec<u8>,
}

impl BitString {
    fn decode(value: &[u8], field: &'static str) -> Result<Self, DecodeError> {
        match value.split_first() {
            Some((&unused, rest)) if unused <= 7 && !(rest.is_empty() && unused != 0) => Ok(Self {
                unused_bits: unused,
                bytes: rest.to_vec(),
            }),
            _ => Err(DecodeError::BadBitString(field)),
        }
    }

    /// Named bit `n` in ASN.1 numbering: bit 0 is the most significant bit of
    /// the first octet. Bits past the end read as `false`, as DER trims
    /// trailing zeros.
    pub fn bit(&self, n: usize) -> bool {
        let used = (self.bytes.len() * 8).saturating_sub(usize::from(self.unused_bits));
        n < used && self.bytes[n / 8] & (0x80 >> (n % 8)) != 0
    }
}

/// `code_enum!` makes an ASN.1 INTEGER enumeration that keeps values the
/// spec does not name.
macro_rules! code_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $value:expr),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $(#[doc = stringify!($variant)] $variant,)+
            /// A value the specification does not define.
            Unknown(u8),
        }

        impl $name {
            /// Reads the enumeration from its INTEGER value.
            pub const fn from_code(code: u8) -> Self {
                match code {
                    $($value => Self::$variant,)+
                    other => Self::Unknown(other),
                }
            }

            /// The INTEGER value.
            pub const fn code(self) -> u8 {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(code) => code,
                }
            }
        }
    };
}

code_enum! {
    /// `CancelSessionReason` ([SGP.22 v2.5 §5.7.14]).
    CancelSessionReason {
        EndUserRejection = 0, Postponed = 1, Timeout = 2, PprNotAllowed = 3,
        MetadataMismatch = 4, LoadBppExecutionError = 5, UndefinedReason = 127,
    }
}
code_enum! {
    /// `cancelSessionResponseError` ([SGP.22 v2.5 §5.7.14]).
    CancelSessionError { InvalidTransactionId = 5, UndefinedError = 127 }
}
code_enum! {
    /// `DownloadErrorCode` ([SGP.22 v2.5 §5.7.5]).
    DownloadErrorCode {
        InvalidCertificate = 1, InvalidSignature = 2, UnsupportedCurve = 3,
        NoSessionContext = 4, InvalidTransactionId = 5, UndefinedError = 127,
    }
}
code_enum! {
    /// `AuthenticateErrorCode` ([SGP.22 v2.5 §5.7.13]).
    AuthenticateErrorCode {
        InvalidCertificate = 1, InvalidSignature = 2, UnsupportedCurve = 3,
        NoSessionContext = 4, InvalidOid = 5, EuiccChallengeMismatch = 6,
        CiPkUnknown = 7, UndefinedError = 127,
    }
}
code_enum! {
    /// `ProfileState` ([SGP.22 v2.5 §5.7.15]).
    ProfileState { Disabled = 0, Enabled = 1 }
}
code_enum! {
    /// `ProfileClass` ([SGP.22 v2.5 §5.7.15]).
    ProfileClass { Test = 0, Provisioning = 1, Operational = 2 }
}
code_enum! {
    /// `GetCertsError`, tag `81` of a GetCerts response (SGP.32 section 5.9.10
    /// [U]; values [V] osmocom/pysim `pySim/euicc.py` lines 324-325, which
    /// spell them `invalidCiPKId` and `undefinedError`). The TLV is terminal:
    /// a response holding it holds no certificate.
    GetCertsError { InvalidCiPkId = 1, UndefinedError = 127 }
}
code_enum! {
    /// `EimIdType`, tag `82` of `EimConfigurationData` (SGP.32 section 5.9.18
    /// [U]; values [V] osmocom/pysim `pySim/euicc.py` line 335:
    /// `eimIdTypeOid`, `eimIdTypeFqdn`, `eimIdTypeProprietary`).
    EimIdType { Oid = 1, Fqdn = 2, Proprietary = 3 }
}
code_enum! {
    /// `EimSupportedProtocol`, tag `87` of `EimConfigurationData`, which may
    /// repeat (SGP.32 section 5.9.18 [U]; values [V] osmocom/pysim
    /// `pySim/euicc.py` lines 341-342: `eimRetrieveHttps`,
    /// `eimRetrieveCoaps`, `eimInjectHttps`, `eimInjectCoaps`,
    /// `eimProprietary`).
    EimSupportedProtocol {
        RetrieveHttps = 0, RetrieveCoaps = 1, InjectHttps = 2, InjectCoaps = 3,
        Proprietary = 4,
    }
}
code_enum! {
    /// `IconType` ([SGP.22 v2.5 §5.7.15]).
    IconType { Jpg = 0, Png = 1 }
}
code_enum! {
    /// `ProfileInfoListError` ([SGP.22 v2.5 §5.7.15]).
    ProfileInfoListError { IncorrectInputValues = 1, UndefinedError = 127 }
}
code_enum! {
    /// `enableResult` ([SGP.22 v2.5 §5.7.16]).
    EnableResult {
        Ok = 0, IccidOrAidNotFound = 1, ProfileNotInDisabledState = 2,
        DisallowedByPolicy = 3, WrongProfileReenabling = 4, CatBusy = 5,
        UndefinedError = 127,
    }
}
code_enum! {
    /// `disableResult`. pySim's `rsp.asn` (`DisableProfileResponse`) lists
    /// ok(0), iccidOrAidNotFound(1), profileNotInEnabledState(2),
    /// disallowedByPolicy(3) and undefinedError(127); `CatBusy` (5) is not in
    /// that file for either function and is kept here, as for
    /// [`EnableResult`], so an eUICC that answers it gets a distinct name.
    DisableResult {
        Ok = 0, IccidOrAidNotFound = 1, ProfileNotInEnabledState = 2,
        DisallowedByPolicy = 3, CatBusy = 5, UndefinedError = 127,
    }
}
code_enum! {
    /// `setNicknameResult` ([SGP.22 v2.5 §5.7.21]).
    SetNicknameResult { Ok = 0, IccidNotFound = 1, UndefinedError = 127 }
}
code_enum! {
    /// `deleteResult` ([SGP.22 v2.5 §5.7.18]).
    DeleteResult {
        Ok = 0, IccidOrAidNotFound = 1, ProfileNotInDisabledState = 2,
        DisallowedByPolicy = 3, UndefinedError = 127,
    }
}
code_enum! {
    /// `deleteNotificationStatus` of `NotificationSentResponse`, the answer to
    /// RemoveNotificationFromList ([SGP.22 v2.5 §5.7.12]; pySim `rsp.asn`:
    /// ok(0), nothingToDelete(1), undefinedError(127)).
    RemoveNotificationResult { Ok = 0, NothingToDelete = 1, UndefinedError = 127 }
}
code_enum! {
    /// `resetResult` of `EuiccMemoryResetResponse` ([SGP.22 v2.5 §5.7.19];
    /// pySim `rsp.asn`: ok(0), nothingToDelete(1), undefinedError(127)).
    ResetResult { Ok = 0, NothingToDelete = 1, UndefinedError = 127 }
}
code_enum! {
    /// `SetDefaultDpAddrRes` ([SGP.22 v2.5 §5.7.4]): ok(0) and
    /// undefinedError(127), tag `80` in the **response**. pySim `euicc.py`
    /// line 116 spells the enumeration as `Enum(Int8ub, ok=0,
    /// undefinedError=127)`.
    ///
    /// A code the enumeration does not name stays
    /// [`SetDefaultDpResult::Unknown`] and is never guessed into one of the
    /// two.
    SetDefaultDpResult { Ok = 0, UndefinedError = 127 }
}
code_enum! {
    /// `euiccCategory` ([SGP.22 v2.5 §5.7.8]).
    EuiccCategory { Other = 0, BasicEuicc = 1, MediumEuicc = 2, ContactlessEuicc = 3 }
}

// ---------------------------------------------------------------------------
// Request encoders
// ---------------------------------------------------------------------------

fn check(value: &[u8], field: &'static str, min: usize, max: usize) -> Result<(), EncodeError> {
    if (min..=max).contains(&value.len()) {
        Ok(())
    } else {
        Err(EncodeError::FieldLength {
            field,
            min,
            max,
            got: value.len(),
        })
    }
}

/// `GetEuiccChallengeRequest`: `BF 2E 00` ([SGP.22 v2.5 §5.7.7]).
pub fn get_euicc_challenge_request() -> Vec<u8> {
    tlv(0xBF2E, &[])
}

/// `GetEuiccInfo1Request`: `BF 20 00` ([SGP.22 v2.5 §5.7.8]).
pub fn get_euicc_info1_request() -> Vec<u8> {
    tlv(0xBF20, &[])
}

/// `GetEuiccInfo2Request`: `BF 22 00` ([SGP.22 v2.5 §5.7.8]).
pub fn get_euicc_info2_request() -> Vec<u8> {
    tlv(0xBF22, &[])
}

/// `GetEuiccDataRequest` asking for the EID only, `BF3E 03 5C 01 5A`
/// ([SGP.22 v2.5 §5.7.20], the frame pySim sends).
pub fn get_eid_request() -> Vec<u8> {
    tlv(0xBF3E, &tlv(0x5C, &[0x5A]))
}

/// `GetEuiccConfiguredAddressesRequest`, `BF 3C 00` (ES10a,
/// [SGP.22 v2.5 §5.7.3]): the default SM-DP+ and root SM-DS addresses.
pub fn get_euicc_configured_addresses_request() -> Vec<u8> {
    tlv(0xBF3C, &[])
}

/// Longest `defaultDpAddress` this crate will encode, in bytes.
///
/// `[U]` SGP.22 constrains `defaultDpAddress` with an ASN.1 `SIZE(1..max)`, but
/// the upper bound was **not** verified against the v2.5 PDF text, so this is
/// this crate's own cap and not a published constant. 128 is chosen because an
/// SM-DP+ address is a host name or a URL, neither of which comes anywhere near
/// it, and a cap that stops a hostile address is worth more than a byte of room.
/// `blocks` still segments a longer frame when `--max-segment` is small, so
/// this is a policy limit, not a wire limit.
pub const MAX_DEFAULT_DP_ADDRESS_BYTES: usize = 128;

/// `SetDefaultDpAddressRequest`, `BF 3F { 80 <defaultDpAddress> }` (ES10a,
/// [SGP.22 v2.5 §5.7.4]): tag `80` [V] carries the new default SM-DP+ address
/// as a **UTF-8 string**.
///
/// **Tag `80` means two different things in this one function.** In the request
/// it is the address, a string; in the response it is `SetDefaultDpAddrRes`, an
/// **INTEGER** ([`decode_set_default_dp`]). They are different messages, which
/// is exactly why the encoder and the decoder are two functions and never one.
///
/// Verified 2026-10-15 against pySim `euicc.py` (osmocom/pysim, GPL reference,
/// read not copied): line 108 `class DefaultDpAddress(BER_TLV_IE, tag=0x80)`
/// with `_construct = Utf8Adapter(GreedyBytes)` (a UTF-8 string), lines 115-118
/// `class SetDefaultDpAddrRes(BER_TLV_IE, tag=0x80)` with
/// `_construct = Enum(Int8ub, ok=0, undefinedError=127)` and
/// `class SetDefaultDpAddress(BER_TLV_IE, tag=0xbf3f, nested=[DefaultDpAddress,
/// SetDefaultDpAddrRes])`, and `do_set_default_dp_address` at line 424, which
/// builds exactly this frame and sends it as one STORE DATA.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for an empty address or one over
/// [`MAX_DEFAULT_DP_ADDRESS_BYTES`].
pub fn set_default_dp_request(address: &str) -> Result<Vec<u8>, EncodeError> {
    check(
        address.as_bytes(),
        "defaultDpAddress",
        1,
        MAX_DEFAULT_DP_ADDRESS_BYTES,
    )?;
    Ok(tlv(0xBF3F, &tlv(0x80, address.as_bytes())))
}

/// Longest `profileNickname`, in bytes ([SGP.22 v2.5 §5.7.21]:
/// `UTF8String (SIZE(0..64))`; counted in bytes, the stricter reading).
pub const MAX_NICKNAME_BYTES: usize = 64;

/// `SetNicknameRequest`, `BF29` ([SGP.22 v2.5 §5.7.21]): the 10-octet ICCID
/// (tag `5A`) and the nickname (tag `90`, 0 to 64 bytes; empty clears it).
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for an ICCID that is not 10 bytes or a
/// nickname over [`MAX_NICKNAME_BYTES`].
pub fn set_nickname_request(iccid: &[u8], nickname: &str) -> Result<Vec<u8>, EncodeError> {
    check(iccid, "iccid", 10, 10)?;
    check(
        nickname.as_bytes(),
        "profileNickname",
        0,
        MAX_NICKNAME_BYTES,
    )?;
    let mut body = tlv(0x5A, iccid);
    push_tlv(&mut body, 0x90, nickname.as_bytes());
    Ok(tlv(0xBF29, &body))
}

/// `ListNotificationRequest` with no filter, `BF28 00`: every pending
/// notification's metadata, nothing retrieved or removed ([SGP.22 v2.5 §5.7.11]).
pub fn list_notification_request() -> Vec<u8> {
    tlv(0xBF28, &[])
}

/// `GetCertsRequest`: `BF 56 00`, an empty BER-TLV. SGP.32 section 5.9.10
/// [U]; `BF56` is [V] osmocom/pysim `pySim/euicc.py` line 318 (`GetCertsReq`,
/// nested nothing). The response is the two certificates or one error code.
pub fn get_certs_request() -> Vec<u8> {
    tlv(0xBF56, &[])
}

/// `GetEimConfigurationDataRequest`: `BF 55 00`, an empty BER-TLV. SGP.32
/// section 5.9.18 [U]; `BF55` is [V] osmocom/pysim `pySim/euicc.py` line 349
/// (`GetEimConfigurationData`, nested one `EimConfigurationDataSeq`).
pub fn get_eim_configuration_data_request() -> Vec<u8> {
    tlv(0xBF55, &[])
}

/// `PrepareDownloadRequest`, `BF21` ([SGP.22 v2.5 §5.7.5]). The signed and
/// certificate parts come from the SM-DP+ (`ES9+.GetBoundProfilePackage`
/// input) and are passed through as DER, because the signature covers their
/// exact bytes.
#[derive(Debug, Clone, Copy)]
pub struct PrepareDownloadRequest<'a> {
    /// `smdpSigned2`, complete DER including its `30` header.
    pub smdp_signed2: &'a [u8],
    /// `smdpSignature2`, the value of tag `5F37`.
    pub smdp_signature2: &'a [u8],
    /// `hashCc`, 32 bytes, when a confirmation code is required.
    pub hash_cc: Option<&'a [u8]>,
    /// `smdpCertificate` (CERT.DPpb.ECDSA), complete DER.
    pub smdp_certificate: &'a [u8],
}

impl PrepareDownloadRequest<'_> {
    /// The STORE DATA data field.
    ///
    /// # Errors
    ///
    /// [`EncodeError::FieldLength`] when `hash_cc` is not 32 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = self.smdp_signed2.to_vec();
        push_tlv(&mut body, 0x5F37, self.smdp_signature2);
        if let Some(hash) = self.hash_cc {
            check(hash, "hashCc", 32, 32)?;
            push_tlv(&mut body, 0x04, hash);
        }
        body.extend_from_slice(self.smdp_certificate);
        Ok(tlv(0xBF21, &body))
    }
}

/// `AuthenticateServerRequest`, `BF38` ([SGP.22 v2.5 §5.7.13]). Like
/// [`PrepareDownloadRequest`], the server-supplied parts are DER passed
/// through.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateServerRequest<'a> {
    /// `serverSigned1`, complete DER including its `30` header.
    pub server_signed1: &'a [u8],
    /// `serverSignature1`, the value of tag `5F37`.
    pub server_signature1: &'a [u8],
    /// `euiccCiPKIdToBeUsed`, the value of a SubjectKeyIdentifier.
    pub euicc_ci_pk_id_to_be_used: &'a [u8],
    /// `serverCertificate` (CERT.XXauth.ECDSA), complete DER.
    pub server_certificate: &'a [u8],
    /// `ctxParams1`, complete DER including its `A0` header.
    pub ctx_params1: &'a [u8],
}

impl AuthenticateServerRequest<'_> {
    /// The STORE DATA data field.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = self.server_signed1.to_vec();
        push_tlv(&mut body, 0x5F37, self.server_signature1);
        push_tlv(&mut body, 0x04, self.euicc_ci_pk_id_to_be_used);
        body.extend_from_slice(self.server_certificate);
        body.extend_from_slice(self.ctx_params1);
        tlv(0xBF38, &body)
    }
}

/// `CancelSessionRequest`, `BF41` ([SGP.22 v2.5 §5.7.14]):
/// `80 <transactionId> 81 <reason>`.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] unless `transaction_id` is 1 to 16 bytes
/// (Annex H, `TransactionId`).
pub fn cancel_session_request(
    transaction_id: &[u8],
    reason: CancelSessionReason,
) -> Result<Vec<u8>, EncodeError> {
    check(transaction_id, "transactionId", 1, 16)?;
    let mut body = tlv(0x80, transaction_id);
    push_tlv(&mut body, 0x81, &[reason.code()]);
    Ok(tlv(0xBF41, &body))
}

/// A profile named by ISD-P AID or by ICCID, as EnableProfile and
/// DeleteProfile take it ([SGP.22 v2.5 §5.7.16], §5.7.18).
#[derive(Debug, Clone, Copy)]
pub enum ProfileIdentifier<'a> {
    /// The ISD-P AID, 1 to 16 bytes, tag `4F`.
    IsdpAid(&'a [u8]),
    /// The ICCID as coded in EF ICCID (swapped nibbles), exactly 10 bytes,
    /// tag `5A`.
    Iccid(&'a [u8]),
}

impl ProfileIdentifier<'_> {
    fn encode(self) -> Result<Vec<u8>, EncodeError> {
        match self {
            Self::IsdpAid(aid) => {
                check(aid, "isdpAid", 1, 16)?;
                Ok(tlv(0x4F, aid))
            }
            Self::Iccid(iccid) => {
                check(iccid, "iccid", 10, 10)?;
                Ok(tlv(0x5A, iccid))
            }
        }
    }
}

/// `EnableProfileRequest`, `BF31` ([SGP.22 v2.5 §5.7.16]):
/// `A0 <identifier> 81 <refreshFlag>`, the flag `FF` for true.
///
/// Checked 2026-10-10 against pySim `pySim/esim/asn1/rsp/rsp.asn`
/// (`EnableProfileRequest ::= [49] SEQUENCE { profileIdentifier CHOICE {
/// isdpAid [APPLICATION 15] OctetTo16, iccid Iccid }, refreshFlag BOOLEAN }`
/// under `AUTOMATIC TAGS`: the CHOICE is `[0]`, so `A0`; the flag is `[1]`,
/// so `81`) and lpac `euicc/es10c.c` (`es10c_enable_disable_delete_profile`
/// sends `BF31 { A0 { 4F|5A id } 81 01 FF|00 }`).
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed identifier.
pub fn enable_profile_request(
    profile: ProfileIdentifier<'_>,
    refresh: bool,
) -> Result<Vec<u8>, EncodeError> {
    state_request(0xBF31, profile, refresh)
}

/// `DisableProfileRequest`, `BF32` ([SGP.22 v2.5 §5.7.17]): the same body as
/// [`enable_profile_request`] (pySim `rsp.asn`: `DisableProfileRequest ::=
/// [50] SEQUENCE { profileIdentifier CHOICE { ... }, refreshFlag BOOLEAN }`;
/// lpac `es10c_disable_profile` passes tag `0xBF32` to the same builder).
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed identifier.
pub fn disable_profile_request(
    profile: ProfileIdentifier<'_>,
    refresh: bool,
) -> Result<Vec<u8>, EncodeError> {
    state_request(0xBF32, profile, refresh)
}

fn state_request(
    tag: u32,
    profile: ProfileIdentifier<'_>,
    refresh: bool,
) -> Result<Vec<u8>, EncodeError> {
    let mut body = tlv(0xA0, &profile.encode()?);
    push_tlv(&mut body, 0x81, &[if refresh { 0xFF } else { 0x00 }]);
    Ok(tlv(tag, &body))
}

/// `DeleteProfileRequest`, `BF33` ([SGP.22 v2.5 §5.7.18]): the identifier
/// directly, `4F` or `5A`.
///
/// Checked 2026-10-10 against pySim `rsp.asn` (`DeleteProfileRequest ::= [51]
/// CHOICE { isdpAid [APPLICATION 15] OctetTo16, iccid Iccid }`) and lpac
/// `euicc/es10c.c` (`es10c_delete_profile` calls
/// `es10c_enable_disable_delete_profile` with tag `0xBF33` and no refresh flag,
/// which packs the identifier node as the only child: `BF33 { 4F|5A id }`).
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed identifier.
pub fn delete_profile_request(profile: ProfileIdentifier<'_>) -> Result<Vec<u8>, EncodeError> {
    Ok(tlv(0xBF33, &profile.encode()?))
}

/// Which parts of the eUICC `eUICCMemoryReset` clears: the `resetOptions`
/// BIT STRING of [SGP.22 v2.5 §5.7.19].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResetOptions {
    /// Bit 0, `deleteOperationalProfiles`.
    pub delete_operational_profiles: bool,
    /// Bit 1, `deleteFieldLoadedTestProfiles`.
    pub delete_field_loaded_test_profiles: bool,
    /// Bit 2, `resetDefaultSmdpAddress`.
    pub reset_default_smdp_address: bool,
}

impl ResetOptions {
    /// Whether no option is chosen.
    pub fn is_empty(self) -> bool {
        self == Self::default()
    }
}

/// `EuiccMemoryResetRequest`, `BF34` ([SGP.22 v2.5 §5.7.19]):
/// `82 <len> <unused> <bits>`, bit 0 the most significant. The BIT STRING is a
/// named-bit list, so DER drops trailing zero bits: the unused-bit count is the
/// number of trailing zeros of the octet.
///
/// Checked 2026-10-10 against pySim `rsp.asn` (`EuiccMemoryResetRequest ::=
/// [52] SEQUENCE { resetOptions [2] BIT STRING { deleteOperationalProfiles(0),
/// deleteFieldLoadedTestProfiles(1), resetDefaultSmdpAddress(2) } }`) and lpac
/// `euicc/es10c.c` (`es10c_euicc_memory_reset` sends `BF34 { 82 02 05 E0 }`,
/// all three bits, which this produces for all three options).
///
/// # Errors
///
/// [`EncodeError::FieldLength`] when no option is chosen.
pub fn memory_reset_request(options: ResetOptions) -> Result<Vec<u8>, EncodeError> {
    let bits = [
        options.delete_operational_profiles,
        options.delete_field_loaded_test_profiles,
        options.reset_default_smdp_address,
    ]
    .iter()
    .enumerate()
    .fold(0u8, |acc, (i, on)| acc | (u8::from(*on) << (7 - i)));
    if bits == 0 {
        return Err(EncodeError::FieldLength {
            field: "resetOptions",
            min: 1,
            max: 3,
            got: 0,
        });
    }
    let body = tlv(0x82, &[bits.trailing_zeros() as u8, bits]);
    Ok(tlv(0xBF34, &body))
}

/// `NotificationSentRequest`, `BF30` ([SGP.22 v2.5 §5.7.12], the request of
/// RemoveNotificationFromList): `80 <seqNumber>` with `seqNumber` the shortest
/// two's-complement INTEGER.
///
/// Checked 2026-10-10 against pySim `rsp.asn` (`NotificationSentRequest ::=
/// [48] SEQUENCE { seqNumber [0] INTEGER }`) and lpac `euicc/es10b.c`
/// (`es10b_remove_notification_from_list` sends `BF30 { 80 <long2bin> }`).
pub fn remove_notification_request(seq_number: u32) -> Vec<u8> {
    tlv(0xBF30, &tlv(0x80, &seq_integer(seq_number)))
}

/// `seqNumber` as the shortest two's-complement INTEGER content.
fn seq_integer(seq_number: u32) -> Vec<u8> {
    let mut int: Vec<u8> = seq_number
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    if int.first().is_none_or(|b| b & 0x80 != 0) {
        int.insert(0, 0);
    }
    int
}

/// `RetrieveNotificationsListRequest`, `BF2B` ([SGP.22 v2.5 §5.7], clause
/// number not checked): the signed `PendingNotification`s, read-only
/// (retrieving removes nothing; that is RemoveNotificationFromList). `None` is
/// `BF2B 00`, the OPTIONAL `searchCriteria` left out, so every pending
/// notification comes back. `Some(seq)` is `BF2B { A0 { 80 <seqNumber> } }`.
///
/// Checked 2026-10-10 against lpac `euicc/es10b.c`
/// (`es10b_retrieve_notifications_list`: `BF2B`, constructed `A0`
/// `searchCriteria`, `80 <long2bin>`; lpac never sends the no-filter form)
/// and pySim `pySim/esim/asn1/rsp/rsp.asn` (`RetrieveNotificationsListRequest
/// ::= [43] SEQUENCE { searchCriteria CHOICE { seqNumber [0] INTEGER,
/// profileManagementOperation [1] NotificationEvent } OPTIONAL }`). The `A0`
/// is the AUTOMATIC TAGS context tag of the lone, untagged `searchCriteria`
/// member (see the module's Tagging section), so both agree.
pub fn retrieve_notifications_request(seq_number: Option<u32>) -> Vec<u8> {
    match seq_number {
        None => tlv(0xBF2B, &[]),
        Some(seq) => tlv(0xBF2B, &tlv(0xA0, &tlv(0x80, &seq_integer(seq)))),
    }
}

/// The `searchCriteria` of GetProfilesInfo ([SGP.22 v2.5 §5.7.15]).
#[derive(Debug, Clone, Copy)]
pub enum SearchCriteria<'a> {
    /// By ISD-P AID, tag `4F`.
    IsdpAid(&'a [u8]),
    /// By ICCID, tag `5A`.
    Iccid(&'a [u8]),
    /// By profile class, tag `95`.
    ProfileClass(ProfileClass),
}

/// `ProfileInfoListRequest`, `BF2D` ([SGP.22 v2.5 §5.7.15]).
///
/// `tag_list` is the tags to return per profile, as numbers (`0x5A`,
/// `0x9F70`); tags up to `0xFF` are one octet, above that two. With neither
/// argument the result is the spec's `BF2D 00` example.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed AID or ICCID.
pub fn get_profiles_info_request(
    criteria: Option<SearchCriteria<'_>>,
    tag_list: Option<&[u16]>,
) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    if let Some(criteria) = criteria {
        let inner = match criteria {
            SearchCriteria::IsdpAid(aid) => ProfileIdentifier::IsdpAid(aid).encode()?,
            SearchCriteria::Iccid(iccid) => ProfileIdentifier::Iccid(iccid).encode()?,
            SearchCriteria::ProfileClass(class) => tlv(0x95, &[class.code()]),
        };
        push_tlv(&mut body, 0xA0, &inner);
    }
    if let Some(tags) = tag_list {
        let mut list = Vec::new();
        for tag in tags {
            if *tag > 0xFF {
                list.extend_from_slice(&tag.to_be_bytes());
            } else {
                list.push(*tag as u8);
            }
        }
        push_tlv(&mut body, 0x5C, &list);
    }
    Ok(tlv(0xBF2D, &body))
}

// ---------------------------------------------------------------------------
// Response decoders
// ---------------------------------------------------------------------------

/// `GetEuiccChallengeResponse` ([SGP.22 v2.5 §5.7.7]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EuiccChallenge {
    /// `euiccChallenge`, 16 random bytes.
    pub challenge: [u8; 16],
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEUICCChallenge.
///
/// # Errors
///
/// A [`DecodeError`] when the data is not a `BF2E` holding a 16-byte `80`.
pub fn decode_get_euicc_challenge(data: &[u8]) -> Result<EuiccChallenge, DecodeError> {
    let mut challenge = None;
    let mut unknown = Vec::new();
    for node in only(data, 0xBF2E)? {
        match node.tag {
            0x80 if challenge.is_none() => challenge = Some(exact(node.value, "euiccChallenge")?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EuiccChallenge {
        challenge: require(challenge, "euiccChallenge")?,
        unknown,
    })
}

fn key_id_list(value: &[u8], context: &'static str) -> Result<Vec<Vec<u8>>, DecodeError> {
    parse(value)?
        .into_iter()
        .map(|node| {
            if node.tag == 0x04 {
                Ok(node.value.to_vec())
            } else {
                Err(DecodeError::UnexpectedTag {
                    context,
                    found: node.tag,
                })
            }
        })
        .collect()
}

/// `EUICCInfo1` ([SGP.22 v2.5 §5.7.8]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EuiccInfo1 {
    /// `svn`, the SGP.22 version supported, major/minor/revision.
    pub svn: [u8; 3],
    /// `euiccCiPKIdListForVerification`, most preferred first.
    pub ci_pk_id_for_verification: Vec<Vec<u8>>,
    /// `euiccCiPKIdListForSigning`, most preferred first.
    pub ci_pk_id_for_signing: Vec<Vec<u8>>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEUICCInfo for EUICCInfo1 (`BF20`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_euicc_info1(data: &[u8]) -> Result<EuiccInfo1, DecodeError> {
    let (mut svn, mut verification, mut signing) = (None, None, None);
    let mut unknown = Vec::new();
    for node in only(data, 0xBF20)? {
        match node.tag {
            0x82 if svn.is_none() => svn = Some(exact(node.value, "svn")?),
            0xA9 if verification.is_none() => {
                verification = Some(key_id_list(node.value, "euiccCiPKIdListForVerification")?);
            }
            0xAA if signing.is_none() => {
                signing = Some(key_id_list(node.value, "euiccCiPKIdListForSigning")?);
            }
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EuiccInfo1 {
        svn: require(svn, "svn")?,
        ci_pk_id_for_verification: require(verification, "euiccCiPKIdListForVerification")?,
        ci_pk_id_for_signing: require(signing, "euiccCiPKIdListForSigning")?,
        unknown,
    })
}

/// `CertificationDataObject` ([SGP.22 v2.5 §5.7.8]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationDataObject {
    /// `platformLabel`.
    pub platform_label: String,
    /// `discoveryBaseURL`, possibly empty.
    pub discovery_base_url: String,
}

/// `EUICCInfo2` ([SGP.22 v2.5 §5.7.8]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EuiccInfo2 {
    /// `profileVersion`, major/minor/revision.
    pub profile_version: [u8; 3],
    /// `svn`.
    pub svn: [u8; 3],
    /// `euiccFirmwareVer`.
    pub euicc_firmware_ver: [u8; 3],
    /// `extCardResource`, raw (ETSI TS 102 226).
    pub ext_card_resource: Vec<u8>,
    /// `uiccCapability`; named bits are defined by the TCA profile package.
    pub uicc_capability: BitString,
    /// `ts102241Version`.
    pub ts102241_version: Option<[u8; 3]>,
    /// `globalplatformVersion`.
    pub globalplatform_version: Option<[u8; 3]>,
    /// `rspCapability`: bit 0 additionalProfile, 1 crlSupport, 2 rpmSupport,
    /// 3 testProfileSupport, 4 deviceInfoExtensibilitySupport, 5
    /// serviceSpecificDataSupport.
    pub rsp_capability: BitString,
    /// `euiccCiPKIdListForVerification`, most preferred first.
    pub ci_pk_id_for_verification: Vec<Vec<u8>>,
    /// `euiccCiPKIdListForSigning`, most preferred first.
    pub ci_pk_id_for_signing: Vec<Vec<u8>>,
    /// `euiccCategory`.
    pub euicc_category: Option<EuiccCategory>,
    /// `forbiddenProfilePolicyRules` (`PprIds`: bit 0 pprUpdateControl, 1
    /// ppr1, 2 ppr2).
    pub forbidden_profile_policy_rules: Option<BitString>,
    /// `ppVersion`, the Protection Profile version.
    pub pp_version: [u8; 3],
    /// `sasAcreditationNumber`.
    pub sas_accreditation_number: String,
    /// `certificationDataObject`.
    pub certification_data_object: Option<CertificationDataObject>,
    /// `treProperties`: bit 0 isDiscrete, 1 isIntegrated, 2 usesRemoteMemory.
    pub tre_properties: Option<BitString>,
    /// `treProductReference`.
    pub tre_product_reference: Option<String>,
    /// `additionalEuiccProfilePackageVersions`.
    pub additional_euicc_profile_package_versions: Vec<[u8; 3]>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEUICCInfo for EUICCInfo2 (`BF22`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_euicc_info2(data: &[u8]) -> Result<EuiccInfo2, DecodeError> {
    info2_from_nodes(only(data, 0xBF22)?)
}

fn info2_from_nodes(nodes: Vec<Node<'_>>) -> Result<EuiccInfo2, DecodeError> {
    let mut profile_version = None;
    let mut svn = None;
    let mut firmware = None;
    let mut ext_card_resource = None;
    let mut uicc_capability = None;
    let mut ts102241 = None;
    let mut gp = None;
    let mut rsp_capability = None;
    let mut verification = None;
    let mut signing = None;
    let mut category = None;
    let mut forbidden = None;
    let mut pp_version = None;
    let mut sas = None;
    let mut cert_object = None;
    let mut tre_properties = None;
    let mut tre_reference = None;
    let mut additional = Vec::new();
    let mut unknown = Vec::new();
    for node in nodes {
        let v = node.value;
        match node.tag {
            0x81 if profile_version.is_none() => {
                profile_version = Some(exact(v, "profileVersion")?)
            }
            0x82 if svn.is_none() => svn = Some(exact(v, "svn")?),
            0x83 if firmware.is_none() => firmware = Some(exact(v, "euiccFirmwareVer")?),
            0x84 if ext_card_resource.is_none() => ext_card_resource = Some(v.to_vec()),
            0x85 if uicc_capability.is_none() => {
                uicc_capability = Some(BitString::decode(v, "uiccCapability")?);
            }
            0x86 if ts102241.is_none() => ts102241 = Some(exact(v, "ts102241Version")?),
            0x87 if gp.is_none() => gp = Some(exact(v, "globalplatformVersion")?),
            0x88 if rsp_capability.is_none() => {
                rsp_capability = Some(BitString::decode(v, "rspCapability")?);
            }
            0xA9 if verification.is_none() => {
                verification = Some(key_id_list(v, "euiccCiPKIdListForVerification")?);
            }
            0xAA if signing.is_none() => {
                signing = Some(key_id_list(v, "euiccCiPKIdListForSigning")?);
            }
            0x8B if category.is_none() => {
                category = Some(EuiccCategory::from_code(small_int(v, "euiccCategory")?));
            }
            0x99 if forbidden.is_none() => {
                forbidden = Some(BitString::decode(v, "forbiddenProfilePolicyRules")?);
            }
            // ppVersion and sasAcreditationNumber are untagged in the module,
            // so they keep their universal tags.
            0x04 if pp_version.is_none() => pp_version = Some(exact(v, "ppVersion")?),
            0x0C if sas.is_none() => sas = Some(utf8(v, "sasAcreditationNumber")?),
            0xAC if cert_object.is_none() => {
                let (mut label, mut url) = (None, None);
                for inner in parse(v)? {
                    match inner.tag {
                        0x80 if label.is_none() => {
                            label = Some(utf8(inner.value, "platformLabel")?)
                        }
                        0x81 if url.is_none() => url = Some(utf8(inner.value, "discoveryBaseURL")?),
                        found => {
                            return Err(DecodeError::UnexpectedTag {
                                context: "certificationDataObject",
                                found,
                            })
                        }
                    }
                }
                cert_object = Some(CertificationDataObject {
                    platform_label: require(label, "platformLabel")?,
                    discovery_base_url: require(url, "discoveryBaseURL")?,
                });
            }
            0x8D if tre_properties.is_none() => {
                tre_properties = Some(BitString::decode(v, "treProperties")?);
            }
            0x8E if tre_reference.is_none() => {
                tre_reference = Some(utf8(v, "treProductReference")?);
            }
            0xAF if additional.is_empty() => {
                for inner in parse(v)? {
                    if inner.tag != 0x04 {
                        return Err(DecodeError::UnexpectedTag {
                            context: "additionalEuiccProfilePackageVersions",
                            found: inner.tag,
                        });
                    }
                    additional.push(exact(inner.value, "additionalEuiccProfilePackageVersions")?);
                }
            }
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EuiccInfo2 {
        profile_version: require(profile_version, "profileVersion")?,
        svn: require(svn, "svn")?,
        euicc_firmware_ver: require(firmware, "euiccFirmwareVer")?,
        ext_card_resource: require(ext_card_resource, "extCardResource")?,
        uicc_capability: require(uicc_capability, "uiccCapability")?,
        ts102241_version: ts102241,
        globalplatform_version: gp,
        rsp_capability: require(rsp_capability, "rspCapability")?,
        ci_pk_id_for_verification: require(verification, "euiccCiPKIdListForVerification")?,
        ci_pk_id_for_signing: require(signing, "euiccCiPKIdListForSigning")?,
        euicc_category: category,
        forbidden_profile_policy_rules: forbidden,
        pp_version: require(pp_version, "ppVersion")?,
        sas_accreditation_number: require(sas, "sasAcreditationNumber")?,
        certification_data_object: cert_object,
        tre_properties,
        tre_product_reference: tre_reference,
        additional_euicc_profile_package_versions: additional,
        unknown,
    })
}

/// Decodes the response data of GetEuiccData asked for tag `5A` only: the
/// 16-byte EID ([SGP.22 v2.5 §5.7.20]).
///
/// # Errors
///
/// A [`DecodeError`] when the data is not a `BF3E` holding a 16-byte `5A`.
pub fn decode_get_eid(data: &[u8]) -> Result<[u8; 16], DecodeError> {
    let mut eid = None;
    for node in only(data, 0xBF3E)? {
        if node.tag == 0x5A && eid.is_none() {
            eid = Some(exact(node.value, "eidValue")?);
        }
    }
    require(eid, "eidValue")
}

/// `EuiccConfiguredAddresses` ([SGP.22 v2.5 §5.7.3]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredAddresses {
    /// `defaultDpAddress`, tag `80`; absent when none is configured.
    pub default_dp_address: Option<String>,
    /// `rootDsAddress`, tag `81`. The spec makes it mandatory; a card that
    /// leaves it out still gets its other address shown, so this is optional.
    pub root_ds_address: Option<String>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEuiccConfiguredAddresses (`BF3C`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure or a non-UTF-8 address.
pub fn decode_configured_addresses(data: &[u8]) -> Result<ConfiguredAddresses, DecodeError> {
    let (mut default_dp, mut root_ds) = (None, None);
    let mut unknown = Vec::new();
    for node in only(data, 0xBF3C)? {
        match node.tag {
            0x80 if default_dp.is_none() => {
                default_dp = Some(utf8(node.value, "defaultDpAddress")?)
            }
            0x81 if root_ds.is_none() => root_ds = Some(utf8(node.value, "rootDsAddress")?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok(ConfiguredAddresses {
        default_dp_address: default_dp,
        root_ds_address: root_ds,
        unknown,
    })
}

/// Decodes the response data of SetNickname (`BF29`) into its
/// `setNicknameResult` ([SGP.22 v2.5 §5.7.21]).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_set_nickname(data: &[u8]) -> Result<SetNicknameResult, DecodeError> {
    result_code(data, 0xBF29, "setNicknameResult")
        .map(|(code, _)| SetNicknameResult::from_code(code))
}

/// `SetDefaultDpAddressResponse` ([SGP.22 v2.5 §5.7.4]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDefaultDpResponse {
    /// `SetDefaultDpAddrRes`, tag `80`, an **INTEGER** - not the UTF-8 string
    /// the same tag carries in the request.
    pub result: SetDefaultDpResult,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of SetDefaultDpAddress (`BF3F`) into its
/// `SetDefaultDpAddrRes` ([SGP.22 v2.5 §5.7.4]).
///
/// Separate from [`decode_configured_addresses`] on purpose: tag `80` is the
/// address, a UTF-8 string, in the GetEuiccConfiguredAddresses **response**,
/// and `SetDefaultDpAddrRes`, an INTEGER, here. One decoder cannot read both,
/// and the tests pin which is which.
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure - including a
/// `BF3C` answer, whose outer tag is not `BF3F` and whose `80` is a string.
pub fn decode_set_default_dp(data: &[u8]) -> Result<SetDefaultDpResponse, DecodeError> {
    let (result, unknown) = result_code(data, 0xBF3F, "setDefaultDpAddrRes")?;
    Ok(SetDefaultDpResponse {
        result: SetDefaultDpResult::from_code(result),
        unknown,
    })
}

/// One `NotificationMetadata` (`BF2F`) of a ListNotification response
/// ([SGP.22 v2.5 §5.7.11]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMetadata {
    /// `seqNumber`.
    pub seq_number: u32,
    /// `profileManagementOperation`: bit 0 install, 1 enable, 2 disable, 3 delete.
    pub operation: BitString,
    /// `notificationAddress`, the SM-DP+ or other recipient.
    pub address: String,
    /// `iccid`, tag `5A`, when present.
    pub iccid: Option<Vec<u8>>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// `ListNotificationResponse` ([SGP.22 v2.5 §5.7.11]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListNotificationResponse {
    /// `notificationMetadataList` (`A0`); empty when none are pending.
    Ok(Vec<NotificationMetadata>),
    /// `listNotificationsResultError` (`81`), 127 being undefinedError.
    Error(u8),
}

/// Decodes the response data of ListNotification (`BF28`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure.
pub fn decode_list_notification(data: &[u8]) -> Result<ListNotificationResponse, DecodeError> {
    let outer = only(data, 0xBF28)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("listNotificationResponse"));
    };
    match choice.tag {
        0x81 => Ok(ListNotificationResponse::Error(small_int(
            choice.value,
            "listNotificationsResultError",
        )?)),
        0xA0 => parse(choice.value)?
            .into_iter()
            .map(|node| match node.tag {
                0xBF2F => decode_notification_metadata(node.value),
                found => Err(DecodeError::UnexpectedTag {
                    context: "notificationMetadataList",
                    found,
                }),
            })
            .collect::<Result<_, _>>()
            .map(ListNotificationResponse::Ok),
        found => Err(DecodeError::UnexpectedTag {
            context: "ListNotificationResponse",
            found,
        }),
    }
}

fn decode_notification_metadata(value: &[u8]) -> Result<NotificationMetadata, DecodeError> {
    let (mut seq, mut operation, mut address, mut iccid) = (None, None, None, None);
    let mut unknown = Vec::new();
    for node in parse(value)? {
        let v = node.value;
        match node.tag {
            0x80 if seq.is_none() => {
                if v.is_empty() || v.len() > 4 {
                    return Err(DecodeError::BadLength {
                        field: "seqNumber",
                        expected: "1 to 4",
                        got: v.len(),
                    });
                }
                seq = Some(v.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)));
            }
            0x81 if operation.is_none() => {
                operation = Some(BitString::decode(v, "profileManagementOperation")?);
            }
            0x0C if address.is_none() => address = Some(utf8(v, "notificationAddress")?),
            0x5A if iccid.is_none() => iccid = Some(ranged(v, "iccid", "10", 10..=10)?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok(NotificationMetadata {
        seq_number: require(seq, "seqNumber")?,
        operation: require(operation, "profileManagementOperation")?,
        address: require(address, "notificationAddress")?,
        iccid,
        unknown,
    })
}

/// Which `PendingNotification` CHOICE arm a notification is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// `profileInstallationResult` (`BF37`), sent after a profile install.
    ProfileInstallationResult,
    /// `otherSignedNotification` (a SEQUENCE, `30`): enable, disable, delete.
    OtherSigned,
}

/// One signed `PendingNotification`: the exact bytes to hand to
/// ES9+.HandleNotification, and the metadata read out of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNotification {
    /// The CHOICE arm.
    pub kind: PendingKind,
    /// The whole encoding (`BF37 ..` or `30 ..`), unmodified: the eUICC's
    /// signature covers it.
    pub raw: Vec<u8>,
    /// The `NotificationMetadata` (`BF2F`) inside it.
    pub metadata: NotificationMetadata,
    /// `transactionId` (`80`) of a profile installation result.
    pub transaction_id: Option<Vec<u8>>,
}

/// Decodes one `PendingNotification`, as far as lpac does and a little
/// further: the arm, the `BF2F` metadata, and for `BF37` the `transactionId`.
/// The signature and certificates are not checked.
///
/// Checked 2026-10-10 against lpac `euicc/es10b.c`
/// (`es10b_retrieve_notifications_list`: tag `BF37` descends `BF27` then
/// `BF2F`; tag `30` finds `BF2F` directly; the notification address is the
/// `0C` inside) and pySim `rsp.asn` (`PendingNotification ::= CHOICE {
/// profileInstallationResult [55] ProfileInstallationResult, otherSignedNotification
/// OtherSignedNotification }`; `ProfileInstallationResultData ::= [39]
/// SEQUENCE { transactionId [0], notificationMetadata [47], .. }`;
/// `OtherSignedNotification ::= SEQUENCE { tbsOtherNotification
/// NotificationMetadata, .. }`).
///
/// # Errors
///
/// A [`DecodeError`] for trailing data, an unknown arm or a missing `BF2F`.
pub fn decode_pending_notification(raw: &[u8]) -> Result<PendingNotification, DecodeError> {
    let outer = parse(raw)?;
    let [node] = outer.as_slice() else {
        return Err(match outer.first() {
            None => DecodeError::Truncated {
                needed: 1,
                available: 0,
            },
            Some(first) => DecodeError::TrailingData(raw.len() - first.raw.len()),
        });
    };
    let (kind, fields) = match node.tag {
        0xBF37 => {
            let data = parse(node.value)?
                .into_iter()
                .find(|n| n.tag == 0xBF27)
                .ok_or(DecodeError::MissingField("profileInstallationResultData"))?;
            (PendingKind::ProfileInstallationResult, parse(data.value)?)
        }
        0x30 => (PendingKind::OtherSigned, parse(node.value)?),
        found => {
            return Err(DecodeError::UnexpectedTag {
                context: "PendingNotification",
                found,
            })
        }
    };
    let meta = fields
        .iter()
        .find(|n| n.tag == 0xBF2F)
        .ok_or(DecodeError::MissingField("notificationMetadata"))?;
    let transaction_id = (kind == PendingKind::ProfileInstallationResult)
        .then(|| fields.iter().find(|n| n.tag == 0x80))
        .flatten()
        .map(|n| n.value.to_vec());
    Ok(PendingNotification {
        kind,
        raw: raw.to_vec(),
        metadata: decode_notification_metadata(meta.value)?,
        transaction_id,
    })
}

/// `RetrieveNotificationsListResponse` (`BF2B`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrieveNotificationsResponse {
    /// `notificationList` (`A0`).
    Ok(Vec<PendingNotification>),
    /// `notificationsListResultError`: 1 noResultAvailable, 127 undefinedError.
    Error(u8),
}

/// Decodes the response data of RetrieveNotificationsList (`BF2B`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure or notification.
pub fn decode_retrieve_notifications(
    data: &[u8],
) -> Result<RetrieveNotificationsResponse, DecodeError> {
    let outer = only(data, 0xBF2B)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField(
            "retrieveNotificationsListResponse",
        ));
    };
    match choice.tag {
        0x81 => Ok(RetrieveNotificationsResponse::Error(small_int(
            choice.value,
            "notificationsListResultError",
        )?)),
        0xA0 => parse(choice.value)?
            .into_iter()
            .map(|node| decode_pending_notification(node.raw))
            .collect::<Result<_, _>>()
            .map(RetrieveNotificationsResponse::Ok),
        found => Err(DecodeError::UnexpectedTag {
            context: "RetrieveNotificationsListResponse",
            found,
        }),
    }
}

/// `PrepareDownloadResponse` ([SGP.22 v2.5 §5.7.5]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareDownloadResponse {
    /// `downloadResponseOk` (`A0`).
    Ok(PrepareDownloadOk),
    /// `downloadResponseError` (`A1`).
    Error(PrepareDownloadError),
}

/// `PrepareDownloadResponseOk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareDownloadOk {
    /// `euiccSigned2`, complete DER: the exact bytes `euiccSignature2` covers.
    pub euicc_signed2: Vec<u8>,
    /// `euiccSigned2.transactionId`.
    pub transaction_id: Vec<u8>,
    /// `euiccSigned2.euiccOtpk` (otPK.EUICC.ECKA), tag `5F49`.
    pub euicc_otpk: Vec<u8>,
    /// `euiccSigned2.hashCc`, when present.
    pub hash_cc: Option<Vec<u8>>,
    /// `euiccSignature2`, tag `5F37`.
    pub euicc_signature2: Vec<u8>,
    /// Tags this decoder does not know, at either level.
    pub unknown: Vec<Unknown>,
}

/// `PrepareDownloadResponseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareDownloadError {
    /// `transactionId`.
    pub transaction_id: Vec<u8>,
    /// `downloadErrorCode`.
    pub code: DownloadErrorCode,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of PrepareDownload (`BF21`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_prepare_download(data: &[u8]) -> Result<PrepareDownloadResponse, DecodeError> {
    let outer = only(data, 0xBF21)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("downloadResponse"));
    };
    let inner = parse(choice.value)?;
    let mut unknown = Vec::new();
    match choice.tag {
        0xA0 => {
            let (mut signed, mut signature) = (None, None);
            for node in inner {
                match node.tag {
                    0x30 if signed.is_none() => signed = Some(node),
                    0x5F37 if signature.is_none() => signature = Some(node.value.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let signed = require(signed, "euiccSigned2")?;
            let (mut tid, mut otpk, mut hash) = (None, None, None);
            for node in parse(signed.value)? {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x5F49 if otpk.is_none() => otpk = Some(node.value.to_vec()),
                    0x04 if hash.is_none() => {
                        hash = Some(ranged(node.value, "hashCc", "32", 32..=32)?)
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(PrepareDownloadResponse::Ok(PrepareDownloadOk {
                euicc_signed2: signed.raw.to_vec(),
                transaction_id: require(tid, "transactionId")?,
                euicc_otpk: require(otpk, "euiccOtpk")?,
                hash_cc: hash,
                euicc_signature2: require(signature, "euiccSignature2")?,
                unknown,
            }))
        }
        0xA1 => {
            let (mut tid, mut code) = (None, None);
            for node in inner {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x02 if code.is_none() => {
                        code = Some(DownloadErrorCode::from_code(small_int(
                            node.value,
                            "downloadErrorCode",
                        )?));
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(PrepareDownloadResponse::Error(PrepareDownloadError {
                transaction_id: require(tid, "transactionId")?,
                code: require(code, "downloadErrorCode")?,
                unknown,
            }))
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "PrepareDownloadResponse",
            found,
        }),
    }
}

/// `AuthenticateServerResponse` ([SGP.22 v2.5 §5.7.13]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticateServerResponse {
    /// `authenticateResponseOk` (`A0`).
    Ok(Box<AuthenticateServerOk>),
    /// `authenticateResponseError` (`A1`).
    Error(AuthenticateServerError),
}

/// `AuthenticateResponseOk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateServerOk {
    /// `euiccSigned1`, complete DER: the exact bytes `euiccSignature1` covers.
    pub euicc_signed1: Vec<u8>,
    /// `euiccSigned1.transactionId`.
    pub transaction_id: Vec<u8>,
    /// `euiccSigned1.serverAddress`.
    pub server_address: String,
    /// `euiccSigned1.serverChallenge`.
    pub server_challenge: [u8; 16],
    /// `euiccSigned1.euiccInfo2`.
    pub euicc_info2: EuiccInfo2,
    /// `euiccSigned1.ctxParams1`, complete DER including its header.
    pub ctx_params1: Vec<u8>,
    /// `euiccSignature1`, tag `5F37`.
    pub euicc_signature1: Vec<u8>,
    /// `euiccCertificate` (CERT.EUICC.ECDSA), complete DER.
    pub euicc_certificate: Vec<u8>,
    /// `eumCertificate` (CERT.EUM.ECDSA), complete DER.
    pub eum_certificate: Vec<u8>,
    /// Tags this decoder does not know, at either level.
    pub unknown: Vec<Unknown>,
}

/// `AuthenticateResponseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateServerError {
    /// `transactionId`.
    pub transaction_id: Vec<u8>,
    /// `authenticateErrorCode`.
    pub code: AuthenticateErrorCode,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of AuthenticateServer (`BF38`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_authenticate_server(data: &[u8]) -> Result<AuthenticateServerResponse, DecodeError> {
    let outer = only(data, 0xBF38)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("authenticateServerResponse"));
    };
    let inner = parse(choice.value)?;
    let mut unknown = Vec::new();
    match choice.tag {
        0xA0 => {
            let mut signed = None;
            let mut signature = None;
            let mut certs = Vec::new();
            for node in inner {
                match node.tag {
                    0x30 if signed.is_none() => signed = Some(node),
                    0x5F37 if signature.is_none() => signature = Some(node.value.to_vec()),
                    0x30 if certs.len() < 2 => certs.push(node.raw.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let signed = require(signed, "euiccSigned1")?;
            let (mut tid, mut address, mut challenge, mut info2, mut ctx) =
                (None, None, None, None, None);
            for node in parse(signed.value)? {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x83 if address.is_none() => address = Some(utf8(node.value, "serverAddress")?),
                    0x84 if challenge.is_none() => {
                        challenge = Some(exact(node.value, "serverChallenge")?)
                    }
                    0xBF22 if info2.is_none() => {
                        info2 = Some(info2_from_nodes(parse(node.value)?)?)
                    }
                    0xA0 if ctx.is_none() => ctx = Some(node.raw.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let mut certs = certs.into_iter();
            Ok(AuthenticateServerResponse::Ok(Box::new(
                AuthenticateServerOk {
                    euicc_signed1: signed.raw.to_vec(),
                    transaction_id: require(tid, "transactionId")?,
                    server_address: require(address, "serverAddress")?,
                    server_challenge: require(challenge, "serverChallenge")?,
                    euicc_info2: require(info2, "euiccInfo2")?,
                    ctx_params1: require(ctx, "ctxParams1")?,
                    euicc_signature1: require(signature, "euiccSignature1")?,
                    euicc_certificate: require(certs.next(), "euiccCertificate")?,
                    eum_certificate: require(certs.next(), "eumCertificate")?,
                    unknown,
                },
            )))
        }
        0xA1 => {
            let (mut tid, mut code) = (None, None);
            for node in inner {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x02 if code.is_none() => {
                        code = Some(AuthenticateErrorCode::from_code(small_int(
                            node.value,
                            "authenticateErrorCode",
                        )?));
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(AuthenticateServerResponse::Error(AuthenticateServerError {
                transaction_id: require(tid, "transactionId")?,
                code: require(code, "authenticateErrorCode")?,
                unknown,
            }))
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "AuthenticateServerResponse",
            found,
        }),
    }
}

/// `CancelSessionResponse` ([SGP.22 v2.5 §5.7.14]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelSessionResponse {
    /// `cancelSessionResponseOk` (`A0`).
    Ok(CancelSessionOk),
    /// `cancelSessionResponseError` (`81`).
    Error(CancelSessionError),
}

/// `CancelSessionResponseOk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelSessionOk {
    /// `euiccCancelSessionSigned`, complete DER: what the signature covers.
    pub euicc_cancel_session_signed: Vec<u8>,
    /// `transactionId`.
    pub transaction_id: Vec<u8>,
    /// `smdpOid`, the OID content octets (not the whole TLV).
    pub smdp_oid: Vec<u8>,
    /// `reason`.
    pub reason: CancelSessionReason,
    /// `euiccCancelSessionSignature`, tag `5F37`.
    pub euicc_cancel_session_signature: Vec<u8>,
    /// Tags this decoder does not know, at either level.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of CancelSession (`BF41`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_cancel_session(data: &[u8]) -> Result<CancelSessionResponse, DecodeError> {
    let outer = only(data, 0xBF41)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("cancelSessionResponse"));
    };
    match choice.tag {
        0x81 => Ok(CancelSessionResponse::Error(CancelSessionError::from_code(
            small_int(choice.value, "cancelSessionResponseError")?,
        ))),
        0xA0 => {
            let mut unknown = Vec::new();
            let (mut signed, mut signature) = (None, None);
            for node in parse(choice.value)? {
                match node.tag {
                    0x30 if signed.is_none() => signed = Some(node),
                    0x5F37 if signature.is_none() => signature = Some(node.value.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let signed = require(signed, "euiccCancelSessionSigned")?;
            let (mut tid, mut oid, mut reason) = (None, None, None);
            for node in parse(signed.value)? {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x81 if oid.is_none() => oid = Some(node.value.to_vec()),
                    0x82 if reason.is_none() => {
                        reason = Some(CancelSessionReason::from_code(small_int(
                            node.value, "reason",
                        )?));
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(CancelSessionResponse::Ok(CancelSessionOk {
                euicc_cancel_session_signed: signed.raw.to_vec(),
                transaction_id: require(tid, "transactionId")?,
                smdp_oid: require(oid, "smdpOid")?,
                reason: require(reason, "reason")?,
                euicc_cancel_session_signature: require(signature, "euiccCancelSessionSignature")?,
                unknown,
            }))
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "CancelSessionResponse",
            found,
        }),
    }
}

/// One `ProfileInfo` (`E3`) of a GetProfilesInfo response
/// ([SGP.22 v2.5 §5.7.15]). Every field is optional: the eUICC returns only
/// the tags asked for, and omits any it does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileInfo {
    /// `iccid`, tag `5A`, as coded in EF ICCID.
    pub iccid: Option<Vec<u8>>,
    /// `isdpAid`, tag `4F`.
    pub isdp_aid: Option<Vec<u8>>,
    /// `profileState`, tag `9F70`.
    pub profile_state: Option<ProfileState>,
    /// `profileNickname`, tag `90`.
    pub profile_nickname: Option<String>,
    /// `serviceProviderName`, tag `91`.
    pub service_provider_name: Option<String>,
    /// `profileName`, tag `92`.
    pub profile_name: Option<String>,
    /// `iconType`, tag `93`.
    pub icon_type: Option<IconType>,
    /// `icon`, tag `94`.
    pub icon: Option<Vec<u8>>,
    /// `profileClass`, tag `95`.
    pub profile_class: Option<ProfileClass>,
    /// `notificationConfigurationInfo` (`B6`), contents left as DER.
    pub notification_configuration_info: Option<Vec<u8>>,
    /// `profileOwner` (`B7`), contents left as DER.
    pub profile_owner: Option<Vec<u8>>,
    /// `dpProprietaryData` (`B8`), contents left as DER.
    pub dp_proprietary_data: Option<Vec<u8>>,
    /// `profilePolicyRules`, tag `99` (`PprIds`: bit 0 pprUpdateControl, 1
    /// ppr1, 2 ppr2).
    pub profile_policy_rules: Option<BitString>,
    /// Tags this decoder does not know (for example `BF22`, service-specific
    /// data).
    pub unknown: Vec<Unknown>,
}

/// `ProfileInfoListResponse` ([SGP.22 v2.5 §5.7.15]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileInfoListResponse {
    /// `profileInfoListOk` (`A0`); empty when no profile matches.
    Ok {
        /// The profiles, in the order returned.
        profiles: Vec<ProfileInfo>,
        /// Non-`E3` tags found in the list.
        unknown: Vec<Unknown>,
    },
    /// `profileInfoListError` (`81`).
    Error(ProfileInfoListError),
}

/// Decodes the response data of GetProfilesInfo (`BF2D`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure.
pub fn decode_profiles_info(data: &[u8]) -> Result<ProfileInfoListResponse, DecodeError> {
    let outer = only(data, 0xBF2D)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("profileInfoListResponse"));
    };
    match choice.tag {
        0x81 => Ok(ProfileInfoListResponse::Error(
            ProfileInfoListError::from_code(small_int(choice.value, "profileInfoListError")?),
        )),
        0xA0 => {
            let mut profiles = Vec::new();
            let mut unknown = Vec::new();
            for node in parse(choice.value)? {
                if node.tag == 0xE3 {
                    profiles.push(decode_profile_info(node.value)?);
                } else {
                    keep(&mut unknown, node);
                }
            }
            Ok(ProfileInfoListResponse::Ok { profiles, unknown })
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "ProfileInfoListResponse",
            found,
        }),
    }
}

fn decode_profile_info(value: &[u8]) -> Result<ProfileInfo, DecodeError> {
    let mut info = ProfileInfo::default();
    for node in parse(value)? {
        let v = node.value;
        match node.tag {
            0x5A if info.iccid.is_none() => info.iccid = Some(ranged(v, "iccid", "10", 10..=10)?),
            0x4F if info.isdp_aid.is_none() => {
                info.isdp_aid = Some(ranged(v, "isdpAid", "1 to 16", 1..=16)?)
            }
            0x9F70 if info.profile_state.is_none() => {
                info.profile_state = Some(ProfileState::from_code(small_int(v, "profileState")?));
            }
            0x90 if info.profile_nickname.is_none() => {
                info.profile_nickname = Some(utf8(v, "profileNickname")?)
            }
            0x91 if info.service_provider_name.is_none() => {
                info.service_provider_name = Some(utf8(v, "serviceProviderName")?);
            }
            0x92 if info.profile_name.is_none() => {
                info.profile_name = Some(utf8(v, "profileName")?)
            }
            0x93 if info.icon_type.is_none() => {
                info.icon_type = Some(IconType::from_code(small_int(v, "iconType")?));
            }
            0x94 if info.icon.is_none() => info.icon = Some(v.to_vec()),
            0x95 if info.profile_class.is_none() => {
                info.profile_class = Some(ProfileClass::from_code(small_int(v, "profileClass")?));
            }
            0xB6 if info.notification_configuration_info.is_none() => {
                info.notification_configuration_info = Some(v.to_vec());
            }
            0xB7 if info.profile_owner.is_none() => info.profile_owner = Some(v.to_vec()),
            0xB8 if info.dp_proprietary_data.is_none() => {
                info.dp_proprietary_data = Some(v.to_vec())
            }
            0x99 if info.profile_policy_rules.is_none() => {
                info.profile_policy_rules = Some(BitString::decode(v, "profilePolicyRules")?);
            }
            _ => keep(&mut info.unknown, node),
        }
    }
    Ok(info)
}

/// `EnableProfileResponse` ([SGP.22 v2.5 §5.7.16]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableProfileResponse {
    /// `enableResult`, tag `80`.
    pub result: EnableResult,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of EnableProfile (`BF31`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_enable_profile(data: &[u8]) -> Result<EnableProfileResponse, DecodeError> {
    let (result, unknown) = result_code(data, 0xBF31, "enableResult")?;
    Ok(EnableProfileResponse {
        result: EnableResult::from_code(result),
        unknown,
    })
}

/// Decodes the response data of DisableProfile (`BF32`) into its
/// `disableResult` ([SGP.22 v2.5 §5.7.17]).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_disable_profile(data: &[u8]) -> Result<DisableResult, DecodeError> {
    result_code(data, 0xBF32, "disableResult").map(|(code, _)| DisableResult::from_code(code))
}

/// `DeleteProfileResponse` ([SGP.22 v2.5 §5.7.18]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteProfileResponse {
    /// `deleteResult`, tag `80`.
    pub result: DeleteResult,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of DeleteProfile (`BF33`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_delete_profile(data: &[u8]) -> Result<DeleteProfileResponse, DecodeError> {
    let (result, unknown) = result_code(data, 0xBF33, "deleteResult")?;
    Ok(DeleteProfileResponse {
        result: DeleteResult::from_code(result),
        unknown,
    })
}

/// Decodes the response data of eUICCMemoryReset (`BF34`): `resetResult`
/// ([SGP.22 v2.5 §5.7.19]).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_memory_reset(data: &[u8]) -> Result<ResetResult, DecodeError> {
    result_code(data, 0xBF34, "resetResult").map(|(code, _)| ResetResult::from_code(code))
}

/// Decodes the response data of RemoveNotificationFromList (`BF30`):
/// `deleteNotificationStatus` ([SGP.22 v2.5 §5.7.12]).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_remove_notification(data: &[u8]) -> Result<RemoveNotificationResult, DecodeError> {
    result_code(data, 0xBF30, "deleteNotificationStatus")
        .map(|(code, _)| RemoveNotificationResult::from_code(code))
}

fn result_code(
    data: &[u8],
    tag: u32,
    field: &'static str,
) -> Result<(u8, Vec<Unknown>), DecodeError> {
    let mut result = None;
    let mut unknown = Vec::new();
    for node in only(data, tag)? {
        match node.tag {
            0x80 if result.is_none() => result = Some(small_int(node.value, field)?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok((require(result, field)?, unknown))
}

// ---------------------------------------------------------------------------
// SGP.32, issue #229: GetCerts and GetEimConfigurationData
// ---------------------------------------------------------------------------

/// The certificates of a GetCerts response, kept whole.
///
/// Both are opaque: `GreedyBytes` in osmocom/pysim `pySim/euicc.py` lines 320
/// and 323, and [V] that is all this says about them. This crate parses
/// X.509 elsewhere, so a certificate is reported as its length and its
/// bytes and no invented parser sits between the card and the operator.
/// Either may be absent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Certificates {
    /// `eumCertificate`, tag `A5`.
    pub eum: Option<Vec<u8>>,
    /// `euiccCertificate`, tag `A6`.
    pub euicc: Option<Vec<u8>>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// `GetCertsResponse` (SGP.32 section 5.9.10, clause [U]; tags and values [V]
/// osmocom/pysim `pySim/euicc.py` lines 317-326).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetCertsResponse {
    /// The certificates the card holds.
    Ok(Certificates),
    /// `getCertsError`, tag `81`, and nothing else: the error is terminal.
    Error(GetCertsError),
}

/// Decodes the response data of GetCerts (`BF56`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure.
pub fn decode_get_certs(data: &[u8]) -> Result<GetCertsResponse, DecodeError> {
    let (mut eum, mut euicc) = (None, None);
    let mut error = None;
    let mut unknown = Vec::new();
    for node in only(data, 0xBF56)? {
        match node.tag {
            0xA5 if eum.is_none() => eum = Some(node.value.to_vec()),
            0xA6 if euicc.is_none() => euicc = Some(node.value.to_vec()),
            0x81 if error.is_none() => {
                error = Some(GetCertsError::from_code(small_int(
                    node.value,
                    "getCertsError",
                )?));
            }
            _ => keep(&mut unknown, node),
        }
    }
    if let Some(code) = error {
        return Ok(GetCertsResponse::Error(code));
    }
    Ok(GetCertsResponse::Ok(Certificates {
        eum,
        euicc,
        unknown,
    }))
}

/// Which of the two possible shapes inside the `A0` a card answered with.
///
/// pySim's `EimConfigurationData` is itself tagged `80`
/// (`pySim/euicc.py` line 344) and nests one level inside
/// `EimConfigurationDataSeq` (line 347), so its `A0` carries a single `80`
/// wrapper around the fields. SGP.32's `SEQUENCE` tag accounts for the
/// fields sitting directly in the `A0` instead. Both answers are accepted;
/// the decoder reports the one it saw instead of picking one and refusing
/// the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EimShape {
    /// `BF55 { A0 { 80 { 80 <eimId> 81 <eimFqdn> ... } } }`: pySim's
    /// `EimConfigurationData` inside `EimConfigurationDataSeq`. Primary,
    /// because pySim is the reference the issue names.
    Wrapper80,
    /// `BF55 { A0 { 80 <eimId> 81 <eimFqdn> ... } }`: the fields directly
    /// in the sequence. Fallback.
    Direct,
}

impl EimShape {
    /// The spelling used in `--json` and in the human report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wrapper80 => {
                "wrapper-80 (pySim EimConfigurationData inside EimConfigurationDataSeq)"
            }
            Self::Direct => "direct",
        }
    }
}

/// What an IoT eUICC says about the EIM it is provisioned with
/// (`EimConfigurationData`, SGP.32 section 5.9.18, clause [U]; every tag [V]
/// osmocom/pysim `pySim/euicc.py` lines 330-342).
///
/// The response carries these inside one `A0` sequence, which is decoded as
/// a tag of its own and never flattened into the response. Inside that
/// sequence they arrive either under pySim's tag-`80` wrapper or directly,
/// and [`shape`](Self::shape) says which it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EimConfigurationData {
    /// Which of the two shapes inside the `A0` this answer used; see
    /// [`EimShape`].
    pub shape: EimShape,
    /// `eimId`, tag `80`, UTF-8.
    pub eim_id: String,
    /// `eimFqdn`, tag `81`, UTF-8.
    pub eim_fqdn: String,
    /// `eimIdType`, tag `82`.
    pub eim_id_type: EimIdType,
    /// `counterValue`, tag `83`: a DER INTEGER, not a raw octet.
    pub counter_value: u64,
    /// `associationToken`, tag `84`: a DER INTEGER, not a raw octet.
    pub association_token: u64,
    /// `eimSupportedProtocol`, tag `87`, once per protocol the card supports
    /// and in the order returned: a card that supports several answers with
    /// several, so all of them are kept.
    pub supported_protocols: Vec<EimSupportedProtocol>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEimConfigurationData (`BF55`).
///
/// The fields are read from inside the `A0`, wrapped in pySim's tag-`80`
/// `EimConfigurationData` if that wrapper is there and directly if it is
/// not; [`EimConfigurationData::shape`] records which. The two are told
/// apart by their nesting, not by their tag, because the wrapper and
/// `eimId` share `80`.
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure, including a `counterValue`
/// or `associationToken` that is not a non-negative minimal DER INTEGER.
pub fn decode_get_eim_configuration_data(data: &[u8]) -> Result<EimConfigurationData, DecodeError> {
    let outer = only(data, 0xBF55)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("getEimConfigurationDataResponse"));
    };
    if choice.tag != 0xA0 {
        return Err(DecodeError::UnexpectedTag {
            context: "GetEimConfigurationDataResponse",
            found: choice.tag,
        });
    }
    let (body, shape) = unwrap_eim(choice.value);
    let (mut eim_id, mut eim_fqdn, mut id_type) = (None, None, None);
    let (mut counter, mut token) = (None, None);
    let mut protocols = Vec::new();
    let mut unknown = Vec::new();
    for node in parse(body)? {
        let v = node.value;
        match node.tag {
            0x80 if eim_id.is_none() => eim_id = Some(utf8(v, "eimId")?),
            0x81 if eim_fqdn.is_none() => eim_fqdn = Some(utf8(v, "eimFqdn")?),
            0x82 if id_type.is_none() => {
                id_type = Some(EimIdType::from_code(small_int(v, "eimIdType")?));
            }
            0x83 if counter.is_none() => counter = Some(der_integer(v, "counterValue")?),
            0x84 if token.is_none() => token = Some(der_integer(v, "associationToken")?),
            0x87 => protocols.push(EimSupportedProtocol::from_code(small_int(
                v,
                "eimSupportedProtocol",
            )?)),
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EimConfigurationData {
        shape,
        eim_id: require(eim_id, "eimId")?,
        eim_fqdn: require(eim_fqdn, "eimFqdn")?,
        eim_id_type: require(id_type, "eimIdType")?,
        counter_value: require(counter, "counterValue")?,
        association_token: require(token, "associationToken")?,
        supported_protocols: protocols,
        unknown,
    })
}

/// The body of the `A0` to decode, and the shape it came in.
///
/// pySim's `EimConfigurationData` is tagged `80` (`pySim/euicc.py` line 344)
/// and so is `EimId` (line 330), so the tag on its own decides nothing: it
/// is the nesting that does. The `A0` content is a wrapper only when it is
/// exactly one TLV, that TLV carries `80`, and its own value parses as a
/// TLV sequence whose first child carries a field tag. Everything else -
/// a lone `80` holding the UTF-8 of an EIM id, a plain field list, an
/// unparseable `80` - is the direct shape. Anything unreadable falls back
/// to the direct shape rather than erroring, so a well-formed direct answer
/// can never be lost to a misread, and no byte vector can make this loop.
fn unwrap_eim(a0: &[u8]) -> (&[u8], EimShape) {
    const FIELD_TAGS: [u32; 6] = [0x80, 0x81, 0x82, 0x83, 0x84, 0x87];
    let Ok(outer) = parse(a0) else {
        return (a0, EimShape::Direct);
    };
    let [node] = outer.as_slice() else {
        return (a0, EimShape::Direct);
    };
    if node.tag != 0x80 {
        return (a0, EimShape::Direct);
    }
    let Ok(inner) = parse(node.value) else {
        return (a0, EimShape::Direct);
    };
    match inner.first() {
        Some(first) if FIELD_TAGS.contains(&first.tag) => (node.value, EimShape::Wrapper80),
        _ => (a0, EimShape::Direct),
    }
}

/// A field whose value octets are a **DER INTEGER**, which is the one
/// encoding in this file that is not a raw octet: `02 <len> <two's
/// complement>`, so 0 is `02 01 00`, 1 is `02 01 01`, 128 is `02 02 00 80`
/// and 255 is `02 02 00 FF`. Reading `83 03 02 02 00 80` as one octet
/// instead of as the value 128 is the mistake this function exists to
/// prevent.
///
/// The envelope (identifier octet `02`, length written minimally, nothing
/// after it) is decoded by [`crate::der`], the strict reader, which is what
/// BER-TLV is not. X.690 8.3's three rules for the value are then checked
/// here, because a TLV reader does not know them: the value is not negative,
/// it is written in the shortest form, and it fits the 64 bits reported.
fn der_integer(value: &[u8], field: &'static str) -> Result<u64, DecodeError> {
    let der = crate::der::Der::decode(value).map_err(|e| DecodeError::BadDerEncoding {
        field,
        message: e.to_string(),
    })?;
    if der.tag() != 0x02 {
        return Err(DecodeError::NotAnInteger {
            field,
            found: der.tag(),
        });
    }
    let bytes = der.value();
    match bytes.split_first() {
        None => return Err(DecodeError::NegativeInteger { field }),
        Some((&high, _)) if high & 0x80 != 0 => return Err(DecodeError::NegativeInteger { field }),
        _ => {}
    }
    // A leading `00` only earns its place when the octet after it needs it.
    if bytes[0] == 0x00 && bytes.get(1).is_some_and(|next| next & 0x80 == 0) {
        return Err(DecodeError::NonMinimalInteger { field });
    }
    let magnitude = if bytes[0] == 0x00 { &bytes[1..] } else { bytes };
    if magnitude.len() > 8 {
        return Err(DecodeError::IntegerTooWide { field });
    }
    Ok(magnitude.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
}

impl fmt::Display for BitString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02X}")?;
        }
        write!(f, "/{}", self.unused_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Error as TransportError, ReaderName};
    use std::collections::VecDeque;

    // -- Test-vector provenance ------------------------------------------
    //
    // Requests, and the responses fed to the decoders, were produced by
    // compiling the SGP.22 ASN.1 module with `asn1tools` 0.169.0 and encoding
    // the values given beside each test. The module is lpac's
    // `docs/asn1/rsp.asn` at estkme-group/lpac
    // 82ada9e53251c7f0cb08bfd9060b17019a30242c (SGP.22 Annex H, v2.2 field
    // set), with the three v2.5 EUICCInfo2 fields `treProperties [13]`,
    // `treProductReference [14]` and `additionalEuiccProfilePackageVersions
    // [15]` added exactly as SGP.22 v2.5 section 5.7.8 gives them. The
    // certificate is `CERT_S_SM_DPauth_ECDSA_NIST.der` (SGP.26 v3 test PKI)
    // from osmocom/pysim 3c437d41e025b2a735e19588e937e578f17a8cd6,
    // `tests/unittests/smdpp_data/certs/DPauth/`. Spec examples are quoted
    // from SGP.22 v2.5 and marked as such. None of this is captured from a
    // card; there is no public captured ProfileInfoListResponse.

    const CERT: &str = "30820238308201DFA00302010202020100300A06082A8648CE3D04030230443110300E06035504030C07546573742043493111300F060355040B0C0854455354434552543110300E060355040A0C0752535054455354310B3009060355040613024954301E170D3230303430313038333133305A170D3330303333303038333133305A3025310D300B060355040A0C0441434D453114301206035504030C0B5445535420534D2D44502B3059301306072A8648CE3D020106082A8648CE3D030107034200044DFED4F4694791BF1695CEA0307A35B418019695387BB75B7D2447B6B5209F0445AE4E5E521CD13888D75FE07C8580222AE20DBAAC1D77CD76304993421BD739A381DF3081DC301F0603551D23041830168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3301D0603551D0E04160414BD5A82CC1A96602118BA7560A1FF83A78B210BE5300E0603551D1104073005880388370A300E0603551D0F0101FF04040302078030170603551D200101FF040D300B300906076781120102010430610603551D1F045A3058302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D412E63726C302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D422E63726C300A06082A8648CE3D040302034700304402200823EE7DFA5E3DD07838E930F81BC34AE99F06CBA35927FE9E502C464DC1FEE302200D2D4087DB01A5382D21690AC0488B15067FB2460D336332446CA99F08A8A4EF";
    const TID: &str = "0102030405060708090A0B0C0D0E0F10";
    const ICCID: &str = "98001032547698103214";
    const AID: &str = "A0000005591010FFFFFFFF8900001000";
    const SKI: &str = "81370F5125D0B1D408D4C3B232E6D25E795BEBFB";

    fn h(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str.replace(' ', "")).unwrap()
    }

    fn cat(parts: &[&str]) -> Vec<u8> {
        h(&parts.concat())
    }

    // -- Segmentation ----------------------------------------------------

    fn reassembled(commands: &[Command]) -> Vec<u8> {
        commands.iter().flat_map(|c| c.data().to_vec()).collect()
    }

    #[test]
    fn one_block_is_the_get_eid_frame_pysim_uses() {
        // osmocom/pysim 3c437d41 tests/unittests/test_globalplatform.py:88,
        // `get_eid_cmd_plain` (GetEID, ES10c, BF3E 03 5C 01 5A).
        let data = h("BF3E035C015A");
        let sent = blocks(0x80, &data).unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].encode().unwrap(), h("80E2910006BF3E035C015A00"));
        // Same file: tests/pySim-shell_test/utils.py:126 uses CLA 81
        // (logical channel 1), here with the Le Table 47 requires.
        let channel = blocks(0x81, &data).unwrap();
        assert_eq!(channel[0].encode().unwrap(), h("81E2910006BF3E035C015A00"));
    }

    #[test]
    fn block_counts_at_the_255_boundaries() {
        for (len, expect) in [
            (1usize, vec![1usize]),
            (254, vec![254]),
            (255, vec![255]),
            (256, vec![255, 1]),
            (510, vec![255, 255]),
            (511, vec![255, 255, 1]),
            (5000, [vec![255; 19], vec![155]].concat()),
        ] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let cmds = blocks(0x80, &data).unwrap();
            let sizes: Vec<usize> = cmds.iter().map(|c| c.data().len()).collect();
            assert_eq!(sizes, expect, "len {len}");
            assert_eq!(reassembled(&cmds), data, "len {len}");
            for (i, cmd) in cmds.iter().enumerate() {
                let last = i + 1 == cmds.len();
                let header = cmd.header();
                assert_eq!(header.instruction(), INS_STORE_DATA);
                assert_eq!(
                    header.parameter_1(),
                    if last { 0x91 } else { 0x11 },
                    "len {len} block {i}"
                );
                assert_eq!(header.parameter_2(), i as u8);
                assert_eq!(cmd.le(), Some(Le::Short(0)));
            }
        }
    }

    #[test]
    fn exactly_256_blocks_fit_and_one_more_byte_does_not() {
        let fits = vec![0xAB; 255 * 256];
        let cmds = blocks(0x80, &fits).unwrap();
        assert_eq!(cmds.len(), 256);
        assert_eq!(cmds[255].header().parameter_2(), 0xFF);
        assert_eq!(cmds[255].header().parameter_1(), 0x91);
        let too_big = vec![0xAB; 255 * 256 + 1];
        assert_eq!(
            blocks(0x80, &too_big),
            Err(EncodeError::TooManyBlocks {
                bytes: 255 * 256 + 1,
                blocks: 257
            })
        );
    }

    #[test]
    fn class_and_empty_data_are_refused() {
        for cla in [0x80, 0x81, 0x82, 0x83, 0xC0, 0xCF] {
            assert!(is_valid_class(cla));
            assert!(blocks(cla, &[1]).is_ok());
        }
        for cla in [0x00, 0x7F, 0x84, 0xA0, 0xBF, 0xD0, 0xFF] {
            assert_eq!(blocks(cla, &[1]), Err(EncodeError::BadClass(cla)));
        }
        assert_eq!(blocks(0x80, &[]), Err(EncodeError::EmptyData));
    }

    #[test]
    fn each_bpp_segment_restarts_block_numbering() {
        let big: Vec<u8> = (0..600).map(|i| i as u8).collect();
        let segments = vec![vec![0xBF, 0x36, 0x03], big.clone(), vec![0x87, 0x01, 0x02]];
        let all = bpp_blocks(0x80, &segments).unwrap();
        assert_eq!(all.len(), 3);
        for (segment, cmds) in segments.iter().zip(&all) {
            assert_eq!(&reassembled(cmds), segment);
            assert_eq!(cmds[0].header().parameter_2(), 0);
            let last = cmds.last().unwrap().header();
            assert_eq!(last.parameter_1(), 0x91);
            assert_eq!(usize::from(last.parameter_2()), cmds.len() - 1);
        }
        assert_eq!(all[1].len(), 3);
        assert_eq!(all[1][0].header().parameter_1(), 0x11);
    }

    // -- Sending ---------------------------------------------------------

    struct Scripted {
        reader: ReaderName,
        replies: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Scripted {
        fn new(replies: Vec<Vec<u8>>) -> Self {
            Self {
                reader: ReaderName::new("scripted eUICC").unwrap(),
                replies: replies.into(),
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
            Ok(self.replies.pop_front().unwrap_or_else(|| vec![0x90, 0x00]))
        }
        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn channel_policy() -> Policy {
        Policy {
            get_response_class: 0x00,
            ..Policy::default()
        }
    }

    #[test]
    fn many_blocks_reach_the_card_in_order_and_reassemble() {
        let data: Vec<u8> = (0..700).map(|i| (i % 251) as u8).collect();
        let mut card = Scripted::new(vec![]);
        let sent = store_data(&mut card, 0x80, &data, &channel_policy()).unwrap();
        assert!(sent.complete);
        assert_eq!(sent.exchanges.len(), 3);
        let on_wire: Vec<u8> = card
            .sent
            .iter()
            .flat_map(|apdu| {
                // header 4, Lc, data, Le
                apdu[5..apdu.len() - 1].to_vec()
            })
            .collect();
        assert_eq!(on_wire, data);
        let p1p2: Vec<(u8, u8)> = card.sent.iter().map(|a| (a[2], a[3])).collect();
        assert_eq!(p1p2, vec![(0x11, 0), (0x11, 1), (0x91, 2)]);
        assert!(card
            .sent
            .iter()
            .all(|a| a[0] == 0x80 && a[1] == 0xE2 && *a.last().unwrap() == 0));
    }

    #[test]
    fn a_61xx_on_the_last_block_is_followed_with_get_response() {
        // A GetEUICCChallenge response read back through GET RESPONSE.
        let response = h("BF2E128010A0A1A2A3A4A5A6A7A8A9AAABACADAEAF");
        let mut reply = response.clone();
        reply.extend_from_slice(&[0x90, 0x00]);
        let mut card = Scripted::new(vec![vec![0x61, response.len() as u8], reply]);
        let sent = store_data(
            &mut card,
            0x80,
            &get_euicc_challenge_request(),
            &channel_policy(),
        )
        .unwrap();
        assert!(sent.complete);
        assert_eq!(sent.data(), response.as_slice());
        assert_eq!(card.sent[0], h("80E291 00 03 BF2E00 00"));
        assert_eq!(card.sent[1], h("00C0000015"));
        assert_eq!(
            decode_get_euicc_challenge(sent.data()).unwrap().challenge[0],
            0xA0
        );
    }

    #[test]
    fn a_refused_intermediate_block_stops_the_sequence() {
        let mut card = Scripted::new(vec![vec![0x6A, 0x88]]);
        let sent = store_data(&mut card, 0x80, &[0u8; 600], &channel_policy()).unwrap();
        assert!(!sent.complete);
        assert_eq!(sent.exchanges.len(), 1);
        assert_eq!(card.sent.len(), 1, "no block after a refusal");
    }

    #[test]
    fn load_bound_profile_package_sends_segments_and_stops_on_refusal() {
        let segments = vec![vec![1u8; 10], vec![2u8; 300], vec![3u8; 5]];
        let mut card = Scripted::new(vec![]);
        let sent =
            load_bound_profile_package(&mut card, 0x80, &segments, &channel_policy()).unwrap();
        assert_eq!(sent.len(), 3);
        // 1 + 2 + 1 blocks, with P2 restarting at each segment.
        let p2: Vec<u8> = card.sent.iter().map(|a| a[3]).collect();
        assert_eq!(p2, vec![0, 0, 1, 0]);
        let p1: Vec<u8> = card.sent.iter().map(|a| a[2]).collect();
        assert_eq!(p1, vec![0x91, 0x11, 0x91, 0x91]);

        let mut card = Scripted::new(vec![vec![0x90, 0x00], vec![0x69, 0x85]]);
        let sent =
            load_bound_profile_package(&mut card, 0x80, &segments, &channel_policy()).unwrap();
        assert_eq!(sent.len(), 2, "the third segment is not sent after a 6985");
    }

    // -- Request encoders ------------------------------------------------

    #[test]
    fn argument_free_requests() {
        assert_eq!(get_euicc_challenge_request(), h("BF2E00"));
        assert_eq!(get_euicc_info1_request(), h("BF2000"));
        assert_eq!(get_euicc_info2_request(), h("BF2200"));
    }

    #[test]
    fn cancel_session_request_bytes() {
        let tid = h(TID);
        assert_eq!(
            cancel_session_request(&tid, CancelSessionReason::EndUserRejection).unwrap(),
            cat(&["BF4115 8010", TID, "810100"])
        );
        assert_eq!(
            cancel_session_request(&tid, CancelSessionReason::UndefinedReason).unwrap(),
            cat(&["BF4115 8010", TID, "81017F"])
        );
        assert!(cancel_session_request(&[], CancelSessionReason::Timeout).is_err());
        assert!(cancel_session_request(&[0; 17], CancelSessionReason::Timeout).is_err());
    }

    #[test]
    fn enable_and_delete_request_bytes() {
        let (iccid, aid) = (h(ICCID), h(AID));
        assert_eq!(
            enable_profile_request(ProfileIdentifier::Iccid(&iccid), true).unwrap(),
            cat(&["BF3111 A00C 5A0A", ICCID, "8101FF"])
        );
        assert_eq!(
            enable_profile_request(ProfileIdentifier::IsdpAid(&aid), false).unwrap(),
            cat(&["BF3117 A012 4F10", AID, "810100"])
        );
        assert_eq!(
            delete_profile_request(ProfileIdentifier::Iccid(&iccid)).unwrap(),
            cat(&["BF330C 5A0A", ICCID])
        );
        assert_eq!(
            delete_profile_request(ProfileIdentifier::IsdpAid(&aid)).unwrap(),
            cat(&["BF3312 4F10", AID])
        );
        assert!(delete_profile_request(ProfileIdentifier::Iccid(&iccid[..9])).is_err());
        assert!(delete_profile_request(ProfileIdentifier::IsdpAid(&[])).is_err());
        assert!(delete_profile_request(ProfileIdentifier::IsdpAid(&[0; 17])).is_err());
    }

    #[test]
    fn get_profiles_info_request_matches_the_spec_examples() {
        // SGP.22 v2.5 section 5.7.15, "Example of use", verbatim.
        assert_eq!(get_profiles_info_request(None, None).unwrap(), h("BF2D 00"));
        let aid = h("A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 10 00");
        assert_eq!(
            get_profiles_info_request(
                Some(SearchCriteria::IsdpAid(&aid)),
                Some(&[0x5A, 0x4F, 0x9F70, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xB6, 0xB7, 0xB8, 0x99]),
            )
            .unwrap(),
            h("BF2D 24 A0 12 4F 10 A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 10 00 5C 0E 5A 4F 9F70 90 91 92 93 94 95 B6 B7 B8 99")
        );
        assert_eq!(
            get_profiles_info_request(None, Some(&[0x5A, 0x9F70])).unwrap(),
            h("BF 2D 05 5C 03 5A 9F70")
        );
    }

    #[test]
    fn get_profiles_info_request_other_criteria() {
        let iccid = h(ICCID);
        assert_eq!(
            get_profiles_info_request(Some(SearchCriteria::Iccid(&iccid)), None).unwrap(),
            cat(&["BF2D0E A00C 5A0A", ICCID])
        );
        assert_eq!(
            get_profiles_info_request(
                Some(SearchCriteria::ProfileClass(ProfileClass::Operational)),
                Some(&[0x5A, 0x9F70])
            )
            .unwrap(),
            h("BF2D0A A003 950102 5C03 5A9F70")
        );
    }

    #[test]
    fn prepare_download_request_bytes() {
        let signed2 = cat(&[
            "305980",
            "10",
            TID,
            "0101FF5F4941",
            (1..=0x41)
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
                .as_str(),
        ]);
        let sig2: Vec<u8> = (0x10..0x50).collect();
        let hash: Vec<u8> = (0x60..0x80).collect();
        let cert = h(CERT);
        let with = PrepareDownloadRequest {
            smdp_signed2: &signed2,
            smdp_signature2: &sig2,
            hash_cc: Some(&hash),
            smdp_certificate: &cert,
        };
        let expected = cat(&[
            "BF218202FC",
            &hex::encode_upper(&signed2),
            "5F3740",
            &hex::encode_upper(&sig2),
            "0420",
            &hex::encode_upper(&hash),
            CERT,
        ]);
        assert_eq!(with.encode().unwrap(), expected);
        let without = PrepareDownloadRequest {
            hash_cc: None,
            ..with
        };
        let expected = cat(&[
            "BF218202DA",
            &hex::encode_upper(&signed2),
            "5F3740",
            &hex::encode_upper(&sig2),
            CERT,
        ]);
        assert_eq!(without.encode().unwrap(), expected);
        assert!(PrepareDownloadRequest {
            hash_cc: Some(&hash[..31]),
            ..with
        }
        .encode()
        .is_err());
    }

    #[test]
    fn authenticate_server_request_bytes() {
        let server_signed1 = cat(&[
            "304880 10",
            TID,
            "8110 202122232425262728292A2B2C2D2E2F",
            "8310 736D64702E6578616D706C652E636F6D",
            "8410 404142434445464748494A4B4C4D4E4F",
        ]);
        let ctx = h("A01380074D415443482D31A108800435290611A100");
        let sig: Vec<u8> = (0x80..0xC0).collect();
        let (ski, cert) = (h(SKI), h(CERT));
        let request = AuthenticateServerRequest {
            server_signed1: &server_signed1,
            server_signature1: &sig,
            euicc_ci_pk_id_to_be_used: &ski,
            server_certificate: &cert,
            ctx_params1: &ctx,
        };
        let expected = cat(&[
            "BF388202F4",
            &hex::encode_upper(&server_signed1),
            "5F3740",
            &hex::encode_upper(&sig),
            "0414",
            SKI,
            CERT,
            "A01380074D415443482D31A108800435290611A100",
        ]);
        assert_eq!(request.encode(), expected);
    }

    // -- Response decoders -----------------------------------------------

    #[test]
    fn challenge_response() {
        let data = h("BF2E128010A0A1A2A3A4A5A6A7A8A9AAABACADAEAF");
        let got = decode_get_euicc_challenge(&data).unwrap();
        assert_eq!(got.challenge.to_vec(), (0xA0..=0xAF).collect::<Vec<u8>>());
        assert!(got.unknown.is_empty());
        assert!(decode_get_euicc_challenge(&h("BF2E03 800100")).is_err());
        assert!(decode_get_euicc_challenge(&h("BF2000")).is_err());
        assert!(matches!(
            decode_get_euicc_challenge(&h("BF2E00")),
            Err(DecodeError::MissingField("euiccChallenge"))
        ));
    }

    #[test]
    fn euicc_info1_response() {
        let data = cat(&[
            "BF204B 8203020500 A92C 0414",
            SKI,
            "0414 000102030405060708090A0B0C0D0E0F10111213 AA16 0414",
            SKI,
        ]);
        let got = decode_euicc_info1(&data).unwrap();
        assert_eq!(got.svn, [2, 5, 0]);
        assert_eq!(
            got.ci_pk_id_for_verification,
            vec![h(SKI), (0..20).collect::<Vec<u8>>()]
        );
        assert_eq!(got.ci_pk_id_for_signing, vec![h(SKI)]);
        assert!(got.unknown.is_empty());
    }

    /// The GetEUICCInfo2 response in lpac's stdio driver documentation,
    /// estkme-group/lpac 82ada9e53251c7f0cb08bfd9060b17019a30242c
    /// `driver/apdu/stdio.c:205`, status word removed.
    const LPAC_INFO2: &str = "BF2281C6810302010082030202008303040600840F8101008204000628248304000019228504067F36C08603090200870302030088020490A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB990206C004030000010C0D47492D42412D55502D30343139AC48801F312E322E3834302E313233343536372F6D79506C6174666F726D4C6162656C812568747470733A2F2F6D79636F6D70616E792E636F6D2F6D79444C4F41526567697374726172";

    #[test]
    fn euicc_info2_from_a_published_response() {
        let data = h(LPAC_INFO2);
        assert_eq!(data.len(), 202);
        let got = decode_euicc_info2(&data).unwrap();
        // Field values cross-checked against asn1tools decoding the same
        // bytes with the Annex H module.
        assert_eq!(got.profile_version, [2, 1, 0]);
        assert_eq!(got.svn, [2, 2, 0]);
        assert_eq!(got.euicc_firmware_ver, [4, 6, 0]);
        assert_eq!(got.ext_card_resource, h("8101008204000628248304000019 22"));
        assert_eq!(
            got.uicc_capability,
            BitString {
                unused_bits: 6,
                bytes: h("7F36C0")
            }
        );
        assert_eq!(got.ts102241_version, Some([9, 2, 0]));
        assert_eq!(got.globalplatform_version, Some([2, 3, 0]));
        assert_eq!(
            got.rsp_capability,
            BitString {
                unused_bits: 4,
                bytes: vec![0x90]
            }
        );
        assert!(got.rsp_capability.bit(0), "additionalProfile");
        assert!(!got.rsp_capability.bit(1), "crlSupport");
        assert!(got.rsp_capability.bit(3), "testProfileSupport");
        assert!(!got.rsp_capability.bit(4), "past the end of the named bits");
        assert_eq!(got.ci_pk_id_for_verification, vec![h(SKI)]);
        assert_eq!(got.ci_pk_id_for_signing, vec![h(SKI)]);
        assert_eq!(got.euicc_category, None);
        let ppr = got.forbidden_profile_policy_rules.unwrap();
        assert!(
            ppr.bit(0) && ppr.bit(1) && !ppr.bit(2),
            "pprUpdateControl and ppr1"
        );
        assert_eq!(got.pp_version, [0, 0, 1]);
        assert_eq!(got.sas_accreditation_number, "GI-BA-UP-0419");
        assert_eq!(
            got.certification_data_object,
            Some(CertificationDataObject {
                platform_label: "1.2.840.1234567/myPlatformLabel".into(),
                discovery_base_url: "https://mycompany.com/myDLOARegistrar".into(),
            })
        );
        assert!(got.unknown.is_empty());
    }

    const INFO2_V25: &str = "BF2281B781030201008203020500830304060084158101008204000628248304000019228504067F36C0850200FF86030300008703020301880204B0A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB8B0102990202C004030000010C0D47492D42412D55502D30343139AC1E80056C6162656C811568747470733A2F2F646C6F612E6578616D706C652F8D0205408E075452452D524546AF050403030200";

    #[test]
    fn euicc_info2_with_the_v25_fields() {
        let got = decode_euicc_info2(&h(INFO2_V25)).unwrap();
        assert_eq!(got.euicc_category, Some(EuiccCategory::MediumEuicc));
        assert_eq!(
            got.tre_properties,
            Some(BitString {
                unused_bits: 5,
                bytes: vec![0x40]
            })
        );
        assert!(got.tre_properties.as_ref().unwrap().bit(1), "isIntegrated");
        assert_eq!(got.tre_product_reference.as_deref(), Some("TRE-REF"));
        assert_eq!(
            got.additional_euicc_profile_package_versions,
            vec![[3, 2, 0]]
        );
        assert_eq!(
            got.rsp_capability,
            BitString {
                unused_bits: 4,
                bytes: vec![0xB0]
            }
        );
        assert!(
            got.rsp_capability.bit(0) && got.rsp_capability.bit(2) && got.rsp_capability.bit(3)
        );
    }

    #[test]
    fn unknown_tags_are_kept_not_dropped() {
        // INFO2_V25 with an extra `9F 8F 01 02 AA BB` and a repeated `82`
        // appended inside BF22 (length 0xB7 grows by 6 + 5).
        let mut data = h(INFO2_V25);
        data[3] += 11;
        data.extend_from_slice(&h("9F8F0102AABB 8203010203"));
        // 0xB7 + 11 = 0xC2, still a one-octet 0x81 length.
        let got = decode_euicc_info2(&data).unwrap();
        assert_eq!(
            got.unknown,
            vec![
                Unknown {
                    tag: 0x9F8F01,
                    value: vec![0xAA, 0xBB]
                },
                Unknown {
                    tag: 0x82,
                    value: vec![1, 2, 3]
                },
            ]
        );
        assert_eq!(got.svn, [2, 5, 0], "the first of a repeated field wins");
    }

    #[test]
    fn info2_rejects_damage() {
        let data = h(INFO2_V25);
        for cut in [1, 3, 10, data.len() - 1] {
            assert!(decode_euicc_info2(&data[..cut]).is_err(), "cut at {cut}");
        }
        // BF22 with only a version: mandatory fields missing.
        assert!(matches!(
            decode_euicc_info2(&h("BF2205 8103020100")),
            Err(DecodeError::MissingField("svn"))
        ));
        let mut trailing = data.clone();
        trailing.extend_from_slice(&[0, 0]);
        assert!(matches!(
            decode_euicc_info2(&trailing),
            Err(DecodeError::TrailingData(2))
        ));
        assert!(matches!(
            decode_euicc_info1(&data),
            Err(DecodeError::WrongTag { .. })
        ));
    }

    #[test]
    fn prepare_download_responses() {
        let ok = cat(&[
            "BF2181C0 A081BD 3078 8010", TID,
            "5F4941 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041",
            "0420 606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "5F3740 101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
        ]);
        let PrepareDownloadResponse::Ok(got) = decode_prepare_download(&ok).unwrap() else {
            panic!("expected Ok");
        };
        assert_eq!(got.transaction_id, h(TID));
        assert_eq!(got.euicc_otpk, (1..=0x41).collect::<Vec<u8>>());
        assert_eq!(got.hash_cc, Some((0x60..0x80).collect()));
        assert_eq!(got.euicc_signature2, (0x10..0x50).collect::<Vec<u8>>());
        assert_eq!(got.euicc_signed2.len(), 2 + 0x78);
        assert_eq!(&got.euicc_signed2[..2], &[0x30, 0x78]);
        assert!(got.unknown.is_empty());

        let error = cat(&["BF2117 A115 8010", TID, "020102"]);
        assert_eq!(
            decode_prepare_download(&error).unwrap(),
            PrepareDownloadResponse::Error(PrepareDownloadError {
                transaction_id: h(TID),
                code: DownloadErrorCode::InvalidSignature,
                unknown: vec![],
            })
        );
    }

    #[test]
    fn authenticate_server_responses() {
        let sig: Vec<u8> = (0x80..0xC0).collect();
        let euicc_signed1_inner = cat(&[
            "8010",
            TID,
            "8310 736D64702E6578616D706C652E636F6D",
            "8410 404142434445464748494A4B4C4D4E4F",
            INFO2_V25,
            "A01380074D415443482D31A108800435290611A100",
        ]);
        let signed1 = [
            vec![
                0x30,
                0x82,
                (euicc_signed1_inner.len() >> 8) as u8,
                euicc_signed1_inner.len() as u8,
            ],
            euicc_signed1_inner,
        ]
        .concat();
        assert_eq!(signed1.len(), 4 + 0x106);
        let inner = cat(&[
            &hex::encode_upper(&signed1),
            "5F3740",
            &hex::encode_upper(&sig),
            CERT,
            CERT,
        ]);
        let data = [
            vec![
                0xBF,
                0x38,
                0x82,
                ((inner.len() + 4) >> 8) as u8,
                (inner.len() + 4) as u8,
                0xA0,
                0x82,
                (inner.len() >> 8) as u8,
                inner.len() as u8,
            ],
            inner,
        ]
        .concat();
        assert_eq!(data.len(), 1486, "BF38 8205C9 A0 8205C5 ...");
        let AuthenticateServerResponse::Ok(got) = decode_authenticate_server(&data).unwrap() else {
            panic!("expected Ok");
        };
        assert_eq!(got.transaction_id, h(TID));
        assert_eq!(got.server_address, "smdp.example.com");
        assert_eq!(
            got.server_challenge.to_vec(),
            (0x40..0x50).collect::<Vec<u8>>()
        );
        assert_eq!(got.euicc_info2.svn, [2, 5, 0]);
        assert_eq!(
            got.euicc_info2.tre_product_reference.as_deref(),
            Some("TRE-REF")
        );
        assert_eq!(
            got.ctx_params1,
            h("A01380074D415443482D31A108800435290611A100")
        );
        assert_eq!(got.euicc_signature1, sig);
        assert_eq!(got.euicc_signed1, signed1);
        assert_eq!(got.euicc_certificate, h(CERT));
        assert_eq!(got.eum_certificate, h(CERT));
        assert!(got.unknown.is_empty());

        let error = cat(&["BF3817 A115 8010", TID, "020106"]);
        assert_eq!(
            decode_authenticate_server(&error).unwrap(),
            AuthenticateServerResponse::Error(AuthenticateServerError {
                transaction_id: h(TID),
                code: AuthenticateErrorCode::EuiccChallengeMismatch,
                unknown: vec![],
            })
        );
    }

    #[test]
    fn cancel_session_responses() {
        let sig: Vec<u8> = (0x10..0x50).collect();
        let ok = cat(&[
            "BF4161 A05F 301A 8010",
            TID,
            "810388370A 820101",
            "5F3740",
            &hex::encode_upper(&sig),
        ]);
        let CancelSessionResponse::Ok(got) = decode_cancel_session(&ok).unwrap() else {
            panic!("expected Ok");
        };
        assert_eq!(got.transaction_id, h(TID));
        assert_eq!(got.smdp_oid, h("88370A"));
        assert_eq!(got.reason, CancelSessionReason::Postponed);
        assert_eq!(got.euicc_cancel_session_signature, sig);
        assert_eq!(got.euicc_cancel_session_signed.len(), 2 + 0x1A);

        assert_eq!(
            decode_cancel_session(&h("BF4103 810105")).unwrap(),
            CancelSessionResponse::Error(CancelSessionError::InvalidTransactionId)
        );
    }

    #[test]
    fn profiles_info_responses() {
        // asn1tools encoding of ProfileInfoListResponse with two profiles.
        let data = cat(&[
            "BF2D5E A05C E348 5A0A", ICCID, "4F10", AID,
            "9F7001 01 9004 6E69636B 9108 4F70657261746F72 9204 50726F66 9301 01 9404 89504E47 9501 02 9902 0540",
            "E310 5A0A 98001032547698103215 9F7001 00",
        ]);
        let ProfileInfoListResponse::Ok { profiles, unknown } =
            decode_profiles_info(&data).unwrap()
        else {
            panic!("expected Ok");
        };
        assert!(unknown.is_empty());
        assert_eq!(profiles.len(), 2);
        let first = &profiles[0];
        assert_eq!(first.iccid, Some(h(ICCID)));
        assert_eq!(first.isdp_aid, Some(h(AID)));
        assert_eq!(first.profile_state, Some(ProfileState::Enabled));
        assert_eq!(first.profile_nickname.as_deref(), Some("nick"));
        assert_eq!(first.service_provider_name.as_deref(), Some("Operator"));
        assert_eq!(first.profile_name.as_deref(), Some("Prof"));
        assert_eq!(first.icon_type, Some(IconType::Png));
        assert_eq!(first.icon, Some(h("89504E47")));
        assert_eq!(first.profile_class, Some(ProfileClass::Operational));
        assert!(first.profile_policy_rules.as_ref().unwrap().bit(1), "ppr1");
        assert_eq!(profiles[1].iccid, Some(h("98001032547698103215")));
        assert_eq!(profiles[1].profile_state, Some(ProfileState::Disabled));
        assert_eq!(profiles[1].profile_name, None);

        assert_eq!(
            decode_profiles_info(&h("BF2D02 A000")).unwrap(),
            ProfileInfoListResponse::Ok {
                profiles: vec![],
                unknown: vec![]
            }
        );
        assert_eq!(
            decode_profiles_info(&h("BF2D03 810101")).unwrap(),
            ProfileInfoListResponse::Error(ProfileInfoListError::IncorrectInputValues)
        );
    }

    #[test]
    fn profile_info_keeps_tags_it_does_not_know() {
        // `BF22` (service-specific data) is in the 5.7.15 tag list and is not
        // modelled; it must survive.
        let data = cat(&["BF2D13 A011 E30F 5A0A", ICCID, "BF2200"]);
        let ProfileInfoListResponse::Ok { profiles, .. } = decode_profiles_info(&data).unwrap()
        else {
            panic!("expected Ok");
        };
        assert_eq!(
            profiles[0].unknown,
            vec![Unknown {
                tag: 0xBF22,
                value: vec![]
            }]
        );
    }

    #[test]
    fn enable_and_delete_responses() {
        assert_eq!(
            decode_enable_profile(&h("BF3103 800100")).unwrap().result,
            EnableResult::Ok
        );
        assert_eq!(
            decode_enable_profile(&h("BF3103 800102")).unwrap().result,
            EnableResult::ProfileNotInDisabledState
        );
        assert_eq!(
            decode_enable_profile(&h("BF3103 80017F")).unwrap().result,
            EnableResult::UndefinedError
        );
        assert_eq!(
            decode_enable_profile(&h("BF3103 800163")).unwrap().result,
            EnableResult::Unknown(0x63)
        );
        assert_eq!(
            decode_delete_profile(&h("BF3303 800100")).unwrap().result,
            DeleteResult::Ok
        );
        assert_eq!(
            decode_delete_profile(&h("BF3303 800103")).unwrap().result,
            DeleteResult::DisallowedByPolicy
        );
        assert!(decode_delete_profile(&h("BF3100")).is_err());
        assert!(matches!(
            decode_delete_profile(&h("BF3300")),
            Err(DecodeError::MissingField("deleteResult"))
        ));
        let extra = decode_enable_profile(&h("BF3106 800100 840100")).unwrap();
        assert_eq!(
            extra.unknown,
            vec![Unknown {
                tag: 0x84,
                value: vec![0]
            }]
        );
    }

    #[test]
    fn code_enums_round_trip_every_code() {
        for code in 0..=255u8 {
            assert_eq!(CancelSessionReason::from_code(code).code(), code);
            assert_eq!(EnableResult::from_code(code).code(), code);
            assert_eq!(ProfileClass::from_code(code).code(), code);
        }
    }

    #[test]
    fn ber_reader_handles_the_length_forms() {
        let long = [vec![0x04, 0x81, 0x80], vec![7; 128]].concat();
        assert_eq!(parse(&long).unwrap()[0].value.len(), 128);
        let longer = [vec![0x04, 0x82, 0x01, 0x00], vec![7; 256]].concat();
        assert_eq!(parse(&longer).unwrap()[0].value.len(), 256);
        assert_eq!(
            parse(&h("04 80 00 00")).err(),
            Some(DecodeError::UnsupportedLength(0x80))
        );
        assert!(matches!(
            parse(&h("04 05 01")),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(matches!(
            parse(&h("BF")),
            Err(DecodeError::Truncated { .. })
        ));
        assert_eq!(tlv(0xBF2D, &[0u8; 200])[..4], [0xBF, 0x2D, 0x81, 200]);
    }

    #[test]
    fn set_nickname_request_and_response() {
        let iccid = h("98 00 10 32 54 76 98 10 32 14");
        assert_eq!(
            set_nickname_request(&iccid, "nick").unwrap(),
            h("BF29 12 5A0A 98001032547698103214 9004 6E69636B")
        );
        // An empty nickname clears it.
        assert_eq!(
            set_nickname_request(&iccid, "").unwrap(),
            h("BF29 0E 5A0A 98001032547698103214 9000")
        );
        assert!(set_nickname_request(&iccid[..9], "x").is_err());
        assert!(set_nickname_request(&iccid, &"a".repeat(65)).is_err());
        assert!(set_nickname_request(&iccid, &"a".repeat(64)).is_ok());
        assert_eq!(
            decode_set_nickname(&h("BF29 03 80 01 00")).unwrap(),
            SetNicknameResult::Ok
        );
        assert_eq!(
            decode_set_nickname(&h("BF29 03 80 01 01")).unwrap(),
            SetNicknameResult::IccidNotFound
        );
        assert!(decode_set_nickname(&h("BF29 00")).is_err());
    }

    #[test]
    fn enable_and_disable_requests_and_disable_response() {
        let iccid = h("98 00 10 32 54 76 98 10 32 14");
        let aid = h("A0000005591010FFFFFFFF8900001000");
        // Hand-written from pySim rsp.asn + lpac es10c.c: BFxx { A0 { 5A|4F id } 81 01 FF|00 }.
        assert_eq!(
            enable_profile_request(ProfileIdentifier::Iccid(&iccid), true).unwrap(),
            h("BF31 11 A0 0C 5A0A 98001032547698103214 81 01 FF")
        );
        assert_eq!(
            disable_profile_request(ProfileIdentifier::Iccid(&iccid), false).unwrap(),
            h("BF32 11 A0 0C 5A0A 98001032547698103214 81 01 00")
        );
        assert_eq!(
            enable_profile_request(ProfileIdentifier::IsdpAid(&aid), true).unwrap(),
            h("BF31 17 A0 12 4F10 A0000005591010FFFFFFFF8900001000 81 01 FF")
        );
        assert!(disable_profile_request(ProfileIdentifier::Iccid(&iccid[..9]), true).is_err());
        assert!(disable_profile_request(ProfileIdentifier::IsdpAid(&[0; 17]), true).is_err());
        for (code, want) in [
            ("00", DisableResult::Ok),
            ("01", DisableResult::IccidOrAidNotFound),
            ("02", DisableResult::ProfileNotInEnabledState),
            ("03", DisableResult::DisallowedByPolicy),
            ("05", DisableResult::CatBusy),
            ("7F", DisableResult::UndefinedError),
            ("63", DisableResult::Unknown(0x63)),
        ] {
            assert_eq!(
                decode_disable_profile(&h(&format!("BF32 03 80 01 {code}"))).unwrap(),
                want
            );
        }
        assert!(decode_disable_profile(&h("BF32 00")).is_err());
        assert!(decode_disable_profile(&h("BF31 03 80 01 00")).is_err());
    }

    #[test]
    fn delete_reset_and_remove_notification_frames_and_results() {
        // Hand-written from pySim rsp.asn + lpac es10b.c / es10c.c.
        assert_eq!(remove_notification_request(5), h("BF30 03 80 01 05"));
        assert_eq!(remove_notification_request(0x80), h("BF30 04 80 02 0080"));
        assert_eq!(remove_notification_request(0x1234), h("BF30 04 80 02 1234"));
        assert_eq!(remove_notification_request(0), h("BF30 03 80 01 00"));
        let opts = |a, b, c| ResetOptions {
            delete_operational_profiles: a,
            delete_field_loaded_test_profiles: b,
            reset_default_smdp_address: c,
        };
        for (o, want) in [
            (opts(true, true, true), "BF34 04 82 02 05E0"),
            (opts(true, false, false), "BF34 04 82 02 0780"),
            (opts(false, true, false), "BF34 04 82 02 0640"),
            (opts(false, false, true), "BF34 04 82 02 0520"),
            (opts(true, false, true), "BF34 04 82 02 05A0"),
            (opts(true, true, false), "BF34 04 82 02 06C0"),
        ] {
            assert_eq!(memory_reset_request(o).unwrap(), h(want));
        }
        assert!(memory_reset_request(ResetOptions::default()).is_err());
        assert!(ResetOptions::default().is_empty());
        for (code, want) in [
            ("00", ResetResult::Ok),
            ("01", ResetResult::NothingToDelete),
            ("7F", ResetResult::UndefinedError),
            ("63", ResetResult::Unknown(0x63)),
        ] {
            assert_eq!(
                decode_memory_reset(&h(&format!("BF34 03 80 01 {code}"))).unwrap(),
                want
            );
        }
        assert_eq!(
            decode_remove_notification(&h("BF30 03 80 01 01")).unwrap(),
            RemoveNotificationResult::NothingToDelete
        );
        assert!(decode_memory_reset(&h("BF34 00")).is_err());
        assert!(decode_remove_notification(&h("BF34 03 80 01 00")).is_err());
    }

    #[test]
    fn configured_addresses_request_and_response() {
        assert_eq!(get_euicc_configured_addresses_request(), h("BF3C 00"));
        let both = decode_configured_addresses(&h(
            "BF3C 1B 80 07 64702E6578616D 81 10 64732E6578616D706C652E6F7267",
        ));
        // 0x1B is a deliberate miscount: the decoder checks lengths.
        assert!(both.is_err());
        let ok = decode_configured_addresses(&h(
            "BF3C 19 80 07 64702E6578616D 81 0E 64732E6578616D706C652E6F7267",
        ))
        .unwrap();
        assert_eq!(ok.default_dp_address.as_deref(), Some("dp.exam"));
        assert_eq!(ok.root_ds_address.as_deref(), Some("ds.example.org"));
        let root_only =
            decode_configured_addresses(&h("BF3C 10 81 0E 64732E6578616D706C652E6F7267")).unwrap();
        assert_eq!(root_only.default_dp_address, None);
    }

    #[test]
    fn set_default_dp_request_is_the_bf3f_string_frame() {
        // Hand-written from pySim `euicc.py` (lines 108, 118, 424): BF3F
        // wrapping 80 wrapping the UTF-8 address. Two addresses, because one
        // would not catch a length field that only happens to come out right.
        assert_eq!(
            set_default_dp_request("dp.example.com").unwrap(),
            h("BF3F 10 80 0E 64702E6578616D706C652E636F6D")
        );
        assert_eq!(
            set_default_dp_request("smdp.example.com").unwrap(),
            h("BF3F 12 80 10 736D64702E6578616D706C652E636F6D")
        );
        assert!(matches!(
            set_default_dp_request(&"a".repeat(200)),
            Err(EncodeError::FieldLength {
                field: "defaultDpAddress",
                ..
            })
        ));
        assert!(set_default_dp_request(&"a".repeat(MAX_DEFAULT_DP_ADDRESS_BYTES)).is_ok());
        assert!(matches!(
            set_default_dp_request(""),
            Err(EncodeError::FieldLength {
                field: "defaultDpAddress",
                ..
            })
        ));
    }

    #[test]
    fn set_default_dp_result_is_an_integer_where_the_request_tag_was_a_string() {
        // Tag 80 in one function: a UTF-8 string outbound, an INTEGER inbound.
        // Confusing the two is the obvious bug here.
        assert_eq!(
            decode_set_default_dp(&h("BF3F 03 80 01 00")).unwrap(),
            SetDefaultDpResponse {
                result: SetDefaultDpResult::Ok,
                unknown: vec![]
            }
        );
        assert_eq!(
            decode_set_default_dp(&h("BF3F 03 80 01 7F"))
                .unwrap()
                .result,
            SetDefaultDpResult::UndefinedError
        );
        // A code the enumeration does not name is kept, never guessed.
        assert_eq!(
            decode_set_default_dp(&h("BF3F 03 80 01 63"))
                .unwrap()
                .result,
            SetDefaultDpResult::Unknown(99)
        );
        assert_eq!(
            decode_set_default_dp(&h("BF3F 03 80 01 63"))
                .unwrap()
                .result
                .code(),
            99
        );
        // An address is not a result, and BF3C is not this response.
        assert!(matches!(
            decode_set_default_dp(&h("BF3C 09 80 07 64702E6578616D")),
            Err(DecodeError::WrongTag { .. })
        ));
        assert!(decode_set_default_dp(&h("BF3F 10 80 07 64702E6578616D")).is_err());
        assert!(decode_set_default_dp(&h("BF3F 00")).is_err());
        // An unknown tag beside the result is kept whole, not dropped.
        assert_eq!(
            decode_set_default_dp(&h("BF3F 06 80 01 00 99 01 AA"))
                .unwrap()
                .unknown,
            vec![Unknown {
                tag: 0x99,
                value: vec![0xAA]
            }]
        );
    }

    #[test]
    fn sized_blocks_cut_at_the_chosen_size() {
        let cmds = blocks_sized(0x81, &[7u8; 100], 40).unwrap();
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].encode().unwrap()[..5], [0x81, 0xE2, 0x11, 0x00, 40]);
        assert_eq!(cmds[2].encode().unwrap()[..5], [0x81, 0xE2, 0x91, 0x02, 20]);
        assert_eq!(blocks_sized(0x81, &[7u8; 100], 255).unwrap().len(), 1);
        assert!(blocks_sized(0x81, &[7u8; 10], 0).is_err());
        assert!(blocks_sized(0x81, &[7u8; 10], 256).is_err());
        // 300 bytes at 1 per block is more than P2 can number.
        assert!(matches!(
            blocks_sized(0x81, &[7u8; 300], 1),
            Err(EncodeError::TooManyBlocks { .. })
        ));
    }

    // -- SGP.32, issue #229: GetCerts and GetEimConfigurationData --------
    //
    // Every byte vector below was built by hand from the tag and value list
    // of osmocom/pysim `pySim/euicc.py` (the module documentation gives the
    // line numbers), not copied out of a tool's output: there is no IoT
    // eUICC here to capture one from, and SGP.32 itself was not reachable
    // offline, so nothing here is claimed to be a capture. What is claimed is
    // that the decoder accepts exactly the structure that reference describes
    // and refuses everything else.

    /// A GetCerts response holding both certificates.
    const BOTH_CERTS: &str = "BF560B A505 AABBCCDDEE A602 0102";

    /// The fields of `EimConfigurationData`, without either envelope.
    fn eim_fields(
        id: &str,
        fqdn: &str,
        id_type: u8,
        counter: &[u8],
        token: &[u8],
        protocols: &[u8],
    ) -> Vec<u8> {
        let mut inner = tlv(0x80, id.as_bytes());
        push_tlv(&mut inner, 0x81, fqdn.as_bytes());
        push_tlv(&mut inner, 0x82, &[id_type]);
        push_tlv(&mut inner, 0x83, counter);
        push_tlv(&mut inner, 0x84, token);
        for protocol in protocols {
            push_tlv(&mut inner, 0x87, &[*protocol]);
        }
        inner
    }

    /// A GetEimConfigurationData response: `BF55 { A0 { ... } }`.
    fn eim_response(
        id: &str,
        fqdn: &str,
        id_type: u8,
        counter: &[u8],
        token: &[u8],
        protocols: &[u8],
    ) -> Vec<u8> {
        tlv(
            0xBF55,
            &tlv(
                0xA0,
                &eim_fields(id, fqdn, id_type, counter, token, protocols),
            ),
        )
    }

    /// The same response in the shape pySim decodes: the fields sit under
    /// `EimConfigurationData`'s own tag-`80` wrapper inside the `A0`.
    fn eim_response_wrapped(
        id: &str,
        fqdn: &str,
        id_type: u8,
        counter: &[u8],
        token: &[u8],
        protocols: &[u8],
    ) -> Vec<u8> {
        let fields = eim_fields(id, fqdn, id_type, counter, token, protocols);
        tlv(0xBF55, &tlv(0xA0, &tlv(0x80, &fields)))
    }

    /// The content of the `A0` of a whole `BF55` response.
    fn eim_content(response: &[u8]) -> &[u8] {
        let a0 = parse(response).unwrap()[0].value;
        parse(a0).unwrap()[0].value
    }

    /// The one answer both shapes must produce, asserted for each of them.
    fn assert_the_same_answer(eim: &EimConfigurationData) {
        assert_eq!(eim.eim_id, "1.3.6.1.4.1.41487");
        assert_eq!(eim.eim_fqdn, "eim.example.org");
        assert_eq!(eim.eim_id_type, EimIdType::Oid);
        assert_eq!(eim.counter_value, 7);
        assert_eq!(eim.association_token, 256);
        assert_eq!(
            eim.supported_protocols,
            vec![
                EimSupportedProtocol::RetrieveHttps,
                EimSupportedProtocol::InjectCoaps
            ]
        );
        assert!(eim.unknown.is_empty());
    }

    fn eim_ok(counter: &[u8], token: &[u8]) -> Result<EimConfigurationData, DecodeError> {
        decode_get_eim_configuration_data(&eim_response(
            "1.3.6.1.4.1.41487",
            "eim.example.org",
            1,
            counter,
            token,
            &[0, 3],
        ))
    }

    #[test]
    fn sgp32_requests_are_empty_ber_tlvs() {
        assert_eq!(get_certs_request(), h("BF5600"));
        assert_eq!(get_eim_configuration_data_request(), h("BF5500"));
    }

    #[test]
    fn get_certs_carries_both_certificates_opaque() {
        let GetCertsResponse::Ok(certs) = decode_get_certs(&h(BOTH_CERTS)).unwrap() else {
            panic!("a GetCerts response with two certificates is not an error");
        };
        assert_eq!(certs.eum, Some(h("AABBCCDDEE")));
        assert_eq!(certs.euicc, Some(h("0102")));
        assert!(certs.unknown.is_empty());
    }

    #[test]
    fn get_certs_may_carry_one_certificate_or_none() {
        let GetCertsResponse::Ok(only_eum) =
            decode_get_certs(&h("BF5607 A505 AABBCCDDEE")).unwrap()
        else {
            panic!("one certificate is not an error");
        };
        assert_eq!(only_eum.eum, Some(h("AABBCCDDEE")));
        assert_eq!(only_eum.euicc, None);

        let GetCertsResponse::Ok(only_euicc) = decode_get_certs(&h("BF5604 A602 0102")).unwrap()
        else {
            panic!("one certificate is not an error");
        };
        assert_eq!(only_euicc.euicc, Some(h("0102")));
        assert_eq!(only_euicc.eum, None);

        let GetCertsResponse::Ok(none) = decode_get_certs(&h("BF5600")).unwrap() else {
            panic!("an empty response is not an error");
        };
        assert_eq!((none.eum, none.euicc), (None, None));
    }

    #[test]
    fn get_certs_error_is_terminal_and_unlisted_codes_stay_unknown() {
        assert_eq!(
            decode_get_certs(&h("BF5603 81 01 01")),
            Ok(GetCertsResponse::Error(GetCertsError::InvalidCiPkId))
        );
        assert_eq!(
            decode_get_certs(&h("BF5603 81 01 7F")),
            Ok(GetCertsResponse::Error(GetCertsError::UndefinedError))
        );
        assert_eq!(
            decode_get_certs(&h("BF5603 81 01 2A")),
            Ok(GetCertsResponse::Error(GetCertsError::Unknown(42)))
        );
        // A response that (a card should not) holds a certificate as well:
        // the error is still what is reported, never an empty certificate.
        assert_eq!(
            decode_get_certs(&h("BF560A A505 AABBCCDDEE 81 01 01")),
            Ok(GetCertsResponse::Error(GetCertsError::InvalidCiPkId))
        );
        // The error is one octet, as every code in this file is.
        assert!(decode_get_certs(&h("BF5604 81 02 00 01")).is_err());
        assert!(decode_get_certs(&h("BF5500")).is_err());
    }

    #[test]
    fn get_certs_certificate_longer_than_127_octets_uses_the_long_length() {
        let cert = vec![0xAB_u8; 200];
        let response = tlv(0xBF56, &tlv(0xA5, &cert));
        assert_eq!(&response[..4], [0xBF, 0x56, 0x81, 0xCB]);
        let GetCertsResponse::Ok(certs) = decode_get_certs(&response).unwrap() else {
            panic!("a long certificate is not an error");
        };
        assert_eq!(certs.eum.as_deref().map(<[u8]>::len), Some(200));
        assert_eq!(certs.euicc, None);
    }

    #[test]
    fn eim_configuration_data_is_decoded_out_of_the_a0_sequence() {
        let response = eim_response(
            "1.3.6.1.4.1.41487",
            "eim.example.org",
            1,
            &[0x02, 0x01, 0x07],
            &[0x02, 0x02, 0x01, 0x00],
            &[0, 3],
        );
        // The A0 sequence tag is a tag of its own, not decoration: the bytes
        // on the wire are BF 55 <len> A0 <len> 80 ...
        assert_eq!(
            &response[..6],
            [0xBF, 0x55, 0x3A, 0xA0, 0x38, 0x80],
            "BF55 {{ A0 {{ 80 eimId"
        );
        let eim = decode_get_eim_configuration_data(&response).unwrap();
        assert_eq!(eim.eim_id, "1.3.6.1.4.1.41487");
        assert_eq!(eim.eim_fqdn, "eim.example.org");
        assert_eq!(eim.eim_id_type, EimIdType::Oid);
        assert_eq!(eim.counter_value, 7);
        assert_eq!(eim.association_token, 256);
        // Every 87 is kept, in order: a card may support several protocols.
        assert_eq!(
            eim.supported_protocols,
            vec![
                EimSupportedProtocol::RetrieveHttps,
                EimSupportedProtocol::InjectCoaps
            ]
        );
    }

    #[test]
    fn the_pysim_wrapper_shape_is_decoded_and_reported() {
        let response = eim_response_wrapped(
            "1.3.6.1.4.1.41487",
            "eim.example.org",
            1,
            &[0x02, 0x01, 0x07],
            &[0x02, 0x02, 0x01, 0x00],
            &[0, 3],
        );
        // The vector really is the wrapped shape: the `A0` holds one `80`
        // and nothing else, and that `80` holds a TLV sequence.
        let wrapper = parse(eim_content(&response)).unwrap();
        assert_eq!(wrapper.len(), 1);
        assert_eq!(wrapper[0].tag, 0x80);
        assert_eq!(parse(wrapper[0].value).unwrap()[0].tag, 0x80);
        let eim = decode_get_eim_configuration_data(&response).unwrap();
        assert_eq!(eim.shape, EimShape::Wrapper80);
        assert_eq!(
            eim.shape.as_str(),
            "wrapper-80 (pySim EimConfigurationData inside EimConfigurationDataSeq)"
        );
        assert_the_same_answer(&eim);
    }

    #[test]
    fn the_direct_shape_is_decoded_and_reported() {
        let response = eim_response(
            "1.3.6.1.4.1.41487",
            "eim.example.org",
            1,
            &[0x02, 0x01, 0x07],
            &[0x02, 0x02, 0x01, 0x00],
            &[0, 3],
        );
        // The vector really is the direct shape: the `A0` holds seven field
        // TLVs, not one wrapper.
        assert_eq!(parse(eim_content(&response)).unwrap().len(), 7);
        let eim = decode_get_eim_configuration_data(&response).unwrap();
        assert_eq!(eim.shape, EimShape::Direct);
        assert_eq!(eim.shape.as_str(), "direct");
        assert_the_same_answer(&eim);
    }

    #[test]
    fn a_lone_80_holding_utf8_is_an_eim_id_not_a_wrapper() {
        // `80` is both the wrapper and `eimId`, so only the nesting tells
        // them apart. This `80` holds the UTF-8 of an id, which is not a
        // TLV sequence, so it is the id and the answer is the direct shape:
        // refused nowhere, guessed at nowhere, and never a loop.
        let response = eim_response(
            "eim",
            "eim.example.org",
            1,
            &[0x02, 0x01, 0x00],
            &[0x02, 0x01, 0x00],
            &[0],
        );
        let fields = parse(eim_content(&response)).unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].tag, 0x80);
        assert!(parse(fields[0].value).is_err());
        let eim = decode_get_eim_configuration_data(&response).unwrap();
        assert_eq!(eim.shape, EimShape::Direct);
        assert_eq!(eim.eim_id, "eim");
        assert_eq!(eim.eim_fqdn, "eim.example.org");
        assert_eq!(eim.eim_id_type, EimIdType::Oid);
        assert_eq!(eim.counter_value, 0);
        assert_eq!(eim.association_token, 0);
        assert_eq!(
            eim.supported_protocols,
            vec![EimSupportedProtocol::RetrieveHttps]
        );
    }

    #[test]
    fn eim_id_type_and_every_supported_protocol_are_named() {
        for (code, want) in [
            (1, EimIdType::Oid),
            (2, EimIdType::Fqdn),
            (3, EimIdType::Proprietary),
            (9, EimIdType::Unknown(9)),
        ] {
            assert_eq!(EimIdType::from_code(code), want);
            let response = eim_response(
                "eim",
                "eim.example.org",
                code,
                &[0x02, 0x01, 0x00],
                &[0x02, 0x01, 0x00],
                &[],
            );
            assert_eq!(
                decode_get_eim_configuration_data(&response)
                    .unwrap()
                    .eim_id_type,
                want,
                "eimIdType {code}"
            );
        }
        for code in 0..=4 {
            assert_eq!(EimSupportedProtocol::from_code(code).code(), code);
        }
        // Six protocol TLVs in one response, one of them unlisted.
        let response = eim_response(
            "eim",
            "eim.example.org",
            2,
            &[0x02, 0x01, 0x00],
            &[0x02, 0x01, 0x00],
            &[0, 1, 2, 3, 4, 9],
        );
        let eim = decode_get_eim_configuration_data(&response).unwrap();
        assert_eq!(
            eim.supported_protocols,
            vec![
                EimSupportedProtocol::RetrieveHttps,
                EimSupportedProtocol::RetrieveCoaps,
                EimSupportedProtocol::InjectHttps,
                EimSupportedProtocol::InjectCoaps,
                EimSupportedProtocol::Proprietary,
                EimSupportedProtocol::Unknown(9),
            ]
        );
        // No 87 at all is not an error; it is an empty list.
        assert_eq!(
            decode_get_eim_configuration_data(&eim_response(
                "eim",
                "eim.example.org",
                3,
                &[0x02, 0x01, 0x00],
                &[0x02, 0x01, 0x00],
                &[],
            ))
            .unwrap()
            .supported_protocols,
            Vec::<EimSupportedProtocol>::new()
        );
    }

    #[test]
    fn eim_counter_and_token_are_der_integers_not_raw_octets() {
        // 0 is 02 01 00, 1 is 02 01 01, 128 is 02 02 00 80 and 255 is 02 02
        // 00 FF: the tag and the length octet belong to the encoding, not to
        // the value, and a leading 00 belongs to the encoding too.
        for (bytes, want) in [
            (h("020100"), 0_u64),
            (h("020101"), 1),
            (h("02020080"), 128),
            (h("020200FF"), 255),
            (h("02020100"), 256),
            // u64::MAX is nine value octets: the leading 00 is what makes
            // an eight-octet 0xFF.. a positive number.
            (h("020900FFFFFFFFFFFFFFFF"), u64::MAX),
        ] {
            assert_eq!(
                eim_ok(&bytes, &bytes).unwrap().counter_value,
                want,
                "counterValue {bytes:02X?}"
            );
            assert_eq!(
                eim_ok(&bytes, &bytes).unwrap().association_token,
                want,
                "associationToken {bytes:02X?}"
            );
        }
    }

    #[test]
    fn eim_rejects_an_integer_that_is_not_der() {
        // A single raw octet is not a DER value at all.
        assert!(matches!(
            eim_ok(&[0x07], &[0x02, 0x01, 0x00]),
            Err(DecodeError::BadDerEncoding { .. })
        ));
        // An OCTET STRING where an INTEGER belongs.
        assert!(matches!(
            eim_ok(&[0x04, 0x01, 0x07], &[0x02, 0x01, 0x00]),
            Err(DecodeError::NotAnInteger {
                field: "counterValue",
                found: 4
            })
        ));
        // Negative, and empty of value octets.
        assert!(matches!(
            eim_ok(&[0x02, 0x01, 0x80], &[0x02, 0x01, 0x00]),
            Err(DecodeError::NegativeInteger { .. })
        ));
        assert!(matches!(
            eim_ok(&[0x02, 0x01, 0x01], &[0x02, 0x00]),
            Err(DecodeError::NegativeInteger {
                field: "associationToken"
            })
        ));
        // A value written longer than it needs to be.
        assert!(matches!(
            eim_ok(&[0x02, 0x02, 0x00, 0x01], &[0x02, 0x01, 0x00]),
            Err(DecodeError::NonMinimalInteger {
                field: "counterValue"
            })
        ));
        // Wider than the 64 bits reported.
        assert!(matches!(
            eim_ok(
                &[0x02, 0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                &[0x02, 0x01, 0x00]
            ),
            Err(DecodeError::IntegerTooWide { .. })
        ));
        // Bytes after the INTEGER, and a length written non-minimally: both
        // are the strict reader's to refuse, and neither is a number.
        assert!(matches!(
            eim_ok(&[0x02, 0x02, 0x01, 0x00, 0xFF], &[0x02, 0x01, 0x00]),
            Err(DecodeError::BadDerEncoding { .. })
        ));
        assert!(matches!(
            eim_ok(&[0x02, 0x81, 0x01, 0x07], &[0x02, 0x01, 0x00]),
            Err(DecodeError::BadDerEncoding { .. })
        ));
    }

    #[test]
    fn a_malformed_eim_response_is_refused_not_guessed() {
        // No A0 sequence: the fields are never read at the top level.
        assert!(matches!(
            decode_get_eim_configuration_data(&h("BF5503 80 01 41")),
            Err(DecodeError::UnexpectedTag {
                context: "GetEimConfigurationDataResponse",
                found: 0x80
            })
        ));
        // Wrong response tag entirely.
        assert!(matches!(
            decode_get_eim_configuration_data(&h(BOTH_CERTS)),
            Err(DecodeError::WrongTag { .. })
        ));
        // An A0 missing every field.
        assert!(matches!(
            decode_get_eim_configuration_data(&h("BF5502 A000")),
            Err(DecodeError::MissingField("eimId"))
        ));
        // eimFqdn not valid UTF-8.
        assert!(matches!(
            decode_get_eim_configuration_data(&h("BF5508 A006 8001 41 8101 FF")),
            Err(DecodeError::BadUtf8("eimFqdn"))
        ));
        // A one-octet code is required of 82 as of every code here.
        assert!(matches!(
            decode_get_eim_configuration_data(&h("BF550C A00A 8001 41 8101 41 8202 0001")),
            Err(DecodeError::BadLength {
                field: "eimIdType",
                ..
            })
        ));
        // Nothing at all.
        assert!(decode_get_eim_configuration_data(&h("BF5500")).is_err());
        assert!(decode_get_eim_configuration_data(&[]).is_err());
    }
}
