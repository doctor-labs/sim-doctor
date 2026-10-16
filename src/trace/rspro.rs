//! RSPRO (osmo-remsim) reader for `sim-doctor trace`: the modem-to-card and
//! card-to-modem TPDUs of a pcap or pcapng capture, as command/response pairs.
//!
//! Sources (checked 2026-10-15):
//! - Schema: osmo-remsim `asn1/RSPRO.asn`, `IMPLICIT TAGS`. The choice
//!   alternatives `tpduModemToCard [12]` and `tpduCardToModem [13]` are SEQUENCEs
//!   with implicit context tags, so 0xAC and 0xAD. `msg [2]` holds a CHOICE, which
//!   X.680 tags EXPLICITLY: 0xA2 around the alternative. The untagged SEQUENCE
//!   members keep their universal tags.
//! - Encoding: osmo-remsim `doc/manuals/chapters/rspro.adoc`: BER over TCP.
//! - Framing: osmo-remsim `src/bankd/bankd_main.c` prepends the RSPRO extension
//!   header and then the IPA header. IPA is a u16 big-endian length counting the
//!   bytes after it, a proto byte (IPAC_PROTO_OSMO 0xEE), then the extension byte
//!   (IPAC_PROTO_EXT_RSPRO 0x07), then the BER RsproPDU. Values from libosmocore
//!   `include/osmocom/gsm/protocol/ipaccess.h`.
//! - Pairing and bank check: pySim `pySim/apdu_source/pyshark_rspro.py`. A
//!   modem-to-card TPDU waits for the next card-to-modem TPDU, and a capture that
//!   changes bank slot is refused. Status messages (14, 15) carry no TPDU; skipped.
//!
//! Ceiling: TCP segments are read in capture order per direction. Retransmitted
//! and overlapping bytes are trimmed; out-of-order data is appended as it arrives
//! and a gap is not filled, so such a capture may lose a message. A direction
//! whose bytes stop being IPA frames is dropped and the rest still counts.

use std::collections::HashMap;

use super::{pcap, Pair};

const TCP: u8 = 6;
const IPA_PROTO_IPACCESS: u8 = 0xFE;
const IPA_PROTO_OSMO: u8 = 0xEE;
const IPA_EXT_RSPRO: u8 = 0x07;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_MSG: u8 = 0xA2;
const TAG_MODEM_TO_CARD: u8 = 0xAC;
const TAG_CARD_TO_MODEM: u8 = 0xAD;

/// (bankId, slotNr) on the SIM bank side.
type BankSlot = (u32, u32);

/// One TPDU message: its direction, the bank slot it names, and the TPDU bytes.
struct Tpdu {
    to_card: bool,
    bank: BankSlot,
    data: Vec<u8>,
}

/// (client address, client port, bank address, bank port) of one TCP direction.
type Flow = ([u8; 4], u16, [u8; 4], u16);

/// The bytes of one TCP direction, rebuilt from its segments in capture order.
#[derive(Default)]
struct Stream {
    buf: Vec<u8>,
    next: Option<u32>,
    dead: bool,
}

impl Stream {
    /// Adds a segment, trimming the bytes that were already seen.
    fn append(&mut self, seq: u32, payload: &[u8]) {
        let mut data = payload;
        if let Some(next) = self.next {
            let behind = next.wrapping_sub(seq);
            if behind < 0x8000_0000 {
                // The segment starts at or before the bytes we have.
                let skip = behind as usize;
                if skip >= data.len() {
                    return;
                }
                data = &data[skip..];
            }
        }
        self.buf.extend_from_slice(data);
        self.next = Some(seq.wrapping_add(payload.len() as u32));
    }

    /// Moves every complete IPA frame out of the buffer, keeping the RSPRO TPDUs.
    fn drain(&mut self, out: &mut Vec<Tpdu>) {
        while self.buf.len() >= 3 {
            let len = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
            let proto = self.buf[2];
            let known = proto == IPA_PROTO_OSMO || proto == IPA_PROTO_IPACCESS;
            if len == 0 || !known {
                self.dead = true;
                self.buf.clear();
                return;
            }
            if self.buf.len() < 2 + len {
                return;
            }
            let body = &self.buf[3..2 + len];
            if proto == IPA_PROTO_OSMO && body.first() == Some(&IPA_EXT_RSPRO) {
                if let Some(t) = tpdu(&body[1..]) {
                    out.push(t);
                }
            }
            self.buf.drain(..2 + len);
        }
    }
}

/// Reads the RSPRO TPDU pairs of a capture. Empty when it holds no RSPRO.
///
/// # Errors
///
/// The capture is malformed, or it moves between SIM bank slots. Never panics.
pub fn parse(bytes: &[u8]) -> Result<Vec<Pair>, String> {
    let mut streams: HashMap<Flow, Stream> = HashMap::new();
    let mut tpdus = Vec::new();
    pcap::for_each_frame(bytes, &mut |link: u32, frame: &[u8]| {
        let Some(ip) = pcap::ipv4(link, frame) else {
            return;
        };
        if ip.proto != TCP {
            return;
        }
        let Some((ports, seq, payload)) = tcp_segment(ip.payload) else {
            return;
        };
        let st = streams
            .entry((ip.src, ports.0, ip.dst, ports.1))
            .or_default();
        if st.dead {
            return;
        }
        st.append(seq, payload);
        st.drain(&mut tpdus);
    })?;

    let mut bank: Option<BankSlot> = None;
    let mut pending: Option<Vec<u8>> = None;
    let mut pairs = Vec::new();
    for t in tpdus {
        match bank {
            None => bank = Some(t.bank),
            Some(b) if b != t.bank => {
                return Err(format!(
                    "the capture mixes SIM bank slots B({}:{}) and B({}:{}); split it per card",
                    b.0, b.1, t.bank.0, t.bank.1
                ));
            }
            Some(_) => {}
        }
        if t.to_card {
            pending = Some(t.data);
        } else if let Some(cmd) = pending.take() {
            pairs.push((None, cmd, t.data));
        }
    }
    Ok(pairs)
}

/// Ports, sequence number and payload of a TCP segment; None without payload.
fn tcp_segment(t: &[u8]) -> Option<((u16, u16), u32, &[u8])> {
    let ports = (
        u16::from_be_bytes([*t.first()?, *t.get(1)?]),
        u16::from_be_bytes([*t.get(2)?, *t.get(3)?]),
    );
    let seq = u32::from_be_bytes(t.get(4..8)?.try_into().ok()?);
    let header = usize::from(*t.get(12)? >> 4) * 4;
    if header < 20 {
        return None;
    }
    let payload = t.get(header..)?;
    (!payload.is_empty()).then_some((ports, seq, payload))
}

/// The TPDU of one BER RsproPDU, when it is a tpduModemToCard or tpduCardToModem.
fn tpdu(ber: &[u8]) -> Option<Tpdu> {
    let (tag, pdu, _) = tlv(ber)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let msg = children(pdu)?.into_iter().find(|(t, _)| *t == TAG_MSG)?.1;
    let (kind, body, _) = tlv(msg)?;
    let to_card = match kind {
        TAG_MODEM_TO_CARD => true,
        TAG_CARD_TO_MODEM => false,
        _ => return None,
    };
    // ModemToCard: fromClientSlot, toBankSlot, flags, data.
    // CardToModem: fromBankSlot, toClientSlot, flags, data.
    let fields = children(body)?;
    let bank = bank_slot(fields.get(if to_card { 1 } else { 0 })?)?;
    let &(data_tag, data) = fields.get(3)?;
    if data_tag != TAG_OCTET_STRING {
        return None;
    }
    Some(Tpdu {
        to_card,
        bank,
        data: data.to_vec(),
    })
}

/// BankSlot ::= SEQUENCE { bankId INTEGER, slotNr INTEGER, ... }, given as its TLV.
fn bank_slot(&(tag, value): &(u8, &[u8])) -> Option<BankSlot> {
    let fields = children(value)?;
    let &(a, id) = fields.first()?;
    let &(b, nr) = fields.get(1)?;
    if tag != TAG_SEQUENCE || a != TAG_INTEGER || b != TAG_INTEGER {
        return None;
    }
    Some((int(id)?, int(nr)?))
}

/// INTEGER content octets; bankId and slotNr are 0..1023, so 4 bytes is plenty.
fn int(v: &[u8]) -> Option<u32> {
    (!v.is_empty() && v.len() <= 4).then(|| v.iter().fold(0, |a, &x| (a << 8) | u32::from(x)))
}

/// One BER TLV with a single-octet tag and a definite length: (tag, value, rest).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        // 0x80 is the indefinite form, which RSPRO does not use.
        let n = usize::from(first & 0x7F);
        if !(1..=4).contains(&n) {
            return None;
        }
        let len = b
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        (len, 2 + n)
    };
    let value = b.get(hdr..hdr + len)?;
    Some((tag, value, &b[hdr + len..]))
}

/// The TLVs making up a constructed value, in order.
fn children(mut b: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (tag, value, rest) = tlv(b)?;
        out.push((tag, value));
        b = rest;
    }
    Some(out)
}
