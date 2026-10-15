//! Offline RSPRO (osmo-remsim) capture reading for `sim-doctor trace`, through the
//! public `trace::parse_bytes`. Byte vectors only: no reader, no daemon, no card.
//!
//! Wire layout under test (all checked against primary sources, see
//! `src/trace/rspro.rs`): pcap, Ethernet, IPv4, TCP, then the IPA multiplex
//! (u16 BE length, proto 0xEE OSMO, ext proto 0x07 RSPRO), then a BER RsproPDU.

use sim_doctor::trace::parse_bytes;

/// BER TLV with a single-octet tag and a definite length (below 256 here).
fn ber(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    if v.len() < 128 {
        o.push(v.len() as u8);
    } else {
        o.extend([0x81, v.len() as u8]);
    }
    o.extend_from_slice(v);
    o
}

/// ClientSlot or BankSlot: SEQUENCE of two INTEGERs.
fn slot(id: u8, nr: u8) -> Vec<u8> {
    ber(0x30, &[ber(2, &[id]), ber(2, &[nr])].concat())
}

/// One IPA-framed RsproPDU carrying a TPDU. `tag` is 0xAC (tpduModemToCard,
/// [12] IMPLICIT SEQUENCE) or 0xAD (tpduCardToModem, [13]); `msg` is [2] EXPLICIT.
fn ipa_msg(tag: u8, a: Vec<u8>, b: Vec<u8>, data: &[u8]) -> Vec<u8> {
    let flags = ber(
        0x30,
        &[ber(1, &[0xff]), ber(1, &[0]), ber(1, &[0]), ber(1, &[0])].concat(),
    );
    let body = [a, b, flags, ber(4, data)].concat();
    let pdu = ber(
        0x30,
        &[
            ber(0x80, &[2]),
            ber(0x81, &[5]),
            ber(0xA2, &ber(tag, &body)),
        ]
        .concat(),
    );
    let mut out = ((pdu.len() + 2) as u16).to_be_bytes().to_vec();
    out.extend([0xEE, 0x07]);
    out.extend(pdu);
    out
}

fn to_card(data: &[u8]) -> Vec<u8> {
    ipa_msg(0xAC, slot(7, 0), slot(1, 2), data)
}

fn to_modem(data: &[u8]) -> Vec<u8> {
    ipa_msg(0xAD, slot(1, 2), slot(7, 0), data)
}

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const BANK: [u8; 4] = [10, 0, 0, 2];

/// Ethernet + IPv4 + TCP around `payload`; `seq` is the TCP sequence number.
fn tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend([0x08, 0x00, 0x45, 0]);
    f.extend(((40 + payload.len()) as u16).to_be_bytes());
    f.extend([0, 0, 0, 0, 64, 6, 0, 0]);
    f.extend(src);
    f.extend(dst);
    f.extend(sport.to_be_bytes());
    f.extend(dport.to_be_bytes());
    f.extend(seq.to_be_bytes());
    f.extend([0, 0, 0, 0, 0x50, 0x18, 0, 0, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

/// Classic little-endian pcap, Ethernet link type, one record per frame.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut f = vec![0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    f.extend([0xFF, 0xFF, 0, 0, 1, 0, 0, 0]);
    for fr in frames {
        f.extend([0u8; 8]);
        f.extend((fr.len() as u32).to_le_bytes());
        f.extend((fr.len() as u32).to_le_bytes());
        f.extend_from_slice(fr);
    }
    f
}

const CMD: [u8; 7] = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
const RSP: [u8; 2] = [0x9F, 0x0F];

#[test]
fn rspro_command_and_response_form_one_pair() {
    let frames = [
        tcp(CLIENT, BANK, 50000, 9998, 1000, &to_card(&CMD)),
        tcp(BANK, CLIENT, 9998, 50000, 5000, &to_modem(&RSP)),
    ];
    let pairs = parse_bytes(&pcap(&frames)).unwrap();
    assert_eq!(pairs, vec![(None, CMD.to_vec(), RSP.to_vec())]);
}

#[test]
fn split_segments_retransmits_and_ipa_ccm_are_handled() {
    let first = to_card(&CMD);
    let (head, tail) = first.split_at(9);
    let ccm = [0u8, 1, 0xFE]; // IPA CCM, proto 0xFE: skipped
    let second_cmd = [0xA0, 0xC0, 0x00, 0x00, 0x00];
    let frames = [
        tcp(CLIENT, BANK, 50000, 9998, 1000, &ccm),
        tcp(CLIENT, BANK, 50000, 9998, 1003, head),
        tcp(CLIENT, BANK, 50000, 9998, 1003, head), // retransmission
        tcp(CLIENT, BANK, 50000, 9998, 1003 + head.len() as u32, tail),
        tcp(BANK, CLIENT, 9998, 50000, 5000, &to_modem(&RSP)),
        tcp(
            CLIENT,
            BANK,
            50000,
            9998,
            1003 + first.len() as u32,
            &to_card(&second_cmd),
        ),
        tcp(
            BANK,
            CLIENT,
            9998,
            50000,
            5000 + to_modem(&RSP).len() as u32,
            &to_modem(&RSP),
        ),
    ];
    let pairs = parse_bytes(&pcap(&frames)).unwrap();
    assert_eq!(
        pairs,
        vec![
            (None, CMD.to_vec(), RSP.to_vec()),
            (None, second_cmd.to_vec(), RSP.to_vec()),
        ]
    );
}

#[test]
fn a_capture_that_switches_bank_slot_is_refused() {
    let other_bank = ipa_msg(0xAD, slot(3, 1), slot(7, 0), &RSP);
    let frames = [
        tcp(CLIENT, BANK, 50000, 9998, 1000, &to_card(&CMD)),
        tcp(BANK, CLIENT, 9998, 50000, 5000, &to_modem(&RSP)),
        tcp(
            BANK,
            CLIENT,
            9998,
            50000,
            5000 + to_modem(&RSP).len() as u32,
            &other_bank,
        ),
    ];
    let err = parse_bytes(&pcap(&frames)).unwrap_err();
    assert!(err.contains("mixes"), "{err}");
}

#[test]
fn other_tcp_traffic_is_not_rspro_and_is_an_error_without_gsmtap() {
    let frames = [tcp(
        CLIENT,
        BANK,
        50000,
        80,
        1000,
        b"GET / HTTP/1.1\r\n\r\n",
    )];
    let err = parse_bytes(&pcap(&frames)).unwrap_err();
    assert!(err.contains("no GSMTAP SIM APDU"), "{err}");
}
