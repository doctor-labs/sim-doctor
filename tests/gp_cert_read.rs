//! `gp cert read`: the `7F21` decode that runs once the octets are off the card.
//!
//! The APDU half of the command is the SELECT and READ BINARY that every other `gp` command
//! already builds, and that machinery is not what #249 adds. What #249 adds is the decode, so
//! that is what these check: a scripted card answers, `cert_read` assembles the blocks, and the
//! `parsed` object in the envelope has to name the fields the certificate really carries.
//!
//! The scripted card answers by command prefix (`00A4`, `00B0`) from a queue, and answers `6D00`
//! to anything nobody scripted, so a command this command did not expect fails the test instead
//! of passing quietly.

use std::collections::{HashMap, VecDeque};

use sim_doctor::cert::SignatureCheck;
use sim_doctor::gp::{cert_read, CERT_READ_BLOCK, CERT_READ_MAX_BLOCKS};
use sim_doctor::transport::{CardSession, Error as TransportError, ReaderName};

/// A card answering from a command-prefix -> response-hex queue, recording what it was sent.
struct Scripted {
    reader: ReaderName,
    table: HashMap<String, VecDeque<Vec<u8>>>,
    sent: Vec<String>,
}

impl Scripted {
    fn new(rows: &[(&str, &[&str])]) -> Self {
        Self {
            reader: ReaderName::new("scripted").unwrap(),
            table: rows
                .iter()
                .map(|(command, responses)| {
                    (
                        command.to_string(),
                        responses
                            .iter()
                            .map(|r| hex::decode(r).unwrap())
                            .collect::<VecDeque<Vec<u8>>>(),
                    )
                })
                .collect(),
            sent: Vec::new(),
        }
    }
}

impl CardSession for Scripted {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
        let key = hex::encode_upper(command);
        let slot = if self.table.contains_key(&key) {
            key.clone()
        } else {
            key[..4].to_string()
        };
        self.sent.push(key);
        Ok(self
            .table
            .get_mut(&slot)
            .and_then(|queue| queue.pop_front())
            .unwrap_or_else(|| vec![0x6D, 0x00]))
    }

    fn disconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// One signed `7F21`, written by the writer under test so the two cannot drift apart, and then
/// checked against facts stated here rather than against whatever the code happens to return.
fn a_card_certificate(discretionary_octets: usize) -> Vec<u8> {
    let key = sim_doctor::gpcert::signing_key_from_bytes(&[0xABu8; 32]).unwrap();
    let mut builder = sim_doctor::gpcert::Builder::new();
    builder.serial(&[0x01]).unwrap();
    builder.ca(&[0x11, 0x22, 0x33]).unwrap();
    builder.subject(&[0x44, 0x55]).unwrap();
    builder
        .usage(sim_doctor::gpcert::Usage::Verification)
        .unwrap();
    builder.effective("20260115").unwrap();
    builder.expires("20270115").unwrap();
    if discretionary_octets > 0 {
        builder
            .discretionary(&vec![0x5Au8; discretionary_octets])
            .unwrap();
    }
    builder
        .public_key(&sim_doctor::gpcert::public_point(&key))
        .unwrap();
    let plain = sim_doctor::gpcert::sign_plain(&builder.dtbs().unwrap(), &key).unwrap();
    builder.sign(&plain).unwrap().encode()
}

/// The `B0` point of the certificate above, as upper-case hex, computed from the same key.
fn the_point() -> String {
    let key = sim_doctor::gpcert::signing_key_from_bytes(&[0xABu8; 32]).unwrap();
    hex::encode_upper(sim_doctor::gpcert::public_point(&key))
}

#[test]
fn a_certificate_read_in_one_block_is_decoded_into_the_envelope() {
    let certificate = a_card_certificate(0);

    // `7F 21 81 AB`: the body is 104 signed octets plus a 67-octet `5F37`, so 171, which is over
    // 127 and takes the long form. The first version of this writer put a single `AB` there,
    // which no reader accepts, so the read path could not read its own output.
    assert_eq!(&certificate[..4], &[0x7F, 0x21, 0x81, 0xAB]);

    let block = hex::encode_upper(&certificate) + "9000";
    let mut card = Scripted::new(&[("00A4", &["9000"]), ("00B0", &[block.as_str()])]);
    let report = cert_read(&mut card, false).unwrap();

    assert!(report.isd_found, "{:?}", report.data);
    assert_eq!(report.data["file"], "7F21");
    assert_eq!(report.data["read"].as_bool(), Some(true));
    assert_eq!(report.data["octets"], certificate.len());
    assert_eq!(report.data["certificate"], hex::encode_upper(&certificate));
    assert_eq!(report.data["blocks"].as_array().unwrap().len(), 1);

    let parsed = &report.data["parsed"];
    assert!(parsed.get("error").is_none(), "{parsed}");
    assert_eq!(parsed["usage"], "verification (82 00)");
    assert_eq!(parsed["effective"], "20260115");
    assert_eq!(parsed["expires"], "20270115");
    assert_eq!(parsed["signed_data_len"], 104);
    assert_eq!(parsed["public_key_point"], the_point());
    let tags: Vec<&str> = parsed["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        ["0093", "0042", "5F20", "0095", "5F25", "5F24", "7F49"]
    );

    // One SELECT, then one READ BINARY at offset 0: 175 octets fits one short Le.
    assert_eq!(&card.sent[0][..4], "00A4");
    assert_eq!(&card.sent[1][..8], "00B00000");

    // What came off the card verifies against the key that signed it.
    let key = sim_doctor::gpcert::signing_key_from_bytes(&[0xABu8; 32]).unwrap();
    let decoded = sim_doctor::gpcert::parse(&certificate).unwrap();
    assert_eq!(
        decoded.verify_signature(&sim_doctor::gpcert::public_point(&key)),
        SignatureCheck::Valid
    );
    assert_eq!(decoded.signed_data().len(), 104);
}

#[test]
fn a_certificate_longer_than_one_block_is_read_across_blocks() {
    // 255 octets of discretionary data is the most one field may carry, and it pushes the
    // certificate past the 240-octet block, so the READ BINARY offset has to move.
    let certificate = a_card_certificate(255);
    let block = CERT_READ_BLOCK as usize;
    assert!(
        certificate.len() > block,
        "{} octets should need more than one block",
        certificate.len()
    );
    let first = hex::encode_upper(&certificate[..block]) + "9000";
    let second = hex::encode_upper(&certificate[block..]) + "9000";
    let mut card = Scripted::new(&[
        ("00A4", &["9000"]),
        ("00B0", &[first.as_str(), second.as_str()]),
    ]);
    let report = cert_read(&mut card, false).unwrap();

    assert_eq!(report.data["read"].as_bool(), Some(true));
    assert_eq!(report.data["octets"], certificate.len());
    assert_eq!(report.data["certificate"], hex::encode_upper(&certificate));
    assert_eq!(report.data["blocks"].as_array().unwrap().len(), 2);
    assert!(
        report.data["parsed"].get("error").is_none(),
        "{}",
        report.data["parsed"]
    );
    assert_eq!(report.data["parsed"]["signed_data_len"], 362);
    assert_eq!(&card.sent[1][..8], "00B00000");
    assert_eq!(
        &card.sent[2][..8],
        format!("00B0{block:04X}"),
        "{}",
        card.sent[2]
    );
}

#[test]
fn a_certificate_longer_than_the_command_reads_is_refused_and_not_truncated() {
    let full_block = hex::encode_upper(vec![0xA5u8; CERT_READ_BLOCK as usize]) + "9000";
    let responses: Vec<&str> = vec![full_block.as_str(); CERT_READ_MAX_BLOCKS];
    let mut card = Scripted::new(&[("00A4", &["9000"]), ("00B0", &responses)]);
    let report = cert_read(&mut card, false).unwrap();

    assert_eq!(report.data["read"], false);
    assert!(
        report.data["error"]
            .as_str()
            .unwrap()
            .contains("longer than"),
        "{}",
        report.data["error"]
    );
    assert_eq!(
        report.data["blocks"].as_array().unwrap().len(),
        CERT_READ_MAX_BLOCKS
    );
    assert!(report.data["parsed"].is_null());
    assert!(report.data["certificate"].is_null());
}
