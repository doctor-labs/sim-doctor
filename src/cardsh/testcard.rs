//! A small stateful UICC for the shell's tests (test builds only). Not a model of any real card: it
//! answers the commands the shell sends, the way ETSI TS 102 221 says a card does, so the shell's state
//! handling is exercised against something that remembers a selection.

use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::rc::Rc;

use super::*;
use crate::transport::{Error as TransportError, ReaderName};

/// The USIM application's AID as EF.DIR lists it.
pub const USIM_AID: [u8; 12] = [
    0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0x49, 0xFF, 0x05, 0x89,
];

/// The Milenage keys of the test card (TS 35.208 test set 1).
pub const TEST_K: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
pub const TEST_OPC: [u8; 16] = [
    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
];

/// A pseudo file identifier for "the application": ADFs have none of their own.
const ADF: u16 = 0x7FFF;

#[derive(Clone)]
pub struct File {
    pub path: Vec<u16>,
    pub df: bool,
    /// `None` for a DF; `Some(record_length)` for a record file (0 = transparent).
    pub rec_len: Option<usize>,
    pub content: Vec<Vec<u8>>,
    /// Whether the file descriptor byte marks this EF as BER-TLV (TS 102 221
    /// structure bits `100`, file-descriptor octet `0x39`). Such EFs are read
    /// with RETRIEVE DATA / SET DATA rather than READ BINARY / UPDATE BINARY.
    pub ber_tlv: bool,
}

pub struct TestCard {
    reader: ReaderName,
    pub files: Vec<File>,
    /// Current directory path, and the EF selected (path) if any, per channel.
    cur: [(Vec<u16>, Option<Vec<u16>>); 4],
    queued: VecDeque<Vec<u8>>,
    open: BTreeSet<u8>,
    pub sent: Rc<RefCell<Vec<Vec<u8>>>>,
    /// Key reference -> (code, tries left, tries at most, verified).
    pub chv: std::collections::BTreeMap<u8, Chv>,
    /// Key reference of the PIN -> (unblock code, tries left, tries at most).
    pub puk: std::collections::BTreeMap<u8, (Vec<u8>, u8, u8)>,
    /// The highest sequence number the card has accepted (SQNms).
    pub sqn_ms: u64,
    /// Whether the card is locked (SET STATUS ISD/locked has been applied).
    pub locked: bool,
}

#[derive(Clone)]
pub struct Chv {
    pub code: Vec<u8>,
    pub left: u8,
    pub max: u8,
    pub verified: bool,
}

fn pad(code: &str) -> Vec<u8> {
    let mut v = code.as_bytes().to_vec();
    v.resize(8, 0xFF);
    v
}

fn f(path: &[u16], df: bool, rec_len: Option<usize>, content: Vec<Vec<u8>>) -> File {
    File {
        path: path.to_vec(),
        df,
        rec_len,
        content,
        ber_tlv: false,
    }
}

/// Like [`f`] but the EF has BER-TLV structure (file-descriptor `0x39`).
fn fbtlv(path: &[u16], content: Vec<u8>) -> File {
    File {
        path: path.to_vec(),
        df: false,
        rec_len: Some(0),
        content: vec![content],
        ber_tlv: true,
    }
}

impl TestCard {
    pub fn usim() -> Self {
        let mf = 0x3F00;
        let files = vec![
            f(&[mf], true, None, vec![]),
            f(
                &[mf, 0x2FE2],
                false,
                Some(0),
                vec![vec![
                    0x98, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54,
                ]],
            ),
            f(
                &[mf, 0x2F00],
                false,
                Some(0x1C),
                vec![
                    [
                        &[0x61, 0x10, 0x4F, 0x0C][..],
                        &USIM_AID[..],
                        &[0x50, 0x04, b'U', b'S', b'I', b'M'],
                    ]
                    .concat()
                    .into_iter()
                    .chain(std::iter::repeat(0xFF))
                    .take(0x1C)
                    .collect(),
                    vec![0xFF; 0x1C],
                ],
            ),
            f(&[mf, ADF], true, None, vec![]),
            // IMSI 001010123456789
            f(
                &[mf, ADF, 0x6F07],
                false,
                Some(0),
                vec![vec![0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]],
            ),
            // EF.AD: operation mode normal, MNC length 2.
            f(
                &[mf, ADF, 0x6FAD],
                false,
                Some(0),
                vec![vec![0x00, 0x00, 0x00, 0x02]],
            ),
            // EF.UST: empty service table (1 byte of 0x00 — no services).
            f(&[mf, ADF, 0x6F38], false, Some(0), vec![vec![0x00]]),
            f(&[mf, 0x7F10], true, None, vec![]),
            f(
                &[mf, 0x7F10, 0x6F3A],
                false,
                Some(0x1C),
                vec![
                    // "Ann" 0123456789 (alpha 14, then BCD number)
                    [
                        &b"Ann"[..],
                        &[0xFF; 11],
                        &[
                            0x07, 0x81, 0x10, 0x32, 0x54, 0x76, 0x98, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF,
                        ],
                    ]
                    .concat(),
                    vec![0xFF; 0x1C],
                    vec![0xFF; 0x1C],
                ],
            ),
            f(
                &[mf, 0x7F10, 0x6F99],
                false,
                Some(0),
                vec![(0..300u16).map(|i| (i % 251) as u8).collect()],
            ),
            f(&[mf, 0x7F20], true, None, vec![]),
            f(
                &[mf, 0x7F20, 0x6F07],
                false,
                Some(0),
                vec![vec![0x08, 0x29, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]],
            ),
            // EF.SST: empty SIM service table (1 byte of 0x00 — no services).
            f(&[mf, 0x7F20, 0x6F38], false, Some(0), vec![vec![0x00]]),
            // A BER-TLV EF under ADF.USIM: two tags (2F = aa bb cc, 30 = 11 22).
            // FID 0x6F5A is deliberately unused by the standard table; used only by tests.
            fbtlv(
                &[mf, ADF, 0x6F5A],
                vec![
                    0x2F, 0x03, 0xAA, 0xBB, 0xCC, // tag 2F, len 3
                    0x30, 0x02, 0x11, 0x22, // tag 30, len 2
                ],
            ),
        ];
        Self {
            reader: ReaderName::new("test card").unwrap(),
            files,
            cur: std::array::from_fn(|_| (vec![mf], None)),
            queued: VecDeque::new(),
            open: BTreeSet::from([0]),
            sent: Rc::default(),
            sqn_ms: 100,
            chv: [
                (0x01, "1234"),
                (0x81, "5678"),
                (0x11, "9999"),
                (0x0A, "77777777"),
            ]
            .into_iter()
            .map(|(k, c)| {
                (
                    k,
                    Chv {
                        code: pad(c),
                        left: 3,
                        max: 3,
                        verified: false,
                    },
                )
            })
            .collect(),
            puk: [(0x01, "12345678"), (0x81, "87654321")]
                .into_iter()
                .map(|(k, c)| (k, (pad(c), 10, 10)))
                .collect(),
            locked: false,
        }
    }

    fn find(&self, path: &[u16]) -> Option<&File> {
        self.files.iter().find(|f| f.path == path)
    }

    fn fcp(&self, file: &File) -> Vec<u8> {
        let fid = *file.path.last().unwrap();
        let mut body = Vec::new();
        if file.df {
            body.extend_from_slice(&[0x82, 0x02, 0x38, 0x21]);
        } else if file.ber_tlv {
            // BER-TLV EF (TS 102 221 structure `100`): working EF, structure
            // bits 4 = "unknown" to the 3-bit parser, but this test card routes
            // SET/RETRIEVE DATA by the `ber_tlv` flag rather than the decoded
            // structure, so the fd byte only needs to mark it as an EF (not a DF).
            body.extend_from_slice(&[0x82, 0x02, 0x0C, 0x21]);
        } else if let Some(len) = file.rec_len.filter(|l| *l > 0) {
            let l = len as u16;
            body.extend_from_slice(&[
                0x82,
                0x05,
                0x0A,
                0x21,
                (l >> 8) as u8,
                l as u8,
                file.content.len() as u8,
            ]);
        } else {
            body.extend_from_slice(&[0x82, 0x02, 0x09, 0x21]);
        }
        if fid != ADF {
            body.extend_from_slice(&[0x83, 0x02, (fid >> 8) as u8, fid as u8]);
        } else {
            body.extend_from_slice(&[0x84, USIM_AID.len() as u8]);
            body.extend_from_slice(&USIM_AID);
        }
        if !file.df {
            let size = match file.rec_len {
                Some(l) if l > 0 => l * file.content.len(),
                _ => file.content.first().map_or(0, Vec::len),
            };
            body.extend_from_slice(&[0x80, 0x02, (size >> 8) as u8, size as u8]);
        }
        body.extend_from_slice(&[0x8A, 0x01, 0x05]);
        let mut out = vec![0x62, body.len() as u8];
        out.extend(body);
        out
    }

    /// Answers SELECT: `61 len` and the FCP queued behind it.
    fn select_ok(&mut self, ch: usize, dir: Vec<u16>, ef: Option<Vec<u16>>, p2: u8) -> Vec<u8> {
        let target = ef.clone().unwrap_or_else(|| dir.clone());
        let file = self.find(&target).cloned().unwrap();
        self.cur[ch] = (dir, ef);
        if p2 & 0x0C == 0x0C {
            return vec![0x90, 0x00];
        }
        let fcp = self.fcp(&file);
        let n = fcp.len() as u8;
        self.queued = VecDeque::from([fcp]);
        vec![0x61, n]
    }

    fn select(&mut self, ch: usize, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let (dir, _) = self.cur[ch].clone();
        let ids: Vec<u16> = data
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
            .collect();
        match p1 {
            0x00 if ids.len() == 1 => {
                let id = ids[0];
                if id == 0x3F00 {
                    return self.select_ok(ch, vec![0x3F00], None, p2);
                }
                let mut child = dir.clone();
                child.push(id);
                if let Some(file) = self.find(&child) {
                    return if file.df {
                        self.select_ok(ch, child, None, p2)
                    } else {
                        self.select_ok(ch, dir, Some(child), p2)
                    };
                }
                if dir.last() == Some(&id) {
                    return self.select_ok(ch, dir, None, p2);
                }
                if dir.len() > 1 && dir[dir.len() - 2..][0] == id || dir.len() == 2 && id == 0x3F00
                {
                    let parent = dir[..dir.len() - 1].to_vec();
                    return self.select_ok(ch, parent, None, p2);
                }
                vec![0x6A, 0x82]
            }
            0x08 | 0x09 => {
                let mut path = if p1 == 0x08 { vec![0x3F00] } else { dir };
                path.extend(ids);
                match self.find(&path) {
                    Some(file) if file.df => self.select_ok(ch, path, None, p2),
                    Some(_) => {
                        let d = path[..path.len() - 1].to_vec();
                        self.select_ok(ch, d, Some(path), p2)
                    }
                    None => vec![0x6A, 0x82],
                }
            }
            0x04 if data.len() >= 5 && USIM_AID.starts_with(data) || data == USIM_AID => {
                self.select_ok(ch, vec![0x3F00, ADF], None, p2)
            }
            _ => vec![0x6A, 0x82],
        }
    }

    fn read(&mut self, ch: usize, cmd: &[u8]) -> Vec<u8> {
        let (dir, ef) = self.cur[ch].clone();
        let Some(file) = ef.and_then(|p| self.find(&p).cloned()) else {
            let _ = dir;
            return vec![0x69, 0x86];
        };
        let le = match cmd.get(4) {
            Some(0) | None => 256,
            Some(n) => usize::from(*n),
        };
        let (p1, p2) = (cmd[2], cmd[3]);
        if cmd[1] == 0xB0 {
            if file.rec_len.is_some_and(|l| l > 0) {
                return vec![0x69, 0x81];
            }
            let off = (usize::from(p1 & 0x7F) << 8) | usize::from(p2);
            let data = &file.content[0];
            if off > data.len() {
                return vec![0x6B, 0x00];
            }
            let avail = data.len() - off;
            if le > avail {
                return vec![0x6C, avail as u8];
            }
            let mut r = data[off..off + le].to_vec();
            r.extend_from_slice(&[0x90, 0x00]);
            r
        } else {
            let Some(rl) = file.rec_len.filter(|l| *l > 0) else {
                return vec![0x69, 0x81];
            };
            if p2 != 0x04 && p2 != 0x02 && p2 != 0x03 {
                return vec![0x6B, 0x00];
            }
            let n = usize::from(p1);
            if n == 0 || n > file.content.len() {
                return vec![0x6A, 0x83];
            }
            if le != rl && le != 256 {
                return vec![0x6C, rl as u8];
            }
            let mut r = file.content[n - 1].clone();
            r.extend_from_slice(&[0x90, 0x00]);
            r
        }
    }

    /// UPDATE BINARY (0xD6) for the selected transparent EF: writes `data` at `offset`.
    fn write(&mut self, ch: usize, cmd: &[u8]) -> Vec<u8> {
        let ef = self.cur[ch].1.clone();
        let Some(path) = ef else {
            return vec![0x69, 0x86];
        };
        let idx = self.files.iter().position(|f| f.path == path);
        let Some(idx) = idx else {
            return vec![0x69, 0x86];
        };
        let file = &mut self.files[idx];
        if file.rec_len.is_some_and(|l| l > 0) {
            return vec![0x69, 0x81];
        }
        let off = (usize::from(cmd[2] & 0x7F) << 8) | usize::from(cmd[3]);
        let data: &[u8] = if cmd.len() > 5 {
            &cmd[5..5 + usize::from(cmd[4]).min(cmd.len() - 5)]
        } else {
            &[]
        };
        // Grow the content if the write extends past the end, then splice.
        let content = &mut file.content[0];
        if off + data.len() > content.len() {
            content.resize(off + data.len(), 0);
        }
        content[off..off + data.len()].copy_from_slice(data);
        vec![0x90, 0x00]
    }
}

impl CardSession for TestCard {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.sent.borrow_mut().push(c.to_vec());
        if c.len() < 4 {
            return Ok(vec![0x67, 0x00]);
        }
        // SET STATUS (INS F0) passes even when the card is locked: it is the
        // only command allowed during a lock.
        if self.locked && c[1] != 0xF0 {
            return Ok(vec![0x6A, 0x81]); // conditions not satisfied
        }
        let ch = usize::from(if c[0] & 0x40 == 0 {
            c[0] & 0x03
        } else {
            4 + (c[0] & 0x0F)
        })
        .min(3);
        let data: &[u8] = if c.len() > 5 {
            &c[5..5 + usize::from(c[4]).min(c.len() - 5)]
        } else {
            &[]
        };
        let ins = c[1];
        Ok(match ins {
            0xA4 => {
                let r = self.select(ch, c[2], c[3], data);
                if c[0] == 0xA0 && r[0] == 0x61 {
                    // GSM 11.11 answers with its own layout and 9F xx.
                    let file = self.cur[ch]
                        .1
                        .clone()
                        .unwrap_or_else(|| self.cur[ch].0.clone());
                    let f = self.find(&file).cloned().unwrap();
                    let size: usize = f.content.iter().map(Vec::len).sum();
                    let mut body = vec![0u8; 22];
                    body[2..4].copy_from_slice(&(size as u16).to_be_bytes());
                    body[4..6].copy_from_slice(&file.last().unwrap().to_be_bytes());
                    body[6] = if f.df {
                        if file.len() == 1 {
                            1
                        } else {
                            2
                        }
                    } else {
                        4
                    };
                    self.queued = VecDeque::from([body]);
                    vec![0x9F, 22]
                } else {
                    r
                }
            }
            0xC0 => match self.queued.pop_front() {
                Some(mut r) => {
                    r.extend_from_slice(&[0x90, 0x00]);
                    r
                }
                None => vec![0x6F, 0x00],
            },
            0xB0 | 0xB2 => self.read(ch, c),
            0xD6 => self.write(ch, c),
            0x70 => {
                if c[2] == 0x00 {
                    match (1u8..=3).find(|n| !self.open.contains(n)) {
                        Some(n) => {
                            self.open.insert(n);
                            self.cur[usize::from(n)] = (vec![0x3F00], None);
                            vec![n, 0x90, 0x00]
                        }
                        None => vec![0x68, 0x81],
                    }
                } else if self.open.remove(&c[3]) {
                    vec![0x90, 0x00]
                } else {
                    vec![0x6A, 0x86]
                }
            }
            0xF2 => vec![0x90, 0x00],
            // INTERNAL AUTHENTICATE, 3G context: 10 RAND 10 AUTN. Real Milenage with a sequence-number check.
            0x88 if c[3] == 0x81 && c[0] & 0xFC == 0 => match data {
                [0x10, rest @ ..] if rest.len() == 33 && rest[16] == 0x10 => {
                    let rand: [u8; 16] = rest[..16].try_into().unwrap();
                    let autn: [u8; 16] = rest[17..].try_into().unwrap();
                    let op = crate::aka::Operator::Opc(TEST_OPC);
                    let ak = crate::aka::compute(TEST_K, op, &rand, &[0; 6], &[0; 2]).ak;
                    let mut sqn = [0u8; 6];
                    for i in 0..6 {
                        sqn[i] = autn[i] ^ ak[i];
                    }
                    let amf: [u8; 2] = autn[6..8].try_into().unwrap();
                    let o = crate::aka::compute(TEST_K, op, &rand, &sqn, &amf);
                    let n = sqn.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
                    let body = if o.mac_a != autn[8..] {
                        return Ok(vec![0x98, 0x62]);
                    } else if n <= self.sqn_ms {
                        let ms: [u8; 6] = self.sqn_ms.to_be_bytes()[2..].try_into().unwrap();
                        let so = crate::aka::compute(TEST_K, op, &rand, &ms, &[0; 2]);
                        let mut b = vec![0xDC, 0x0E];
                        b.extend((0..6).map(|i| ms[i] ^ so.ak_star[i]));
                        b.extend(so.mac_s);
                        b
                    } else {
                        self.sqn_ms = n;
                        let mut b = vec![0xDB, 0x08];
                        b.extend(o.res);
                        b.push(0x10);
                        b.extend(o.ck);
                        b.push(0x10);
                        b.extend(o.ik);
                        b
                    };
                    let len = body.len() as u8;
                    self.queued = VecDeque::from([body]);
                    vec![0x61, len]
                }
                _ => vec![0x67, 0x00],
            },
            // RUN GSM ALGORITHM (SIM, CLA A0) / INTERNAL AUTHENTICATE in the GSM context (USIM, P2 80).
            // Not COMP128: SRES and Kc are fixed mixes of RAND, enough to tell a stateless card apart.
            0x88 if c[3] == 0x00 && c[0] == 0xA0 || c[3] == 0x80 && c[0] & 0xFC == 0 => {
                let rand = if c[3] == 0x80 {
                    data.get(1..)
                } else {
                    Some(data)
                };
                match rand.filter(|r| r.len() == 16) {
                    None => vec![0x67, 0x00],
                    Some(_) if c[0] == 0xA0 && self.cur[0].0 != [0x3F00, 0x7F20] => {
                        vec![0x6F, 0x00]
                    }
                    Some(r) => {
                        let sres: Vec<u8> = (0..4).map(|i| r[i] ^ r[i + 4]).collect();
                        let kc: Vec<u8> = (0..8).map(|i| r[i] ^ r[i + 8].rotate_left(1)).collect();
                        let mut body = if c[3] == 0x80 { vec![0x04] } else { vec![] };
                        body.extend(&sres);
                        if c[3] == 0x80 {
                            body.push(0x08);
                        }
                        body.extend(&kc);
                        let n = body.len() as u8;
                        self.queued = VecDeque::from([body]);
                        vec![if c[0] == 0xA0 { 0x9F } else { 0x61 }, n]
                    }
                }
            }
            // VERIFY: no data asks how many tries are left; a wrong code costs one.
            0x20 => match self.chv.get_mut(&c[3]) {
                None => vec![0x6A, 0x88],
                Some(k) if k.left == 0 => vec![0x69, 0x83],
                Some(k) if data.is_empty() => {
                    if k.verified {
                        vec![0x90, 0x00]
                    } else {
                        vec![0x63, 0xC0 | k.left]
                    }
                }
                Some(k) if data == k.code => {
                    k.left = k.max;
                    k.verified = true;
                    vec![0x90, 0x00]
                }
                Some(k) => {
                    k.left -= 1;
                    if k.left == 0 {
                        vec![0x69, 0x83]
                    } else {
                        vec![0x63, 0xC0 | k.left]
                    }
                }
            },
            // UNBLOCK PIN: PUK (8) + new PIN (8).
            0x2C => match (self.puk.get_mut(&c[3]), self.chv.get_mut(&c[3])) {
                (Some((_, 0, _)), _) => vec![0x69, 0x83],
                (Some((_, left, _)), Some(_)) if data.is_empty() => vec![0x63, 0xC0 | *left],
                (Some((code, left, max)), Some(k))
                    if data.len() == 16 && &data[..8] == code.as_slice() =>
                {
                    *left = *max;
                    k.code = data[8..].to_vec();
                    k.left = k.max;
                    k.verified = false;
                    vec![0x90, 0x00]
                }
                (Some((_, left, _)), Some(_)) if data.len() == 16 => {
                    *left -= 1;
                    if *left == 0 {
                        vec![0x69, 0x83]
                    } else {
                        vec![0x63, 0xC0 | *left]
                    }
                }
                (Some(_), Some(_)) => vec![0x67, 0x00],
                _ => vec![0x6A, 0x88],
            },
            // SET DATA / DELETE DATA (TS 102 221 11.3.2): INS 0xDB, case 3.
            // P2 bit 7 set = first block, clear = more blocks. The data is a
            // BER-TLV fragment; a single tag byte on the first block deletes it.
            0xDB => self.set_data(ch, c[2], c[3], data),
            // RETRIEVE DATA (TS 102 221 11.3.1): INS 0xCB, case 4.
            // P2 bit 7 set = first block. The data is one tag octet (0x5C asks
            // for the list of tags present).
            0xCB => self.retrieve_data(ch, c[2], c[3], data),
            // GET IDENTITY (TS 31.102 4.2.2): INS 0x78, case 2 with Le.
            // Returns the SUCI/identity from the selected application.
            0x78 => self.get_identity(ch),
            // ENVELOPE (INS 0xC2): the terminal pushes an envelope to the card,
            // e.g. an Event Download (D6) or SMS-PP download (D1). The test card
            // just records it (via self.sent in transmit) and answers 90 00.
            0xC2 => vec![0x90, 0x00],
            // TERMINAL RESPONSE (INS 0x14): answers a proactive command.
            // The test card answers 90 00.
            0x14 => vec![0x90, 0x00],
            // SET STATUS (GP Card Spec v2.3.1 11.5.2.3.3, INS F0): P1 = scope,
            // P2 = lifecycle state. The card is locked when scope is ISD and the
            // state is `locked` (0x83). The AID data, if present, names a file.
            0xF0 => self.set_status(c[2], c[3], data),
            _ => vec![0x6D, 0x00],
        })
    }

    fn disconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl TestCard {
    /// SET DATA: store/replace a BER-TLV object or delete a tag. The selected
    /// EF must be BER-TLV; anything else is refused with `6A 80`.
    fn set_data(&mut self, ch: usize, _p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let Some(path) = self.cur[ch].1.clone() else {
            return vec![0x6A, 0x86];
        };
        let file = match self.files.iter_mut().find(|f| f.path == path) {
            Some(f) => f,
            None => return vec![0x6A, 0x82],
        };
        if !file.ber_tlv {
            return vec![0x6A, 0x80];
        }
        let first = p2 & 0x80 != 0;
        let body = &mut file.content[0];
        if !first {
            // Append more-blocks data to the accumulator (not exercised by tests
            // whose payloads fit in one block, but kept so the card answers).
            body.extend_from_slice(data);
            return vec![0x90, 0x00];
        }
        // First block: a lone tag octet deletes that tag; otherwise the data is
        // a complete BER-TLV object (tag + length + value).
        if data.len() == 1 {
            remove_tag(body, data[0]);
        } else if data.len() >= 2 {
            // Replace an existing object for this tag, or append a new one.
            remove_tag(body, data[0]);
            body.extend_from_slice(data);
        }
        vec![0x90, 0x00]
    }

    /// RETRIEVE DATA: return a tag's value, or the list of tags (tag 0x5C).
    fn retrieve_data(&mut self, ch: usize, _p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let (_dir, ef) = self.cur[ch].clone();
        let Some(path) = ef else {
            return vec![0x6A, 0x86];
        };
        let file = match self.files.iter().find(|f| f.path == path) {
            Some(f) => f,
            None => return vec![0x6A, 0x82],
        };
        if !file.ber_tlv {
            return vec![0x6A, 0x80];
        }
        if p2 & 0x80 == 0 {
            // Next block: nothing more to send for a single-block answer.
            return vec![0x62, 0xF1];
        }
        let want = data.first().copied().unwrap_or(0);
        let mut out = Vec::new();
        if want == 0x5C {
            // Return all tag octets present, wrapped in a 5C TLV.
            let tags: Vec<u8> = collect_tags(&file.content[0]);
            out.push(0x5C);
            out.push(tags.len() as u8);
            out.extend(tags);
        } else if let Some(val) = find_value(&file.content[0], want) {
            out.push(want);
            out.extend(crate::tlv::Length::new(u16::try_from(val.len()).unwrap()).encode());
            out.extend_from_slice(&val);
        } else {
            return vec![0x6A, 0x82];
        }
        // The shell asked for 256 bytes (Le 00); answer what we have.
        out.extend_from_slice(&[0x90, 0x00]);
        out
    }

    /// GET IDENTITY (TS 31.102 4.2.2): returns the SUCI/identity.
    /// The identity is read from EF.IMSI when no 5GS identity is available.
    fn get_identity(&mut self, ch: usize) -> Vec<u8> {
        let (_dir, ef) = self.cur[ch].clone();
        // If we have an EF selected, try to read its identity.
        // For a USIM application, this would typically be the IMSI or SUCI.
        // Return a synthetic identity for testing purposes.
        if let Some(path) = ef {
            let file = match self.files.iter().find(|f| f.path == path) {
                Some(f) => f,
                None => return vec![0x6A, 0x82],
            };
            // For identity files, return synthetic data
            if file.content.is_empty() || file.content[0].is_empty() {
                // Return a synthetic identity: a minimal SUCI-like structure
                // Format: identity type + data (for testing, we return IMSI-like data)
                // 0x00 0x08 indicates IMSI at layer 1, followed by 8 octets of data
                let mut identity = vec![0x00, 0x08]; // IMSI type, length 8
                identity.extend_from_slice(&[0x09, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78, 0x90]); // IMSI: 001010123456789
                identity.extend_from_slice(&[0x90, 0x00]);
                identity
            } else {
                // Return what's in the file for BER-TLV EFs
                let content = &file.content[0];
                if file.ber_tlv {
                    let tags = collect_tags(content);
                    if let Some(&tag) = tags.first() {
                        if let Some(val) = find_value(content, tag) {
                            let mut out = vec![tag];
                            out.extend(
                                crate::tlv::Length::new(u16::try_from(val.len()).unwrap()).encode(),
                            );
                            out.extend(val);
                            out.extend_from_slice(&[0x90, 0x00]);
                            return out;
                        }
                    }
                }
                // Return the raw content
                let mut out = content.clone();
                out.extend_from_slice(&[0x90, 0x00]);
                out
            }
        } else {
            // No EF selected - return a synthetic identity from the USIM application
            // EF.IMSI contains IMSI 001010123456789 (BCD encoded)
            let mut identity = vec![0x00, 0x08]; // Identity type, length 8
            identity.extend_from_slice(&[0x09, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78, 0x90]); // IMSI
            identity.extend_from_slice(&[0x90, 0x00]);
            identity
        }
    }

    /// SET STATUS (GP Card Spec v2.3.1 11.5.2.3.3): `p1` = scope, `p2` = state.
    /// Only the ISD lock is simulated: ISD scope (`80`) with CARD_LOCKED (`7F`)
    /// sets the card's `locked` flag so later commands answer `6A 81`; ISD scope
    /// with INITIALIZED (`07`) or SECURED (`0F`) clears it. Every other scope and
    /// state answers `90 00` without changing anything; the AID is ignored.
    fn set_status(&mut self, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        if p1 == 0x80 && p2 == 0x7F {
            self.locked = true;
            return vec![0x90, 0x00];
        }
        if p1 == 0x80 && matches!(p2, 0x07 | 0x0F) && self.locked {
            self.locked = false;
            return vec![0x90, 0x00];
        }
        let _ = data;
        vec![0x90, 0x00]
    }
}

/// Removes every BER-TLV object carrying `tag` from `body`, in place.
fn remove_tag(body: &mut Vec<u8>, tag: u8) {
    let mut at = 0usize;
    while at < body.len() {
        let Some((len, n)) = read_ber_len(&body[at + 1..]) else {
            break;
        };
        if body[at] == tag {
            body.drain(at..at + 1 + n + len_value(len));
        } else {
            at += 1 + n + len_value(len);
        }
    }
}

/// The tag bytes present in a flattened BER-TLV body.
fn collect_tags(body: &[u8]) -> Vec<u8> {
    let mut tags = Vec::new();
    let mut at = 0usize;
    while at < body.len() {
        let tag = body[at];
        let Some((len, n)) = read_ber_len(&body[at + 1..]) else {
            break;
        };
        tags.push(tag);
        at += 1 + n + len_value(len);
    }
    tags
}

/// The value bytes for `tag` in a flattened BER-TLV body, if present.
fn find_value(body: &[u8], tag: u8) -> Option<Vec<u8>> {
    let mut at = 0usize;
    while at < body.len() {
        let Some((len, n)) = read_ber_len(&body[at + 1..]) else {
            break;
        };
        if body[at] == tag {
            let start = at + 1 + n;
            return Some(body[start..start + len_value(len)].to_vec());
        }
        at += 1 + n + len_value(len);
    }
    None
}

/// Reads a BER-TLV length, returning `(value, header_octets)` or `None` if it
/// cannot be parsed from the available bytes.
fn read_ber_len(bytes: &[u8]) -> Option<(u16, usize)> {
    let (&first, rest) = bytes.split_first()?;
    if first & 0x80 == 0 {
        return Some((u16::from(first), 1));
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 2 || rest.len() < count {
        return None;
    }
    let mut value: u16 = 0;
    for &octet in &rest[..count] {
        value = (value << 8) | u16::from(octet);
    }
    Some((value, 1 + count))
}

/// The number of value octets a decoded length describes.
fn len_value(len: u16) -> usize {
    len as usize
}

/// A shell on a fresh [`TestCard::usim`] (a new one for every `equip`), and the log of every command
/// the cards were sent.
pub fn shell_log() -> (Shell, Rc<RefCell<Vec<Vec<u8>>>>) {
    let log: Rc<RefCell<Vec<Vec<u8>>>> = Rc::default();
    let sent = log.clone();
    let mut sh = Shell::new(
        Box::new(move |_| {
            let mut card = TestCard::usim();
            card.sent = sent.clone();
            Ok((
                Box::new(card) as Box<dyn CardSession>,
                "test card".to_owned(),
                Some(vec![0x3B, 0x9F]),
            ))
        }),
        Opts {
            yes: false,
            dialect: TagSet::ts_102_221(),
            secrets: None,
            card_key: None,
            card_keys: None,
        },
    );
    sh.equip(None, Profile::Uicc).unwrap();
    (sh, log)
}

/// The PIN source text that also gives the test card's Milenage keys.
pub const KEYS: &str =
    "ki=hex:465b5ce8b199b49faa5f0a2ee238a6bc; opc=hex:cd63cb71954a9f4e48a5994e37a02baf";

/// Like [`shell_log`] with a PIN source and `--yes` as given.
pub fn shell_with(secrets: &str, yes: bool) -> (Shell, Rc<RefCell<Vec<Vec<u8>>>>) {
    let (mut sh, log) = shell_log();
    sh.opts.secrets = Some(crate::cardsh::secrets::Secrets::parse(secrets).unwrap());
    sh.opts.yes = yes;
    (sh, log)
}

pub fn shell_on(_card: TestCard) -> Shell {
    shell_log().0
}

/// A writer into a shared buffer, so a [`Record`](crate::transport::replay::Record) log can be read back.
#[derive(Clone, Default)]
struct Sink(Rc<RefCell<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `script` (`;`-separated) on a fresh test card with `--yes` as given and returns the recorded
/// exchange log (the `SIM_DOCTOR_RECORD` format) and the replies.
pub fn record(script: &str, yes: bool) -> (String, Vec<Reply>) {
    let sink = Sink::default();
    let log = sink.clone();
    let mut sh = Shell::new(
        Box::new(move |_| {
            let rec = crate::transport::replay::Record::new(TestCard::usim(), log.clone());
            Ok((
                Box::new(rec) as Box<dyn CardSession>,
                "test card".to_owned(),
                None,
            ))
        }),
        Opts {
            yes,
            dialect: TagSet::ts_102_221(),
            secrets: Some(crate::cardsh::secrets::Secrets::parse(FIXTURE_SECRETS).unwrap()),
            card_key: None,
            card_keys: None,
        },
    );
    sh.equip(None, Profile::Uicc).unwrap();
    let replies = split_commands(script).iter().map(|l| sh.exec(l)).collect();
    let text = String::from_utf8(sink.0.borrow().clone()).unwrap();
    (text, replies)
}

/// The scripts whose recordings are committed under `tests/corpus/` for the process tests:
/// (file name, `--yes`, script).
/// The PIN source the recorded scripts run with (and `tests/cardsh.rs` hands the binary).
pub const FIXTURE_SECRETS: &str = "pin1=1234; pin2=0000; puk1=12345678; new-pin1=4321; \
     ki=hex:465b5ce8b199b49faa5f0a2ee238a6bc; opc=hex:cd63cb71954a9f4e48a5994e37a02baf";

pub const FIXTURES: &[(&str, bool, &str)] = &[
    (
        "cardsh_channels.jsonl",
        false,
        "open_channel; status; channel 0; status; close_channel 1; status",
    ),
    (
        "cardsh_apdu.jsonl",
        false,
        "apdu 00A4000C022FE2; apdu 00B000000A --expect-response-regex ^9810; apdu 00D6000001AA; \
         apdu --yes 00D6000001AA --expect-sw 6Dxx",
    ),
    (
        "cardsh_select.jsonl",
        false,
        "select 3F00; select 7F20; select 6F07; select 3F00; select 3F00/7F10/6F3A; select ADF.USIM; \
         select EF.IMSI; select_path 6FAD; select 2FE2",
    ),
    (
        "cardsh_cardinfo.jsonl",
        false,
        "select 7F20; cardinfo; status",
    ),
    (
        "cardsh_read.jsonl",
        false,
        "select 2FE2; read_binary; read_binary --offset 2 --length 3; read_binary --length 20; select 3F00/7F10/6F3A; \
         read_record 1; read_records; read_record 4; select 3F00/7F10/6F99; read_binary",
    ),
    (
        "cardsh_decoded.jsonl",
        false,
        "select ADF.USIM; select EF.IMSI; read_binary_decoded; select EF.AD; read_binary_decoded; \
         select 3F00/7F10/6F3A; read_records_decoded; select 3F00/2FE2; read_binary_decoded",
    ),
    (
        "cardsh_chv.jsonl",
        true,
        "verify_chv; verify_chv --pin-nr 2; verify_chv --pin-nr 2",
    ),
    (
        "cardsh_unblock.jsonl",
        true,
        "unblock_chv; verify_chv",
    ),
    (
        "cardsh_gsm.jsonl",
        true,
        "run_gsm_algorithm --rand 000102030405060708090a0b0c0d0e0f --repeat 2",
    ),
    (
        "cardsh_auth.jsonl",
        true,
        "authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 200; \
         authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 50 --resync; \
         authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --autn 00112233445566778899aabbccddeeff",
    ),
    (
        "cardsh_fsdump.jsonl",
        false,
        "fsdump; fsdump --filename EF.ICCID; export --filename EF.ICCID",
    ),
    (
        // RETRIEVE DATA (read-only: sent without --yes). The BER-TLV EF 6F5A holds
        // tags 2F (aa bb cc) and 30 (11 22); tag 31 is absent and fails.
        "cardsh_retrieve.jsonl",
        false,
        "select 3F00/ADF:A0000000871002/6F5A; retrieve_tags; retrieve_data 2F; \
         retrieve_data 30; retrieve_data 5C; retrieve_data 31",
    ),
];

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(name)
}

#[test]
fn committed_fixtures_match_a_fresh_recording() {
    for (name, yes, script) in FIXTURES {
        let want = std::fs::read_to_string(fixture_path(name))
            .unwrap_or_else(|e| panic!("{name}: {e}; run the ignored regenerate_fixtures test"));
        assert_eq!(
            want,
            record(script, *yes).0,
            "{name} drifted from the test card"
        );
    }
}

#[test]
#[ignore = "regenerates tests/corpus/cardsh_*.jsonl"]
fn regenerate_fixtures() {
    for (name, yes, script) in FIXTURES {
        std::fs::write(fixture_path(name), record(script, *yes).0).unwrap();
    }
}
