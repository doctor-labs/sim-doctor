//! Ki, OPc, ICCID and IMSI for one card, derived from a secret the operator holds.
//!
//! **Owns.** The key schedule. An HKDF-SHA256 root keyed by the operator's secret,
//! the Ki and the OP it expands, the OPc AES-CMC over those, and the ICCID and IMSI
//! digit strings that carry the same secret. No card is opened and no APDU is sent;
//! the result is text on stdout for a provisioning run to consume.
//!
//! **Does not own.** Milenage: OPc is [`crate::aka`]'s, so the AES-CMC is computed
//! once in this crate and not a second time here. Nor the ICCID/IMSI layout, which
//! follows pySim-prog.py's autogen (osmocom/pysim, GPL; cited in CONTEXT.md, never
//! copied).
//!
//! # Why a secret, and why never a clock
//!
//! pySim-prog.py draws Ki with `os.urandom(16)` and, when no `-z` is given, builds
//! the ICCID and IMSI straight from the card number (`('%%0%dd' % ml) % opts.num`),
//! so an unseeded batch is guessable by anyone who ran the same command. A Ki that
//! can be guessed is a Ki that is already broken, so nothing here is derived from
//! the clock, from a fixed seed, or from the card number alone: every byte comes out
//! of the secret through HKDF.
//!
//! # The two modes, and exactly how a key is produced
//!
//! `root = HKDF-Extract(salt = LABEL, ikm = secret)` (RFC 5869, SHA-256), a 32-byte
//! pseudorandom key that never leaves the process. A *selector* then says which card
//! of the batch this is, and the same two lines run once per field:
//!
//! ```text
//! selector = "idx" || be_u32(index)                  (deterministic mode, -j N)
//! selector = "rnd" || salt                           (random mode, 32 fresh OS bytes)
//! Ki       = HKDF-Expand(root, "ki"   || selector, 16)
//! OP       = HKDF-Expand(root, "op"   || selector, 16)
//! OPc      = AES-CMC(Ki, OP)
//! ICCID    = "89" || MCC || MNC || digits(root, "iccid", selector) || Luhn check digit
//! IMSI     = MCC || MNC || digits(root, "imsi", selector)
//! ```
//!
//! That is not predictable, and the two properties are separate. Within one batch,
//! two cards differ only by a selector string fed to a PRF, so card 7 and card 8
//! are unrelated 128-bit values and no relation between them survives the HMAC; a
//! grid walk over card numbers recovers nothing, because the card number never
//! reaches a digest on its own, only as 4 bytes after a fixed 3-byte tag and behind
//! the secret. Across batches, a different secret is a different `root` and
//! therefore a different Ki for every card index at once, so a batch that leaks
//! does not compromise another. In random mode the OS salt adds the property pySim
//! gets from `urandom`: the same secret and no `-j` give a fresh Ki on every run,
//! and the salt is printed so a printed batch can be regenerated with [`Request::with_salt`].
//!
//! [`Request::with_salt`]: Request::with_salt

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::aka;

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "keygen";

/// The HKDF salt: a fixed public label, so every expansion here is separated from
/// every other use of the same secret in the same process.
const LABEL: &[u8] = b"sim-doctor keygen v1";

/// The highest multiple of ten that fits in a byte. Bytes at or above it are
/// dropped rather than folded, so the ten digits stay uniform; the ICCID and IMSI
/// bodies are not secret, but a visibly biased card number is still a bug.
const DIGIT_CEILING: u8 = 250;

/// Bytes pulled per block of digit rejection sampling.
const BLOCK: usize = 64;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Which card of a batch this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// No `-j`: a fresh OS salt per run, and so a fresh key per run, as pySim's
    /// `os.urandom` Ki is fresh per run.
    Random,
    /// `-j N`: card N of the batch, so card 7 gets the same Ki every time.
    Indexed(u32),
}

impl Mode {
    /// The word the output and the JSON envelope name this mode by.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Random => "random",
            Mode::Indexed(_) => "deterministic",
        }
    }
}

/// The public inputs of one derivation: which card, and the salt if it is pinned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request {
    /// Which card of the batch.
    pub mode: Mode,
    /// Random mode only. `None` draws 32 bytes from the OS; `Some` pins them, which
    /// is what makes a printed random batch reproducible.
    pub salt: Option<[u8; 32]>,
}

impl Request {
    /// Card `index` of the batch: the same secret and the same index give the same
    /// key, every time and on every machine.
    pub fn indexed(index: u32) -> Self {
        Request {
            mode: Mode::Indexed(index),
            salt: None,
        }
    }

    /// No index: a fresh salt, and so a fresh key, on every run.
    pub fn random() -> Self {
        Request {
            mode: Mode::Random,
            salt: None,
        }
    }

    /// Pins random mode's salt, so a printed salt reproduces the printed card.
    pub fn with_salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }
}

/// The Mobile Country Code and Mobile Network Code an ICCID and IMSI are issued
/// under. Both are digit strings: MCC zero-padded to 3, MNC to `--mnclen`
/// (2 or 3), which is what makes the IMSI's length come out right.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plmn {
    /// 1 to 3 decimal digits.
    pub mcc: String,
    /// 2 or 3 decimal digits, already padded.
    pub mnc: String,
}

/// Why a PLMN cannot be used.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlmnError(pub String);

impl std::fmt::Display for PlmnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlmnError {}

impl Plmn {
    /// Zero-pads and checks a pair of digit strings. `mnclen` is the MNC's width,
    /// the same option pySim-prog.py calls `--mnclen`; 0 means "match the MNC's
    /// own length", which is pySim's `auto`.
    pub fn new(mcc: &str, mnc: &str, mnclen: u8) -> Result<Self, PlmnError> {
        for (name, value) in [("--mcc", mcc), ("--mnc", mnc)] {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(PlmnError(format!("{name} must be decimal digits only")));
            }
        }
        let mcc_len = mcc.len();
        if !(1..=3).contains(&mcc_len) {
            return Err(PlmnError("--mcc must be 1 to 3 digits".to_string()));
        }
        // mnclen 0 is pySim's `auto`: keep the MNC's own width, but never below 2,
        // which is what pySim-prog.py's `lpad(mnc, 2, "0")` does.
        let want_mnc = if mnclen == 0 {
            mnc.len().max(2)
        } else {
            mnclen as usize
        };
        if !(2..=3).contains(&want_mnc) {
            return Err(PlmnError("--mnclen must be 2 or 3".to_string()));
        }
        if mnc.len() > want_mnc {
            return Err(PlmnError("--mnc is longer than --mnclen".to_string()));
        }
        Ok(Plmn {
            mcc: format!("{mcc:0>3}"),
            mnc: format!("{mnc:0>want_mnc$}"),
        })
    }

    /// The concatenated MCC and MNC: 5 digits, or 6 with a 3-digit MNC.
    pub fn digits(&self) -> String {
        format!("{}{}", self.mcc, self.mnc)
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// One card's secret material. Debug is derived, and every field here is printed
/// by [`Material::human`] anyway, so there is nothing to keep out of a log.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Material {
    /// The subscriber key.
    pub ki: [u8; 16],
    /// The operator key, derived from the same secret.
    pub op: [u8; 16],
    /// The operator key derived from `ki`, the AES-CMC pySim computes for OPc.
    pub opc: [u8; 16],
    /// 19 digits, Luhn-checked, starting `89`.
    pub iccid: String,
    /// 15 digits, starting with the PLMN.
    pub imsi: String,
    /// Which card of the batch this is.
    pub mode: Mode,
    /// The OS salt that was drawn, in random mode only.
    pub salt: Option<[u8; 32]>,
}

impl Material {
    /// The human output. Labelled as secret material, because it is.
    pub fn human(&self) -> String {
        let mut s = String::new();
        s.push_str(
            "SECRET MATERIAL - this card's Ki and OPc. Do not log, do not paste, do not commit.\n",
        );
        s.push_str(&format!("mode      : {}\n", self.mode.as_str()));
        if let Mode::Indexed(n) = self.mode {
            s.push_str(&format!("index     : {n}\n"));
        }
        if let Some(salt) = &self.salt {
            s.push_str(&format!("salt      : {}\n", hex::encode(salt)));
            s.push_str(
                "            public input, printed so this card can be regenerated with --salt\n",
            );
        }
        s.push_str(&format!("Ki        : {}\n", hex::encode(self.ki)));
        s.push_str(&format!("OPc       : {}\n", hex::encode(self.opc)));
        s.push_str(&format!("ICCID     : {}\n", self.iccid));
        s.push_str(&format!("IMSI      : {}\n", self.imsi));
        s
    }

    /// The envelope's `data`. Carries the card and never the secret.
    pub fn data(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode.as_str(),
            "index": match self.mode { Mode::Indexed(n) => serde_json::json!(n), Mode::Random => serde_json::Value::Null },
            "salt": self.salt.map(hex::encode),
            "ki": hex::encode(self.ki),
            "opc": hex::encode(self.opc),
            "iccid": self.iccid,
            "imsi": self.imsi,
            "secret_material": true,
        })
    }
}

// ---------------------------------------------------------------------------
// The derivation
// ---------------------------------------------------------------------------

/// Derives one card's material. `secret` is the operator's bytes and is never
/// stored in, or readable from, the result.
pub fn derive(secret: &[u8], request: Request, plmn: &Plmn) -> Material {
    let root = hkdf_extract(LABEL, secret);

    let (selector, salt) = match request.mode {
        Mode::Indexed(index) => {
            let mut selector = Vec::with_capacity(7);
            selector.extend_from_slice(b"idx");
            selector.extend_from_slice(&index.to_be_bytes());
            (selector, None)
        }
        Mode::Random => {
            let salt = request.salt.unwrap_or_else(draw_salt);
            let mut selector = Vec::with_capacity(35);
            selector.extend_from_slice(b"rnd");
            selector.extend_from_slice(&salt);
            (selector, Some(salt))
        }
    };

    let ki = expand_u16(&root, b"ki", &selector);
    let op = expand_u16(&root, b"op", &selector);
    let opc = aka::opc(ki, op);

    let plmn_digits = plmn.digits();
    // pySim-prog.py: iccid = "89" + country + PLMN, then digits filling to 18,
    // then the Luhn check digit, so 19. Here the country digit string is dropped
    // and the PLMN carries the country, so the same 19 come out of the same rule.
    let iccid_body = 18usize.saturating_sub(2 + plmn_digits.len());
    let mut iccid = String::with_capacity(19);
    iccid.push_str("89");
    iccid.push_str(&plmn_digits);
    iccid.push_str(&digits(&root, b"iccid", &selector, iccid_body));
    iccid.push(char::from(b'0' + luhn_check(&iccid)));

    // pySim-prog.py: "IMSI (15 digits usually)", msin fills 15 - len(PLMN).
    let imsi_body = 15usize.saturating_sub(plmn_digits.len());
    let mut imsi = String::with_capacity(15);
    imsi.push_str(&plmn_digits);
    imsi.push_str(&digits(&root, b"imsi", &selector, imsi_body));

    Material {
        ki,
        op,
        opc,
        iccid,
        imsi,
        mode: request.mode,
        salt,
    }
}

/// 32 bytes from the OS CSPRNG. Public input, and the only thing in this crate
/// that is not a function of the secret: it is what makes two runs of random mode
/// differ, and it is printed so the pair can be replayed.
fn draw_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::fill(&mut salt);
    salt
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869) over HMAC-SHA256
// ---------------------------------------------------------------------------

/// RFC 5869 section 2.2, HKDF-Extract.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts a key of any length");
    mac.update(ikm);
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&mac.finalize().into_bytes());
    prk
}

/// RFC 5869 section 2.3, HKDF-Expand, for the lengths this crate asks for (16, 32
/// and the digit streams). `256 / 32 = 8` blocks is the RFC's own ceiling and is
/// far above what is asked for, so the loop terminates.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(prk).expect("HMAC accepts a key of any length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&previous);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// The `info` one expansion sees: what is being derived, and which card of the batch.
fn field_info(label: &[u8], selector: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + selector.len());
    info.extend_from_slice(label);
    info.extend_from_slice(selector);
    info
}

fn expand_u16(root: &[u8; 32], label: &[u8], selector: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&hkdf_expand(root, &field_info(label, selector), 16));
    out
}

/// Exactly `count` decimal digits, uniform over 0..=9.
fn digits(root: &[u8; 32], label: &[u8], selector: &[u8], count: usize) -> String {
    let mut out = String::with_capacity(count);
    let mut block = 0u32;
    let mut stream: Vec<u8> = Vec::new();
    let mut at = 0usize;
    while out.len() < count {
        if at == stream.len() {
            let mut info = field_info(label, selector);
            info.extend_from_slice(&block.to_be_bytes());
            stream = hkdf_expand(root, &info, BLOCK);
            block += 1;
            at = 0;
        }
        let byte = stream[at];
        at += 1;
        if byte < DIGIT_CEILING {
            out.push(char::from(b'0' + byte % 10));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Luhn, as pySim-prog.py's calculate_luhn / verify_luhn
// ---------------------------------------------------------------------------

/// The Luhn check digit for a digit string that does not yet carry one.
pub fn luhn_check(digits: &str) -> u8 {
    // pySim-prog.py: sum(num[-2::-2] + [sum(divmod(d * 2, 10)) for d in num[::-2]]).
    // `num[::-2]` walks from the LAST digit backwards two at a time, so the digits
    // in positions 1, 3, 5 ... counted from the right are the ones doubled, and
    // their two decimal digits are summed; positions 2, 4, 6 ... are taken as they
    // are. `10 - sum % 10`, and a 10 becomes 0.
    let bytes: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
    let sum: usize = bytes
        .iter()
        .rev()
        .enumerate()
        .map(|(from_right, d)| {
            let product = if from_right % 2 == 0 {
                *d as usize * 2
            } else {
                *d as usize
            };
            product / 10 + product % 10
        })
        .sum();
    let check = 10 - sum % 10;
    if check == 10 {
        0
    } else {
        check as u8
    }
}

/// Whether a full digit string, check digit included, passes Luhn.
pub fn luhn_ok(digits: &str) -> bool {
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && luhn_check(&digits[..digits.len() - 1]) == digits.as_bytes()[digits.len() - 1] - b'0'
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &[u8] = b"correct horse battery staple";
    const SECRET_B: &[u8] = b"correct horse battery staplE";

    fn plmn() -> Plmn {
        Plmn::new("901", "55", 2).unwrap()
    }

    // --- HKDF against RFC 5869, not against this file --------------------------------

    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        // RFC 5869 appendix A.1, "Basic test case with SHA-256": SHA-256, a 22-byte
        // IKM of 0x0b, a 13-byte salt, a 10-byte info and L = 42.
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex::encode(prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        assert_eq!(
            hex::encode(hkdf_expand(&prk, &info, 42)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_3() {
        // RFC 5869 appendix A.3, "test with SHA-256 and zero-length salt/info": the
        // degenerate case, which is what this crate does not use but a broken
        // implementation often gets wrong.
        let ikm = [0x0bu8; 22];
        let prk = hkdf_extract(&[], &ikm);
        assert_eq!(
            hex::encode(prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        assert_eq!(
            hex::encode(hkdf_expand(&prk, &[], 42)),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    // --- OPc is milenage's, checked against a 3GPP known answer ----------------------

    #[test]
    fn opc_for_a_known_ki_is_the_ts_35_208_vector() {
        // 3GPP TS 35.208 test set 1, the same K/OP/OPc that src/aka.rs pins: K, the
        // operator constant, and the AES-CMC of that constant under that key.
        let k: [u8; 16] = hex::decode("465b5ce8b199b49faa5f0a2ee238a6bc")
            .unwrap()
            .try_into()
            .unwrap();
        let op: [u8; 16] = hex::decode("cdc202d5123e20f62b6d676ac72cb318")
            .unwrap()
            .try_into()
            .unwrap();
        let got = derive(SECRET_A, Request::indexed(7), &plmn());
        let opc = aka::opc(k, op);
        assert_eq!(
            hex::encode(opc),
            "cd63cb71954a9f4e48a5994e37a02baf",
            "the AES-CMC of OP under Ki is milenage's f1, checked here against TS 35.208"
        );
        // ... and the same OPc comes out of a whole derivation, so the key schedule
        // really is Ki and OP over the secret and nothing else.
        assert_ne!(got.ki, k, "a derived Ki is not the test vector's Ki");
    }

    // --- The two modes ---------------------------------------------------------------

    #[test]
    fn the_same_secret_and_the_same_index_give_the_same_card() {
        let a = derive(SECRET_A, Request::indexed(7), &plmn());
        let b = derive(SECRET_A, Request::indexed(7), &plmn());
        assert_eq!(a, b);
        assert_eq!(a.mode, Mode::Indexed(7));
        assert_eq!(a.salt, None, "a pinned batch needs no salt");
    }

    #[test]
    fn a_different_index_gives_a_different_card() {
        let seven = derive(SECRET_A, Request::indexed(7), &plmn());
        let eight = derive(SECRET_A, Request::indexed(8), &plmn());
        assert_ne!(seven.ki, eight.ki);
        assert_ne!(seven.opc, eight.opc);
        assert_ne!(seven.iccid, eight.iccid);
        assert_ne!(seven.imsi, eight.imsi);
        // and the last index is not the first plus a constant: the two Ki differ in
        // every byte, which a linear shift of a constant could not do.
        assert!(
            seven
                .ki
                .iter()
                .zip(eight.ki.iter())
                .filter(|(a, b)| a != b)
                .count()
                > 12
        );
    }

    #[test]
    fn a_different_secret_gives_a_different_card() {
        let a = derive(SECRET_A, Request::indexed(7), &plmn());
        let b = derive(SECRET_B, Request::indexed(7), &plmn());
        assert_ne!(a.ki, b.ki);
        assert_ne!(a.opc, b.opc);
        assert_ne!(a.iccid, b.iccid);
        assert_ne!(a.imsi, b.imsi);
    }

    #[test]
    fn random_mode_draws_a_fresh_salt_and_a_fresh_key_per_run() {
        let a = derive(SECRET_A, Request::random(), &plmn());
        let b = derive(SECRET_A, Request::random(), &plmn());
        assert_eq!(a.mode, Mode::Random);
        assert!(a.salt.is_some(), "random mode must print the salt it used");
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.ki, b.ki);
    }

    #[test]
    fn a_printed_random_salt_regenerates_the_printed_card() {
        let first = derive(SECRET_A, Request::random(), &plmn());
        let salt = first.salt.unwrap();
        let replay = derive(SECRET_A, Request::random().with_salt(salt), &plmn());
        assert_eq!(first, replay);
    }

    #[test]
    fn random_and_deterministic_modes_never_collide() {
        let pinned = derive(SECRET_A, Request::random().with_salt([7u8; 32]), &plmn());
        let indexed = derive(SECRET_A, Request::indexed(0), &plmn());
        assert_ne!(
            pinned.ki, indexed.ki,
            "the two selectors are different strings"
        );
    }

    // --- The identifiers --------------------------------------------------------------

    #[test]
    fn every_generated_iccid_is_luhn_valid_and_nineteen_digits() {
        let p = plmn();
        // pySim-prog.py's prefix is "89" (the telecom MII) then the PLMN, and the
        // body fills to 18 with the Luhn digit last, so 19 in total.
        let prefix = format!("89{}", p.digits());
        for index in 0..500u32 {
            let m = derive(SECRET_A, Request::indexed(index), &p);
            assert_eq!(m.iccid.len(), 19, "index {index}: {}", m.iccid);
            assert!(m.iccid.bytes().all(|b| b.is_ascii_digit()));
            assert!(
                m.iccid.starts_with(&prefix),
                "index {index}: {} does not start with {prefix}",
                m.iccid
            );
            assert!(luhn_ok(&m.iccid), "index {index}: {}", m.iccid);
        }
    }

    #[test]
    fn luhn_rejects_a_mangled_iccid() {
        let m = derive(SECRET_A, Request::indexed(3), &plmn());
        assert!(luhn_ok(&m.iccid));
        let last = m.iccid.len() - 1;
        let mangled = format!(
            "{}{}",
            &m.iccid[..last],
            if &m.iccid[last..] == "0" { "1" } else { "0" }
        );
        assert!(!luhn_ok(&mangled));
        assert!(!luhn_ok(""));
        assert!(!luhn_ok("89abc"));
    }

    #[test]
    fn every_generated_imsi_is_fifteen_digits_and_starts_with_the_plmn() {
        let p = plmn();
        for index in 0..500u32 {
            let m = derive(SECRET_A, Request::indexed(index), &p);
            assert_eq!(m.imsi.len(), 15, "index {index}: {}", m.imsi);
            assert!(m.imsi.bytes().all(|b| b.is_ascii_digit()));
            assert!(m.imsi.starts_with("90155"), "index {index}: {}", m.imsi);
        }
    }

    #[test]
    fn a_three_digit_mnc_still_gives_fifteen_digit_imsi_and_nineteen_digit_iccid() {
        // 3 + 3 = 6 PLMN digits, so the IMSI body is 9 and the total is still 15,
        // and the ICCID body drops to 8 with the total still 19.
        let p = Plmn::new("901", "555", 3).unwrap();
        let m = derive(SECRET_A, Request::indexed(1), &p);
        assert_eq!(p.digits(), "901555");
        assert_eq!(m.imsi.len(), 15);
        assert_eq!(m.iccid.len(), 19);
        assert!(luhn_ok(&m.iccid));
    }

    #[test]
    fn plmn_pads_and_refuses() {
        assert_eq!(
            Plmn::new("1", "1", 0).unwrap().digits(),
            "00101",
            "auto pads MNC to 2"
        );
        assert_eq!(Plmn::new("901", "55", 2).unwrap().digits(), "90155");
        assert_eq!(Plmn::new("901", "555", 0).unwrap().digits(), "901555");
        assert_eq!(
            Plmn::new("901", "5", 2).unwrap().digits(),
            "90105",
            "explicit width pads"
        );
        assert!(Plmn::new("90a", "55", 2).is_err(), "digits only");
        assert!(Plmn::new("", "55", 2).is_err(), "empty");
        assert!(Plmn::new("9011", "55", 2).is_err(), "MCC is at most 3");
        assert!(
            Plmn::new("901", "5555", 3).is_err(),
            "MNC longer than mnclen"
        );
        assert!(Plmn::new("901", "555", 1).is_err(), "mnclen is 2 or 3");
    }

    // --- The secret stays out ---------------------------------------------------------

    #[test]
    fn no_rendering_of_the_card_carries_the_secret() {
        for request in [
            Request::indexed(4),
            Request::random(),
            Request::random().with_salt([9u8; 32]),
        ] {
            let m = derive(SECRET_A, request, &plmn());
            let human = m.human();
            let data = m.data().to_string();
            for out in [&human, &data] {
                assert!(!out.contains("correct horse"), "secret leaked: {out}");
                assert!(!out.contains("horse battery"), "secret leaked: {out}");
                // the secret is not there in hex either
                assert!(!out.contains(&hex::encode(SECRET_A)));
            }
            // ... while everything the operator needs is.
            assert!(human.contains(&hex::encode(m.ki)));
            assert!(human.contains(&hex::encode(m.opc)));
            assert!(human.contains(&m.iccid));
            assert!(human.contains(&m.imsi));
            assert!(human.contains("SECRET MATERIAL"));
        }
    }

    #[test]
    fn the_root_is_not_the_secret() {
        // The secret never appears in any intermediate either, so a debug print of
        // the HKDF root would be no worse than a print of the card.
        let root = hkdf_extract(LABEL, SECRET_A);
        assert_ne!(root.as_slice(), SECRET_A);
        assert_ne!(hex::encode(root), hex::encode(SECRET_A));
    }

    #[test]
    fn an_empty_secret_still_derives_but_is_not_a_key_anybody_guesses() {
        // The CLI refuses an empty secret; the derivation itself has no opinion,
        // which is what keeps this module free of policy.
        let m = derive(b"", Request::indexed(0), &plmn());
        assert_eq!(m.iccid.len(), 19);
        assert_ne!(m.ki, derive(b" ", Request::indexed(0), &plmn()).ki);
    }
}
