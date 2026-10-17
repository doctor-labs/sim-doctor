//! Master key diversification: the named KDF templates `emv`, `visa2`, `visa`
//! and `kdf3` that turn one master key into the per-card ENC, MAC and DEK a
//! GlobalPlatform card expects, from the key diversification data (KDD) the
//! card returns in INITIALIZE UPDATE.
//!
//! **Owns.** The template table, the template expander, the two finalisations
//! (3DES-ECB for SCP01/SCP02, the counter-mode KDF for SCP03) and the refusal
//! of an unknown template name. Host side only: nothing here talks to a card,
//! and every key is a `Vec<u8>` the caller drops without printing.
//!
//! **Why a template and not a fixed algorithm.** The two published schemes (EMV
//! CPS and Visa) and the scheme called `kdf3` differ only in *how the KDD and
//! the purpose are laid out* in the block that is fed to a cipher. The layout is
//! what a template names, so the table below is the whole interface.
//!
//! **Source of every constant in this file**, all read on the reference
//! (martinpaljak/GlobalPlatformPro, branch `next`, LGPL-3.0-or-later; read, never
//! copied):
//!
//! - the four template strings, with their names: `library/src/main/java/pro/javacard/gp/keys/PlaintextKeys.java:50-59` (`kdf_templates`), transcribed here verbatim
//!   in [`TEMPLATES`];
//! - `$0..$f` = KDD byte, `$k` = key purpose, `$_` = the SCP03 block separator,
//!   `0x` = a plain hex literal, spaces and case are insignificant:
//!   `PlaintextKeys.java:427-444` ([`expand`]) and `:450-464` ([`split`]);
//! - the purpose values 1/2/3/4 (ENC/MAC/DEK/RMAC): `library/src/main/java/pro/javacard/gp/GPCardKeys.java:32-45`
//!   ([`Purpose::value`]);
//! - master key lengths 16, 24, 32: `PlaintextKeys.java:93-98` (`validateKey`);
//!   KDD at most 10 bytes: `PlaintextKeys.java:382-385`;
//! - 3DES-ECB of the expanded block for SCP01/SCP02, 3DES key resize to 24
//!   bytes: `library/src/main/java/pro/javacard/gp/GPCrypto.java:150-154`
//!   (`des3_ecb`), `:268-270` (`des3key`);
//! - SCP03: the expanded template split at `$_` is handed to
//!   `GPCrypto.scp03_kdf(key, a, b, bytes)` (`PlaintextKeys.java:220-237`), which
//!   is BouncyCastle's `KDFCounterBytesGenerator` seeded with
//!   `KDFCounterParameters(key, a, b, 8)` (`GPCrypto.java:232-240`). That is
//!   NIST SP 800-108 counter mode with an 8-bit counter:
//!   `K(i) = CMAC(key, a || [i]_1 || b)` for `i = 1, 2, ...`, taking the first
//!   `bytes` of the stream (bcgit/bc-java `core/src/main/java/org/bouncycastle/crypto/generators/KDFCounterBytesGenerator.java:142-171`,
//!   `.../crypto/params/KDFCounterParameters.java:62-93`).
//!
//! **Not implemented on purpose.** `$l$l` (a key length in bits,
//! `PlaintextKeys.java:446-448`) is left out: no template in the table uses it,
//! and a template that used it would be a construction this module has no
//! known-answer vector for. Such a template is refused, not guessed.
//! A 32-byte master key with a 3DES template is refused too: the reference
//! resizes the key to 24 bytes (`des3key`) and this module does not reproduce a
//! resize it cannot check against a vector.
//!
//! Key material must not reach logs or panic messages through `{:?}`, so the
//! errors below carry lengths and names, never key bytes.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use cmac::{Cmac, Mac};

/// The four named templates, in the order of the reference table
/// (`PlaintextKeys.java:50-59`), transcribed verbatim. `$<n>` is KDD byte `n`,
/// `$k` the key purpose, `0xNN` a hex literal and `$_` the SCP03 block
/// separator.
pub const TEMPLATES: [(&str, &str); 4] = [
    ("emv", "$4 $5 $6 $7 $8 $9 0xF0 $k $4 $5 $6 $7 $8 $9 0x0F $k"),
    (
        "visa2",
        "$0 $1 $4 $5 $6 $7 0xF0 $k $0 $1 $4 $5 $6 $7 0x0F $k",
    ),
    (
        "visa",
        "$0 $1 $2 $3 $8 $9 0xF0 $k $0 $1 $2 $3 $8 $9 0x0F $k",
    ),
    (
        "kdf3",
        "$_ 0x00 0x00 0x00 $k 0x00 $0 $1 $2 $3 $4 $5 $6 $7 $8 $9",
    ),
];

/// The names of the templates, for a parser's list of accepted values.
pub const TEMPLATE_NAMES: [&str; 4] = ["emv", "visa2", "visa", "kdf3"];

/// The longest KDD a card may return (`PlaintextKeys.java:382-385`).
pub const KDD_MAX: usize = 10;

/// The key a diversified key is derived for. The `$k` byte of the template is
/// the one-based identifier of the key's purpose in the key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The card's encryption key.
    Enc,
    /// The card's MAC key.
    Mac,
    /// The card's data encryption key.
    Dek,
    /// The card's response MAC key (derived, never loaded).
    Rmac,
}

impl Purpose {
    /// The `$k` byte: ENC 1, MAC 2, DEK 3, RMAC 4 (`GPCardKeys.java:32-45`).
    pub fn value(self) -> u8 {
        match self {
            Self::Enc => 1,
            Self::Mac => 2,
            Self::Dek => 3,
            Self::Rmac => 4,
        }
    }

    /// Every purpose, in key set order.
    pub const ALL: [Purpose; 4] = [Self::Enc, Self::Mac, Self::Dek, Self::Rmac];
}

/// Which finalisation the expanded block gets: 3DES-ECB for SCP01 and SCP02,
/// the counter-mode KDF for SCP03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scp {
    /// SCP01/SCP02: 3DES-ECB of the expanded block under the master key.
    Des,
    /// SCP03: the SP 800-108 counter-mode KDF under the master key.
    Kdf,
}

/// What went wrong diversifying a key. Every message carries a name or a length,
/// never key bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The template name is not one of [`TEMPLATE_NAMES`].
    #[error("unknown KDF template {0:?}; the known templates are emv, kdf3, visa and visa2")]
    UnknownTemplate(String),
    /// The template names a KDD byte the diversification data does not have.
    #[error(
        "KDF template {template:?} wants KDD byte ${index}, which a {len} byte KDD does not have"
    )]
    KddTooShort {
        /// The template that asked for it.
        template: &'static str,
        /// The KDD byte index the template asked for.
        index: usize,
        /// How many bytes the KDD has.
        len: usize,
    },
    /// The KDD is longer than [`KDD_MAX`].
    #[error("KDD is {0} bytes; a card's KDD is at most {max}", max = KDD_MAX)]
    KddTooLong(usize),
    /// A 3DES template needs `$_`, which none of them carry.
    #[error("KDF template {0:?} has no '$_' block separator, so it is not an SCP03 template")]
    NoBlockSeparator(&'static str),
    /// The template has a `$` token that this module does not implement.
    #[error("KDF template {template:?} contains {token:?}, which is not a token of the four named templates")]
    Unresolved {
        /// The template that contains it.
        template: &'static str,
        /// The offending text, for example `$l`.
        token: String,
    },
    /// A character that is not a hex digit, where the template has hex.
    #[error("KDF template {template:?} contains {ch:?}, which is not hex")]
    NotHex {
        /// The template that contains it.
        template: &'static str,
        /// The offending character.
        ch: char,
    },
    /// The expanded block does not hold a whole number of 3DES blocks.
    #[error("the expanded block is {0} bytes, which is not a whole number of 3DES blocks")]
    NotBlockAligned(usize),
    /// The template has an odd number of hex digits, so it names half a byte.
    #[error("KDF template {0:?} expands to an odd number of hex digits")]
    OddDigits(&'static str),
    /// The master key is not a length the reference accepts.
    #[error("master key is {0} bytes; GlobalPlatformPro accepts 16, 24 or 32")]
    MasterKeyLength(usize),
    /// A 3DES template with a master key 3DES cannot take as it stands.
    #[error("a 3DES KDF template takes a 16 or 24 byte master key, not {0}")]
    ThreeDesKeyLength(usize),
}

/// The template named `name`, or [`Error::UnknownTemplate`] listing the names.
pub fn template(name: &str) -> Result<&'static str, Error> {
    TEMPLATES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, text)| *text)
        .ok_or_else(|| Error::UnknownTemplate(name.to_string()))
}

/// Diversifies `master` into the card key for `purpose`, with the named
/// `template_name` (`emv`, `visa2`, `visa` or `kdf3`) over the card's `kdd`.
///
/// # Errors
///
/// [`Error::UnknownTemplate`], [`Error::KddTooShort`], [`Error::KddTooLong`],
/// [`Error::NoBlockSeparator`], [`Error::Unresolved`], [`Error::NotHex`],
/// [`Error::NotBlockAligned`], [`Error::MasterKeyLength`] or
/// [`Error::ThreeDesKeyLength`].
pub fn diversify(
    master: &[u8],
    template_name: &str,
    kdd: &[u8],
    purpose: Purpose,
    scp: Scp,
) -> Result<Vec<u8>, Error> {
    let text = template(template_name)?;
    if !matches!(master.len(), 16 | 24 | 32) {
        return Err(Error::MasterKeyLength(master.len()));
    }
    if kdd.len() > KDD_MAX {
        return Err(Error::KddTooLong(kdd.len()));
    }
    match scp {
        Scp::Des => three_des_ecb(master, &expand(text, kdd, purpose)?),
        Scp::Kdf => {
            let (a, b) = split(text)?;
            counter_kdf(
                master,
                &expand(a, kdd, purpose)?,
                &expand(b, kdd, purpose)?,
                master.len(),
            )
        }
    }
}

/// The two halves of an SCP03 template: block A is what the counter follows,
/// block B what it precedes. `$_` is the only separator and the template must
/// carry exactly one (`PlaintextKeys.java:450-464`).
fn split(template: &'static str) -> Result<(&'static str, &'static str), Error> {
    let parts: Vec<&str> = template.split("$_").collect();
    match parts.as_slice() {
        [a, b] => Ok((a, b)),
        _ => Err(Error::NoBlockSeparator(template)),
    }
}

/// The bytes a template stands for, with every token substituted.
///
/// `$_` is dropped here (the SCP03 path splits on it before expanding, the
/// 3DES path has no `$_` at all). Everything else is a stream of hex digits,
/// exactly as the reference lower-cases the template, drops spaces and the `0x`
/// markers and hex-decodes what is left (`PlaintextKeys.java:427-444`).
fn expand(template: &'static str, kdd: &[u8], purpose: Purpose) -> Result<Vec<u8>, Error> {
    let mut nibbles: Vec<u8> = Vec::new();
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => i += 1,
            '0' if chars.get(i + 1) == Some(&'x') => i += 2,
            '$' => {
                let width = match chars.get(i + 1) {
                    Some('_' | 'k') => 2,
                    _ => 3,
                };
                let token: String = chars[i..(i + width).min(chars.len())].iter().collect();
                if chars.get(i + 1) == Some(&'k') {
                    let value = purpose.value();
                    nibbles.push(value >> 4);
                    nibbles.push(value & 0x0f);
                    i += 2;
                    continue;
                }
                match chars.get(i + 1).and_then(|c| c.to_digit(16)) {
                    Some(index) => {
                        let byte = *kdd.get(index as usize).ok_or(Error::KddTooShort {
                            template,
                            index: index as usize,
                            len: kdd.len(),
                        })?;
                        nibbles.push(byte >> 4);
                        nibbles.push(byte & 0x0f);
                        i += 2;
                    }
                    None => return Err(Error::Unresolved { template, token }),
                }
            }
            c => {
                let digit = c.to_digit(16).ok_or(Error::NotHex { template, ch: c })? as u8;
                nibbles.push(digit);
                i += 1;
            }
        }
    }
    if nibbles.len() % 2 == 1 {
        return Err(Error::OddDigits(template));
    }
    Ok(nibbles
        .chunks_exact(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect())
}

/// The SCP03 finalisation: NIST SP 800-108 counter mode with an 8-bit counter
/// over AES-CMAC, `K(i) = CMAC(key, a || [i]_1 || b)`, taking the first `bytes`
/// of the stream (`GPCrypto.java:232-240` over BouncyCastle's
/// `KDFCounterBytesGenerator`).
fn counter_kdf(key: &[u8], a: &[u8], b: &[u8], bytes: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(bytes);
    // The counter is one byte, so i = 1 to 255 is all there is (BouncyCastle
    // refuses past `16 << 8`). The only caller asks for the key length, 16, 24
    // or 32 bytes, which is one or two blocks.
    for counter in 1u16..=255 {
        if out.len() >= bytes {
            break;
        }
        let index = [counter as u8];
        out.extend_from_slice(&cmac(key, &[a, &index, b])?);
    }
    out.truncate(bytes);
    Ok(out)
}

/// The SCP01/SCP02 finalisation: 3DES-ECB of the expanded block under the master
/// key (`GPCrypto.java:150-154`). ECB is block independent, so the blocks are
/// encrypted one by one.
fn three_des_ecb(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    // `des3key` hands DESede a 24 byte key whatever it is given (`GPCrypto.java:268-270`),
    // and for a 16 byte key that resize is the two-key form: K1 || K2 || K1. One
    // 24 byte cipher path covers both, and the KCV of the 16 byte default key
    // comes out as 8BAF47, which is what GlobalPlatformPro prints for it.
    let mut triple = [0u8; 24];
    match key.len() {
        16 => {
            triple[..16].copy_from_slice(key);
            triple[16..].copy_from_slice(&key[..8]);
        }
        24 => triple.copy_from_slice(key),
        n => return Err(Error::ThreeDesKeyLength(n)),
    }
    if data.is_empty() || data.len() % 8 != 0 {
        return Err(Error::NotBlockAligned(data.len()));
    }
    let cipher = <des::TdesEde3 as KeyInit>::new_from_slice(&triple)
        .map_err(|_| Error::ThreeDesKeyLength(key.len()))?;
    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(8) {
        let mut block: [u8; 8] = chunk.try_into().expect("8-byte chunk");
        // Encrypt THROUGH the array: `encrypt_block` takes `&mut Block<Self>`, so
        // handing it `&mut block.into()` writes into a temporary that is dropped
        // on the next line and this function would silently return its plaintext.
        cipher.encrypt_block((&mut block).into());
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// One AES-CMAC over `parts`, with an AES-128, AES-192 or AES-256 key.
fn cmac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 16], Error> {
    macro_rules! run {
        ($cipher:ty) => {{
            let mut mac = <Cmac<$cipher> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::MasterKeyLength(key.len()))?;
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().into()
        }};
    }
    match key.len() {
        16 => Ok(run!(aes::Aes128)),
        24 => Ok(run!(aes::Aes192)),
        32 => Ok(run!(aes::Aes256)),
        n => Err(Error::MasterKeyLength(n)),
    }
}

/// The 15-byte SCP03 block A of Amendment D table 4-1 for `constant` and an
/// output length of `bits` bits: `0^11 || constant || 0x00 || [bits]_2`
/// (`GPCrypto.java:211-222`). Only used to pin [`counter_kdf`] against the
/// already known-answer tested [`crate::scp03::derive_session_keys`].
pub fn scp03_block_a(constant: u8, bits: u16) -> [u8; 15] {
    let mut label = [0u8; 15];
    label[11] = constant;
    label[13..15].copy_from_slice(&bits.to_be_bytes());
    label
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gp::aes_kcv;
    use crate::scp03;

    /// The GlobalPlatform key check value of a diversified 3DES key: the first
    /// three bytes of 3DES-ECB of 8 zero bytes (`GPCrypto.java:260-266`), taken
    /// through the same 24 byte key resize that `des3_ecb` does
    /// (`GPCrypto.java:268-270`). The vectors below are the reference's, so the
    /// expectation does not move; only the way the KCV is computed follows the
    /// reference exactly.
    fn kcv_3des(key: &[u8]) -> [u8; 3] {
        let block = three_des_ecb(key, &[0u8; 8]).expect("3DES key of 16 or 24 bytes");
        [block[0], block[1], block[2]]
    }

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hex")
    }

    // The reference's own test inputs and expectations, from
    // martinpaljak/GlobalPlatformPro branch next,
    // library/src/test/java/pro/javacard/gp/test/TestPlaintextKeys.java:25-28.
    const MASTER_16: &str = "404142434445464748494A4B4C4D4E4F";
    const MASTER_24: &str = "404142434445464748494A4B4C4D4E4F5051525354555657";
    const MASTER_32: &str = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
    const KDD: &str = "00010203040506070809";

    fn derive(name: &str, master: &str, kdd: &str, purpose: Purpose, scp: Scp) -> Vec<u8> {
        diversify(&hex(master), name, &hex(kdd), purpose, scp).expect("diversify")
    }

    /// The 16-byte case of the 3DES path, pinned end to end. `des3key` hands
    /// DESede a 24-byte key whatever it is given (`GPCrypto.java:268-270`), and
    /// `resize_des` builds it as `key[0..16] || key[0..8]`
    /// (`GPCrypto.java:379-381`), so for a 16-byte key it is K1 || K2 || K1. The
    /// diversified EMV ENC key and its key check value below were computed with
    /// `openssl enc -des-ede3 -K <key||key[..8]>` over eight 0x00 bytes, an
    /// independent model of `des3_ecb` + `kcv_3des` (`GPCrypto.java:150-154`,
    /// `:260-266`). The KCV is the reference expectation, TestPlaintextKeys:31-40.
    #[test]
    fn a_16_byte_3des_key_encrypts_through_the_24_byte_resize() {
        let master = hex(MASTER_16);
        let block = expand(
            template("emv").expect("known template"),
            &hex(KDD),
            Purpose::Enc,
        )
        .expect("expands");
        let key = three_des_ecb(&master, &block).expect("16-byte master key");
        assert_eq!(
            hex::encode_upper(&key),
            "0EF59FCBF8019B62E62AF6EA20B8BF25",
            "the diversified EMV ENC key"
        );
        let kcv = three_des_ecb(&key, &[0u8; 8]).expect("KCV");
        assert_eq!(
            hex::encode_upper(&kcv[..3]),
            "C33013",
            "the key check value of the diversified EMV ENC key"
        );
        // The reference resizes before hashing, so the KCV of a 16-byte key and
        // of that same key widened to 24 bytes are one and the same.
        let wide = [key.clone(), key[..8].to_vec()].concat();
        assert_eq!(
            crate::gp::des_kcv(&key).unwrap(),
            crate::gp::des_kcv(&wide).unwrap()
        );
    }

    /// TestPlaintextKeys.java:87-98, `testDiversification_KDF3_ExternalVector`: an
    /// AES-256 master key, a 10-byte KDD and the whole 32-byte ENC key.
    #[test]
    fn kdf3_scp03_matches_the_external_vector() {
        let got = derive(
            "kdf3",
            "8C72C72CF908411653018807950D82FBAD947562F0828A0B10B8B9606ABF3BCD",
            "D9B1DE5D0362DEDCE4FB",
            Purpose::Enc,
            Scp::Kdf,
        );
        assert_eq!(
            got,
            hex("9AAC5D0B3601F89438A0D9D0B6B256CFB47E6462DFA5228D3420C4AC7C224781"),
            "kdf3 ENC key is not the vector's"
        );
    }

    /// TestPlaintextKeys.java:54-62: AES-128 master key, KDD 000102..09, KDF3.
    #[test]
    fn kdf3_scp03_aes128_kcvs_match() {
        for (purpose, want) in [
            (Purpose::Enc, "E79C05"),
            (Purpose::Mac, "D1BD77"),
            (Purpose::Dek, "3FDE8C"),
        ] {
            let key = derive("kdf3", MASTER_16, KDD, purpose, Scp::Kdf);
            assert_eq!(key.len(), 16);
            assert_eq!(
                hex::encode_upper(aes_kcv(&key).unwrap()),
                want,
                "{purpose:?}"
            );
        }
    }

    /// TestPlaintextKeys.java:65-73: the same with an AES-192 master key.
    #[test]
    fn kdf3_scp03_aes192_kcvs_match() {
        for (purpose, want) in [
            (Purpose::Enc, "1DE8EA"),
            (Purpose::Mac, "47C00C"),
            (Purpose::Dek, "C04D76"),
        ] {
            let key = derive("kdf3", MASTER_24, KDD, purpose, Scp::Kdf);
            assert_eq!(key.len(), 24);
            assert_eq!(
                hex::encode_upper(aes_kcv(&key).unwrap()),
                want,
                "{purpose:?}"
            );
        }
    }

    /// TestPlaintextKeys.java:76-84: the same with an AES-256 master key, which
    /// is the one case that takes two counter blocks.
    #[test]
    fn kdf3_scp03_aes256_kcvs_match() {
        for (purpose, want) in [
            (Purpose::Enc, "2972D2"),
            (Purpose::Mac, "036F94"),
            (Purpose::Dek, "5D57B8"),
        ] {
            let key = derive("kdf3", MASTER_32, KDD, purpose, Scp::Kdf);
            assert_eq!(key.len(), 32);
            assert_eq!(
                hex::encode_upper(aes_kcv(&key).unwrap()),
                want,
                "{purpose:?}"
            );
        }
    }

    /// TestPlaintextKeys.java:31-40: the EMV template over SCP02, which is a
    /// 3DES-ECB finalisation, checked by its 3DES key check values.
    #[test]
    fn emv_scp02_kcvs_match() {
        for (purpose, want) in [
            (Purpose::Enc, "C33013"),
            (Purpose::Mac, "6F4CA6"),
            (Purpose::Dek, "BB8179"),
        ] {
            let key = derive("emv", MASTER_16, KDD, purpose, Scp::Des);
            assert_eq!(hex::encode_upper(kcv_3des(&key)), want, "{purpose:?}");
        }
    }

    /// TestPlaintextKeys.java:43-51: the same for the `visa2` template.
    #[test]
    fn visa2_scp02_kcvs_match() {
        for (purpose, want) in [
            (Purpose::Enc, "2BE598"),
            (Purpose::Mac, "58DA38"),
            (Purpose::Dek, "3C328E"),
        ] {
            let key = derive("visa2", MASTER_16, KDD, purpose, Scp::Des);
            assert_eq!(hex::encode_upper(kcv_3des(&key)), want, "{purpose:?}");
        }
    }

    /// What each template expands to, read off the table at
    /// PlaintextKeys.java:50-59 with the token rules of :427-444: KDD
    /// `00010203040506070809`, purpose ENC is `$k` = 01.
    #[test]
    fn templates_expand_to_the_reference_blocks() {
        let kdd = hex(KDD);
        let block = |name: &str, purpose: Purpose| {
            expand(template(name).expect("known template"), &kdd, purpose).expect("expands")
        };
        assert_eq!(
            block("emv", Purpose::Enc),
            hex("040506070809F0010405060708090F01")
        );
        assert_eq!(
            block("emv", Purpose::Dek),
            hex("040506070809F0030405060708090F03")
        );
        assert_eq!(
            block("visa2", Purpose::Enc),
            hex("000104050607F0010001040506070F01")
        );
        assert_eq!(
            block("visa", Purpose::Enc),
            hex("000102030809F0010001020308090F01")
        );
        let (_, b) = split(template("kdf3").expect("known template")).expect("has $_");
        assert_eq!(
            expand(b, &kdd, Purpose::Mac).expect("expands"),
            hex("000000020000010203040506070809")
        );
    }

    /// `$_` is what makes a template an SCP03 template; the 3DES ones have none
    /// (PlaintextKeys.java:450-464 refuses them).
    #[test]
    fn a_3des_template_is_refused_for_scp03() {
        assert_eq!(
            diversify(&hex(MASTER_16), "emv", &hex(KDD), Purpose::Enc, Scp::Kdf),
            Err(Error::NoBlockSeparator(
                "$4 $5 $6 $7 $8 $9 0xF0 $k $4 $5 $6 $7 $8 $9 0x0F $k"
            ))
        );
        // The reference refuses it the other way round too: `kdf_template_finalize`
        // still sees the `$_` and throws (PlaintextKeys.java:466-471).
        assert_eq!(
            diversify(&hex(MASTER_16), "kdf3", &hex(KDD), Purpose::Enc, Scp::Des),
            Err(Error::Unresolved {
                template: "$_ 0x00 0x00 0x00 $k 0x00 $0 $1 $2 $3 $4 $5 $6 $7 $8 $9",
                token: "$_".into(),
            })
        );
    }

    /// `validateKey` takes 16, 24 or 32 bytes and nothing else
    /// (PlaintextKeys.java:93-98); 3DES as it stands takes 16 or 24.
    #[test]
    fn a_wrong_master_key_length_is_refused() {
        for length in [0usize, 8, 15, 17, 33] {
            let master = vec![0x40u8; length];
            assert_eq!(
                diversify(&master, "kdf3", &hex(KDD), Purpose::Enc, Scp::Kdf),
                Err(Error::MasterKeyLength(length))
            );
            assert_eq!(
                diversify(&master, "emv", &hex(KDD), Purpose::Enc, Scp::Des),
                Err(Error::MasterKeyLength(length))
            );
        }
        assert_eq!(
            diversify(&hex(MASTER_32), "emv", &hex(KDD), Purpose::Enc, Scp::Des),
            Err(Error::ThreeDesKeyLength(32))
        );
    }

    /// A card's KDD is at most 10 bytes (PlaintextKeys.java:382-385).
    #[test]
    fn a_long_kdd_is_refused() {
        assert_eq!(
            diversify(&hex(MASTER_16), "kdf3", &[0u8; 11], Purpose::Enc, Scp::Kdf),
            Err(Error::KddTooLong(11))
        );
        assert_eq!(
            diversify(&hex(MASTER_16), "emv", &[0u8; 4], Purpose::Enc, Scp::Des),
            Err(Error::KddTooShort {
                template: "$4 $5 $6 $7 $8 $9 0xF0 $k $4 $5 $6 $7 $8 $9 0x0F $k",
                index: 4,
                len: 4,
            })
        );
    }

    /// The unknown name is refused, and the message says what is known, so a
    /// typo is a message rather than a wrong key.
    #[test]
    fn an_unknown_template_name_is_refused() {
        let err = template("visa3").unwrap_err();
        assert_eq!(err, Error::UnknownTemplate("visa3".into()));
        let text = err.to_string();
        for name in TEMPLATE_NAMES {
            assert!(text.contains(name), "{text} does not name {name}");
        }
        assert!(
            !text.contains("40"),
            "the message carries key bytes: {text}"
        );
    }

    /// The SCP03 finalisation here and the already known-answer tested session
    /// key derivation in `scp03` are the same function: with block A as
    /// Amendment D table 4-1 has it and the KDD as block B, the first 16 bytes
    /// out of [`counter_kdf`] are S-ENC, S-MAC or S-RMAC. This is what keeps
    /// `--key-kdf` on top of the existing session derivation.
    #[test]
    fn the_scp03_finalisation_is_the_session_key_kdf() {
        let host = [0xa0u8; 8];
        let card = [0x0bu8; 8];
        let mut context = [0u8; 16];
        context[..8].copy_from_slice(&host);
        context[8..].copy_from_slice(&card);
        let (enc_key, mac_key) = (hex(MASTER_16), hex(MASTER_16));
        let keys = scp03::derive_session_keys(
            &scp03::Key::new(&enc_key[..16]).expect("16"),
            &scp03::Key::new(&mac_key[..16]).expect("16"),
            &host,
            &card,
        );
        assert_eq!(
            counter_kdf(&enc_key, &scp03_block_a(0x04, 128), &context, 16).expect("kdf"),
            keys.enc.as_bytes().to_vec(),
            "S-ENC"
        );
        assert_eq!(
            counter_kdf(&mac_key, &scp03_block_a(0x06, 128), &context, 16).expect("kdf"),
            keys.mac.as_bytes().to_vec(),
            "S-MAC"
        );
        assert_eq!(
            counter_kdf(&mac_key, &scp03_block_a(0x07, 128), &context, 16).expect("kdf"),
            keys.rmac.as_bytes().to_vec(),
            "S-RMAC"
        );
    }

    /// Key material must not reach a log through `{:?}`, so the diversified keys
    /// are `Vec<u8>` the caller drops and the errors carry no key bytes.
    #[test]
    fn errors_carry_no_key_bytes() {
        for name in ["emv", "visa2", "visa", "kdf3"] {
            for purpose in Purpose::ALL {
                let short = diversify(&hex(MASTER_16)[..8], name, &hex(KDD), purpose, Scp::Kdf);
                assert!(short.is_err());
                assert!(!short.unwrap_err().to_string().contains("4041"));
            }
        }
    }
}
