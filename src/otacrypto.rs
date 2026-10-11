//! Offline OTA ciphers and checksums: DES, 3DES and AES in CBC, plus
//! cryptographic checksums (CBC-MAC for DES/3DES, AES-CMAC for AES), as
//! pySim's OTA layer uses for SIM Toolkit envelope protection.
//!
//! **Owns.** The pure-crypto core: key-length validation, block-aligned CBC
//! encrypt and decrypt with no padding (an IV of zero when none is given), and
//! the checksum (`sign`) and verification (`check`) operations. Sends nothing
//! and reads nothing: the caller hands it bytes and a key and gets bytes back.
//! pySim's OTA code does the same two jobs with two different primitives
//! depending on the key type, and this module matches that.
//!
//! **Does not own.** The command line. [`crate::main`] decides which algorithm,
//! key, IV and MAC length a caller asked for, turns a refused key length or a
//! non-block-aligned payload into exit code 2, and turns a mismatched MAC into
//! exit code 1. This module is the function a future library caller would call
//! directly.
//!
//! **Algorithms and key sizes.** DES takes an 8-byte key; 3DES takes a 16-byte
//! (two-key, K1=K3) or 24-byte (three-key) key; AES takes 16, 24 or 32 bytes.
//! The block size is 8 bytes for DES/3DES and 16 for AES. Encryption and
//! decryption use CBC with no padding, so the data must already be a whole
//! number of blocks.
//!
//! **Checksums.** `Alg::Aes` uses AES-CMAC (NIST SP 800-38B, as SCP03 does in
//! [`crate::scp03`]); the DES variants use CBC-MAC with a zero IV. Per TS 102
//! 225 an OTA checksum is computed over data padded with `0x00` up to the block
//! size when it is not already a multiple, so `sign` does that padding. The
//! returned MAC is truncated to `mac_len` (default 8, which is the OTA checksum
//! length), never more than the block size.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "otacrypto";

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, KeyInit as CmacKeyInit, Mac};
use des::{Des, TdesEde2, TdesEde3};

/// Block size of DES and 3DES.
const DES_BLOCK: usize = 8;
/// Block size of AES.
const AES_BLOCK: usize = 16;

/// Which symmetric cipher an OTA operation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// Single DES, 8-byte key.
    Des,
    /// Two-key (16-byte) or three-key (24-byte) Triple DES.
    Tdes,
    /// AES-128, AES-192 or AES-256 from the key length.
    Aes,
}

/// What went wrong in an OTA crypto operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The key was not one of the accepted lengths for the algorithm.
    #[error("the {alg:?} key is {got} bytes; DES needs 8, 3DES 16 or 24, AES 16/24/32")]
    KeyLength {
        /// The algorithm that was asked for.
        alg: Alg,
        /// The length actually given.
        got: usize,
    },
    /// The IV was not one block long.
    #[error("the IV is {got} bytes, expected {expected}")]
    IvLength {
        /// The block size the IV was checked against.
        expected: usize,
        /// The length actually given.
        got: usize,
    },
    /// The data was not a whole number of cipher blocks.
    #[error("the data is {got} bytes, not a multiple of the {expected}-byte block size")]
    DataLength {
        /// The block size the data was checked against.
        expected: usize,
        /// The length actually given.
        got: usize,
    },
    /// The requested MAC length was not between 1 and the block size.
    #[error("the MAC length is {got}, expected 1 to {max}")]
    MacLength {
        /// The block size: the MAC must not exceed it.
        max: usize,
        /// The length actually requested or given.
        got: usize,
    },
}

impl Alg {
    /// The cipher's block size in bytes.
    pub const fn block_size(self) -> usize {
        match self {
            Alg::Des | Alg::Tdes => DES_BLOCK,
            Alg::Aes => AES_BLOCK,
        }
    }

    /// Whether `key` is one of the accepted lengths for this algorithm.
    pub fn accepts_key(self, key: &[u8]) -> bool {
        match self {
            Alg::Des => key.len() == 8,
            Alg::Tdes => matches!(key.len(), 16 | 24),
            Alg::Aes => matches!(key.len(), 16 | 24 | 32),
        }
    }
}

/// Validates the key length and block-alignment, then runs CBC encryption with
/// no padding. `iv`, when given, must be one block; it is all-zero when absent.
pub fn encrypt(alg: Alg, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Error> {
    validate(alg, key, iv, data)?;
    let default = zeroes(alg.block_size());
    let iv = iv.unwrap_or(&default);
    let mut buf = data.to_vec();
    cbc_encrypt(alg, key, iv, &mut buf)
}

/// Decrypts CBC ciphertext with no padding. The data must be block-aligned and
/// `key`/`iv` must be valid for `alg`.
pub fn decrypt(alg: Alg, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Error> {
    validate(alg, key, iv, data)?;
    let default = zeroes(alg.block_size());
    let iv = iv.unwrap_or(&default);
    let mut buf = data.to_vec();
    cbc_decrypt(alg, key, iv, &mut buf)
}

/// A checksum `mac_len` long (default 8, between 1 and the block size) over
/// `data`, using AES-CMAC for `Alg::Aes` and CBC-MAC (zero IV) for the DES
/// variants. When `data` is not a whole block it is zero-padded to the block
/// size, as TS 102 225 does for an OTA cryptographic checksum.
pub fn sign(alg: Alg, key: &[u8], data: &[u8], mac_len: Option<usize>) -> Result<Vec<u8>, Error> {
    check_key(alg, key)?;
    let bs = alg.block_size();
    let want = mac_len.unwrap_or(8);
    if !(1..=bs).contains(&want) {
        return Err(Error::MacLength { max: bs, got: want });
    }

    let mac = match alg {
        Alg::Aes => aes_cmac(key, data),
        Alg::Des | Alg::Tdes => {
            let mut padded = data.to_vec();
            if padded.len() % bs != 0 {
                let add = bs - (padded.len() % bs);
                padded.extend(std::iter::repeat_n(0u8, add));
            }
            // CBC-MAC with a zero IV: the last cipher block of the padded data.
            let zero_iv = zeroes(bs);
            let mut buf = padded;
            let full = cbc_encrypt(alg, key, &zero_iv, &mut buf)?;
            full[full.len() - bs..].to_vec()
        }
    };

    Ok(mac[..want].to_vec())
}

/// Recomputes the checksum and compares it in constant time against `mac`,
/// returning `true` only when every byte matches. `mac` sets the MAC length.
pub fn check(alg: Alg, key: &[u8], data: &[u8], mac: &[u8]) -> Result<bool, Error> {
    check_key(alg, key)?;
    let bs = alg.block_size();
    if !(1..=bs).contains(&mac.len()) {
        return Err(Error::MacLength {
            max: bs,
            got: mac.len(),
        });
    }
    let expected = sign(alg, key, data, Some(mac.len()))?;
    Ok(constant_time_eq(&expected, mac))
}

/// AES-CMAC (NIST SP 800-38B) over `data`, full block-size output.
fn aes_cmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    macro_rules! mac {
        ($cipher:ty) => {{
            let mut m = <Cmac<$cipher> as CmacKeyInit>::new_from_slice(key).expect("key checked");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match key.len() {
        16 => mac!(Aes128),
        24 => mac!(Aes192),
        _ => mac!(Aes256),
    }
}

/// Runs CBC encryption in place over `buf` (block-aligned) with `iv`.
fn cbc_encrypt(alg: Alg, key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<Vec<u8>, Error> {
    macro_rules! enc {
        ($cipher:ty) => {{
            let len = buf.len();
            cbc::Encryptor::<$cipher>::new_from_slices(key, iv)
                .expect("key/iv length validated by caller")
                .encrypt_padded::<NoPadding>(buf, len)
                .expect("data is a whole number of blocks")
                .to_vec()
        }};
    }
    let out = match (alg, key.len()) {
        (Alg::Des, _) => enc!(Des),
        (Alg::Tdes, 16) => enc!(TdesEde2),
        (Alg::Tdes, 24) => enc!(TdesEde3),
        (Alg::Tdes, _) => {
            return Err(Error::KeyLength {
                alg,
                got: key.len(),
            })
        }
        (Alg::Aes, 16) => enc!(Aes128),
        (Alg::Aes, 24) => enc!(Aes192),
        (Alg::Aes, 32) => enc!(Aes256),
        (Alg::Aes, _) => {
            return Err(Error::KeyLength {
                alg,
                got: key.len(),
            })
        }
    };
    Ok(out)
}

/// Runs CBC decryption in place over `buf` (block-aligned) with `iv`.
fn cbc_decrypt(alg: Alg, key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<Vec<u8>, Error> {
    macro_rules! dec {
        ($cipher:ty) => {{
            cbc::Decryptor::<$cipher>::new_from_slices(key, iv)
                .expect("key/iv length validated by caller")
                .decrypt_padded::<NoPadding>(buf)
                .expect("data is a whole number of blocks")
                .to_vec()
        }};
    }
    let out = match (alg, key.len()) {
        (Alg::Des, _) => dec!(Des),
        (Alg::Tdes, 16) => dec!(TdesEde2),
        (Alg::Tdes, 24) => dec!(TdesEde3),
        (Alg::Tdes, _) => {
            return Err(Error::KeyLength {
                alg,
                got: key.len(),
            })
        }
        (Alg::Aes, 16) => dec!(Aes128),
        (Alg::Aes, 24) => dec!(Aes192),
        (Alg::Aes, 32) => dec!(Aes256),
        (Alg::Aes, _) => {
            return Err(Error::KeyLength {
                alg,
                got: key.len(),
            })
        }
    };
    Ok(out)
}

fn validate(alg: Alg, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<(), Error> {
    check_key(alg, key)?;
    let bs = alg.block_size();
    if let Some(v) = iv {
        if v.len() != bs {
            return Err(Error::IvLength {
                expected: bs,
                got: v.len(),
            });
        }
    }
    if data.len() % bs != 0 {
        return Err(Error::DataLength {
            expected: bs,
            got: data.len(),
        });
    }
    Ok(())
}

fn check_key(alg: Alg, key: &[u8]) -> Result<(), Error> {
    if alg.accepts_key(key) {
        Ok(())
    } else {
        Err(Error::KeyLength {
            alg,
            got: key.len(),
        })
    }
}

fn zeroes(n: usize) -> Vec<u8> {
    vec![0u8; n]
}

/// `a == b` without short-circuiting on length or content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut acc = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= usize::from(*x ^ *y);
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES_KEY: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const DES_KEY: &[u8] = &[0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
    const IV: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn aes_cbc_round_trips_and_matches_nist_sp800_38a() {
        // NIST SP 800-38A F.2.1, single block.
        let pt = h("6bc1bee22e409f96e93d7e117393172a");
        let ct = encrypt(Alg::Aes, AES_KEY, Some(IV), &pt).unwrap();
        assert_eq!(ct, h("7649abac8119b246cee98e9b12e9197d"));
        let back = decrypt(Alg::Aes, AES_KEY, Some(IV), &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn des_and_two_key_3des_with_equal_halves_agree_with_the_classic_vector() {
        let pt = h("0123456789ABCDEF");
        let des_ct = encrypt(Alg::Des, DES_KEY, None, &pt).unwrap();
        assert_eq!(des_ct, h("85e813540f0ab405"));
        let two_key = [DES_KEY, DES_KEY].concat();
        let tdes_ct = encrypt(Alg::Tdes, &two_key, None, &pt).unwrap();
        assert_eq!(tdes_ct, des_ct);
    }

    #[test]
    fn sign_and_check_use_aes_cmac_and_des_cbc_mac() {
        let pt = h("6bc1bee22e409f96e93d7e117393172a");
        let aes_mac = sign(Alg::Aes, AES_KEY, &pt, None).unwrap();
        assert_eq!(aes_mac, h("070a16b46b4d4144"));
        let aes_full = sign(Alg::Aes, AES_KEY, &pt, Some(16)).unwrap();
        assert_eq!(aes_full, h("070a16b46b4d4144f79bdd9dd04a287c"));
        let des_mac = sign(Alg::Des, DES_KEY, &h("0123456789ABCDEF"), None).unwrap();
        assert_eq!(des_mac, h("85e813540f0ab405"));

        assert!(check(Alg::Aes, AES_KEY, &pt, &h("070a16b46b4d4144")).unwrap());
        assert!(!check(Alg::Aes, AES_KEY, &pt, &h("0000000000000000")).unwrap());
    }

    #[test]
    fn non_block_aligned_data_is_rejected() {
        assert!(encrypt(Alg::Aes, AES_KEY, None, &h("00112233")).is_err());
        assert!(sign(Alg::Des, DES_KEY, &h("ab"), None).is_ok());
        // sign pads short data rather than refusing.
        assert_eq!(sign(Alg::Des, DES_KEY, &h("ab"), None).unwrap().len(), 8);
    }
}
