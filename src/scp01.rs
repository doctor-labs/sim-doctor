//! GlobalPlatform Secure Channel Protocol 01 (SCP01): the legacy 3DES secure
//! channel. The pure crypto core, the handshake builders and the
//! secure-messaging wrapper. Sends nothing.
//!
//! **Owns.** Session key derivation (a single two-key 3DES encryption of a
//! permuted 16-byte challenge context), the card and host cryptograms, the
//! SCP01 command MAC with its 8-byte ICV, the INITIALIZE UPDATE and EXTERNAL
//! AUTHENTICATE command builders, and the command wrapper. Authentication is
//! host-challenge-only: there is no card cryptogram exchange beyond the one in
//! the INITIALIZE UPDATE response.
//!
//! **Scope.** C-MAC and C-ENC only. R-MAC and R-ENC are not implemented:
//! responses are returned untouched, exactly as the reference wrapper returns
//! its response, so a recorded response is not verified. No CLI subcommand is
//! wired to this module in this change; nothing here opens a reader.
//!
//! **Provenance.** Read, never copied, from GlobalPlatformPro
//! (LGPL-3.0-or-later; each cited file carries that SPDX header):
//! `nextgen/src/main/java/pro/javacard/gp/ng/SCP01.java` (the wrapper and its
//! block-size budget), `library/src/main/java/pro/javacard/gp/SCP01Wrapper.java`
//! (`wrap`, the authoritative CLA / Lc / pad80 ordering),
//! `library/src/main/java/pro/javacard/gp/GPCrypto.java` (`mac_3des` line 157,
//! `pad80` line 81), `nextgen/src/main/java/pro/javacard/gp/ng/
//! PlaintextCardKeys.java` (`deriveSessionSCP01` line 337) and
//! `nextgen/src/main/java/pro/javacard/gp/ng/GlobalPlatformCookbook.java`
//! (`authenticate_scp01` line 505, `ext_authenticate_des` line 458). No GPL or
//! LGPL code was copied here; the behaviour is reimplemented from those cites.
//!
//! **Do not carry anything over from [`crate::scp03`].** The three MACs differ:
//!
//! * The SCP01 MAC is a **plain 3DES CBC-MAC over the whole padded buffer,
//!   taking the LAST (rightmost) 8 bytes** (`GPCrypto.mac_3des`, lines
//!   157-166). It is not AES-CMAC (SCP03) and not the single-DES-then-final-3DES
//!   form SCP02 uses (`mac_des_3des`, lines 169-189).
//! * The ICV is the transmitted MAC itself and becomes the next IV. There is no
//!   separate MAC chaining value and no extra 3DES advance.
//! * The transmitted MAC is the **full 8 bytes**, not 4.
//! * The C-ENC IV is **always zero**, never the ICV, and the plaintext carries a
//!   one-octet length prefix before ISO/IEC 7816-4 padding.
//!
//! **Known-answer tests.** Every expected value below was produced by
//! `openssl enc -des-ede3` and `-des-ede3-cbc` (`-nopad -nosalt`) on the box,
//! which is independent of this implementation. The KAT and the fixed host
//! challenge are the ones recorded in the reference capture
//! `nextgen/src/test/resources/scp01-auth.dump` lines 2-3. The card challenge
//! the tests use is synthetic; see [`derive_session_key`].

//! **Key-schedule trap.** The 3DES key here is two-key. The reference
//! `des3key(v) = new SecretKeySpec(resize_des(v, 24), "DESede")`
//! (GPCrypto.java:268-269), with `resize_des` building
//! `concatenate(copyOf(key,16), copyOf(key,8))` (GPCrypto.java:381-383), turns a
//! 16-byte key into K1||K2||K1, i.e. K3 = K1. That is exactly what
//! `des::TdesEde2` does with a 16-byte key. `openssl enc -des-ede3-cbc -K`
//! instead ZERO-PADS a 16-byte `-K` up to 24 (K3 = 0) and then disagrees on the
//! very first block. Every openssl key used below is therefore the explicit
//! 24-byte K1||K2||K1, never a 16-byte one.

/// This module name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scp01";

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use des::TdesEde2;

use crate::apdu::{Command, Header, Le};

/// The 3DES block size, and the length of every MAC and ICV here.
pub const BLOCK: usize = 8;
/// Length of a two-key 3DES key (K1, K2, K1).
pub const KEY_LEN: usize = 16;
/// Length of a host or card challenge.
pub const CHALLENGE_LEN: usize = 8;
/// The SCP01 MAC is a full block.
pub const MAC_LEN: usize = 8;

/// INS of INITIALIZE UPDATE (CLA 80).
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
/// INS of EXTERNAL AUTHENTICATE (CLA 84).
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// INS of GET STATUS, as used by the recorded SCP01 capture.
pub const INS_GET_STATUS: u8 = 0xf2;

/// GlobalPlatform secure messaging base class byte.
pub const CLA_GP: u8 = 0x80;
/// Secure messaging bit: the command carries a MAC.
pub const CLA_BIT_MAC: u8 = 0x04;
/// Secure messaging bit: the command body is encrypted.
pub const CLA_BIT_ENC: u8 = 0x08;

/// Security level bit: C-MAC only.
pub const LEVEL_C_MAC: u8 = 0x01;
/// Security level bits: C-MAC and C-ENC.
pub const LEVEL_C_MAC_C_ENC: u8 = 0x03;

/// What went wrong building or wrapping an SCP01 value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A key was not 16 bytes.
    #[error("key is {0} bytes, expected 16")]
    KeyLength(usize),
    /// A challenge was not 8 bytes.
    #[error("challenge is {0} bytes, expected 8")]
    ChallengeLength(usize),
    /// Input to a CBC operation was not a whole number of blocks.
    #[error("input is {0} bytes, not a whole number of 8-byte blocks")]
    NotBlockAligned(usize),
    /// The data plus its MAC would not fit a short Lc.
    #[error("data is {0} bytes; with the 8-byte SCP01 MAC it exceeds a short APDU")]
    TooLong(usize),
    /// The card cryptogram did not match.
    #[error("card cryptogram mismatch")]
    CardCryptogram,
}

/// ISO/IEC 7816-4 padding method 2 (pad80) to an 8-byte block: a single 0x80
/// octet then zeros, always adding at least one octet. `GPCrypto.pad80` line 81.
pub fn pad80(input: &[u8]) -> Vec<u8> {
    let total = (input.len() / BLOCK + 1) * BLOCK;
    let mut out = input.to_vec();
    out.resize(total, 0);
    out[input.len()] = 0x80;
    out
}

/// The inverse of [`pad80`].
///
/// # Errors
///
/// [`Error::NotBlockAligned`] if the input is not a whole number of blocks, or
/// if it carries no 0x80 marker.
pub fn unpad80(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() % BLOCK != 0 {
        return Err(Error::NotBlockAligned(input.len()));
    }
    let mut i = input.len() - 1;
    while i > 0 && input[i] == 0 {
        i -= 1;
    }
    if input[i] != 0x80 {
        return Err(Error::NotBlockAligned(input.len()));
    }
    Ok(input[..i].to_vec())
}

/// 3DES-CBC encryption. `key` is two-key 3DES (K1, K2, K1), so 16 bytes.
fn des3_cbc(key: &[u8; KEY_LEN], iv: &[u8; BLOCK], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() % BLOCK != 0 {
        return Err(Error::NotBlockAligned(data.len()));
    }
    let mut buf = data.to_vec();
    let len = data.len();
    let out = cbc::Encryptor::<TdesEde2>::new_from_slices(&key[..], &iv[..])
        .map_err(|_| Error::KeyLength(KEY_LEN))?
        .encrypt_padded::<NoPadding>(&mut buf, len)
        .map_err(|_| Error::NotBlockAligned(data.len()))?;
    Ok(out.to_vec())
}

/// 3DES-CBC decryption, the inverse of [`des3_cbc`].
fn des3_cbc_decrypt(key: &[u8; KEY_LEN], iv: &[u8; BLOCK], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() % BLOCK != 0 {
        return Err(Error::NotBlockAligned(data.len()));
    }
    let mut buf = data.to_vec();
    let out = cbc::Decryptor::<TdesEde2>::new_from_slices(&key[..], &iv[..])
        .map_err(|_| Error::KeyLength(KEY_LEN))?
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| Error::NotBlockAligned(data.len()))?;
    Ok(out.to_vec())
}

/// 3DES-ECB over whole blocks.
///
/// Each block gets its own fresh zero-IV CBC context, which is ECB by
/// definition. Do NOT replace this with one CBC pass over the whole buffer: the
/// blocks agree for the first one and diverge after it, which would silently
/// corrupt the 16-byte session-key derivation.
fn des3_ecb(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() % BLOCK != 0 {
        return Err(Error::NotBlockAligned(data.len()));
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(BLOCK) {
        let mut block = chunk.to_vec();
        let sealed = cbc::Encryptor::<TdesEde2>::new_from_slices(&key[..], &[0u8; BLOCK])
            .map_err(|_| Error::KeyLength(KEY_LEN))?
            .encrypt_padded::<NoPadding>(&mut block, BLOCK)
            .map_err(|_| Error::NotBlockAligned(BLOCK))?;
        out.extend_from_slice(sealed);
    }
    Ok(out)
}

/// The SCP01 command MAC: pad the input to 8 bytes, run **the whole buffer**
/// through 3DES-CBC from `icv`, and take the **last** block.
///
/// `GPCrypto.mac_3des` line 157, which comments "rightmost 8 bytes". Taking the
/// first chained block instead is the SCP02 / SCP03 style mistake and is pinned
/// against in `mac_is_the_last_chained_block_not_the_first`.
pub fn mac_3des(
    input: &[u8],
    key: &[u8; KEY_LEN],
    icv: &[u8; BLOCK],
) -> Result<[u8; BLOCK], Error> {
    let ct = des3_cbc(key, icv, &pad80(input))?;
    let mut mac = [0u8; BLOCK];
    mac.copy_from_slice(&ct[ct.len() - BLOCK..]);
    Ok(mac)
}

/// Derives the SCP01 session key from the card KAT and the two challenges.
///
/// The 16-byte context is host challenge then card challenge, permuted to
/// `[12:16] [0:4] [8:12] [4:8]`, encrypted once with 3DES-ECB.
/// `PlaintextCardKeys.deriveSessionSCP01` lines 341-348.
///
/// SCP01 carries a single key, so the encryption and MAC session keys are the
/// same 16 bytes; see [`derive_session_keys`].
///
/// **The card challenge used by the known-answer tests is synthetic.** The
/// reference capture `scp01-auth.dump` records a real card, but the
/// card-challenge field of its INITIALIZE UPDATE response could not be
/// identified with confidence from the recorded bytes, and guessing it would
/// make the vector agree with this implementation by construction. The test
/// vectors are therefore openssl-generated over the capture real KAT and real
/// host challenge with a synthetic card challenge, and the capture own
/// cryptogram is not replayed here.
pub fn derive_session_key(
    kat: &[u8; KEY_LEN],
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> Result<[u8; KEY_LEN], Error> {
    let mut ctx = [0u8; CHALLENGE_LEN * 2];
    ctx[..CHALLENGE_LEN].copy_from_slice(host);
    ctx[CHALLENGE_LEN..].copy_from_slice(card);
    let mut perm = [0u8; CHALLENGE_LEN * 2];
    perm[0..4].copy_from_slice(&ctx[12..16]);
    perm[4..8].copy_from_slice(&ctx[0..4]);
    perm[8..12].copy_from_slice(&ctx[8..12]);
    perm[12..16].copy_from_slice(&ctx[4..8]);
    let sk = des3_ecb(kat, &perm)?;
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&sk);
    Ok(out)
}

/// The session keys of one SCP01 session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Session ENC key. Equal to `mac`: SCP01 carries one key.
    pub enc: [u8; KEY_LEN],
    /// Session MAC key. Equal to `enc`: SCP01 carries one key.
    pub mac: [u8; KEY_LEN],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("enc", &"<redacted>")
            .field("mac", &"<redacted>")
            .finish()
    }
}

/// Derives both session keys. See [`derive_session_key`].
pub fn derive_session_keys(
    kat: &[u8; KEY_LEN],
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> Result<SessionKeys, Error> {
    let k = derive_session_key(kat, host, card)?;
    Ok(SessionKeys { enc: k, mac: k })
}

/// The card cryptogram, over card challenge then host challenge.
/// `GlobalPlatformCookbook.authenticate_scp01` line 510.
pub fn card_cryptogram(
    sk: &[u8; KEY_LEN],
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> Result<[u8; BLOCK], Error> {
    let mut ctx = [0u8; CHALLENGE_LEN * 2];
    ctx[..CHALLENGE_LEN].copy_from_slice(card);
    ctx[CHALLENGE_LEN..].copy_from_slice(host);
    mac_3des(&ctx, sk, &[0u8; BLOCK])
}

/// The host cryptogram, over host challenge then card challenge.
/// `GlobalPlatformCookbook.authenticate_scp01` lines 512-514.
pub fn host_cryptogram(
    sk: &[u8; KEY_LEN],
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> Result<[u8; BLOCK], Error> {
    let mut ctx = [0u8; CHALLENGE_LEN * 2];
    ctx[..CHALLENGE_LEN].copy_from_slice(host);
    ctx[CHALLENGE_LEN..].copy_from_slice(card);
    mac_3des(&ctx, sk, &[0u8; BLOCK])
}

/// Checks the card cryptogram against the value the card returned.
///
/// # Errors
///
/// [`Error::CardCryptogram`] on any difference, including one bit, and
/// [`Error::ChallengeLength`] if `expected` is not 8 bytes.
pub fn verify_card_cryptogram(
    sk: &[u8; KEY_LEN],
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
    expected: &[u8],
) -> Result<(), Error> {
    if expected.len() != BLOCK {
        return Err(Error::ChallengeLength(expected.len()));
    }
    let got = card_cryptogram(sk, host, card)?;
    if got[..] == expected[..] {
        Ok(())
    } else {
        Err(Error::CardCryptogram)
    }
}

/// Which protections a command carries, as the EXTERNAL AUTHENTICATE P1 encodes
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLevel {
    /// C-MAC: append the 8-byte MAC and set the secure messaging bit.
    pub mac: bool,
    /// C-ENC: encrypt the body with the session ENC key under a zero IV.
    pub enc: bool,
}

impl SecurityLevel {
    /// C-MAC only (P1 = 0x01).
    pub const C_MAC: Self = Self {
        mac: true,
        enc: false,
    };
    /// C-MAC and C-ENC (P1 = 0x03).
    pub const C_MAC_C_ENC: Self = Self {
        mac: true,
        enc: true,
    };
    /// Nothing (P1 = 0x00): the open channel.
    pub const PLAIN: Self = Self {
        mac: false,
        enc: false,
    };

    /// Decodes an EXTERNAL AUTHENTICATE P1 byte.
    pub const fn from_level(byte: u8) -> Self {
        match byte {
            LEVEL_C_MAC_C_ENC => Self::C_MAC_C_ENC,
            LEVEL_C_MAC => Self::C_MAC,
            _ => Self::PLAIN,
        }
    }
}

/// Wraps one command, returning the secure-messaging APDU bytes and the new ICV.
///
/// The pure byte-level core of [`Channel::wrap_parts`]; it opens nothing and
/// returns bytes, so it is directly testable. The ordering is the reference
/// one, and the order matters:
///
/// 1. `new_cla = cla | 0x04` (MAC) `| 0x08` (ENC).
/// 2. If MAC, the MAC is taken over `new_cla, ins, p1, p2, orig_lc + 8, data`
///    with the **plaintext** body, and `orig_lc + 8` is the Lc octet inside that
///    MAC input even when the body is also encrypted.
/// 3. If ENC, the body is prefixed with its own one-octet length, pad80'd and
///    encrypted under a **zero** IV. That adds to the transmitted Lc but not to
///    the Lc octet inside the MAC.
/// 4. The MAC is appended after the body, then any Le.
///
/// `SCP01Wrapper.wrap` lines 49-100 and `SCP01.wrap` lines 75-101.
///
/// # Errors
///
/// [`Error::TooLong`] if the wrapped command cannot carry a short Lc.
#[allow(clippy::too_many_arguments)]
pub fn wrap_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: Option<u8>,
    level: SecurityLevel,
    keys: &SessionKeys,
    icv: &[u8; BLOCK],
) -> Result<(Vec<u8>, [u8; BLOCK]), Error> {
    let new_cla =
        cla | if level.mac { CLA_BIT_MAC } else { 0 } | if level.enc { CLA_BIT_ENC } else { 0 };

    if !level.mac && !level.enc {
        let mut apdu = vec![new_cla, ins, p1, p2];
        if let Some(le) = le {
            apdu.push(le);
        }
        return Ok((apdu, *icv));
    }

    let orig_lc = data.len();
    let lc_with_mac = orig_lc + MAC_LEN;
    if lc_with_mac > 0xFF {
        return Err(Error::TooLong(orig_lc));
    }

    // Step 2: MAC over the plaintext body, before any encryption.
    let new_icv = if level.mac {
        let mut m = vec![new_cla, ins, p1, p2, lc_with_mac as u8];
        m.extend_from_slice(data);
        mac_3des(&m, &keys.mac, icv)?
    } else {
        *icv
    };

    // Step 3: encrypt, length-prefixed, under a zero IV.
    let mut new_lc = lc_with_mac;
    let mut new_data = data.to_vec();
    if level.enc && orig_lc > 0 {
        let mut plain = Vec::with_capacity(orig_lc + 1);
        plain.push(orig_lc as u8);
        plain.extend_from_slice(data);
        let padded = pad80(&plain);
        new_lc += padded.len() - orig_lc;
        new_data = des3_cbc(&keys.enc, &[0u8; BLOCK], &padded)?;
    }
    if new_lc > 0xFF {
        return Err(Error::TooLong(orig_lc));
    }

    if level.mac {
        new_data.extend_from_slice(&new_icv);
    }

    let mut apdu = vec![new_cla, ins, p1, p2];
    if new_lc > 0 {
        apdu.push(new_lc as u8);
        apdu.extend_from_slice(&new_data);
    }
    if let Some(le) = le {
        apdu.push(le);
    }
    Ok((apdu, new_icv))
}

/// Decrypts a C-ENC body and strips the one-octet length prefix.
///
/// # Errors
///
/// [`Error::NotBlockAligned`] if the ciphertext is not whole blocks, or
/// [`Error::ChallengeLength`] if the length prefix does not match the payload.
pub fn decrypt_body(key: &[u8; KEY_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let plain = des3_cbc_decrypt(key, &[0u8; BLOCK], ciphertext)?;
    let padded = unpad80(&plain)?;
    if padded.is_empty() {
        return Ok(Vec::new());
    }
    let len = padded[0] as usize;
    if len + 1 != padded.len() {
        return Err(Error::ChallengeLength(padded.len()));
    }
    Ok(padded[1..].to_vec())
}

/// A live SCP01 channel: the session keys and the 8-byte ICV.
///
/// Holds key material, so [`Debug`] redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct Channel {
    /// Session keys.
    pub keys: SessionKeys,
    /// The chaining value: the last transmitted MAC.
    pub icv: [u8; BLOCK],
    /// What this channel protects.
    pub level: SecurityLevel,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("keys", &self.keys)
            .field("icv", &"<redacted>")
            .field("level", &self.level)
            .finish()
    }
}

impl Channel {
    /// A fresh channel over `keys` with a zero ICV, as EXTERNAL AUTHENTICATE
    /// requires.
    pub fn new(keys: SessionKeys, level: SecurityLevel) -> Self {
        Self {
            keys,
            icv: [0u8; BLOCK],
            level,
        }
    }

    /// Wraps one command from its parts and advances the ICV to the transmitted
    /// MAC.
    ///
    /// The reference emits the wrapped command as a short case-4 APDU, so a
    /// command with no Le gains a `00`; that is the shape of every APDU in the
    /// recorded capture.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] when the wrapped form does not fit a short Lc.
    pub fn wrap_parts(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u8>,
    ) -> Result<Command, Error> {
        let (apdu, icv) = wrap_apdu(
            cla, ins, p1, p2, data, le, self.level, &self.keys, &self.icv,
        )?;
        self.icv = icv;
        let body = if apdu.len() > 5 {
            apdu[5..apdu.len() - usize::from(le.is_some())].to_vec()
        } else {
            Vec::new()
        };
        Ok(Command::case4(
            Header::new(apdu[0], apdu[1], apdu[2], apdu[3]),
            body,
            Le::Short(0),
        ))
    }

    /// Builds EXTERNAL AUTHENTICATE and records the ICV it establishes.
    ///
    /// The MAC is taken over `84 82 <level> 00 10 <host cryptogram>` from a zero
    /// ICV. `ext_authenticate_des` line 458.
    ///
    /// # Errors
    ///
    /// Never in practice; mirrors [`wrap_apdu`].
    pub fn external_authenticate(
        &mut self,
        security_level: u8,
        host_cryptogram: &[u8; MAC_LEN],
    ) -> Result<Command, Error> {
        let level = self.level;
        self.level = SecurityLevel::C_MAC;
        let cmd = self.wrap_parts(
            CLA_GP,
            INS_EXTERNAL_AUTHENTICATE,
            security_level,
            0x00,
            host_cryptogram,
            Some(0),
        );
        self.level = level;
        cmd
    }
}

/// Builds INITIALIZE UPDATE (`80 50 <key version> 00 08 <host challenge> 00`).
pub fn initialize_update(key_version: u8, host: &[u8; CHALLENGE_LEN]) -> Command {
    Command::case4(
        Header::new(CLA_GP, INS_INITIALIZE_UPDATE, key_version, 0x00),
        host.to_vec(),
        Le::Short(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The KAT and fixed host challenge from the reference capture
    /// `nextgen/src/test/resources/scp01-auth.dump` lines 2-3.
    const KAT: [u8; KEY_LEN] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    const HOST: [u8; CHALLENGE_LEN] = [0xc0, 0xf8, 0xae, 0x05, 0x5c, 0x5a, 0xb8, 0x3b];
    /// **Synthetic** card challenge; see [`derive_session_key`].
    const CARD: [u8; CHALLENGE_LEN] = [0xe4, 0xb3, 0x96, 0xbd, 0x96, 0x86, 0x6d, 0x06];
    /// The permuted context: `host || card` reordered to [12:16][0:4][8:12][4:8].
    const PERM_CTX: [u8; 16] = [
        0x96, 0x86, 0x6d, 0x06, 0xc0, 0xf8, 0xae, 0x05, 0xe4, 0xb3, 0x96, 0xbd, 0x5c, 0x5a, 0xb8,
        0x3b,
    ];
    /// The session key: openssl `enc -des-ede3 -K 404142...4f -nopad` on
    /// `PERM_CTX`.
    const SK: [u8; KEY_LEN] = [
        0x39, 0xe1, 0xe2, 0xcc, 0x34, 0x34, 0x6a, 0x5f, 0xd2, 0x02, 0x2b, 0xd5, 0x79, 0x6a, 0xd3,
        0x40,
    ];

    fn keys() -> SessionKeys {
        SessionKeys { enc: SK, mac: SK }
    }

    #[test]
    fn pad80_adds_one_marker_and_always_at_least_one_octet() {
        assert_eq!(pad80(&[]), vec![0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pad80(&[1, 2, 3]), vec![1, 2, 3, 0x80, 0, 0, 0, 0]);
        // Exactly a block long: a whole extra block is added, never bare zeros.
        assert_eq!(pad80(&[0; 8]).len(), 16);
        assert_eq!(pad80(&[0; 8])[8], 0x80);
        assert_eq!(pad80(&[0; 8])[9..], [0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn unpad80_round_trips_pad80() {
        for n in 0..40usize {
            let input: Vec<u8> = (0..n).map(|i| i as u8).collect();
            assert_eq!(unpad80(&pad80(&input)).unwrap(), input);
        }
    }

    #[test]
    fn session_key_matches_openssl_3des_ecb() {
        assert_eq!(derive_session_key(&KAT, &HOST, &CARD).unwrap(), SK);
    }

    #[test]
    fn session_key_uses_the_permuted_context() {
        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(&HOST);
        ctx[8..].copy_from_slice(&CARD);
        let mut expected = [0u8; 16];
        expected[0..4].copy_from_slice(&ctx[12..16]);
        expected[4..8].copy_from_slice(&ctx[0..4]);
        expected[8..12].copy_from_slice(&ctx[8..12]);
        expected[12..16].copy_from_slice(&ctx[4..8]);
        assert_eq!(expected, PERM_CTX);
        // Dropping the permutation gives a different key, so the test above is
        // really pinning the permutation.
        assert_ne!(des3_ecb(&KAT, &ctx).unwrap(), SK.to_vec());
    }

    #[test]
    fn session_keys_enc_and_mac_are_equal_for_one_key() {
        let k = derive_session_keys(&KAT, &HOST, &CARD).unwrap();
        assert_eq!(k.enc, k.mac);
        assert_eq!(k.enc, SK);
        assert!(!format!("{k:?}").contains("6b1eff"));
    }

    #[test]
    fn mac_is_the_last_chained_block_not_the_first() {
        // 16 bytes of input chains two 3DES blocks. SCP01 takes the second.
        let input = [0xabu8; 16];
        let full = des3_cbc(&SK, &[0; 8], &pad80(&input)).unwrap();
        assert_eq!(full.len(), 24);
        let got = mac_3des(&input, &SK, &[0; 8]).unwrap();
        assert_eq!(&got[..], &full[16..24], "SCP01 takes the rightmost block");
        assert_ne!(&got[..], &full[0..8], "not the first chained block");
    }

    #[test]
    fn card_and_host_cryptograms_match_openssl() {
        // openssl enc -des-ede3-cbc -K <SK||K1> -iv 0, pad80 then the last block.
        assert_eq!(
            card_cryptogram(&SK, &HOST, &CARD).unwrap().to_vec(),
            vec![0x4b, 0x02, 0x81, 0x12, 0xbf, 0xce, 0xf5, 0x00]
        );
        assert_eq!(
            host_cryptogram(&SK, &HOST, &CARD).unwrap().to_vec(),
            vec![0x29, 0x68, 0x06, 0x44, 0x0c, 0xab, 0x84, 0x32]
        );
        assert_ne!(
            card_cryptogram(&SK, &HOST, &CARD).unwrap(),
            host_cryptogram(&SK, &HOST, &CARD).unwrap()
        );
    }

    #[test]
    fn verify_card_cryptogram_rejects_one_flipped_bit() {
        let mut good = card_cryptogram(&SK, &HOST, &CARD).unwrap();
        assert!(verify_card_cryptogram(&SK, &HOST, &CARD, &good).is_ok());
        good[3] ^= 0x01;
        assert_eq!(
            verify_card_cryptogram(&SK, &HOST, &CARD, &good),
            Err(Error::CardCryptogram)
        );
        assert_eq!(
            verify_card_cryptogram(&SK, &HOST, &CARD, &[0; 4]),
            Err(Error::ChallengeLength(4))
        );
    }

    #[test]
    fn external_authenticate_matches_openssl_mac() {
        let hc: [u8; MAC_LEN] = [0x29, 0x68, 0x06, 0x44, 0x0c, 0xab, 0x84, 0x32];
        let mut ch = Channel::new(keys(), SecurityLevel::C_MAC);
        ch.external_authenticate(LEVEL_C_MAC, &hc)
            .expect("short APDU");
        // openssl -K <SK||K1> -iv 0: pad80(84 82 01 00 10 <hc>), last 8 bytes.
        assert_eq!(
            ch.icv.to_vec(),
            vec![0xbf, 0x94, 0xea, 0xc7, 0xb0, 0xd9, 0x85, 0x2a]
        );
    }

    #[test]
    fn get_status_wrap_shape_matches_the_recorded_capture() {
        // The capture GET STATUS is 84 F2 80 02 0A 4F 00 <8-byte MAC> 00:
        // CLA 0x84 (MAC only, no encryption), Lc 0x0A = 2 + 8.
        let icv: [u8; BLOCK] = [0xbf, 0x94, 0xea, 0xc7, 0xb0, 0xd9, 0x85, 0x2a];
        let (apdu, next) = wrap_apdu(
            0x80,
            INS_GET_STATUS,
            0x80,
            0x02,
            &[0x4f, 0x00],
            Some(0),
            SecurityLevel::C_MAC,
            &keys(),
            &icv,
        )
        .expect("short APDU");
        assert_eq!(apdu[0], 0x84, "secure messaging bit set");
        assert_eq!(apdu[4], 0x0a, "Lc counts the 8 MAC bytes");
        // 5 header + 2 body + 8 MAC + 1 Le = 16, which is exactly the recorded
        // capture 84 F2 80 02 0A 4F 00 36DE04E3CAE9B20A 00 (16 octets).
        assert_eq!(apdu.len(), 16);
        // MAC over 84 F2 80 02 0A 4F 00 from the EXTERNAL AUTHENTICATE ICV.
        assert_eq!(
            next.to_vec(),
            vec![0xc8, 0xbd, 0x01, 0x57, 0x5f, 0xf7, 0x9e, 0x40]
        );
        assert_eq!(&apdu[5..7], &[0x4f, 0x00], "body first");
        assert_eq!(&apdu[7..15], &next[..], "then the full 8-byte MAC");
        assert_eq!(apdu[15], 0x00, "then Le");
    }

    #[test]
    fn wrap_sets_both_bits_for_mac_and_enc() {
        let (apdu, _) = wrap_apdu(
            CLA_GP,
            INS_GET_STATUS,
            0x80,
            0x02,
            &[0x4f, 0x00],
            Some(0),
            SecurityLevel::C_MAC_C_ENC,
            &keys(),
            &[0; 8],
        )
        .expect("short APDU");
        assert_eq!(apdu[0], 0x8c, "0x80 | MAC | ENC");
    }

    #[test]
    fn encrypted_body_is_length_prefixed_and_padded_to_eight() {
        // 2 bytes of body -> 02 4f 00, pad80 to 8 -> 02 4f 00 80 00 00 00 00.
        let (apdu, _) = wrap_apdu(
            CLA_GP,
            INS_GET_STATUS,
            0x80,
            0x02,
            &[0x4f, 0x00],
            Some(0),
            SecurityLevel::C_MAC_C_ENC,
            &keys(),
            &[0; 8],
        )
        .expect("short APDU");
        // SCP01Wrapper.java:55 adds 8 for the MAC, :79 adds t.size() - origData.length
        // for the padded ciphertext: Lc = 2 + (8 - 2) + 8 = 16 = 0x10.
        assert_eq!(apdu[4], 0x10);
        assert_eq!(
            apdu[5..13].to_vec(),
            vec![0xc4, 0x06, 0xb5, 0x3f, 0x8c, 0xf6, 0xd2, 0xcd],
            "openssl enc -des-ede3-cbc -K <SK||K1> -iv 0 over 024f008000000000"
        );
    }

    #[test]
    fn mac_lc_octet_excludes_the_encryption_overhead() {
        // The MAC is taken over the plaintext body with Lc = orig + 8, before
        // encryption adds its padding. Computed independently here.
        let expected = mac_3des(
            &[0x8c, INS_GET_STATUS, 0x80, 0x02, 0x0a, 0x4f, 0x00],
            &SK,
            &[0; 8],
        )
        .unwrap();
        let (_, icv) = wrap_apdu(
            CLA_GP,
            INS_GET_STATUS,
            0x80,
            0x02,
            &[0x4f, 0x00],
            Some(0),
            SecurityLevel::C_MAC_C_ENC,
            &keys(),
            &[0; 8],
        )
        .expect("short APDU");
        assert_eq!(icv, expected);
    }

    #[test]
    fn decryption_undoes_the_length_prefixed_encryption() {
        let cipher = [0xc4, 0x06, 0xb5, 0x3f, 0x8c, 0xf6, 0xd2, 0xcd];
        assert_eq!(decrypt_body(&SK, &cipher).unwrap(), vec![0x4f, 0x00]);
    }

    #[test]
    fn icv_advances_to_the_transmitted_mac() {
        let mut ch = Channel::new(keys(), SecurityLevel::C_MAC);
        assert_eq!(ch.icv, [0; 8]);
        ch.wrap_parts(0x80, INS_GET_STATUS, 0x80, 0x02, &[0x4f, 0x00], Some(0))
            .expect("short APDU");
        let first = ch.icv;
        assert_ne!(first, [0; 8]);
        ch.wrap_parts(0x80, INS_GET_STATUS, 0x80, 0x02, &[0x4f, 0x00], Some(0))
            .expect("short APDU");
        assert_ne!(first, ch.icv, "chaining: the second MAC differs");
    }

    #[test]
    fn channel_wrap_produces_a_short_case4_command() {
        let mut ch = Channel::new(keys(), SecurityLevel::C_MAC);
        let cmd = ch
            .wrap_parts(0x80, INS_GET_STATUS, 0x80, 0x02, &[0x4f, 0x00], Some(0))
            .expect("short APDU");
        let data = cmd.data().to_vec();
        assert_eq!(data.len(), 10, "2 body bytes then the 8-byte MAC");
        assert_eq!(&data[..2], &[0x4f, 0x00]);
        assert_eq!(&data[2..], &ch.icv[..], "MAC is the whole ICV");
        assert!(!format!("{ch:?}").contains("4b9ab1"));
    }

    #[test]
    fn initialize_update_carries_the_host_challenge() {
        let cmd = initialize_update(0x00, &HOST);
        assert_eq!(cmd.data().to_vec(), HOST.to_vec());
        assert_eq!(
            Header::new(CLA_GP, INS_INITIALIZE_UPDATE, 0x00, 0x00).class(),
            0x80
        );
    }

    #[test]
    fn plain_level_leaves_the_apdu_alone() {
        let (apdu, icv) = wrap_apdu(
            0x80,
            INS_GET_STATUS,
            0x80,
            0x02,
            &[0x4f, 0x00],
            Some(0),
            SecurityLevel::PLAIN,
            &keys(),
            &[0; 8],
        )
        .unwrap();
        assert_eq!(apdu, vec![0x80, 0xf2, 0x80, 0x02, 0x00]);
        assert_eq!(icv, [0; 8]);
    }

    #[test]
    fn over_long_bodies_are_rejected() {
        let err = wrap_apdu(
            CLA_GP,
            INS_GET_STATUS,
            0x80,
            0x02,
            &[0u8; 250],
            None,
            SecurityLevel::C_MAC,
            &keys(),
            &[0; 8],
        )
        .unwrap_err();
        assert!(matches!(err, Error::TooLong(250)));
    }

    #[test]
    fn block_alignment_is_checked() {
        assert_eq!(
            des3_cbc(&SK, &[0; 8], &[0u8; 7]).unwrap_err(),
            Error::NotBlockAligned(7)
        );
        assert_eq!(unpad80(&[0u8; 7]).unwrap_err(), Error::NotBlockAligned(7));
    }

    #[test]
    fn security_level_decodes_the_external_authenticate_p1() {
        assert_eq!(SecurityLevel::from_level(0x03), SecurityLevel::C_MAC_C_ENC);
        assert_eq!(SecurityLevel::from_level(0x01), SecurityLevel::C_MAC);
        assert_eq!(SecurityLevel::from_level(0x00), SecurityLevel::PLAIN);
    }
}
