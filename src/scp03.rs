//! GlobalPlatform Secure Channel Protocol 03 (SCP03): the pure crypto core, the
//! two handshake APDU builders, and the `auth/scp03-missing-mac` rule.
//!
//! **Owns.** Session key derivation (GP Card Spec Amendment D v1.1.2, section
//! 4.1.5: NIST SP 800-108 counter-mode KDF with AES-CMAC as the PRF), host and
//! card cryptograms, the C-MAC with its MAC chaining value, the INITIALIZE
//! UPDATE and EXTERNAL AUTHENTICATE command builders, the INITIALIZE UPDATE
//! response parser (which records the key version number, i.e. the keyset
//! identifier), and the evaluation of the missing-MAC rule over a *recorded*
//! exchange.
//!
//! **Does not own.** A transport. Nothing here sends a byte to a card. The live
//! paths are `gp status|delete|install --keys-file/--keys-env` in [`crate::gp`], which are
//! opt-in, makes a single attempt (a wrong EXTERNAL AUTHENTICATE counts toward a
//! card's retry limit) and checks the card cryptogram with
//! [`verify_card_cryptogram`] before it sends EXTERNAL AUTHENTICATE. INITIALIZE
//! UPDATE (`80 50`) and EXTERNAL AUTHENTICATE (`84 82`) stay forbidden on the live
//! operator SIM everywhere else.
//!
//! **Scope.** AES-128, AES-192 and AES-256 keys (16, 24 or 32 bytes), 8-byte
//! challenges and 8-byte cryptograms/MACs
//! (the "i" = 0x00/0x10 profiles). All four protections of Amendment D 6.2: the
//! C-MAC, C-ENC (the host encrypts the command data; the card's half of that
//! same bit is C-DECRYPTION), R-MAC (the card MACs the response) and R-ENC
//! (the host decrypts the response data), at the five levels in
//! [`SecurityLevel`]. SCP02 and SCP11 are not implemented (tracked as a
//! follow-up to issue #22).

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scp03";

use crate::apdu::{Command, Header, Le, StatusWord};
use crate::rules;
use aes::cipher::consts::U16;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};

/// Length of an AES block, of a MAC chaining value and of a full CMAC output:
/// 16 bytes whatever the key length is.
pub const BLOCK: usize = 16;
/// Length of the longest AES key, AES-256.
pub const MAX_KEY_LEN: usize = 32;
/// Length of a host or card challenge.
pub const CHALLENGE_LEN: usize = 8;
/// Length of a cryptogram and of a transmitted C-MAC.
pub const MAC_LEN: usize = 8;

/// INS of INITIALIZE UPDATE (CLA 80).
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
/// INS of EXTERNAL AUTHENTICATE (CLA 84).
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// Security level bit: command MAC.
pub const LEVEL_C_MAC: u8 = 0x01;
/// Security level bit: command encryption. The host encrypts the command data
/// (C-ENC, 6.2.6) and the card decrypts it (C-DECRYPTION). One bit with two
/// names, because it is the same operation seen from either end of the channel.
pub const LEVEL_C_ENC: u8 = 0x02;
/// Security level bit: response MAC, produced by the card and checked here.
pub const LEVEL_R_MAC: u8 = 0x10;
/// Security level bit: response encryption. The card encrypts the response data
/// and the host decrypts it (R-ENC, 6.2.7).
pub const LEVEL_R_ENC: u8 = 0x20;
/// `01`: C-MAC only, the level every live path used before this issue.
pub const LEVEL_C_MAC_ONLY: u8 = LEVEL_C_MAC;
/// `03`: C-MAC and command encryption, which the card applies as C-DECRYPTION.
pub const LEVEL_C_MAC_C_DECRYPTION: u8 = LEVEL_C_MAC | LEVEL_C_ENC;
/// `11`: C-MAC and R-MAC.
pub const LEVEL_C_MAC_R_MAC: u8 = LEVEL_C_MAC | LEVEL_R_MAC;
/// `31`: C-MAC, R-MAC and R-ENC.
pub const LEVEL_C_MAC_R_MAC_R_ENC: u8 = LEVEL_C_MAC | LEVEL_R_MAC | LEVEL_R_ENC;
/// `33`: all four protections.
pub const LEVEL_ALL: u8 = LEVEL_C_MAC_C_DECRYPTION | LEVEL_R_MAC | LEVEL_R_ENC;

/// Data derivation constants, Amendment D table 4-1.
const DDC_CARD_CRYPTOGRAM: u8 = 0x00;
const DDC_HOST_CRYPTOGRAM: u8 = 0x01;
const DDC_S_ENC: u8 = 0x04;
const DDC_S_MAC: u8 = 0x06;
const DDC_S_RMAC: u8 = 0x07;

/// What went wrong building or parsing an SCP03 value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// INITIALIZE UPDATE response of an unsupported length.
    #[error("INITIALIZE UPDATE response is {0} bytes, expected 29 or 32 (before the status word)")]
    ResponseLength(usize),
    /// The response's key information does not announce SCP03.
    #[error("key information announces SCP {0:02X}, not 03")]
    NotScp03(u8),
    /// The command data plus the MAC would not fit a short Lc.
    #[error("command data is {0} bytes; with the 8-byte C-MAC it exceeds a short APDU")]
    TooLong(usize),
    /// The response carries no room for the 8-byte R-MAC.
    #[error("response is {0} bytes: too short to carry the {MAC_LEN}-byte R-MAC")]
    ResponseTooShort(usize),
    /// The response's R-MAC does not verify under S-RMAC.
    #[error("R-MAC mismatch: this response was not produced with these session keys")]
    ResponseMac,
    /// Ciphertext is not a whole number of AES blocks.
    #[error("ciphertext is {0} bytes, not a non-zero multiple of the {BLOCK}-byte AES block")]
    NotWholeBlocks(usize),
    /// Decrypted data carries no `80` padding byte.
    #[error("decrypted data carries no 0x80 padding byte")]
    BadPadding,
    /// A security level this tool will not build.
    #[error("security level {0:02X} is not an SCP03 level this tool builds ({1})")]
    UnsupportedLevel(u8, String),
}

/// An AES key: 16, 24 or 32 bytes, i.e. AES-128, AES-192 or AES-256.
///
/// SCP03 sizes each derived key to the static key it comes from (Amendment D
/// 4.1.5: the KDF parameter `L` is the length of the derived value), so the
/// key length belongs to the key and not to the cipher: AES-192 and AES-256
/// keys are keyed CMACs too, and both still produce a 16-byte MAC.
#[derive(Clone, Copy)]
pub struct Key {
    bytes: [u8; MAX_KEY_LEN],
    len: usize,
}

impl Key {
    /// `None` for any length AES does not have.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if !matches!(bytes.len(), 16 | 24 | 32) {
            return None;
        }
        let mut key = Self {
            bytes: [0u8; MAX_KEY_LEN],
            len: bytes.len(),
        };
        key.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(key)
    }

    /// The 16-byte case, for the callers that hold a fixed `[u8; BLOCK]`.
    pub const fn from_aes128(bytes: &[u8; BLOCK]) -> Self {
        let mut key = Self {
            bytes: [0u8; MAX_KEY_LEN],
            len: BLOCK,
        };
        let mut i = 0;
        while i < BLOCK {
            key.bytes[i] = bytes[i];
            i += 1;
        }
        key
    }

    /// The key bytes: 16, 24 or 32 of them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The key as a fixed array, `None` unless it is an AES-128 key.
    pub fn as_aes128(&self) -> Option<&[u8; BLOCK]> {
        self.as_bytes().try_into().ok()
    }

    /// The key length in bits, which is the KDF parameter `L`: 128, 192 or 256.
    pub fn bits(&self) -> u16 {
        (self.len * 8) as u16
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Key {}

// Key material must not reach logs or panic messages through `{:?}`.
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key(AES-{})", self.bits())
    }
}

/// AES-CMAC (NIST SP 800-38B) over `parts`, full 16-byte output.
///
/// The key length picks the cipher; the output is one block either way.
pub(crate) fn cmac(key: &Key, parts: &[&[u8]]) -> [u8; BLOCK] {
    macro_rules! run {
        ($cipher:ty) => {{
            // The caller matched the key length to the cipher, so new_from_slice
            // cannot fail.
            let mut mac = <Cmac<$cipher> as KeyInit>::new_from_slice(key.as_bytes())
                .expect("a key of the cipher length");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().into()
        }};
    }
    match key.as_bytes().len() {
        16 => run!(Aes128),
        24 => run!(Aes192),
        _ => run!(Aes256),
    }
}

/// The SP 800-108 counter-mode KDF as Amendment D 4.1.5 uses it:
/// `CMAC(key, 0^11 || constant || 0x00 || L(2) || counter(1) || context)`,
/// counter 1 upwards, until `L` bits are derived.
///
/// `L` is the length of the derived value, not of the block: 128, 192 or 256
/// bits for a session key, 64 for a cryptogram. AES-192 and AES-256 therefore
/// run the counter twice where AES-128 runs it once, and `L` = 256 is coded
/// `01 00` in the two-byte field (pySim `scp03_key_derivation` loops on
/// `len(dk) < l // 8` in exactly this way).
fn kdf(key: &Key, constant: u8, l_bits: u16, context: &[u8]) -> Vec<u8> {
    let want = usize::from(l_bits / 8);
    let mut out = Vec::with_capacity(want);
    for counter in 1..u8::MAX {
        let mut label = [0u8; BLOCK];
        label[11] = constant;
        label[13..15].copy_from_slice(&l_bits.to_be_bytes());
        label[15] = counter;
        out.extend_from_slice(&cmac(key, &[&label, context]));
        if out.len() >= want {
            break;
        }
    }
    out.truncate(want);
    out
}

/// The three session keys of one SCP03 session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// S-ENC: keys C-ENC (card-side C-DECRYPTION) and R-ENC.
    pub enc: Key,
    /// S-MAC, keys the C-MAC and both cryptograms.
    pub mac: Key,
    /// S-RMAC, keys the R-MAC.
    pub rmac: Key,
}

// Key material must not reach logs or panic messages through `{:?}`.
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

fn context(host: &[u8; CHALLENGE_LEN], card: &[u8; CHALLENGE_LEN]) -> [u8; 2 * CHALLENGE_LEN] {
    let mut out = [0u8; 2 * CHALLENGE_LEN];
    out[..CHALLENGE_LEN].copy_from_slice(host);
    out[CHALLENGE_LEN..].copy_from_slice(card);
    out
}

/// Derives S-ENC, S-MAC and S-RMAC from the static keys and both challenges.
pub fn derive_session_keys(
    static_enc: &Key,
    static_mac: &Key,
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> SessionKeys {
    let ctx = context(host, card);
    SessionKeys {
        enc: derived(static_enc, DDC_S_ENC, &ctx),
        mac: derived(static_mac, DDC_S_MAC, &ctx),
        rmac: derived(static_mac, DDC_S_RMAC, &ctx),
    }
}

/// One session key. `L` is the length in bits of the static key, so S-ENC is as
/// long as the static ENC key and S-MAC and S-RMAC as long as the static MAC
/// key: splitting a key set into ENC, MAC and DEK does not change with the
/// length (pySim `Scp03SessionKeys.__init__` and GlobalPlatformPro
/// `PlaintextCardKeys.deriveSession` both derive each key from its own static
/// key with the length of that key in bits as `L`).
fn derived(static_key: &Key, constant: u8, ctx: &[u8]) -> Key {
    let out = kdf(static_key, constant, static_key.bits(), ctx);
    Key::new(&out).expect("the KDF returns one output of the length of the key")
}

/// Which side's cryptogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Proves the card knows the keys.
    Card,
    /// Proves the host knows the keys.
    Host,
}

/// The 8-byte authentication cryptogram of one side, keyed with S-MAC.
pub fn cryptogram(
    s_mac: &Key,
    side: Side,
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> [u8; MAC_LEN] {
    let constant = match side {
        Side::Card => DDC_CARD_CRYPTOGRAM,
        Side::Host => DDC_HOST_CRYPTOGRAM,
    };
    let full = kdf(s_mac, constant, 64, &context(host, card));
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// Compares two byte strings without an early exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether the card's cryptogram proves it holds the keys behind `keys`.
pub fn verify_card_cryptogram(
    keys: &SessionKeys,
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
    received: &[u8],
) -> bool {
    ct_eq(&cryptogram(&keys.mac, Side::Card, host, card), received)
}

/// Pads to a whole number of `block`-byte blocks with `80` then zeroes
/// (Amendment D 6.2.5 points at GPCS B.2.3 and NIST SP 800-38A). pySim
/// `pad80`, `pySim/global_platform/scp.py:44-47`.
fn pad80(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    out.resize(out.len().next_multiple_of(block), 0);
    out
}

/// Strips [`pad80`], refusing data that carries no `80` byte. pySim `unpad80`
/// (`scp.py:50-56`), which asserts the same thing.
fn unpad80(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    match data[..end].last() {
        Some(0x80) => Ok(data[..end - 1].to_vec()),
        _ => Err(Error::BadPadding),
    }
}

/// AES-CBC under an explicit ICV, no padding of its own: the caller has already
/// padded to a whole number of blocks (SP 800-38A, which Amendment D B.2 defers
/// to). Written on the bare block cipher rather than through the `cbc` crate,
/// whose cipher 0.5 types are a different major version from the ones `cmac`
/// and this file's AES key conversions already use.
fn cbc_encrypt(s_enc: &Key, iv: &[u8; BLOCK], data: &[u8]) -> Vec<u8> {
    match s_enc.as_bytes().len() {
        16 => cbc_encrypt_with::<Aes128>(s_enc, iv, data),
        24 => cbc_encrypt_with::<Aes192>(s_enc, iv, data),
        _ => cbc_encrypt_with::<Aes256>(s_enc, iv, data),
    }
}

fn cbc_encrypt_with<C: BlockCipherEncrypt + KeyInit + BlockSizeUser<BlockSize = U16>>(
    s_enc: &Key,
    iv: &[u8; BLOCK],
    data: &[u8],
) -> Vec<u8> {
    let cipher = C::new_from_slice(s_enc.as_bytes()).expect("a key of the cipher length");
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(BLOCK) {
        let mut mixed = [0u8; BLOCK];
        for (i, byte) in mixed.iter_mut().enumerate() {
            *byte = chunk[i] ^ prev[i];
        }
        let mut work = mixed.into();
        cipher.encrypt_block(&mut work);
        prev.copy_from_slice(&work[..]);
        out.extend_from_slice(&prev);
    }
    out
}

/// The inverse of [`cbc_encrypt`].
fn cbc_decrypt(s_enc: &Key, iv: &[u8; BLOCK], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() || data.len() % BLOCK != 0 {
        return Err(Error::NotWholeBlocks(data.len()));
    }
    Ok(match s_enc.as_bytes().len() {
        16 => cbc_decrypt_with::<Aes128>(s_enc, iv, data),
        24 => cbc_decrypt_with::<Aes192>(s_enc, iv, data),
        _ => cbc_decrypt_with::<Aes256>(s_enc, iv, data),
    })
}

fn cbc_decrypt_with<C: BlockCipherDecrypt + KeyInit + BlockSizeUser<BlockSize = U16>>(
    s_enc: &Key,
    iv: &[u8; BLOCK],
    data: &[u8],
) -> Vec<u8> {
    let cipher = C::new_from_slice(s_enc.as_bytes()).expect("a key of the cipher length");
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(BLOCK) {
        let mut plain = [0u8; BLOCK];
        plain.copy_from_slice(chunk);
        let mut work = plain.into();
        cipher.decrypt_block(&mut work);
        plain.copy_from_slice(&work[..]);
        for (i, prev_byte) in prev.iter().enumerate() {
            plain[i] ^= prev_byte;
        }
        out.extend_from_slice(&plain);
        prev.copy_from_slice(chunk);
    }
    out
}

/// An SCP03 security level this tool will build.
///
/// The five levels in [`Self::ALL`] are the ones pySim's own SCP03 known-answer
/// classes drive (`tests/unittests/test_globalplatform.py`, AES128/192/256 at
/// levels `01`, `03`, `11` and `33`) plus `31`, R-MAC and R-ENC without command
/// encryption. The bits are pySim's `SCP.do_cmac`, `do_cenc`, `do_rmac` and
/// `do_renc`, `pySim/global_platform/scp.py:165-183`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecurityLevel(u8);

impl SecurityLevel {
    /// `01`: C-MAC only, and the level [`Channel::new`] opens.
    pub const C_MAC: Self = Self(LEVEL_C_MAC);
    /// Every level this tool builds, ascending.
    pub const ALL: [Self; 5] = [
        Self::C_MAC,
        Self(LEVEL_C_MAC_C_DECRYPTION),
        Self(LEVEL_C_MAC_R_MAC),
        Self(LEVEL_C_MAC_R_MAC_R_ENC),
        Self(LEVEL_ALL),
    ];

    /// The level byte, as it goes in P1 of EXTERNAL AUTHENTICATE.
    pub const fn bits(self) -> u8 {
        self.0
    }
    /// Whether every command carries a C-MAC. True of every level here.
    pub const fn c_mac(self) -> bool {
        self.0 & LEVEL_C_MAC != 0
    }
    /// Whether command data is encrypted (C-ENC; C-DECRYPTION on the card).
    pub const fn c_enc(self) -> bool {
        self.0 & LEVEL_C_ENC != 0
    }
    /// Whether the card MACs its response and the MAC is checked here.
    pub const fn r_mac(self) -> bool {
        self.0 & LEVEL_R_MAC != 0
    }
    /// Whether response data is decrypted once the R-MAC has verified.
    pub const fn r_enc(self) -> bool {
        self.0 & LEVEL_R_ENC != 0
    }

    /// The level with those bits, or [`None`] for anything this tool will not
    /// build: `00` (no secure messaging), a level without the C-MAC, and R-ENC
    /// without R-MAC, which pySim refuses too (`scp.py:627-628`).
    pub fn from_bits(bits: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.0 == bits)
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}

/// The levels this tool builds, as `01 03 11 31 33`, for a refusal message.
pub fn levels() -> String {
    SecurityLevel::ALL
        .iter()
        .map(|level| level.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a response with status word `sw` carries an R-MAC. Amendment D 6.2.5
/// and pySim `SCP03.unwrap_rsp_apdu`, `scp.py:621-637`: `90 00` and the warning
/// status words `62 xx` and `63 xx` are protected, every other status word is
/// not, and an unprotected response is passed through untouched.
fn r_mac_applies(sw: &[u8]) -> bool {
    match sw {
        [0x90, 0x00] => true,
        [w1, _] => *w1 == 0x62 || *w1 == 0x63,
        _ => false,
    }
}

/// A secure channel: the C-MAC state (S-MAC and the MAC chaining value), the
/// R-MAC key, S-ENC and the encryption counter.
///
/// The chaining value starts at zero and becomes the **full 16-byte** CMAC of
/// every command wrapped, in order, so wrapping must happen once per command
/// actually sent and in send order. The R-MAC reads that same chaining value
/// and does not advance it.
#[derive(Clone)]
pub struct Channel {
    s_enc: Key,
    s_mac: Key,
    s_rmac: Key,
    chain: [u8; BLOCK],
    block_nr: u64,
    level: SecurityLevel,
    logical: u8,
}

// Key material must not reach logs through `{:?}`, as in `SessionKeys`.
impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("level", &self.level)
            .field("logical", &self.logical)
            .field("chain", &self.chain)
            .field("encryption_counter", &self.block_nr)
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// A fresh channel at [`SecurityLevel::C_MAC`]: the level every live path
    /// used before C-ENC, R-MAC and R-ENC existed, and the one whose bytes
    /// [`Channel::wrap`] still produces.
    pub fn new(keys: &SessionKeys) -> Self {
        Self::at_level(keys, SecurityLevel::C_MAC)
    }

    /// A fresh channel that builds `level` from the start, with a zero chaining
    /// value and a zero encryption counter.
    pub fn at_level(keys: &SessionKeys, level: SecurityLevel) -> Self {
        Self {
            s_enc: keys.enc,
            s_mac: keys.mac,
            s_rmac: keys.rmac,
            chain: [0; BLOCK],
            block_nr: 0,
            level,
            logical: 0,
        }
    }

    /// Wraps for logical channel `channel` (0 to 19): the MAC covers the class
    /// byte as sent, which carries the channel number (GP Card Spec v2.3.1
    /// 11.1.4; pySim puts the channel in CLA before the secure channel wraps it).
    pub fn on_logical_channel(mut self, channel: u8) -> Self {
        self.logical = channel;
        self
    }

    /// Sets the level this channel builds. A channel already used has a chain
    /// and a counter; changing the level mid-session gives the two halves of
    /// the channel different ideas about the wire format, so set it first.
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.level = level;
        self
    }

    /// The level this channel builds.
    pub const fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// The encryption counter, pySim's `Scp03SessionKeys.block_nr`
    /// (`scp.py:456`): how many C-ENC steps have been taken.
    pub const fn encryption_counter(&self) -> u64 {
        self.block_nr
    }

    /// The ICV of one encryption: Amendment D 6.2.6 for a command and 6.2.7 for
    /// a response. The counter is left-padded with zeroes to a full block and
    /// encrypted with S-ENC under an all-zero IV, which for one block is a
    /// plain ECB encryption. For a response the most significant byte is set to
    /// `80` first and the counter is the one the command just used, not a new
    /// one. pySim `Scp03SessionKeys._get_icv`, `scp.py:472-490`.
    fn icv(&self, counter: u64, response: bool) -> [u8; BLOCK] {
        let mut raw = [0u8; BLOCK];
        raw[BLOCK - 8..].copy_from_slice(&counter.to_be_bytes());
        if response {
            raw[0] = 0x80;
        }
        cbc_encrypt(&self.s_enc, &[0; BLOCK], &raw)
            .try_into()
            .expect("one AES block in, one AES block out")
    }

    /// C-ENC: pads `data` with [`pad80`] and encrypts it under S-ENC with the
    /// ICV of `counter`. The caller owns the counter; [`Channel::wrap`] takes
    /// the next value and advances it. pySim `Scp03SessionKeys._encrypt`
    /// (`scp.py:493-495`) reached from `SCP03._wrap_cmd_apdu:595-600`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] when the padded data plus the MAC exceeds 255 bytes.
    pub fn encrypt_command_data(&self, counter: u64, data: &[u8]) -> Result<Vec<u8>, Error> {
        let padded = pad80(data, BLOCK);
        if padded.len() + MAC_LEN > 0xFF {
            return Err(Error::TooLong(data.len()));
        }
        Ok(cbc_encrypt(&self.s_enc, &self.icv(counter, false), &padded))
    }

    /// C-DECRYPTION: what the card does to a command it received. The inverse
    /// of [`Channel::encrypt_command_data`] with the same `counter`, and the
    /// reason the level carrying the C-ENC bit is called
    /// [`LEVEL_C_MAC_C_DECRYPTION`].
    ///
    /// # Errors
    ///
    /// [`Error::NotWholeBlocks`] or [`Error::BadPadding`].
    pub fn decrypt_command_data(&self, counter: u64, data: &[u8]) -> Result<Vec<u8>, Error> {
        unpad80(&cbc_decrypt(&self.s_enc, &self.icv(counter, false), data)?)
    }

    /// R-ENC: decrypts response data the card encrypted, with the ICV of
    /// `counter` carrying the `80` marker, and strips the padding. `counter` is
    /// the value the matching command used, because a response does not advance
    /// the counter.
    ///
    /// # Errors
    ///
    /// [`Error::NotWholeBlocks`] or [`Error::BadPadding`].
    pub fn decrypt_response_data(&self, counter: u64, data: &[u8]) -> Result<Vec<u8>, Error> {
        unpad80(&cbc_decrypt(&self.s_enc, &self.icv(counter, true), data)?)
    }

    /// The MAC the card appends to a response: the first [`MAC_LEN`] bytes of
    /// `CMAC(S-RMAC, chain || response data || sw)` (Amendment D 6.2.5). The
    /// chaining value is the one the last command left and is **not** advanced
    /// here: the chain moves on at the next C-MAC. pySim
    /// `Scp03SessionKeys.calc_rmac`, `scp.py:466-470`.
    pub fn response_mac(&self, response_data: &[u8], sw: &[u8]) -> [u8; MAC_LEN] {
        let full = cmac(&self.s_rmac, &[&self.chain, response_data, sw]);
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&full[..MAC_LEN]);
        out
    }

    /// Checks the R-MAC on a response and, at an R-ENC level, decrypts the
    /// data. `data` is the response data field as the card sent it and `sw` its
    /// status word, both before this function.
    ///
    /// No R-MAC is generated and no protection is applied to a response that
    /// carries an error status word, and none at a level without R-MAC: the
    /// data is returned unchanged in both cases.
    ///
    /// # Errors
    ///
    /// [`Error::ResponseTooShort`], [`Error::ResponseMac`],
    /// [`Error::NotWholeBlocks`] or [`Error::BadPadding`]. A caller that gets
    /// one of these must discard the data: it did not come from a card holding
    /// these session keys.
    pub fn open_response(&self, data: &[u8], sw: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.level.r_mac() || !r_mac_applies(sw) {
            return Ok(data.to_vec());
        }
        if data.len() < MAC_LEN {
            return Err(Error::ResponseTooShort(data.len()));
        }
        let (body, received) = data.split_at(data.len() - MAC_LEN);
        if !ct_eq(&self.response_mac(body, sw), received) {
            return Err(Error::ResponseMac);
        }
        if self.level.r_enc() {
            return self.decrypt_response_data(self.block_nr, body);
        }
        Ok(body.to_vec())
    }

    /// Adds the C-MAC to `command`: sets the secure messaging bit (0x04) in
    /// CLA, appends the 8-byte MAC to the data and advances the chain. At a
    /// C-ENC level the data is encrypted first and the counter advances.
    ///
    /// MAC input (Amendment D 6.2.4): `chain || CLA' INS P1 P2 Lc' || data`,
    /// where `CLA'` has the bit set, `Lc'` counts the MAC, and `data` is the
    /// data as it goes on the wire (the ciphertext, at a C-ENC level).
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] when data plus MAC exceeds 255 bytes.
    pub fn wrap(&mut self, command: &Command) -> Result<Command, Error> {
        self.wrap_inner(command, false)
    }

    /// [`Channel::wrap`] with a chosen view of whether command encryption
    /// applies. EXTERNAL AUTHENTICATE is never encrypted: its data field is the
    /// host cryptogram, sent in the clear (Amendment D 7.1.2; pySim
    /// `SCP03.gen_ext_auth_apdu`, `scp.py:562-567`, "bypass encryption for
    /// EXTERNAL AUTHENTICATE"), and it burns no counter value.
    fn wrap_inner(&mut self, command: &Command, skip_cenc: bool) -> Result<Command, Error> {
        let data = command.data();
        let h = command.header();
        let class = crate::apdu::class_on_channel(h.class(), self.logical)
            .map_or(h.class() | 0x04, |c| {
                c | if c & 0x40 != 0 { 0x20 } else { 0x04 }
            });
        let header = Header::new(class, h.instruction(), h.parameter_1(), h.parameter_2());
        // A command with no data field has nothing to encrypt but still burns a
        // counter value (pySim `SCP03._wrap_cmd_apdu:588-592`, which does this
        // for a case 1 or case 2 command, the only ones sent without an Lc).
        let mut body = if self.level.c_enc() && !skip_cenc {
            if data.is_empty() {
                self.block_nr += 1;
                Vec::new()
            } else {
                let cipher = self.encrypt_command_data(self.block_nr + 1, data)?;
                self.block_nr += 1;
                cipher
            }
        } else {
            data.to_vec()
        };
        let lc = u8::try_from(body.len() + MAC_LEN).map_err(|_| Error::TooLong(body.len()))?;
        let full = cmac(
            &self.s_mac,
            &[&self.chain, &header.to_bytes(), &[lc], &body],
        );
        self.chain = full;
        body.extend_from_slice(&full[..MAC_LEN]);
        Ok(match command.le() {
            Some(le) => Command::case4(header, body, le),
            None => Command::case3(header, body),
        })
    }

    /// [`Self::wrap`] for a command that carries a data field with NO Lc octet
    /// in front of it, given as the parts rather than as a [`Command`].
    ///
    /// Only one command in this crate is of that shape: the reference's SELECT
    /// by FID, `00 A4 00 02 <FID> 00`, which puts the file identifier where a
    /// data field would be and sends no P3 length for it
    /// (`cla + a4 + sel_ctrl + 02 + fid + 00`, pySim/commands.py:284).
    /// [`apdu::Command`] has one case-4 shape and `case4` always emits an Lc, so
    /// re-assembling those bytes into a [`Command`] would insert an octet the
    /// reference does not send - and a plan that is bytes precisely because the
    /// dry run and the run must not disagree cannot afford that.
    ///
    /// Same MAC input as [`Self::wrap`] (Amendment D 6.2.4) with the Lc octet
    /// left out, because there is none on the wire: `chain || CLA' INS P1 P2 ||
    /// data`. The MAC goes after the data and before the Le, the chaining value
    /// is the full 16-octet CMAC, and it happens once per command actually
    /// sent, in send order.
    ///
    /// `le` is a short-form Le only, because that is the only form the commands
    /// this exists for use.
    ///
    /// # Errors
    ///
    /// Never in this version: the output is a byte vector with no Lc octet to
    /// overflow. The `Result` is kept so this and [`Self::wrap`] can be swapped
    /// without a signature change.
    pub fn wrap_bytes(
        &mut self,
        header: Header,
        data: &[u8],
        le: Option<u8>,
    ) -> Result<Vec<u8>, Error> {
        let class = crate::apdu::class_on_channel(header.class(), self.logical)
            .map_or(header.class() | 0x04, |c| {
                c | if c & 0x40 != 0 { 0x20 } else { 0x04 }
            });
        let header = Header::new(
            class,
            header.instruction(),
            header.parameter_1(),
            header.parameter_2(),
        );
        let full = cmac(&self.s_mac, &[&self.chain, &header.to_bytes(), data]);
        self.chain = full;
        let mut command = header.to_bytes().to_vec();
        command.extend_from_slice(data);
        command.extend_from_slice(&full[..MAC_LEN]);
        if let Some(le) = le {
            command.push(le);
        }
        Ok(command)
    }
}

/// INITIALIZE UPDATE (`80 50 <key version> 00 08 <host challenge> 00`).
///
/// `key_version` is the key version number (the keyset identifier); 0 asks the
/// card for its default keyset.
pub fn initialize_update(key_version: u8, host: &[u8; CHALLENGE_LEN]) -> Command {
    Command::case4(
        Header::new(0x80, INS_INITIALIZE_UPDATE, key_version, 0x00),
        host.to_vec(),
        Le::Short(0),
    )
}

/// EXTERNAL AUTHENTICATE (`84 82 <level> 00 10 <host cryptogram> <C-MAC>`),
/// MAC'd through `channel`, which must be fresh (zero chaining value).
///
/// # Errors
///
/// Never in practice; mirrors [`Channel::wrap`].
pub fn external_authenticate(
    channel: &mut Channel,
    security_level: u8,
    host_cryptogram: &[u8; MAC_LEN],
) -> Result<Command, Error> {
    // The wrap adds the secure-messaging bit, so build the plain 80 82 form.
    channel.wrap_inner(
        &Command::case3(
            Header::new(0x80, INS_EXTERNAL_AUTHENTICATE, security_level, 0x00),
            host_cryptogram.to_vec(),
        ),
        true,
    )
}

/// A parsed INITIALIZE UPDATE response (status word already stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeUpdateResponse {
    /// Key diversification data (10 bytes).
    pub diversification: [u8; 10],
    /// Key version number: the keyset identifier the card selected.
    pub key_version: u8,
    /// The "i" parameter of the SCP.
    pub i_parameter: u8,
    /// The card challenge.
    pub card_challenge: [u8; CHALLENGE_LEN],
    /// The card cryptogram.
    pub card_cryptogram: [u8; MAC_LEN],
    /// Sequence counter, present only for pseudo-random challenges (i bit 0x10).
    pub sequence_counter: Option<[u8; 3]>,
}

impl InitializeUpdateResponse {
    /// Parses `10 diversification || kvn || 03 || i || 8 challenge || 8
    /// cryptogram [|| 3 sequence counter]`.
    ///
    /// # Errors
    ///
    /// [`Error::ResponseLength`] or [`Error::NotScp03`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 29 && bytes.len() != 32 {
            return Err(Error::ResponseLength(bytes.len()));
        }
        if bytes[11] != 0x03 {
            return Err(Error::NotScp03(bytes[11]));
        }
        // Lengths were checked above, so these conversions cannot fail.
        Ok(Self {
            diversification: bytes[..10].try_into().expect("10 bytes"),
            key_version: bytes[10],
            i_parameter: bytes[12],
            card_challenge: bytes[13..21].try_into().expect("8 bytes"),
            card_cryptogram: bytes[21..29].try_into().expect("8 bytes"),
            sequence_counter: bytes.get(29..32).map(|s| s.try_into().expect("3 bytes")),
        })
    }
}

// ---------------------------------------------------------------------------
// auth/scp03-missing-mac
// ---------------------------------------------------------------------------

/// The ID of the missing-MAC rule, as AGENTS.md section 3 spells it.
pub const MISSING_MAC_RULE: &str = "auth/scp03-missing-mac";

/// Which command a recorded exchange sent without a valid C-MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// EXTERNAL AUTHENTICATE whose data carried no (or a wrong) C-MAC.
    ExternalAuthenticateWithoutMac,
    /// A command sent on an established C-MAC channel with no C-MAC appended.
    CommandWithoutMac,
}

impl ProbeKind {
    fn label(self) -> &'static str {
        match self {
            Self::ExternalAuthenticateWithoutMac => "EXTERNAL AUTHENTICATE without C-MAC",
            Self::CommandWithoutMac => "command without C-MAC on a C-MAC channel",
        }
    }
}

/// One recorded exchange: a command that should have been refused for lack of
/// a MAC, and what the card answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// What was sent.
    pub kind: ProbeKind,
    /// What the card answered.
    pub status: StatusWord,
}

/// The recorded SCP03 exchanges a scan was handed.
///
/// **Recorded, not live.** Nothing in this crate produces one from a card;
/// tests build it from mock exchanges. The scan carries `None` today, so the
/// rule is registered but reports no evidence (see [`had_evidence`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Audit {
    /// The probes, in the order they were recorded.
    pub probes: Vec<Probe>,
}

/// The rule's declaration.
pub fn missing_mac_spec() -> rules::RuleSpec {
    rules::RuleSpec::new(
        rules::RuleId::new(MISSING_MAC_RULE).expect("a validated constant"),
        rules::Severity::High,
        "the card accepted an SCP03 command that carried no valid C-MAC",
    )
    .with_remediation(
        "require C-MAC (security level 01 or higher) on EXTERNAL AUTHENTICATE and on every \
         command after it, and configure the security domain to refuse a command without one",
    )
    .with_cwe("CWE-345")
    .with_reference(
        "GlobalPlatform Card Specification Amendment D (SCP03), security level and C-MAC",
    )
}

/// Raises one finding per probe the card answered `90 00`.
///
/// Strictly `90 00`: a `61 xx` or `91 xx` is not proof the command was acted
/// on, and claiming it was would manufacture a finding.
pub fn missing_mac(audit: &Audit) -> Vec<rules::Finding> {
    audit
        .probes
        .iter()
        .filter(|probe| probe.status.is_success())
        .map(|probe| {
            rules::Finding::new(
                rules::RuleId::new(MISSING_MAC_RULE).expect("a validated constant"),
                rules::Severity::High,
                format!(
                    "{} was accepted with {}: the card does not enforce the C-MAC",
                    probe.kind.label(),
                    probe
                        .status
                        .to_bytes()
                        .map(|b| format!("{b:02X}"))
                        .join(" "),
                ),
                rules::Location::apdu(probe.kind.label()),
                rules::Evidence::text(format!("status={}", hex::encode(probe.status.to_bytes()))),
            )
        })
        .collect()
}

/// Whether there was any recorded exchange to decide from.
pub fn had_evidence(audit: &Audit) -> bool {
    !audit.probes.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // NIST SP 800-38B, Appendix D.1 (AES-128), examples 1 and 2, via the
    // `cmac` crate: pins the PRF the KDF is built on.
    #[test]
    fn cmac_nist_sp_800_38b() {
        let key = Key::from_aes128(&h("2b7e151628aed2a6abf7158809cf4f3c"));
        assert_eq!(cmac(&key, &[]), h::<16>("bb1d6929e95937287fa37d129b756746"));
        assert_eq!(
            cmac(&key, &[&h::<16>("6bc1bee22e409f96e93d7e117393172a")]),
            h::<16>("070a16b46b4d4144f79bdd9dd04a287c")
        );
    }

    // Known answers: session keys and both cryptograms.
    //
    // Source: OpenPhysical/Gp4Net, scripts/scp03_test_vectors.json at commit
    // 55a974b9affe77eb3ad1b07ac8dfdc4a3aaa34c5
    // (https://github.com/OpenPhysical/Gp4Net/blob/55a974b9affe77eb3ad1b07ac8dfdc4a3aaa34c5/scripts/scp03_test_vectors.json),
    // generated there by a Python implementation of GP Amendment D / SP 800-108.
    // All keys are obvious test patterns. Columns: enc, mac, host challenge,
    // card challenge, S-ENC, S-MAC, S-RMAC, card cryptogram, host cryptogram.
    #[allow(clippy::type_complexity)]
    const VECTORS: &[[&str; 9]] = &[
        [
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "0001020304050607",
            "08090A0B0C0D0E0F",
            "3619112820D79FF81146E6862151F521",
            "E2B6C0D5DC55B27602375D7A983A2B3C",
            "35210536E8D79B6574FC6F8B6049630D",
            "6E3E560916763FAA",
            "C44D56DED351F5A4",
        ],
        [
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000",
            "0000000000000000",
            "D119A7CCA75F050B4F306C8E1E5CC554",
            "78C41DD9D3CCFA9814C3B128FB0BB166",
            "B7698E3A4E8C6AE05E8D8C9A533CA83E",
            "D2119C5615BCA32C",
            "A6C824ACA566F3FD",
        ],
        [
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFF",
            "33DE3D6267494625C13A8E2B382372C5",
            "D14E9907C8EA69F19EEE0BB1D678BE52",
            "F4F51A2E049B61F3C24AC5733BAC07E9",
            "93A22E96300255BC",
            "18117A53AF7F8382",
        ],
        [
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "0123456789ABCDEF",
            "FEDCBA9876543210",
            "4FE5C3B41D1241A27F1B41F16EC8962B",
            "CA632CE8EB08EFC57B8606A06559A9C6",
            "48D57C3EC8EFCBB6631EC72330FB6428",
            "1EF309E33483B925",
            "0385E37C1B125747",
        ],
        [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "55555555555555555555555555555555",
            "5555555555555555",
            "AAAAAAAAAAAAAAAA",
            "F1919F3ACF4A5E0CCD5BA7BE22FFFF41",
            "E47B29F6A71006EBAE6F2908CBD6F6C3",
            "F28B86FCC30CE9030ECC9771AA050242",
            "B53C0785454B72FF",
            "627BADF61D353860",
        ],
    ];

    #[test]
    fn kdf_and_cryptograms_match_known_answers() {
        for v in VECTORS {
            let (host, card) = (h::<8>(v[2]), h::<8>(v[3]));
            let keys = derive_session_keys(
                &Key::from_aes128(&h(v[0])),
                &Key::from_aes128(&h(v[1])),
                &host,
                &card,
            );
            assert_eq!(keys.enc.as_bytes(), &h::<16>(v[4])[..], "S-ENC {}", v[0]);
            assert_eq!(keys.mac.as_bytes(), &h::<16>(v[5])[..], "S-MAC {}", v[0]);
            assert_eq!(keys.rmac.as_bytes(), &h::<16>(v[6])[..], "S-RMAC {}", v[0]);
            assert_eq!(
                cryptogram(&keys.mac, Side::Card, &host, &card),
                h::<8>(v[7])
            );
            assert_eq!(
                cryptogram(&keys.mac, Side::Host, &host, &card),
                h::<8>(v[8])
            );
            assert!(verify_card_cryptogram(&keys, &host, &card, &h::<8>(v[7])));
            assert!(!verify_card_cryptogram(&keys, &host, &card, &h::<8>(v[8])));
        }
    }

    #[test]
    fn initialize_update_bytes() {
        let cmd = initialize_update(0x30, &h("0001020304050607"));
        assert_eq!(
            hex::encode(cmd.encode().unwrap()),
            "8050300008000102030405060700"
        );
    }

    // No external vector exists for the C-MAC wrapping (the Gp4Net file has
    // none), so this recomputes the Amendment D 6.2.4 input by hand and checks
    // the chain advances with the FULL 16-byte MAC.
    #[test]
    fn c_mac_wrap_and_chain() {
        let keys = derive_session_keys(
            &Key::from_aes128(&h("000102030405060708090A0B0C0D0E0F")),
            &Key::from_aes128(&h("101112131415161718191A1B1C1D1E1F")),
            &h("0001020304050607"),
            &h("08090A0B0C0D0E0F"),
        );
        let host_cryptogram = h::<8>("C44D56DED351F5A4");
        let mut ch = Channel::new(&keys);
        let ea = external_authenticate(&mut ch, LEVEL_C_MAC, &host_cryptogram).unwrap();

        let mut input = vec![0u8; 16];
        input.extend_from_slice(&[0x84, 0x82, 0x01, 0x00, 0x10]);
        input.extend_from_slice(&host_cryptogram);
        let full = cmac(&keys.mac, &[&input]);
        let wire = ea.encode().unwrap();
        assert_eq!(&wire[..5], &[0x84, 0x82, 0x01, 0x00, 0x10]);
        assert_eq!(&wire[5..13], &host_cryptogram);
        assert_eq!(&wire[13..], &full[..8]);

        // Second command chains on the full first MAC.
        let next = Command::case3(Header::new(0x80, 0xCA, 0x00, 0x66), vec![0xAA]);
        let wrapped = ch.wrap(&next).unwrap();
        let mut input = full.to_vec();
        input.extend_from_slice(&[0x84, 0xCA, 0x00, 0x66, 0x09, 0xAA]);
        let second = cmac(&keys.mac, &[&input]);
        let wire = wrapped.encode().unwrap();
        assert_eq!(&wire[wire.len() - 8..], &second[..8]);
        assert_ne!(&full[..8], &second[..8]);
    }

    // Replay of pySim tests/unittests/test_globalplatform.py, class
    // SCP03_Test_AES128_11 (osmocom/pysim): a recorded INITIALIZE UPDATE
    // exchange, the EXTERNAL AUTHENTICATE it leads to at security level 11, and
    // five C-MAC'd commands chained after it, including the case 4 GET STATUS
    // `80 F2 80 02 02 4F 00 00` that `gp status` sends. Keys 000102.. / 101112...
    #[test]
    fn replays_pysim_scp03_session() {
        let (enc, mac) = (
            Key::from_aes128(&h("000102030405060708090a0b0c0d0e0f")),
            Key::from_aes128(&h("101112131415161718191a1b1c1d1e1f")),
        );
        let host = h::<8>("b13e5f938fc108c4");
        assert_eq!(
            hex::encode(initialize_update(0x30, &host).encode().unwrap()),
            "8050300008b13e5f938fc108c400"
        );
        let resp = InitializeUpdateResponse::parse(&h::<32>(
            "000000000000000000003003703eb51047495b249f66c484c1d2ef1948000002",
        ))
        .unwrap();
        assert_eq!(resp.key_version, 0x30);
        assert_eq!(resp.i_parameter, 0x70);
        assert_eq!(resp.sequence_counter, Some([0, 0, 2]));
        let keys = derive_session_keys(&enc, &mac, &host, &resp.card_challenge);
        assert!(verify_card_cryptogram(
            &keys,
            &host,
            &resp.card_challenge,
            &resp.card_cryptogram
        ));
        // a card holding other keys fails the check: the "wrong key" stop
        let wrong = derive_session_keys(
            &enc,
            &Key::from_aes128(&[0xFF; 16]),
            &host,
            &resp.card_challenge,
        );
        assert!(!verify_card_cryptogram(
            &wrong,
            &host,
            &resp.card_challenge,
            &resp.card_cryptogram
        ));
        let host_cg = cryptogram(&keys.mac, Side::Host, &host, &resp.card_challenge);
        let mut ch = Channel::new(&keys);
        let ea = external_authenticate(&mut ch, 0x11, &host_cg).unwrap();
        assert_eq!(
            hex::encode(ea.encode().unwrap()),
            "84821100107d5f5826a993ebc89eea24957fa0b3ce"
        );
        let get = |hex_cmd: &str| {
            let b = hex::decode(hex_cmd).unwrap();
            let (header, rest) = (Header::new(b[0], b[1], b[2], b[3]), &b[4..]);
            match rest {
                [] => Command::case1(header),
                [le] => Command::case2(header, Le::Short(*le)),
                [lc, tail @ ..] if tail.len() == usize::from(*lc) => {
                    Command::case3(header, tail.to_vec())
                }
                [lc, tail @ ..] => Command::case4(
                    header,
                    tail[..usize::from(*lc)].to_vec(),
                    Le::Short(tail[usize::from(*lc)]),
                ),
            }
        };
        for (plain, wire) in [
            (
                "80E2910006BF3E035C015A00",
                "84e291000ebf3e035c015a558d036518a2829700",
            ),
            ("80F22002", "84f220020863a63f8959827fb2"),
            ("80ca006600", "84ca006608a0c6a4a74166f7ce00"),
            (
                "80F220020a4f0212345c054f9f70c5",
                "84f22002124f0212345c054f9f70c52249b50272656536",
            ),
            ("80f28002024f0000", "84f280020a4f00e91443f6dce6b8ed00"),
        ] {
            let wrapped = ch.wrap(&get(plain)).unwrap();
            assert_eq!(hex::encode(wrapped.encode().unwrap()), wire, "{plain}");
        }
    }

    #[test]
    fn wrap_on_a_logical_channel_macs_the_class_byte_as_sent() {
        // GP Card Spec v2.3.1 11.1.4: channel 5 is the further interindustry
        // coding, GlobalPlatform + secure messaging = E1. Expected bytes come from
        // an independent Python model of Amendment D 6.2.4 (it reproduces the
        // basic-channel vectors of this file) with that class byte.
        let keys = derive_session_keys(
            &Key::from_aes128(&h("000102030405060708090A0B0C0D0E0F")),
            &Key::from_aes128(&h("101112131415161718191A1B1C1D1E1F")),
            &[0xB1, 0x3E, 0x5F, 0x93, 0x8F, 0xC1, 0x08, 0xC4],
            &[0x3E, 0xB5, 0x10, 0x47, 0x49, 0x5B, 0x24, 0x9F],
        );
        let delete = Command::case4(
            Header::new(0x80, 0xE4, 0, 0),
            hex::decode("4F07A0000000620001").unwrap(),
            crate::apdu::Le::Short(0),
        );
        let wrapped = Channel::new(&keys)
            .on_logical_channel(5)
            .wrap(&delete)
            .unwrap();
        assert_eq!(
            hex::encode_upper(wrapped.encode().unwrap()),
            "E1E40000114F07A00000006200019F185F2324F5F3A900"
        );
        // the basic channel is unchanged: 84
        let basic = Channel::new(&keys).wrap(&delete).unwrap();
        assert_eq!(basic.header().class(), 0x84);
    }

    #[test]
    fn wrap_rejects_oversize_data() {
        let keys = derive_session_keys(
            &Key::from_aes128(&[0; 16]),
            &Key::from_aes128(&[0; 16]),
            &[0; 8],
            &[0; 8],
        );
        let big = Command::case3(Header::new(0x80, 0xE2, 0, 0), vec![1u8; 248]);
        assert_eq!(Channel::new(&keys).wrap(&big), Err(Error::TooLong(248)));
    }

    #[test]
    fn parse_initialize_update_response() {
        let mut r = Vec::new();
        r.extend_from_slice(&[0x11; 10]);
        r.extend_from_slice(&[0x30, 0x03, 0x00]);
        r.extend_from_slice(&[0x22; 8]);
        r.extend_from_slice(&[0x33; 8]);
        let p = InitializeUpdateResponse::parse(&r).unwrap();
        assert_eq!(p.key_version, 0x30);
        assert_eq!(p.card_challenge, [0x22; 8]);
        assert_eq!(p.card_cryptogram, [0x33; 8]);
        assert_eq!(p.sequence_counter, None);
        r.extend_from_slice(&[0, 0, 7]);
        assert_eq!(
            InitializeUpdateResponse::parse(&r)
                .unwrap()
                .sequence_counter,
            Some([0, 0, 7])
        );
        assert_eq!(
            InitializeUpdateResponse::parse(&r[..28]),
            Err(Error::ResponseLength(28))
        );
        r[11] = 0x02;
        assert_eq!(InitializeUpdateResponse::parse(&r), Err(Error::NotScp03(2)));
    }

    #[test]
    fn rule_fires_only_on_a_90_00_probe() {
        let audit = Audit {
            probes: vec![
                Probe {
                    kind: ProbeKind::ExternalAuthenticateWithoutMac,
                    status: StatusWord::new(0x69, 0x82),
                },
                Probe {
                    kind: ProbeKind::CommandWithoutMac,
                    status: StatusWord::new(0x90, 0x00),
                },
            ],
        };
        assert!(had_evidence(&audit));
        let found = missing_mac(&audit);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule().as_str(), MISSING_MAC_RULE);
        assert_eq!(found[0].severity(), rules::Severity::High);
        assert!(missing_mac(&Audit::default()).is_empty());
        assert!(!had_evidence(&Audit::default()));
        assert_eq!(missing_mac_spec().id().as_str(), MISSING_MAC_RULE);
    }

    fn b(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// The plain command of a wire APDU, for replaying a recorded exchange.
    fn command(hex_cmd: &str) -> Command {
        let bytes = b(hex_cmd);
        let (header, rest) = (
            Header::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            &bytes[4..],
        );
        match rest {
            [] => Command::case1(header),
            [le] => Command::case2(header, Le::Short(*le)),
            [lc, tail @ ..] if tail.len() == usize::from(*lc) => {
                Command::case3(header, tail.to_vec())
            }
            [lc, tail @ ..] => Command::case4(
                header,
                tail[..usize::from(*lc)].to_vec(),
                Le::Short(tail[usize::from(*lc)]),
            ),
        }
    }

    // ------------------------------------------------------------------
    // pySim's own SCP03 known answers.
    //
    // osmocom/pysim tests/unittests/test_globalplatform.py: one `SCP03_Test`
    // subclass per security level, all on KEYSET_AES128 (KVN 30, ENC 00..0F,
    // MAC 10..1F, DEK 20..2F). Each class records the INITIALIZE UPDATE command
    // and response it used, so the host and card challenges -- and with them
    // every session key, every ICV and every MAC -- are the reference's bytes
    // and not this implementation's. `test_01`..`test_06` run in order over one
    // SCP03 object, so the channel carries across them: handshake, then GET EID
    // and its response, then the four case-1..4 commands.
    // ------------------------------------------------------------------
    const PYSIM_ENC: &str = "000102030405060708090a0b0c0d0e0f";
    const PYSIM_MAC: &str = "101112131415161718191a1b1c1d1e1f";
    /// `SCP03_Test.get_eid_rsp_plain`, the same for every class: the response
    /// data in the clear, which at 11 and 33 is only reachable after the R-MAC
    /// verified and, at 33, after R-ENC decrypted it.
    const PYSIM_EID_RSP: &str = "bf3e125a1089882119900000000000000000000005";

    /// The plain data field of `SCP03_Test.get_eid_cmd_plain`.
    const PYSIM_EID_REQ: &str = "bf3e035c015a";
    /// The four plain commands `SCP03_Test` wraps, in its order.
    const PYSIM_PLAIN: [&str; 4] = [
        "80f22002",                       // case 1
        "80ca006600",                     // case 2
        "80f220020a4f0212345c054f9f70c5", // case 3
        "80f28002024f0000",               // case 4
    ];

    struct PySim {
        level: u8,
        init_upd_cmd: &'static str,
        init_upd_rsp: &'static str,
        ext_auth: &'static str,
        get_eid_cmd: &'static str,
        get_eid_rsp: &'static str,
        cases: [&'static str; 4],
    }

    /// `SCP03_Test_AES128_11`: C-MAC and R-MAC, no encryption either way.
    const AES128_11: PySim = PySim {
        level: LEVEL_C_MAC_R_MAC,
        init_upd_cmd: "8050300008b13e5f938fc108c400",
        init_upd_rsp: "000000000000000000003003703eb51047495b249f66c484c1d2ef1948000002",
        ext_auth: "84821100107d5f5826a993ebc89eea24957fa0b3ce",
        get_eid_cmd: "84e291000ebf3e035c015a558d036518a2829700",
        get_eid_rsp: "bf3e125a1089882119900000000000000000000005971be68992dbbdfa",
        cases: [
            "84f220020863a63f8959827fb2",
            "84ca006608a0c6a4a74166f7ce00",
            "84f22002124f0212345c054f9f70c52249b50272656536",
            "84f280020a4f00e91443f6dce6b8ed00",
        ],
    };

    /// `SCP03_Test_AES128_03`: C-MAC and command encryption. Its recorded
    /// response carries no R-MAC and is already in the clear.
    const AES128_03: PySim = PySim {
        level: LEVEL_C_MAC_C_DECRYPTION,
        init_upd_cmd: "80503000088e1552d0513c60f300",
        init_upd_rsp: "0000000000000000000030037030760cd2c47c1dd395065fe5ead8a9d7000001",
        ext_auth: "8482030010fd4721a14d9b07003c451d2f8ae6bb21",
        get_eid_cmd: "84e2910018ca9c00f6713d79bc8baa642bdff51c3f6a4082d3bd9ad26c00",
        get_eid_rsp: "bf3e125a1089882119900000000000000000000005",
        cases: [
            "84f2200208c9811b11f1264cf1",
            "84ca006608e10ab60b3054798800",
            "84f22002184e2908bdb48b2315a55482e9e936ca122d6ecfae7d17416e",
            "84f28002180dd10a6b6193e5340b9e77d32d5a179cd710ac2773aefb2800",
        ],
    };

    /// `SCP03_Test_AES128_33`: all four protections at once. Its recorded
    /// response is R-MAC'd over the ciphertext and the ciphertext is the plain
    /// GET EID response under the counter its command used.
    const AES128_33: PySim = PySim {
        level: LEVEL_ALL,
        init_upd_cmd: "8050300008fdf38259a1e0de4400",
        init_upd_rsp: "000000000000000000003003703b1aca81e821f219081cdc01c26b372d000003",
        ext_auth: "84823300108c36f96bcc00724a4e13ad591d7da3f0",
        get_eid_cmd: "84e2910018267a85dfe4a98fca6fb0527e0dfecce4914e40401433c87f00",
        get_eid_rsp:
            "f3ba2b1013aa6224f5e1c138d71805c569e5439b47576260b75fc021b25097cb2e68f8a0144975b9",
        cases: [
            "84f2200208ac6a59024bed84cc",
            "84ca006608409912ad8fb7aed000",
            "84f22002185f3dafc3ac14c381536a488bf44e06d056df9d74dbd21e5a",
            "84f280021865165105be3373347d0424d4400af2ac393f569ec779389e00",
        ],
    };

    fn pysim_keys(v: &PySim) -> SessionKeys {
        let init = b(v.init_upd_cmd);
        let host: [u8; CHALLENGE_LEN] = init[5..13].try_into().expect("8-byte host challenge");
        let iur = InitializeUpdateResponse::parse(&b(v.init_upd_rsp)).expect("pySim's response");
        let keys = derive_session_keys(
            &Key::from_aes128(&h(PYSIM_ENC)),
            &Key::from_aes128(&h(PYSIM_MAC)),
            &host,
            &iur.card_challenge,
        );
        assert!(
            verify_card_cryptogram(&keys, &host, &iur.card_challenge, &iur.card_cryptogram),
            "pySim's card cryptogram"
        );
        keys
    }

    /// Replays one pySim class byte for byte: INITIALIZE UPDATE, the response,
    /// EXTERNAL AUTHENTICATE, GET EID wrapped, that response opened, and the
    /// four case-1..4 commands wrapped. Returns the channel as pySim had it
    /// after the GET EID response, with the session keys.
    fn replay(v: &PySim) -> (Channel, SessionKeys) {
        let level = SecurityLevel::from_bits(v.level).expect("a level pySim tests");
        let init = b(v.init_upd_cmd);
        let host: [u8; CHALLENGE_LEN] = init[5..13].try_into().expect("8-byte host challenge");
        assert_eq!(
            hex::encode(initialize_update(init[2], &host).encode().unwrap()),
            v.init_upd_cmd
        );
        let keys = pysim_keys(v);
        let mut ch = Channel::at_level(&keys, level);
        let host_cg = cryptogram(&keys.mac, Side::Host, &host, &channel_card_challenge(v));
        assert_eq!(
            hex::encode(
                external_authenticate(&mut ch, v.level, &host_cg)
                    .unwrap()
                    .encode()
                    .unwrap()
            ),
            v.ext_auth
        );
        // EXTERNAL AUTHENTICATE is never encrypted and burns no counter value,
        // which is why the first encrypted command below uses counter 1.
        assert_eq!(ch.encryption_counter(), 0);

        let wire = hex::encode(
            ch.wrap(&command("80e2910006bf3e035c015a00"))
                .unwrap()
                .encode()
                .unwrap(),
        );
        assert_eq!(wire, v.get_eid_cmd);
        assert_eq!(
            ch.open_response(&b(v.get_eid_rsp), &[0x90, 0x00]).unwrap(),
            b(PYSIM_EID_RSP)
        );
        // The caller wants the channel as pySim had it when the GET EID
        // response arrived, so hand back a copy taken before the four cases
        // advanced the chain and the counter further.
        let at_response = ch.clone();
        for (plain, wire) in PYSIM_PLAIN.into_iter().zip(v.cases) {
            assert_eq!(
                hex::encode(ch.wrap(&command(plain)).unwrap().encode().unwrap()),
                wire,
                "{plain}"
            );
        }
        (at_response, keys)
    }

    fn channel_card_challenge(v: &PySim) -> [u8; CHALLENGE_LEN] {
        InitializeUpdateResponse::parse(&b(v.init_upd_rsp))
            .expect("pySim's response")
            .card_challenge
    }

    // R-MAC, against `SCP03_Test_AES128_11`: the response the reference
    // recorded is its data in the clear with pySim's own 8-byte R-MAC on it.
    #[test]
    fn pysim_level_11_authenticates_the_response() {
        replay(&AES128_11);
    }

    // C-ENC, against `SCP03_Test_AES128_03`: the command data is AES-CBC under
    // S-ENC with the ICV of the counter, and the C-MAC covers the ciphertext.
    #[test]
    fn pysim_level_03_encrypts_the_command() {
        replay(&AES128_03);
    }

    // All four, against `SCP03_Test_AES128_33`.
    #[test]
    fn pysim_level_33_runs_all_four_protections() {
        replay(&AES128_33);
    }

    // Each protection on its own, against the same pySim bytes.
    #[test]
    fn c_enc_is_py_sim_s_ciphertext_under_the_counter() {
        let ch = Channel::at_level(
            &pysim_keys(&AES128_03),
            SecurityLevel::from_bits(LEVEL_C_MAC_C_DECRYPTION).expect("level"),
        );
        let cipher = ch.encrypt_command_data(1, &b(PYSIM_EID_REQ)).unwrap();
        // the data field of pySim's `get_eid_cmd` at level 03
        assert_eq!(hex::encode(&cipher), "ca9c00f6713d79bc8baa642bdff51c3f");
        // and the case-3 body from the same class, padded from 10 to 16 bytes,
        // under the counter it had there: the GET EID took 1 and the two
        // data-less case-1 and case-2 commands took 2 and 3.
        let long = ch
            .encrypt_command_data(4, &b("4f0212345c054f9f70c5"))
            .unwrap();
        // the first 16 bytes of the data field of pySim's `case_3_apdu`
        assert_eq!(
            &hex::encode(&long)[..32],
            "4e2908bdb48b2315a55482e9e936ca12"
        );
    }

    // C-DECRYPTION: the card's half of the same bit, and the exact inverse.
    #[test]
    fn c_decryption_recovers_the_command_the_card_would_read() {
        for v in [&AES128_03, &AES128_33] {
            let ch = Channel::at_level(&pysim_keys(v), SecurityLevel::from_bits(v.level).unwrap());
            // GET EID is a case-4 command: header, Lc, the protected data,
            // the 8-byte C-MAC over it, then the Le byte.
            let wire = b(v.get_eid_cmd);
            let data = &wire[5..wire.len() - 1 - MAC_LEN];
            assert_eq!(data.len(), BLOCK, "{} is a whole AES block", v.level);
            assert_eq!(
                ch.decrypt_command_data(1, data).unwrap(),
                b(PYSIM_EID_REQ),
                "level {:02X}",
                v.level
            );
            // the round trip through the encrypting half returns the same
            // ciphertext pySim recorded
            assert_eq!(ch.encrypt_command_data(1, &b(PYSIM_EID_REQ)).unwrap(), data);
            // and the padding is the 0x80-then-zeroes of Amendment D B.2
            let padded = cbc_decrypt(&ch.s_enc, &ch.icv(1, false), data).unwrap();
            assert_eq!(padded[6], 0x80, "the 0x80 padding byte");
            assert!(padded[7..].iter().all(|b| *b == 0), "zero padding");
            // a counter the command did not use gives different bytes
            assert_ne!(
                ch.decrypt_command_data(2, data).ok(),
                Some(b(PYSIM_EID_REQ))
            );
        }
    }

    // R-MAC, on its own: the first 8 bytes of CMAC(S-RMAC, chain || data || sw).
    #[test]
    fn r_mac_is_py_sim_s_trailing_eight_bytes() {
        for v in [&AES128_11, &AES128_33] {
            let (ch, _) = replay(v);
            let rsp = b(v.get_eid_rsp);
            let (data, mac) = rsp.split_at(rsp.len() - MAC_LEN);
            assert_eq!(
                hex::encode(ch.response_mac(data, &[0x90, 0x00])),
                hex::encode(mac)
            );
            // the R-MAC reads the chaining value and does not advance it
            assert_eq!(
                hex::encode(ch.response_mac(data, &[0x90, 0x00])),
                hex::encode(mac)
            );
            // a different status word MACs differently, which is why only
            // 90 00 and the 62 xx / 63 xx warnings are protected
            assert_ne!(ch.response_mac(data, &[0x63, 0x10]), mac);
        }
    }

    // R-ENC, on its own: the response body under the counter the command used.
    #[test]
    fn r_enc_is_py_sim_s_ciphertext_under_the_same_counter() {
        let (ch, keys) = replay(&AES128_33);
        let rsp = b(AES128_33.get_eid_rsp);
        let (data, _) = rsp.split_at(rsp.len() - MAC_LEN);
        assert_eq!(ch.encryption_counter(), 1);
        assert_eq!(ch.decrypt_response_data(1, data).unwrap(), b(PYSIM_EID_RSP));
        // the response ICV is the command's counter with its top byte set to 80
        let mut raw = [0u8; BLOCK];
        raw[BLOCK - 8..].copy_from_slice(&1u64.to_be_bytes());
        raw[0] = 0x80;
        let expected: [u8; BLOCK] = cbc_encrypt(&keys.enc, &[0; BLOCK], &raw)
            .try_into()
            .expect("one AES block");
        assert_eq!(ch.icv(1, true), expected);
        assert_ne!(ch.icv(1, true), ch.icv(1, false));
        assert_ne!(ch.icv(2, true), ch.icv(1, true));
    }

    // The ICV is what binds a response to its command: only the counter that
    // command used opens it.
    #[test]
    fn a_response_whose_icv_does_not_match_is_refused() {
        let (ch, keys) = replay(&AES128_33);
        let rsp = b(AES128_33.get_eid_rsp);
        let (data, _) = rsp.split_at(rsp.len() - MAC_LEN);
        let plain = b(PYSIM_EID_RSP);
        // the counter the command used is the only one that opens it
        assert_eq!(ch.decrypt_response_data(1, data).unwrap(), plain);
        assert_ne!(ch.decrypt_response_data(2, data).ok(), Some(plain.clone()));
        assert_ne!(ch.decrypt_response_data(0, data).ok(), Some(plain));
        // and a body that is not a whole number of AES blocks is refused
        // before any cipher runs
        assert_eq!(
            ch.decrypt_response_data(1, &data[..15]),
            Err(Error::NotWholeBlocks(15))
        );
        // the command ICV does not open the response ICV
        assert_ne!(
            cbc_decrypt(&keys.enc, &ch.icv(1, false), data).unwrap(),
            cbc_decrypt(&keys.enc, &ch.icv(1, true), data).unwrap()
        );
    }

    #[test]
    fn a_response_whose_r_mac_does_not_verify_is_refused() {
        let (ch, _) = replay(&AES128_33);
        let rsp = b(AES128_33.get_eid_rsp);
        let mut flipped = rsp.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert_eq!(
            ch.open_response(&flipped, &[0x90, 0x00]),
            Err(Error::ResponseMac)
        );
        // a body that moves under an unchanged MAC is refused too
        let mut swapped = rsp.clone();
        swapped.swap(0, 1);
        assert_eq!(
            ch.open_response(&swapped, &[0x90, 0x00]),
            Err(Error::ResponseMac)
        );
        // a status word the MAC was not computed over is refused
        assert_eq!(
            ch.open_response(&rsp, &[0x62, 0x10]),
            Err(Error::ResponseMac)
        );
        // and a response too short to hold an R-MAC is refused outright
        assert_eq!(
            ch.open_response(&rsp[..4], &[0x90, 0x00]),
            Err(Error::ResponseTooShort(4))
        );
    }

    // Amendment D 6.2.5 / pySim `scp.py:621-637`: an error status word is not
    // protected, so its data is handed back exactly as the card sent it.
    #[test]
    fn an_error_status_word_is_passed_through_unprotected() {
        let (ch, _) = replay(&AES128_33);
        let rsp = b(AES128_33.get_eid_rsp);
        for sw in [[0x69, 0x82], [0x6A, 0x80], [0x6F, 0x00]] {
            assert_eq!(ch.open_response(&rsp, &sw).unwrap(), rsp, "{sw:02X?}");
        }
    }

    // At a level with no R-MAC the response is handed back untouched, which is
    // how pySim's own `SCP03_Test_AES128_03` records its response.
    #[test]
    fn a_level_without_r_mac_does_not_touch_the_response() {
        let (ch, _) = replay(&AES128_03);
        let rsp = b(AES128_03.get_eid_rsp);
        assert!(!ch.security_level().r_mac());
        assert_eq!(ch.open_response(&rsp, &[0x90, 0x00]).unwrap(), rsp);
    }

    #[test]
    fn security_levels_that_exist_and_levels_that_do_not() {
        assert_eq!(
            SecurityLevel::ALL.map(|level| level.bits()),
            [
                LEVEL_C_MAC_ONLY,
                LEVEL_C_MAC_C_DECRYPTION,
                LEVEL_C_MAC_R_MAC,
                LEVEL_C_MAC_R_MAC_R_ENC,
                LEVEL_ALL
            ]
        );
        assert_eq!(levels(), "01 03 11 31 33");
        for level in SecurityLevel::ALL {
            assert_eq!(SecurityLevel::from_bits(level.bits()), Some(level));
        }
        // 00 is no secure messaging, the rest are a level without the C-MAC or
        // R-ENC without R-MAC, which pySim refuses too (scp.py:627-628).
        for bits in [0x00u8, 0x02, 0x10, 0x13, 0x20, 0x21, 0x23, 0x41, 0xFF] {
            assert_eq!(SecurityLevel::from_bits(bits), None, "{bits:02X}");
            assert_eq!(
                Error::UnsupportedLevel(bits, levels()).to_string(),
                format!(
                    "security level {bits:02X} is not an SCP03 level this tool builds \
                     (01 03 11 31 33)"
                )
            );
        }
    }

    // Today's C-MAC path must not move: `Channel::new` is the channel the live
    // commands had, and its bytes are the ones pySim records at level 01.
    #[test]
    fn level_c_mac_bytes_do_not_move() {
        let keys = pysim_keys(&AES128_11);
        let mut by_default = Channel::new(&keys);
        let mut by_level = Channel::at_level(&keys, SecurityLevel::C_MAC);
        assert_eq!(by_default.security_level(), SecurityLevel::C_MAC);
        assert_eq!(by_default.encryption_counter(), 0);
        let cmd = command("80e2910006bf3e035c015a00");
        let from_new = hex::encode(by_default.wrap(&cmd).unwrap().encode().unwrap());
        let from_level = hex::encode(by_level.wrap(&cmd).unwrap().encode().unwrap());
        assert_eq!(from_new, from_level);
        // no encryption, and the counter does not move
        assert_eq!(by_default.encryption_counter(), 0);
        assert!(!by_default.security_level().c_enc());
        assert!(!by_default.security_level().r_mac());
        assert!(!by_default.security_level().r_enc());
    }

    // The AES-128 bytes are what they were before AES-192 and AES-256 were
    // added: the same inputs give the same outputs. Source:
    // OpenPhysical/Gp4Net scripts/scp03_test_vectors.json at commit
    // 55a974b9affe77eb3ad1b07ac8dfdc4a3aaa34c5 (vector 0), the file and vector
    // `kdf_and_cryptograms_match_known_answers` already pins, plus the
    // challenges of pySim SCP03_Test_AES128_11.
    #[test]
    fn aes_128_output_is_unchanged() {
        let (enc, mac) = (
            Key::from_aes128(&h("000102030405060708090A0B0C0D0E0F")),
            Key::from_aes128(&h("101112131415161718191A1B1C1D1E1F")),
        );
        let (host, card) = (h("0001020304050607"), h("08090A0B0C0D0E0F"));
        let keys = derive_session_keys(&enc, &mac, &host, &card);
        assert_eq!(
            keys.enc.as_bytes(),
            &h::<16>("3619112820D79FF81146E6862151F521")[..]
        );
        assert_eq!(
            keys.mac.as_bytes(),
            &h::<16>("E2B6C0D5DC55B27602375D7A983A2B3C")[..]
        );
        assert_eq!(
            keys.rmac.as_bytes(),
            &h::<16>("35210536E8D79B6574FC6F8B6049630D")[..]
        );
        assert_eq!(keys.enc.bits(), 128);
        assert_eq!(keys.mac.bits(), 128);
        assert_eq!(
            cryptogram(&keys.mac, Side::Card, &host, &card),
            h::<8>("6E3E560916763FAA")
        );
        assert_eq!(
            cryptogram(&keys.mac, Side::Host, &host, &card),
            h::<8>("C44D56DED351F5A4")
        );
        // A key never prints its bytes.
        assert_eq!(format!("{:?}", enc), "Key(AES-128)");
    }

    /// The plain commands pySim wraps, parsed as APDUs: case 1 to case 4.
    fn get(hex_cmd: &str) -> Command {
        let b = hex::decode(hex_cmd).unwrap();
        let (header, rest) = (Header::new(b[0], b[1], b[2], b[3]), &b[4..]);
        match rest {
            [] => Command::case1(header),
            [le] => Command::case2(header, Le::Short(*le)),
            [lc, tail @ ..] if tail.len() == usize::from(*lc) => {
                Command::case3(header, tail.to_vec())
            }
            [lc, tail @ ..] => Command::case4(
                header,
                tail[..usize::from(*lc)].to_vec(),
                Le::Short(tail[usize::from(*lc)]),
            ),
        }
    }

    /// One byte of a hex string, as the APDU field it sits in.
    fn hex_byte(pair: &str) -> u8 {
        u8::from_str_radix(pair, 16).unwrap()
    }

    /// Replays one pySim SCP03 test class: the INITIALIZE UPDATE command is
    /// built as pySim built it, the card cryptogram in the recorded response
    /// verifies with `enc`/`mac`, the EXTERNAL AUTHENTICATE comes out as
    /// `ext_auth`, and the five chained C-MAC commands as `cases`.
    #[allow(clippy::too_many_arguments)]
    fn replay_pysim_session(
        enc: &str,
        mac: &str,
        init_cmd: &str,
        init_rsp: &str,
        level: u8,
        ext_auth: &str,
        cases: &[(&str, &str)],
    ) {
        let (enc, mac) = (
            Key::new(&hex::decode(enc).unwrap()).unwrap(),
            Key::new(&hex::decode(mac).unwrap()).unwrap(),
        );
        // 80 <ins> <kvn> 00 08 <host challenge> 00
        let host = h::<8>(&init_cmd[10..26]);
        assert_eq!(
            hex::encode(
                initialize_update(hex_byte(&init_cmd[4..6]), &host)
                    .encode()
                    .unwrap()
            ),
            init_cmd
        );
        let iur = InitializeUpdateResponse::parse(&hex::decode(init_rsp).unwrap()).unwrap();
        let keys = derive_session_keys(&enc, &mac, &host, &iur.card_challenge);
        // Each derived key is as long as the static key it came from.
        assert_eq!(keys.enc.bits(), enc.bits());
        assert_eq!(keys.mac.bits(), mac.bits());
        assert_eq!(keys.rmac.bits(), mac.bits());
        assert_eq!(format!("{:?}", enc), format!("Key(AES-{})", enc.bits()));
        assert!(verify_card_cryptogram(
            &keys,
            &host,
            &iur.card_challenge,
            &iur.card_cryptogram
        ));
        let host_cg = cryptogram(&keys.mac, Side::Host, &host, &iur.card_challenge);
        let mut ch = Channel::new(&keys);
        let ea = external_authenticate(&mut ch, level, &host_cg).unwrap();
        assert_eq!(hex::encode(ea.encode().unwrap()), ext_auth);
        for (plain, wire) in cases {
            let wrapped = ch.wrap(&get(plain)).unwrap();
            assert_eq!(hex::encode(wrapped.encode().unwrap()), *wire, "{plain}");
        }
    }

    // pySim tests/unittests/test_globalplatform.py: KEYSET_AES192 (line 170)
    // and class SCP03_Test_AES192_11 (line 212), 24-byte ENC, MAC and DEK at
    // kvn 0x31. The expected bytes are the ones pySim asserts.
    #[test]
    fn replays_pysim_scp03_session_aes192() {
        replay_pysim_session(
            "000102030405060708090a0b0c0d0e0f0001020304050607",
            "101112131415161718191a1b1c1d1e1f1011121314151617",
            "80503100087396430b768b085b00",
            "000000000000000000003103708cfc23522ffdbf1e5df5542cac8fd866000003",
            0x11,
            "84821100102145ed30b146f5db252fb7e624cec244",
            &[
                (
                    "80E2910006BF3E035C015A00",
                    "84e291000ebf3e035c015aff42cf801d14394400",
                ),
                ("80F22002", "84f22002084584e4f6784811ee"),
                ("80ca006600", "84ca006608937776ebe190fa3000"),
                (
                    "80F220020a4f0212345c054f9f70c5",
                    "84f22002124f0212345c054f9f70c59a52bddf3040368c",
                ),
                ("80f28002024f0000", "84f280020a4f009804b11411f7393d00"),
            ],
        );
    }

    // pySim tests/unittests/test_globalplatform.py: KEYSET_AES256 (line 172)
    // and class SCP03_Test_AES256_11 (line 248), 32-byte ENC, MAC and DEK at
    // kvn 0x32. The widest case: `L` = 256 is coded `01 00` in the KDF label
    // and the counter runs twice, as it does for AES-192.
    #[test]
    fn replays_pysim_scp03_session_aes256() {
        replay_pysim_session(
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f",
            "805032000811666d57866c6f5400",
            "0000000000000000000032037053ea8847efa7674e41498a4d66cf0dee000003",
            0x11,
            "84821100102f2ad190eff2fafc4908996d1cebd310",
            &[
                (
                    "80E2910006BF3E035C015A00",
                    "84e291000ebf3e035c015af4b680372542b59d00",
                ),
                ("80F22002", "84f2200208d618b7da68d5fe52"),
                ("80ca006600", "84ca0066088f3e055db23ad5e500"),
                (
                    "80F220020a4f0212345c054f9f70c5",
                    "84f22002124f0212345c054f9f70c5b6e15cc42404915e",
                ),
                ("80f28002024f0000", "84f280020a4f00aa124aa74afe7f7500"),
            ],
        );
    }

    // A key set is one length throughout: an ENC of 20 bytes is not a key.
    #[test]
    fn only_the_three_aes_key_lengths_are_keys() {
        assert!(Key::new(&[0; 16]).is_some());
        assert!(Key::new(&[0; 24]).is_some());
        assert!(Key::new(&[0; 32]).is_some());
        assert!(Key::new(&[0; 20]).is_none());
        assert_eq!(Key::new(&[0; 24]).unwrap().as_bytes().len(), 24);
        assert_eq!(Key::new(&[7; 24]).unwrap().as_aes128(), None);
        assert_eq!(Key::from_aes128(&[7; 16]).as_aes128(), Some(&[7; 16]));
    }
}
