//! GlobalPlatform Secure Channel Protocol 02 (SCP02): the pure crypto core, the
//! handshake APDU builders, the secure-messaging wrapper and the release
//! command. Sends nothing; the live path is `gp scp02` in [`crate::gp`].
//!
//! **Owns.** Session key derivation (two-key 3DES-CBC over
//! `constant || seq-counter || 0x00 x 12`), the card and host cryptograms (3DES
//! CBC-MAC with a zero IV under **S-ENC**), the C-MAC of GP Card Spec v2.3.1
//! B.1.2.2 (single DES plus final 3DES) with its 8-byte ICV, the INITIALIZE
//! UPDATE and EXTERNAL AUTHENTICATE builders, the INITIALIZE UPDATE response
//! parser, and the MANAGE CHANNEL release.
//!
//! **Scope.** C-MAC only (security level 0x01). R-MAC, R-ENC and C-DECRYPTION are
//! not implemented; [`Channel::wrap`] appends the C-MAC after the data and no
//! encryption, and the CLI never asks for a level above 01.
//!
//! **Provenance.** Every wire vector in the tests below is pySim own, from
//! `tests/unittests/test_globalplatform.py` (`SCP02_Auth_Test`, `SCP02_Test`)
//! with the keyset `ck_3des_70`; the algorithms are pySim
//! `pySim/global_platform/scp.py` (`SCP02`, `Scp02SessionKeys`,
//! `scp02_key_derivation`). GPL code is read and cited, never copied. Nothing was
//! taken from GlobalPlatformPro (LGPL-3.0); its `SCP02Wrapper.wrap` was read only
//! to confirm the ICV advance, which pySim also states.
//!
//! **What differs from SCP03** (do not carry anything over from [`crate::scp03`]):
//!
//! * Keys are 3DES, 16 bytes, not AES; the block size is 8, not 16.
//! * The card challenge is **6** bytes and the sequence counter is a mandatory
//!   2-byte big-endian field, because the INITIALIZE UPDATE response is a fixed
//!   28 bytes with `02` at offset 11 (`SCP02.constr_iur`).
//! * The cryptograms are keyed with **S-ENC**, not S-MAC, and both are computed
//!   over the **sequence counter** as well as both challenges
//!   (`SCP02._compute_cryptograms`), in the order `host || ctr || card` and
//!   `ctr || card || host`.
//! * There is no 16-byte MAC chaining value. [`Channel`] keeps the 8-byte ICV of
//!   B.1.2.2, advanced by *one more single DES encryption of the transmitted
//!   C-MAC*, not set to the C-MAC itself. An SCP02 channel is therefore not a
//!   value-chained one: the ICV is the only state, it starts at zero for EXTERNAL
//!   AUTHENTICATE, and each command advances it once.
//! * The C-MAC is always one full DES block and is appended after the data, with
//!   any Le after it.

/// This module name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scp02";

use crate::apdu::{Command, Header, Le};
use crate::otacrypto::{self, Alg};

/// Length of a 3DES key (two-key 3DES, K1 = K3).
pub const KEY_LEN: usize = 16;
/// Length of a DES block: the C-MAC, the ICV and an APDU data field.
pub const BLOCK: usize = 8;
/// Length of the host challenge.
pub const HOST_CHALLENGE_LEN: usize = 8;
/// Length of the **card** challenge, which is 6, not 8.
pub const CARD_CHALLENGE_LEN: usize = 6;
/// Length of a cryptogram and of a transmitted C-MAC.
pub const MAC_LEN: usize = 8;
/// Length of a parsed INITIALIZE UPDATE response, status word stripped.
pub const IUR_LEN: usize = 28;

/// INS of INITIALIZE UPDATE.
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
/// INS of EXTERNAL AUTHENTICATE.
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// INS of MANAGE CHANNEL, which carries the release (GP Card Spec v2.3.1 11.7).
pub const INS_MANAGE_CHANNEL: u8 = 0x70;
/// P1 and P2 of MANAGE CHANNEL that closes the secure messaging channel
/// (11.7.1 Table 11-2). Same P1-`80` encoding `session::manage_channel_close`
/// already uses.
pub const MANAGE_CHANNEL_RELEASE: (u8, u8) = (0x80, 0x00);
/// The secure messaging indicator, set in CLA before a command is MAC-ed.
pub const CLA_SM: u8 = 0x04;
/// Security level bit: command MAC. The only level implemented here.
pub const LEVEL_C_MAC: u8 = 0x01;
/// The byte at offset 11 of an SCP02 INITIALIZE UPDATE response.
pub const SCP_IDENTIFIER: u8 = 0x02;

/// Key derivation constants (GP Card Spec v2.3.1 B.1.1.1; the
/// `Scp02SessionKeys.DERIV_CONST_*` constants in pySim).
const DERIV_C_MAC: [u8; 2] = [0x01, 0x01];
const DERIV_R_MAC: [u8; 2] = [0x01, 0x02];
const DERIV_S_ENC: [u8; 2] = [0x01, 0x82];
const DERIV_S_DEC: [u8; 2] = [0x01, 0x81];

/// Key version numbers an SCP02 card may use.
///
/// `SCP02.kvn_ranges` in `pySim/global_platform/scp.py`: `01` is a
/// sysmoUSIM-SJS1 special case, `20`-`2F` is the range GPC_GUI_010 V1.0.1 6
/// reserves for SCP02 (quoted verbatim in the pySim comment there) and `70` is a
/// sysmoISIM-SJA2/SJA5 special case. `70` sits outside `20`-`2F`, which is why
/// pySim lists it as a separate range.
pub const KVN_RANGES: &[(u8, u8)] = &[(0x01, 0x01), (0x20, 0x2f), (0x70, 0x70)];

/// Whether `kvn` is one an SCP02 card may use. Key version `00` is accepted by
/// every card (it asks for the first available key set, GPC_SPE_034 E.5.1.3) and
/// is not range-checked.
pub fn kvn_allowed(kvn: u8) -> bool {
    kvn == 0 || KVN_RANGES.iter().any(|(lo, hi)| kvn >= *lo && kvn <= *hi)
}

/// What went wrong building or parsing an SCP02 value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// INITIALIZE UPDATE response of an unsupported length.
    #[error("INITIALIZE UPDATE response is {0} bytes, expected 28 (before the status word)")]
    ResponseLength(usize),
    /// The response key information does not announce SCP02.
    #[error("key information announces SCP {0:02X}, not 02")]
    NotScp02(u8),
    /// The command data plus the C-MAC would not fit a short Lc.
    #[error("command data is {0} bytes; with the 8-byte C-MAC it exceeds a short APDU")]
    TooLong(usize),
}

/// Appends `80` and zeros up to the next multiple of `BLOCK` (GP Card Spec
/// v2.3.1 B.1.2.2, ISO/IEC 7816-4 padding method 2; `pad80` in pySim).
pub fn pad80(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while out.len() % BLOCK != 0 {
        out.push(0);
    }
    out
}

/// One block of single DES in ECB.
fn des_block(key: &[u8; BLOCK], block: &[u8; BLOCK], decrypt: bool) -> [u8; BLOCK] {
    let iv = [0u8; BLOCK];
    let out = if decrypt {
        otacrypto::decrypt(Alg::Des, key, Some(&iv), block)
    } else {
        otacrypto::encrypt(Alg::Des, key, Some(&iv), block)
    }
    .expect("one DES block under an 8-byte key");
    out[..BLOCK].try_into().expect("one DES block")
}

/// 3DES-CBC encryption with a zero IV. `data` must be a whole number of blocks,
/// which [`pad80`] guarantees.
fn tdes3_cbc_zero_iv(key: &[u8; KEY_LEN], data: &[u8]) -> Vec<u8> {
    otacrypto::encrypt(Alg::Tdes, key, Some(&[0u8; BLOCK]), data).expect("padded to whole blocks")
}

/// One SCP02 session key: 3DES-CBC under the static key with a zero IV over
/// `constant || counter || 0x00 x 12`.
///
/// GP Card Spec v2.3.1 B.1.1.1; `scp02_key_derivation` in
/// `pySim/global_platform/scp.py`, which builds exactly these 16 bytes and
/// encrypts them under the 16-byte static key with a zero IV. The result is two
/// 3DES blocks, so this returns the whole 16-byte key. [V]
pub fn derive_key(constant: &[u8; 2], counter: u16, static_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut derivation = [0u8; KEY_LEN];
    derivation[..2].copy_from_slice(constant);
    derivation[2..4].copy_from_slice(&counter.to_be_bytes());
    // derivation[4..16] is already zero: the 12 trailing zero bytes of the spec.
    tdes3_cbc_zero_iv(static_key, &derivation)[..KEY_LEN]
        .try_into()
        .expect("two 3DES blocks")
}

/// The session keys of one SCP02 session.
///
/// Only `enc` (the cryptograms) and `mac` (the C-MAC) are used by the paths
/// here; `rmac` and `dek` are derived because the card derives them, but R-MAC,
/// R-ENC and C-DECRYPTION are not implemented.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// S-ENC, the cryptogram key.
    pub enc: [u8; KEY_LEN],
    /// S-MAC, keys the C-MAC (its first 8 bytes are the DES key).
    pub mac: [u8; KEY_LEN],
    /// S-RMAC, derived but unused while R-MAC is not implemented.
    pub rmac: [u8; KEY_LEN],
    /// S-DEC, the session DEK, derived but unused while C-DECRYPTION is not
    /// implemented.
    pub dek: [u8; KEY_LEN],
}

/// Derives S-ENC, S-MAC, S-RMAC and S-DEC from the static key set and the card
/// sequence counter. The static DEK falls back to the static MAC key when the
/// operator supplied only ENC and MAC.
pub fn derive_session_keys(
    static_enc: &[u8; KEY_LEN],
    static_mac: &[u8; KEY_LEN],
    static_dek: &[u8; KEY_LEN],
    counter: u16,
) -> SessionKeys {
    SessionKeys {
        enc: derive_key(&DERIV_S_ENC, counter, static_enc),
        mac: derive_key(&DERIV_C_MAC, counter, static_mac),
        rmac: derive_key(&DERIV_R_MAC, counter, static_mac),
        dek: derive_key(&DERIV_S_DEC, counter, static_dek),
    }
}

/// 3DES CBC-MAC with a zero IV over `data`, padded with [`pad80`]: chain
/// `E_K(block XOR h)` from a zero `h` over every block and return the **last**
/// cipher block.
///
/// `Scp02SessionKeys.calc_mac_3des` in pySim returns `h` after the loop, which
/// is the final chained block, not the first. The same last-block rule is what
/// [`otacrypto::sign`] applies to its CBC-MAC.
fn cbc_mac(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; BLOCK] {
    let padded = pad80(data);
    let out = tdes3_cbc_zero_iv(key, &padded);
    out[out.len() - BLOCK..]
        .try_into()
        .expect("the last 3DES block")
}

/// The card cryptogram: 3DES CBC-MAC under **S-ENC** over
/// `host challenge || sequence counter || card challenge`.
///
/// The field order and the presence of the counter are pySim own, not the shorter
/// Card Spec form: `SCP02._compute_cryptograms` in `pySim/global_platform/scp.py`,
/// pinned by the `SCP02_Auth_Test` and `SCP02_Test` vectors in the tests below and
/// by GlobalPlatformPro `SCP02Wrapper`. [V]
pub fn card_cryptogram(
    keys: &SessionKeys,
    host_challenge: &[u8; HOST_CHALLENGE_LEN],
    card_challenge: &[u8; CARD_CHALLENGE_LEN],
    counter: u16,
) -> [u8; MAC_LEN] {
    let mut data = Vec::with_capacity(HOST_CHALLENGE_LEN + 2 + CARD_CHALLENGE_LEN);
    data.extend_from_slice(host_challenge);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(card_challenge);
    cbc_mac(&keys.enc, &data)
}

/// The host cryptogram: the same MAC over
/// `sequence counter || card challenge || host challenge`.
pub fn host_cryptogram(
    keys: &SessionKeys,
    host_challenge: &[u8; HOST_CHALLENGE_LEN],
    card_challenge: &[u8; CARD_CHALLENGE_LEN],
    counter: u16,
) -> [u8; MAC_LEN] {
    let mut data = Vec::with_capacity(2 + CARD_CHALLENGE_LEN + HOST_CHALLENGE_LEN);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(card_challenge);
    data.extend_from_slice(host_challenge);
    cbc_mac(&keys.enc, &data)
}

/// Compares two byte strings without an early exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc ^ (x ^ y)) == 0
}

/// Whether the card cryptogram proves the card holds the keys behind `keys`.
///
/// Checked **before** EXTERNAL AUTHENTICATE is sent, so wrong keys cost no
/// authentication attempt (GP Card Spec v2.3.1 11.7.4; pySim raises in
/// `SCP02.parse_init_update_resp` rather than continuing).
pub fn verify_card_cryptogram(
    keys: &SessionKeys,
    host_challenge: &[u8; HOST_CHALLENGE_LEN],
    card_challenge: &[u8; CARD_CHALLENGE_LEN],
    counter: u16,
    received: &[u8],
) -> bool {
    ct_eq(
        &card_cryptogram(keys, host_challenge, card_challenge, counter),
        received,
    )
}

// Key material must not reach logs or panic messages through Debug.
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

/// The C-MAC of GP Card Spec v2.3.1 B.1.2.2: pad the input to a multiple of 8,
/// chain single-DES encryptions of `data XOR h` under the first 8 bytes of S-MAC,
/// then `h = E(D(h))` under the last 8 bytes of S-MAC. The **transmitted** value
/// is that final `h`; the ICV for the next command is one further single DES
/// encryption of it under the first 8 bytes of S-MAC.
///
/// `Scp02SessionKeys.calc_mac_1des` in pySim, cross-read against GlobalPlatformPro
/// `SCP02Wrapper.wrap`, which advances `icv` by `des_ecb(icv, macKey)` and stores
/// the MAC that `mac_des_3des` returned. [V]
fn c_mac(s_mac: &[u8; KEY_LEN], icv: &[u8; BLOCK], data: &[u8]) -> [u8; BLOCK] {
    let mut left = [0u8; BLOCK];
    left.copy_from_slice(&s_mac[..BLOCK]);
    let mut right = [0u8; BLOCK];
    right.copy_from_slice(&s_mac[BLOCK..]);
    let padded = pad80(data);
    let mut h = *icv;
    for block in padded.chunks_exact(BLOCK) {
        let mut mixed = [0u8; BLOCK];
        for (m, (a, b)) in mixed.iter_mut().zip(h.iter().zip(block.iter())) {
            *m = a ^ b;
        }
        h = des_block(&left, &mixed, false);
    }
    h = des_block(&right, &h, true);
    des_block(&left, &h, false)
}

/// CLA with the secure messaging bit set, then INS, P1, P2, Lc counting the
/// C-MAC, then the data: the C-MAC input of B.1.2.2.
fn mac_input(header: &Header, lc: u8, data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(5 + data.len());
    input.extend_from_slice(&header.to_bytes());
    input.push(lc);
    input.extend_from_slice(data);
    input
}

/// A secure channel command-MAC state: S-MAC and the 8-byte ICV.
///
/// **Not** a value chain. The SCP02 ICV starts at zero for EXTERNAL AUTHENTICATE
/// and is advanced once per command by a single DES encryption of the C-MAC just
/// transmitted (B.1.2.2); there is no 16-byte MAC chaining value to set, as
/// SCP03 has.
#[derive(Clone)]
pub struct Channel {
    s_mac: [u8; KEY_LEN],
    icv: [u8; BLOCK],
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Channel { .. }")
    }
}

impl Channel {
    /// A fresh channel: a zero ICV, ready for the EXTERNAL AUTHENTICATE that
    /// opens it.
    pub fn new(keys: &SessionKeys) -> Self {
        Self {
            s_mac: keys.mac,
            icv: [0; BLOCK],
        }
    }

    /// The ICV the next command is MAC-ed under. Public so the dry run can
    /// report it. Not key material: it is the last transmitted C-MAC encrypted
    /// once more.
    pub const fn icv(&self) -> [u8; BLOCK] {
        self.icv
    }

    /// Adds the C-MAC to `command`: sets the secure messaging bit `04` in CLA,
    /// appends the 8-byte C-MAC to the data, keeps any Le after it and advances
    /// the ICV by one DES encryption of the transmitted MAC.
    ///
    /// MAC input (B.1.2.2, built the same way by pySim `_wrap_cmd_apdu` and
    /// GlobalPlatformPro `SCP02Wrapper.wrap`): CLA with the secure messaging bit
    /// set, then INS, P1, P2, Lc counting the C-MAC, then the data. A command
    /// that carried an Le keeps it, after the MAC; a command that did not, does
    /// not gain one. [V]
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] when the data plus the C-MAC exceeds 255 bytes.
    pub fn wrap(&mut self, command: &Command) -> Result<Command, Error> {
        let data = command.data();
        let lc = u8::try_from(data.len() + MAC_LEN).map_err(|_| Error::TooLong(data.len()))?;
        let h = command.header();
        let header = Header::new(
            h.class() | CLA_SM,
            h.instruction(),
            h.parameter_1(),
            h.parameter_2(),
        );
        let mac = c_mac(&self.s_mac, &self.icv, &mac_input(&header, lc, data));
        let mut left = [0u8; BLOCK];
        left.copy_from_slice(&self.s_mac[..BLOCK]);
        self.icv = des_block(&left, &mac, false);
        let mut body = data.to_vec();
        body.extend_from_slice(&mac);
        Ok(match command.le() {
            Some(le) => Command::case4(header, body, le),
            None => Command::case3(header, body),
        })
    }
}

/// INITIALIZE UPDATE (`80 50 <key version> 00 08 <host challenge> 00`).
///
/// `key_version` is the key version number; 0 asks the card for its first
/// available key set (`SCP02.gen_init_update_apdu`).
pub fn initialize_update(key_version: u8, host_challenge: &[u8; HOST_CHALLENGE_LEN]) -> Command {
    Command::case4(
        Header::new(0x80, INS_INITIALIZE_UPDATE, key_version, 0x00),
        host_challenge.to_vec(),
        Le::Short(0),
    )
}

/// A parsed SCP02 INITIALIZE UPDATE response (status word already stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeUpdateResponse {
    /// Key diversification data (10 bytes), unused by SCP02 and kept for the
    /// trace.
    pub diversification: [u8; 10],
    /// Key version number: the key set the card selected.
    pub key_version: u8,
    /// The card sequence counter, which feeds the key derivation *and* both
    /// cryptograms. Always present for SCP02, unlike the optional SCP03 counter.
    pub sequence_counter: u16,
    /// The card challenge, 6 bytes.
    pub card_challenge: [u8; CARD_CHALLENGE_LEN],
    /// The card cryptogram, 8 bytes.
    pub card_cryptogram: [u8; MAC_LEN],
}

impl InitializeUpdateResponse {
    /// Parses `10 diversification || kvn || 02 || counter(2) || 6 challenge ||
    /// 8 cryptogram`, 28 bytes exactly, per `SCP02.constr_iur`.
    ///
    /// # Errors
    ///
    /// [`Error::ResponseLength`] or [`Error::NotScp02`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != IUR_LEN {
            return Err(Error::ResponseLength(bytes.len()));
        }
        if bytes[11] != SCP_IDENTIFIER {
            return Err(Error::NotScp02(bytes[11]));
        }
        // Lengths were checked above, so these conversions cannot fail.
        Ok(Self {
            diversification: bytes[..10].try_into().expect("10 bytes"),
            key_version: bytes[10],
            sequence_counter: u16::from_be_bytes([bytes[12], bytes[13]]),
            card_challenge: bytes[14..20].try_into().expect("6 bytes"),
            card_cryptogram: bytes[20..28].try_into().expect("8 bytes"),
        })
    }
}

/// EXTERNAL AUTHENTICATE (`84 82 <level> 00 10 <host cryptogram> <C-MAC>`),
/// MAC-ed through `channel`, whose ICV must be the zero it starts at.
///
/// # Errors
///
/// Never in practice; mirrors [`Channel::wrap`].
pub fn external_authenticate(
    channel: &mut Channel,
    security_level: u8,
    host_cryptogram: &[u8; MAC_LEN],
) -> Result<Command, Error> {
    channel.wrap(&Command::case3(
        Header::new(0x80, INS_EXTERNAL_AUTHENTICATE, security_level, 0x00),
        host_cryptogram.to_vec(),
    ))
}

/// The release: MANAGE CHANNEL with P1 `80`, MAC-ed on `channel`.
///
/// GP Card Spec v2.3.1 11.7.1 Table 11-2 gives P1 `80` as close secure messaging
/// channel, and this repository already encodes a P1-`80` MANAGE CHANNEL the same
/// way in `session::manage_channel_close` (which puts a logical channel number in
/// P2; here P2 is `00`, the basic channel, because what is released is the secure
/// messaging channel, not a logical channel).
///
/// pySim own `release_scp` is a purely local drop of the SCP object and sends no
/// APDU, so this is the card-side half that pySim leaves to the card.
///
/// # Errors
///
/// Never in practice; mirrors [`Channel::wrap`].
pub fn release(channel: &mut Channel) -> Result<Command, Error> {
    let (p1, p2) = MANAGE_CHANNEL_RELEASE;
    channel.wrap(&Command::case1(Header::new(
        0x00,
        INS_MANAGE_CHANNEL,
        p1,
        p2,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // The pySim keyset `ck_3des_70`, defined at module scope in
    // tests/unittests/test_globalplatform.py: `GpCardKeyset(0x20, KIC, KID,
    // KIK)` over KIC 1001.., KID 1011.. and KIK 1021...
    const ENC: &str = "100102030405060708090a0b0c0d0e0f";
    const MAC: &str = "101102030405060708090a0b0c0d0e0f";
    const DEK: &str = "102102030405060708090a0b0c0d0e0f";
    const KVN: u8 = 0x20;
    // `SCP02_Auth_Test.host_challenge` and `.init_update_resp`.
    const HOST_CHALLENGE: &str = "40A62C37FA6304F8";
    const IUR: &str = "00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3";
    // `SCP02_Auth_Test.test_mutual_auth_success`, EXTERNAL AUTHENTICATE.
    const EXT_AUTH: &str = "8482010010BA6961667737C5BCEBECE14C7D6A4376";

    fn session_keys() -> (SessionKeys, InitializeUpdateResponse) {
        let iur = InitializeUpdateResponse::parse(&h::<28>(IUR)).unwrap();
        let keys = derive_session_keys(&h(ENC), &h(MAC), &h(DEK), iur.sequence_counter);
        (keys, iur)
    }

    /// Rebuilds a plain command from a hex APDU, the four cases SCP02_Test uses.
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

    // ISO/IEC 7816-4 padding method 2, as `pad80` in pySim.
    #[test]
    fn pad80_is_iso_7816_4_method_2() {
        assert_eq!(pad80(&[]), vec![0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pad80(&[1]), vec![1, 0x80, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            pad80(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            vec![1, 2, 3, 4, 5, 6, 7, 0x80]
        );
        let mut want = vec![0xABu8; 9];
        want.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pad80(&[0xAB; 9]), want);
    }

    // Replay of pySim tests/unittests/test_globalplatform.py, class
    // SCP02_Auth_Test.test_mutual_auth_success: the INITIALIZE UPDATE pySim
    // builds, the recorded 28-byte response, and the EXTERNAL AUTHENTICATE it
    // leads to at security level 01. Every byte below is pySim own: if the
    // derivation constants, the field order of either cryptogram or the B.1.2.2
    // C-MAC were wrong, this could not come out.
    #[test]
    fn replays_pysim_scp02_handshake() {
        let host = h::<8>(HOST_CHALLENGE);
        assert_eq!(
            hex::encode_upper(initialize_update(KVN, &host).encode().unwrap()),
            "805020000840A62C37FA6304F800"
        );
        let iur = InitializeUpdateResponse::parse(&h::<28>(IUR)).unwrap();
        assert_eq!(iur.key_version, 0x70);
        assert_eq!(iur.sequence_counter, 1);
        assert_eq!(iur.card_challenge, h::<6>("6B4524ABEE7C"));
        assert_eq!(iur.card_cryptogram, h::<8>("F32EA3838BC148F3"));

        let (keys, iur) = session_keys();
        assert!(verify_card_cryptogram(
            &keys,
            &host,
            &iur.card_challenge,
            iur.sequence_counter,
            &iur.card_cryptogram
        ));
        let host_cg = host_cryptogram(&keys, &host, &iur.card_challenge, iur.sequence_counter);
        // The host cryptogram is the first 8 data bytes of the pySim vector
        // `8482010010BA6961667737C5BCEBECE14C7D6A4376` (Lc is 10, then 8 bytes
        // of host cryptogram, then the 8-byte C-MAC).
        assert_eq!(hex::encode_upper(host_cg), "BA6961667737C5BC");
        // The two cryptograms are different values, not one reused.
        assert_ne!(&host_cg[..], &iur.card_cryptogram[..]);
        let mut channel = Channel::new(&keys);
        assert_eq!(channel.icv(), [0u8; 8]);
        let ext_auth = external_authenticate(&mut channel, LEVEL_C_MAC, &host_cg).unwrap();
        assert_eq!(hex::encode_upper(ext_auth.encode().unwrap()), EXT_AUTH);
    }

    // Replay of `SCP02_Auth_Test.test_mutual_auth_fail_card_cryptogram`: pySim
    // flips the last byte of the response and `parse_init_update_resp` raises,
    // so EXTERNAL AUTHENTICATE is never generated. The refusal is local and
    // costs no authentication attempt.
    #[test]
    fn refuses_a_card_cryptogram_that_does_not_verify() {
        let host = h::<8>(HOST_CHALLENGE);
        let mut wrong = h::<28>(IUR);
        wrong[27] = 0xff;
        let iur = InitializeUpdateResponse::parse(&wrong).unwrap();
        let (keys, _) = session_keys();
        assert!(!verify_card_cryptogram(
            &keys,
            &host,
            &iur.card_challenge,
            iur.sequence_counter,
            &iur.card_cryptogram
        ));
        // A card holding other keys fails the same check.
        let other = derive_session_keys(&h(ENC), &[0xFF; 16], &h(DEK), 1);
        assert!(!verify_card_cryptogram(
            &other,
            &host,
            &iur.card_challenge,
            iur.sequence_counter,
            &iur.card_cryptogram
        ));
        // The host cryptogram is not accepted in place of the card one.
        let real = InitializeUpdateResponse::parse(&h::<28>(IUR)).unwrap();
        let hcg = host_cryptogram(&keys, &host, &real.card_challenge, real.sequence_counter);
        assert!(!verify_card_cryptogram(
            &keys,
            &host,
            &real.card_challenge,
            real.sequence_counter,
            &hcg
        ));
    }

    // Replay of pySim class SCP02_Test.test_mac_command: the same ICV-chained
    // session, then four C-MAC-ed commands in send order, one per APDU case.
    // These pin the C-MAC, its input (CLA with the SM bit, Lc counting the MAC,
    // the data unpadded) and the ICV advance, which is the part SCP02 and SCP03
    // do not share.
    #[test]
    fn replays_pysim_scp02_c_mac_chain() {
        let host = h::<8>(HOST_CHALLENGE);
        let (keys, iur) = session_keys();
        let host_cg = host_cryptogram(&keys, &host, &iur.card_challenge, iur.sequence_counter);
        let mut channel = Channel::new(&keys);
        external_authenticate(&mut channel, LEVEL_C_MAC, &host_cg).unwrap();
        for (plain, wire) in [
            ("80F22002", "84F220020814DB34FA4341DCA8"),
            ("80ca006600", "84CA00660855ED7C5FF069512B00"),
            (
                "80F220020a4f0212345c054f9f70c5",
                "84F22002124F0212345C054F9F70C58FC1B380C4228AF8",
            ),
            ("80f28002024f0000", "84F280020A4F003B95F09317DE6A4E00"),
        ] {
            let wrapped = channel.wrap(&get(plain)).unwrap();
            let got = hex::encode_upper(wrapped.encode().unwrap());
            assert_eq!(got, wire, "{plain}");
        }
    }

    // No third-party release vector exists: pySim `release_scp` sends nothing at
    // all. What is checked here is the structure the Card Spec fixes: a MANAGE
    // CHANNEL with P1 80 on the basic channel, MAC-ed on the live channel (CLA
    // with the SM bit, Lc 08, an 8-byte C-MAC) and the ICV advanced past the
    // release exactly as for any other command.
    #[test]
    fn release_is_a_mac_ed_manage_channel_80() {
        let host = h::<8>(HOST_CHALLENGE);
        let (keys, iur) = session_keys();
        let host_cg = host_cryptogram(&keys, &host, &iur.card_challenge, iur.sequence_counter);
        let mut channel = Channel::new(&keys);
        external_authenticate(&mut channel, LEVEL_C_MAC, &host_cg).unwrap();
        let before = channel.icv();
        let rel = release(&mut channel).unwrap();
        let wire = rel.encode().unwrap();
        assert_eq!(wire.len(), 5 + MAC_LEN);
        // CLA 00 with the secure messaging bit set.
        assert_eq!(wire[0], CLA_SM);
        assert_eq!(wire[1], INS_MANAGE_CHANNEL);
        assert_eq!((wire[2], wire[3]), MANAGE_CHANNEL_RELEASE);
        assert_eq!(wire[4], MAC_LEN as u8);
        assert_ne!(channel.icv(), before);
        let again = release(&mut channel).unwrap();
        assert_ne!(hex::encode(again.encode().unwrap()), hex::encode(wire));
    }

    #[test]
    fn parse_initialize_update_response() {
        let mut long = h::<28>(IUR).to_vec();
        long.push(0x00);
        assert_eq!(
            InitializeUpdateResponse::parse(&long),
            Err(Error::ResponseLength(29))
        );
        let mut r = h::<28>(IUR);
        r[11] = 0x03;
        assert_eq!(InitializeUpdateResponse::parse(&r), Err(Error::NotScp02(3)));
    }

    // `SCP02.kvn_ranges` in pySim, and the key version the pysim vectors use:
    // the card answered 70, a sysmoISIM-SJA2 special case outside 20..2F.
    #[test]
    fn key_version_ranges_match_pysim() {
        assert!(kvn_allowed(0x00));
        assert!(kvn_allowed(0x01));
        assert!(!kvn_allowed(0x02));
        assert!(kvn_allowed(0x20));
        assert!(kvn_allowed(0x2f));
        assert!(!kvn_allowed(0x30));
        assert!(kvn_allowed(0x70));
        assert!(!kvn_allowed(0x71));
    }

    #[test]
    fn wrap_rejects_oversize_data() {
        let (keys, _) = session_keys();
        let big = Command::case3(Header::new(0x80, 0xE2, 0, 0), vec![1u8; 248]);
        assert_eq!(Channel::new(&keys).wrap(&big), Err(Error::TooLong(248)));
    }
}
