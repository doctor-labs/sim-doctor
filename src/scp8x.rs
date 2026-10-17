//! GlobalPlatform Secure Channel Protocols "80" and "81": the identifiers, the
//! SCP Information and key-type bytes the card spec names for them, and the
//! refusal to open either channel. Library only: nothing here sends a byte.
//!
//! **Owns.** The identifiers ([`Scheme`]), the SCP Information tags for SCP81 and
//! the key type coding for a pre-shared TLS key (constants), and the reason each
//! scheme is refused ([`Scheme::refusal`]).
//!
//! **Does not own.** Any wire protocol. The card spec gives only the names:
//! SCP80 is "defined in [TS 102 225] and [TS 102 226]" and SCP81 is "defined in
//! [Amd B] based on HTTP and Pre-Shared Key TLS" (GPC Card Spec v2.3.1 10.7,
//! lines 6781-6782). Neither ETSI TS nor Amendment B is in the reference set, and
//! the tree has no TLS-PSK or HTTP stack. SCP81 is not SCP03 plus a certificate
//! chain: the card spec describes it as HTTP over pre-shared-key TLS.

/// Secure Channel Protocol identifier of SCP80 (GPC Card Spec v2.3.1 10.7, line 6781).
pub const SCP80: u8 = 0x80;
/// Secure Channel Protocol identifier of SCP81 (GPC Card Spec v2.3.1 10.7, line 6782).
pub const SCP81: u8 = 0x81;
/// SCP Information tag "SCP type" (GPC Card Spec v2.3.1 Table H-6, line 16689).
pub const TAG_SCP_TYPE: u8 = 0x80;
/// SCP Information tag "Supported TLS cipher suites for SCP81" (Table H-6, line 16692).
pub const TAG_TLS_CIPHER_SUITES: u8 = 0x83;
/// SCP Information tag "Maximum length of Pre Shared Key in bytes" (Table H-6, line 16693).
pub const TAG_MAX_PSK_LEN: u8 = 0x84;
/// Key type "Pre-Shared Key for Transport Layer Security" (Table 11-16, line 7303).
pub const KEY_TYPE_PSK_TLS: u8 = 0x85;

/// The two schemes this module names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Secure Channel Protocol "80", the ETSI OTA scheme.
    Scp80,
    /// Secure Channel Protocol "81", HTTP over pre-shared-key TLS.
    Scp81,
}

impl Scheme {
    /// The scheme for a Secure Channel Protocol identifier, or None for any other byte.
    pub fn from_identifier(id: u8) -> Option<Self> {
        match id {
            SCP80 => Some(Self::Scp80),
            SCP81 => Some(Self::Scp81),
            _ => None,
        }
    }

    /// The identifier byte of this scheme.
    pub fn identifier(self) -> u8 {
        match self {
            Self::Scp80 => SCP80,
            Self::Scp81 => SCP81,
        }
    }

    /// Why this scheme is refused, naming the reference that defines it.
    pub fn refusal(self) -> &'static str {
        match self {
            Self::Scp80 => "SCP80 is defined in ETSI TS 102 225 and TS 102 226 (GPC Card Spec 2.3.1 10.7); neither is in the reference set, so the wire protocol is refused",
            Self::Scp81 => "SCP81 is defined in GlobalPlatform Amendment B (RAM over HTTP, GPC Card Spec 2.3.1 10.7) and needs pre-shared-key TLS; Amendment B is not in the reference set and this tree has no TLS-PSK or HTTP stack, so the channel is refused",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_match_card_spec_10_7() {
        assert_eq!(Scheme::from_identifier(0x80), Some(Scheme::Scp80));
        assert_eq!(Scheme::from_identifier(0x81), Some(Scheme::Scp81));
        assert_eq!(Scheme::Scp80.identifier(), 0x80);
        assert_eq!(Scheme::Scp81.identifier(), 0x81);
        for id in [0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x82, 0xEF, 0xF0] {
            assert_eq!(Scheme::from_identifier(id), None, "identifier {id:02X}");
        }
    }

    #[test]
    fn tags_and_key_type_match_tables() {
        assert_eq!(TAG_SCP_TYPE, 0x80);
        assert_eq!(TAG_TLS_CIPHER_SUITES, 0x83);
        assert_eq!(TAG_MAX_PSK_LEN, 0x84);
        assert_eq!(KEY_TYPE_PSK_TLS, 0x85);
    }

    #[test]
    fn both_schemes_are_refused_and_name_their_missing_reference() {
        assert!(Scheme::Scp80.refusal().contains("TS 102 225"));
        assert!(Scheme::Scp81.refusal().contains("Amendment B"));
        assert!(Scheme::Scp81.refusal().contains("pre-shared-key TLS"));
    }
}
