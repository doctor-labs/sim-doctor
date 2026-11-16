//! SGP.22 activation code parsing (`LPA:1$...`) and confirmation-code hints.
//!
//! A profile download is started from an activation code the operator hands to
//! the LPA (SGP.22 v2.5, the "Activation Code" carried by the `MatchingID`
//! event; the format is `LPA:1$<SMDP+ address>$<AC token / matching ID>` and,
//! in practice, an optional fourth `$1` field marks a confirmation code as
//! required for the download).
//!
//! **Owns.** Parsing and validating that string into the parts a download needs:
//! the SM-DP+ address, the matching ID (the AC token), and whether a
//! confirmation code is required. Nothing here opens a socket or talks to a
//! card.
//!
//! **Does not own.** ES11 discovery, the confirmation code value itself, or the
//! download. The SM-DP+ address is validated as an FQDN by
//! [`crate::es9::SmdpAddress`].

use crate::es9::{self, SmdpAddress};

/// This module's name.
pub const NAME: &str = "activation";

/// A parsed activation code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCode {
    /// The SM-DP+ address (FQDN) the profile is downloaded from.
    pub smdp: SmdpAddress,
    /// The matching ID / AC token.
    pub matching_id: String,
    /// True when the activation code marks a confirmation code as required.
    /// A download that needs one and does not supply it is refused by the
    /// eUICC/SM-DP+ (see `profile_download`'s note on hashCc).
    pub confirmation_code_required: bool,
}

/// Why an activation code string cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not an `LPA:1$...` activation code.
    #[error("activation code must start with LPA:1$")]
    NotLpa,
    /// Wrong number of `$`-separated fields.
    #[error("activation code must be LPA:1$<smdp>$<matching-id>[$<cc-required>[$<oid>]]")]
    Shape,
    /// The SM-DP+ address is not a valid FQDN.
    #[error("SM-DP+ address: {0}")]
    Smdp(String),
    /// The matching ID is empty.
    #[error("activation code matching ID is empty")]
    EmptyMatchingId,
}

impl ActivationCode {
    /// Parse `LPA:1$<smdp>$<matchingId>[$cc[$oid]]`.
    ///
    /// The confirmation-code-required flag is read from the fourth field when
    /// present: `1` (or `required`/`cc-required` in tolerant form) means
    /// required, anything else means not required. A trailing OID field, if
    /// present, is accepted and ignored here.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        let body = text.strip_prefix("LPA:1$").ok_or(Error::NotLpa)?;
        let parts: Vec<&str> = body.split('$').collect();
        if parts.len() < 2 || parts.len() > 4 {
            return Err(Error::Shape);
        }
        let smdp = SmdpAddress::parse(parts[0]).map_err(|e: es9::Error| Error::Smdp(e.to_string()))?;
        let matching_id = parts[1].trim().to_string();
        if matching_id.is_empty() {
            return Err(Error::EmptyMatchingId);
        }
        let confirmation_code_required = parts
            .get(2)
            .map(|f| {
                let f = f.trim();
                f == "1" || f.eq_ignore_ascii_case("required") || f.eq_ignore_ascii_case("cc-required")
            })
            .unwrap_or(false);
        Ok(Self {
            smdp,
            matching_id,
            confirmation_code_required,
        })
    }

    /// A stable JSON form for reports.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "smdp_address": self.smdp.as_str(),
            "matching_id": self.matching_id,
            "confirmation_code_required": self.confirmation_code_required,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_activation_code() {
        let ac = ActivationCode::parse("LPA:1$smdp.example.com$MATCH-123").unwrap();
        assert_eq!(ac.smdp.as_str(), "smdp.example.com");
        assert_eq!(ac.matching_id, "MATCH-123");
        assert!(!ac.confirmation_code_required);
    }

    #[test]
    fn parses_confirmation_code_required_flag() {
        let ac = ActivationCode::parse("LPA:1$smdp.example.com$MATCH-123$1").unwrap();
        assert!(ac.confirmation_code_required);
        let ac = ActivationCode::parse("LPA:1$smdp.example.com$MATCH-123$1$1.3.6.1.4.1").unwrap();
        assert!(ac.confirmation_code_required);
    }

    #[test]
    fn rejects_non_lpa() {
        assert!(matches!(ActivationCode::parse("foo$bar$baz"), Err(Error::NotLpa)));
    }
}
