//! Named GlobalPlatform card profiles: `sim-doctor gp --profile <NAME>` (also
//! `-P`), issue #238.
//!
//! **What a profile is.** A profile is a local configuration choice: it names
//! the three places where GlobalPlatform cards of a given generation disagree
//! on the wire, so an operator can say which kind of card is in the reader
//! instead of the tool guessing. It is never read from the card and it never
//! changes what is *written*: selecting a profile does not send a single byte
//! that the default profile would not.
//!
//! **The reference.** GlobalPlatformPro (martinpaljak/GlobalPlatformPro,
//! branch `next`, LGPL-3.0-or-later), `GPCardProfile.java`. It is a 60-line
//! class holding two named profiles in an unmodifiable map and three
//! accessors. Read and cited, never copied: no code, table or comment from
//! that file is reproduced here.
//!
//! | Field here | Reference | Reference line |
//! |---|---|---|
//! | `status_uses_tags` | `getStatusUsesTags()` | `GPCardProfile.java:37-39`, set at `:15-16` |
//! | `reports_modules` | `doesReportModules()` | `GPCardProfile.java:41-43`, set at `:15-16` |
//! | `old_style_ssd_parameters` | `oldStyleSSDParameters()` | `GPCardProfile.java:45-47`, set at `:15-16` |
//!
//! **What each switch means on the wire**, from the reference's own use of them:
//!
//! - `status_uses_tags` picks the GET STATUS P2 coding. `true` sends P2 `02`,
//!   the TLV ("tagged") response, `false` sends P2 `00`; the "more data"
//!   follow-up is `P2 | 01`, so `03` or `01`
//!   ([V] `GPSession.java:1044` and `:1086`). This repository always sent
//!   `02`/`03` before, so `default` is exactly the pre-existing behaviour and
//!   only `old` changes it.
//! - `reports_modules` decides whether the load-files-**and-executable-modules**
//!   scope is asked for at all: the reference queries P1 `10` only when the
//!   profile reports modules, and otherwise reads load files with P1 `20`
//!   alone ([V] `GPSession.java:1105-1112`). This repository always read all
//!   four scopes of [`crate::gp::STATUS_SCOPES`]; `old` drops the `10` scope.
//! - `old_style_ssd_parameters` chooses how Security Domain personalisation
//!   parameters are built: the legacy single-template `C9 45` form instead of
//!   the amended TLV tree ([V] `GPTool.java:705` and `:738`). **sim-doctor has
//!   no consumer for this switch** - see
//!   [`CardProfile::old_style_ssd_parameters`] - so it is defined, reported and
//!   never acted on.
//!
//! **The CLI spelling** is GlobalPlatformPro's own: one option accepting both
//! a short and a long name, "Use pre-defined profile", with a required argument
//! ([V] `GPCommandLineInterfaceNG.java:238`).
//!
//! **Not ported: `fromCPLC`.** The reference has a `fromCPLC(byte[])` that
//! ignores its argument and always answers with the default profile
//! ([V] `GPCardProfile.java:53-55`): it is a stub there, not an
//! implementation. sim-doctor does not guess a profile from the CPLC, and this
//! module has no such function, so there is nothing to port and nothing to
//! mislead a reader into thinking auto-detection exists.

use serde_json::{json, Value};

/// One named set of per-card GlobalPlatform conventions.
///
/// Every field is a *local* choice about how to ask a card a question. None of
/// them is read back from the card, and none of them sends a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardProfile {
    /// The name `--profile` takes, and the name reported back in the envelope.
    pub name: &'static str,

    /// GET STATUS asks for the TLV response (P2 `02`) rather than the legacy
    /// non-tagged coding (P2 `00`).
    ///
    /// Consumed by `gp status`: see [`CardProfile::status_p2`].
    pub status_uses_tags: bool,

    /// The load-files-and-executable-modules scope (P1 `10`) is queried, so
    /// the registry lists the modules inside each load file.
    ///
    /// Consumed by `gp status`: see [`CardProfile::reads_module_scope`].
    pub reports_modules: bool,

    /// Security Domain personalisation parameters are built in the legacy
    /// single-template form rather than the amended TLV tree.
    ///
    /// **No consumer in sim-doctor yet.** The only Install Parameters this
    /// repository builds are the operator's own `--params` bytes on
    /// `gp install` (the mandatory `C9` tag), and it has no
    /// extradition-rule (`0x82`/`0x87`) or SCP-template (`0x81`) amendment for
    /// a profile to choose between - those flags do not exist here. The switch
    /// is therefore defined, reported in the envelope and otherwise inert.
    /// Inventing a personalisation command to consume it would be new scope,
    /// so it is reported instead.
    pub old_style_ssd_parameters: bool,
}

impl CardProfile {
    /// GET STATUS P2 for the first page and for the `63 10` "more data"
    /// follow-up.
    ///
    /// `(02, 03)` with the TLV coding, `(00, 01)` without: the reference
    /// follows up with `P2 | 01` [V] `GPSession.java:1086`.
    #[must_use]
    pub const fn status_p2(&self) -> (u8, u8) {
        if self.status_uses_tags {
            (0x02, 0x03)
        } else {
            (0x00, 0x01)
        }
    }

    /// Whether the load-files-and-executable-modules GET STATUS scope (P1
    /// `10`) belongs in this run's registry read.
    ///
    /// The reference asks for it only when the profile reports modules [V]
    /// `GPSession.java:1105-1112`.
    #[must_use]
    pub const fn reads_module_scope(&self) -> bool {
        self.reports_modules
    }
}

impl Default for CardProfile {
    /// The profile in force when `--profile` is not given.
    fn default() -> Self {
        DEFAULT
    }
}

/// The profile table, in the order `--profile` and its refusal message list
/// the names.
///
/// `default` and `old` with the three switch values of the reference's two
/// profile objects ([V] `GPCardProfile.java:15-16`, registered at `:22-23`).
pub const PROFILES: [CardProfile; 2] = [
    CardProfile {
        name: "default",
        status_uses_tags: true,
        reports_modules: true,
        old_style_ssd_parameters: false,
    },
    CardProfile {
        name: "old",
        status_uses_tags: false,
        reports_modules: false,
        old_style_ssd_parameters: true,
    },
];

/// The profile every `gp` command uses when `--profile` is not given.
///
/// Its switches are the ones this repository used unconditionally before
/// issue #238, so omitting the flag changes nothing.
pub const DEFAULT: CardProfile = PROFILES[0];

/// The profile named `name`, or `None` if there is no such profile.
#[must_use]
pub fn from_name(name: &str) -> Option<CardProfile> {
    PROFILES.iter().copied().find(|p| p.name == name)
}

/// The known profile names, comma separated, for the refusal message.
#[must_use]
pub fn names() -> String {
    PROFILES
        .iter()
        .map(|p| p.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The profile as it is reported in a `gp` envelope, under `data.profile`.
///
/// `is_default` says whether this is the profile that would have been used
/// anyway, so a reader can tell "no flag" from "the default profile asked
/// for by name".
#[must_use]
pub fn to_json(profile: &CardProfile) -> Value {
    json!({
        "name": profile.name,
        "is_default": *profile == DEFAULT,
        "status_uses_tags": profile.status_uses_tags,
        "reports_modules": profile.reports_modules,
        "old_style_ssd_parameters": profile.old_style_ssd_parameters,
    })
}

/// The profile as the human report states it, read from the `data.profile`
/// block [`to_json`] writes.
///
/// Takes the block rather than a [`CardProfile`] so there is one renderer and
/// the envelope and the terminal line cannot drift apart. A switch that is
/// missing or not a boolean prints `no`: a line either states a whole profile
/// or is not printed at all.
#[must_use]
pub fn render_text(profile: &Value) -> String {
    let switch = |key: &str| {
        if profile[key].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        }
    };
    let name = profile["name"].as_str().unwrap_or(DEFAULT.name);
    format!(
        "Profile: {name} (GET STATUS tags: {}, module listing: {}, old-style SSD parameters: {})",
        switch("status_uses_tags"),
        switch("reports_modules"),
        switch("old_style_ssd_parameters"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is the issue: both profiles, all three fields, against
    /// GPCardProfile.java:15-16 (the two profile objects) and :22-23 (their
    /// names). Each field is written out here rather than derived, so a change
    /// to the table cannot quietly follow a change to the test.
    #[test]
    fn the_table_is_the_two_named_profiles_of_the_reference() {
        assert_eq!(PROFILES.len(), 2);
        assert_eq!(
            PROFILES[0],
            CardProfile {
                name: "default",
                status_uses_tags: true,
                reports_modules: true,
                old_style_ssd_parameters: false,
            }
        );
        assert_eq!(
            PROFILES[1],
            CardProfile {
                name: "old",
                status_uses_tags: false,
                reports_modules: false,
                old_style_ssd_parameters: true,
            }
        );
        // MODERN is the default profile there (GPCardProfile.java:49-51).
        assert_eq!(DEFAULT, PROFILES[0]);
        assert_eq!(CardProfile::default(), DEFAULT);
    }

    #[test]
    fn a_profile_is_found_by_name_and_an_unknown_one_is_not() {
        assert_eq!(from_name("default"), Some(DEFAULT));
        assert_eq!(from_name("old"), Some(PROFILES[1]));
        assert_eq!(from_name("Default"), None, "the name is exact");
        assert_eq!(from_name("modern"), None);
        assert_eq!(from_name(""), None);
        assert_eq!(from_name("old "), None);
        assert_eq!(names(), "default, old");
    }

    #[test]
    fn the_default_profile_reproduces_what_the_tool_did_before_the_flag() {
        // P2 02 then 03, and the P1 10 scope read: the unconditional coding
        // this repository used before issue #238.
        assert_eq!(DEFAULT.status_p2(), (0x02, 0x03));
        assert!(DEFAULT.reads_module_scope());
    }

    #[test]
    fn the_old_profile_asks_get_status_without_tags_and_skips_the_module_scope() {
        // GPSession.java:1044 (`p2 = useTags ? 0x02 : 0x00`) and :1086
        // (`p2 | 0x01`); :1105-1112 for the scope.
        let old = PROFILES[1];
        assert_eq!(old.status_p2(), (0x00, 0x01));
        assert!(!old.reads_module_scope());
        assert!(old.old_style_ssd_parameters);
    }

    #[test]
    fn the_json_names_the_profile_and_says_whether_it_would_have_been_used() {
        let default = to_json(&DEFAULT);
        assert_eq!(default["name"], json!("default"));
        assert_eq!(default["is_default"], json!(true));
        assert_eq!(default["status_uses_tags"], json!(true));
        assert_eq!(default["reports_modules"], json!(true));
        assert_eq!(default["old_style_ssd_parameters"], json!(false));

        // The same profile asked for by name is not a different card view,
        // but it is a flag the operator gave.
        assert_eq!(to_json(&from_name("default").unwrap()), default);

        let old = to_json(&PROFILES[1]);
        assert_eq!(old["name"], json!("old"));
        assert_eq!(old["is_default"], json!(false));
        assert_eq!(old["status_uses_tags"], json!(false));
        assert_eq!(old["reports_modules"], json!(false));
        assert_eq!(old["old_style_ssd_parameters"], json!(true));
    }

    #[test]
    fn the_human_line_states_the_name_and_all_three_switches() {
        let line = render_text(&to_json(&DEFAULT));
        assert!(line.starts_with("Profile: default"), "{line}");
        assert!(line.contains("GET STATUS tags: yes"), "{line}");
        assert!(line.contains("module listing: yes"), "{line}");
        assert!(line.contains("old-style SSD parameters: no"), "{line}");

        let old = render_text(&to_json(&PROFILES[1]));
        assert!(old.starts_with("Profile: old"), "{old}");
        assert!(old.contains("GET STATUS tags: no"), "{old}");
        assert!(old.contains("module listing: no"), "{old}");
        assert!(old.contains("old-style SSD parameters: yes"), "{old}");
    }
}
