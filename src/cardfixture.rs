//! A database of known card profiles, and the versioned fixture format that carries them.
//!
//! **Owns.** The card-profile table ([`PROFILES`]): ten profiles of real, purchasable
//! JavaCard/GlobalPlatform cards, every stated field pinned to the line of
//! GlobalPlatformPro's `docs/TestedCards/README.md` that states it. The card-profile
//! *field schema* ([`PROFILE_FIELDS`]) as pySim defines it, one field per line of
//! `pySim/profile.py`. The [`FORMAT`] document: its shape, the loader
//! ([`Fixture::parse`]) that refuses anything it cannot read exactly, and the
//! generator ([`CardProfile::render`]) that writes a profile into it. Issue #286.
//!
//! **Does not own.** Card *simulator classes*. That table is issue #275's
//! `cardprofile` module, built from `pySim/legacy/cards.py` (FakeMagicSim, MagicSim,
//! SuperSim, sysmoUSIM-SJS1, ...): fourteen simulator classes with ATR-based
//! autodetection. **Nothing here repeats it.** The two tables are disjoint by
//! construction and two tests hold them apart:
//! `every_listing_provenance_names_tested_cards` (this table is TestCards-only) and
//! `every_schema_field_names_pysim_profile_py` (the schema is profile.py-only).
//! The rows here are *bought cards* with the JavaCard and GlobalPlatform versions the
//! seller prints, which is a fact no simulator class can supply.
//!
//! **What this is not.** A list of SIMs' contents, and not a comparison. The TS.48
//! corpus (`tests/corpus/ts48/`, [`crate::ts48`]) answers a different question: it is
//! the *file list* of a public GSMA eUICC test profile, and `ts48 compare` diffs a
//! walked tree against it. **This module holds no file list, no file identifier, no
//! size and no layout** - it holds no fact about a card's filesystem, so it cannot
//! answer "does this card match TS.48", and the two never have to be kept in step.
//! What it adds is the *other* axis: which card an operator is holding, when a
//! finding says something odd. A `9x xx` from a card whose seller prints
//! "GlobalPlatform 2.0.1" and a card claiming 2.2.1 are different research problems,
//! and until now this crate had no place to say which is which.
//!
//! **Why a format and a generator rather than card images.** The references ship no
//! card images: pySim *synthesises* its cards and GlobalPlatformPro's TestedCards is
//! prose with URLs. Committing blobs would mean inventing bytes no source contains.
//! So the committed artefact is the **format**, the **generator** and the derived
//! **table**, all text: `sim-doctor cards fixture <NAME>` writes any profile's
//! document, and it is byte-identical every time
//! (`rendering_is_deterministic`, `a_generated_fixture_reparses_to_the_same_profile`).
//! **No binary blob is committed by this issue.** A card image that a reader wants
//! is built from a profile through a card-writing session, never checked in.
//!
//! **Provenance is the point, so it is a type.** [`Provenance`] is a source file, a
//! 1-based line and a sentence saying what that line asserts; it is not an optional
//! comment. Every profile carries the three support criteria the reference lists
//! ([`SUPPORT_CRITERIA`]) plus its own listing line, every note carries its line, and
//! [`Fixture::parse`] **refuses** a document whose provenance is empty
//! ([`FixtureError::NoProvenance`]) or whose line is 0
//! ([`FixtureError::BadProvenanceLine`]). A fixture that cannot say where it came from
//! is not evidence.
//!
//! **Priced and dated data decays.** Prices and shop URLs are copied verbatim from the
//! reference (`12€`, `£14.00`, and the URLs as written) and every generated document
//! carries [`READ_ON`], the date the reference was read, as a required field. A stale
//! price is dated data, not a live quote.
//!
//! **References.** `martinpaljak/GlobalPlatformPro`, branch `next`,
//! `docs/TestedCards/README.md` (LGPL-3.0); `osmocom/pysim`, branch `master`,
//! `pySim/profile.py` (GPL). Both read 2026-10-16. **No code is copied from either**:
//! the facts (names, versions, prices, URLs) are quoted and line-pinned, and every
//! line of Rust here is this crate's own.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "cardfixture";

/// The envelope `type` of `sim-doctor cards`.
pub const KIND: &str = "cards";

/// The one fixture format this build reads and writes.
///
/// The version is in the string on purpose: a fixture that says `.../2` is refused by
/// name ([`FixtureError::UnknownFormat`]), never read as if it were this one.
pub const FORMAT: &str = "sim-doctor/card-fixture/1";

/// The date both references were read. Every generated fixture carries it.
pub const READ_ON: &str = "2026-10-16";

/// The card table's reference, repository-relative.
pub const TESTED_CARDS: &str = "martinpaljak/GlobalPlatformPro docs/TestedCards/README.md";

/// The field schema's reference, repository-relative.
pub const PYSIM_PROFILE: &str = "osmocom/pysim pySim/profile.py";

/// The branch each reference was read at.
pub const REF_BRANCHES: &str = "GlobalPlatformPro: next; pysim: master";

/// `docs/TestedCards/README.md:42`: where the reference sends a reader for more cards.
pub const MORE_INFO: &str = "http://www.fi.muni.cz/~xsvenda/jcsupport.html";

use serde::{Deserialize, Serialize};

/// One note the reference attaches to a card, and the line that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Note {
    /// The reference's own words, minus the list bullet.
    pub text: &'static str,
    /// The 1-based line of `docs/TestedCards/README.md` that carries it.
    pub line: u32,
}

/// Where one fact came from: the file, the line in it, and what that line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Provenance<'a> {
    /// `repo path` of the reference, as [`TESTED_CARDS`] or [`PYSIM_PROFILE`].
    pub source: &'a str,
    /// 1-based line number in that file. Zero is refused, never rendered.
    pub line: u32,
    /// What that line asserts, in this crate's words.
    pub asserts: &'a str,
}

/// A provenance record read back out of a fixture document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// `repo path` of the reference.
    pub source: String,
    /// 1-based line number in that file.
    pub line: u32,
    /// What that line asserts.
    pub asserts: String,
}

impl ProvenanceRecord {
    /// The owned copy of a compiled-in record.
    pub fn from_claim(claim: &Provenance<'_>) -> Self {
        Self {
            source: claim.source.to_owned(),
            line: claim.line,
            asserts: claim.asserts.to_owned(),
        }
    }
}

/// Which of the reference's two headings an entry is listed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Listing {
    /// `docs/TestedCards/README.md:10`, "Supported cards (with a confirmed shop link,
    /// in no particular order)". Every one of these has a link the reference prints.
    Supported,
    /// `docs/TestedCards/README.md:34`, "Tested cards without a confirmed shop link".
    TestedWithoutShopLink,
}

impl Listing {
    /// The heading line this variant is read from.
    pub const fn heading_line(self) -> u32 {
        match self {
            Listing::Supported => 10,
            Listing::TestedWithoutShopLink => 34,
        }
    }
}

/// One card in the table.
///
/// A field is `None` **only** where the reference does not state it. The two Feitian
/// entries have no stated JavaCard version even though their shop slug contains a
/// capacity, and JCOP J3D081's "40" is a price, not 40K; neither is filled in, and
/// `versions_are_stated_only_where_the_reference_states_them` holds that line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CardProfile {
    /// Stable lower-case name, the one an operator types.
    pub name: &'static str,
    /// The product name as the reference writes it.
    pub title: &'static str,
    /// The vendor or product line, from the reference's own heading or product name.
    pub vendor: &'static str,
    /// Which of the reference's two headings this is listed under.
    pub listing: Listing,
    /// The `JavaCard x.y.z` the reference prints, if it prints one.
    pub javacard: Option<&'static str>,
    /// The `GlobalPlatform x.y` the reference prints, if it prints one.
    pub globalplatform: Option<&'static str>,
    /// The stated EEPROM size, if the reference states one.
    pub memory: Option<&'static str>,
    /// The stated price, verbatim in the reference's own currency spelling.
    pub price: Option<&'static str>,
    /// The URL the reference prints, if it prints one.
    pub shop: Option<&'static str>,
    /// Notes the reference attaches, each with the line that carries it.
    pub notes: &'static [Note],
}

impl CardProfile {
    /// The line of the reference this profile is listed on.
    ///
    /// It lives in [`ENTRY_LINES`] beside the table rather than in the row, so the
    /// renderer, the fixture document and the tests all read one number: a row that
    /// could disagree with its own line number is a silent way to cite the wrong line.
    /// A name with no line is 0, and 0 is refused everywhere it is read back.
    pub fn entry_line(&self) -> u32 {
        ENTRY_LINES
            .iter()
            .find(|(name, _)| *name == self.name)
            .map_or(0, |(_, line)| *line)
    }

    /// Every provenance record this entry carries: the reference's three support
    /// criteria, then the line this card is listed on.
    pub fn provenance(&self) -> Vec<Provenance<'static>> {
        let mut all: Vec<Provenance<'static>> = SUPPORT_CRITERIA.to_vec();
        all.push(Provenance {
            source: TESTED_CARDS,
            line: self.entry_line(),
            asserts: "the line this card profile, its JavaCard and GlobalPlatform versions, its price and its link are read from",
        });
        all
    }
}

/// Every profile's listing line, so [`CardProfile::entry_line`] needs no field for it.
///
/// Kept beside the table rather than inside it because a `const fn` cannot loop over
/// `self`, and a second table that could disagree with the first would be worse than
/// one that cannot.
const ENTRY_LINES: &[(&str, u32)] = &[
    ("smartcafe-expert-3-2-72k", 11),
    ("jcop-j3d081-v2-4-2", 17),
    ("jcop-nxp-j3a080-dual-interface", 23),
    ("gemalto-top-im-gx4", 26),
    ("gemalto-idcore-3010-cc", 29),
    ("feitian-javacos-a40", 31),
    ("feitian-javacos-a22", 32),
    ("oberthur-cosmo-v7-128k", 35),
    ("athena-idprotect", 36),
    ("gemalto-top-im-fips-cy2", 39),
];

/// `docs/TestedCards/README.md:2-4`: the reference's own definition of "supported".
///
/// Every profile carries all three, because the heading an entry sits under claims all
/// three of them at once. An entry whose line does not satisfy one of them is the
/// reference's error to report, not this table's to smooth over.
pub const SUPPORT_CRITERIA: [Provenance<'static>; 3] = [
    Provenance {
        source: TESTED_CARDS,
        line: 2,
        asserts: "listed as supported if and only if it is available from some verified webshop, in small quantities",
    },
    Provenance {
        source: TESTED_CARDS,
        line: 3,
        asserts: "listed as supported if and only if it comes with default keys or otherwise known keys and OP_READY state",
    },
    Provenance {
        source: TESTED_CARDS,
        line: 4,
        asserts: "listed as supported if and only if it has been verified as working for at least a load-install-lock-uninstall-unlock cycle",
    },
];

/// The card table: ten profiles of cards a reader can actually buy.
///
/// Read from [`TESTED_CARDS`] on [`READ_ON`]. Every field is either the reference's
/// own text or absent; nothing is filled in from a datasheet, a guess or a sibling
/// entry. `versions_are_stated_only_where_the_reference_states_them` is the test
/// that holds it.
pub const PROFILES: &[CardProfile] = &[
    CardProfile {
        name: "smartcafe-expert-3-2-72k",
        title: "SmartCafe Expert 3.2 72K",
        vendor: "SmartCafe",
        listing: Listing::Supported,
        javacard: Some("2.2.1"),
        globalplatform: Some("2.1.1"),
        memory: Some("72K"),
        price: Some("12\u{e9}"),
        shop: Some(
            "http://www.smartcardfocus.com/shop/ilp/id~521/SmartCafe_Expert_3_2_72K/p/index.shtml",
        ),
        notes: &[
            Note {
                text: "Virgin cards require unlocking with \"-emv\"",
                line: 12,
            },
            Note {
                text: "the reference lists other products with the same name but different EEPROM and connectivity",
                line: 13,
            },
            Note {
                text: "http://www.smartcardfocus.com/shop/ilp/id~684/smartcafe-expert-6-0-80k-dual-/p/index.shtml",
                line: 14,
            },
            Note {
                text: "http://www.smartcardfocus.com/shop/ilp/id~521/smartcafe-expert-3-2-72k/p/index.shtml",
                line: 15,
            },
            Note {
                text: "http://www.smartcardfocus.com/shop/ilp/id~523/smartcafe-expert-3-2-144k-dual/p/index.shtml",
                line: 16,
            },
        ],
    },
    CardProfile {
        name: "jcop-j3d081-v2-4-2",
        title: "JCOP J3D081 v2.4.2",
        vendor: "JCOP",
        listing: Listing::Supported,
        javacard: Some("3.0.1"),
        globalplatform: Some("2.2"),
        memory: None,
        price: Some("40\u{e9}"),
        shop: Some("http://www.motechno.com/javacard3.0.html"),
        notes: &[
            Note {
                text: "the reference lists other products with the same JavaCard and GlobalPlatform versions",
                line: 18,
            },
            Note {
                text: "http://www.cryptoshop.com/products/smartcards/jcop-31-v2-4-1-72k.html",
                line: 19,
            },
            Note {
                text: "http://www.cryptoshop.com/products/smartcards/j2a081-v2-4-1-jcop-21.html",
                line: 20,
            },
            Note {
                text: "http://www.smartcardfocus.com/shop/ilp/id~685/j3a041-40k/p/index.shtml",
                line: 21,
            },
            Note {
                text: "http://www.smartcardfocus.com/shop/ilp/id~688/j3d081-80k/p/index.shtml",
                line: 22,
            },
            Note {
                text: "the 40 on this line is the price in euro; no EEPROM size is stated here",
                line: 17,
            },
        ],
    },
    CardProfile {
        name: "jcop-nxp-j3a080-dual-interface",
        title: "JCOP v2.4.1 NXP J3A080 Dual Interface Card (10 pcs.)",
        vendor: "JCOP",
        listing: Listing::Supported,
        javacard: None,
        globalplatform: None,
        memory: None,
        price: Some("110\u{e9}"),
        shop: Some("https://www.united-access.com/javacard"),
        notes: &[
            Note {
                text: "the title's v2.4.1 is the JCOP product revision, not a JavaCard version; this line states no JavaCard and no GlobalPlatform version",
                line: 23,
            },
        ],
    },
    CardProfile {
        name: "gemalto-top-im-gx4",
        title: "GEMALTO IDCORE 10 - GEMALTO TOP IM GX4",
        vendor: "Gemalto",
        listing: Listing::Supported,
        javacard: Some("2.2.1"),
        globalplatform: Some("2.0.1"),
        memory: None,
        price: Some("16\u{e9}"),
        shop: Some("http://www.cryptoshop.com/gemalto-idcore-10-gemalto-top-im-gx4.html"),
        notes: &[
            Note {
                text: "Virgin cards require unlocking with \"-visa2 -key <motherkey>\"",
                line: 27,
            },
            Note {
                text: "Instead of a reasonable error code a failed transaction is returned on errors.",
                line: 28,
            },
        ],
    },
    CardProfile {
        name: "gemalto-idcore-3010-cc",
        title: "GEMALTO IDCORE 3010 CC / TOP DM CC",
        vendor: "Gemalto",
        listing: Listing::Supported,
        javacard: None,
        globalplatform: None,
        memory: None,
        price: Some("25\u{e9}"),
        shop: Some("http://www.cryptoshop.com/gemalto-top-dm-cc.html"),
        notes: &[Note {
                text: "this line states a price and a link but no JavaCard and no GlobalPlatform version",
                line: 29,
            }],
    },
    CardProfile {
        name: "feitian-javacos-a40",
        title: "javacos-a40-dual-interface-java-card-64k",
        vendor: "Feitian",
        listing: Listing::Supported,
        javacard: None,
        globalplatform: None,
        memory: None,
        price: None,
        shop: Some(
            "http://www.smartcardfocus.com/shop/ilp/id~711/javacos-a40-dual-interface-java-card-64k/p/index.shtml",
        ),
        notes: &[Note {
                text: "listed as a bare URL: no product name, no JavaCard version, no GlobalPlatform version and no price, and the capacity inside the shop slug is not read as a stated memory size",
                line: 31,
            }],
    },
    CardProfile {
        name: "feitian-javacos-a22",
        title: "javacos-a22-dual-interface-java-card-150k",
        vendor: "Feitian",
        listing: Listing::Supported,
        javacard: None,
        globalplatform: None,
        memory: None,
        price: None,
        shop: Some(
            "http://www.smartcardfocus.com/shop/ilp/id~712/javacos-a22-dual-interface-java-card-150k/p/index.shtml",
        ),
        notes: &[Note {
                text: "listed as a bare URL: no product name, no JavaCard version, no GlobalPlatform version and no price, and the capacity inside the shop slug is not read as a stated memory size",
                line: 32,
            }],
    },
    CardProfile {
        name: "oberthur-cosmo-v7-128k",
        title: "Oberthur Cosmo v7 128K",
        vendor: "Oberthur",
        listing: Listing::TestedWithoutShopLink,
        javacard: Some("2.2.2"),
        globalplatform: Some("2.1.1"),
        memory: Some("128K"),
        price: None,
        shop: None,
        notes: &[Note {
                text: "smartcardfocus.com used to sell it",
                line: 35,
            }],
    },
    CardProfile {
        name: "athena-idprotect",
        title: "Athena ID-protect",
        vendor: "Athena",
        listing: Listing::TestedWithoutShopLink,
        javacard: Some("2.2.2"),
        globalplatform: Some("2.1.1"),
        memory: None,
        price: Some("29\u{e9}"),
        shop: Some("http://www.cryptoshop.com/idprotect-key-usb-nano-laser.html"),
        notes: &[
            Note {
                text: "listed under the heading for cards without a confirmed shop link, yet this line prints one",
                line: 36,
            },
            Note {
                text: "http://www.cryptoshop.com/athena-idprotect-java-card-bio-match-on-card.html",
                line: 37,
            },
            Note {
                text: "http://www.athena-scs.com/docs/products-solutions-datasheets/athena-idprotect-laser.pdf",
                line: 38,
            },
        ],
    },
    CardProfile {
        name: "gemalto-top-im-fips-cy2",
        title: "Gemalto TOP IM FIPS CY2",
        vendor: "Gemalto",
        listing: Listing::TestedWithoutShopLink,
        javacard: None,
        globalplatform: None,
        memory: None,
        price: Some("\u{a3}14.00"),
        shop: Some("http://smartware2u.com/products/30-gemalto-top-im-fips-cy2.aspx"),
        notes: &[
            Note {
                text: "listed under the heading for cards without a confirmed shop link, yet this line prints a purchase URL: the reference contradicts itself here, so both facts are reported and neither is resolved",
                line: 39,
            },
            Note {
                text: "## Tested cards without a confirmed shop link",
                line: 34,
            },
        ],
    },
];

/// The profile with this name, if the table has one.
pub fn find(name: &str) -> Option<&'static CardProfile> {
    PROFILES.iter().find(|profile| profile.name == name)
}

/// Every profile name, in table order.
pub fn names() -> Vec<&'static str> {
    PROFILES.iter().map(|profile| profile.name).collect()
}

/// One field of a card profile, as `pySim/profile.py` defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProfileField {
    /// The field name, spelled as the reference spells it.
    pub name: &'static str,
    /// The assignment in `CardProfile.__init__` that sets it.
    pub line: u32,
    /// The docstring line that names it.
    pub doc_line: u32,
    /// What the reference says the field is.
    pub doc: &'static str,
}

/// The nine fields `pySim/profile.py:50-59` gives a card profile, each with the
/// docstring line that names it.
///
/// This is the schema [`FORMAT`] is shaped on: a fixture carries exactly these
/// fields, so a document means the same thing here as a `CardProfile` does there.
/// `addons` is the reference's own field and is carried here; why no row in this
/// table has one is [`ADDON_PROVENANCE`].
pub const PROFILE_FIELDS: &[ProfileField] = &[
    ProfileField {
        name: "name",
        line: 50,
        doc_line: 34,
        doc: "a Card Profile describes a card, its filesystem hierarchy, an [initial] list of applications as well as profile-specific SW and shell commands",
    },
    ProfileField {
        name: "desc",
        line: 51,
        doc_line: 41,
        doc: "Description",
    },
    ProfileField {
        name: "files_in_mf",
        line: 52,
        doc_line: 42,
        doc: "List of CardEF instances present in MF",
    },
    ProfileField {
        name: "sw",
        line: 53,
        doc_line: 44,
        doc: "List of status word definitions",
    },
    ProfileField {
        name: "applications",
        line: 54,
        doc_line: 43,
        doc: "List of CardApplications present on card",
    },
    ProfileField {
        name: "shell_cmdsets",
        line: 55,
        doc_line: 45,
        doc: "List of cmd2 shell command sets of profile-specific commands",
    },
    ProfileField {
        name: "cla",
        line: 56,
        doc_line: 46,
        doc: "class byte that should be used with cards of this profile",
    },
    ProfileField {
        name: "sel_ctrl",
        line: 57,
        doc_line: 47,
        doc: "selection control bytes class byte that should be used with cards of this profile",
    },
    ProfileField {
        name: "addons",
        line: 59,
        doc_line: 48,
        doc: "List of optional CardAddons that a card of this profile might have",
    },
];

/// `pySim/profile.py:56`: a profile that states no class byte gets `00`.
pub const CLA_DEFAULT: &str = "00";

/// `pySim/profile.py:57`: a profile that states no selection control gets `0004`.
pub const SEL_CTRL_DEFAULT: &str = "0004";

/// The provenance of the two defaults, which are facts and are cited like any other.
pub const DEFAULT_PROVENANCE: [Provenance<'static>; 2] = [
    Provenance {
        source: PYSIM_PROFILE,
        line: 56,
        asserts: "kw.get(\"cla\", \"00\"): the class byte a profile that states none uses",
    },
    Provenance {
        source: PYSIM_PROFILE,
        line: 57,
        asserts:
            "kw.get(\"sel_ctrl\", \"0004\"): the selection control a profile that states none uses",
    },
];

/// `pySim/profile.py:166-169`: an add-on is not a card application and not a full
/// profile, and the reference's one named example is GSM-R specific files.
///
/// The field is in [`FORMAT`] because the reference has it. **No entry in this crate
/// carries a non-empty add-on list**, because no reference lists one: inventing a GSM-R
/// add-on for a bought card would be a claim no source supports.
pub const ADDON_PROVENANCE: Provenance<'static> = Provenance {
    source: PYSIM_PROFILE,
    line: 166,
    asserts: "a Card Profile Add-on is something that is not a card application and not a full stand-alone card profile, but an add-on to an existing profile",
};

/// The provenance of the document's shape: one record per [`PROFILE_FIELDS`] entry,
/// then the two defaults, then the add-on note.
pub fn schema_provenance() -> Vec<Provenance<'static>> {
    let mut all: Vec<Provenance<'static>> = PROFILE_FIELDS
        .iter()
        .map(|field| Provenance {
            source: PYSIM_PROFILE,
            line: field.line,
            asserts: "the assignment that gives a card profile this field",
        })
        .collect();
    all.extend(DEFAULT_PROVENANCE.iter().copied());
    all.push(ADDON_PROVENANCE);
    all
}

/// Why a fixture document was refused.
///
/// Every variant is a refusal with its reason. **Nothing here is repaired, defaulted
/// or guessed**: an unknown format version is not read as the version this build knows,
/// a missing field is not filled from a sibling, and a malformed value is not coerced.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// Not JSON at all, or JSON of the wrong shape for [`RawFixture`].
    #[error("the fixture is not readable JSON: {0}")]
    NotJson(#[from] serde_json::Error),

    /// A `format` this build does not implement.
    #[error(
        "unknown fixture format {found:?}; this build reads {supported:?} and refuses rather than guessing"
    )]
    UnknownFormat {
        /// What the document said.
        found: String,
        /// The one format this build reads.
        supported: &'static str,
    },

    /// A key this build does not know, anywhere in the document.
    #[error("unknown key {field:?} in a {supported:?} fixture; refusing rather than ignoring it")]
    UnknownKey {
        /// The key the document carried.
        field: String,
        /// The one format this build reads.
        supported: &'static str,
    },

    /// A required field that was absent or null.
    #[error("missing required field {0:?}")]
    MissingField(&'static str),

    /// A field of the wrong JSON type, or a value that is not what the field means.
    #[error("field {field:?} is {value}, which is not {expectation}")]
    MalformedValue {
        /// The field, named by its path in the document.
        field: &'static str,
        /// What was there instead.
        value: String,
        /// What the field has to be.
        expectation: &'static str,
    },

    /// A document that cannot say where it came from.
    #[error("a fixture with no provenance is not evidence: it cannot say which line of which file it came from")]
    NoProvenance,

    /// A provenance record whose line is not a line.
    #[error("provenance record {index} names line {line}; a line number starts at 1")]
    BadProvenanceLine {
        /// Which record, counting from 0.
        index: usize,
        /// The line it named.
        line: i64,
    },
}

/// The keys [`FORMAT`] carries, at the top level.
const FIXTURE_KEYS: &[&str] = &[
    "format",
    "read_on",
    "profile",
    "cla",
    "sel_ctrl",
    "provenance",
];

/// The keys [`FORMAT`]'s `profile` object carries: [`CardProfile`]'s fields.
const PROFILE_KEYS: &[&str] = &[
    "name",
    "title",
    "vendor",
    "listing",
    "javacard",
    "globalplatform",
    "memory",
    "price",
    "shop",
    "notes",
];

/// The keys a `notes` entry carries.
const NOTE_KEYS: &[&str] = &["text", "line"];

/// The keys a `provenance` entry carries.
const PROVENANCE_KEYS: &[&str] = &["source", "line", "asserts"];

/// A fixture document, as [`CardProfile::render`] writes it.
///
/// Borrowed rather than owned because every field comes from the compiled-in table, so
/// rendering borrows and nothing is copied. The counterpart read back from a file is
/// [`ParsedFixture`], which owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fixture<'a> {
    /// Always [`FORMAT`]. Required, so a reader never has to guess the shape.
    pub format: &'a str,
    /// [`READ_ON`]: the date the references behind this document were read.
    ///
    /// Required, because a price and a URL are dated data and a document that does not
    /// carry its date cannot be aged.
    pub read_on: &'a str,
    /// The card profile.
    pub profile: &'a CardProfile,
    /// The class byte: [`CLA_DEFAULT`] unless the row states one.
    pub cla: &'a str,
    /// The selection control: [`SEL_CTRL_DEFAULT`] unless the row states one.
    pub sel_ctrl: &'a str,
    /// Where the shape came from, then where this row came from.
    pub provenance: Vec<Provenance<'a>>,
}

impl CardProfile {
    /// The fixture document for this profile.
    ///
    /// The `cla` and `sel_ctrl` are [`CLA_DEFAULT`] and [`SEL_CTRL_DEFAULT`] because
    /// [`CardProfile`] states neither: the reference prints them as the defaults its
    /// `CardProfile.__init__` applies to a profile that states none
    /// (`pySim/profile.py:56-57`), and inventing a value from a card's behaviour would
    /// be a claim about the card that no source makes.
    pub fn fixture(&self) -> Fixture<'_> {
        let mut provenance = schema_provenance();
        provenance.extend(self.provenance());
        Fixture {
            format: FORMAT,
            read_on: READ_ON,
            profile: self,
            cla: CLA_DEFAULT,
            sel_ctrl: SEL_CTRL_DEFAULT,
            provenance,
        }
    }

    /// The document as one line of compact JSON, with no trailing newline.
    ///
    /// Deterministic: same row in, same bytes out, because the document is a struct of
    /// strings and arrays with no map and no clock
    /// (`rendering_is_deterministic`).
    ///
    /// # Errors
    ///
    /// A [`FixtureError::NotJson`] if the document could not be serialised, which a
    /// struct of strings, numbers and slices cannot do.
    pub fn render(&self) -> Result<String, FixtureError> {
        serde_json::to_string(&self.fixture()).map_err(FixtureError::from)
    }

    /// The document as indented JSON for a person to read, with no trailing newline.
    ///
    /// # Errors
    ///
    /// A [`FixtureError::NotJson`] if the document could not be serialised.
    pub fn render_pretty(&self) -> Result<String, FixtureError> {
        serde_json::to_string_pretty(&self.fixture()).map_err(FixtureError::from)
    }
}

impl<'a> Fixture<'a> {
    /// Reads a document back, refusing anything it cannot read exactly.
    ///
    /// # Errors
    ///
    /// A [`FixtureError`] naming the reason. [`FixtureError::UnknownFormat`] and
    /// [`FixtureError::UnknownKey`] are refusals by design: a future `.../2` document
    /// read as this one would be a fixture that means something other than it says.
    pub fn parse(text: &str) -> Result<ParsedFixture, FixtureError> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        let map = value.as_object().ok_or(FixtureError::MalformedValue {
            field: "fixture",
            value: json_kind(&value).to_owned(),
            expectation: "a JSON object",
        })?;
        reject_unknown_keys(map, FIXTURE_KEYS)?;

        let format = required_text(map, "format", "format")?;
        if format != FORMAT {
            return Err(FixtureError::UnknownFormat {
                found: format,
                supported: FORMAT,
            });
        }
        // The date is required but not constrained: a fixture written by another build
        // on another day is still readable, it is just older or newer, and the date is
        // reported rather than enforced.
        let read_on = required_text(map, "read_on", "read_on")?;
        let cla = hex_field(map, "cla", "cla", 2)?;
        let sel_ctrl = hex_field(map, "sel_ctrl", "sel_ctrl", 4)?;

        let profile_value = map
            .get("profile")
            .ok_or(FixtureError::MissingField("profile"))?;
        let profile = profile_value
            .as_object()
            .ok_or(FixtureError::MalformedValue {
                field: "profile",
                value: json_kind(profile_value).to_owned(),
                expectation: "a JSON object",
            })?;
        reject_unknown_keys(profile, PROFILE_KEYS)?;
        let name = required_text(profile, "name", "profile.name")?;
        let title = required_text(profile, "title", "profile.title")?;
        let vendor = required_text(profile, "vendor", "profile.vendor")?;
        let listing_value = required_text(profile, "listing", "profile.listing")?;
        let listing: Listing = serde_json::from_value(serde_json::Value::String(
            listing_value.clone(),
        ))
        .map_err(|_| FixtureError::MalformedValue {
            field: "profile.listing",
            value: format!("{listing_value:?}"),
            expectation: "\"supported\" or \"tested-without-shop-link\"",
        })?;

        let mut notes = Vec::new();
        if let Some(raw) = profile.get("notes") {
            let list = raw.as_array().ok_or(FixtureError::MalformedValue {
                field: "profile.notes",
                value: json_kind(raw).to_owned(),
                expectation: "an array of note objects",
            })?;
            for (index, entry) in list.iter().enumerate() {
                let note = entry.as_object().ok_or(FixtureError::MalformedValue {
                    field: "profile.notes",
                    value: json_kind(entry).to_owned(),
                    expectation: "an array of note objects",
                })?;
                reject_unknown_keys(note, NOTE_KEYS)?;
                let text = required_text(note, "text", "profile.notes.text")?;
                let line = line_field(note.get("line"), index, "profile.notes.line")?;
                notes.push(ParsedNote { text, line });
            }
        }

        let raw_provenance = map
            .get("provenance")
            .ok_or(FixtureError::MissingField("provenance"))?;
        let list = raw_provenance
            .as_array()
            .ok_or(FixtureError::MalformedValue {
                field: "provenance",
                value: json_kind(raw_provenance).to_owned(),
                expectation: "an array of provenance objects",
            })?;
        if list.is_empty() {
            return Err(FixtureError::NoProvenance);
        }
        let mut provenance = Vec::with_capacity(list.len());
        for (index, entry) in list.iter().enumerate() {
            let claim = entry.as_object().ok_or(FixtureError::MalformedValue {
                field: "provenance",
                value: json_kind(entry).to_owned(),
                expectation: "an array of provenance objects",
            })?;
            reject_unknown_keys(claim, PROVENANCE_KEYS)?;
            let source = required_text(claim, "source", "provenance.source")?;
            let line = line_field(claim.get("line"), index, "provenance.line")?;
            let asserts = required_text(claim, "asserts", "provenance.asserts")?;
            provenance.push(ProvenanceRecord {
                source,
                line,
                asserts,
            });
        }

        Ok(ParsedFixture {
            format,
            read_on,
            profile_name: name,
            title,
            vendor,
            listing,
            javacard: optional_text(profile, "javacard", "profile.javacard")?,
            globalplatform: optional_text(profile, "globalplatform", "profile.globalplatform")?,
            memory: optional_text(profile, "memory", "profile.memory")?,
            price: optional_text(profile, "price", "profile.price")?,
            shop: optional_text(profile, "shop", "profile.shop")?,
            notes,
            cla,
            sel_ctrl,
            provenance,
        })
    }
}

/// A note as read back from a fixture document, owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedNote {
    /// The note's text.
    pub text: String,
    /// The line it was read from.
    pub line: u32,
}

/// A fixture document read back off disk or stdin, owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedFixture {
    /// The `format` the document declared; always [`FORMAT`] if it parsed.
    pub format: String,
    /// [`READ_ON`], as the document stated it.
    pub read_on: String,
    /// The row's name.
    pub profile_name: String,
    /// The row's title.
    pub title: String,
    /// The row's vendor.
    pub vendor: String,
    /// Which heading the row is listed under.
    pub listing: Listing,
    /// Stated JavaCard version, if the reference states one.
    pub javacard: Option<String>,
    /// Stated GlobalPlatform version, if the reference states one.
    pub globalplatform: Option<String>,
    /// Stated EEPROM size, if the reference states one.
    pub memory: Option<String>,
    /// Stated price, verbatim.
    pub price: Option<String>,
    /// Stated shop URL.
    pub shop: Option<String>,
    /// Notes, each with its line.
    pub notes: Vec<ParsedNote>,
    /// The class byte.
    pub cla: String,
    /// The selection control.
    pub sel_ctrl: String,
    /// Where the shape came from, then where the row came from.
    pub provenance: Vec<ProvenanceRecord>,
}

impl ParsedFixture {
    /// The round-trip predicate: true when this document says exactly what the
    /// compiled-in row says - every field, every note, every line.
    ///
    /// False rather than an error on the first difference, because the caller is a test
    /// asking whether a generator round-trips.
    pub fn matches_profile(&self, other: &CardProfile) -> bool {
        self.read_on == READ_ON && self.matches_row(other)
    }

    /// As [`ParsedFixture::matches_profile`], but ignoring the date the document was
    /// read on.
    ///
    /// The two are separate because a document read on another day is still the same
    /// row: what changes is how old it is, and [`ParsedFixture::read_on`] reports that
    /// without the row changing. Collapsing the two would either refuse an older
    /// fixture or silently re-date it.
    pub fn matches_row(&self, other: &CardProfile) -> bool {
        self.format == FORMAT
            && self.profile_name == other.name
            && self.title == other.title
            && self.vendor == other.vendor
            && self.listing == other.listing
            && optional_eq(self.javacard.as_deref(), other.javacard)
            && optional_eq(self.globalplatform.as_deref(), other.globalplatform)
            && optional_eq(self.memory.as_deref(), other.memory)
            && optional_eq(self.price.as_deref(), other.price)
            && optional_eq(self.shop.as_deref(), other.shop)
            && self.cla == CLA_DEFAULT
            && self.sel_ctrl == SEL_CTRL_DEFAULT
            && self.notes.len() == other.notes.len()
            && self
                .notes
                .iter()
                .zip(other.notes.iter())
                .all(|(a, b)| a.text == b.text && a.line == b.line)
            && {
                // The document carries the schema's records first, then the row's,
                // which is what CardProfile::fixture() builds; anything else has
                // lost or reordered a record on the way through.
                let expected = other.fixture().provenance;
                self.provenance.len() == expected.len()
                    && self
                        .provenance
                        .iter()
                        .zip(expected.iter())
                        .all(|(a, b)| a == &ProvenanceRecord::from_claim(b))
            }
    }
}

fn optional_eq(found: Option<&str>, compiled: Option<&str>) -> bool {
    found == compiled
}

/// What a `serde_json::Value` holds, in words.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

fn reject_unknown_keys(
    map: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), FixtureError> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(FixtureError::UnknownKey {
                field: key.clone(),
                supported: FORMAT,
            });
        }
    }
    Ok(())
}

fn required_text(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &'static str,
) -> Result<String, FixtureError> {
    match map.get(key) {
        None | Some(serde_json::Value::Null) => Err(FixtureError::MissingField(path)),
        Some(serde_json::Value::String(text)) => Ok(text.clone()),
        Some(other) => Err(FixtureError::MalformedValue {
            field: path,
            value: json_kind(other).to_owned(),
            expectation: "a string",
        }),
    }
}

fn optional_text(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &'static str,
) -> Result<Option<String>, FixtureError> {
    match map.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(FixtureError::MalformedValue {
            field: path,
            value: json_kind(other).to_owned(),
            expectation: "a string or null",
        }),
    }
}

/// A required hex field of exactly `len` digits.
fn hex_field(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &'static str,
    len: usize,
) -> Result<String, FixtureError> {
    let text = required_text(map, key, path)?;
    if text.len() == len && text.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(text)
    } else {
        Err(FixtureError::MalformedValue {
            field: path,
            value: format!("{text:?}"),
            expectation: if len == 2 {
                "two hex digits"
            } else {
                "four hex digits"
            },
        })
    }
}

/// A provenance line: present, a number, and at least 1.
fn line_field(
    value: Option<&serde_json::Value>,
    index: usize,
    field: &'static str,
) -> Result<u32, FixtureError> {
    let number = match value {
        None | Some(serde_json::Value::Null) => {
            return Err(FixtureError::MalformedValue {
                field,
                value: "absent".to_owned(),
                expectation: "a line number",
            })
        }
        Some(serde_json::Value::Number(number)) => number.as_i64(),
        Some(other) => {
            return Err(FixtureError::MalformedValue {
                field,
                value: json_kind(other).to_owned(),
                expectation: "a line number",
            })
        }
    };
    match number {
        Some(line) if line >= 1 && line <= i64::from(u32::MAX) => Ok(line as u32),
        other => Err(FixtureError::BadProvenanceLine {
            index,
            line: other.unwrap_or(i64::MIN),
        }),
    }
}

/// The sentence the human output carries, because the obvious misreading is that this
/// is another filesystem profile like the TS.48 corpus.
pub const NOT_A_FILE_LIST: &str =
    "This table is a card catalogue, not a file-system profile: it carries no file \
     identifier, no size and no layout, so it cannot answer whether a card matches \
     TS.48. `sim-doctor ts48 compare` does that, against the GSMA profile's file list.";

/// The staleness sentence, with the date in it rather than beside it.
pub fn prices_are_dated() -> String {
    format!(
        "Prices and shop links are quoted verbatim from {TESTED_CARDS} (LGPL-3.0) and \
         were read on {READ_ON}. They are dated data, not current quotes: this table does \
         not re-check that a link still resolves or that a price still holds, and a \
         reader who needs the price today must open the link."
    )
}

/// `sim-doctor cards list`, as a person reads it.
pub fn table() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<34} {:<10} {:<8} {:<8} {}\n",
        "CARD PROFILE", "JAVACARD", "GP", "MEMORY", "LISTING"
    ));
    for profile in PROFILES {
        out.push_str(&format!(
            "{:<34} {:<10} {:<8} {:<8} {}\n",
            profile.name,
            profile.javacard.unwrap_or("-"),
            profile.globalplatform.unwrap_or("-"),
            profile.memory.unwrap_or("-"),
            listing_word(profile.listing),
        ));
    }
    out.push('\n');
    out.push_str(&format!(
        "{} profiles from {TESTED_CARDS}, branch {REF_BRANCHES}, read {READ_ON}.\n",
        PROFILES.len()
    ));
    out.push_str(&format!(
        "The field schema is {PYSIM_PROFILE}, branch {REF_BRANCHES}.\n\n"
    ));
    out.push_str(NOT_A_FILE_LIST);
    out.push('\n');
    out.push('\n');
    out.push_str(&prices_are_dated());
    out.push('\n');
    out
}

/// `sim-doctor cards show NAME`, provenance included.
pub fn detail(profile: &CardProfile) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", profile.name));
    out.push_str(&format!("  title             {}\n", profile.title));
    out.push_str(&format!("  vendor            {}\n", profile.vendor));
    out.push_str(&format!(
        "  listed under      {} ({TESTED_CARDS}:{})\n",
        listing_word(profile.listing),
        profile.listing.heading_line()
    ));
    out.push_str(&format!("  javacard          {}\n", dash(profile.javacard)));
    out.push_str(&format!(
        "  globalplatform    {}\n",
        dash(profile.globalplatform)
    ));
    out.push_str(&format!("  memory            {}\n", dash(profile.memory)));
    out.push_str(&format!("  price             {}\n", dash(profile.price)));
    out.push_str(&format!("  shop              {}\n", dash(profile.shop)));
    if profile.notes.is_empty() {
        out.push_str("  notes             none recorded\n");
    } else {
        out.push_str("  notes\n");
        for note in profile.notes {
            out.push_str(&format!(
                "    {TESTED_CARDS}:{}  {}\n",
                note.line, note.text
            ));
        }
    }
    out.push_str("  provenance\n");
    for claim in profile.provenance() {
        out.push_str(&format!(
            "    {}:{}  {}\n",
            claim.source, claim.line, claim.asserts
        ));
    }
    out.push_str("  fixture\n");
    out.push_str(&format!(
        "    sim-doctor cards fixture {} > {}.card-fixture.json\n",
        profile.name, profile.name
    ));
    out.push_str(&format!(
        "    writes one {FORMAT} document, read back on {READ_ON}\n",
    ));
    out.push('\n');
    out.push_str(&prices_are_dated());
    out.push('\n');
    out
}

fn listing_word(listing: Listing) -> &'static str {
    match listing {
        Listing::Supported => "supported",
        Listing::TestedWithoutShopLink => "tested-without-shop-link",
    }
}

fn dash(value: Option<&str>) -> &str {
    value.unwrap_or("- not stated by the reference -")
}

/// The `data` object `sim-doctor cards list --json` carries.
pub fn catalogue() -> serde_json::Value {
    serde_json::json!({
        "format": FORMAT,
        "read_on": READ_ON,
        "reference_branches": REF_BRANCHES,
        "more_information": MORE_INFO,
        "note": NOT_A_FILE_LIST,
        "staleness": prices_are_dated(),
        "sources": [
            { "reference": TESTED_CARDS, "licence": "LGPL-3.0", "read_on": READ_ON },
            { "reference": PYSIM_PROFILE, "licence": "GPL", "read_on": READ_ON },
        ],
        "defaults": { "cla": CLA_DEFAULT, "sel_ctrl": SEL_CTRL_DEFAULT },
        "schema": {
            "fields": PROFILE_FIELDS,
            "provenance": schema_provenance(),
        },
        "profiles": PROFILES.iter().map(profile_json).collect::<Vec<_>>(),
    })
}

/// The `data` object `sim-doctor cards show NAME --json` carries.
pub fn profile_json(profile: &CardProfile) -> serde_json::Value {
    serde_json::json!({
        "name": profile.name,
        "title": profile.title,
        "vendor": profile.vendor,
        "listing": profile.listing,
        "listing_line": profile.entry_line(),
        "heading_line": profile.listing.heading_line(),
        "javacard": profile.javacard,
        "globalplatform": profile.globalplatform,
        "memory": profile.memory,
        "price": profile.price,
        "shop": profile.shop,
        "notes": profile.notes,
        "provenance": profile.provenance(),
        "fixture_command": format!("sim-doctor cards fixture {}", profile.name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest line either reference has, so a citation past it is a typo.
    const TESTED_CARDS_LINES: u32 = 42;

    fn rendered(name: &str) -> String {
        find(name)
            .expect("every test names a row that is in the table")
            .render()
            .expect("a struct of strings, numbers and slices serialises")
    }

    fn document(name: &str) -> serde_json::Value {
        serde_json::from_str(&rendered(name)).expect("the generator writes JSON")
    }

    fn reparse(value: &serde_json::Value) -> Result<ParsedFixture, FixtureError> {
        Fixture::parse(&serde_json::to_string(value).expect("a Value serialises"))
    }

    #[test]
    fn every_entry_carries_provenance() {
        for profile in PROFILES {
            let claims = profile.provenance();
            assert_eq!(
                claims.len(),
                4,
                "{} must carry the three support criteria and its own listing line",
                profile.name
            );
            for claim in claims {
                assert!(
                    !claim.source.is_empty() && !claim.asserts.is_empty() && claim.line >= 1,
                    "{} carries an empty provenance record: {claim:?}",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn every_note_carries_its_line_inside_the_reference() {
        for profile in PROFILES {
            assert!(
                !profile.notes.is_empty(),
                "{} carries no note",
                profile.name
            );
            for note in profile.notes {
                assert!(
                    !note.text.is_empty(),
                    "{} has an empty note on line {}",
                    profile.name,
                    note.line
                );
                assert!(
                    (1..=TESTED_CARDS_LINES).contains(&note.line),
                    "{} cites line {} of {TESTED_CARDS}, which has {TESTED_CARDS_LINES} lines",
                    profile.name,
                    note.line
                );
            }
        }
    }

    #[test]
    fn every_cited_line_is_inside_its_reference() {
        for profile in PROFILES {
            for claim in profile.provenance() {
                assert!(
                    (1..=TESTED_CARDS_LINES).contains(&claim.line),
                    "{} cites {}:{}, past the end of that file",
                    profile.name,
                    claim.source,
                    claim.line
                );
            }
        }
        for field in PROFILE_FIELDS {
            assert!(
                (34..=59).contains(&field.line),
                "the schema cites {}:{}, outside the CardProfile constructor",
                PYSIM_PROFILE,
                field.line
            );
            assert!(
                (34..=48).contains(&field.doc_line),
                "the schema cites {}:{}, outside the constructor docstring",
                PYSIM_PROFILE,
                field.doc_line
            );
        }
    }

    #[test]
    fn versions_are_stated_only_where_the_reference_states_them() {
        /// name, stated JavaCard, stated GlobalPlatform, the line that states them.
        const EXPECTED: &[(&str, Option<&str>, Option<&str>, u32)] = &[
            ("smartcafe-expert-3-2-72k", Some("2.2.1"), Some("2.1.1"), 11),
            ("jcop-j3d081-v2-4-2", Some("3.0.1"), Some("2.2"), 17),
            ("jcop-nxp-j3a080-dual-interface", None, None, 23),
            ("gemalto-top-im-gx4", Some("2.2.1"), Some("2.0.1"), 26),
            ("gemalto-idcore-3010-cc", None, None, 29),
            ("feitian-javacos-a40", None, None, 31),
            ("feitian-javacos-a22", None, None, 32),
            ("oberthur-cosmo-v7-128k", Some("2.2.2"), Some("2.1.1"), 35),
            ("athena-idprotect", Some("2.2.2"), Some("2.1.1"), 36),
            ("gemalto-top-im-fips-cy2", None, None, 39),
        ];
        assert_eq!(
            EXPECTED.len(),
            PROFILES.len(),
            "the expectation table has to cover every row, or it proves nothing"
        );
        for (name, javacard, globalplatform, line) in EXPECTED {
            let profile = find(name).expect("the expectation names a row in the table");
            assert_eq!(profile.javacard, *javacard, "{name}: JavaCard version");
            assert_eq!(
                profile.globalplatform, *globalplatform,
                "{name}: GlobalPlatform version"
            );
            assert_eq!(profile.entry_line(), *line, "{name}: listing line");
        }
    }

    #[test]
    fn the_everything_else_is_absent_where_the_reference_stays_silent() {
        for profile in PROFILES {
            if profile.javacard.is_none() {
                assert!(
                    profile.globalplatform.is_none(),
                    "{} states a GlobalPlatform version but no JavaCard version; \
                     one without the other has to be read from the reference again",
                    profile.name
                );
            }
            if profile.price.is_some() {
                assert!(
                    profile.shop.is_some(),
                    "{} has a price but no link, and the reference prints them together",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn a_supported_entry_has_a_link_because_its_heading_says_so() {
        for profile in PROFILES {
            if profile.listing == Listing::Supported {
                assert!(
                    profile.shop.is_some(),
                    "{} sits under \"Supported cards (with a confirmed shop link)\" \
                     and carries no link",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn the_reference_contradiction_is_reported_and_not_resolved() {
        let contradicted: Vec<&CardProfile> = PROFILES
            .iter()
            .filter(|profile| {
                profile.listing == Listing::TestedWithoutShopLink && profile.shop.is_some()
            })
            .collect();
        let names: Vec<&str> = contradicted.iter().map(|profile| profile.name).collect();
        assert_eq!(
            names,
            vec!["athena-idprotect", "gemalto-top-im-fips-cy2"],
            "exactly these two entries sit under \"without a confirmed shop link\" and \
             print one anyway. A third would mean this table had started resolving the \
             reference's contradictions; fewer would mean it had silently resolved one \
             of these two, which is the same mistake in the other direction"
        );
        for profile in &contradicted {
            assert!(
                profile
                    .notes
                    .iter()
                    .any(|note| note.line == profile.entry_line()),
                "{} must carry a note that names the line it is listed on",
                profile.name
            );
        }
        let fips = find("gemalto-top-im-fips-cy2").expect("a row in the table");
        let lines: Vec<u32> = fips.notes.iter().map(|note| note.line).collect();
        assert_eq!(
            lines,
            vec![39, 34],
            "the FIPS card's notes must name its listing line and the heading it \
             contradicts, so a reader sees both facts"
        );
    }

    #[test]
    fn names_are_unique_and_kebab_case() {
        let mut seen: Vec<&str> = Vec::new();
        for profile in PROFILES {
            assert!(
                !seen.contains(&profile.name),
                "{} is listed twice",
                profile.name
            );
            seen.push(profile.name);
            assert!(
                !profile.name.starts_with('-')
                    && !profile.name.ends_with('-')
                    && !profile.name.contains("--")
                    && profile
                        .name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{} is not a lower-case kebab-case name",
                profile.name
            );
        }
        assert_eq!(seen.len(), PROFILES.len());
    }

    #[test]
    fn every_listing_line_is_distinct_and_points_at_a_listed_card() {
        let mut lines: Vec<u32> = PROFILES
            .iter()
            .map(|profile| profile.entry_line())
            .collect();
        lines.sort_unstable();
        let before = lines.len();
        lines.dedup();
        assert_eq!(before, lines.len(), "two rows cite the same line");
        for profile in PROFILES {
            assert!(
                (11..=39).contains(&profile.entry_line()),
                "{} is listed at line {}, which is not a card line in the reference",
                profile.name,
                profile.entry_line()
            );
        }
    }

    #[test]
    fn every_listing_provenance_names_tested_cards() {
        // The two references are kept apart on purpose: this table is the card table,
        // and pySim's simulator-class catalogue is issue #275's, not this issue's.
        // A row whose provenance named profile.py would be a simulator class smuggled
        // into the card table.
        for profile in PROFILES {
            for claim in profile.provenance() {
                assert_eq!(
                    claim.source, TESTED_CARDS,
                    "{} cites {}, which is not the card table's reference",
                    profile.name, claim.source
                );
            }
        }
    }

    #[test]
    fn the_support_criteria_are_the_reference_lines() {
        let lines: Vec<u32> = SUPPORT_CRITERIA.iter().map(|claim| claim.line).collect();
        assert_eq!(lines, vec![2, 3, 4]);
        for claim in SUPPORT_CRITERIA {
            assert_eq!(claim.source, TESTED_CARDS);
            assert!(
                claim.asserts.contains("supported if and only if"),
                "the criteria are the reference's own \"if and only if\", and that is \
                 the sentence that has to be carried: {}",
                claim.asserts
            );
        }
    }

    #[test]
    fn the_schema_is_the_reference_constructor_in_order() {
        let names: Vec<&str> = PROFILE_FIELDS.iter().map(|field| field.name).collect();
        assert_eq!(
            names,
            vec![
                "name",
                "desc",
                "files_in_mf",
                "sw",
                "applications",
                "shell_cmdsets",
                "cla",
                "sel_ctrl",
                "addons",
            ],
            "pySim/profile.py sets these, in this order, in CardProfile.__init__"
        );
        let lines: Vec<u32> = PROFILE_FIELDS.iter().map(|field| field.line).collect();
        assert_eq!(
            lines,
            vec![50, 51, 52, 53, 54, 55, 56, 57, 59],
            "line 58 of pySim/profile.py is the addons comment, not an assignment"
        );
        for field in PROFILE_FIELDS {
            assert!(!field.doc.is_empty(), "{} has no docstring", field.name);
        }
    }

    #[test]
    fn every_schema_field_carries_its_pysim_provenance() {
        for claim in schema_provenance() {
            assert_eq!(
                claim.source, PYSIM_PROFILE,
                "the schema's provenance must come from profile.py alone, so it cannot \
                 be confused with the card table's"
            );
            assert!(claim.line >= 1 && !claim.asserts.is_empty());
        }
        assert_eq!(CLA_DEFAULT, "00");
        assert_eq!(SEL_CTRL_DEFAULT, "0004");
        let defaults: Vec<u32> = DEFAULT_PROVENANCE.iter().map(|claim| claim.line).collect();
        assert_eq!(defaults, vec![56, 57]);
    }

    #[test]
    fn the_table_states_no_file_system_fact() {
        // TS.48 owns the file list. Nothing here may start looking like one.
        let mut value = document("smartcafe-expert-3-2-72k");
        let profile = value["profile"]
            .as_object()
            .expect("the document carries a profile object");
        assert!(
            !profile.contains_key("files_in_mf"),
            "the schema names files_in_mf, but no row may state one: this table holds \
             no file identifier, size or layout"
        );
        for forbidden in ["files", "files_in_mf", "size", "path", "record_length"] {
            assert!(
                !profile.contains_key(forbidden),
                "{forbidden} would make this a filesystem profile"
            );
        }
        value = document("feitian-javacos-a40");
        assert!(value["profile"]["memory"].is_null());
    }

    #[test]
    fn an_unknown_format_version_is_refused_and_named() {
        let text =
            rendered("smartcafe-expert-3-2-72k").replace(FORMAT, "sim-doctor/card-fixture/2");
        match Fixture::parse(&text) {
            Err(FixtureError::UnknownFormat { found, supported }) => {
                assert_eq!(found, "sim-doctor/card-fixture/2");
                assert_eq!(supported, FORMAT);
                let message = FixtureError::UnknownFormat { found, supported }.to_string();
                assert!(
                    message.contains("refuses rather than guessing"),
                    "{message}"
                );
            }
            other => panic!("a v2 document must be refused, not read as v1: {other:?}"),
        }
    }

    #[test]
    fn a_corrupt_fixture_is_refused_with_the_parse_error() {
        for corrupt in [
            "",
            "not json at all",
            "{\"format\":",
            "[]",
            "42",
            "{\"format\":\"sim-doctor/card-fixture/1\",}",
        ] {
            match Fixture::parse(corrupt) {
                Err(FixtureError::NotJson(_)) => {}
                Err(FixtureError::MalformedValue { field, .. }) => assert_eq!(field, "fixture"),
                other => panic!("{corrupt:?} must be refused, not read: {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let mut value = document("gemalto-top-im-gx4");
        value["surprise"] = serde_json::json!(7);
        match reparse(&value) {
            Err(FixtureError::UnknownKey { field, supported }) => {
                assert_eq!(field, "surprise");
                assert_eq!(supported, FORMAT);
            }
            other => panic!("an unknown key must be refused: {other:?}"),
        }
        let mut nested = document("gemalto-top-im-gx4");
        nested["profile"]["surprise"] = serde_json::json!(7);
        assert!(matches!(
            reparse(&nested),
            Err(FixtureError::UnknownKey { .. })
        ));
    }

    #[test]
    fn a_missing_required_field_is_refused_by_name() {
        for (key, path) in [
            ("read_on", "read_on"),
            ("cla", "cla"),
            ("sel_ctrl", "sel_ctrl"),
        ] {
            let mut value = document("athena-idprotect");
            value
                .as_object_mut()
                .expect("the document is an object")
                .remove(key);
            match reparse(&value) {
                Err(FixtureError::MissingField(field)) => assert_eq!(field, path),
                other => panic!("a fixture with no {key} must be refused: {other:?}"),
            }
        }
        let mut unnamed = document("athena-idprotect");
        unnamed["profile"]
            .as_object_mut()
            .expect("the profile is an object")
            .remove("name");
        match reparse(&unnamed) {
            Err(FixtureError::MissingField(field)) => assert_eq!(field, "profile.name"),
            other => panic!("a fixture with no profile.name must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_byte_field_is_refused() {
        for (key, bad) in [
            ("cla", "0"),
            ("cla", "zz"),
            ("cla", "000"),
            ("sel_ctrl", "00"),
        ] {
            let mut value = document("oberthur-cosmo-v7-128k");
            value[key] = serde_json::json!(bad);
            match reparse(&value) {
                Err(FixtureError::MalformedValue {
                    field, value: got, ..
                }) => {
                    assert_eq!(field, key);
                    assert!(
                        got.contains(bad),
                        "the refusal has to quote the value: {got}"
                    );
                }
                other => panic!("{key} = {bad:?} must be refused: {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_listing_is_refused() {
        let mut value = document("smartcafe-expert-3-2-72k");
        value["profile"]["listing"] = serde_json::json!("supported-ish");
        match reparse(&value) {
            Err(FixtureError::MalformedValue { field, .. }) => {
                assert_eq!(field, "profile.listing")
            }
            other => panic!("an unrecognised listing must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_fixture_with_no_provenance_is_refused() {
        let mut value = document("gemalto-idcore-3010-cc");
        value["provenance"] = serde_json::json!([]);
        match reparse(&value) {
            Err(FixtureError::NoProvenance) => {}
            other => panic!("a fixture with no provenance must be refused: {other:?}"),
        }
        let mut missing = document("gemalto-idcore-3010-cc");
        missing
            .as_object_mut()
            .expect("the document is an object")
            .remove("provenance");
        assert!(matches!(
            reparse(&missing),
            Err(FixtureError::MissingField("provenance"))
        ));
    }

    #[test]
    fn a_provenance_line_of_zero_or_less_is_refused() {
        for bad in [0, -1] {
            let mut value = document("feitian-javacos-a22");
            value["provenance"][0]["line"] = serde_json::json!(bad);
            match reparse(&value) {
                Err(FixtureError::BadProvenanceLine { index, line }) => {
                    assert_eq!(index, 0);
                    assert_eq!(line, bad);
                    let message = FixtureError::BadProvenanceLine { index, line }.to_string();
                    assert!(message.contains("starts at 1"), "{message}");
                }
                other => panic!("line {bad} is not a line: {other:?}"),
            }
        }
        let mut text = document("feitian-javacos-a22");
        text["provenance"][0]["line"] = serde_json::json!("eleven");
        assert!(matches!(
            reparse(&text),
            Err(FixtureError::MalformedValue {
                field: "provenance.line",
                ..
            })
        ));
    }

    #[test]
    fn a_provenance_record_without_its_sentence_is_refused() {
        let mut value = document("smartcafe-expert-3-2-72k");
        value["provenance"][0]
            .as_object_mut()
            .expect("a provenance record is an object")
            .remove("asserts");
        match reparse(&value) {
            Err(FixtureError::MissingField(field)) => assert_eq!(field, "provenance.asserts"),
            other => panic!("a record with no sentence says nothing: {other:?}"),
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        for profile in PROFILES {
            assert_eq!(
                profile.render().expect("serialises"),
                profile.render().expect("serialises"),
                "{} rendered twice into different bytes",
                profile.name
            );
            assert_eq!(
                profile.render_pretty().expect("serialises"),
                profile.render_pretty().expect("serialises")
            );
        }
    }

    #[test]
    fn a_generated_fixture_reparses_to_the_same_profile() {
        for profile in PROFILES {
            let parsed = Fixture::parse(&rendered(profile.name))
                .unwrap_or_else(|err| panic!("{} must read back: {err}", profile.name));
            assert!(
                parsed.matches_profile(profile),
                "{} does not survive its own generator",
                profile.name
            );
            assert_eq!(parsed.cla, CLA_DEFAULT);
            assert_eq!(parsed.sel_ctrl, SEL_CTRL_DEFAULT);
            assert_eq!(
                parsed.provenance.len(),
                profile.provenance().len() + PROFILE_FIELDS.len() + DEFAULT_PROVENANCE.len() + 1,
                "{} lost or gained a provenance record on the way through",
                profile.name
            );
        }
    }

    #[test]
    fn the_generated_document_declares_its_format_and_its_date() {
        for profile in PROFILES {
            let text = rendered(profile.name);
            let prefix = format!("{{\"format\":\"{FORMAT}\",\"read_on\":\"{READ_ON}\"");
            assert!(
                text.starts_with(&prefix),
                "{} must open with its format and the date it was read",
                profile.name
            );
            let parsed = Fixture::parse(&text).expect("reads back");
            assert_eq!(parsed.format, FORMAT);
            assert_eq!(parsed.read_on, READ_ON);
        }
    }

    #[test]
    fn a_fixture_read_on_another_day_is_readable_and_reports_its_date() {
        // Not a refusal: an older or newer document is still a document. Refusing it
        // would mean this crate only trusts its own output, and quietly re-dating it
        // would be worse.
        let text = rendered("gemalto-top-im-fips-cy2").replace(READ_ON, "2027-01-01");
        let row = find("gemalto-top-im-fips-cy2").expect("a row in the table");
        let parsed = Fixture::parse(&text).expect("a document from another day still reads");
        assert_eq!(
            parsed.read_on, "2027-01-01",
            "the date has to be reported as read"
        );
        assert!(
            parsed.matches_row(row),
            "every other field still says the same row: only the date moved"
        );
        assert!(
            !parsed.matches_profile(row),
            "and it is not a document this build read, which the date has to show"
        );
    }

    #[test]
    fn an_unknown_profile_is_not_in_the_table() {
        assert!(find("no-such-card").is_none());
        assert!(find("").is_none());
        assert!(find("FaketmagicSim").is_none());
    }

    #[test]
    fn the_human_table_names_every_profile_and_says_what_it_is_not() {
        let text = table();
        for profile in PROFILES {
            assert!(
                text.contains(profile.name),
                "the table does not mention {}",
                profile.name
            );
        }
        assert!(text.contains(NOT_A_FILE_LIST));
        assert!(text.contains(READ_ON), "the table has to carry its date");
    }

    #[test]
    fn the_detail_block_cites_every_record_it_carries() {
        for profile in PROFILES {
            let text = detail(profile);
            // Every provenance record and every note is cited, and the block cites the
            // reference twice more on purpose: once for the heading the entry sits
            // under, once inside the staleness sentence.
            assert_eq!(
                text.matches(TESTED_CARDS).count(),
                profile.provenance().len() + profile.notes.len() + 2,
                "{}'s detail block must cite every provenance record and every note",
                profile.name
            );
            assert!(
                text.contains(&format!("{}:{}", TESTED_CARDS, profile.entry_line())),
                "{}'s detail block must name its listing line",
                profile.name
            );
            assert!(text.contains(READ_ON));
            assert!(text.contains(FORMAT));
        }
    }

    #[test]
    fn the_json_carries_the_provenance_of_every_entry() {
        let value = catalogue();
        let profiles = value["profiles"]
            .as_array()
            .expect("the catalogue carries an array of profiles");
        assert_eq!(profiles.len(), PROFILES.len());
        for (entry, profile) in profiles.iter().zip(PROFILES) {
            let claims = entry["provenance"]
                .as_array()
                .expect("every entry carries its provenance");
            assert_eq!(claims.len(), profile.provenance().len());
            for (claim, expected) in claims.iter().zip(profile.provenance()) {
                assert_eq!(claim["source"], expected.source);
                assert_eq!(claim["line"], expected.line);
                assert_eq!(claim["asserts"], expected.asserts);
                assert!(!claim["asserts"].as_str().unwrap_or("").is_empty());
            }
            assert_eq!(entry["listing_line"], profile.entry_line());
        }
        assert_eq!(value["format"], FORMAT);
        assert_eq!(value["read_on"], READ_ON);
        assert_eq!(
            value["schema"]["fields"].as_array().map(Vec::len),
            Some(PROFILE_FIELDS.len())
        );
    }
}
