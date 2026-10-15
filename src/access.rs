//! Access conditions and PIN status, decoded from what a SELECT already says.
//!
//! **Owns.** Reading a file's security attributes - the compact (`8C`),
//! expanded (`AB`) and referenced (`8B`) forms - and the PIN status template
//! (`C6`) out of the raw values [`crate::walk`] kept, and the one read-only
//! step that makes the referenced form decodable: READ RECORD of EF.ARR.
//!
//! **Does not own.** The rules that judge what was decoded
//! ([`crate::scan`]), or the tag table ([`crate::fcp`]).
//!
//! # Sources, all ETSI TS 102 221 V17.0.0 (2021-10) unless stated
//!
//! - clause 9.2.5 and E.2: compact format. An AM byte, then one SC byte per
//!   bit set in b7..b1, in order b7 to b1. Several AM+SC groups are an OR.
//!   `b8 = 1` makes b7..b4 proprietary, so such a group is not read.
//! - clause 9.2.6 and E.3: expanded format. An AM_DO (tag `80` carries an AM
//!   byte) followed by SC_DOs; tags `81`..`8F` describe commands and are not
//!   read here. SC_DO tags are `90` ALW and `97` NEV (table 9.3), `A4` a user
//!   authentication (a key reference, so a PIN or ADM), `A0` an OR template
//!   and `AF` an AND template (clause E.3.2 and ISO/IEC 7816-4).
//! - clause 9.2.7 and 11.1.1.4.7.3: `8B` is EF.ARR file ID plus record number,
//!   or the file ID followed by SE ID and record number pairs. EF.ARR is found
//!   in the DF holding the file, then its parents up to the MF.
//! - AM byte bits for an EF: b1 READ (and SEARCH), b2 UPDATE. Read from the
//!   worked examples in clauses 9.2.5, E.2.3 and annex F/G (`01` READ, `02`
//!   UPDATE, `03` both); bits not set in the AM byte are NEVer (clause 9.2.2).
//! - clause 9.5.2 and 11.1.1.4.10: the PIN status template `C6` is a PS_DO
//!   (`90`, a bitmap whose b8 is the first following key reference), then key
//!   references (`83`), each optionally preceded by a usage qualifier (`95`).
//!   Qualifier b5 (`08`) is "use the PIN for verification". Key reference `01`
//!   is PIN Appl 1 and `11` the universal PIN (table 9.3).
//!
//! # What is not decoded
//!
//! AM_DOs other than tag `80`, the proprietary AM forms, and any SC_DO that is
//! not ALW or NEV (these are "restricted": something must be satisfied, and
//! this module does not say what). A file whose attributes do not decode has
//! no [`Access`], and a rule must treat that as "not known", never as clean.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "access";

use crate::apdu::{Command, Header, Le, StatusWord};
use crate::fs::{self, Path};
use crate::session::{self, Policy};
use crate::tlv::{Stream, Tlv};
use crate::transport::CardSession;
use crate::walk::{self, Node, Tree};

/// How deep an OR/AND template may nest before it is called restricted.
const MAX_TEMPLATE_DEPTH: usize = 4;

/// The most records of one EF.ARR this module reads. READ RECORD addresses
/// records 1 to 254 in P1.
const MAX_ARR_RECORDS: usize = 254;

const AM_READ: u8 = 0b01;
const AM_UPDATE: u8 = 0b10;

/// What a security condition demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// ALWays: no verification is needed.
    Always,
    /// NEVer.
    Never,
    /// Something must be satisfied (a PIN, ADM, a secure channel), or this
    /// module cannot say what.
    Restricted,
}

impl Condition {
    /// The spelling evidence uses.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Always => "ALW",
            Self::Never => "NEV",
            Self::Restricted => "restricted",
        }
    }

    /// All must hold: any NEV wins, all ALW is ALW, otherwise restricted.
    fn and(conditions: impl IntoIterator<Item = Self>) -> Self {
        let all: Vec<Self> = conditions.into_iter().collect();
        if all.is_empty() {
            Self::Restricted
        } else if all.contains(&Self::Never) {
            Self::Never
        } else if all.iter().all(|c| *c == Self::Always) {
            Self::Always
        } else {
            Self::Restricted
        }
    }

    /// One must hold: any ALW wins, all NEV is NEV, otherwise restricted.
    fn or(conditions: impl IntoIterator<Item = Self>) -> Self {
        let all: Vec<Self> = conditions.into_iter().collect();
        if all.is_empty() {
            Self::Restricted
        } else if all.contains(&Self::Always) {
            Self::Always
        } else if all.iter().all(|c| *c == Self::Never) {
            Self::Never
        } else {
            Self::Restricted
        }
    }

    /// What holds whichever of several rules applies: ALW only if every one
    /// is, NEV only if every one is.
    fn across(conditions: impl IntoIterator<Item = Self>) -> Self {
        let all: Vec<Self> = conditions.into_iter().collect();
        if !all.is_empty() && all.iter().all(|c| *c == Self::Always) {
            Self::Always
        } else if !all.is_empty() && all.iter().all(|c| *c == Self::Never) {
            Self::Never
        } else {
            Self::Restricted
        }
    }
}

/// The READ and UPDATE conditions of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// READ (and SEARCH) of the file.
    pub read: Condition,
    /// UPDATE of the file.
    pub update: Condition,
}

impl Access {
    fn across(rules: &[Self]) -> Self {
        Self {
            read: Condition::across(rules.iter().map(|a| a.read)),
            update: Condition::across(rules.iter().map(|a| a.update)),
        }
    }
}

/// A readable name for a security condition, for the per-file `desc` text.
///
/// pySim (and this crate's `pin_names`) names the keys a condition may wait
/// on; this keeps that same naming so the `desc` output reads like pySim, e.g.
/// `READ: PIN1, UPDATE: ADM1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCond {
    /// No verification: the `90` always condition.
    Always,
    /// Never: the `97` never condition.
    Never,
    /// A key (PIN/ADM/etc.) the condition waits on, named from table 9.3.
    Key(u8),
    /// Something must hold that is not a named key (a secure channel, a
    /// proprietary SC_DO, an unread rule).
    Restricted,
}

impl KeyCond {
    /// The readable spelling pySim uses: `ALW`, `NEV`, the key name, or
    /// `restricted`.
    fn text(self) -> String {
        match self {
            Self::Always => "ALW".to_owned(),
            Self::Never => "NEV".to_owned(),
            Self::Key(key) => pin_key_name(key)
                .map(|n| n.to_owned())
                .unwrap_or_else(|| format!("restricted (key ref {key:02X})")),
            Self::Restricted => "restricted".to_owned(),
        }
    }

    /// Folds two alternative conditions (an OR): ALW wins, all NEV is NEV,
    /// otherwise restricted; a key is kept only when both sides name it.
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Always, _) | (_, Self::Always) => Self::Always,
            (Self::Never, Self::Never) => Self::Never,
            (Self::Key(k), Self::Key(j)) if k == j => Self::Key(k),
            _ => Self::Restricted,
        }
    }

    /// Folds two conditions that must both hold (an AND): NEV wins, both ALW
    /// is ALW, a key is kept only when both sides name the same one.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Never, _) | (_, Self::Never) => Self::Never,
            (Self::Always, Self::Always) => Self::Always,
            (Self::Key(k), Self::Key(j)) if k == j => Self::Key(k),
            _ => Self::Restricted,
        }
    }
}

/// The readable name of a key reference, matching pySim's `pin_names`
/// (TS 102 221 table 9.3): PIN1-PIN8, ADM1-ADM10, the universal PIN, and
/// 2PIN1-2PIN8. `None` for a reference this crate does not name.
pub fn pin_key_name(key_reference: u8) -> Option<&'static str> {
    Some(match key_reference {
        0x01 => "PIN1",
        0x02 => "PIN2",
        0x03 => "PIN3",
        0x04 => "PIN4",
        0x05 => "PIN5",
        0x06 => "PIN6",
        0x07 => "PIN7",
        0x08 => "PIN8",
        0x0A => "ADM1",
        0x0B => "ADM2",
        0x0C => "ADM3",
        0x0D => "ADM4",
        0x0E => "ADM5",
        0x11 => "UNIVERSAL_PIN",
        0x81 => "2PIN1",
        0x82 => "2PIN2",
        0x83 => "2PIN3",
        0x84 => "2PIN4",
        0x85 => "2PIN5",
        0x86 => "2PIN6",
        0x87 => "2PIN7",
        0x88 => "2PIN8",
        0x8A => "ADM6",
        0x8B => "ADM7",
        0x8C => "ADM8",
        0x8D => "ADM9",
        0x8E => "ADM10",
        _ => return None,
    })
}

/// The access-condition text a file's FCP carries, decoded from whatever
/// security attributes the SELECT response contained: the compact form (`8C`),
/// the expanded form (`AB`), or the referenced form (`8B`). The referenced
/// form only names the EF.ARR and record it points at, because reading those
/// records is a card exchange this offline decoder does not perform; a caller
/// that wants the full rule resolves the reference with [`resolve`] first.
///
/// Returns `None` when the FCP states no security attributes this module can
/// decode, i.e. the access is not known from the SELECT response alone.
pub fn fcp_access_text(body: &[u8], dialect: &crate::fcp::TagSet) -> Option<String> {
    let template = crate::fcp::Template::parse(body, dialect).ok()?;
    // `8B` (referenced): a pointer to EF.ARR records.
    if let Some(reference) = template.security_reference() {
        if let Some(arr) = parse_arr_ref(reference) {
            let file = format!("{:04X}", u16::from_be_bytes(arr.file));
            let records = arr
                .records
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",");
            return Some(format!(
                "READ/UPDATE: referenced to EF.ARR {file} record(s) {records}"
            ));
        }
        return Some("READ/UPDATE: restricted (EF.ARR reference undecoded)".to_owned());
    }
    // `AB` (expanded): the rule is inline, so it decodes fully.
    if let Some(expanded) = template.security_expanded() {
        return Some(expanded_access_text(expanded));
    }
    // `8C` (compact): the rule is inline.
    if let Ok(Some(conditions)) = template.access_conditions() {
        return Some(compact_access_text(conditions.octets()));
    }
    None
}

/// Renders the expanded (`AB` / EF.ARR-record) form to text like
/// `READ: PIN1, UPDATE: ADM1`.
fn expanded_access_text(bytes: &[u8]) -> String {
    let access = parse_expanded_rule(bytes).unwrap_or((KeyCond::Restricted, KeyCond::Restricted));
    format!("READ: {}, UPDATE: {}", access.0.text(), access.1.text())
}

/// Decodes one expanded access rule (clause 9.2.6, E.3) into named conditions.
/// Trailing `FF` padding is ignored. Returns (read, update).
fn parse_expanded_rule(bytes: &[u8]) -> Option<(KeyCond, KeyCond)> {
    let end = bytes.iter().rposition(|b| *b != 0xFF)? + 1;
    let atoms = Stream::new(&bytes[..end]).collect_atoms().ok()?;
    Some(rule_conditions(&atoms))
}

/// Walks AM_DO/SC_DO atoms in wire order, AND-ing the SC_DOs within each
/// command set and OR-ing across command sets (clause E.3.2). A command
/// description AM_DO (tag `81`-`8F`) that is not a recognized AM byte makes the
/// result "restricted", never NEV.
fn rule_conditions(atoms: &[Tlv<'_>]) -> (KeyCond, KeyCond) {
    let mut reads = Vec::new();
    let mut updates = Vec::new();
    let mut current_am: Option<u8> = None;
    let mut current_conds: Vec<KeyCond> = Vec::new();
    let mut unread = false;
    for atom in atoms {
        let tag = atom.tag().octet();
        if (0x80..=0x8F).contains(&tag) {
            // Flush the previous command set.
            if let Some(am) = current_am {
                let cond = fold_conditions(&current_conds);
                if am & AM_READ != 0 {
                    reads.push(cond);
                }
                if am & AM_UPDATE != 0 {
                    updates.push(cond);
                }
            }
            let am = match (tag, atom.value()) {
                (0x80, [b]) if b & 0x80 == 0 => Some(*b),
                _ => None,
            };
            if am.is_none() {
                unread = true;
            }
            current_am = am;
            current_conds = Vec::new();
        } else {
            current_conds.push(condition_key_of(atom, 0));
        }
    }
    // Flush the last command set.
    if let Some(am) = current_am {
        let cond = fold_conditions(&current_conds);
        if am & AM_READ != 0 {
            reads.push(cond);
        }
        if am & AM_UPDATE != 0 {
            updates.push(cond);
        }
    }
    let settle = |c: KeyCond| {
        if unread && c == KeyCond::Never {
            KeyCond::Restricted
        } else {
            c
        }
    };
    (settle(fold_keys(&reads)), settle(fold_keys(&updates)))
}

/// AND-folds a list of conditions within one command set.
fn fold_conditions(conds: &[KeyCond]) -> KeyCond {
    conds
        .iter()
        .copied()
        .reduce(KeyCond::and)
        .unwrap_or(KeyCond::Restricted)
}

/// OR-folds the conditions that apply to one operation across command sets.
fn fold_keys(conds: &[KeyCond]) -> KeyCond {
    conds
        .iter()
        .copied()
        .reduce(KeyCond::or)
        .unwrap_or(KeyCond::Never)
}

/// Maps one SC_DO to a [`KeyCond`], extracting the key reference from an `A4`
/// control-reference template.
fn condition_key_of(sc: &Tlv<'_>, depth: usize) -> KeyCond {
    match (sc.tag().octet(), sc.value()) {
        (0x90, []) => KeyCond::Always,
        (0x97, []) => KeyCond::Never,
        (0xA4, value) => key_ref_of(value).map_or(KeyCond::Restricted, KeyCond::Key),
        (0xA0 | 0xAF, inner) if depth < MAX_TEMPLATE_DEPTH => {
            let children = Stream::new(inner).collect_atoms().ok();
            match children {
                Some(children) if children.is_empty() => KeyCond::Restricted,
                Some(children) => {
                    let folded = fold_conditions(
                        &children
                            .iter()
                            .map(|c| condition_key_of(c, depth + 1))
                            .collect::<Vec<_>>(),
                    );
                    folded
                }
                None => KeyCond::Restricted,
            }
        }
        // Anything else (e.g. a `9D` secure-messaging byte, a `0x83` key-ref do
        // outside a CRT) is not a condition this crate names.
        _ => KeyCond::Restricted,
    }
}

/// The key reference byte carried by a `90 ... 83 01 <ref>` control-reference
/// template, when the template is shaped like one. `None` otherwise.
fn key_ref_of(value: &[u8]) -> Option<u8> {
    let atoms = Stream::new(value).collect_atoms().ok()?;
    for atom in atoms {
        if atom.tag().octet() == 0x83 && atom.value().len() == 1 {
            return Some(atom.value()[0]);
        }
    }
    None
}

/// Renders the compact (`8C`) form to text. The compact form (clause 9.2.5,
/// E.2) is an AM byte followed by one SC byte per set bit, in b7..b1 order;
/// several AM+SC groups are an OR. It carries no key reference, so a
/// restricted condition stays unnamed, matching pySim's `ALW`/`NEV`/`restricted`.
fn compact_access_text(bytes: &[u8]) -> String {
    let access = parse_compact(bytes).unwrap_or(Access {
        read: Condition::Restricted,
        update: Condition::Restricted,
    });
    let cond = |c: Condition| match c {
        Condition::Always => "ALW".to_owned(),
        Condition::Never => "NEV".to_owned(),
        Condition::Restricted => "restricted".to_owned(),
    };
    format!(
        "READ: {}, UPDATE: {}",
        cond(access.read),
        cond(access.update)
    )
}

/// Where a `8B` points: an EF.ARR and the record numbers in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrRef {
    /// The EF.ARR file identifier.
    pub file: [u8; 2],
    /// Record numbers, one per security environment (one when unqualified).
    pub records: Vec<u8>,
}

/// Decodes the value of tag `8B` (clause 11.1.1.4.7.3). `None` for the
/// one-octet form (an implicitly known EF.ARR) and for any other length.
pub fn parse_arr_ref(value: &[u8]) -> Option<ArrRef> {
    match value {
        [hi, lo, record] => Some(ArrRef {
            file: [*hi, *lo],
            records: vec![*record],
        }),
        [hi, lo, pairs @ ..] if !pairs.is_empty() && pairs.len() % 2 == 0 => Some(ArrRef {
            file: [*hi, *lo],
            records: pairs.chunks(2).map(|p| p[1]).collect(),
        }),
        _ => None,
    }
}

/// The EF.ARR a node's `8B` names, found the way clause 9.2.7 says: in the
/// directory holding the file, then each parent up to the MF.
pub fn arr_path(tree: &Tree, node: &Node, arr: &ArrRef) -> Option<Path> {
    let id = fs::FileId::from_bytes(arr.file);
    let mut dir = node.path().parent().or_else(|| Some(Path::master_file()));
    while let Some(current) = dir {
        if let Ok(candidate) = current.child(id) {
            if tree.at(&candidate).is_some_and(|n| n.state().is_selected()) {
                return Some(candidate);
            }
        }
        dir = current.parent();
    }
    None
}

/// The access a file's FCP states, when it states one that decodes.
///
/// `8B` needs EF.ARR to have been read by [`resolve`]; without that it is
/// `None`, which is "not known".
pub fn access_of(tree: &Tree, node: &Node) -> Option<Access> {
    let caps = node.state().capabilities()?;
    if let Some(reference) = &caps.security_reference {
        let arr = parse_arr_ref(reference)?;
        let path = arr_path(tree, node, &arr)?;
        let records = tree.access_rule_records(&path)?;
        let rules: Option<Vec<Access>> = arr
            .records
            .iter()
            .map(|n| {
                let record = records.get(usize::from(*n).checked_sub(1)?)?;
                parse_expanded(record)
            })
            .collect();
        let rules = rules?;
        return (!rules.is_empty()).then(|| Access::across(&rules));
    }
    if let Some(expanded) = &caps.security_expanded {
        return parse_expanded(expanded);
    }
    caps.access_conditions
        .reported()
        .and_then(|v| parse_compact(v))
}

/// Decodes compact security attributes (`8C` value, clause 9.2.5).
pub fn parse_compact(value: &[u8]) -> Option<Access> {
    let mut index = 0;
    let (mut reads, mut updates) = (Vec::new(), Vec::new());
    while index < value.len() {
        let am = value[index];
        index += 1;
        if am & 0x80 != 0 {
            return None;
        }
        let count = (am & 0x7F).count_ones() as usize;
        let scs = value.get(index..index + count)?;
        index += count;
        let (mut read, mut update) = (Condition::Never, Condition::Never);
        let mut next = 0;
        for bit in (0..7).rev() {
            if am >> bit & 1 == 1 {
                let c = if scs[next] == 0x00 {
                    Condition::Always
                } else {
                    Condition::Restricted
                };
                next += 1;
                match 1u8 << bit {
                    AM_READ => read = c,
                    AM_UPDATE => update = c,
                    _ => {}
                }
            }
        }
        reads.push(read);
        updates.push(update);
    }
    if reads.is_empty() {
        return None;
    }
    Some(Access {
        read: Condition::or(reads),
        update: Condition::or(updates),
    })
}

/// Decodes an expanded access rule: an `AB` value or an EF.ARR record
/// (clause 9.2.6, E.3). Trailing `FF` padding is ignored.
pub fn parse_expanded(bytes: &[u8]) -> Option<Access> {
    let end = bytes.iter().rposition(|b| *b != 0xFF)? + 1;
    let atoms = Stream::new(&bytes[..end]).collect_atoms().ok()?;
    let mut sets: Vec<(Option<u8>, Vec<Tlv<'_>>)> = Vec::new();
    for atom in atoms {
        if (0x80..=0x8F).contains(&atom.tag().octet()) {
            let am = match (atom.tag().octet(), atom.value()) {
                (0x80, [am]) if am & 0x80 == 0 => Some(*am),
                _ => None,
            };
            sets.push((am, Vec::new()));
        } else {
            sets.last_mut()?.1.push(atom);
        }
    }
    let unread = sets.iter().any(|(am, _)| am.is_none());
    let (mut reads, mut updates) = (Vec::new(), Vec::new());
    for (am, scs) in &sets {
        let Some(am) = am else { continue };
        let condition = Condition::and(scs.iter().map(|sc| condition_of(sc, 0)));
        reads.push(if am & AM_READ != 0 {
            condition
        } else {
            Condition::Never
        });
        updates.push(if am & AM_UPDATE != 0 {
            condition
        } else {
            Condition::Never
        });
    }
    if reads.is_empty() {
        return None;
    }
    // A command-description AM_DO may grant what the AM byte does not, so a
    // NEV is only a NEV when nothing was left unread.
    let settle = |c: Condition| {
        if unread && c == Condition::Never {
            Condition::Restricted
        } else {
            c
        }
    };
    Some(Access {
        read: settle(Condition::or(reads)),
        update: settle(Condition::or(updates)),
    })
}

fn condition_of(sc: &Tlv<'_>, depth: usize) -> Condition {
    match (sc.tag().octet(), sc.value()) {
        (0x90, []) => Condition::Always,
        (0x97, []) => Condition::Never,
        (tag @ (0xA0 | 0xAF), inner) if depth < MAX_TEMPLATE_DEPTH => {
            let Ok(children) = Stream::new(inner).collect_atoms() else {
                return Condition::Restricted;
            };
            let parts = children.iter().map(|c| condition_of(c, depth + 1));
            if tag == 0xA0 {
                Condition::or(parts)
            } else {
                Condition::and(parts)
            }
        }
        _ => Condition::Restricted,
    }
}

/// One PIN a directory's PIN status template lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinEntry {
    /// The key reference (table 9.3): `01` is PIN Appl 1, `11` the universal PIN.
    pub key_reference: u8,
    /// Whether the PS_DO bitmap marks it enabled.
    pub enabled: bool,
    /// The usage qualifier that preceded it, when one did.
    pub usage_qualifier: Option<u8>,
}

/// Decodes the value of the PIN status template DO `C6` (clause 11.1.1.4.10).
/// `None` when it is not a PS_DO followed by well-formed key references.
pub fn parse_pin_status(value: &[u8]) -> Option<Vec<PinEntry>> {
    let atoms = Stream::new(value).collect_atoms().ok()?;
    let (first, rest) = atoms.split_first()?;
    if first.tag().octet() != 0x90 {
        return None;
    }
    let bitmap = first.value();
    let mut entries = Vec::new();
    let mut qualifier = None;
    for atom in rest {
        match (atom.tag().octet(), atom.value()) {
            (0x95, [q]) => qualifier = Some(*q),
            (0x83, [key]) => {
                let index = entries.len();
                let enabled = *bitmap.get(index / 8)? >> (7 - index % 8) & 1 == 1;
                entries.push(PinEntry {
                    key_reference: *key,
                    enabled,
                    usage_qualifier: qualifier.take(),
                });
            }
            _ => return None,
        }
    }
    Some(entries)
}

/// Whether PIN Appl 1 (key reference `01`) is listed and disabled, with no
/// enabled universal PIN (`11`) in use in its place (clause 9.3.1, table 9.0d).
/// `None` when the template does not list PIN Appl 1.
pub fn pin1_disabled(entries: &[PinEntry]) -> Option<bool> {
    let pin1 = entries.iter().find(|e| e.key_reference == 0x01)?;
    let universal_in_use = entries.iter().any(|e| {
        e.key_reference == 0x11 && e.enabled && e.usage_qualifier.is_some_and(|q| q & 0x08 != 0)
    });
    Some(!pin1.enabled && !universal_in_use)
}

/// Reads every EF.ARR a selected file's `8B` names, once each, so that
/// [`access_of`] can decode the references. Sends only SELECT and READ RECORD.
///
/// A short or refused read leaves that file's remaining records unread, and
/// the files that point at them undecoded: unknown, not clean.
///
/// # Errors
///
/// Whatever [`session::send`] returns.
pub fn resolve<S: CardSession + ?Sized>(
    session: &mut S,
    tree: &mut Tree,
    policy: &Policy,
) -> Result<(), session::Error> {
    let mut wanted: Vec<Path> = Vec::new();
    for node in tree.selected() {
        let Some(reference) = node
            .state()
            .capabilities()
            .and_then(|c| c.security_reference.as_deref())
            .and_then(parse_arr_ref)
        else {
            continue;
        };
        if let Some(path) = arr_path(tree, node, &reference) {
            if !wanted.contains(&path) {
                wanted.push(path);
            }
        }
    }
    for path in wanted {
        let Some(shape) = tree
            .at(&path)
            .and_then(|n| n.state().capabilities())
            .and_then(|c| c.descriptor.reported())
            .and_then(|d| match d.octets.as_slice() {
                [_, _, hi, lo, count, ..] => Some((u16::from_be_bytes([*hi, *lo]), *count)),
                _ => None,
            })
        else {
            continue;
        };
        let records = read_records(session, &path, shape, policy)?;
        tree.record_access_rules(path, records);
    }
    Ok(())
}

/// SELECTs `path` (under an application: SELECT by AID, then by path from it).
/// The inner `Err` is the refusing status word, when there was one.
pub(crate) fn select_file<S: CardSession + ?Sized>(
    session: &mut S,
    path: &Path,
    policy: &Policy,
) -> Result<Result<(), Option<StatusWord>>, session::Error> {
    for command in walk::select_commands(walk::Addressing::PathFromMasterFile, path) {
        let select = session::send(session, &command, policy)?;
        if !select.status().is_some_and(|s| s.is_normal_processing()) {
            return Ok(Err(select.status()));
        }
    }
    Ok(Ok(()))
}

fn read_records<S: CardSession + ?Sized>(
    session: &mut S,
    path: &Path,
    (length, count): (u16, u8),
    policy: &Policy,
) -> Result<Vec<Vec<u8>>, session::Error> {
    let mut records = Vec::new();
    let Some(le) = Le::for_byte_count(u32::from(length)).filter(|_| length > 0) else {
        return Ok(records);
    };
    if select_file(session, path, policy)?.is_err() {
        return Ok(records);
    }
    for number in 1..=usize::from(count).min(MAX_ARR_RECORDS) {
        // `number` is at most 254 here.
        let header = Header::new(0x00, 0xB2, u8::try_from(number).unwrap_or(0xFF), 0x04);
        let read = session::send(session, &Command::case2(header, le), policy)?;
        if !read.status().is_some_and(|s| s.is_normal_processing()) {
            break;
        }
        records.push(read.data().to_vec());
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fcp::TagSet;

    #[test]
    fn expanded_rule_read_always_update_adm() {
        // ETSI TS 102 221 annex F: READ ALW, UPDATE/DEACTIVATE/ACTIVATE level 5.
        let rule = [
            0x80, 0x01, 0x01, 0x90, 0x00, 0x80, 0x01, 0x1A, 0xA4, 0x06, 0x83, 0x01, 0x0A, 0x95,
            0x01, 0x08, 0xFF, 0xFF,
        ];
        let access = parse_expanded(&rule).unwrap();
        assert_eq!(access.read, Condition::Always);
        assert_eq!(access.update, Condition::Restricted);
    }

    #[test]
    fn expanded_or_template_with_always_is_always() {
        let rule = [0x80, 0x01, 0x02, 0xA0, 0x04, 0xA4, 0x00, 0x90, 0x00];
        let access = parse_expanded(&rule).unwrap();
        assert_eq!(access.update, Condition::Always);
        assert_eq!(access.read, Condition::Never);
    }

    #[test]
    fn an_unread_command_description_never_reads_as_never() {
        let rule = [0x80, 0x01, 0x01, 0x90, 0x00, 0x84, 0x01, 0x32, 0x90, 0x00];
        assert_eq!(parse_expanded(&rule).unwrap().update, Condition::Restricted);
    }

    #[test]
    fn compact_examples_from_the_spec() {
        // 8C 03: AM 03 SC 00 00 is ALW for READ and UPDATE (clause E.2.3).
        let both = parse_compact(&[0x03, 0x00, 0x00]).unwrap();
        assert_eq!(
            (both.read, both.update),
            (Condition::Always, Condition::Always)
        );
        // AM 03 SC 10 00: UPDATE by PIN (b2 first? SCs follow b7..b1, so b2 then b1).
        let pin = parse_compact(&[0x03, 0x10, 0x00]).unwrap();
        assert_eq!(
            (pin.read, pin.update),
            (Condition::Always, Condition::Restricted)
        );
        assert_eq!(parse_compact(&[0x81, 0x00]), None);
        assert_eq!(parse_compact(&[0x03, 0x00]), None);
    }

    #[test]
    fn arr_references() {
        assert_eq!(
            parse_arr_ref(&[0x2F, 0x06, 0x03]),
            Some(ArrRef {
                file: [0x2F, 0x06],
                records: vec![3]
            })
        );
        assert_eq!(
            parse_arr_ref(&[0x6F, 0x06, 0x00, 0x01, 0x01, 0x02])
                .unwrap()
                .records,
            vec![1, 2]
        );
        assert_eq!(parse_arr_ref(&[0x03]), None);
    }

    #[test]
    fn pin_status_bitmap_pairs_with_key_references() {
        // PS_DO 80: first key reference enabled; 95 08 then 83 11 universal.
        let value = [
            0x90, 0x01, 0x80, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x83, 0x01, 0x11,
        ];
        let entries = parse_pin_status(&value).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].enabled && !entries[1].enabled);
        assert_eq!(pin1_disabled(&entries), Some(false));
        let off = parse_pin_status(&[0x90, 0x01, 0x00, 0x83, 0x01, 0x01]).unwrap();
        assert_eq!(pin1_disabled(&off), Some(true));
        assert_eq!(parse_pin_status(&[0x83, 0x01, 0x01]), None);
    }

    /// Wraps atoms in a `62` FCP template body, as a SELECT response would.
    fn fcp_wrap(atoms: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x62);
        let len = atoms.concat().len();
        body.push(u8::try_from(len).unwrap());
        body.extend(atoms.concat());
        body
    }

    /// One BER-TLV atom: `tag len body`.
    fn atom(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn fcp_access_text_decodes_the_compact_8c_form() {
        // 8C 03: AM 03 (READ+UPDATE) SC 00 00 -> ALW for both (clause E.2.3).
        let fcp = fcp_wrap(&[atom(0x8C, &[0x03, 0x00, 0x00])]);
        assert_eq!(
            fcp_access_text(&fcp, &TagSet::ts_102_221()),
            Some("READ: ALW, UPDATE: ALW".to_owned())
        );
        // 8C 03: AM 03 SC 10 00 -> READ ALW, UPDATE restricted.
        let fcp = fcp_wrap(&[atom(0x8C, &[0x03, 0x10, 0x00])]);
        assert_eq!(
            fcp_access_text(&fcp, &TagSet::ts_102_221()),
            Some("READ: ALW, UPDATE: restricted".to_owned())
        );
    }

    #[test]
    fn fcp_access_text_decodes_the_expanded_ab_form_to_named_keys() {
        // AB: READ PIN1 (AM_READ, A4 83 01 01), UPDATE ADM1 (AM_UPDATE, A4 83 01 0A).
        let rule = [
            0x80, 0x01, 0x01, 0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,
            0xA4, 0x06, 0x83, 0x01, 0x0A, 0x95, 0x01, 0x08,
        ];
        let fcp = fcp_wrap(&[atom(0xAB, &rule)]);
        assert_eq!(
            fcp_access_text(&fcp, &TagSet::ts_102_221()),
            Some("READ: PIN1, UPDATE: ADM1".to_owned())
        );
        // AB: READ ALW, UPDATE ALW.
        let rule = [0x80, 0x01, 0x03, 0x90, 0x00];
        let fcp = fcp_wrap(&[atom(0xAB, &rule)]);
        assert_eq!(
            fcp_access_text(&fcp, &TagSet::ts_102_221()),
            Some("READ: ALW, UPDATE: ALW".to_owned())
        );
        // AB: READ ALW, UPDATE NEV.
        let rule = [0x80, 0x01, 0x01, 0x90, 0x00, 0x80, 0x01, 0x02, 0x97, 0x00];
        let fcp = fcp_wrap(&[atom(0xAB, &rule)]);
        assert_eq!(
            fcp_access_text(&fcp, &TagSet::ts_102_221()),
            Some("READ: ALW, UPDATE: NEV".to_owned())
        );
    }

    #[test]
    fn fcp_access_text_referenced_8b_names_the_ef_arr_target() {
        // 8B -> EF.ARR 6F06, record 2.
        let fcp = fcp_wrap(&[atom(0x8B, &[0x6F, 0x06, 0x02])]);
        let text = fcp_access_text(&fcp, &TagSet::ts_102_221());
        assert_eq!(
            text,
            Some("READ/UPDATE: referenced to EF.ARR 6F06 record(s) 2".to_owned())
        );
    }

    #[test]
    fn fcp_access_text_none_when_no_security_attributes() {
        // A file descriptor with no access-condition atoms.
        let fcp = fcp_wrap(&[atom(0x80, &[0x02, 0x00, 0x09])]);
        assert_eq!(fcp_access_text(&fcp, &TagSet::ts_102_221()), None);
    }

    #[test]
    fn pin_key_names_match_py_sim_table_9_3() {
        // Verifiably mapped key references.
        assert_eq!(pin_key_name(0x01), Some("PIN1"));
        assert_eq!(pin_key_name(0x02), Some("PIN2"));
        assert_eq!(pin_key_name(0x0A), Some("ADM1"));
        assert_eq!(pin_key_name(0x0E), Some("ADM5"));
        assert_eq!(pin_key_name(0x11), Some("UNIVERSAL_PIN"));
        assert_eq!(pin_key_name(0x81), Some("2PIN1"));
        assert_eq!(pin_key_name(0x8E), Some("ADM10"));
        // Outside the assigned table: unnamed.
        assert_eq!(pin_key_name(0x00), None);
        assert_eq!(pin_key_name(0x9F), None);
    }

    #[test]
    fn an_enabled_universal_pin_in_use_covers_a_disabled_pin1() {
        let value = [
            0x90, 0x01, 0x40, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x83, 0x01, 0x11,
        ];
        let entries = parse_pin_status(&value).unwrap();
        assert_eq!(pin1_disabled(&entries), Some(false));
    }
}
