//! Card personalization / programming: a pySim-prog-style document turned into an
//! APDU sequence.
//!
//! **Owns.** The programming document format ([`Document`]), parsing and
//! validation, offline planning that turns one document into an ordered APDU
//! sequence for a supported card type, and batch-CSV planning helpers.
//!
//! **Does not own.** Opening a reader, sending bytes to a card, or the card-type
//! detection/probe logic itself (that lives in [`crate::cardprofile`],
//! [`crate::legacy`] and [`crate::sysmocom`]). This module is the offline half:
//! document in, APDU plan out.
//!
//! # The document
//!
//! A pySim-prog-style description of one card: which card type/model to program
//! and the identity and key material to write. Supported fields:
//! ICCID, IMSI, Ki, OPc, ACC, MSISDN, FPLMN, SMSC (SMSP), ePDG, P-CSCF, IMPI,
//! IMPU (plus ADM/PIN, MCC/MNC/MNC length, OP and operator name where the model
//! carries them). Fields that do not apply to the chosen type or cannot be
//! written offline are reported in `needs_live_card` rather than silently
//! dropped; writing the wrong thing to a card is worse than refusing to guess.
//!
//! # Supported card types
//!
//! Offline APDU planning is implemented for the legacy and sysmocom card families:
//! magicsim/supersim, opencells/wavemobile, grcardsim/gialer, sysmosim-gr2,
//! sysmoISIM/SIM-SJA2, sysmoISIM/SIM-SJA5, sysmoSIM-SJS1. ISIM-capable sysmocom
//! models accept ISIM fields (IMPI, IMPU, domain/ePDG, P-CSCF) as documented plan
//! steps/notes where the exact EF path/length must be confirmed on the live card.
//!
//! # Safety
//!
//! Nothing here touches a card. The plan is the exact sequence that would be
//! sent; actually sending it requires a live card, an authenticated session
//! (VERIFY ADM / CHV as the model requires) and an explicit opt-in to write
//! (dry run unless `--yes`). Key material (Ki, OPc, OP, ADM/PIN) is never
//! rendered in APDU hex in the plan output.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::aka;
use crate::legacy::{self, Secret};
use crate::sysmocom;

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "program";

/// The `kind` of a programming plan document.
pub const PLAN_KIND: &str = "sim-doctor-program-plan/1";

/// The `kind` a programming document must declare.
pub const DOC_KIND: &str = "sim-doctor-program/1";

/// Carried in every plan.
pub const WARNING: &str =
    "programming writes identity and key material to a card and is not reversible: \
the APDU sequence below is what would be sent, but sending it needs a live card, \
the correct ADM/PIN for the selected card type, and an explicit opt-in to write (dry run unless --yes)";

/// Offline-plannable card types (canonical names and aliases accepted by [`Document::card_type`]).
pub const SUPPORTED_CARD_TYPES: &[(&str, &[&str])] = &[
    ("magicsim", &["magic", "supersim", "fakemagicsim", "fake-magic-sim"]),
    ("opencells", &["opencells-sim", "wavemobile", "wavemobile-sim"]),
    ("grcardsim", &["grcard", "gialer", "gialersim"]),
    ("sysmosim-gr2", &["sysmosimgr2", "gr2"]),
    ("sysmoisim-sja2", &["sysmousim-sja2", "sja2"]),
    ("sysmoisim-sja5", &["sysmousim-sja5", "sja5"]),
    ("sysmosim-sjs1", &["sysmousim-sjs1", "sjs1"]),
];

/// Returns the canonical supported card type names, in order.
pub fn supported_card_types() -> Vec<&'static str> {
    SUPPORTED_CARD_TYPES.iter().map(|(n, _)| *n).collect()
}

/// Returns all accepted type strings (canonical + aliases), for help text.
pub fn all_card_type_names() -> Vec<&'static str> {
    let mut out = Vec::new();
    for (name, aliases) in SUPPORTED_CARD_TYPES {
        out.push(*name);
        out.extend_from_slice(aliases);
    }
    out
}

/// What went wrong while parsing or planning a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// A short, machine-stable kind.
    pub kind: &'static str,
    /// What a person reads. Never includes key material.
    pub detail: String,
}

impl Error {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for Error {}

/// One programming document: the pySim-prog-style description of a card to write.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Document {
    /// The document kind. Accepted when absent; when present must be [`DOC_KIND`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The card type/model to program (pySim-prog `-t`).
    #[serde(default, alias = "card", alias = "model")]
    pub r#type: Option<String>,
    /// ICCID, 1 to 20 decimal digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iccid: Option<String>,
    /// IMSI, 1 to 15 decimal digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imsi: Option<String>,
    /// Subscriber key Ki, 16 bytes hex (32 hex digits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ki: Option<String>,
    /// Derived operator key OPc, 16 bytes hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opc: Option<String>,
    /// Operator key OP, 16 bytes hex. Converted to OPc with Ki when needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    /// ADM / administrative PIN (model-dependent).
    #[serde(
        default,
        alias = "pin_adm",
        alias = "adm_pin",
        skip_serializing_if = "Option::is_none"
    )]
    pub adm: Option<String>,
    /// MCC, 3 decimal digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcc: Option<String>,
    /// MNC, 2 or 3 decimal digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnc: Option<String>,
    /// MNC length (2 or 3).
    #[serde(default, alias = "mnclen", skip_serializing_if = "Option::is_none")]
    pub mnc_len: Option<u8>,
    /// SMSC / SMS Service Provider record (EF.SMSP), hex.
    #[serde(default, alias = "smsc", skip_serializing_if = "Option::is_none")]
    pub smsp: Option<String>,
    /// MSISDN (digits / EF.MSISDN number). Record encoding is card/file-size dependent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msisdn: Option<String>,
    /// Access control class (EF.ACC), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acc: Option<String>,
    /// Forbidden PLMNs (EF.FPLMN), as PLMN strings `MCCMNC` or 3-byte hex entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fplmn: Option<Vec<String>>,
    /// Operator name (magic-SIM).
    #[serde(default, alias = "name", skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    /// ISIM IMPI (NAI, e.g. user@realm). Written as EF.IMPI (tag 0x80) under ADF.ISIM on ISIM-capable cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impi: Option<String>,
    /// ISIM IMPU (SIP URI / TEL URI). Written as an EF.IMPU record under ADF.ISIM on ISIM-capable cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impu: Option<String>,
    /// ISIM home network domain (EF.DOMAIN, tag 0x80) / IMS domain.
    #[serde(default, alias = "ims_domain", skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// P-CSCF address (FQDN or URI) for EF.P-CSCF under ADF.ISIM.
    #[serde(default, alias = "p_cscf", skip_serializing_if = "Option::is_none")]
    pub pcscf: Option<String>,
    /// ePDG identifier/selection (FQDN or address) for USIM/ISIM ePDG EFs (e.g. EF.ePDGId/EF.ePDGSelection).
    #[serde(default, alias = "e_pdg", alias = "epdg_id", skip_serializing_if = "Option::is_none")]
    pub epdg: Option<String>,
}

impl Document {
    /// Parses a programming document from JSON text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let doc: Self = serde_json::from_str(text).map_err(|e| {
            Error::new(
                "document-invalid",
                format!("not a valid JSON document: {e}"),
            )
        })?;
        if let Some(kind) = &doc.kind {
            if kind != DOC_KIND {
                return Err(Error::new(
                    "document-invalid",
                    format!("document kind is `{kind}`, expected `{DOC_KIND}`"),
                ));
            }
        }
        Ok(doc)
    }

    /// The normalized card type name, lowercased.
    pub fn card_type(&self) -> Result<String, Error> {
        let t = self
            .r#type
            .as_deref()
            .ok_or_else(|| {
                Error::new(
                    "document-invalid",
                    "missing `type` (the card type/model to program)",
                )
            })?
            .trim()
            .to_ascii_lowercase();
        if t.is_empty() {
            return Err(Error::new("document-invalid", "`type` is empty"));
        }
        Ok(t)
    }

    /// Resolves OPc: provided OPc, or derived from Ki+OP via milenage. Refuses on disagreement.
    pub fn resolve_opc(&self) -> Result<Option<String>, Error> {
        let opc = norm_hex_opt(self.opc.as_deref());
        let op = norm_hex_opt(self.op.as_deref());
        match (opc, op) {
            (None, None) => Ok(None),
            (Some(opc), None) => Ok(Some(opc)),
            (None, Some(op_hex)) => {
                let ki_hex = self.ki.as_deref().ok_or_else(|| {
                    Error::new("document-invalid", "`op` needs `ki` to derive OPc")
                })?;
                let ki = decode_key16("ki", ki_hex)?;
                let opk = decode_key16("op", &op_hex)?;
                let derived = aka::opc(arr16(&ki), arr16(&opk));
                Ok(Some(hex_upper(&derived)))
            }
            (Some(opc), Some(op_hex)) => {
                if let Some(ki_hex) = self.ki.as_deref() {
                    if let (Ok(ki), Ok(opk)) =
                        (decode_key16("ki", ki_hex), decode_key16("op", &op_hex))
                    {
                        let derived = aka::opc(arr16(&ki), arr16(&opk));
                        if !eq_hex(&opc, &hex_upper(&derived)) {
                            return Err(Error::new(
                                "document-invalid",
                                "`opc` and `op` (derived with `ki`) disagree",
                            ));
                        }
                    }
                }
                Ok(Some(opc))
            }
        }
    }

    /// Normalized MCC.
    pub fn normalized_mcc(&self) -> Result<Option<String>, Error> {
        let Some(mcc) = self.mcc.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        if !mcc.chars().all(|c| c.is_ascii_digit()) || mcc.len() != 3 {
            return Err(Error::new(
                "document-invalid",
                "`mcc` must be 3 decimal digits",
            ));
        }
        Ok(Some(mcc.to_owned()))
    }

    /// Normalized MNC, padded/validated against `mnc_len` when given.
    pub fn normalized_mnc(&self) -> Result<Option<String>, Error> {
        let Some(mnc) = self.mnc.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        if !mnc.chars().all(|c| c.is_ascii_digit()) || !(2..=3).contains(&mnc.len()) {
            return Err(Error::new(
                "document-invalid",
                "`mnc` must be 2 or 3 decimal digits",
            ));
        }
        let mut mnc = mnc.to_owned();
        if let Some(len) = self.mnc_len {
            if !(2..=3).contains(&len) {
                return Err(Error::new("document-invalid", "`mnc_len` must be 2 or 3"));
            }
            if (len as usize) < mnc.len() {
                return Err(Error::new(
                    "document-invalid",
                    "`mnc` is longer than `mnc_len`",
                ));
            }
            if mnc.len() < len as usize {
                mnc = format!("{:0>width$}", mnc, width = len as usize);
            }
        }
        Ok(Some(mnc))
    }
}

/// A single APDU step in a programming plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanStep {
    /// What this step does.
    pub description: String,
    /// The APDU bytes as uppercase hex. Omitted when the payload contains secret
    /// material or depends on live-card state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apdu: Option<String>,
    /// The path of file identifiers selected before this step, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    /// The field being written, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The file identifier targeted, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Notes about this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// The offline APDU plan for one programming document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// Always [`PLAN_KIND`].
    pub kind: String,
    /// The card type the plan targets.
    pub card_type: String,
    /// Supported card types (canonical names).
    pub supported_card_types: Vec<String>,
    /// [`WARNING`].
    pub warning: &'static str,
    /// True: no bytes were sent and no card was touched.
    pub card_touched: bool,
    /// The ordered APDU steps.
    pub steps: Vec<PlanStep>,
    /// What still requires a live card / cannot be completed offline.
    pub needs_live_card: Vec<String>,
    /// Fields the plan writes or accounts for (best-effort summary).
    pub writes: Vec<String>,
}

/// Plans the programming described by `text` (a JSON document).
pub fn plan_json(text: &str) -> Result<Plan, Error> {
    let doc = Document::parse(text)?;
    plan_document(&doc)
}

/// Plans the programming described by `doc`.
pub fn plan_document(doc: &Document) -> Result<Plan, Error> {
    let card_type = doc.card_type()?;
    let mcc = doc.normalized_mcc()?;
    let mnc = doc.normalized_mnc()?;
    let opc = doc.resolve_opc()?;
    validate_extra_fields(doc)?;

    let mut needs_live_card = vec![
        "A live card/reader and the correct ADM/CHV for the selected card type.".to_owned(),
        "All writes are gated behind an explicit opt-in (dry run unless --yes); sending requires an authenticated session.".to_owned(),
        "A post-write read-back/verification on the live card is required to confirm the programming (matching the reference tool).".to_owned(),
    ];
    let mut steps = Vec::new();
    let mut writes = Vec::new();

    if let Some(model) = legacy_model(&card_type) {
        let req = build_legacy_request(doc, &mcc, &mnc, opc.as_deref())?;
        let program = legacy::Program::new();
        let planned = program.plan(model, &req).map_err(|e| match e {
            legacy::Error::NothingToProgram(msg) => Error::new("nothing-to-program", msg),
            other => Error::new("plan-invalid", other.to_string()),
        })?;
        for pw in &planned {
            append_legacy_step(&mut steps, &mut needs_live_card, pw);
            let f = format!("{:?}", pw.field);
            if !writes.contains(&f) {
                writes.push(f);
            }
        }
        // Generic EF steps/notes for fields not covered by the legacy driver surface.
        add_generic_sim_fields(&mut steps, &mut needs_live_card, &mut writes, doc, false);
    } else if let Some(model) = sysmocom_model(&card_type) {
        let req = build_sysmocom_request(doc, &mcc, &mnc, opc.as_deref())?;
        let at = sysmocom::At::new();
        let planned = at.plan(model, &req).map_err(|e| match e {
            sysmocom::Error::NothingToProgram(msg) => Error::new("nothing-to-program", msg),
            other => Error::new("plan-invalid", other.to_string()),
        })?;
        for pw in &planned {
            append_sysmocom_step(&mut steps, model, pw);
            let f = format!("{:?}", pw.field);
            if !writes.contains(&f) {
                writes.push(f);
            }
        }
        // sysmocom vendor-file surface is limited; account for remaining requested fields.
        add_generic_sim_fields(&mut steps, &mut needs_live_card, &mut writes, doc, true);
        needs_live_card.push(
            "sysmocom SJA2/SJA5/SJS1 programming is performed over the AT+CSIM transport; APDUs below are the card APDUs carried inside AT+CSIM frames.".to_owned(),
        );
    } else {
        return Err(Error::new(
            "unsupported-type",
            format!(
                "card type `{card_type}` is not supported for offline APDU planning; supported types: {}",
                all_card_type_names().join(", ")
            ),
        ));
    }

    writes.sort();
    writes.dedup();

    Ok(Plan {
        kind: PLAN_KIND.to_owned(),
        card_type,
        supported_card_types: supported_card_types()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        warning: WARNING,
        card_touched: false,
        steps,
        needs_live_card,
        writes,
    })
}

fn validate_extra_fields(doc: &Document) -> Result<(), Error> {
    if let Some(msisdn) = doc.msisdn.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !msisdn.chars().all(|c| c.is_ascii_digit() || c == '+' || c == '*' || c == '#' ) {
            return Err(Error::new(
                "document-invalid",
                "`msisdn` must contain digits (and optionally +/*/#)",
            ));
        }
    }
    for (name, val) in [
        ("impi", doc.impi.as_deref()),
        ("impu", doc.impu.as_deref()),
        ("domain", doc.domain.as_deref()),
        ("pcscf", doc.pcscf.as_deref()),
        ("epdg", doc.epdg.as_deref()),
    ] {
        if let Some(v) = val.map(str::trim).filter(|s| !s.is_empty()) {
            if v.len() > 255 {
                return Err(Error::new(
                    "document-invalid",
                    format!("`{name}` is too long"),
                ));
            }
        }
    }
    Ok(())
}

fn add_generic_sim_fields(
    steps: &mut Vec<PlanStep>,
    needs: &mut Vec<String>,
    writes: &mut Vec<String>,
    doc: &Document,
    isim_capable: bool,
) {
    // MSISDN (EF.MSISDN 6F40, linear fixed record; encoding/record length card-dependent)
    if doc.msisdn.as_deref().map(str::trim).is_some_and(|s| !s.is_empty()) && !writes.iter().any(|w| w.to_lowercase().contains("msisdn")) {
        let (path, file) = if isim_capable {
            (vec!["3F00".into(), "7FFF".into(), "6F40".into()], "6F40")
        } else {
            (vec!["3F00".into(), "7F10".into(), "6F40".into()], "6F40")
        };
        steps.push(PlanStep {
            description: "UPDATE RECORD EF.MSISDN (record 1) with encoded MSISDN number".into(),
            apdu: None,
            path,
            field: Some("Msisdn".into()),
            file: Some(file.into()),
            notes: vec![
                "EF.MSISDN is linear-fixed; record length, alpha size and capability/extension ids must be read from the live card. Number is encoded per TS 31.102/51.011 (TON/NPI + BCD).".into(),
                "APDU payload may contain identity material and is omitted from the offline plan output.".into(),
            ],
        });
        needs.push("MSISDN (EF.MSISDN) requires the EF record length/alpha layout from the live card; plan shows the intended target EF and encoding rule.".into());
        writes.push("Msisdn".into());
    }
    // SMSC/SMSP may be needed on sysmocom path or if not covered
    if doc.smsp.as_deref().map(str::trim).is_some_and(|s| !s.is_empty()) && !writes.iter().any(|w| w.to_lowercase().contains("smsp") || w.to_lowercase().contains("sms")) {
        needs.push("SMSC/SMSP (EF.SMSP) programming for this card type requires the EF path/record layout on the live card (commonly 7F10/6F42 on SIM/USIM).".into());
        writes.push("Smsp".into());
    }
    // FPLMN
    if doc.fplmn.as_ref().is_some_and(|v| !v.is_empty()) {
        needs.push("FPLMN (EF.FPLMN 6F7B under DF.GSM/ADF.USIM) programming requires selecting the correct DF/ADF on the target card and writing the encoded PLMN list padded to the file length read from the card.".into());
        let path = vec!["3F00".into(), "7F20".into(), "6F7B".into()];
        steps.push(PlanStep {
            description: format!(
                "UPDATE BINARY EF.FPLMN ({} entrie(s), encoded on live card)",
                doc.fplmn.as_ref().map(|v| v.len()).unwrap_or(0)
            ),
            apdu: None,
            path,
            field: Some("Fplmn".into()),
            file: Some("6F7B".into()),
            notes: vec![
                "Encode each PLMN as 3 bytes (MCC/MNC digit coding) and pad remaining entries with FF FF FF up to the EF length reported by the card.".into(),
            ],
        });
        if !writes.iter().any(|w| w == "Fplmn") {
            writes.push("Fplmn".into());
        }
    }
    // ISIM / IMS fields
    let isim_fields: Vec<(&str, &str, &str, bool)> = vec![
        ("impi", "EF.IMPI (6F02, ADF.ISIM, transparent tag 0x80)", "6F02", doc.impi.as_deref().is_some()),
        ("domain", "EF.DOMAIN (6F03, ADF.ISIM, transparent tag 0x80)", "6F03", doc.domain.as_deref().is_some()),
        ("impu", "EF.IMPU (6F04, ADF.ISIM, linear-fixed records)", "6F04", doc.impu.as_deref().is_some()),
        ("pcscf", "EF.P-CSCF (6F09, ADF.ISIM, linear-fixed records)", "6F09", doc.pcscf.as_deref().is_some()),
    ];
    for (key, desc, fid, present) in isim_fields {
        if !present { continue; }
        let path = if isim_capable {
            vec!["3F00".into(), "7FFF".into(), "ADF.ISIM".into(), fid.into()]
        } else {
            vec!["3F00".into(), "ADF.ISIM".into(), fid.into()]
        };
        steps.push(PlanStep {
            description: format!("Program {desc}"),
            apdu: None,
            path,
            field: Some(key.to_ascii_uppercase()),
            file: Some(fid.into()),
            notes: vec![
                "Requires selecting ADF.ISIM on the live card (AID from EF.DIR) and confirming EF size/record structure before writing.".into(),
                "NAI/URI values are encoded per TS 31.103 (transparent tag 0x80 or record encoding) and padded to the EF size.".into(),
            ],
        });
        needs.push(format!("{key} ({desc}) requires ADF.ISIM selection and EF size/record layout from the live ISIM-capable card."));
        writes.push(key.to_ascii_uppercase());
    }
    // ePDG (USIM/ISIM ePDG selection/identifier EFs)
    if doc.epdg.as_deref().map(str::trim).is_some_and(|s| !s.is_empty()) {
        steps.push(PlanStep {
            description: "Program ePDG identifier/selection (EF.ePDGId 6F65 / EF.ePDGSelection 6F64 or card-specific ePDG EFs)".into(),
            apdu: None,
            path: vec!["3F00".into(), "ADF.USIM/ADF.ISIM".into(), "6F64|6F65".into()],
            field: Some("ePDG".into()),
            file: Some("6F64/6F65".into()),
            notes: vec![
                "ePDG EFs and encoding (FQDN/IP, priority/selection records) are profile/card dependent; select the correct ADF and read EF metadata on the live card before writing.".into(),
            ],
        });
        needs.push("ePDG (EF.ePDGId/EF.ePDGSelection) programming requires the correct ADF and EF structure from the live card.".into());
        writes.push("ePDG".into());
    }
}

fn legacy_model(t: &str) -> Option<legacy::Model> {
    match t {
        "magicsim" | "magic" | "supersim" | "fakemagicsim" | "fake-magic-sim" => {
            Some(legacy::Model::MagicSim)
        }
        "opencells" | "opencells-sim" | "wavemobile" | "wavemobile-sim" => {
            Some(legacy::Model::OpenCells)
        }
        "grcardsim" | "grcard" | "gialer" | "gialersim" => Some(legacy::Model::GrCard),
        "sysmosim-gr2" | "sysmosimgr2" | "gr2" => Some(legacy::Model::SysmoSIMgr2),
        _ => None,
    }
}

fn sysmocom_model(t: &str) -> Option<sysmocom::Model> {
    match t {
        "sysmoisim-sja2" | "sysmousim-sja2" | "sja2" => Some(sysmocom::Model::Sja2),
        "sysmoisim-sja5" | "sysmousim-sja5" | "sja5" => Some(sysmocom::Model::Sja5),
        "sysmosim-sjs1" | "sysmousim-sjs1" | "sjs1" => Some(sysmocom::Model::Sjs1),
        _ => None,
    }
}

fn build_legacy_request(
    doc: &Document,
    mcc: &Option<String>,
    mnc: &Option<String>,
    opc: Option<&str>,
) -> Result<legacy::ProgramRequest, Error> {
    Ok(legacy::ProgramRequest {
        iccid: doc.iccid.clone(),
        imsi: doc.imsi.clone(),
        ki: opt_secret16(doc.ki.as_deref(), "ki")?,
        opc: opt_secret16(opc, "opc")?,
        pin_adm: doc
            .adm
            .as_deref()
            .map(|s| Secret::new(s.trim().as_bytes().to_vec())),
        operator_name: doc.operator_name.clone(),
        smsp: doc.smsp.clone(),
        acc: doc.acc.clone(),
        mcc: mcc.clone(),
        mnc: mnc.clone(),
    })
}

fn build_sysmocom_request(
    doc: &Document,
    _mcc: &Option<String>,
    _mnc: &Option<String>,
    opc: Option<&str>,
) -> Result<sysmocom::ProgramRequest, Error> {
    let mut req = sysmocom::ProgramRequest::default();
    if let Some(adm) = doc.adm.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        req.admin = vec![Secret::new(adm.as_bytes().to_vec())];
    }
    req.ki = opt_secret16(doc.ki.as_deref(), "ki")?;
    req.opc = opt_secret16(opc, "opc")?;
    Ok(req)
}

fn opt_secret16(hex: Option<&str>, name: &str) -> Result<Option<Secret>, Error> {
    let Some(h) = hex.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(Secret::new(decode_key16(name, h)?)))
}

fn decode_key16(name: &str, h: &str) -> Result<Vec<u8>, Error> {
    let h = norm_hex(h);
    let bytes = hex::decode(&h)
        .map_err(|_| Error::new("document-invalid", format!("`{name}` is not valid hex")))?;
    if bytes.len() != 16 {
        return Err(Error::new(
            "document-invalid",
            format!(
                "`{name}` must be 16 bytes (32 hex digits), got {} bytes",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

fn arr16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}

fn norm_hex(h: &str) -> String {
    h.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_uppercase()
}

fn norm_hex_opt(h: Option<&str>) -> Option<String> {
    h.map(str::trim).filter(|s| !s.is_empty()).map(norm_hex)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn eq_hex(a: &str, b: &str) -> bool {
    norm_hex(a) == norm_hex(b)
}

fn append_legacy_step(
    steps: &mut Vec<PlanStep>,
    needs: &mut Vec<String>,
    pw: &legacy::PlannedWrite,
) {
    use legacy::Body;
    let path: Vec<String> = pw.path.iter().map(|s| s.to_ascii_uppercase()).collect();
    // SELECT chain
    let mut cur = Vec::new();
    for fid in &path {
        cur.push(fid.clone());
        let apdu = legacy::select(fid).ok().map(|b| hex_upper(&b));
        steps.push(PlanStep {
            description: format!("SELECT {fid}"),
            apdu,
            path: cur.clone(),
            field: None,
            file: Some(fid.clone()),
            notes: Vec::new(),
        });
    }
    let (desc, apdu, notes) = match &pw.body {
        Body::Binary { offset, data } => {
            let a = if matches!(pw.field, legacy::Field::Ki | legacy::Field::Opc) {
                None
            } else {
                legacy::update_binary(*offset, data)
                    .ok()
                    .map(|b| hex_upper(&b))
            };
            let mut n = Vec::new();
            if a.is_none() && matches!(pw.field, legacy::Field::Ki | legacy::Field::Opc) {
                n.push(
                    "APDU payload contains key material and is omitted from the plan output."
                        .into(),
                );
            }
            (
                format!(
                    "UPDATE BINARY {} ({}, {} bytes at offset {offset})",
                    pw.fid.to_ascii_uppercase(),
                    pw.name,
                    data.len()
                ),
                a,
                n,
            )
        }
        Body::Record { record, data } => {
            let sensitive = matches!(
                pw.field,
                legacy::Field::Iccid
                    | legacy::Field::Ki
                    | legacy::Field::Imsi
                    | legacy::Field::OperatorName
                    | legacy::Field::Smsp
            );
            let a = if sensitive {
                None
            } else {
                legacy::update_record(*record, data)
                    .ok()
                    .map(|b| hex_upper(&b))
            };
            let mut n = Vec::new();
            if a.is_none() {
                n.push("APDU payload may contain key/identity material and is omitted from the offline plan output.".into());
            }
            (
                format!(
                    "UPDATE RECORD {} ({}, record {record}, {} bytes)",
                    pw.fid.to_ascii_uppercase(),
                    pw.name,
                    data.len()
                ),
                a,
                n,
            )
        }
        Body::Plmn { hplmn } => {
            needs.push("EF.PLMNSEL write pads to the file length read from the card (SELECT response); the full UPDATE BINARY length is determined on a live card.".to_owned());
            (
                format!("UPDATE BINARY EF.PLMNSEL ({}), HPLMN {}", pw.name, hex_upper(hplmn)),
                None,
                vec!["PLMN payload starts with encoded HPLMN and is padded with FF to the EF length reported by the card.".into()],
            )
        }
        Body::Proprietary(_) => (
            format!("PROPRIETARY APDU ({})", pw.name),
            None,
            vec!["Proprietary write APDU carries ADM/Ki material and is omitted from the plan output; it is sent on a live card with --yes.".into()],
        ),
        Body::Auth { chv, .. } => (
            format!("VERIFY CHV 0x{chv:02X} ({})", pw.name),
            None,
            vec!["VERIFY CHV APDU carries the ADM/PIN and is omitted from the plan output.".into()],
        ),
    };
    steps.push(PlanStep {
        description: desc,
        apdu,
        path,
        field: Some(format!("{:?}", pw.field)),
        file: Some(pw.fid.to_ascii_uppercase()),
        notes,
    });
}

fn append_sysmocom_step(
    steps: &mut Vec<PlanStep>,
    model: sysmocom::Model,
    pw: &sysmocom::PlannedWrite,
) {
    let dir = model.programming_directory().to_ascii_uppercase();
    let dir_apdu = sysmocom::select(&dir).ok().map(|b| hex_upper(&b));
    steps.push(PlanStep {
        description: format!("SELECT {dir} (programming directory)"),
        apdu: dir_apdu,
        path: vec!["3F00".into(), dir.clone()],
        field: None,
        file: Some(dir.clone()),
        notes: Vec::new(),
    });
    let fid = pw.fid.to_ascii_uppercase();
    let sel_apdu = sysmocom::select(&fid).ok().map(|b| hex_upper(&b));
    steps.push(PlanStep {
        description: format!("SELECT {fid} ({})", pw.name),
        apdu: sel_apdu,
        path: vec!["3F00".into(), dir, fid.clone()],
        field: Some(format!("{:?}", pw.field)),
        file: Some(fid.clone()),
        notes: Vec::new(),
    });
    steps.push(PlanStep {
        description: format!("UPDATE BINARY {fid} ({}, {} bytes)", pw.name, pw.data.len()),
        apdu: None,
        path: Vec::new(),
        field: Some(format!("{:?}", pw.field)),
        file: Some(fid),
        notes: vec!["UPDATE BINARY payload contains key/PIN material and is omitted from the offline plan output; it is sent on a live card with --yes.".into()],
    });
}

/// Plans programming for each row of a provisioning/programming CSV (batch CSV).
///
/// Recognized columns (case-insensitive): `type`/`card`, `iccid`, `imsi`,
/// `ki`, `opc`, `op`, `adm`/`pin_adm`, `mcc`, `mnc`, `mnc_len`, `smsp`/`smsc`,
/// `msisdn`, `acc`, `fplmn`, `impi`, `impu`, `domain`/`ims_domain`,
/// `pcscf`/`p_cscf`, `epdg`/`e_pdg`, `operator_name`/`name`. A `type` column or
/// `default_type` must provide the card type for each row. Rows missing required
/// identity material fail with the row number; key values are never included in
/// errors. Planning is offline (no card touched).
pub fn plans_from_csv(text: &str, default_type: Option<&str>) -> Result<Vec<Plan>, Error> {
    let rows = crate::cardsh::csvfile::parse(text)
        .map_err(|e| Error::new("document-invalid", format!("CSV: {e}")))?;
    let mut it = rows.into_iter();
    let header = it
        .next()
        .ok_or_else(|| Error::new("document-invalid", "CSV is empty"))?;
    let headers: Vec<String> = header
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase())
        .collect();
    let mut plans = Vec::new();
    for (idx, row) in it.enumerate() {
        let rowno = idx + 2; // 1-based including header
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let get = |names: &[&str]| -> Option<String> {
            for name in names {
                if let Some(i) = headers.iter().position(|h| h == name) {
                    if let Some(v) = row.get(i) {
                        let t = v.trim().to_string();
                        if !t.is_empty() {
                            return Some(t);
                        }
                    }
                }
            }
            None
        };
        let r#type = get(&["type", "card"]).or_else(|| default_type.map(|s| s.to_string()));
        let Some(r#type) = r#type else {
            return Err(Error::new(
                "document-invalid",
                format!("row {rowno}: missing card type (no `type` column/value and no default type)"),
            ));
        };
        let fplmn = get(&["fplmn"]).map(|s| {
            s.split(|c: char| c == ';' || c == '|')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
        });
        let doc = Document {
            kind: Some(DOC_KIND.to_owned()),
            r#type: Some(r#type),
            iccid: get(&["iccid"]),
            imsi: get(&["imsi"]),
            ki: get(&["ki"]),
            opc: get(&["opc"]),
            op: get(&["op"]),
            adm: get(&["adm", "pin_adm", "adm_pin"]),
            mcc: get(&["mcc"]),
            mnc: get(&["mnc"]),
            mnc_len: get(&["mnc_len", "mnclen"]).and_then(|v| v.parse().ok()),
            smsp: get(&["smsp", "smsc"]),
            msisdn: get(&["msisdn"]),
            acc: get(&["acc"]),
            fplmn,
            operator_name: get(&["operator_name", "name"]),
            impi: get(&["impi"]),
            impu: get(&["impu"]),
            domain: get(&["domain", "ims_domain"]),
            pcscf: get(&["pcscf", "p_cscf"]),
            epdg: get(&["epdg", "e_pdg", "epdg_id"]),
        };
        let plan = plan_document(&doc).map_err(|e| {
            Error::new(
                e.kind,
                format!("row {rowno}: {} (key material redacted)", e.detail),
            )
        })?;
        plans.push(plan);
    }
    if plans.is_empty() {
        return Err(Error::new(
            "nothing-to-program",
            "CSV contains no data rows to program",
        ));
    }
    Ok(plans)
}

/// Returns a redacted JSON view of a document suitable for dry-run display
/// (omits Ki/OPc/OP/ADM values).
pub fn redacted_document_json(doc: &Document) -> serde_json::Value {
    serde_json::json!({
        "kind": doc.kind,
        "type": doc.r#type,
        "iccid": doc.iccid,
        "imsi": doc.imsi,
        "msisdn": doc.msisdn,
        "mcc": doc.mcc,
        "mnc": doc.mnc,
        "mnc_len": doc.mnc_len,
        "smsp": doc.smsp,
        "acc": doc.acc,
        "fplmn": doc.fplmn,
        "operator_name": doc.operator_name,
        "impi": doc.impi,
        "impu": doc.impu,
        "domain": doc.domain,
        "pcscf": doc.pcscf,
        "epdg": doc.epdg,
        "ki": doc.ki.as_ref().map(|_| "<redacted>"),
        "opc": doc.opc.as_ref().map(|_| "<redacted>"),
        "op": doc.op.as_ref().map(|_| "<redacted>"),
        "adm": doc.adm.as_ref().map(|_| "<redacted>"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: &str) -> Document {
        Document::parse(json).unwrap()
    }

    #[test]
    fn parses_minimal_magicsim_document() {
        let d = doc(
            r#"{"type":"magicsim","iccid":"8986000000000000001","imsi":"001010000000001","mcc":"001","mnc":"01","ki":"00112233445566778899AABBCCDDEEFF"}"#,
        );
        assert_eq!(d.card_type().unwrap(), "magicsim");
        assert_eq!(d.normalized_mcc().unwrap().as_deref(), Some("001"));
        assert_eq!(d.normalized_mnc().unwrap().as_deref(), Some("01"));
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = Document::parse(r#"{"kind":"other/1","type":"magicsim"}"#).unwrap_err();
        assert_eq!(err.kind, "document-invalid");
    }

    #[test]
    fn derives_opc_from_op_and_ki() {
        let d = doc(
            r#"{"type":"opencells","ki":"000102030405060708090A0B0C0D0E0F","op":"00112233445566778899AABBCCDDEEFF"}"#,
        );
        let opc = d.resolve_opc().unwrap().unwrap();
        assert_eq!(opc.len(), 32);
    }

    #[test]
    fn plans_magicsim_identity_and_keys() {
        let plan = plan_json(
            r#"{
            "type":"magicsim",
            "iccid":"8986000000000000001",
            "imsi":"001010000000001",
            "mcc":"001","mnc":"01",
            "ki":"00112233445566778899AABBCCDDEEFF",
            "smsp":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        }"#,
        )
        .unwrap();
        assert_eq!(plan.kind, PLAN_KIND);
        assert!(!plan.card_touched);
        assert!(!plan.steps.is_empty());
        let apdus: Vec<_> = plan.steps.iter().filter_map(|s| s.apdu.as_deref()).collect();
        assert!(
            apdus.iter().any(|a| a.starts_with("A0A4")),
            "expected SELECT APDUs, got {apdus:?}"
        );
        assert!(plan.steps.iter().any(|s| s.description.contains("UPDATE")));
        assert!(!plan.needs_live_card.is_empty());
        assert!(plan.warning.contains("dry run unless --yes"));
        assert!(!plan.supported_card_types.is_empty());
    }

    #[test]
    fn plans_opencells_with_adm() {
        let plan = plan_json(
            r#"{
            "type":"opencells",
            "adm":"00000000",
            "iccid":"8986000000000000001",
            "imsi":"001010000000001",
            "ki":"00112233445566778899AABBCCDDEEFF",
            "opc":"FFEEDDCCBBAA99887766554433221100"
        }"#,
        )
        .unwrap();
        assert!(plan
            .steps
            .iter()
            .any(|s| s.description.contains("PROPRIETARY") || s.description.contains("VERIFY CHV")));
    }

    #[test]
    fn op_and_opc_must_agree() {
        let d = doc(
            r#"{"type":"magicsim","ki":"00112233445566778899AABBCCDDEEFF","op":"00112233445566778899AABBCCDDEEFF","opc":"00000000000000000000000000000000"}"#,
        );
        assert!(d.resolve_opc().is_err());
    }

    #[test]
    fn plans_sysmocom_sja2() {
        let plan = plan_json(
            r#"{
            "type":"sysmoISIM-SJA2",
            "adm":"12345678",
            "ki":"00112233445566778899AABBCCDDEEFF",
            "opc":"FFEEDDCCBBAA99887766554433221100"
        }"#,
        )
        .unwrap();
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn refuses_unsupported_type() {
        let err = plan_json(r#"{"type":"no-such-card","iccid":"1"}"#).unwrap_err();
        assert_eq!(err.kind, "unsupported-type");
    }

    #[test]
    fn fplmn_adds_live_card_note() {
        let plan = plan_json(
            r#"{
            "type":"magicsim","iccid":"8986000000000000001","imsi":"001010000000001",
            "mcc":"001","mnc":"01","ki":"00112233445566778899AABBCCDDEEFF",
            "fplmn":["00101"]
        }"#,
        )
        .unwrap();
        assert!(plan.steps.iter().any(|s| s.field.as_deref() == Some("Fplmn")));
        assert!(plan.needs_live_card.iter().any(|n| n.contains("FPLMN")));
    }

    #[test]
    fn accepts_new_fields_and_accounts_for_them() {
        let plan = plan_json(
            r#"{
            "type":"sysmoisim-sja5",
            "iccid":"8986000000000000001","imsi":"001010000000001",
            "ki":"00112233445566778899AABBCCDDEEFF",
            "msisdn":"15551234567","smsp":"FFFFFFFF",
            "impi":"user@ims.mnc001.mcc001.3gppnetwork.org",
            "impu":"sip:user@ims.mnc001.mcc001.3gppnetwork.org",
            "domain":"ims.mnc001.mcc001.3gppnetwork.org",
            "pcscf":"pcscf.ims.example.org",
            "epdg":"epdg.epc.mnc001.mcc001.pub.3gppnetwork.org"
        }"#,
        )
        .unwrap();
        assert!(plan.writes.iter().any(|w| w == "Msisdn"));
        assert!(plan.writes.iter().any(|w| w == "IMPI"));
        assert!(plan.writes.iter().any(|w| w == "IMPU"));
        assert!(plan.writes.iter().any(|w| w.contains("ePDG") || w == "ePDG"));
    }

    #[test]
    fn plans_from_csv_batch() {
        let csv = "type,iccid,imsi,mcc,mnc,ki,msisdn\nmagicsim,8986000000000000001,001010000000001,001,01,00112233445566778899AABBCCDDEEFF,15551234567\nmagicsim,8986000000000000002,001010000000002,001,01,00112233445566778899AABBCCDDEEFF,15551234568\n";
        let plans = plans_from_csv(csv, None).unwrap();
        assert_eq!(plans.len(), 2);
        assert!(plans.iter().all(|p| !p.card_touched));
    }

    #[test]
    fn redacted_document_hides_keys() {
        let d = doc(r#"{"type":"magicsim","ki":"00112233445566778899AABBCCDDEEFF","adm":"1234"}"#);
        let j = redacted_document_json(&d);
        assert_eq!(j["ki"], "<redacted>");
        assert_eq!(j["adm"], "<redacted>");
    }

    #[test]
    fn supported_types_listed() {
        let types = supported_card_types();
        assert!(types.contains(&"magicsim"));
        assert!(types.contains(&"sysmoisim-sja2"));
        assert!(types.len() >= 7);
    }
}
