//! Card personalization / programming: a pySim-prog-style document turned into an
//! APDU sequence.
//!
//! **Owns.** The programming document format ([`Document`]), parsing and
//! validation, and the offline planning that turns one document into the ordered
//! APDU sequence a reference tool would send for that card type.
//!
//! **Does not own.** Opening a reader, sending bytes to a card, or the card-type
//! detection/probe logic itself (that lives in [`crate::cardprofile`],
//! [`crate::legacy`] and [`crate::sysmocom`]). This module is the offline half:
//! document in, APDU plan out.
//!
//! # The document
//!
//! A pySim-prog-style description of one card: which card type/model to program
//! and the identity and key material to write (ICCID, IMSI, Ki, OPc/OP, ADM/PIN,
//! SMSP/SMSC, ACC, MCC/MNC and their length, FPLMN, and the operator name where
//! the model carries one). Fields that do not apply to the chosen type are
//! rejected rather than silently dropped, because writing the wrong thing to a
//! card is worse than refusing to guess.
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
    /// Access control class (EF.ACC), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acc: Option<String>,
    /// Forbidden PLMNs (EF.FPLMN), as PLMN strings `MCCMNC` or 3-byte hex entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fplmn: Option<Vec<String>>,
    /// Operator name (magic-SIM).
    #[serde(default, alias = "name", skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
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
    /// [`WARNING`].
    pub warning: &'static str,
    /// True: no bytes were sent and no card was touched.
    pub card_touched: bool,
    /// The ordered APDU steps.
    pub steps: Vec<PlanStep>,
    /// What still requires a live card / cannot be completed offline.
    pub needs_live_card: Vec<String>,
    /// Fields the plan writes (best-effort summary).
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
        if doc.iccid.is_some()
            || doc.imsi.is_some()
            || doc.mcc.is_some()
            || doc.smsp.is_some()
            || doc.acc.is_some()
        {
            needs_live_card.push(
                "ICCID/IMSI/MCC-MNC/SMSP/ACC programming for sysmocom SJA2/SJA5/SJS1 models is not covered by the sysmocom vendor-file surface in this build; write those EFs via the card shell or a model-specific flow on a live card.".to_owned(),
            );
        }
        needs_live_card.push(
            "sysmocom SJA2/SJA5/SJS1 programming is performed over the AT+CSIM transport; APDUs below are the card APDUs carried inside AT+CSIM frames.".to_owned(),
        );
    } else {
        return Err(Error::new(
            "unsupported-type",
            format!(
                "card type `{card_type}` is not supported for offline APDU planning; \
supported types: magicsim, supersim, opencells, grcardsim, gialer, wavemobile, sysmosim-gr2, \
sysmoisim-sja2, sysmousim-sja2, sysmoisim-sja5, sysmousim-sja5, sysmosim-sjs1"
            ),
        ));
    }

    // FPLMN: if requested, add a note/step (generic EF update needs live-card path/size).
    if let Some(entries) = &doc.fplmn {
        if !entries.is_empty() {
            needs_live_card.push(
                "FPLMN (EF.FPLMN 6F7B under DF.GSM/ADF) programming requires selecting the correct DF/ADF on the target card and writing the encoded PLMN list; the exact path and file length must be read from the live card.".to_owned(),
            );
            let path = vec!["3F00".into(), "7F20".into(), "6F7B".into()];
            steps.push(PlanStep {
                description: format!("UPDATE BINARY EF.FPLMN ({} entrie(s), encoded on live card)", entries.len()),
                apdu: None,
                path,
                field: Some("FPLMN".into()),
                file: Some("6F7B".into()),
                notes: vec![
                    "Encode each PLMN as 3 bytes (TS 51.011/31.102 MCC/MNC digit coding) and pad remaining entries with FF FF FF up to the file length read from the card.".into(),
                ],
            });
            if !writes.iter().any(|w| w == "FPLMN") {
                writes.push("FPLMN".into());
            }
        }
    }

    writes.sort();
    writes.dedup();

    Ok(Plan {
        kind: PLAN_KIND.to_owned(),
        card_type,
        warning: WARNING,
        card_touched: false,
        steps,
        needs_live_card,
        writes,
    })
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
    // sysmocom vendor surface: CHV1/CHV2, ADM1-4, Ki/OPc (SJS1) or SIM_AUTH_KEY pair.
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
    // Proprietary/auth bodies may carry secrets (ADM/Ki); treat conservatively.
    let contains_key_material = matches!(pw.body, Body::Proprietary(_))
        && matches!(pw.field, legacy::Field::Ki | legacy::Field::AdmPin);
    let (desc, apdu, notes) = match &pw.body {
        Body::Binary { offset, data } => {
            let a = if matches!(pw.field, legacy::Field::Ki | legacy::Field::Opc) {
                None
            } else {
                legacy::update_binary(*offset, data).ok().map(|b| hex_upper(&b))
            };
            let mut n = Vec::new();
            if a.is_none() && matches!(pw.field, legacy::Field::Ki | legacy::Field::Opc) {
                n.push("APDU payload contains key material and is omitted from the plan output.".into());
            }
            (
                format!("UPDATE BINARY {} ({}, {} bytes at offset {offset})", pw.fid.to_ascii_uppercase(), pw.name, data.len()),
                a,
                n,
            )
        }
        Body::Record { record, data } => {
            // Provider/name records and others may embed Ki or identity material; omit payload to avoid leaking secrets.
            let sensitive = matches!(pw.field, legacy::Field::Iccid | legacy::Field::Ki | legacy::Field::Imsi | legacy::Field::OperatorName | legacy::Field::Smsp);
            let a = if sensitive { None } else { legacy::update_record(*record, data).ok().map(|b| hex_upper(&b)) };
            let mut n = Vec::new();
            if a.is_none() {
                n.push("APDU payload may contain key/identity material and is omitted from the offline plan output.".into());
            }
            (
                format!("UPDATE RECORD {} ({}, record {record}, {} bytes)", pw.fid.to_ascii_uppercase(), pw.name, data.len()),
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
        Body::Proprietary(_) => {
            let _ = contains_key_material;
            (
                format!("PROPRIETARY APDU ({})", pw.name),
                None,
                vec!["Proprietary write APDU carries ADM/Ki material and is omitted from the plan output; it is sent on a live card with --yes.".into()],
            )
        }
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
        assert_eq!(d.resolve_opc().unwrap().unwrap(), opc);
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
        // SELECT APDUs are present; secret-bearing write payloads are omitted.
        let apdus: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|s| s.apdu.as_deref())
            .collect();
        assert!(
            apdus.iter().any(|a| a.starts_with("A0A4")),
            "expected SELECT APDUs, got {apdus:?}"
        );
        assert!(plan.writes.iter().any(|w| w.contains("Iccid")));
        assert!(plan.steps.iter().any(|s| s.description.contains("UPDATE")));
        assert!(!plan.needs_live_card.is_empty());
        assert!(plan.warning.contains("dry run unless --yes"));
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
        assert!(
            plan.steps
                .iter()
                .any(|s| s.description.contains("PROPRIETARY")
                    || s.description.contains("VERIFY CHV"))
        );
        assert!(plan.needs_live_card.iter().any(|n| n.contains("live card")));
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
        assert!(plan.steps.iter().any(|s| s.file.as_deref() == Some("A515")));
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
        assert!(plan
            .steps
            .iter()
            .any(|s| s.field.as_deref() == Some("FPLMN")));
        assert!(plan.needs_live_card.iter().any(|n| n.contains("FPLMN")));
    }
}
