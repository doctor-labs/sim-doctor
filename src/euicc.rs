//! eUICC, read-only: select the ISD-R on a logical channel and read what
//! ES10 will say without changing anything (issues #116, #132).
//!
//! **Owns.** The three read-only queries behind `sim-doctor euicc`: `info`
//! (GetEID, GetEuiccInfo1, GetEuiccInfo2, GetEuiccConfiguredAddresses),
//! `profiles` (GetProfilesInfo) and `notifications` (ListNotification,
//! metadata only), the JSON each produces and the sanitized human table. lpac
//! names: `chip info`, `profile list`, `notification list`. Also the writes:
//! [`nickname`] (SetNickname, lpac `profile nickname`) and [`set_state`]
//! (EnableProfile / DisableProfile, lpac `profile enable` / `disable`): each a
//! dry run by default, sent only when `apply` is set, and then verified by a
//! re-read.
//!
//! The erasing writes are [`delete_profile`] (DeleteProfile, `profile delete`),
//! [`memory_reset`] (eUICCMemoryReset, `chip purge`; needs `--confirm-eid`) and
//! [`remove_notification`] (RemoveNotificationFromList, `notification remove`),
//! under the same rule.
//!
//! Also [`dump_notifications`] (RetrieveNotificationsList, `notification dump`
//! without lpac's per-sequence loop): read-only, it removes nothing.
//!
//! **Does not own, and never sends.** The download functions or anything over
//! HTTPS (sending a dumped notification is [`crate::notif`]). The only commands on the wire are MANAGE
//! CHANNEL (open, close), SELECT of the ISD-R, and STORE DATA carrying one of
//! the read requests above, or a write above when applying. The channel is
//! closed again on every path, a failure included.
//!
//! **Card safety.** A card that is not an eUICC refuses the ISD-R SELECT; that
//! is reported as [`Failure`] `not-an-euicc` and no STORE DATA is sent.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "euicc";

use serde_json::{json, Value};

use crate::apdu::{Command, Header, Le};
use crate::contract::sanitize;
use crate::es10::{self, BitString};
use crate::session::{self, PendingFollowUp, Policy};
use crate::transport::CardSession;

/// The ISD-R AID (SGP.22 v2.5 section 4.1).
pub const ISDR_AID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00,
];

/// Tags GetProfilesInfo is asked for: ICCID, ISD-P AID, state, nickname,
/// provider, name, class. The icon (`94`) is left out on purpose: it is large
/// and nothing here shows it.
const PROFILE_TAGS: [u16; 7] = [0x5A, 0x4F, 0x9F70, 0x90, 0x91, 0x92, 0x95];

/// STORE DATA data bytes per block unless `--max-segment` changes it: lpac's
/// default, since some eUICCs reject full 255-byte blocks.
pub const DEFAULT_MAX_SEGMENT: usize = 120;

/// Which read-only query to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    /// EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`).
    Info,
    /// GetProfilesInfo (lpac `profile list`).
    Profiles,
    /// ListNotification metadata (lpac `notification list`).
    Notifications,
    /// GetEUICCChallenge, the 16 random bytes an SM-DP+ signs over (SGP.22 v2.5
    /// §5.7.7; pySim `get_euicc_challenge`). Reads nothing from the profiles.
    Challenge,
}

impl Query {
    /// The subcommand name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Profiles => "profiles",
            Self::Notifications => "notifications",
            Self::Challenge => "challenge",
        }
    }
}

/// Why a query produced no data: a stable `kind`, a message, and extra data.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// Machine-checkable cause (`not-an-euicc`, `channel-unavailable`, ...).
    pub kind: &'static str,
    /// What to tell the operator.
    pub message: String,
    /// The envelope `data`, always holding `error.kind`.
    pub data: Value,
}

impl Failure {
    /// A failure of `kind` with `extra` merged into the envelope data.
    pub fn new(kind: &'static str, message: String, extra: Value) -> Self {
        let mut data = json!({ "error": { "kind": kind, "message": message } });
        if let (Some(into), Some(from)) = (data.as_object_mut(), extra.as_object()) {
            into.extend(from.clone());
        }
        Self {
            kind,
            message,
            data,
        }
    }
}

fn exchange_failed(err: impl std::fmt::Display) -> Failure {
    Failure::new("exchange-failed", err.to_string(), json!({}))
}

fn status_hex(ex: &session::Exchange) -> Value {
    ex.status()
        .map_or(Value::Null, |s| json!(hex::encode_upper(s.to_bytes())))
}

/// CLA for logical channel `n`: first interindustry for 0..=3 and 4..=19
/// (`0x40`), or, with `proprietary`, the `8x` / `Cx` classes STORE DATA uses.
fn channel_cla(proprietary: bool, n: u8) -> u8 {
    match (proprietary, n) {
        (false, 0..=3) => n,
        (false, _) => 0x40 | (n - 4),
        (true, 0..=3) => 0x80 | n,
        (true, _) => 0xC0 | (n - 4),
    }
}

/// Asks the ISD-R one ES10 function: the request goes out as STORE DATA, the
/// response data comes back. The `&'static str` names the function in errors.
type Ask<'a> = dyn FnMut(&'static str, Vec<u8>) -> Result<Vec<u8>, Failure> + 'a;

/// Runs `query` against the ISD-R with AID `aid` on a freshly opened logical
/// channel, and closes the channel afterwards.
///
/// # Errors
///
/// A [`Failure`]; the card refusing is data, not a panic.
pub fn run<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    query: Query,
) -> Result<Value, Failure> {
    run_with(session, aid, query, DEFAULT_MAX_SEGMENT)
}

/// [`run`] with at most `max_segment` data bytes per STORE DATA block.
///
/// # Errors
///
/// As [`run`].
pub fn run_with<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    query: Query,
    max_segment: usize,
) -> Result<Value, Failure> {
    in_channel(session, aid, max_segment, |ask| read_query(ask, query))
}

/// Opens a logical channel, selects the ISD-R, hands `body` a way to ask it
/// ES10 functions, then closes the channel on every path.
fn in_channel<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    body: impl FnOnce(&mut Ask<'_>) -> Result<Value, Failure>,
) -> Result<Value, Failure> {
    let (channel, open) = session::open_channel(session).map_err(exchange_failed)?;
    let Some(channel) = channel else {
        return Err(Failure::new(
            "channel-unavailable",
            format!(
                "the card did not open a logical channel (MANAGE CHANNEL status {}); \
                 it is probably not an eUICC",
                status_hex(&open).as_str().unwrap_or("none")
            ),
            json!({ "status": status_hex(&open) }),
        ));
    };
    let result = on_channel(session, channel, aid, max_segment, body);
    let closed = matches!(
        session::close_channel(session, channel),
        Ok(Some(ex)) if ex.is_success()
    );
    let mut data = result?;
    data["channel"] = json!({ "number": channel, "closed": closed });
    Ok(data)
}

fn on_channel<S: CardSession + ?Sized>(
    session: &mut S,
    channel: u8,
    aid: &[u8],
    max_segment: usize,
    body: impl FnOnce(&mut Ask<'_>) -> Result<Value, Failure>,
) -> Result<Value, Failure> {
    let policy = Policy {
        get_response_class: channel_cla(false, channel),
        proactive_command: PendingFollowUp::Ignore,
        ..Policy::default()
    };
    let select = Command::case4(
        Header::new(channel_cla(false, channel), 0xA4, 0x04, 0x00),
        aid,
        Le::Short(0),
    );
    let ex = session::send(session, &select, &policy).map_err(exchange_failed)?;
    if !ex.is_success() {
        return Err(Failure::new(
            "not-an-euicc",
            format!(
                "not an eUICC: the card refused SELECT of the ISD-R {} (status {})",
                hex::encode_upper(aid),
                status_hex(&ex).as_str().unwrap_or("none")
            ),
            json!({ "aid": hex::encode_upper(aid), "status": status_hex(&ex) }),
        ));
    }
    let cla = channel_cla(true, channel);
    let mut ask = |what: &'static str, request: Vec<u8>| -> Result<Vec<u8>, Failure> {
        let sent = es10::store_data_sized(session, cla, &request, max_segment, &policy)
            .map_err(exchange_failed)?;
        let last = sent.exchanges.last();
        if !sent.complete || !last.is_some_and(session::Exchange::is_success) {
            return Err(Failure::new(
                "es10-refused",
                format!(
                    "the ISD-R refused {what} (status {})",
                    last.map_or(Value::Null, status_hex)
                        .as_str()
                        .unwrap_or("none")
                ),
                json!({ "function": what }),
            ));
        }
        Ok(sent.data().to_vec())
    };
    let mut data = body(&mut ask)?;
    data["aid"] = json!(hex::encode_upper(aid));
    Ok(data)
}

fn bad(what: &'static str, e: es10::DecodeError) -> Failure {
    Failure::new(
        "decode-failed",
        format!("{what} response is malformed: {e}"),
        json!({ "function": what }),
    )
}

/// GetProfilesInfo for every profile, with [`PROFILE_TAGS`].
fn read_profiles(ask: &mut Ask<'_>) -> Result<Vec<es10::ProfileInfo>, Failure> {
    let request =
        es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).map_err(exchange_failed)?;
    match es10::decode_profiles_info(&ask("GetProfilesInfo", request)?)
        .map_err(|e| bad("GetProfilesInfo", e))?
    {
        es10::ProfileInfoListResponse::Ok { profiles, .. } => Ok(profiles),
        es10::ProfileInfoListResponse::Error(code) => Err(Failure::new(
            "es10-refused",
            format!("GetProfilesInfo returned error code {}", code.code()),
            json!({ "function": "GetProfilesInfo", "code": code.code() }),
        )),
    }
}

fn read_eid(ask: &mut Ask<'_>) -> Result<String, Failure> {
    let eid = es10::decode_get_eid(&ask("GetEID", es10::get_eid_request())?)
        .map_err(|e| bad("GetEID", e))?;
    Ok(hex::encode_upper(eid))
}

/// ListNotification for every pending notification (metadata only).
fn read_notifications(ask: &mut Ask<'_>) -> Result<Vec<es10::NotificationMetadata>, Failure> {
    match es10::decode_list_notification(&ask(
        "ListNotification",
        es10::list_notification_request(),
    )?)
    .map_err(|e| bad("ListNotification", e))?
    {
        es10::ListNotificationResponse::Ok(list) => Ok(list),
        es10::ListNotificationResponse::Error(code) => Err(Failure::new(
            "es10-refused",
            format!("ListNotification returned error code {code}"),
            json!({ "function": "ListNotification", "code": code }),
        )),
    }
}

fn read_query(ask: &mut Ask<'_>, query: Query) -> Result<Value, Failure> {
    let mut data = json!({});
    match query {
        Query::Info => {
            let eid = read_eid(ask)?;
            let info1 =
                es10::decode_euicc_info1(&ask("GetEuiccInfo1", es10::get_euicc_info1_request())?)
                    .map_err(|e| bad("GetEuiccInfo1", e))?;
            let info2 =
                es10::decode_euicc_info2(&ask("GetEuiccInfo2", es10::get_euicc_info2_request())?)
                    .map_err(|e| bad("GetEuiccInfo2", e))?;
            let addresses = es10::decode_configured_addresses(&ask(
                "GetEuiccConfiguredAddresses",
                es10::get_euicc_configured_addresses_request(),
            )?)
            .map_err(|e| bad("GetEuiccConfiguredAddresses", e))?;
            data["eid"] = json!(eid);
            data["configured_addresses"] = json!({
                "default_smdp": addresses.default_dp_address,
                "root_smds": addresses.root_ds_address,
            });
            data["euicc_info1"] = info1_json(&info1);
            data["euicc_info2"] = info2_json(&info2);
        }
        Query::Profiles => {
            data["profiles"] = read_profiles(ask)?.iter().map(profile_json).collect();
        }
        Query::Notifications => {
            data["notifications"] = read_notifications(ask)?
                .iter()
                .map(notification_json)
                .collect();
        }
        Query::Challenge => {
            let challenge = es10::decode_get_euicc_challenge(&ask(
                "GetEUICCChallenge",
                es10::get_euicc_challenge_request(),
            )?)
            .map_err(|e| bad("GetEUICCChallenge", e))?;
            data["challenge"] = json!(hex::encode_upper(challenge.challenge));
        }
    }
    Ok(data)
}

/// An ICCID (18 to 20 decimal digits) as the 10 octets EF ICCID codes: BCD
/// with the nibbles swapped, padded with F (ETSI TS 102 221).
fn raw_iccid(iccid: &str) -> Result<[u8; 10], Failure> {
    if !(18..=20).contains(&iccid.len()) || !iccid.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::new(
            "bad-iccid",
            format!("the ICCID must be 18 to 20 decimal digits, got {iccid:?}"),
            json!({}),
        ));
    }
    let mut padded = iccid.as_bytes().to_vec();
    padded.resize(20, b'F');
    let mut raw = [0u8; 10];
    for (out, pair) in raw.iter_mut().zip(padded.chunks(2)) {
        let nibble = |c: u8| if c == b'F' { 0xF } else { c - b'0' };
        *out = (nibble(pair[1]) << 4) | nibble(pair[0]);
    }
    Ok(raw)
}

/// A request to set one profile's nickname. Built by [`Nickname::new`], which
/// checks the ICCID and the name before anything touches a card.
#[derive(Debug, Clone)]
pub struct Nickname {
    iccid: String,
    raw_iccid: [u8; 10],
    name: String,
    /// Send SetNickname. `false` (the default of the CLI) reads the card and
    /// reports what would change, sending nothing that changes it.
    pub apply: bool,
}

impl Nickname {
    /// Validates `iccid` (18 to 20 decimal digits) and `name` (SGP.22 v2.5
    /// section 5.7.21: 0 to 64 bytes of UTF-8; an empty name clears the
    /// nickname; control characters are refused so the name cannot drive a
    /// terminal when it is shown).
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `bad-iccid` or `bad-nickname`.
    pub fn new(iccid: &str, name: &str, apply: bool) -> Result<Self, Failure> {
        let raw_iccid = raw_iccid(iccid)?;
        if name.len() > es10::MAX_NICKNAME_BYTES {
            return Err(Failure::new(
                "bad-nickname",
                format!(
                    "the nickname is {} bytes of UTF-8; SGP.22 allows at most {}",
                    name.len(),
                    es10::MAX_NICKNAME_BYTES
                ),
                json!({ "bytes": name.len(), "max": es10::MAX_NICKNAME_BYTES }),
            ));
        }
        if name.chars().any(char::is_control) {
            return Err(Failure::new(
                "bad-nickname",
                "the nickname must not contain control characters".to_owned(),
                json!({}),
            ));
        }
        Ok(Self {
            iccid: iccid.to_owned(),
            raw_iccid,
            name: name.to_owned(),
            apply,
        })
    }
}

/// SetNickname (lpac `profile nickname`). Reads the EID and the profile list
/// first. Without [`Nickname::apply`] it stops there and reports the planned
/// change (`dry_run` true, `applied` false) having sent no write. With it, it
/// sends SetNickname, re-reads the profile list and fails with kind
/// `verify-failed` unless the nickname is now the requested one.
///
/// # Errors
///
/// A [`Failure`]; `iccid-not-found` when no profile has that ICCID (nothing is
/// written), `es10-refused` when the ISD-R rejects the change.
pub fn nickname<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &Nickname,
) -> Result<Value, Failure> {
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let nickname_of = |profiles: &[es10::ProfileInfo]| {
            profiles
                .iter()
                .find(|p| p.iccid.as_deref() == Some(&request.raw_iccid[..]))
                .map(|p| p.profile_nickname.clone().unwrap_or_default())
        };
        let profiles = read_profiles(ask)?;
        let Some(current) = nickname_of(&profiles) else {
            return Err(Failure::new(
                "iccid-not-found",
                format!("no profile with ICCID {} on this eUICC", request.iccid),
                json!({
                    "eid": eid,
                    "iccid": request.iccid,
                    "iccids": profiles.iter().filter_map(|p| p.iccid.as_deref().map(iccid_text)).collect::<Vec<_>>(),
                }),
            ));
        };
        let mut data = json!({
            "eid": eid,
            "iccid": request.iccid,
            "current_nickname": current,
            "new_nickname": request.name,
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame = es10::set_nickname_request(&request.raw_iccid, &request.name)
            .map_err(exchange_failed)?;
        let result = es10::decode_set_nickname(&ask("SetNickname", frame)?)
            .map_err(|e| bad("SetNickname", e))?;
        if result == es10::SetNicknameResult::IccidNotFound {
            return Err(Failure::new(
                "iccid-not-found",
                format!("the ISD-R reports no profile with ICCID {}", request.iccid),
                json!({ "eid": data["eid"], "iccid": request.iccid }),
            ));
        }
        if result != es10::SetNicknameResult::Ok {
            return Err(Failure::new(
                "es10-refused",
                format!("SetNickname returned result code {}", result.code()),
                json!({ "function": "SetNickname", "code": result.code(), "eid": data["eid"] }),
            ));
        }
        let after = nickname_of(&read_profiles(ask)?);
        data["verified_nickname"] = json!(after);
        if after.as_deref() != Some(request.name.as_str()) {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "SetNickname was accepted but the profile list now shows {:?}, not {:?}",
                    after.as_deref().unwrap_or("(profile missing)"),
                    request.name
                ),
                json!({ "eid": data["eid"], "iccid": request.iccid, "expected": request.name, "actual": after }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// Which ES10c state change [`set_state`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// EnableProfile (lpac `profile enable`).
    Enable,
    /// DisableProfile (lpac `profile disable`).
    Disable,
}

/// A profile named by ICCID or ISD-P AID, validated before a card is touched.
#[derive(Debug, Clone)]
struct ProfileRef {
    /// What the operator typed (the ICCID digits, or the AID in upper-case hex).
    target: String,
    iccid: Option<[u8; 10]>,
    aid: Option<Vec<u8>>,
}

impl ProfileRef {
    /// 18 to 20 decimal digits are an ICCID, otherwise an ISD-P AID of 5 to 16
    /// bytes written as hex (lpac takes 32 hex digits).
    fn new(id: &str) -> Result<Self, Failure> {
        let (iccid, aid, target) = if (18..=20).contains(&id.len())
            && id.bytes().all(|b| b.is_ascii_digit())
        {
            (Some(raw_iccid(id)?), None, id.to_owned())
        } else {
            match hex::decode(id) {
                Ok(aid) if (5..=16).contains(&aid.len()) => {
                    (None, Some(aid), id.to_ascii_uppercase())
                }
                _ => {
                    return Err(Failure::new(
                        "bad-profile-id",
                        format!(
                            "expected an ICCID (18 to 20 digits) or an ISD-P AID (10 to 32 hex digits), got {id:?}"
                        ),
                        json!({}),
                    ))
                }
            }
        };
        Ok(Self { target, iccid, aid })
    }

    fn matches(&self, p: &es10::ProfileInfo) -> bool {
        match (&self.iccid, &self.aid) {
            (Some(iccid), _) => p.iccid.as_deref() == Some(&iccid[..]),
            (_, Some(aid)) => p.isdp_aid.as_deref() == Some(&aid[..]),
            _ => false,
        }
    }

    fn identifier(&self) -> es10::ProfileIdentifier<'_> {
        match (&self.iccid, &self.aid) {
            (Some(iccid), _) => es10::ProfileIdentifier::Iccid(iccid),
            (_, Some(aid)) => es10::ProfileIdentifier::IsdpAid(aid),
            _ => unreachable!("ProfileRef::new sets one of iccid and aid"),
        }
    }

    /// The profile-not-found refusal, listing the ICCIDs that do exist.
    fn not_found(&self, eid: &str, profiles: &[es10::ProfileInfo]) -> Failure {
        Failure::new(
            "profile-not-found",
            format!("no profile {} on this eUICC", self.target),
            json!({ "eid": eid, "profile": self.target,
                "iccids": profiles.iter().filter_map(|p| p.iccid.as_deref().map(iccid_text)).collect::<Vec<_>>() }),
        )
    }
}

/// A request to enable or disable one profile. Built by [`StateChange::new`],
/// which checks the identifier before anything touches a card.
#[derive(Debug, Clone)]
pub struct StateChange {
    action: Action,
    profile: ProfileRef,
    /// Send the request. `false` (the default of the CLI) reads the card and
    /// reports what would change, sending nothing that changes it.
    pub apply: bool,
}

impl StateChange {
    /// Validates `id`: 18 to 20 decimal digits are an ICCID, otherwise an
    /// ISD-P AID of 5 to 16 bytes written as hex (lpac takes 32 hex digits).
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `bad-profile-id`.
    pub fn new(action: Action, id: &str, apply: bool) -> Result<Self, Failure> {
        Ok(Self {
            action,
            profile: ProfileRef::new(id)?,
            apply,
        })
    }
}

/// The refusal kind and wording for an ES10c result code other than ok(0)
/// (`enableResult` / `disableResult`, [SGP.22 v2.5 §5.7.16], §5.7.17; pySim
/// `rsp.asn`). `None` for a code neither function defines.
fn state_refusal(action: Action, code: u8) -> Option<(&'static str, &'static str)> {
    Some(match (code, action) {
        (1, _) => ("profile-not-found", "iccidOrAidNotFound"),
        (2, Action::Enable) => ("profile-not-in-disabled-state", "profileNotInDisabledState"),
        (2, Action::Disable) => ("profile-not-in-enabled-state", "profileNotInEnabledState"),
        (3, _) => ("disallowed-by-policy", "disallowedByPolicy"),
        (4, Action::Enable) => ("wrong-profile-reenabling", "wrongProfileReenabling"),
        (5, _) => ("cat-busy", "catBusy"),
        (127, _) => ("undefined-error", "undefinedError"),
        _ => return None,
    })
}

/// EnableProfile or DisableProfile (lpac `profile enable` / `profile disable`),
/// with REFRESH requested. Reads the EID and the profile list first and refuses,
/// sending nothing, an unknown profile (`profile-not-found`), enabling an enabled
/// profile (`already-enabled`) and disabling a disabled one (`already-disabled`).
/// Without [`StateChange::apply`] it stops there and reports the plan and its
/// `consequence` (`dry_run` true, `applied` false). With it, it sends the request,
/// maps every non-ok result code to its own error kind (see [`state_refusal`]),
/// re-reads the profile list and fails with `verify-failed` unless the profile is
/// now in the requested state.
///
/// # Errors
///
/// A [`Failure`].
pub fn set_state<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &StateChange,
) -> Result<Value, Failure> {
    use es10::ProfileState::{Disabled, Enabled};
    let (want, name) = match request.action {
        Action::Enable => (Enabled, "EnableProfile"),
        Action::Disable => (Disabled, "DisableProfile"),
    };
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let profiles = read_profiles(ask)?;
        let Some(profile) = profiles.iter().find(|p| request.profile.matches(p)) else {
            return Err(request.profile.not_found(&eid, &profiles));
        };
        let current = profile.profile_state;
        if !matches!(current, Some(Enabled | Disabled)) {
            return Err(Failure::new(
                "profile-state-unknown",
                format!(
                    "profile {} reports no usable state; refusing",
                    request.profile.target
                ),
                json!({ "eid": eid, "profile": request.profile.target }),
            ));
        }
        if current == Some(want) {
            let (kind, word) = match want {
                Enabled => ("already-enabled", "enabled"),
                Disabled => ("already-disabled", "disabled"),
                es10::ProfileState::Unknown(_) => unreachable!(),
            };
            return Err(Failure::new(
                kind,
                format!(
                    "profile {} is already {word}; nothing sent",
                    request.profile.target
                ),
                json!({ "eid": eid, "profile": request.profile.target }),
            ));
        }
        let enabled = profiles
            .iter()
            .filter(|p| p.profile_state == Some(Enabled))
            .count();
        let consequence = match request.action {
            Action::Enable => "Enabling switches the active profile: the device loses its current connection until it re-attaches (REFRESH is requested).",
            Action::Disable if enabled == 1 => "Disabling the only enabled profile leaves the eUICC with no active profile: the device has no subscription until one is enabled (REFRESH is requested).",
            Action::Disable => "Disabling this profile leaves another profile enabled (REFRESH is requested).",
        };
        let state_text = |s: es10::ProfileState| if s == Enabled { "enabled" } else { "disabled" };
        let mut data = json!({
            "eid": eid,
            "action": match request.action { Action::Enable => "enable", Action::Disable => "disable" },
            "profile": request.profile.target,
            "iccid": profile.iccid.as_deref().map(iccid_text),
            "isdp_aid": profile.isdp_aid.as_deref().map(hex::encode_upper),
            "current_state": current.map(state_text),
            "new_state": state_text(want),
            "refresh": true,
            "consequence": consequence,
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame = match request.action {
            Action::Enable => es10::enable_profile_request(request.profile.identifier(), true),
            Action::Disable => es10::disable_profile_request(request.profile.identifier(), true),
        }
        .map_err(exchange_failed)?;
        let response = ask(name, frame)?;
        let code = match request.action {
            Action::Enable => es10::decode_enable_profile(&response).map(|r| r.result.code()),
            Action::Disable => es10::decode_disable_profile(&response).map(|r| r.code()),
        }
        .map_err(|e| bad(name, e))?;
        if code != 0 {
            let (kind, word) =
                state_refusal(request.action, code).unwrap_or(("es10-refused", "unknown result"));
            return Err(Failure::new(
                kind,
                format!("{name} returned {word} (code {code}); the profile was not changed"),
                json!({ "function": name, "code": code, "eid": data["eid"], "profile": request.profile.target }),
            ));
        }
        let after = read_profiles(ask)?
            .iter()
            .find(|p| request.profile.matches(p))
            .and_then(|p| p.profile_state);
        data["verified_state"] = json!(after.map(state_text));
        if after != Some(want) {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "{name} was accepted but the profile list now shows {}, not {}",
                    after.map_or("(profile missing)", state_text),
                    state_text(want)
                ),
                json!({ "eid": data["eid"], "profile": request.profile.target, "expected": state_text(want), "actual": after.map(state_text) }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// The refusal for a non-ok result code of an erasing function: the kind named
/// for its code, or `es10-refused` for a code the function does not define.
fn erase_refusal(
    function: &'static str,
    code: u8,
    names: &[(u8, &'static str, &'static str)],
    extra: Value,
) -> Failure {
    let (kind, word) = names
        .iter()
        .find(|(c, _, _)| *c == code)
        .map_or(("es10-refused", "unknown result"), |(_, k, w)| (*k, *w));
    let mut data = json!({ "function": function, "code": code });
    if let (Some(into), Some(from)) = (data.as_object_mut(), extra.as_object()) {
        into.extend(from.clone());
    }
    Failure::new(
        kind,
        format!("{function} returned {word} (code {code}); nothing was erased"),
        data,
    )
}

/// A request to delete one profile. Built by [`ProfileDelete::new`], which
/// checks the identifier before anything touches a card.
#[derive(Debug, Clone)]
pub struct ProfileDelete {
    profile: ProfileRef,
    /// Send DeleteProfile. `false` (the default of the CLI) reads the card and
    /// reports what would be erased, sending nothing that changes it.
    pub apply: bool,
}

impl ProfileDelete {
    /// Validates `id` as [`StateChange::new`] does.
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `bad-profile-id`.
    pub fn new(id: &str, apply: bool) -> Result<Self, Failure> {
        Ok(Self {
            profile: ProfileRef::new(id)?,
            apply,
        })
    }
}

/// DeleteProfile (lpac `profile delete`). Reads the EID and the profile list
/// first and refuses, sending nothing, an unknown profile (`profile-not-found`)
/// and an enabled one (`profile-enabled`: disable it first). Without
/// [`ProfileDelete::apply`] it stops there and reports the plan and its
/// `consequence` (`dry_run` true, `applied` false). With it, it sends
/// DeleteProfile, maps every non-ok `deleteResult` ([SGP.22 v2.5 §5.7.18]; pySim
/// `rsp.asn`) to its own error kind, re-reads the profile list and fails with
/// `verify-failed` if the profile is still there.
///
/// # Errors
///
/// A [`Failure`].
pub fn delete_profile<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &ProfileDelete,
) -> Result<Value, Failure> {
    use es10::ProfileState::{Disabled, Enabled};
    const CODES: [(u8, &str, &str); 4] = [
        (1, "profile-not-found", "iccidOrAidNotFound"),
        (
            2,
            "profile-not-in-disabled-state",
            "profileNotInDisabledState",
        ),
        (3, "disallowed-by-policy", "disallowedByPolicy"),
        (127, "undefined-error", "undefinedError"),
    ];
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let profiles = read_profiles(ask)?;
        let Some(profile) = profiles.iter().find(|p| request.profile.matches(p)) else {
            return Err(request.profile.not_found(&eid, &profiles));
        };
        let target = &request.profile.target;
        match profile.profile_state {
            Some(Disabled) => {}
            Some(Enabled) => {
                return Err(Failure::new(
                    "profile-enabled",
                    format!("profile {target} is enabled; disable it first (sim-doctor euicc disable {target} --yes); nothing sent"),
                    json!({ "eid": eid, "profile": target }),
                ))
            }
            _ => {
                return Err(Failure::new(
                    "profile-state-unknown",
                    format!("profile {target} reports no usable state; refusing"),
                    json!({ "eid": eid, "profile": target }),
                ))
            }
        }
        let mut data = json!({
            "command": "delete",
            "eid": eid,
            "profile": target,
            "iccid": profile.iccid.as_deref().map(iccid_text),
            "isdp_aid": profile.isdp_aid.as_deref().map(hex::encode_upper),
            "nickname": profile.profile_nickname,
            "name": profile.profile_name,
            "consequence": "The profile is erased permanently. It can only come back by downloading it again from the operator.",
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame =
            es10::delete_profile_request(request.profile.identifier()).map_err(exchange_failed)?;
        let result = es10::decode_delete_profile(&ask("DeleteProfile", frame)?)
            .map_err(|e| bad("DeleteProfile", e))?
            .result;
        if result != es10::DeleteResult::Ok {
            return Err(erase_refusal(
                "DeleteProfile",
                result.code(),
                &CODES,
                json!({ "eid": eid, "profile": target }),
            ));
        }
        let still = read_profiles(ask)?
            .iter()
            .any(|p| request.profile.matches(p));
        data["profile_still_listed"] = json!(still);
        if still {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "DeleteProfile was accepted but profile {target} is still in the profile list"
                ),
                json!({ "eid": eid, "profile": target }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// A request for eUICCMemoryReset. Built by [`MemoryReset::new`], which checks
/// the options and the confirmation before anything touches a card.
#[derive(Debug, Clone)]
pub struct MemoryReset {
    options: es10::ResetOptions,
    confirm_eid: Option<String>,
    /// Send the reset. `false` reads the card and lists what would be erased.
    pub apply: bool,
}

impl MemoryReset {
    /// Validates the request: at least one option (`no-reset-option`), a
    /// well-formed `confirm_eid` of 32 hex digits (`bad-eid`), and, when
    /// `apply` is set, a `confirm_eid` at all (`confirm-eid-required`). Whether
    /// it matches the card is checked in [`memory_reset`].
    ///
    /// # Errors
    ///
    /// A [`Failure`] of one of those kinds.
    pub fn new(
        options: es10::ResetOptions,
        confirm_eid: Option<&str>,
        apply: bool,
    ) -> Result<Self, Failure> {
        if options.is_empty() {
            return Err(Failure::new(
                "no-reset-option",
                "choose what to reset: --operational, --test and/or --smdp-address; nothing is selected by default".to_owned(),
                json!({}),
            ));
        }
        let confirm_eid = match confirm_eid {
            Some(eid) if eid.len() == 32 && eid.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Some(eid.to_ascii_uppercase())
            }
            Some(eid) => {
                return Err(Failure::new(
                    "bad-eid",
                    format!("--confirm-eid must be the 32 hex digits of the EID, got {eid:?}"),
                    json!({}),
                ))
            }
            None => None,
        };
        if apply && confirm_eid.is_none() {
            return Err(Failure::new(
                "confirm-eid-required",
                "an eUICC memory reset needs both --yes and --confirm-eid <EID> (the EID of the card, from `euicc info`)".to_owned(),
                json!({}),
            ));
        }
        Ok(Self {
            options,
            confirm_eid,
            apply,
        })
    }

    /// Whether the reset would erase `p`: operational profiles (a profile with
    /// no class counts, as SGP.22 makes operational the default) and field-loaded
    /// test profiles; provisioning profiles are never touched.
    fn erases(&self, p: &es10::ProfileInfo) -> bool {
        use es10::ProfileClass::{Operational, Provisioning, Test};
        match p.profile_class {
            Some(Test) => self.options.delete_field_loaded_test_profiles,
            Some(Provisioning) => false,
            Some(Operational) | None => self.options.delete_operational_profiles,
            Some(es10::ProfileClass::Unknown(_)) => false,
        }
    }
}

/// eUICCMemoryReset (lpac `chip purge`, [SGP.22 v2.5 §5.7.19]). Reads the EID
/// and the profile list first and refuses, sending nothing, an EID that is not
/// the `--confirm-eid` one (`eid-mismatch`). Without [`MemoryReset::apply`] it
/// stops there and lists every profile that would be erased (`profiles_to_erase`,
/// `dry_run` true). With it, it sends the reset, maps `nothingToDelete(1)` and
/// `undefinedError(127)` to their own kinds (any other code is `es10-refused`),
/// re-reads the profile list and fails with `verify-failed` if an erased profile
/// is still listed.
///
/// # Errors
///
/// A [`Failure`].
pub fn memory_reset<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &MemoryReset,
) -> Result<Value, Failure> {
    const CODES: [(u8, &str, &str); 2] = [
        (1, "nothing-to-delete", "nothingToDelete"),
        (127, "undefined-error", "undefinedError"),
    ];
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        if let Some(want) = &request.confirm_eid {
            if *want != eid {
                return Err(Failure::new(
                    "eid-mismatch",
                    format!("--confirm-eid {want} is not this card's EID {eid}; nothing sent"),
                    json!({ "eid": eid, "confirm_eid": want }),
                ));
            }
        }
        let profiles = read_profiles(ask)?;
        let mut data = json!({
            "command": "reset",
            "eid": eid,
            "options": {
                "delete_operational_profiles": request.options.delete_operational_profiles,
                "delete_field_loaded_test_profiles": request.options.delete_field_loaded_test_profiles,
                "reset_default_smdp_address": request.options.reset_default_smdp_address,
            },
            "profiles_to_erase": profiles.iter().filter(|p| request.erases(p)).map(profile_json).collect::<Vec<_>>(),
            "consequence": "Every listed profile is erased permanently, an enabled one included, and can only come back by downloading it again from the operator.",
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame = es10::memory_reset_request(request.options).map_err(exchange_failed)?;
        let result = es10::decode_memory_reset(&ask("eUICCMemoryReset", frame)?)
            .map_err(|e| bad("eUICCMemoryReset", e))?;
        if result != es10::ResetResult::Ok {
            return Err(erase_refusal(
                "eUICCMemoryReset",
                result.code(),
                &CODES,
                json!({ "eid": eid }),
            ));
        }
        let left: Vec<Value> = read_profiles(ask)?
            .iter()
            .filter(|p| request.erases(p))
            .map(profile_json)
            .collect();
        data["profiles_remaining"] = json!(left);
        if !left.is_empty() {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "eUICCMemoryReset was accepted but {} profile(s) it should have erased are still listed",
                    left.len()
                ),
                json!({ "eid": eid, "profiles_remaining": left }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// A request to remove one notification from the eUICC's list. Built by hand:
/// the sequence number is already a number.
#[derive(Debug, Clone, Copy)]
pub struct NotificationRemoval {
    /// `seqNumber` of the notification, as `euicc notifications` lists it.
    pub seq_number: u32,
    /// Send RemoveNotificationFromList. `false` reads and reports only.
    pub apply: bool,
}

/// RemoveNotificationFromList (lpac `notification remove`, [SGP.22 v2.5
/// §5.7.12]). Reads the EID and the notification list first and refuses,
/// sending nothing, a sequence number not in the list (`notification-not-found`).
/// Without `apply` it stops there. With it, it sends the request, maps
/// `nothingToDelete(1)` and `undefinedError(127)` to their own kinds (any other
/// code is `es10-refused`), re-reads the list and fails with `verify-failed` if
/// the notification is still there.
///
/// # Errors
///
/// A [`Failure`].
pub fn remove_notification<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: NotificationRemoval,
) -> Result<Value, Failure> {
    const CODES: [(u8, &str, &str); 2] = [
        (1, "nothing-to-delete", "nothingToDelete"),
        (127, "undefined-error", "undefinedError"),
    ];
    let seq = request.seq_number;
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let list = read_notifications(ask)?;
        let Some(found) = list.iter().find(|n| n.seq_number == seq) else {
            return Err(Failure::new(
                "notification-not-found",
                format!("no notification with sequence number {seq} on this eUICC; nothing sent"),
                json!({ "eid": eid, "seq_number": seq,
                    "seq_numbers": list.iter().map(|n| n.seq_number).collect::<Vec<_>>() }),
            ));
        };
        let mut data = json!({
            "command": "notification-remove",
            "eid": eid,
            "notification": notification_json(found),
            "consequence": "A removed notification is never sent to the operator's server.",
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame = es10::remove_notification_request(seq);
        let result = es10::decode_remove_notification(&ask("RemoveNotificationFromList", frame)?)
            .map_err(|e| bad("RemoveNotificationFromList", e))?;
        if result != es10::RemoveNotificationResult::Ok {
            return Err(erase_refusal(
                "RemoveNotificationFromList",
                result.code(),
                &CODES,
                json!({ "eid": eid, "seq_number": seq }),
            ));
        }
        let still = read_notifications(ask)?.iter().any(|n| n.seq_number == seq);
        data["notification_still_listed"] = json!(still);
        if still {
            return Err(Failure::new(
                "verify-failed",
                format!("RemoveNotificationFromList was accepted but notification {seq} is still listed"),
                json!({ "eid": eid, "seq_number": seq }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// The `format` member of a notification dump file.
pub const DUMP_FORMAT: &str = "sim-doctor-notification-dump/1";

/// One dumped notification: the metadata fields of [`notification_json`], the
/// arm, the transaction id and the signed bytes as hex.
fn pending_json(p: &es10::PendingNotification) -> Value {
    let mut v = notification_json(&p.metadata);
    v["kind"] = json!(match p.kind {
        es10::PendingKind::ProfileInstallationResult => "profile-installation-result",
        es10::PendingKind::OtherSigned => "other-signed-notification",
    });
    v["transaction_id"] = json!(p.transaction_id.as_deref().map(hex::encode_upper));
    v["pending_notification_hex"] = json!(hex::encode_upper(&p.raw));
    v
}

/// RetrieveNotificationsList (lpac `notification dump`, ES10b): the full,
/// signed pending notifications, for every one or just `seq_number`. Read-only:
/// retrieving does not remove (that stays `notifications remove`). The result
/// is the dump document (`format`, `eid`, `notifications`) that
/// [`crate::notif::replay`] reads back. No pending notification is an empty
/// list; a `seq_number` the card does not have is `notification-not-found`.
///
/// # Errors
///
/// A [`Failure`]; a notification that does not decode is `decode-failed`.
pub fn dump_notifications<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    seq_number: Option<u32>,
) -> Result<Value, Failure> {
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let frame = es10::retrieve_notifications_request(seq_number);
        let list =
            match es10::decode_retrieve_notifications(&ask("RetrieveNotificationsList", frame)?)
                .map_err(|e| bad("RetrieveNotificationsList", e))?
            {
                es10::RetrieveNotificationsResponse::Ok(list) => list,
                es10::RetrieveNotificationsResponse::Error(1) => match seq_number {
                    None => Vec::new(),
                    Some(seq) => {
                        return Err(Failure::new(
                            "notification-not-found",
                            format!("no notification with sequence number {seq} on this eUICC"),
                            json!({ "eid": eid, "seq_number": seq }),
                        ))
                    }
                },
                es10::RetrieveNotificationsResponse::Error(code) => {
                    return Err(Failure::new(
                        "es10-refused",
                        format!("RetrieveNotificationsList returned error code {code}"),
                        json!({ "function": "RetrieveNotificationsList", "code": code }),
                    ))
                }
            };
        Ok(json!({
            "command": "notification-dump",
            "format": DUMP_FORMAT,
            "eid": eid,
            "notifications": list.iter().map(pending_json).collect::<Vec<_>>(),
        }))
    })
}

/// The human report for [`dump_notifications`]; the bytes stay in the dump.
pub fn dump_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = format!("EID: {}\n", text(&data["eid"]));
    for n in data["notifications"].as_array().into_iter().flatten() {
        out += &format!(
            "{}\t{}\t{}\t{}\t{} bytes\n",
            text(&n["seq_number"]),
            n["operation"]
                .as_array()
                .map(|a| a.iter().map(&text).collect::<Vec<_>>().join("+"))
                .unwrap_or_default(),
            text(&n["iccid"]),
            text(&n["address"]),
            n["pending_notification_hex"]
                .as_str()
                .map_or(0, |h| h.len() / 2),
        );
    }
    if data["notifications"].as_array().is_none_or(Vec::is_empty) {
        out += "No pending notifications.\n";
    }
    out
}

fn version(v: [u8; 3]) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

fn hex_list(keys: &[Vec<u8>]) -> Value {
    keys.iter().map(hex::encode_upper).collect()
}

fn bits_json(b: &BitString, names: &[&str]) -> Value {
    let set: Vec<&str> = names
        .iter()
        .enumerate()
        .filter(|(i, _)| b.bit(*i))
        .map(|(_, n)| *n)
        .collect();
    json!({ "hex": hex::encode_upper(&b.bytes), "unused_bits": b.unused_bits, "set": set })
}

const RSP_CAPABILITY: [&str; 6] = [
    "additionalProfile",
    "crlSupport",
    "rpmSupport",
    "testProfileSupport",
    "deviceInfoExtensibilitySupport",
    "serviceSpecificDataSupport",
];

fn info1_json(i: &es10::EuiccInfo1) -> Value {
    json!({
        "svn": version(i.svn),
        "ci_pk_id_for_verification": hex_list(&i.ci_pk_id_for_verification),
        "ci_pk_id_for_signing": hex_list(&i.ci_pk_id_for_signing),
    })
}

fn info2_json(i: &es10::EuiccInfo2) -> Value {
    json!({
        "profile_version": version(i.profile_version),
        "svn": version(i.svn),
        "firmware_version": version(i.euicc_firmware_ver),
        "ext_card_resource": hex::encode_upper(&i.ext_card_resource),
        "uicc_capability": hex::encode_upper(&i.uicc_capability.bytes),
        "ts102241_version": i.ts102241_version.map(version),
        "globalplatform_version": i.globalplatform_version.map(version),
        "rsp_capability": bits_json(&i.rsp_capability, &RSP_CAPABILITY),
        "ci_pk_id_for_verification": hex_list(&i.ci_pk_id_for_verification),
        "ci_pk_id_for_signing": hex_list(&i.ci_pk_id_for_signing),
        "category": i.euicc_category.map(|c| match c {
            es10::EuiccCategory::Other => "other".to_owned(),
            es10::EuiccCategory::BasicEuicc => "basic".to_owned(),
            es10::EuiccCategory::MediumEuicc => "medium".to_owned(),
            es10::EuiccCategory::ContactlessEuicc => "contactless".to_owned(),
            es10::EuiccCategory::Unknown(n) => format!("unknown({n})"),
        }),
        "forbidden_profile_policy_rules": i.forbidden_profile_policy_rules.as_ref()
            .map(|b| bits_json(b, &["pprUpdateControl", "ppr1", "ppr2"])),
        "pp_version": version(i.pp_version),
        "sas_accreditation_number": i.sas_accreditation_number,
        "certification_data_object": i.certification_data_object.as_ref().map(|c| json!({
            "platform_label": c.platform_label,
            "discovery_base_url": c.discovery_base_url,
        })),
        "tre_properties": i.tre_properties.as_ref()
            .map(|b| bits_json(b, &["isDiscrete", "isIntegrated", "usesRemoteMemory"])),
        "tre_product_reference": i.tre_product_reference,
        "additional_profile_package_versions":
            i.additional_euicc_profile_package_versions.iter().map(|v| version(*v)).collect::<Vec<_>>(),
    })
}

/// The ICCID as digits (nibble-swapped, `F` padding dropped), falling back to
/// the raw hex if it is not decodable.
fn iccid_text(raw: &[u8]) -> String {
    crate::ef::decode_iccid(raw).map_or_else(|_| hex::encode_upper(raw), |d| d.as_str().to_owned())
}

fn profile_json(p: &es10::ProfileInfo) -> Value {
    use es10::{ProfileClass, ProfileState};
    json!({
        "iccid": p.iccid.as_deref().map(iccid_text),
        "isdp_aid": p.isdp_aid.as_deref().map(hex::encode_upper),
        "state": p.profile_state.map(|s| match s {
            ProfileState::Enabled => "enabled".to_owned(),
            ProfileState::Disabled => "disabled".to_owned(),
            ProfileState::Unknown(n) => format!("unknown({n})"),
        }),
        "nickname": p.profile_nickname,
        "provider": p.service_provider_name,
        "name": p.profile_name,
        "class": p.profile_class.map(|c| match c {
            ProfileClass::Test => "test".to_owned(),
            ProfileClass::Provisioning => "provisioning".to_owned(),
            ProfileClass::Operational => "operational".to_owned(),
            ProfileClass::Unknown(n) => format!("unknown({n})"),
        }),
    })
}

pub(crate) fn notification_json(n: &es10::NotificationMetadata) -> Value {
    let ops: Vec<&str> = ["install", "enable", "disable", "delete"]
        .iter()
        .enumerate()
        .filter(|(i, _)| n.operation.bit(*i))
        .map(|(_, s)| *s)
        .collect();
    json!({
        "seq_number": n.seq_number,
        "operation": ops,
        "address": n.address,
        "iccid": n.iccid.as_deref().map(iccid_text),
    })
}

/// The human report for `data` (as [`run`] returned it): `key: value` lines
/// and a table, every card-derived string through [`sanitize`].
pub fn to_human(query: Query, data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = String::new();
    match query {
        Query::Info => {
            out += &format!("EID: {}\n", text(&data["eid"]));
            out += &format!(
                "SM-DP+ (default): {}\nSM-DS (root): {}\n",
                text(&data["configured_addresses"]["default_smdp"]),
                text(&data["configured_addresses"]["root_smds"]),
            );
            for (title, key) in [("EUICCInfo1", "euicc_info1"), ("EUICCInfo2", "euicc_info2")] {
                out += &format!("{title}:\n");
                if let Some(map) = data[key].as_object() {
                    for (k, v) in map {
                        let shown = match v {
                            Value::Array(a) => a.iter().map(&text).collect::<Vec<_>>().join(", "),
                            Value::Object(o) => o.values().map(&text).collect::<Vec<_>>().join(" "),
                            other => text(other),
                        };
                        out += &format!("  {k}: {shown}\n");
                    }
                }
            }
        }
        Query::Profiles => {
            out += "ICCID\tSTATE\tCLASS\tNICKNAME\tPROVIDER\tNAME\n";
            for p in data["profiles"].as_array().into_iter().flatten() {
                out += &format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    text(&p["iccid"]),
                    text(&p["state"]),
                    text(&p["class"]),
                    text(&p["nickname"]),
                    text(&p["provider"]),
                    text(&p["name"]),
                );
            }
        }
        Query::Notifications => {
            out += "SEQ\tOPERATION\tICCID\tADDRESS\n";
            for n in data["notifications"].as_array().into_iter().flatten() {
                let ops = n["operation"]
                    .as_array()
                    .map(|a| a.iter().map(&text).collect::<Vec<_>>().join("+"))
                    .unwrap_or_default();
                out += &format!(
                    "{}\t{}\t{}\t{}\n",
                    text(&n["seq_number"]),
                    ops,
                    text(&n["iccid"]),
                    text(&n["address"]),
                );
            }
        }
        Query::Challenge => {
            out += &format!("challenge: {}\n", text(&data["challenge"]));
        }
    }
    out
}

/// The human report for [`nickname`]'s `data`.
pub fn nickname_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = format!(
        "EID: {}\nICCID: {}\nCurrent nickname: {:?}\nNew nickname: {:?}\n",
        text(&data["eid"]),
        text(&data["iccid"]),
        text(&data["current_nickname"]),
        text(&data["new_nickname"]),
    );
    out += if data["applied"] == true {
        "SetNickname sent; the profile list now shows the new nickname.\n"
    } else {
        "Dry run: nothing was sent. Re-run with --yes to set the nickname.\n"
    };
    out
}

/// The human report for [`set_state`]'s `data`.
pub fn state_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let verb = if data["action"] == "enable" {
        "Enable"
    } else {
        "Disable"
    };
    let mut out = format!(
        "EID: {}\nICCID: {}\nISD-P AID: {}\nState: {} -> {}\nConsequence: {}\n",
        text(&data["eid"]),
        text(&data["iccid"]),
        text(&data["isdp_aid"]),
        text(&data["current_state"]),
        text(&data["new_state"]),
        text(&data["consequence"]),
    );
    out += &if data["applied"] == true {
        format!("{verb}Profile sent; the profile list now shows the new state.\n")
    } else {
        format!(
            "Dry run: nothing was sent. Re-run with --yes to {}.\n",
            verb.to_lowercase()
        )
    };
    out
}

/// The human report for [`delete_profile`], [`memory_reset`] and
/// [`remove_notification`]: what is (or was) erased, the consequence, and
/// whether anything was sent.
pub fn erase_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = format!("EID: {}\n", text(&data["eid"]));
    let what = match data["command"].as_str() {
        Some("delete") => {
            out += &format!(
                "ICCID: {}\nISD-P AID: {}\nNickname: {}\nName: {}\n",
                text(&data["iccid"]),
                text(&data["isdp_aid"]),
                text(&data["nickname"]),
                text(&data["name"]),
            );
            "delete the profile"
        }
        Some("reset") => {
            out += "Profiles that would be erased:\n";
            for p in data["profiles_to_erase"].as_array().into_iter().flatten() {
                out += &format!(
                    "  {}\t{}\t{}\t{}\n",
                    text(&p["iccid"]),
                    text(&p["state"]),
                    text(&p["class"]),
                    text(&p["name"]),
                );
            }
            if data["options"]["reset_default_smdp_address"] == true {
                out += "The default SM-DP+ address is reset.\n";
            }
            "reset the eUICC"
        }
        _ => {
            let n = &data["notification"];
            out += &format!(
                "Notification {}: {} {} {}\n",
                text(&n["seq_number"]),
                n["operation"]
                    .as_array()
                    .map(|a| a.iter().map(&text).collect::<Vec<_>>().join("+"))
                    .unwrap_or_default(),
                text(&n["iccid"]),
                text(&n["address"]),
            );
            "remove the notification"
        }
    };
    out += &format!("Consequence: {}\n", text(&data["consequence"]));
    out += &if data["applied"] == true {
        "Sent and verified by a re-read.\n".to_owned()
    } else if data["command"] == "reset" {
        format!(
            "Dry run: nothing was sent. Re-run with --yes --confirm-eid {} to {what}.\n",
            text(&data["eid"])
        )
    } else {
        format!("Dry run: nothing was sent. Re-run with --yes to {what}.\n")
    };
    out
}

/// What setting the default SM-DP+ address costs, in the words the other eUICC
/// writes use (issue #227). Printed by the dry run, carried in `data`, and
/// attached to the command's own help, so a caller reading only the machine
/// output still learns the consequence.
pub const DEFAULT_DP_WARNING: &str = "WARNING: this changes where the eUICC looks for profiles. The default SM-DP+ address is where the card sends every future download request, so an address that cannot be reached leaves it unable to download anything until the address is set back.";

/// A request to set the eUICC's default SM-DP+ address (ES10a
/// SetDefaultDpAddress, [SGP.22 v2.5 §5.7.4]). Built by [`DefaultDp::new`],
/// which checks the address before anything touches a card.
#[derive(Debug, Clone)]
pub struct DefaultDp {
    address: String,
    /// Send SetDefaultDpAddress. `false` (the default of the CLI) sends no
    /// byte at all and opens no reader: [`default_dp_plan`] reports the exact
    /// request instead.
    pub apply: bool,
}

impl DefaultDp {
    /// Validates `address` before any reader is opened: not empty, at most
    /// [`es10::MAX_DEFAULT_DP_ADDRESS_BYTES`] bytes, and free of control
    /// characters so the address cannot drive a terminal when it is shown.
    /// The argument is `&str` and clap hands the CLI a `String`, so it is UTF-8
    /// by construction and a lone surrogate cannot reach this point; the length
    /// is what is checked, and [`es10::set_default_dp_request`] enforces it
    /// again on the wire bytes.
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `bad-sm-dp-address`.
    pub fn new(address: &str, apply: bool) -> Result<Self, Failure> {
        let refused = |message: String| {
            Failure::new(
                "bad-sm-dp-address",
                message,
                json!({ "bytes": address.len(), "max": es10::MAX_DEFAULT_DP_ADDRESS_BYTES }),
            )
        };
        if address.is_empty() {
            return Err(refused(
                "the default SM-DP+ address must not be empty".to_owned(),
            ));
        }
        if address.len() > es10::MAX_DEFAULT_DP_ADDRESS_BYTES {
            return Err(refused(format!(
                "the default SM-DP+ address is {} bytes of UTF-8; this build allows at most {}",
                address.len(),
                es10::MAX_DEFAULT_DP_ADDRESS_BYTES
            )));
        }
        if address.chars().any(char::is_control) {
            return Err(refused(
                "the default SM-DP+ address must not contain control characters".to_owned(),
            ));
        }
        Ok(Self {
            address: address.to_owned(),
            apply,
        })
    }
}

/// The dry run of [`set_default_dp`]: the exact request bytes, the warning, and
/// no card at all.
///
/// No reader is opened here - the library is not even handed a session, so it
/// cannot open one. That is what `card_touched: false` means.
pub fn default_dp_plan(request: &DefaultDp) -> Result<Value, Failure> {
    let frame = es10::set_default_dp_request(&request.address).map_err(exchange_failed)?;
    Ok(json!({
        "command": "set-default-dp",
        "default_smdp_address": request.address,
        "request_hex": hex::encode_upper(&frame),
        "warning": DEFAULT_DP_WARNING,
        "dry_run": true,
        "applied": false,
        "card_touched": false,
    }))
}

/// SetDefaultDpAddress (ES10a, [SGP.22 v2.5 §5.7.4]) on an already validated
/// request. Reads the configured addresses, sends `BF3F { 80 <address> }` as
/// one STORE DATA, maps the result, then re-reads the configured addresses and
/// fails with kind `verify-failed` unless the default SM-DP+ address is now the
/// one that was set. One attempt: there is no retry loop, and the single
/// STORE DATA path in [`es10::store_data_sized`] is the only one used.
///
/// The re-read is GetEuiccConfiguredAddresses (`BF3C`) - the same read
/// `euicc info` reports `configured_addresses.default_smdp` from, asked on the
/// same channel, so verification cannot disagree with what the operator sees.
///
/// # Errors
///
/// A [`Failure`]: `undefined-error` for `undefinedError(127)`, `es10-refused`
/// for a result code the enumeration does not name, `verify-failed` when the
/// card accepted the write and does not show the address.
pub fn set_default_dp<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &DefaultDp,
) -> Result<Value, Failure> {
    in_channel(session, aid, max_segment, |ask| {
        let configured = |ask: &mut Ask<'_>| {
            es10::decode_configured_addresses(&ask(
                "GetEuiccConfiguredAddresses",
                es10::get_euicc_configured_addresses_request(),
            )?)
            .map(|a| a.default_dp_address)
            .map_err(|e| bad("GetEuiccConfiguredAddresses", e))
        };
        let frame = es10::set_default_dp_request(&request.address).map_err(exchange_failed)?;
        let mut data = json!({
            "command": "set-default-dp",
            "default_smdp_address": request.address,
            "request_hex": hex::encode_upper(&frame),
            "warning": DEFAULT_DP_WARNING,
            "dry_run": false,
            "applied": false,
            "previous_default_smdp_address": configured(&mut *ask)?,
        });
        let result = es10::decode_set_default_dp(&ask("SetDefaultDpAddress", frame)?)
            .map_err(|e| bad("SetDefaultDpAddress", e))?;
        if result.result != es10::SetDefaultDpResult::Ok {
            return Err(Failure::new(
                if result.result == es10::SetDefaultDpResult::UndefinedError {
                    "undefined-error"
                } else {
                    "es10-refused"
                },
                format!(
                    "SetDefaultDpAddress returned result code {}",
                    result.result.code()
                ),
                json!({
                    "function": "SetDefaultDpAddress",
                    "code": result.result.code(),
                    "default_smdp_address": request.address,
                }),
            ));
        }
        let after = configured(&mut *ask)?;
        let verified = after.as_deref() == Some(request.address.as_str());
        data["verified_default_smdp_address"] = json!(after.clone());
        if !verified {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "SetDefaultDpAddress was accepted but the configured default SM-DP+ address is now {}, not {}",
                    after.as_deref().unwrap_or("(none configured)"),
                    request.address
                ),
                json!({
                    "expected": request.address,
                    "actual": after,
                    "function": "GetEuiccConfiguredAddresses",
                }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// The human report for [`default_dp_plan`] and [`set_default_dp`].
pub fn default_dp_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = format!(
        "Default SM-DP+ address: {}\nRequest bytes: {}\n",
        text(&data["default_smdp_address"]),
        text(&data["request_hex"]),
    );
    if let Value::String(previous) = &data["previous_default_smdp_address"] {
        out += &format!("Current default SM-DP+ address: {}\n", sanitize(previous));
    }
    out += &format!("{}\n", text(&data["warning"]));
    out += if data["applied"] == true {
        "SetDefaultDpAddress sent; the configured addresses now show the new one.\n"
    } else {
        "Dry run: nothing was sent and no reader was opened. Re-run with --yes to set it.\n"
    };
    out
}

// ---------------------------------------------------------------------------
// Raw STORE DATA: the escape hatch
// ---------------------------------------------------------------------------

/// Largest raw ES10x request [`raw_store_data`] carries, in bytes.
///
/// A STORE DATA block holds at most [`es10::MAX_BLOCK_DATA`] bytes and P2 is
/// one octet, so one request can be at most 256 blocks - 65280 bytes
/// ([SGP.22 v2.5 section 5.7.6]). This bound is stricter, and it is a choice
/// rather than a quotation: a request an operator hand-writes to probe an
/// undocumented ES10 function is tens to hundreds of bytes, so 8192 leaves
/// ample room for the largest hand-built one while keeping the read bounded,
/// the plan printable and the number of card exchanges small.
pub const MAX_RAW_STORE_DATA: usize = 8192;

/// The STORE DATA class byte before a logical channel is folded into it: 80,
/// the base of the 8x / Cx classes of [SGP.22 v2.5 section 5.7.2] Table 47. A
/// dry run can only print this, because the channel the card will open is not
/// known until the card answers.
pub const STORE_DATA_BASE_CLA: u8 = 0x80;

/// What the dry run of [`raw_store_data`] prints in `note`: what would happen,
/// and what does not.
pub const DRY_RUN_NOTE: &str = "WARNING: no card was contacted and nothing was sent. --yes sends this payload to the ISD-R as raw STORE DATA, and the card may act on it in ways this tool cannot undo. No keys are involved: STORE DATA on a fresh logical channel is not SCP03.";

/// The STORE DATA class byte on logical channel `n`: [`STORE_DATA_BASE_CLA`]
/// with the channel folded in, exactly as [`channel_cla`] does for every other
/// function this module sends.
pub fn store_data_class(channel: u8) -> u8 {
    channel_cla(true, channel)
}

/// One operator-supplied ES10x request to send to the ISD-R as STORE DATA - the
/// escape hatch for a function this tool does not implement (pySim-shell
/// `do_es10x_store_data` in `pysim/shell.py`).
///
/// No keys are involved. STORE DATA on a freshly opened logical channel is
/// plain, not SCP03, so there is no key file to give and no authentication
/// that can fail.
#[derive(Debug, Clone)]
pub struct RawStoreData {
    payload: Vec<u8>,
    /// Send it. `false` - the CLI default - cuts the blocks and reports them
    /// without contacting a card.
    pub apply: bool,
}

impl RawStoreData {
    /// Checks the payload before anything else looks at it: a STORE DATA needs
    /// at least one data byte ([SGP.22 v2.5 section 5.7.6]) and this command
    /// carries at most [`MAX_RAW_STORE_DATA`].
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `empty-payload` or `payload-too-large`.
    pub fn new(payload: Vec<u8>, apply: bool) -> Result<Self, Failure> {
        if payload.is_empty() {
            return Err(Failure::new(
                "empty-payload",
                "a raw STORE DATA needs at least one byte of ES10x request".to_owned(),
                json!({ "bytes": 0, "max": MAX_RAW_STORE_DATA }),
            ));
        }
        if payload.len() > MAX_RAW_STORE_DATA {
            return Err(Failure::new(
                "payload-too-large",
                format!(
                    "the raw STORE DATA payload is {} bytes; this command refuses more than {MAX_RAW_STORE_DATA}",
                    payload.len()
                ),
                json!({ "bytes": payload.len(), "max": MAX_RAW_STORE_DATA }),
            ));
        }
        Ok(Self { payload, apply })
    }

    /// The request bytes, exactly as the operator gave them.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// From the hex an operator typed: `BF3E00`, `bf 3e 00`, `BF:3E:00` and
    /// `0xBF3E00` all parse, the same text forms `card decode_hex` takes.
    /// Checked before a reader is opened.
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `not-hex`, plus [`RawStoreData::new`].
    pub fn from_hex(text: &str, apply: bool) -> Result<Self, Failure> {
        let cleaned: String = text
            .trim()
            .trim_start_matches("0x")
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .collect();
        let bytes = hex::decode(&cleaned).map_err(|_| {
            Failure::new(
                "not-hex",
                format!("{text:?} is not hex; the ES10x request is bytes of hex"),
                json!({ "chars": cleaned.chars().count() }),
            )
        })?;
        Self::new(bytes, apply)
    }

    /// From a reader, bounded. At most [`MAX_RAW_STORE_DATA`] bytes of hex are
    /// read - two characters per payload byte, and one byte more to see that
    /// the stream does not stop there - so a stream can never grow the request
    /// without limit and no flag turns that off.
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `payload-too-large` when the stream is longer
    /// than the bound, `cannot-read` when the reader fails, plus
    /// [`RawStoreData::from_hex`] for the text it carries.
    pub fn from_reader(reader: &mut dyn std::io::Read, apply: bool) -> Result<Self, Failure> {
        use std::io::Read as _;
        let cap = MAX_RAW_STORE_DATA * 2 + 1;
        let mut text = Vec::new();
        reader
            .take(cap as u64)
            .read_to_end(&mut text)
            .map_err(|e| {
                Failure::new(
                    "cannot-read",
                    format!("cannot read the payload: {e}"),
                    json!({}),
                )
            })?;
        if text.len() >= cap {
            return Err(Failure::new(
                "payload-too-large",
                format!(
                    "the payload stream is longer than {MAX_RAW_STORE_DATA} bytes of hex; this command refuses more"
                ),
                json!({ "max": MAX_RAW_STORE_DATA }),
            ));
        }
        Self::from_hex(&String::from_utf8_lossy(&text), apply)
    }
}

/// The STORE DATA blocks `payload` becomes on the class byte `cla`, at most
/// `max_segment` data bytes each: what a dry run prints and what `--yes` sends,
/// cut by [`es10::blocks_sized`], the one segmentation this tool has.
///
/// # Errors
///
/// A [`Failure`] of kind `store-data-refused` when the request cannot be
/// carried: more than 256 blocks at this segment size (P2 is one octet), or a
/// segment size outside 1 to 255.
pub fn raw_plan(cla: u8, payload: &[u8], max_segment: usize) -> Result<Value, Failure> {
    let blocks = es10::blocks_sized(cla, payload, max_segment).map_err(|e| {
        Failure::new(
            "store-data-refused",
            format!("this payload cannot be carried as STORE DATA: {e}"),
            json!({ "bytes": payload.len(), "max_segment": max_segment }),
        )
    })?;
    let list = blocks
        .iter()
        .map(|command| {
            let wire = command
                .encode()
                .expect("a STORE DATA block this module built encodes");
            let lc = usize::from(wire[4]);
            json!({
                "cla": hex::encode_upper(&wire[..1]),
                "ins": hex::encode_upper(&wire[1..2]),
                "p1": hex::encode_upper(&wire[2..3]),
                "p2": hex::encode_upper(&wire[3..4]),
                "lc": hex::encode_upper(&wire[4..5]),
                "data": hex::encode_upper(&wire[5..5 + lc]),
                "apdu": hex::encode_upper(&wire),
            })
        })
        .collect::<Vec<_>>();
    let cla_hex = hex::encode_upper([cla]);
    Ok(json!({
        "cla": cla_hex,
        "cla_rule": "the logical channel the card opens is folded into the class byte: 80 is channel 0, 81 is channel 1, C0 is channel 4 (SGP.22 v2.5 section 5.7.2, Table 47)",
        "max_segment": max_segment,
        "block_count": list.len(),
        "blocks": list,
    }))
}

/// The plan a dry run reports and `--yes` sends, built offline: no card, no
/// channel, no reader.
///
/// # Errors
///
/// As [`raw_plan`], plus [`RawStoreData::new`].
pub fn raw_store_data_plan(max_segment: usize, request: &RawStoreData) -> Result<Value, Failure> {
    let payload = request.payload();
    Ok(json!({
        "card_touched": false,
        "dry_run": true,
        "sent": false,
        "applied": false,
        "payload_bytes": payload.len(),
        "payload_hex": hex::encode_upper(payload),
        "plan": raw_plan(STORE_DATA_BASE_CLA, payload, max_segment)?,
        "function": identify(payload),
        "note": DRY_RUN_NOTE,
    }))
}

/// The ES10 function whose request these exact bytes are, when this tool
/// implements one that builds them the same way. `None` for anything else,
/// which is most raw payloads.
fn identify(payload: &[u8]) -> Option<&'static str> {
    let known = [
        ("GetEuiccChallenge", es10::get_euicc_challenge_request()),
        ("GetEID", es10::get_eid_request()),
        ("GetEuiccInfo1", es10::get_euicc_info1_request()),
        ("GetEuiccInfo2", es10::get_euicc_info2_request()),
        (
            "GetEuiccConfiguredAddresses",
            es10::get_euicc_configured_addresses_request(),
        ),
        (
            "GetProfilesInfo",
            es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).unwrap_or_default(),
        ),
    ];
    known
        .iter()
        .find(|(_, request)| request.as_slice() == payload)
        .map(|(name, _)| *name)
}

/// The card answer, verbatim, plus a decoded form when this tool decodes the
/// function [`identify`] recognised. A function it does not decode is a
/// reported answer, not an error: the bytes are still there to read.
fn response_json(payload: &[u8], response: &[u8]) -> Value {
    let function = identify(payload);
    let mut out = json!({
        "function": function,
        "response_bytes": response.len(),
        "response_hex": hex::encode_upper(response),
    });
    match function {
        None => {
            out["decoded"] = json!(false);
            out["decoded_response"] = Value::Null;
            out["note"] = json!(format!(
                "this tool neither builds nor decodes this ES10 function, so the answer above is reported verbatim: {} bytes the card returned",
                response.len()
            ));
        }
        Some(function) => match decode_raw(function, response) {
            Ok(value) => {
                out["decoded"] = json!(true);
                out["decoded_response"] = value;
                out["note"] = json!("these bytes are byte-for-byte a request this tool builds, so the answer is decoded as well as shown verbatim");
            }
            Err(message) => {
                out["decoded"] = json!(false);
                out["decoded_response"] = Value::Null;
                out["decode_error"] = json!(message);
                out["note"] = json!("this tool decodes this ES10 function but the answer does not parse as one; the bytes are shown verbatim above");
            }
        },
    }
    out
}

/// The decoded response for `function`, with this module own decoders.
///
/// # Errors
///
/// A sentence when the answer does not parse as that function.
fn decode_raw(function: &'static str, response: &[u8]) -> Result<Value, String> {
    let wrong = |e: es10::DecodeError| bad(function, e).message;
    match function {
        "GetEuiccChallenge" => Ok(json!({
            "challenge": hex::encode_upper(
                es10::decode_get_euicc_challenge(response).map_err(wrong)?.challenge
            )
        })),
        "GetEID" => Ok(json!({
            "eid": hex::encode_upper(es10::decode_get_eid(response).map_err(wrong)?)
        })),
        "GetEuiccInfo1" => Ok(info1_json(
            &es10::decode_euicc_info1(response).map_err(wrong)?,
        )),
        "GetEuiccInfo2" => Ok(info2_json(
            &es10::decode_euicc_info2(response).map_err(wrong)?,
        )),
        "GetEuiccConfiguredAddresses" => {
            let a = es10::decode_configured_addresses(response).map_err(wrong)?;
            Ok(json!({
                "default_smdp": a.default_dp_address,
                "root_smds": a.root_ds_address,
            }))
        }
        "GetProfilesInfo" => match es10::decode_profiles_info(response).map_err(wrong)? {
            es10::ProfileInfoListResponse::Ok { profiles, .. } => Ok(json!({
                "profiles": profiles.iter().map(profile_json).collect::<Vec<_>>()
            })),
            es10::ProfileInfoListResponse::Error(code) => Ok(json!({ "error_code": code.code() })),
        },
        _ => Ok(Value::Null),
    }
}

/// [`in_channel`] records the channel it opened after the body has run, so
/// every planned block carries the real class byte here. A dry run could only
/// show [`STORE_DATA_BASE_CLA`]; what went on the wire is the truth.
fn fold_channel_into_plan(data: &mut Value) {
    let Some(number) = data["channel"]["number"].as_u64() else {
        return;
    };
    let cla = hex::encode_upper([store_data_class(u8::try_from(number).unwrap_or(0))]);
    if let Some(blocks) = data["plan"]["blocks"].as_array_mut() {
        for block in blocks {
            block["cla"] = json!(cla);
            if let Some(apdu) = block["apdu"]
                .as_str()
                .filter(|a| a.len() > 2)
                .map(str::to_owned)
            {
                block["apdu"] = json!(format!("{cla}{}", &apdu[2..]));
            }
        }
    }
    data["plan"]["cla"] = json!(cla);
}

/// Sends one operator-supplied ES10x request to the ISD-R as STORE DATA and
/// reports what came back, or - without [`RawStoreData::apply`] - plans it and
/// contacts no card at all.
///
/// With `apply` the request goes out on a freshly opened logical channel with
/// the ISD-R selected, exactly as every other function in this module does:
/// [`in_channel`] and [`es10::store_data_sized`], no second STORE DATA path.
/// The response is reassembled by [`session::send`] and reported verbatim.
///
/// # Errors
///
/// A [`Failure`]; `store-data-refused` when the request cannot be carried in
/// blocks, `es10-refused` when the ISD-R rejects it.
pub fn raw_store_data<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &RawStoreData,
) -> Result<Value, Failure> {
    if !request.apply {
        return raw_store_data_plan(max_segment, request);
    }
    let payload = request.payload().to_vec();
    let mut data = in_channel(session, aid, max_segment, |ask| {
        let response = ask("the raw STORE DATA request", payload.clone())?;
        Ok(response_json(&payload, &response))
    })?;
    data["plan"] = raw_plan(STORE_DATA_BASE_CLA, &payload, max_segment)?;
    fold_channel_into_plan(&mut data);
    data["card_touched"] = json!(true);
    data["dry_run"] = json!(false);
    data["sent"] = json!(true);
    data["applied"] = json!(true);
    Ok(data)
}

/// The human report for a raw STORE DATA run: the warning, the block
/// breakdown, and the card answer verbatim.
pub fn raw_to_human(data: &Value) -> String {
    let mut out = String::new();
    out.push_str(
        "WARNING: raw STORE DATA sends an operator-supplied ES10x request to the ISD-R.\n\
         The card may act on it in ways this tool cannot undo. No keys are involved: this is not SCP03.\n",
    );
    out.push_str(&format!(
        "Card touched: {}\n",
        if data["card_touched"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        }
    ));
    out.push_str(&format!(
        "Payload: {} bytes\n",
        data["payload_bytes"].as_u64().unwrap_or(0)
    ));
    out.push_str(&format!(
        "Function: {}\n",
        data["function"]
            .as_str()
            .unwrap_or("(not one this tool builds or decodes)")
    ));
    out.push_str("Blocks (CLA INS P1 P2 Lc data):\n");
    if let Some(blocks) = data["plan"]["blocks"].as_array() {
        for block in blocks {
            let field = |k: &str| block[k].as_str().unwrap_or("-").to_owned();
            out.push_str(&format!(
                "  {} {} {} {} {}  {}\n",
                field("cla"),
                field("ins"),
                field("p1"),
                field("p2"),
                field("lc"),
                field("data")
            ));
        }
    }
    if data["sent"].as_bool().unwrap_or(false) {
        out.push_str(&format!(
            "Response: {} bytes\n  {}\n",
            data["response_bytes"].as_u64().unwrap_or(0),
            data["response_hex"].as_str().unwrap_or("")
        ));
        if data["decoded"].as_bool().unwrap_or(false) {
            out.push_str(&format!(
                "Decoded {}: {}\n",
                data["function"].as_str().unwrap_or("response"),
                sanitize(&data["decoded_response"].to_string())
            ));
        } else if let Some(error) = data["decode_error"].as_str() {
            out.push_str(&format!("Not decoded: {}\n", sanitize(error)));
        }
    }
    out.push_str(&format!(
        "{}\n",
        sanitize(data["note"].as_str().unwrap_or(""))
    ));
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::replay::Replay;

    const EID: &str = "89049032123451234512345678901235";
    const ICCID_RAW: &str = "98001032547698103214";
    const ICCID: &str = "89000123456789012341";
    const SKI: &str = "81370F5125D0B1D408D4C3B232E6D25E795BEBFB";
    const INFO2: &str = "BF2281C6810302010082030202008303040600840F8101008204000628248304000019228504067F36C08603090200870302030088020490A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB990206C004030000010C0D47492D42412D55502D30343139AC48801F312E322E3834302E313233343536372F6D79506C6174666F726D4C6162656C812568747470733A2F2F6D79636F6D70616E792E636F6D2F6D79444C4F41526567697374726172";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// STORE DATA on channel 1 (CLA 81) carrying `request`, as one block.
    fn store(request: &[u8]) -> String {
        format!(
            "81E29100{:02X}{}00",
            request.len(),
            hex::encode_upper(request)
        )
    }

    fn log(pairs: &[(String, String)]) -> String {
        pairs
            .iter()
            .map(|(c, r)| format!("{{\"command\":\"{c}\",\"response\":\"{r}\"}}\n"))
            .collect()
    }

    /// open, select, then the (request, response-with-SW) STORE DATA pairs,
    /// then close.
    fn script(select_sw: &str, steps: &[(Vec<u8>, String)]) -> Replay {
        let mut pairs = vec![
            ("0070000001".to_owned(), "019000".to_owned()),
            (
                format!(
                    "01A40400{:02X}{}00",
                    ISDR_AID.len(),
                    hex::encode_upper(ISDR_AID)
                ),
                select_sw.to_owned(),
            ),
        ];
        if select_sw == "9000" {
            for (req, resp) in steps {
                pairs.push((store(req), resp.clone()));
            }
        }
        pairs.push(("00708001".to_owned(), "9000".to_owned()));
        Replay::from_log(&log(&pairs)).unwrap()
    }

    fn ok(body: &str) -> String {
        format!("{}9000", body.replace(' ', ""))
    }

    #[test]
    fn info_reads_eid_info1_and_info2_and_closes_the_channel() {
        let info1 = format!("BF2035 82030202 00 A916 0414{SKI} AA16 0414{SKI}");
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), ok(&format!("BF3E12 5A10 {EID}"))),
                (es10::get_euicc_info1_request(), ok(&info1)),
                (es10::get_euicc_info2_request(), ok(INFO2)),
                (
                    es10::get_euicc_configured_addresses_request(),
                    ok(&format!(
                        "BF3C19 8007 {} 810E {}",
                        hex::encode("dp.exam"),
                        hex::encode("ds.example.org")
                    )),
                ),
            ],
        );
        let data = run(&mut card, &ISDR_AID, Query::Info).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["eid"], EID);
        assert_eq!(data["euicc_info1"]["svn"], "2.2.0");
        assert_eq!(data["euicc_info1"]["ci_pk_id_for_verification"][0], SKI);
        assert_eq!(data["euicc_info2"]["profile_version"], "2.1.0");
        assert_eq!(data["configured_addresses"]["default_smdp"], "dp.exam");
        assert_eq!(data["configured_addresses"]["root_smds"], "ds.example.org");
        assert_eq!(data["channel"], json!({ "number": 1, "closed": true }));
        let human = to_human(Query::Info, &data);
        assert!(human.starts_with(&format!("EID: {EID}\n")));
        assert!(human.contains("SM-DS (root): ds.example.org\n"));
    }

    /// A GetProfilesInfo response with one profile holding `nick` (none when
    /// empty) and the test ICCID.
    fn profile_response(nick: &str) -> String {
        let nick = if nick.is_empty() {
            String::new()
        } else {
            format!("90{:02X}{}", nick.len(), hex::encode(nick))
        };
        let body = format!(
            "5A0A{ICCID_RAW} 4F10A0000005591010FFFFFFFF89000010 00 9F700101 {nick} 9108 4F70657261746F72 9501 02"
        );
        ok(&fix_lengths(&body))
    }

    fn profiles_request() -> Vec<u8> {
        es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).unwrap()
    }

    fn eid_response() -> String {
        ok(&format!("BF3E12 5A10 {EID}"))
    }

    fn set_request(name: &str) -> Vec<u8> {
        es10::set_nickname_request(&h(ICCID_RAW), name).unwrap()
    }

    #[test]
    fn segment_size_cuts_the_store_data_blocks() {
        // GetProfilesInfo request is 12 bytes; at 5 bytes per block that is
        // three blocks: P1 11/11/91, P2 0/1/2, one logical exchange each.
        let request = profiles_request();
        let body = profile_response("nick");
        let mut pairs = vec![
            ("0070000001".to_owned(), "019000".to_owned()),
            (
                format!(
                    "01A40400{:02X}{}00",
                    ISDR_AID.len(),
                    hex::encode_upper(ISDR_AID)
                ),
                "9000".to_owned(),
            ),
        ];
        let chunks: Vec<&[u8]> = request.chunks(5).collect();
        for (i, c) in chunks.iter().enumerate() {
            let p1 = if i + 1 == chunks.len() { "91" } else { "11" };
            let resp = if i + 1 == chunks.len() {
                body.clone()
            } else {
                "9000".to_owned()
            };
            pairs.push((
                format!("81E2{p1}{i:02X}{:02X}{}00", c.len(), hex::encode_upper(c)),
                resp,
            ));
        }
        pairs.push(("00708001".to_owned(), "9000".to_owned()));
        let mut card = Replay::from_log(&log(&pairs)).unwrap();
        let data = run_with(&mut card, &ISDR_AID, Query::Profiles, 5).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["profiles"][0]["nickname"], "nick");
        assert!(chunks.len() > 1);
        // 0 and 256 are refused before anything is sent.
        let mut card = script("9000", &[]);
        assert_eq!(
            run_with(&mut card, &ISDR_AID, Query::Profiles, 0)
                .unwrap_err()
                .kind,
            "exchange-failed"
        );
    }

    #[test]
    fn nickname_dry_run_reads_and_sends_no_write() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
            ],
        );
        let req = Nickname::new(ICCID, "new", false).unwrap();
        let data = nickname(&mut card, &ISDR_AID, 255, &req).unwrap();
        // open, select, GetEID, GetProfilesInfo, close; no SetNickname.
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["eid"], EID);
        assert_eq!(data["iccid"], ICCID);
        assert_eq!(data["current_nickname"], "old");
        assert_eq!(data["new_nickname"], "new");
        assert_eq!(data["dry_run"], true);
        assert_eq!(data["applied"], false);
        let human = nickname_to_human(&data);
        assert!(human.contains("Dry run: nothing was sent"));
        assert!(human.contains(&format!("ICCID: {ICCID}")));
    }

    #[test]
    fn nickname_with_yes_sends_set_nickname_then_verifies() {
        // Exact SetNickname frame, hand-written: BF29 11 5A0A <iccid> 9003 'n' 'e' 'w'.
        assert_eq!(
            set_request("new"),
            h(&format!("BF2911 5A0A{ICCID_RAW} 9003 6E6577"))
        );
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903 8001 00")),
                (profiles_request(), profile_response("new")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let data = nickname(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["applied"], true);
        assert_eq!(data["dry_run"], false);
        assert_eq!(data["verified_nickname"], "new");
        assert!(nickname_to_human(&data).contains("SetNickname sent"));
    }

    #[test]
    fn nickname_accepted_but_not_visible_is_a_verify_failure() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903 8001 00")),
                (profiles_request(), profile_response("old")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
        assert_eq!(failure.data["actual"], "old");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn nickname_refused_by_the_isdr_is_es10_refused_and_not_verified() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903 8001 7F")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "es10-refused");
        assert_eq!(failure.data["code"], 127);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn set_nickname_result_1_is_iccid_not_found() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903800101")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "iccid-not-found");
        assert_eq!(failure.data["iccid"], ICCID);
        assert_eq!(failure.data["eid"], EID);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn nickname_for_an_unknown_iccid_sends_no_write() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
            ],
        );
        let req = Nickname::new("89000123456789012349", "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "iccid-not-found");
        assert_eq!(failure.data["iccids"], json!([ICCID]));
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn nickname_validation_happens_before_any_card_contact() {
        let long = "x".repeat(65);
        assert_eq!(
            Nickname::new(ICCID, &long, true).unwrap_err().kind,
            "bad-nickname"
        );
        assert_eq!(
            Nickname::new(ICCID, "a\u{1b}[31m", true).unwrap_err().kind,
            "bad-nickname"
        );
        assert_eq!(
            Nickname::new("1234", "ok", true).unwrap_err().kind,
            "bad-iccid"
        );
        assert_eq!(
            Nickname::new("8900012345678901234x", "ok", true)
                .unwrap_err()
                .kind,
            "bad-iccid"
        );
        assert!(Nickname::new(ICCID, &"x".repeat(64), true).is_ok());
        assert!(Nickname::new(ICCID, "", true).is_ok());
        // 19 digits pad with F in the last byte's high nibble.
        assert_eq!(
            Nickname::new("8900012345678901234", "a", false)
                .unwrap()
                .raw_iccid[9],
            0xF4
        );
    }

    const AID_HEX: &str = "A0000005591010FFFFFFFF8900001000";
    const OTHER_RAW: &str = "98001032547698103299";

    /// A GetProfilesInfo response with the test profile in `state` (0 disabled,
    /// 1 enabled) and, when `other` is set, a second profile in that state.
    fn states_response(state: u8, other: Option<u8>) -> String {
        let one = |raw: &str, aid: &str, st: u8| {
            let body = format!("5A0A{raw}4F10{aid}9F7001{st:02X}");
            format!("E3{:02X}{body}", body.len() / 2)
        };
        let mut list = one(ICCID_RAW, AID_HEX, state);
        if let Some(o) = other {
            list += &one(OTHER_RAW, "A0000005591010FFFFFFFF8900001001", o);
        }
        let a0 = format!("A0{:02X}{list}", list.len() / 2);
        ok(&format!("BF2D{:02X}{a0}", a0.len() / 2))
    }

    fn change_request(action: Action) -> Vec<u8> {
        let id = es10::ProfileIdentifier::Iccid(&h(ICCID_RAW));
        match action {
            Action::Enable => es10::enable_profile_request(id, true),
            Action::Disable => es10::disable_profile_request(id, true),
        }
        .unwrap()
    }

    fn eid_and_profiles(state: u8, other: Option<u8>) -> Vec<(Vec<u8>, String)> {
        vec![
            (es10::get_eid_request(), eid_response()),
            (profiles_request(), states_response(state, other)),
        ]
    }

    #[test]
    fn enable_and_disable_frames_are_the_hand_written_bytes() {
        assert_eq!(
            change_request(Action::Enable),
            h(&format!("BF3111 A00C 5A0A{ICCID_RAW} 8101FF"))
        );
        assert_eq!(
            change_request(Action::Disable),
            h(&format!("BF3211 A00C 5A0A{ICCID_RAW} 8101FF"))
        );
    }

    #[test]
    fn dry_run_reads_and_sends_nothing_for_both_actions() {
        for (action, from, other, needle) in [
            (Action::Enable, 0, Some(1), "switches the active profile"),
            (Action::Disable, 1, None, "no active profile"),
        ] {
            let mut card = script("9000", &eid_and_profiles(from, other));
            let req = StateChange::new(action, ICCID, false).unwrap();
            let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
            assert_eq!(card.remaining(), 0);
            assert_eq!(data["dry_run"], true);
            assert_eq!(data["applied"], false);
            assert_eq!(data["iccid"], ICCID);
            assert_eq!(data["isdp_aid"], AID_HEX);
            assert!(data["consequence"].as_str().unwrap().contains(needle));
            let human = state_to_human(&data);
            assert!(human.contains("Dry run: nothing was sent"));
            assert!(human.contains(needle));
        }
        // Disabling one of two enabled profiles does not say "no active profile".
        let mut card = script("9000", &eid_and_profiles(1, Some(1)));
        let req = StateChange::new(Action::Disable, ICCID, false).unwrap();
        let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert!(!data["consequence"].as_str().unwrap().contains("no active"));
    }

    #[test]
    fn yes_sends_the_exact_frame_then_verifies_for_both_actions() {
        for (action, from, to) in [(Action::Enable, 0, 1), (Action::Disable, 1, 0)] {
            let (tag, name) = match action {
                Action::Enable => ("BF31", "enabled"),
                Action::Disable => ("BF32", "disabled"),
            };
            let mut steps = eid_and_profiles(from, None);
            steps.push((change_request(action), ok(&format!("{tag}03 8001 00"))));
            steps.push((profiles_request(), states_response(to, None)));
            let mut card = script("9000", &steps);
            let req = StateChange::new(action, ICCID, true).unwrap();
            let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
            assert_eq!(card.remaining(), 0);
            assert_eq!(data["applied"], true);
            assert_eq!(data["dry_run"], false);
            assert_eq!(data["verified_state"], name);
            assert!(state_to_human(&data).contains("Profile sent"));
        }
    }

    #[test]
    fn an_aid_names_the_profile_with_tag_4f() {
        let aid = h(AID_HEX);
        let frame =
            es10::enable_profile_request(es10::ProfileIdentifier::IsdpAid(&aid), true).unwrap();
        assert_eq!(frame, h(&format!("BF3117 A012 4F10{AID_HEX} 8101FF")));
        let mut steps = eid_and_profiles(0, None);
        steps.push((frame, ok("BF3103 8001 00")));
        steps.push((profiles_request(), states_response(1, None)));
        let mut card = script("9000", &steps);
        let req = StateChange::new(Action::Enable, &AID_HEX.to_lowercase(), true).unwrap();
        let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["verified_state"], "enabled");
    }

    #[test]
    fn every_result_code_is_its_own_kind_and_is_not_verified() {
        let cases: [(Action, &str, &str); 12] = [
            (Action::Enable, "01", "profile-not-found"),
            (Action::Enable, "02", "profile-not-in-disabled-state"),
            (Action::Enable, "03", "disallowed-by-policy"),
            (Action::Enable, "04", "wrong-profile-reenabling"),
            (Action::Enable, "05", "cat-busy"),
            (Action::Enable, "7F", "undefined-error"),
            (Action::Disable, "01", "profile-not-found"),
            (Action::Disable, "02", "profile-not-in-enabled-state"),
            (Action::Disable, "03", "disallowed-by-policy"),
            (Action::Disable, "05", "cat-busy"),
            (Action::Disable, "7F", "undefined-error"),
            (Action::Disable, "63", "es10-refused"),
        ];
        for (action, code, kind) in cases {
            let (tag, from) = match action {
                Action::Enable => ("BF31", 0),
                Action::Disable => ("BF32", 1),
            };
            let mut steps = eid_and_profiles(from, None);
            steps.push((change_request(action), ok(&format!("{tag}03 8001 {code}"))));
            let mut card = script("9000", &steps);
            let req = StateChange::new(action, ICCID, true).unwrap();
            let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, kind, "{action:?} {code}");
            assert_eq!(failure.data["code"], i64::from_str_radix(code, 16).unwrap());
            assert_eq!(card.remaining(), 0, "no verify read after a refusal");
        }
    }

    #[test]
    fn accepted_but_unchanged_is_a_verify_failure() {
        let mut steps = eid_and_profiles(0, None);
        steps.push((change_request(Action::Enable), ok("BF3103 8001 00")));
        steps.push((profiles_request(), states_response(0, None)));
        let mut card = script("9000", &steps);
        let req = StateChange::new(Action::Enable, ICCID, true).unwrap();
        let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
        assert_eq!(failure.data["actual"], "disabled");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn wrong_state_is_refused_with_nothing_sent() {
        for (action, from, kind) in [
            (Action::Enable, 1, "already-enabled"),
            (Action::Disable, 0, "already-disabled"),
        ] {
            let mut card = script("9000", &eid_and_profiles(from, None));
            let req = StateChange::new(action, ICCID, true).unwrap();
            let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, kind);
            assert_eq!(card.remaining(), 0);
        }
    }

    #[test]
    fn an_unknown_profile_is_refused_with_nothing_sent() {
        for id in ["89000123456789012349", "A0000005591010FFFFFFFF8900009999"] {
            let mut card = script("9000", &eid_and_profiles(0, None));
            let req = StateChange::new(Action::Enable, id, true).unwrap();
            let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, "profile-not-found");
            assert_eq!(failure.data["iccids"], json!([ICCID]));
            assert_eq!(card.remaining(), 0);
        }
    }

    #[test]
    fn state_change_validation_happens_before_any_card_contact() {
        for bad in [
            "",
            "1234",
            "8900012345678901234x",
            "A000",
            "ZZ00000000",
            &"A0".repeat(17),
        ] {
            assert_eq!(
                StateChange::new(Action::Enable, bad, true)
                    .unwrap_err()
                    .kind,
                "bad-profile-id",
                "{bad:?}"
            );
        }
        assert!(StateChange::new(Action::Disable, AID_HEX, true).is_ok());
        assert!(StateChange::new(Action::Disable, "89000123456789012", true).is_err());
    }

    #[test]
    fn profiles_lists_state_nickname_provider_and_class() {
        let request = es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).unwrap();
        let body = format!(
            "BF2D32 A030 E32E 5A0A{ICCID_RAW} 4F10A0000005591010FFFFFFFF89000010 00 9F700101 9004 6E69636B 9108 4F70657261746F72 9501 02"
        );
        // Hand-built lengths are checked by the decoder, so size them honestly.
        let body = fix_lengths(&body);
        let mut card = script("9000", &[(request, ok(&body))]);
        let data = run(&mut card, &ISDR_AID, Query::Profiles).unwrap();
        assert_eq!(card.remaining(), 0);
        let p = &data["profiles"][0];
        assert_eq!(p["iccid"], ICCID);
        assert_eq!(p["state"], "enabled");
        assert_eq!(p["nickname"], "nick");
        assert_eq!(p["provider"], "Operator");
        assert_eq!(p["class"], "operational");
        let human = to_human(Query::Profiles, &data);
        assert!(human.contains(&format!("{ICCID}\tenabled\toperational\tnick\tOperator")));
    }

    /// Rebuilds `BF2D ln A0 ln E3 ln <profile>` around a profile body so the
    /// test does not hard-code three nested lengths.
    fn fix_lengths(spaced: &str) -> String {
        let flat = spaced.replace(' ', "");
        let inner = &flat[flat.find("5A0A").unwrap()..];
        let e3 = format!("E3{:02X}{inner}", inner.len() / 2);
        let a0 = format!("A0{:02X}{e3}", e3.len() / 2);
        format!("BF2D{:02X}{a0}", a0.len() / 2)
    }

    #[test]
    fn notifications_list_metadata_only() {
        let addr = "smdp.example.org";
        let meta = format!(
            "800105 8102 0480 0C{:02X}{} 5A0A{ICCID_RAW}",
            addr.len(),
            hex::encode(addr)
        )
        .replace(' ', "");
        let mut card = {
            let n = format!("BF2F{:02X}{meta}", meta.len() / 2);
            let a0 = format!("A0{:02X}{n}", n.len() / 2);
            let all = format!("BF28{:02X}{a0}", a0.len() / 2);
            script("9000", &[(es10::list_notification_request(), ok(&all))])
        };
        let data = run(&mut card, &ISDR_AID, Query::Notifications).unwrap();
        assert_eq!(card.remaining(), 0);
        let n = &data["notifications"][0];
        assert_eq!(n["seq_number"], 5);
        assert_eq!(n["operation"], json!(["install"]));
        assert_eq!(n["iccid"], ICCID);
        assert_eq!(n["address"], "smdp.example.org");
        assert!(to_human(Query::Notifications, &data).contains("install"));
    }

    #[test]
    fn challenge_sends_bf2e_and_reports_the_sixteen_bytes() {
        // GetEUICCChallenge (SGP.22 v2.5 §5.7.7): request `BF2E00`, response
        // `BF2E 12 80 10 <challenge>`.
        let mut card = script(
            "9000",
            &[(
                es10::get_euicc_challenge_request(),
                ok("BF2E12 8010 A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"),
            )],
        );
        let data = run(&mut card, &ISDR_AID, Query::Challenge).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["challenge"], "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF");
        assert_eq!(data["channel"], json!({ "number": 1, "closed": true }));
        assert_eq!(
            to_human(Query::Challenge, &data),
            "challenge: A0A1A2A3A4A5A6A7A8A9AAABACADAEAF\n"
        );
        assert_eq!(Query::Challenge.name(), "challenge");
    }

    #[test]
    fn a_malformed_challenge_is_a_decode_failure() {
        let mut card = script(
            "9000",
            &[(es10::get_euicc_challenge_request(), ok("BF2E03 800100"))],
        );
        let failure = run(&mut card, &ISDR_AID, Query::Challenge).unwrap_err();
        assert_eq!(failure.kind, "decode-failed");
        assert_eq!(failure.data["function"], "GetEUICCChallenge");
    }

    #[test]
    fn a_61xx_answer_is_collected_with_get_response_on_the_channel() {
        let body = format!("BF3E12 5A10 {EID}").replace(' ', "");
        let pairs = vec![
            ("0070000001".to_owned(), "019000".to_owned()),
            (
                format!(
                    "01A40400{:02X}{}00",
                    ISDR_AID.len(),
                    hex::encode_upper(ISDR_AID)
                ),
                "9000".to_owned(),
            ),
            (store(&es10::get_eid_request()), "6114".to_owned()),
            ("01C0000014".to_owned(), format!("{body}9000")),
        ];
        let mut card = Replay::from_log(&log(&pairs)).unwrap();
        let policy = Policy {
            get_response_class: channel_cla(false, 1),
            proactive_command: PendingFollowUp::Ignore,
            ..Policy::default()
        };
        session::send(&mut card, &crate::session::manage_channel_open(), &policy).unwrap();
        let select = Command::case4(
            Header::new(0x01, 0xA4, 0x04, 0x00),
            &ISDR_AID[..],
            Le::Short(0),
        );
        session::send(&mut card, &select, &policy).unwrap();
        let sent = es10::store_data(&mut card, 0x81, &es10::get_eid_request(), &policy).unwrap();
        assert_eq!(es10::decode_get_eid(sent.data()).unwrap(), h(EID)[..]);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn empty_lists_are_ok() {
        let mut card = script(
            "9000",
            &[(es10::list_notification_request(), ok("BF2802 A000"))],
        );
        let data = run(&mut card, &ISDR_AID, Query::Notifications).unwrap();
        assert_eq!(data["notifications"], json!([]));
    }

    #[test]
    fn a_non_euicc_card_is_a_clean_failure_and_gets_no_store_data() {
        let mut card = script("6A82", &[]);
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "not-an-euicc");
        assert!(failure.message.starts_with("not an eUICC"));
        assert_eq!(failure.data["error"]["kind"], "not-an-euicc");
        assert_eq!(failure.data["status"], "6A82");
        // open, select, close: the channel was closed and nothing else sent.
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn a_card_that_refuses_manage_channel_is_reported() {
        let log = log(&[("0070000001".to_owned(), "6881".to_owned())]);
        let mut card = Replay::from_log(&log).unwrap();
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "channel-unavailable");
        assert_eq!(failure.data["status"], "6881");
    }

    #[test]
    fn a_malformed_tlv_is_a_decode_failure_and_the_channel_still_closes() {
        // BF3E claims 0x12 bytes and holds 2.
        let mut card = script("9000", &[(es10::get_eid_request(), ok("BF3E12 5A10"))]);
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "decode-failed");
        assert_eq!(failure.data["function"], "GetEID");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn an_isdr_refusal_is_es10_refused() {
        let mut card = script("9000", &[(es10::get_eid_request(), "6985".to_owned())]);
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "es10-refused");
        assert_eq!(failure.data["function"], "GetEID");
    }

    #[test]
    fn card_text_cannot_drive_the_terminal() {
        let data = json!({ "profiles": [{ "iccid": "1", "state": "enabled", "class": "test",
            "nickname": "a\u{1b}[31mb\u{202e}c", "provider": null, "name": "x" }] });
        let human = to_human(Query::Profiles, &data);
        assert!(!human.contains('\u{1b}') && !human.contains('\u{202e}'));
    }

    #[test]
    fn logical_channel_classes() {
        assert_eq!(channel_cla(false, 1), 0x01);
        assert_eq!(channel_cla(true, 1), 0x81);
        assert_eq!(channel_cla(false, 4), 0x40);
        assert_eq!(channel_cla(true, 5), 0xC1);
    }

    #[test]
    fn requests_are_the_documented_frames() {
        assert_eq!(es10::get_eid_request(), h("BF3E035C015A"));
        assert_eq!(es10::list_notification_request(), h("BF2800"));
    }

    // -- delete, reset, notification remove ------------------------------

    const OTHER_AID: &str = "A0000005591010FFFFFFFF8900001001";

    /// A GetProfilesInfo response: `(iccid_raw, aid, state, class)` per profile.
    fn classed(profiles: &[(&str, &str, u8, u8)]) -> String {
        let list: String = profiles
            .iter()
            .map(|(raw, aid, st, class)| {
                let body = format!("5A0A{raw}4F10{aid}9F7001{st:02X}9501{class:02X}");
                format!("E3{:02X}{body}", body.len() / 2)
            })
            .collect();
        let a0 = format!("A0{:02X}{list}", list.len() / 2);
        ok(&format!("BF2D{:02X}{a0}", a0.len() / 2))
    }

    fn delete_request() -> Vec<u8> {
        es10::delete_profile_request(es10::ProfileIdentifier::Iccid(&h(ICCID_RAW))).unwrap()
    }

    #[test]
    fn delete_dry_run_sends_nothing_and_says_it_is_permanent() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), classed(&[(ICCID_RAW, AID_HEX, 0, 2)])),
            ],
        );
        let req = ProfileDelete::new(ICCID, false).unwrap();
        let data = delete_profile(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["dry_run"], true);
        assert_eq!(data["applied"], false);
        assert_eq!(data["iccid"], ICCID);
        assert!(data["consequence"]
            .as_str()
            .unwrap()
            .contains("erased permanently"));
        assert!(erase_to_human(&data).contains("Dry run: nothing was sent"));
    }

    #[test]
    fn delete_with_yes_sends_the_exact_frame_then_verifies() {
        assert_eq!(delete_request(), h("BF33 0C 5A0A 98001032547698103214"));
        let mut steps = vec![
            (es10::get_eid_request(), eid_response()),
            (profiles_request(), classed(&[(ICCID_RAW, AID_HEX, 0, 2)])),
            (delete_request(), ok("BF3303 800100")),
            (profiles_request(), classed(&[(OTHER_RAW, OTHER_AID, 0, 2)])),
        ];
        let mut card = script("9000", &steps);
        let req = ProfileDelete::new(ICCID, true).unwrap();
        let data = delete_profile(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["applied"], true);
        assert_eq!(data["profile_still_listed"], false);
        // Still listed afterwards: verify-failed.
        steps[3].1 = classed(&[(ICCID_RAW, AID_HEX, 0, 2)]);
        let mut card = script("9000", &steps);
        let failure = delete_profile(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
    }

    #[test]
    fn delete_maps_every_result_code_to_its_own_kind() {
        for (code, kind) in [
            ("01", "profile-not-found"),
            ("02", "profile-not-in-disabled-state"),
            ("03", "disallowed-by-policy"),
            ("7F", "undefined-error"),
            ("63", "es10-refused"),
        ] {
            let mut card = script(
                "9000",
                &[
                    (es10::get_eid_request(), eid_response()),
                    (profiles_request(), classed(&[(ICCID_RAW, AID_HEX, 0, 2)])),
                    (delete_request(), ok(&format!("BF3303 8001 {code}"))),
                ],
            );
            let req = ProfileDelete::new(ICCID, true).unwrap();
            let failure = delete_profile(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, kind, "{code}");
            assert_eq!(failure.data["code"], i64::from_str_radix(code, 16).unwrap());
            assert_eq!(card.remaining(), 0, "no verify read after a refusal");
        }
    }

    #[test]
    fn delete_refuses_an_enabled_profile_and_an_unknown_one_with_nothing_sent() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), classed(&[(ICCID_RAW, AID_HEX, 1, 2)])),
            ],
        );
        let req = ProfileDelete::new(ICCID, true).unwrap();
        let failure = delete_profile(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "profile-enabled");
        assert!(failure.message.contains("disable it first"));
        assert_eq!(card.remaining(), 0);
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), classed(&[(OTHER_RAW, OTHER_AID, 0, 2)])),
            ],
        );
        let failure = delete_profile(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "profile-not-found");
        assert_eq!(card.remaining(), 0);
        assert_eq!(
            ProfileDelete::new("1234", true).unwrap_err().kind,
            "bad-profile-id"
        );
    }

    const ALL: es10::ResetOptions = es10::ResetOptions {
        delete_operational_profiles: true,
        delete_field_loaded_test_profiles: true,
        reset_default_smdp_address: true,
    };

    fn three_profiles() -> String {
        // operational (enabled), test, provisioning
        classed(&[
            (ICCID_RAW, AID_HEX, 1, 2),
            (OTHER_RAW, OTHER_AID, 0, 0),
            (
                "98001032547698103288",
                "A0000005591010FFFFFFFF8900001002",
                0,
                1,
            ),
        ])
    }

    #[test]
    fn reset_validation_needs_an_option_and_for_yes_a_confirm_eid() {
        let only_test = es10::ResetOptions {
            delete_field_loaded_test_profiles: true,
            ..Default::default()
        };
        assert_eq!(
            MemoryReset::new(es10::ResetOptions::default(), Some(EID), true)
                .unwrap_err()
                .kind,
            "no-reset-option"
        );
        assert_eq!(
            MemoryReset::new(ALL, None, true).unwrap_err().kind,
            "confirm-eid-required"
        );
        assert_eq!(
            MemoryReset::new(ALL, Some("1234"), true).unwrap_err().kind,
            "bad-eid"
        );
        assert!(MemoryReset::new(only_test, None, false).is_ok());
        assert!(MemoryReset::new(only_test, Some(&EID.to_lowercase()), true).is_ok());
    }

    #[test]
    fn reset_dry_run_lists_what_it_would_erase_and_sends_nothing() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), three_profiles()),
            ],
        );
        let only_test = es10::ResetOptions {
            delete_field_loaded_test_profiles: true,
            ..Default::default()
        };
        let req = MemoryReset::new(only_test, None, false).unwrap();
        let data = memory_reset(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        let listed = data["profiles_to_erase"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["class"], "test");
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), three_profiles()),
            ],
        );
        let req = MemoryReset::new(ALL, Some(EID), false).unwrap();
        let data = memory_reset(&mut card, &ISDR_AID, 255, &req).unwrap();
        // operational and test; the provisioning profile is never erased.
        assert_eq!(data["profiles_to_erase"].as_array().unwrap().len(), 2);
        assert_eq!(data["dry_run"], true);
        assert!(erase_to_human(&data).contains(&format!("--confirm-eid {EID}")));
    }

    #[test]
    fn reset_with_yes_sends_the_exact_frame_then_verifies() {
        let frame = es10::memory_reset_request(ALL).unwrap();
        assert_eq!(frame, h("BF34 04 82 02 05E0"));
        let mut steps = vec![
            (es10::get_eid_request(), eid_response()),
            (profiles_request(), three_profiles()),
            (frame, ok("BF3403 800100")),
            (
                profiles_request(),
                classed(&[(
                    "98001032547698103288",
                    "A0000005591010FFFFFFFF8900001002",
                    0,
                    1,
                )]),
            ),
        ];
        let mut card = script("9000", &steps);
        let req = MemoryReset::new(ALL, Some(EID), true).unwrap();
        let data = memory_reset(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["applied"], true);
        assert_eq!(data["profiles_remaining"], json!([]));
        // An erased profile still listed: verify-failed.
        steps[3].1 = three_profiles();
        let mut card = script("9000", &steps);
        let failure = memory_reset(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
    }

    #[test]
    fn reset_with_a_mismatched_eid_sends_nothing() {
        let mut card = script("9000", &[(es10::get_eid_request(), eid_response())]);
        let wrong = "89049032123451234512345678901236";
        let req = MemoryReset::new(ALL, Some(wrong), true).unwrap();
        let failure = memory_reset(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "eid-mismatch");
        assert_eq!(failure.data["eid"], EID);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn reset_maps_every_result_code_to_its_own_kind() {
        for (code, kind) in [
            ("01", "nothing-to-delete"),
            ("7F", "undefined-error"),
            ("63", "es10-refused"),
        ] {
            let mut card = script(
                "9000",
                &[
                    (es10::get_eid_request(), eid_response()),
                    (profiles_request(), three_profiles()),
                    (
                        es10::memory_reset_request(ALL).unwrap(),
                        ok(&format!("BF3403 8001 {code}")),
                    ),
                ],
            );
            let req = MemoryReset::new(ALL, Some(EID), true).unwrap();
            let failure = memory_reset(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, kind, "{code}");
            assert_eq!(card.remaining(), 0);
        }
    }

    fn notification_list(seqs: &[u8]) -> String {
        let list: String = seqs
            .iter()
            .map(|seq| {
                let meta =
                    format!("8001{seq:02X}8102 0480 0C0161 5A0A{ICCID_RAW}").replace(' ', "");
                format!("BF2F{:02X}{meta}", meta.len() / 2)
            })
            .collect();
        let a0 = format!("A0{:02X}{list}", list.len() / 2);
        ok(&format!("BF28{:02X}{a0}", a0.len() / 2))
    }

    fn remove_steps(seq: u8, list: &[u8]) -> Vec<(Vec<u8>, String)> {
        vec![
            (es10::get_eid_request(), eid_response()),
            (es10::list_notification_request(), notification_list(list)),
            (
                es10::remove_notification_request(u32::from(seq)),
                ok("BF3003 800100"),
            ),
        ]
    }

    #[test]
    fn notification_remove_dry_run_sends_nothing() {
        let steps = remove_steps(5, &[4, 5]);
        let mut card = script("9000", &steps[..2]);
        let req = NotificationRemoval {
            seq_number: 5,
            apply: false,
        };
        let data = remove_notification(&mut card, &ISDR_AID, 255, req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["notification"]["seq_number"], 5);
        assert_eq!(data["dry_run"], true);
        assert!(data["consequence"]
            .as_str()
            .unwrap()
            .contains("never sent to the operator"));
    }

    #[test]
    fn notification_remove_with_yes_sends_the_exact_frame_then_verifies() {
        assert_eq!(es10::remove_notification_request(5), h("BF30 03 80 01 05"));
        let mut steps = remove_steps(5, &[4, 5]);
        steps.push((es10::list_notification_request(), notification_list(&[4])));
        let mut card = script("9000", &steps);
        let req = NotificationRemoval {
            seq_number: 5,
            apply: true,
        };
        let data = remove_notification(&mut card, &ISDR_AID, 255, req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["applied"], true);
        assert_eq!(data["notification_still_listed"], false);
        steps[3].1 = notification_list(&[4, 5]);
        let mut card = script("9000", &steps);
        let failure = remove_notification(&mut card, &ISDR_AID, 255, req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
    }

    #[test]
    fn notification_remove_maps_every_result_code_to_its_own_kind() {
        for (code, kind) in [
            ("01", "nothing-to-delete"),
            ("7F", "undefined-error"),
            ("63", "es10-refused"),
        ] {
            let mut steps = remove_steps(5, &[5]);
            steps[2].1 = ok(&format!("BF3003 8001 {code}"));
            let mut card = script("9000", &steps);
            let req = NotificationRemoval {
                seq_number: 5,
                apply: true,
            };
            let failure = remove_notification(&mut card, &ISDR_AID, 255, req).unwrap_err();
            assert_eq!(failure.kind, kind, "{code}");
            assert_eq!(card.remaining(), 0);
        }
    }

    #[test]
    fn notification_remove_of_an_unknown_sequence_number_sends_nothing() {
        let steps = remove_steps(9, &[4, 5]);
        let mut card = script("9000", &steps[..2]);
        let req = NotificationRemoval {
            seq_number: 9,
            apply: true,
        };
        let failure = remove_notification(&mut card, &ISDR_AID, 255, req).unwrap_err();
        assert_eq!(failure.kind, "notification-not-found");
        assert_eq!(failure.data["seq_numbers"], json!([4, 5]));
        assert_eq!(card.remaining(), 0);
    }

    // -- notifications dump (RetrieveNotificationsList) ------------------

    /// `PendingNotification`s for `seqs`: the first as an
    /// otherSignedNotification (`30`), a seq of 9 as a profileInstallationResult.
    fn pending(seq: u8) -> String {
        let meta = format!("8001{seq:02X}8102 0480 0C0161 5A0A{ICCID_RAW}").replace(' ', "");
        let meta = format!("BF2F{:02X}{meta}", meta.len() / 2);
        let sig = "5F370211 22";
        let inner = if seq == 9 {
            let data = format!("8002ABCD{meta}");
            let pir = format!("BF27{:02X}{data}{sig}", data.len() / 2);
            format!("BF37{:02X}{pir}", pir.len() / 2)
        } else {
            let body = format!("{meta}{sig}");
            format!("30{:02X}{body}", body.len() / 2)
        };
        inner.replace(' ', "")
    }

    fn retrieve_response(seqs: &[u8]) -> String {
        let list: String = seqs.iter().map(|s| pending(*s)).collect();
        let a0 = format!("A0{:02X}{list}", list.len() / 2);
        ok(&format!("BF2B{:02X}{a0}", a0.len() / 2))
    }

    #[test]
    fn dump_retrieves_the_full_notifications_and_removes_nothing() {
        assert_eq!(es10::retrieve_notifications_request(None), h("BF2B00"));
        // Only GetEID and the retrieve go out: a RemoveNotificationFromList
        // (BF30) would find no scripted answer and fail the run.
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (
                    es10::retrieve_notifications_request(None),
                    retrieve_response(&[4, 9]),
                ),
            ],
        );
        let data = dump_notifications(&mut card, &ISDR_AID, 255, None).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["format"], DUMP_FORMAT);
        assert_eq!(data["eid"], EID);
        let n = &data["notifications"];
        assert_eq!(n.as_array().unwrap().len(), 2);
        assert_eq!(n[0]["seq_number"], 4);
        assert_eq!(n[0]["kind"], "other-signed-notification");
        assert_eq!(n[0]["operation"], json!(["install"]));
        assert_eq!(n[0]["address"], "a");
        assert_eq!(n[0]["iccid"], ICCID);
        assert_eq!(n[0]["pending_notification_hex"], pending(4));
        assert_eq!(n[1]["kind"], "profile-installation-result");
        assert_eq!(n[1]["transaction_id"], "ABCD");
        assert!(dump_to_human(&data).contains("a\t"));
        // The dump round-trips: `notif::load` gets the same signed bytes back.
        let loaded = crate::notif::load(&data.to_string()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(hex::encode_upper(&loaded[1].raw), pending(9));
    }

    #[test]
    fn dump_of_one_sequence_number_sends_the_lpac_search_criteria() {
        assert_eq!(
            es10::retrieve_notifications_request(Some(5)),
            h("BF2B05 A003 800105")
        );
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (
                    es10::retrieve_notifications_request(Some(5)),
                    retrieve_response(&[5]),
                ),
            ],
        );
        let data = dump_notifications(&mut card, &ISDR_AID, 255, Some(5)).unwrap();
        assert_eq!(data["notifications"][0]["seq_number"], 5);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn dump_with_nothing_pending_is_empty_and_an_unknown_seq_is_not_found() {
        let none = ok("BF2B03 8101 01");
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (es10::retrieve_notifications_request(None), none.clone()),
            ],
        );
        let data = dump_notifications(&mut card, &ISDR_AID, 255, None).unwrap();
        assert_eq!(data["notifications"], json!([]));
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (es10::retrieve_notifications_request(Some(7)), none),
            ],
        );
        let f = dump_notifications(&mut card, &ISDR_AID, 255, Some(7)).unwrap_err();
        assert_eq!(f.kind, "notification-not-found");
    }

    #[test]
    fn dump_of_a_malformed_notification_is_decode_failed() {
        // `30 00`: an otherSignedNotification with no BF2F metadata.
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (
                    es10::retrieve_notifications_request(None),
                    ok("BF2B04 A002 3000"),
                ),
            ],
        );
        let f = dump_notifications(&mut card, &ISDR_AID, 255, None).unwrap_err();
        assert_eq!(f.kind, "decode-failed");
    }

    // --- raw STORE DATA (#230) ---------------------------------------------

    #[test]
    fn raw_store_data_prints_the_exact_block_breakdown() {
        // 12 bytes at 5 per block is three blocks: P1 11, 11, 91; P2 00, 01,
        // 02; case 4 with Le 00 (SGP.22 v2.5 section 5.7.2, Tables 47 and 48).
        let request = RawStoreData::new(h("000102030405060708090A0B"), false).unwrap();
        let plan = raw_store_data_plan(5, &request).unwrap();
        assert_eq!(plan["card_touched"], false);
        assert_eq!(plan["sent"], false);
        assert_eq!(plan["applied"], false);
        assert_eq!(plan["payload_bytes"], 12);
        assert_eq!(plan["payload_hex"], "000102030405060708090A0B");
        assert_eq!(plan["plan"]["block_count"], 3);
        let blocks = plan["plan"]["blocks"].as_array().unwrap();
        assert_eq!(blocks[0]["cla"], "80");
        assert_eq!(blocks[0]["ins"], "E2");
        assert_eq!(blocks[0]["p1"], "11");
        assert_eq!(blocks[0]["p2"], "00");
        assert_eq!(blocks[0]["lc"], "05");
        assert_eq!(blocks[0]["data"], "0001020304");
        assert_eq!(blocks[0]["apdu"], "80E2110005000102030400");
        assert_eq!(blocks[1]["p1"], "11");
        assert_eq!(blocks[1]["p2"], "01");
        assert_eq!(blocks[1]["data"], "0506070809");
        assert_eq!(blocks[1]["apdu"], "80E2110105050607080900");
        assert_eq!(blocks[2]["p1"], "91");
        assert_eq!(blocks[2]["p2"], "02");
        assert_eq!(blocks[2]["lc"], "02");
        assert_eq!(blocks[2]["data"], "0A0B");
        assert_eq!(blocks[2]["apdu"], "80E29102020A0B00");
    }

    #[test]
    fn raw_store_data_fits_one_block_when_the_payload_does() {
        // GetEID is BF3E 03 5C 01 5A, six bytes: one block, and it is the
        // last one, so P1 is 91 and P2 is 00.
        let request = RawStoreData::new(es10::get_eid_request(), false).unwrap();
        assert_eq!(request.payload(), h("BF3E035C015A").as_slice());
        let plan = raw_store_data_plan(255, &request).unwrap();
        assert_eq!(plan["plan"]["block_count"], 1);
        assert_eq!(plan["function"], "GetEID");
        assert_eq!(plan["plan"]["blocks"][0]["p1"], "91");
        assert_eq!(plan["plan"]["blocks"][0]["p2"], "00");
        assert_eq!(plan["plan"]["blocks"][0]["lc"], "06");
        assert_eq!(
            plan["plan"]["blocks"][0]["apdu"],
            "80E2910006BF3E035C015A00"
        );
    }

    #[test]
    fn raw_store_data_refuses_a_payload_over_the_bound() {
        let long = RawStoreData::new(vec![0xAB; MAX_RAW_STORE_DATA + 1], true).unwrap_err();
        assert_eq!(long.kind, "payload-too-large");
        assert_eq!(long.data["error"]["kind"], "payload-too-large");
        assert_eq!(long.data["max"], MAX_RAW_STORE_DATA);
        let at = RawStoreData::new(vec![0xAB; MAX_RAW_STORE_DATA], true).unwrap();
        assert_eq!(at.payload().len(), MAX_RAW_STORE_DATA);
        let hexed = "AB".repeat(MAX_RAW_STORE_DATA + 1);
        assert_eq!(
            RawStoreData::from_hex(&hexed, false).unwrap_err().kind,
            "payload-too-large"
        );
    }

    #[test]
    fn raw_store_data_reads_stdin_within_the_bound_and_refuses_a_longer_stream() {
        let mut short = "bf 3e 00\n".as_bytes();
        let read = RawStoreData::from_reader(&mut short, false).unwrap();
        assert_eq!(read.payload(), h("BF3E00").as_slice());
        let long = "AB".repeat(MAX_RAW_STORE_DATA + 1).into_bytes();
        let mut cursor = long.as_slice();
        let f = RawStoreData::from_reader(&mut cursor, false).unwrap_err();
        assert_eq!(f.kind, "payload-too-large");
    }

    #[test]
    fn raw_store_data_refuses_hex_that_is_not_hex_before_anything_else() {
        assert_eq!(
            RawStoreData::from_hex("BF3E0", false).unwrap_err().kind,
            "not-hex"
        );
        assert_eq!(
            RawStoreData::from_hex("BF ZZ 00", false).unwrap_err().kind,
            "not-hex"
        );
        assert_eq!(
            RawStoreData::from_hex("BF3E00", false)
                .unwrap()
                .payload()
                .len(),
            3
        );
        assert_eq!(
            RawStoreData::from_hex("bf3e:00", false).unwrap().payload(),
            h("BF3E00").as_slice()
        );
        assert_eq!(
            RawStoreData::from_hex("0xBF3E00", false).unwrap().payload(),
            h("BF3E00").as_slice()
        );
        assert_eq!(
            RawStoreData::from_hex("", false).unwrap_err().kind,
            "empty-payload"
        );
    }

    #[test]
    fn raw_store_data_refuses_a_request_p2_cannot_number() {
        // P2 is one octet: 256 blocks is the ceiling, 257 cannot be numbered.
        let too_many = RawStoreData::new(vec![0x00; 257], true).unwrap();
        let f = raw_store_data_plan(1, &too_many).unwrap_err();
        assert_eq!(f.kind, "store-data-refused");
        let exact = RawStoreData::new(vec![0x00; 256], true).unwrap();
        assert_eq!(
            raw_store_data_plan(1, &exact).unwrap()["plan"]["block_count"],
            256
        );
    }

    #[test]
    fn a_raw_store_data_dry_run_contacts_no_card() {
        // The three pairs are open, select and close: a dry run must use none.
        let mut card = script("9000", &[]);
        let request = RawStoreData::new(h("0001"), false).unwrap();
        let data = raw_store_data(&mut card, &ISDR_AID, 255, &request).unwrap();
        assert_eq!(card.remaining(), 3);
        assert_eq!(data["card_touched"], false);
        assert_eq!(data["sent"], false);
        assert!(data["note"].as_str().unwrap().contains("WARNING"));
    }

    #[test]
    fn raw_store_data_reassembles_and_decodes_a_function_this_tool_knows() {
        let request = es10::get_eid_request();
        let mut card = script("9000", &[(request.clone(), eid_response())]);
        let raw = RawStoreData::new(request, true).unwrap();
        let data = raw_store_data(&mut card, &ISDR_AID, 255, &raw).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["card_touched"], true);
        assert_eq!(data["sent"], true);
        assert_eq!(data["function"], "GetEID");
        assert_eq!(data["decoded"], true);
        assert_eq!(data["decoded_response"]["eid"], EID);
        assert_eq!(data["response_bytes"], 21);
        assert_eq!(data["response_hex"], format!("BF3E125A10{EID}"));
        // The channel the card opened is folded into the class byte: 81.
        assert_eq!(data["plan"]["cla"], "81");
        assert_eq!(data["plan"]["blocks"][0]["cla"], "81");
        assert_eq!(
            data["plan"]["blocks"][0]["apdu"],
            "81E2910006BF3E035C015A00"
        );
    }

    #[test]
    fn raw_store_data_reports_an_unknown_function_verbatim() {
        // Not a request this tool builds: an operator probing an undocumented
        // ES10 function. The answer is reported, not refused.
        let payload = h("42A1038001");
        let answer = h("BF1002 8002 8001");
        let mut card = script("9000", &[(payload.clone(), ok("BF1002 8002 8001"))]);
        let raw = RawStoreData::new(payload, true).unwrap();
        let data = raw_store_data(&mut card, &ISDR_AID, 255, &raw).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["function"], Value::Null);
        assert_eq!(data["decoded"], false);
        assert_eq!(data["decoded_response"], Value::Null);
        assert_eq!(data["response_bytes"], answer.len());
        assert_eq!(data["response_hex"], "BF100280028001");
        assert!(data["note"].as_str().unwrap().contains("verbatim"));
        let text = raw_to_human(&data);
        assert!(text.contains("BF100280028001"));
        assert!(text.contains("not one this tool builds or decodes"));
    }

    #[test]
    fn raw_store_data_human_report_warns_and_lists_the_blocks() {
        let raw = RawStoreData::new(h("000102030405060708090A0B"), false).unwrap();
        let text = raw_to_human(&raw_store_data_plan(5, &raw).unwrap());
        assert!(text.starts_with("WARNING:"));
        assert!(text.contains("Card touched: no"));
        assert!(text.contains("not SCP03"));
        assert!(text.contains("  80 E2 11 00 05  0001020304"));
        assert!(text.contains("  80 E2 91 02 02  0A0B"));
    }

    /// A GetEuiccConfiguredAddresses answer (BF3C) carrying `dp` as the
    /// default SM-DP+ address and a fixed root SM-DS.
    fn addresses(dp: &str) -> String {
        let (ds, dp) = (hex::encode("ds.example.org"), hex::encode(dp));
        let (nds, ndp) = (ds.len() / 2, dp.len() / 2);
        ok(&format!(
            "BF3C{:02X} 80{ndp:02X} {dp} 81{nds:02X} {ds}",
            2 + ndp + 2 + nds
        ))
    }

    /// The three exchanges of a `--yes` run: the configured addresses before
    /// the write, the write itself, and the same read again.
    fn default_dp_steps(before: &str, after: &str) -> Vec<(Vec<u8>, String)> {
        vec![
            (
                es10::get_euicc_configured_addresses_request(),
                addresses(before),
            ),
            (
                es10::set_default_dp_request("dp.example.com").unwrap(),
                ok("BF3F 03 80 01 00"),
            ),
            (
                es10::get_euicc_configured_addresses_request(),
                addresses(after),
            ),
        ]
    }

    #[test]
    fn default_dp_dry_run_sends_nothing_and_touches_no_card() {
        // The plan is built without a session at all: no reader to open and
        // nothing to transmit.
        let request = DefaultDp::new("dp.example.com", false).unwrap();
        let data = default_dp_plan(&request).unwrap();
        assert_eq!(data["dry_run"], true);
        assert_eq!(data["applied"], false);
        assert_eq!(data["card_touched"], false);
        assert_eq!(data["default_smdp_address"], "dp.example.com");
        assert_eq!(
            data["request_hex"],
            "BF3F10800E64702E6578616D706C652E636F6D"
        );
        assert_eq!(data["warning"], DEFAULT_DP_WARNING);
        let human = default_dp_to_human(&data);
        assert!(human.contains("Dry run: nothing was sent and no reader was opened"));
        assert!(human.contains(DEFAULT_DP_WARNING));
        assert!(human.contains("BF3F10800E64702E6578616D706C652E636F6D"));
    }

    #[test]
    fn set_default_dp_with_yes_sends_the_exact_frame_then_verifies() {
        // The frame, hand-written: BF3F 10 80 0E "dp.example.com".
        assert_eq!(
            es10::set_default_dp_request("dp.example.com").unwrap(),
            h("BF3F 10 80 0E 64702E6578616D706C652E636F6D")
        );
        let mut card = script(
            "9000",
            &default_dp_steps("dp.example.com", "dp.example.com"),
        );
        let request = DefaultDp::new("dp.example.com", true).unwrap();
        let data = set_default_dp(&mut card, &ISDR_AID, 255, &request).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["applied"], true);
        assert_eq!(data["dry_run"], false);
        assert_eq!(data["previous_default_smdp_address"], "dp.example.com");
        assert_eq!(data["verified_default_smdp_address"], "dp.example.com");
        assert!(default_dp_to_human(&data).contains("SetDefaultDpAddress sent"));
    }

    #[test]
    fn set_default_dp_accepted_but_unchanged_is_a_verify_failure() {
        let mut card = script(
            "9000",
            &default_dp_steps("old.example.com", "old.example.com"),
        );
        let request = DefaultDp::new("dp.example.com", true).unwrap();
        let failure = set_default_dp(&mut card, &ISDR_AID, 255, &request).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
        assert_eq!(failure.data["expected"], "dp.example.com");
        assert_eq!(failure.data["actual"], "old.example.com");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn set_default_dp_maps_every_result_code_to_its_own_kind_and_is_not_verified() {
        for (code, kind) in [("7F", "undefined-error"), ("63", "es10-refused")] {
            // Two exchanges only: a refused write is never verified.
            let steps = [
                (
                    es10::get_euicc_configured_addresses_request(),
                    addresses("old.example.com"),
                ),
                (
                    es10::set_default_dp_request("dp.example.com").unwrap(),
                    ok(&format!("BF3F 03 80 01 {code}")),
                ),
            ];
            let mut card = script("9000", &steps);
            let request = DefaultDp::new("dp.example.com", true).unwrap();
            let failure = set_default_dp(&mut card, &ISDR_AID, 255, &request).unwrap_err();
            assert_eq!(failure.kind, kind, "{code}");
            assert_eq!(card.remaining(), 0);
        }
    }

    #[test]
    fn set_default_dp_validation_happens_before_any_card_contact() {
        assert_eq!(
            DefaultDp::new("", true).unwrap_err().kind,
            "bad-sm-dp-address"
        );
        assert_eq!(
            DefaultDp::new("a\u{1b}[31m", true).unwrap_err().kind,
            "bad-sm-dp-address"
        );
        assert_eq!(
            DefaultDp::new("a\n", true).unwrap_err().kind,
            "bad-sm-dp-address"
        );
        assert_eq!(
            DefaultDp::new(&"a".repeat(129), true).unwrap_err().kind,
            "bad-sm-dp-address"
        );
        assert!(DefaultDp::new(&"a".repeat(128), true).is_ok());
        assert!(DefaultDp::new("dp.example.com", true).is_ok());
    }
}
