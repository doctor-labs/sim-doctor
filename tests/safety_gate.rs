//! Safety gate for the card-write paths, as the binary runs them. See the PR for the gate
//! definitions G1..G6. No real card and no reader is involved: every card here is a TCP fake
//! behind `--simulator host:port` (the transport tests/exclusive_sim.rs and src/transport/simulator.rs
//! already use) that COUNTS every APDU frame that reaches it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sim_doctor::scp03::{self, Key, Side};

/// The canary key: it must never appear in any output, in any encoding.
const CANARY_KEY: &str = "0123456789ABCDEF0123456789ABCDEF";
/// The canary PIN (ASCII digits).
const CANARY_PIN: &str = "77777777";
/// Used where a second secret is needed (a new key set, a DM key).
const CANARY_KEY2: &str = "FEDCBA9876543210FEDCBA9876543210";

const ISD: &str = "A000000151000000";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sim-doctor")
}

// ---------------------------------------------------------------------------
// The fake card
// ---------------------------------------------------------------------------

type Responder = Box<dyn FnMut(&[u8]) -> Vec<u8> + Send>;

/// A card behind a TCP socket in the JCSDK framing. Every APDU frame is logged.
struct Fake {
    spec: String,
    apdus: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
}

impl Fake {
    fn start(mut responder: Responder) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let spec = listener.local_addr().unwrap().to_string();
        let apdus: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let connections = Arc::new(AtomicUsize::new(0));
        let (log, count) = (apdus.clone(), connections.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                count.fetch_add(1, Ordering::SeqCst);
                loop {
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).is_err() {
                        break;
                    }
                    let len = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
                    let mut payload = vec![0u8; len];
                    if stream.read_exact(&mut payload).is_err() {
                        break;
                    }
                    match header[0] {
                        0xF0 => send(&mut stream, 0xF0, &ATR),
                        0x00 => {
                            log.lock().unwrap().push(payload.clone());
                            let answer = responder(&payload);
                            send(&mut stream, 0x00, &answer);
                        }
                        _ => break,
                    }
                }
            }
        });
        Fake {
            spec,
            apdus,
            connections,
        }
    }

    /// Every APDU received, as upper-case hex.
    fn sent(&self) -> Vec<String> {
        self.apdus
            .lock()
            .unwrap()
            .iter()
            .map(hex::encode_upper)
            .collect()
    }

    /// How many received APDUs carry this INS byte.
    fn ins(&self, ins: u8) -> usize {
        self.apdus
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.len() > 1 && a[1] == ins)
            .count()
    }

    fn count(&self) -> usize {
        self.apdus.lock().unwrap().len()
    }

    /// The INS bytes that change card state or the key retry counters.
    fn writes(&self) -> Vec<String> {
        self.apdus
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.len() > 1 && !READ_ONLY_INS.contains(&a[1]))
            .map(hex::encode_upper)
            .collect()
    }
}

/// INS bytes a dry run may send: SELECT, INITIALIZE UPDATE, GET DATA, GET STATUS, READ BINARY/RECORD,
/// GET RESPONSE, MANAGE CHANNEL is NOT here (it opens a channel).
const READ_ONLY_INS: &[u8] = &[0xA4, 0x50, 0x82, 0xCA, 0xF2, 0xB0, 0xB2, 0xC0, 0xCB];

const ATR: [u8; 22] = [
    0x3B, 0x9F, 0x95, 0x80, 0x1F, 0xC7, 0x80, 0x31, 0xA0, 0x73, 0xBE, 0x21, 0x13, 0x67, 0x43, 0x20,
    0x07, 0x18, 0x00, 0x00, 0x01, 0xA5,
];

fn send(stream: &mut TcpStream, code: u8, payload: &[u8]) {
    let n = payload.len() as u32;
    let mut frame = vec![code, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    frame.extend_from_slice(payload);
    let _ = stream.write_all(&frame);
}

fn tlv(tag: &str, value: &str) -> String {
    let len = value.len() / 2;
    assert!(len < 128);
    format!("{tag}{len:02X}{value}")
}

fn sw(data: &str, sw: &str) -> Vec<u8> {
    hex::decode(format!("{data}{sw}")).unwrap()
}

/// The registry the cooperative card holds.
type Registry = Arc<Mutex<Vec<String>>>;

fn entry(aid: &str, state: &str) -> String {
    tlv(
        "E3",
        &(tlv("4F", aid) + &tlv("9F70", state) + &tlv("C5", "9E0000")),
    )
}

const SD2: &str = "A000000151000002";
const LOAD_FILE: &str = "A0000000620001";
const MODULE: &str = "A000000062000101";

/// How a cooperative card misbehaves.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Honest: writes take effect and show in the registry.
    Honest,
    /// Answers 9000 to every write but changes nothing (a success claim with no read-back would lie).
    Liar,
    /// Authenticates the host cryptogram check but refuses EXTERNAL AUTHENTICATE with 6300.
    RefuseExtAuth,
    /// Honest, but every VERIFY answers 63C2 (wrong PIN, two tries left).
    WrongPin,
}

/// The state the cooperative card keeps.
#[derive(Clone)]
struct World {
    registry: Registry,
    crs_state: Arc<Mutex<u8>>,
    /// What UPDATE BINARY wrote (and READ BINARY returns), for the read-back checks.
    binary: Arc<Mutex<Vec<u8>>>,
    /// The privilege byte the registry shows for APP.
    privilege: Arc<Mutex<u8>>,
}

impl World {
    fn new() -> World {
        World {
            registry: Arc::new(Mutex::new(vec![APP.to_owned(), SD2.to_owned()])),
            crs_state: Arc::new(Mutex::new(0)),
            binary: Arc::new(Mutex::new(vec![0xFF; 3])),
            privilege: Arc::new(Mutex::new(0)),
        }
    }
}

const APP: &str = "A000000062000199";

/// A card that really performs SCP03 authentication with `card_key` (ENC = MAC) and keeps a
/// registry, a CRS state and one transparent EF. A host that holds a different key fails the
/// card-cryptogram check; a host that holds the same key authenticates for real.
fn card(card_key: &str, world: World, mode: Mode) -> Responder {
    let key = Key::new(&hex::decode(card_key).unwrap()).unwrap();
    let challenge = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut host = [0u8; 8];
    let mut in_crs = false;
    Box::new(move |apdu: &[u8]| {
        if apdu.len() < 4 {
            return sw("", "6700");
        }
        match apdu[1] {
            0xA4 => {
                in_crs =
                    apdu.len() > 8 && hex::encode_upper(&apdu[5..]).starts_with("A00000015143");
                if apdu[2] == 0x00 {
                    // SELECT by file id: an FCP of a 3-byte transparent EF.
                    sw(
                        "621482024121830 22FE28A01058B032F060180020003"
                            .replace(' ', "")
                            .as_str(),
                        "9000",
                    )
                } else {
                    sw(&tlv("6F", &tlv("84", ISD)), "9000")
                }
            }
            0x50 => {
                host.copy_from_slice(&apdu[5..13]);
                let session = scp03::derive_session_keys(&key, &key, &host, &challenge);
                let cryptogram = scp03::cryptogram(&session.mac, Side::Card, &host, &challenge);
                sw(
                    &format!(
                        "{}3003 00{}{}",
                        "00".repeat(10),
                        hex::encode(challenge),
                        hex::encode(cryptogram)
                    )
                    .replace(' ', ""),
                    "9000",
                )
            }
            0x82 if mode == Mode::RefuseExtAuth => sw("", "6300"),
            0xF2 if in_crs => {
                let state = *world.crs_state.lock().unwrap();
                let inner = format!("4F08{APP}9F7002{:02X}{:02X}", 0x03, state);
                sw(&format!("61{:02X}{inner}", inner.len() / 2), "9000")
            }
            0xF2 => match apdu[2] {
                0x80 => sw(&entry(ISD, "0F"), "9000"),
                0x40 => {
                    let list: String = world
                        .registry
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|aid| {
                            if aid == APP {
                                let privilege = *world.privilege.lock().unwrap();
                                tlv(
                                    "E3",
                                    &(tlv("4F", aid)
                                        + &tlv("9F70", "07")
                                        + &tlv("C5", &format!("{privilege:02X}0000"))),
                                )
                            } else {
                                entry(aid, "07")
                            }
                        })
                        .collect();
                    if list.is_empty() {
                        sw("", "6A88")
                    } else {
                        sw(&list, "9000")
                    }
                }
                0x20 | 0x10 => sw(
                    &tlv(
                        "E3",
                        &(tlv("4F", LOAD_FILE) + &tlv("9F70", "01") + &tlv("84", MODULE)),
                    ),
                    "9000",
                ),
                _ => sw("", "6A88"),
            },
            0xCA => match (apdu[2], apdu[3]) {
                (0x00, 0xE0) => sw("E006C00401308810", "9000"),
                (0xFF, 0x40) => sw("FF4000", "9000"),
                _ => sw("", "6A88"),
            },
            0xF0 => {
                if mode == Mode::Honest && in_crs {
                    *world.crs_state.lock().unwrap() = if apdu[3] == 0x01 { 1 } else { 0 };
                }
                sw("", "9000")
            }
            0xE6 => {
                if mode == Mode::Honest && apdu[2] == 0x08 {
                    *world.privilege.lock().unwrap() = 0x04;
                }
                sw("", "9000")
            }
            0x20 if mode == Mode::WrongPin => sw("", "63C2"),
            0xB0 => sw(&hex::encode_upper(&*world.binary.lock().unwrap()), "9000"),
            0xD6 => {
                if mode == Mode::Honest && apdu.len() > 5 {
                    *world.binary.lock().unwrap() = apdu[5..].to_vec();
                }
                sw("", "9000")
            }
            0xE4 => {
                // DELETE: 4F len AID, then the C-MAC.
                if mode == Mode::Honest && apdu.len() > 7 && apdu[5] == 0x4F {
                    let aid = hex::encode_upper(&apdu[7..7 + apdu[6] as usize]);
                    world.registry.lock().unwrap().retain(|a| *a != aid);
                }
                sw("", "9000")
            }
            _ => sw("", "9000"),
        }
    })
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

struct Out {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl Out {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

fn run_in(dir: &PathBuf, args: &[String], env: &[(&str, &str)], stdin: Option<&str>) -> Out {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .current_dir(dir)
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn sim-doctor");
    if let Some(text) = stdin {
        let _ = child.stdin.take().unwrap().write_all(text.as_bytes());
    } else {
        drop(child.stdin.take());
    }
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = out.read_to_end(&mut s);
        s
    });
    let t_err = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = err.read_to_end(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            panic!("sim-doctor {args:?} did not finish in 90 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        stdout: String::from_utf8_lossy(&t_out.join().unwrap()).into_owned(),
        stderr: String::from_utf8_lossy(&t_err.join().unwrap()).into_owned(),
        code: status.code(),
    }
}

/// A scratch directory with the key files in it.
struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(tag: &str) -> Work {
        let dir =
            std::env::temp_dir().join(format!("sim-doctor-gate-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Work { dir }
    }
    fn file(&self, name: &str, text: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Canary detection
// ---------------------------------------------------------------------------

fn base64(bytes: &[u8], url: bool, pad: bool) -> String {
    let table: &[u8] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(table[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
        if pad {
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
    }
    out
}

/// Every spelling of a secret a leak could take: hex (both cases, spaced, 0x-prefixed, with the
/// separators `:` and `-`), base64 (standard and URL, with and without padding), the decimal-array
/// Debug form, and the raw ASCII.
fn spellings(secret_hex: &str, ascii: Option<&str>) -> Vec<String> {
    let bytes = hex::decode(secret_hex).unwrap();
    let mut forms = vec![
        secret_hex.to_uppercase(),
        secret_hex.to_lowercase(),
        base64(&bytes, false, true),
        base64(&bytes, false, false),
        base64(&bytes, true, false),
        format!("{bytes:?}"),
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    ];
    if let Some(text) = ascii {
        forms.push(text.to_owned());
        forms.push(hex::encode_upper(text));
        forms.push(hex::encode(text));
        forms.push(base64(text.as_bytes(), false, true));
        forms.push(base64(text.as_bytes(), false, false));
    }
    forms
}

fn leaks(text: &str, forms: &[String]) -> Vec<String> {
    forms
        .iter()
        .filter(|f| text.contains(f.as_str()))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// The commands under test
// ---------------------------------------------------------------------------

/// A command line (without `--simulator`, `--json`, `--yes`) per SCP03 write path. `{KF}` is the
/// key file, `{NK}` the new key set file.
fn scp_cases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "gp delete",
            vec!["gp", "delete", "--aid", APP, "--keys-file", "{KF}"],
        ),
        (
            "gp make-default",
            vec!["gp", "make-default", "--aid", APP, "--keys-file", "{KF}"],
        ),
        (
            "gp rename-isd",
            vec![
                "gp",
                "rename-isd",
                "--new-aid",
                "A000000151000001",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp delete-key",
            vec![
                "gp",
                "delete-key",
                "--key-id",
                "01",
                "--key-version",
                "31",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp install",
            vec![
                "gp",
                "install",
                "--install-only",
                "--package",
                LOAD_FILE,
                "--module",
                MODULE,
                "--app",
                "A000000062000102",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp create-sd",
            vec![
                "gp",
                "create-sd",
                "--domain",
                "A000000151000003",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp put-key",
            vec![
                "gp",
                "put-key",
                "--new-key-version",
                "31",
                "--new-keys-file",
                "{NK}",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp cplc-set",
            vec![
                "gp",
                "cplc-set",
                "--kind",
                "perso",
                "--data",
                "0011223344556677",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp personalize",
            vec![
                "gp",
                "personalize",
                "--aid",
                APP,
                "--data",
                "5F2002AABB",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp aram add",
            vec![
                "gp",
                "aram",
                "add",
                "--aid",
                APP,
                "--apdu-always",
                "--nfc-always",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp aram delete-all",
            vec![
                "gp",
                "aram",
                "delete-all",
                "--confirm-delete-all",
                "DELETE-ALL",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp aram lock",
            vec!["gp", "aram", "lock", "--keys-file", "{KF}"],
        ),
        (
            "gp move",
            vec![
                "gp",
                "move",
                "--aid",
                APP,
                "--from",
                ISD,
                "--to",
                SD2,
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp store-data",
            vec![
                "gp",
                "store-data",
                "--data",
                "00112233",
                "--keys-file",
                "{KF}",
            ],
        ),
        (
            "gp secure-apdu",
            vec!["gp", "secure-apdu", "80E2900002AABB", "--keys-file", "{KF}"],
        ),
        (
            "gp crs activate",
            vec!["gp", "crs", "activate", APP, "--keys-file", "{KF}"],
        ),
        (
            "gp crs deactivate",
            vec!["gp", "crs", "deactivate", APP, "--keys-file", "{KF}"],
        ),
    ]
}

struct Ctx {
    work: Work,
    kf: String,
    nk: String,
}

impl Ctx {
    fn new(tag: &str) -> Ctx {
        let work = Work::new(tag);
        let kf = work.file(
            "keys.txt",
            &format!("{CANARY_KEY} {CANARY_KEY} {CANARY_KEY}\n"),
        );
        let nk = work.file(
            "new.txt",
            &format!("{CANARY_KEY2} {CANARY_KEY2} {CANARY_KEY2}\n"),
        );
        Ctx { work, kf, nk }
    }

    /// The case's argv with the placeholders filled, `--simulator` after the command word, and,
    /// when `keyed` is false, the key source dropped.
    fn argv(&self, case: &[&str], fake: &Fake, keyed: bool, extra: &[&str]) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();
        let mut skip = false;
        for a in case {
            if skip {
                skip = false;
                continue;
            }
            if !keyed && *a == "--keys-file" {
                skip = true;
                continue;
            }
            args.push(match *a {
                "{KF}" => self.kf.clone(),
                "{NK}" => self.nk.clone(),
                other => other.to_owned(),
            });
        }
        args.insert(1, fake.spec.clone());
        args.insert(1, "--simulator".to_owned());
        args.extend(extra.iter().map(|e| e.to_string()));
        args
    }

    fn run(
        &self,
        case: &[&str],
        mode: Mode,
        card_key: &str,
        keyed: bool,
        extra: &[&str],
    ) -> (Out, Fake) {
        let fake = Fake::start(card(card_key, World::new(), mode));
        let args = self.argv(case, &fake, keyed, extra);
        let out = run_in(&self.work.dir, &args, &[], None);
        (out, fake)
    }
}

fn fail_if(failures: Vec<String>) {
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// G1: without --yes nothing is written
// ---------------------------------------------------------------------------

#[test]
fn g1_scp03_writes_without_a_key_source_never_open_the_card() {
    let ctx = Ctx::new("g1a");
    let mut bad = Vec::new();
    for (name, case) in scp_cases() {
        let (out, fake) = ctx.run(&case, Mode::Honest, CANARY_KEY, false, &["--json"]);
        if fake.connections.load(Ordering::SeqCst) != 0 || fake.count() != 0 {
            bad.push(format!(
                "{name}: {} APDUs, {} connections without --yes and keys",
                fake.count(),
                fake.connections.load(Ordering::SeqCst)
            ));
        }
        if out.stdout.is_empty() && out.stderr.is_empty() {
            bad.push(format!("{name}: printed no plan and no refusal"));
        }
    }
    fail_if(bad);
}

#[test]
fn g1_scp03_writes_with_keys_but_without_yes_send_no_write() {
    // With a key source the dry run makes the one SCP03 authentication and reads the registry (the
    // help of every gp write says so). Nothing but SELECT, INITIALIZE UPDATE, EXTERNAL
    // AUTHENTICATE, GET DATA and GET STATUS may reach the card, and the authentication happens once.
    let ctx = Ctx::new("g1b");
    let mut bad = Vec::new();
    for (name, case) in scp_cases() {
        let (_, fake) = ctx.run(&case, Mode::Honest, CANARY_KEY, true, &["--json"]);
        if !fake.writes().is_empty() {
            bad.push(format!(
                "{name}: state-changing APDUs without --yes: {:?}",
                fake.writes()
            ));
        }
        if fake.ins(0x50) > 1 || fake.ins(0x82) > 1 {
            bad.push(format!("{name}: more than one authentication in a dry run"));
        }
    }
    fail_if(bad);
}

#[test]
fn g1_scp03_dry_run_with_keys_is_documented_to_authenticate_once() {
    // Pins the observed deviation from "zero APDUs": the keyed dry run sends EXTERNAL AUTHENTICATE
    // (a real authentication attempt against the card) although --yes is absent.
    let ctx = Ctx::new("g1c");
    let case = scp_cases().remove(0).1;
    let (out, fake) = ctx.run(&case, Mode::Honest, CANARY_KEY, true, &["--json"]);
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert_eq!(fake.ins(0x82), 1, "{:?}", fake.sent());
    assert!(out.stdout.contains("\"dry_run\":true"), "{}", out.stdout);
}

#[test]
fn g1_card_shell_writes_and_pin_commands_need_yes() {
    let ctx = Ctx::new("g1d");
    let pin = ctx.work.file("pin.txt", &format!("PIN1={CANARY_PIN}\n"));
    let scripts = [
        "select 2FE2; update_binary --data AABBCC",
        "terminate_card_usage",
        "verify_chv",
    ];
    for script in scripts {
        let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
        let args: Vec<String> = [
            "card",
            "--simulator",
            &fake.spec,
            "--chv-file",
            &pin,
            "-c",
            script,
            "--json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = run_in(&ctx.work.dir, &args, &[], None);
        assert_eq!(out.code, Some(0), "{script}: {}", out.all());
        assert!(
            fake.writes().is_empty(),
            "{script}: sent {:?}",
            fake.writes()
        );
        assert!(
            out.stdout.contains("\"sent\":false"),
            "{script}: {}",
            out.stdout
        );
    }
}

#[test]
fn g1_euicc_writes_need_yes() {
    let ctx = Ctx::new("g1e");
    let iccid = "89000000000000000001";
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("euicc nickname", vec!["euicc", "nickname", iccid, "n"]),
        ("euicc enable", vec!["euicc", "enable", iccid]),
        ("euicc disable", vec!["euicc", "disable", iccid]),
        ("euicc delete", vec!["euicc", "delete", iccid]),
        (
            "euicc reset",
            vec![
                "euicc",
                "reset",
                "--operational",
                "--confirm-eid",
                "89049032123451234512345678901235",
            ],
        ),
        (
            "euicc set-default-dp",
            vec!["euicc", "set-default-dp", "smdp.example.com"],
        ),
        ("euicc store-data", vec!["euicc", "store-data", "BF2200"]),
        (
            "euicc notifications remove",
            vec!["euicc", "notifications", "remove", "1"],
        ),
    ];
    let mut bad = Vec::new();
    for (name, case) in cases {
        let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
        let mut args: Vec<String> = case.iter().map(|s| s.to_string()).collect();
        args.insert(1, fake.spec.clone());
        args.insert(1, "--simulator".to_owned());
        let out = run_in(&ctx.work.dir, &args, &[], None);
        // A dry run may read (to print the plan) and open a logical channel (MANAGE CHANNEL 70); it
        // must not send STORE DATA (E2/E3), the carrier of every ES10 write.
        let stores = fake.ins(0xE2) + fake.ins(0xE3);
        if stores != 0 {
            bad.push(format!("{name}: {stores} STORE DATA without --yes"));
        }
        if out.stdout.contains("panicked") || out.stderr.contains("panicked") {
            bad.push(format!("{name}: panicked"));
        }
    }
    fail_if(bad);
}

#[test]
fn g1_fuzz_sends_nothing_without_its_gates() {
    let ctx = Ctx::new("g1f");
    let runs: Vec<Vec<&str>> = vec![
        vec!["fuzz", "ota", "--quick", "--json"],
        vec!["fuzz", "apdu", "--quick", "--json"],
        // the first gate alone: a simulator is not the software card, so the second is still needed
        vec![
            "fuzz",
            "ota",
            "--i-understand-this-can-brick-the-card",
            "--quick",
            "--json",
        ],
        vec![
            "fuzz",
            "ota",
            "--i-understand-this-can-brick-the-card",
            "--passthrough",
            "bruteforce",
            "--json",
        ],
        vec![
            "fuzz",
            "apdu",
            "--i-understand-this-can-brick-the-card",
            "--quick",
            "--json",
        ],
        vec!["fuzz", "mutate", "--json"],
    ];
    for case in runs {
        let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
        let mut args: Vec<String> = case.iter().map(|s| s.to_string()).collect();
        args.insert(1, fake.spec.clone());
        args.insert(1, "--simulator".to_owned());
        let out = run_in(&ctx.work.dir, &args, &[], None);
        assert_eq!(fake.count(), 0, "{case:?} sent APDUs: {}", out.all());
        assert_ne!(out.code, Some(0), "{case:?} should refuse: {}", out.all());
    }
}

#[test]
fn g1_erase_dry_run_sends_nothing() {
    let ctx = Ctx::new("g1g");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let args: Vec<String> = [
        "erase",
        "--simulator",
        &fake.spec,
        "--class",
        "magicsim",
        "--records",
        "1",
        "--json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(&ctx.work.dir, &args, &[], None);
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert_eq!(fake.connections.load(Ordering::SeqCst), 0);
    assert!(
        out.stdout.contains("\"card_touched\":false"),
        "{}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// G2: a failed authentication happens once and the run exits non-zero
// ---------------------------------------------------------------------------

#[test]
fn g2_a_wrong_key_is_tried_once_and_stops_before_external_authenticate() {
    let ctx = Ctx::new("g2a");
    let mut bad = Vec::new();
    for (name, case) in scp_cases() {
        let (out, fake) = ctx.run(&case, Mode::Honest, CANARY_KEY2, true, &["--json", "--yes"]);
        if out.code == Some(0) || out.code.is_none() {
            bad.push(format!("{name}: exit {:?} after a wrong key", out.code));
        }
        if fake.ins(0x50) != 1 {
            bad.push(format!("{name}: {} INITIALIZE UPDATE", fake.ins(0x50)));
        }
        if fake.ins(0x82) != 0 || !fake.writes().is_empty() {
            bad.push(format!("{name}: sent {:?} after a wrong key", fake.sent()));
        }
    }
    fail_if(bad);
}

#[test]
fn g2_a_refused_external_authenticate_is_not_retried() {
    let ctx = Ctx::new("g2b");
    let mut bad = Vec::new();
    for (name, case) in scp_cases() {
        let (out, fake) = ctx.run(
            &case,
            Mode::RefuseExtAuth,
            CANARY_KEY,
            true,
            &["--json", "--yes"],
        );
        if out.code == Some(0) || out.code.is_none() {
            bad.push(format!(
                "{name}: exit {:?} after a refused authentication",
                out.code
            ));
        }
        if fake.ins(0x50) != 1 || fake.ins(0x82) != 1 {
            bad.push(format!(
                "{name}: {} INITIALIZE UPDATE, {} EXTERNAL AUTHENTICATE",
                fake.ins(0x50),
                fake.ins(0x82)
            ));
        }
        if !fake.writes().is_empty() {
            bad.push(format!(
                "{name}: wrote after a refused authentication: {:?}",
                fake.writes()
            ));
        }
    }
    fail_if(bad);
}

#[test]
fn g2_unusable_key_material_never_reaches_the_card() {
    let ctx = Ctx::new("g2c");
    let short = &CANARY_KEY[..31];
    let bad_hex = format!("{}Z", &CANARY_KEY[..31]);
    let kcv = format!("{CANARY_KEY}/000000");
    let files = [
        ctx.work.file("short.txt", short),
        ctx.work.file("badhex.txt", &bad_hex),
        ctx.work.file("kcv.txt", &kcv),
        ctx.work.file("empty.txt", ""),
        ctx.work
            .dir
            .join("missing.txt")
            .to_string_lossy()
            .into_owned(),
    ];
    let mut bad = Vec::new();
    for file in &files {
        for (name, case) in scp_cases() {
            let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
            let mut args = ctx.argv(&case, &fake, true, &["--json", "--yes"]);
            let at = args.iter().position(|a| a == "--keys-file").unwrap();
            args[at + 1] = file.clone();
            let out = run_in(&ctx.work.dir, &args, &[], None);
            if fake.ins(0x50) + fake.ins(0x82) != 0 || !fake.writes().is_empty() {
                bad.push(format!(
                    "{name} with {file}: reached the card: {:?}",
                    fake.sent()
                ));
            }
            if out.code == Some(0) || out.code.is_none() {
                bad.push(format!("{name} with {file}: exit {:?}", out.code));
            }
        }
    }
    fail_if(bad);
}

#[test]
fn g2_a_wrong_pin_is_sent_once() {
    let ctx = Ctx::new("g2d");
    let pin = ctx.work.file("pin.txt", &format!("PIN1={CANARY_PIN}\n"));
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::WrongPin));
    let args: Vec<String> = [
        "card",
        "--simulator",
        &fake.spec,
        "--chv-file",
        &pin,
        "-c",
        "verify_chv",
        "--json",
        "--yes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(&ctx.work.dir, &args, &[], None);
    // one VERIFY without data is the standard tries-left query; exactly one carries the PIN
    let with_pin = fake
        .sent()
        .iter()
        .filter(|a| &a[2..4] == "20" && a.len() > 8)
        .count();
    assert_eq!(with_pin, 1, "{:?}\n{}", fake.sent(), out.all());
    assert_ne!(
        out.code,
        Some(0),
        "a refused PIN must not exit 0:\n{}",
        out.all()
    );
}

// ---------------------------------------------------------------------------
// G3: a canary secret never appears in any output
// ---------------------------------------------------------------------------

fn key_forms() -> Vec<String> {
    let mut forms = spellings(CANARY_KEY, None);
    forms.extend(spellings(CANARY_KEY2, None));
    // every 16-hex-digit window of either key: a partial echo of a malformed key counts as a leak
    for key in [CANARY_KEY, CANARY_KEY2] {
        for i in 0..=key.len() - 16 {
            forms.push(key[i..i + 16].to_owned());
            forms.push(key[i..i + 16].to_lowercase());
        }
    }
    forms
}

#[test]
fn g3_scp03_keys_never_reach_stdout_stderr_json_or_trace() {
    let ctx = Ctx::new("g3a");
    let forms = key_forms();
    let short = ctx.work.file("short.txt", &CANARY_KEY[..31]);
    let bad_hex = ctx
        .work
        .file("badhex.txt", &format!("{}Z", &CANARY_KEY[..31]));
    let kcv = ctx.work.file("kcv.txt", &format!("{CANARY_KEY}/000000"));
    let mut bad = Vec::new();
    let mut check = |label: String, out: &Out| {
        let leaked = leaks(&out.all(), &forms);
        if !leaked.is_empty() {
            bad.push(format!("{label}: leaked {leaked:?}"));
        }
        if out.all().contains("panicked") || out.code == Some(101) {
            bad.push(format!("{label}: panicked"));
        }
    };
    for (name, case) in scp_cases() {
        // success, wrong key, refused authentication, dry run: JSON with --trace, and the text form
        for (mode, key) in [
            (Mode::Honest, CANARY_KEY),
            (Mode::Honest, CANARY_KEY2),
            (Mode::RefuseExtAuth, CANARY_KEY),
        ] {
            for extra in [
                &["--json", "--trace", "--yes"][..],
                &["--trace", "--yes"][..],
                &["--json", "--trace"][..],
            ] {
                let (out, _) = ctx.run(&case, mode, key, true, extra);
                check(format!("{name} {extra:?} key {}", &key[..4]), &out);
            }
        }
        // the environment-variable path
        let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
        let mut args = ctx.argv(&case, &fake, true, &["--json", "--trace", "--yes"]);
        let at = args.iter().position(|a| a == "--keys-file").unwrap();
        args[at] = "--keys-env".into();
        args[at + 1] = "GATE_KEYS".into();
        let out = run_in(
            &ctx.work.dir,
            &args,
            &[(
                "GATE_KEYS",
                &format!("{CANARY_KEY} {CANARY_KEY} {CANARY_KEY}"),
            )],
            None,
        );
        check(format!("{name} --keys-env"), &out);
        // malformed key material: wrong length, bad hex, wrong KCV, a path that is not there
        for file in [&short, &bad_hex, &kcv, &"/nonexistent/keys.txt".to_owned()] {
            let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
            let mut args = ctx.argv(&case, &fake, true, &["--json", "--trace", "--yes"]);
            let at = args.iter().position(|a| a == "--keys-file").unwrap();
            args[at + 1] = file.clone();
            let out = run_in(&ctx.work.dir, &args, &[], None);
            check(format!("{name} malformed {file}"), &out);
        }
    }
    fail_if(bad);
}

#[test]
fn g3_dm_and_new_key_material_never_reach_output() {
    let ctx = Ctx::new("g3b");
    let forms = key_forms();
    let dm = ctx.work.file("dm.txt", CANARY_KEY2);
    let cases: Vec<Vec<&str>> = vec![
        vec![
            "gp",
            "delete",
            "--aid",
            APP,
            "--dm-key-file",
            &dm,
            "--keys-file",
            "{KF}",
        ],
        vec![
            "gp",
            "delete",
            "--aid",
            APP,
            "--dm-token-file",
            &dm,
            "--keys-file",
            "{KF}",
        ],
        vec![
            "gp",
            "install",
            "--install-only",
            "--package",
            LOAD_FILE,
            "--module",
            MODULE,
            "--app",
            "A000000062000102",
            "--dap-key-file",
            &dm,
            "--dap-domain",
            SD2,
            "--keys-file",
            "{KF}",
        ],
    ];
    let mut bad = Vec::new();
    for case in cases {
        for extra in [&["--json", "--trace", "--yes"][..], &["--trace"][..]] {
            for mode in [Mode::Honest, Mode::RefuseExtAuth] {
                let (out, _) = ctx.run(&case, mode, CANARY_KEY, true, extra);
                let leaked = leaks(&out.all(), &forms);
                if !leaked.is_empty() {
                    bad.push(format!("{case:?} {extra:?}: leaked {leaked:?}"));
                }
            }
        }
    }
    fail_if(bad);
}

#[test]
fn g3_pin_never_reaches_output() {
    let ctx = Ctx::new("g3c");
    let forms = spellings(&hex::encode(CANARY_PIN), Some(CANARY_PIN));
    let good = ctx.work.file("pin.txt", &format!("PIN1={CANARY_PIN}\n"));
    let bare = ctx.work.file("bare.txt", CANARY_PIN);
    let long = ctx.work.file(
        "long.txt",
        &format!("PIN1={CANARY_PIN}{CANARY_PIN}{CANARY_PIN}\n"),
    );
    let mut bad = Vec::new();
    for (label, mode) in [("honest", Mode::Honest), ("wrong", Mode::WrongPin)] {
        for file in [&good, &bare, &long] {
            for yes in [true, false] {
                let fake = Fake::start(card(CANARY_KEY, World::new(), mode));
                let mut args: Vec<String> = [
                    "card",
                    "--simulator",
                    &fake.spec,
                    "--chv-file",
                    file,
                    "-c",
                    "verify_chv; change_chv; disable_chv; enable_chv",
                    "--json",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect();
                if yes {
                    args.push("--yes".into());
                }
                let out = run_in(&ctx.work.dir, &args, &[], None);
                let leaked = leaks(&out.all(), &forms);
                if !leaked.is_empty() {
                    bad.push(format!(
                        "{label} {file} yes={yes}: leaked {leaked:?}\n{}",
                        out.all()
                    ));
                }
            }
        }
    }
    // the environment-variable path, and --dump (the exchange log redacts VERIFY data)
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::WrongPin));
    let dump = ctx.work.dir.join("dump.jsonl");
    let args: Vec<String> = [
        "card",
        "--simulator",
        &fake.spec,
        "--chv-env",
        "GATE_PIN",
        "--dump",
        dump.to_str().unwrap(),
        "-c",
        "verify_chv",
        "--json",
        "--yes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(
        &ctx.work.dir,
        &args,
        &[("GATE_PIN", &format!("PIN1={CANARY_PIN}"))],
        None,
    );
    let dumped = std::fs::read_to_string(&dump).unwrap_or_default();
    for (label, text) in [("output", out.all()), ("dump file", dumped)] {
        let leaked = leaks(&text, &forms);
        if !leaked.is_empty() {
            bad.push(format!("--chv-env {label}: leaked {leaked:?}"));
        }
    }
    fail_if(bad);
}

#[test]
fn g3_keygen_secret_never_reaches_output() {
    let ctx = Ctx::new("g3d");
    let forms = spellings(CANARY_KEY, None);
    let file = ctx.work.file("secret.txt", &format!("{CANARY_KEY}\n"));
    let mut bad = Vec::new();
    type KeygenRun<'a> = (Vec<String>, Vec<(&'a str, &'a str)>);
    let runs: Vec<KeygenRun> = vec![
        (
            vec![
                "keygen".into(),
                "--secret-file".into(),
                file.clone(),
                "--json".into(),
            ],
            vec![],
        ),
        (
            vec![
                "keygen".into(),
                "--secret-file".into(),
                file.clone(),
                "--index".into(),
                "3".into(),
            ],
            vec![],
        ),
        (
            vec![
                "keygen".into(),
                "--secret-env".into(),
                "GATE_SECRET".into(),
                "--json".into(),
            ],
            vec![("GATE_SECRET", CANARY_KEY)],
        ),
        (
            vec![
                "keygen".into(),
                "--secret-env".into(),
                "GATE_SECRET".into(),
                "--mcc".into(),
                "99999".into(),
                "--json".into(),
            ],
            vec![("GATE_SECRET", CANARY_KEY)],
        ),
        (
            vec![
                "keygen".into(),
                "--secret-file".into(),
                file.clone(),
                "--salt".into(),
                "zz".into(),
            ],
            vec![],
        ),
        (
            vec![
                "keygen".into(),
                "--secret-file".into(),
                "/nonexistent".into(),
            ],
            vec![],
        ),
    ];
    for (args, env) in runs {
        let out = run_in(&ctx.work.dir, &args, &env, None);
        let leaked = leaks(&out.all(), &forms);
        if !leaked.is_empty() {
            bad.push(format!("{args:?}: leaked {leaked:?}"));
        }
        if out.all().contains("panicked") {
            bad.push(format!("{args:?}: panicked"));
        }
    }
    fail_if(bad);
}

#[test]
fn g3_erase_keys_never_reach_output() {
    let ctx = Ctx::new("g3e");
    let forms = key_forms();
    let mut bad = Vec::new();
    for extra in [
        &["--yes", "--confirm-iccid", "8901260000000000000"][..],
        &["--dry-run"][..],
        &["--yes"][..],
    ] {
        let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
        let mut args: Vec<String> = [
            "erase",
            "--simulator",
            &fake.spec,
            "--class",
            "magicsim",
            "--records",
            "1",
            "--keys-file",
            &ctx.kf,
            "--json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.extend(extra.iter().map(|e| e.to_string()));
        let out = run_in(&ctx.work.dir, &args, &[], None);
        let leaked = leaks(&out.all(), &forms);
        if !leaked.is_empty() {
            bad.push(format!("erase {extra:?}: leaked {leaked:?}"));
        }
    }
    fail_if(bad);
}

// ---------------------------------------------------------------------------
// G4: write verbs and --yes are refused over MCP
// ---------------------------------------------------------------------------

/// Runs `sim-doctor mcp [--simulator spec]` over the calls, returns every JSON-RPC answer by id.
fn mcp_session(
    work: &Work,
    spec: Option<&str>,
    calls: &[(u32, &str, serde_json::Value)],
) -> std::collections::BTreeMap<u32, serde_json::Value> {
    let mut input = String::from(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"gate","version":"0"}}}"#,
    );
    input.push('\n');
    for (id, method, params) in calls {
        input.push_str(
            &serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
                .to_string(),
        );
        input.push('\n');
    }
    let mut args = vec!["mcp".to_owned()];
    if let Some(spec) = spec {
        args.push("--simulator".into());
        args.push(spec.into());
    }
    let out = run_in(&work.dir, &args, &[], Some(&input));
    out.stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| Some((v["id"].as_u64()? as u32, v)))
        .collect()
}

fn refused(answer: &serde_json::Value) -> bool {
    answer.get("error").is_some() || answer["result"]["isError"] == true
}

#[test]
fn g4_mcp_lists_no_write_tool_and_no_yes_or_key_property() {
    let work = Work::new("g4a");
    let answers = mcp_session(&work, None, &[(2, "tools/list", serde_json::json!({}))]);
    let tools = answers[&2]["result"]["tools"].as_array().expect("tools");
    let allowed = [
        "scan",
        "rules_list",
        "rules_explain",
        "euicc_info",
        "euicc_profiles",
        "euicc_notifications",
        "gp_info",
        "gp_ara",
        "gp_status",
    ];
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        assert!(
            allowed.contains(&name),
            "unexpected MCP tool {name}: a new tool needs a review against the write gate"
        );
        let schema = tool["inputSchema"]["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for property in schema.keys().filter(|p| !(name == "scan" && *p == "yes")) {
            // scan advertises "yes" yet refuses it (FINDING F-5, below)
            for forbidden in [
                "keys",
                "key_",
                "confirm",
                "chv",
                "secret",
                "dm_",
                "dap",
                "i_understand",
                "allow_real",
            ] {
                assert!(!property.contains(forbidden), "{name} exposes {property}");
            }
        }
    }
}

#[test]
fn g4_mcp_refuses_write_verbs_and_yes_and_sends_no_apdu() {
    let work = Work::new("g4b");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let calls = [
        (
            3,
            "tools/call",
            serde_json::json!({"name":"gp_delete","arguments":{"aid":APP,"yes":true}}),
        ),
        (
            4,
            "tools/call",
            serde_json::json!({"name":"euicc_nickname","arguments":{"iccid":"89000000000000000001","name":"x","yes":true}}),
        ),
        (
            5,
            "tools/call",
            serde_json::json!({"name":"scan","arguments":{"yes":true}}),
        ),
        (
            6,
            "tools/call",
            serde_json::json!({"name":"scan","arguments":{"tar_uncapped":true,"tar":"full"}}),
        ),
        (
            7,
            "tools/call",
            serde_json::json!({"name":"gp_status","arguments":{"reader":"--yes"}}),
        ),
        (
            8,
            "tools/call",
            serde_json::json!({"name":"gp_status","arguments":{"keys_file":"/etc/passwd","yes":true}}),
        ),
        (
            9,
            "tools/call",
            serde_json::json!({"name":"scan","arguments":{"simulator":"127.0.0.1:1"}}),
        ),
        (
            10,
            "tools/call",
            serde_json::json!({"name":"scan","arguments":{"yes":false}}),
        ),
    ];
    let answers = mcp_session(&work, Some(&fake.spec), &calls);
    for id in [3, 4, 5, 7, 8, 9] {
        assert!(
            refused(&answers[&id]),
            "call {id} was not refused: {}",
            answers[&id]
        );
    }
    // --tar-uncapped without --yes is the dry run (exit 2): an error, and no ENVELOPE.
    assert!(refused(&answers[&6]), "{}", answers[&6]);
    assert_eq!(
        fake.ins(0xC2),
        0,
        "an ENVELOPE reached the card over MCP: {:?}",
        fake.sent()
    );
    assert!(fake.writes().is_empty(), "{:?}", fake.writes());
}

// ---------------------------------------------------------------------------
// G5: a success claim is backed by a read-back
// ---------------------------------------------------------------------------

fn claims_success(out: &Out) -> bool {
    out.code == Some(0)
}

#[test]
fn g5_registry_writes_check_the_registry_not_just_9000() {
    // A card that answers 9000 to every write and changes nothing must never get a success exit.
    let ctx = Ctx::new("g5a");
    let mut bad = Vec::new();
    for name in [
        "gp delete",
        "gp move",
        "gp install",
        "gp create-sd",
        "gp rename-isd",
        "gp aram add",
        "gp crs activate",
        "gp crs deactivate",
    ] {
        let case = scp_cases().into_iter().find(|(n, _)| *n == name).unwrap().1;
        let (out, fake) = ctx.run(&case, Mode::Liar, CANARY_KEY, true, &["--json", "--yes"]);
        let wrote = fake.ins(0xE4) + fake.ins(0xE6) + fake.ins(0xE2) + fake.ins(0xF0) > 0;
        // crs deactivate has nothing to do on an already deactivated application: not a write
        if wrote && claims_success(&out) {
            bad.push(format!(
                "{name}: the card said 9000 and changed nothing, yet exit 0"
            ));
        }
    }
    fail_if(bad);
}

#[test]
fn g5_delete_and_crs_succeed_only_when_the_read_back_agrees() {
    // Positive controls: with an honest card the same commands do succeed, so the liar result above
    // is the read-back and not a blanket refusal.
    let ctx = Ctx::new("g5b");
    let case = scp_cases()
        .into_iter()
        .find(|(n, _)| *n == "gp delete")
        .unwrap()
        .1;
    let (out, fake) = ctx.run(&case, Mode::Honest, CANARY_KEY, true, &["--json", "--yes"]);
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert_eq!(fake.ins(0xE4), 1);
    assert!(out.stdout.contains("\"verified\":true"), "{}", out.stdout);
    let case = scp_cases()
        .into_iter()
        .find(|(n, _)| *n == "gp crs activate")
        .unwrap()
        .1;
    let (out, fake) = ctx.run(&case, Mode::Honest, CANARY_KEY, true, &["--json", "--yes"]);
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert_eq!(fake.ins(0xF0), 1);
}

// ---------------------------------------------------------------------------
// G6: large sweeps need --yes and print the count first
// ---------------------------------------------------------------------------

#[test]
fn g6_scan_tar_uncapped_is_a_dry_run_that_prints_the_count() {
    let ctx = Ctx::new("g6a");
    for (selection, count) in [("focused", "656"), ("full", "16777216")] {
        let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
        let args: Vec<String> = [
            "scan",
            "--simulator",
            &fake.spec,
            "--tar",
            selection,
            "--tar-uncapped",
            "--json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = run_in(&ctx.work.dir, &args, &[], None);
        assert_eq!(out.code, Some(2), "{}", out.all());
        assert_eq!(fake.count(), 0, "{selection}: APDUs without --yes");
        assert_eq!(fake.connections.load(Ordering::SeqCst), 0);
        assert!(
            out.stderr.contains(count),
            "the count {count} is not printed: {}",
            out.stderr
        );
        assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    }
}

#[test]
fn g6_scan_tar_uncapped_with_yes_sends_exactly_the_printed_count() {
    // 656 is the bounded "focused" selection, small enough to run for real against the fake.
    let ctx = Ctx::new("g6b");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let args: Vec<String> = [
        "scan",
        "--simulator",
        &fake.spec,
        "--tar",
        "focused",
        "--tar-uncapped",
        "--yes",
        "--json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(&ctx.work.dir, &args, &[], None);
    assert_eq!(out.code, Some(0), "{}", out.all());
    let sent = fake.ins(0xC2);
    assert!(
        (656..=700).contains(&sent),
        "printed 656 ENVELOPEs, sent {sent}"
    );
}

#[test]
fn g6_fuzz_sweeps_are_capped_even_with_both_gates() {
    let ctx = Ctx::new("g6c");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let args: Vec<String> = [
        "fuzz",
        "--simulator",
        &fake.spec,
        "ota",
        "--i-understand-this-can-brick-the-card",
        "--allow-real-hardware",
        "--passthrough",
        "bruteforce",
        "--json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(&ctx.work.dir, &args, &[], None);
    // the bruteforce sweep is 786432 envelopes; the run is bounded
    assert!(fake.ins(0xC2) <= 4096, "{} envelopes", fake.ins(0xC2));
    assert!(out.stdout.contains("\"capped\":true"), "{}", out.stdout);
}

// ---------------------------------------------------------------------------
// FINDINGS: each test states the property that should hold; each fails today
// ---------------------------------------------------------------------------

#[test]
#[ignore = "FINDING F-1 (high): scan --tar full|focused|range sends up to 4096 ENVELOPEs with no --yes and no count first"]
fn finding_f1_scan_tar_probes_send_envelopes_without_yes() {
    let ctx = Ctx::new("f1");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let args: Vec<String> = ["scan", "--simulator", &fake.spec, "--tar", "full", "--json"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let _ = run_in(&ctx.work.dir, &args, &[], None);
    assert_eq!(
        fake.ins(0xC2),
        0,
        "{} ENVELOPEs were sent without --yes",
        fake.ins(0xC2)
    );
}

#[test]
fn finding_f2_erase_refuses_the_simulator_flag() {
    let ctx = Ctx::new("f2");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let args: Vec<String> = [
        "erase",
        "--simulator",
        &fake.spec,
        "--class",
        "magicsim",
        "--records",
        "1",
        "--keys-file",
        &ctx.kf,
        "--yes",
        "--confirm-iccid",
        "8901260000000000000",
        "--json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(&ctx.work.dir, &args, &[], None);
    // Decided: erase works only on a real reader, so --simulator is refused, not honoured.
    assert_ne!(out.code, Some(0), "{}", out.all());
    assert!(
        out.stderr
            .contains("erase works only on a real card reader"),
        "{}",
        out.stderr
    );
    assert_eq!(fake.count(), 0, "APDUs were sent: {:?}", fake.sent());
    assert_eq!(
        fake.connections.load(Ordering::SeqCst),
        0,
        "the simulator was connected to"
    );
}

#[test]
fn finding_f3_update_binary_read_back_mismatch_is_a_failure() {
    let ctx = Ctx::new("f3");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Liar));
    let args: Vec<String> = [
        "card",
        "--simulator",
        &fake.spec,
        "-c",
        "select 2FE2; update_binary --data AABBCC --read-back",
        "--json",
        "--yes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let out = run_in(&ctx.work.dir, &args, &[], None);
    assert!(out.stdout.contains("\"verified\":false"), "{}", out.stdout);
    assert_ne!(out.code, Some(0), "mismatch exits 0:\n{}", out.stdout);
}

#[test]
fn finding_f4_verified_true_needs_a_read_back() {
    let ctx = Ctx::new("f4");
    let mut bad = Vec::new();
    for name in ["gp cplc-set", "gp personalize", "gp store-data"] {
        let case = scp_cases().into_iter().find(|(n, _)| *n == name).unwrap().1;
        let (out, _) = ctx.run(&case, Mode::Liar, CANARY_KEY, true, &["--json", "--yes"]);
        if out.stdout.contains("\"verified\":true") {
            bad.push(format!(
                "{name}: verified:true while the card changed nothing"
            ));
        }
    }
    fail_if(bad);
}

#[test]
fn finding_f5_mcp_schema_does_not_advertise_yes() {
    let work = Work::new("f5");
    let answers = mcp_session(&work, None, &[(2, "tools/list", serde_json::json!({}))]);
    for tool in answers[&2]["result"]["tools"].as_array().unwrap() {
        let props = tool["inputSchema"]["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        assert!(
            !props.contains_key("yes"),
            "{} advertises yes",
            tool["name"]
        );
    }
}

#[test]
fn finding_f6_mcp_simulator_flag_reaches_the_tool_calls() {
    let work = Work::new("f6");
    let fake = Fake::start(card(CANARY_KEY, World::new(), Mode::Honest));
    let calls = [(
        3,
        "tools/call",
        serde_json::json!({"name":"gp_info","arguments":{}}),
    )];
    let answers = mcp_session(&work, Some(&fake.spec), &calls);
    assert!(
        fake.connections.load(Ordering::SeqCst) >= 1,
        "--simulator was ignored by the tool call: {}",
        answers[&3]
    );
}
