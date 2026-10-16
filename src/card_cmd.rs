//! `sim-doctor card`: the loop around [`sim_doctor::cardsh::Shell`] (PC/SC, stdin, stdout).

use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;

use clap::Args;
use sim_doctor::cardsh::secrets::csv::CardKeyFile;
use sim_doctor::cardsh::{self, Opts, Profile, Shell};
use sim_doctor::transport::replay::Record;
use sim_doctor::transport::CardSession;
use sim_doctor::{contract, scan};

/// Everything `sim-doctor card` takes.
#[derive(Args)]
pub struct CardShellArgs {
    /// The reader to use, matched against the driver's own name (default: the first reader).
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// The command set the card speaks: uicc (class 00) or sim (class A0, GSM 11.11).
    #[arg(long, value_name = "PROFILE", default_value = "uicc", value_parser = ["uicc", "sim"])]
    profile: String,

    /// Which FCP tag table the card answers SELECT with (see `scan --help`).
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = super::parse_dialect
    )]
    dialect: scan::Dialect,

    /// Run these `;`-separated commands and exit.
    #[arg(short = 'c', value_name = "COMMANDS", conflicts_with = "script")]
    command: Option<String>,

    /// Run the commands in this file, one per line (`#` starts a comment), and exit.
    #[arg(long, value_name = "PATH")]
    script: Option<std::path::PathBuf>,

    /// Print every reply as one JSON record (for agents).
    #[arg(long)]
    json: bool,

    /// File holding PINs, PUKs and ADM keys for `verify_chv` / `unblock_chv` (`pin1=1234` per line;
    /// keep it chmod 600). Never a value on the command line: it would land in shell history.
    #[arg(long, value_name = "PATH", conflicts_with = "chv_env")]
    chv_file: Option<std::path::PathBuf>,

    /// Environment variable holding the same text (entries separated by `;` or newlines).
    #[arg(long, value_name = "VAR")]
    chv_env: Option<String>,

    /// pySim CardKeyProvider CSV file for `query_card_key` (ICCID,ADM1,OPC,...; one card per row).
    /// Read and checked before any reader is opened; secrets are never printed unless named in
    /// --fields. Keep it chmod 600.
    #[arg(long, value_name = "PATH")]
    key_file: Option<std::path::PathBuf>,
    /// Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE): no other
    /// process can use the card while this shell is open. Off by default, which shares it.
    #[arg(short = 'X', long)]
    exclusive: bool,

    /// Send the commands that change the card (APDUs outside the read-only set, PIN checks, ...).
    /// Without it they print what they would send and the card is not touched by them.
    #[arg(long)]
    yes: bool,

    /// Write every APDU exchange (command and response, hex) to FILE as JSON lines, in the
    /// SIM_DOCTOR_RECORD replay format. The data field of secret instructions (VERIFY, CHANGE,
    /// ENABLE/DISABLE, RESET RETRY COUNTER, AUTHENTICATE) is redacted as FF bytes, and so are the
    /// response data of AUTHENTICATE (RES, CK, IK, Kc); such lines carry "redacted":true and no
    /// longer replay byte for byte. --dump-secrets records them raw. The file holds raw card data (ICCID, IMSI, file contents): review it before it goes
    /// anywhere. Refuses an existing file unless --force; never writes through a symlink or into a
    /// non-regular file. The file is owner-only (0600).
    #[arg(long, value_name = "FILE")]
    dump: Option<std::path::PathBuf>,

    /// Let --dump overwrite an existing regular file.
    #[arg(long, requires = "dump")]
    force: bool,

    /// Record PINs and keys in plain text: the data field of VERIFY, CHANGE, ENABLE/DISABLE,
    /// RESET RETRY COUNTER and AUTHENTICATE, and the response data of AUTHENTICATE (RES, CK, IK,
    /// Kc), is written raw. Keep the file private. Needs --dump.
    #[arg(long, requires = "dump")]
    dump_secrets: bool,
}

pub fn run(args: CardShellArgs) -> contract::ExitCode {
    // Read and checked before a reader is opened, so a typo costs the card nothing.
    let source = match (&args.chv_file, &args.chv_env) {
        (Some(path), _) => Some(cardsh::secrets::Source::File(path.clone())),
        (None, Some(name)) => Some(cardsh::secrets::Source::Env(name.clone())),
        (None, None) => None,
    };
    let secrets = match source
        .as_ref()
        .map(cardsh::secrets::Secrets::load)
        .transpose()
    {
        Ok(s) => s,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            return contract::ExitCode::Error;
        }
    };
    // The pySim CardKeyProvider CSV for `query_card_key`. Parsed here, not in the shell, so a
    // malformed file is exit 2 before any reader is opened.
    let card_key = match &args.key_file {
        Some(path) => match CardKeyFile::load(path) {
            Ok(f) => Some(f),
            Err(message) => {
                eprintln!("sim-doctor: {message}");
                return contract::ExitCode::Error;
            }
        },
        None => None,
    };
    let dump = match args
        .dump
        .as_deref()
        .map(|path| open_dump(path, args.force))
        .transpose()
    {
        Ok(file) => file,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            return contract::ExitCode::Error;
        }
    };
    let dump_secrets = args.dump_secrets;
    let exclusive = args.exclusive;
    let opener: cardsh::Opener = Box::new(move |requested| {
        let (session, reader, atr) =
            super::open_scan_session(requested, exclusive).map_err(|f| f.message)?;
        let session: Box<dyn CardSession> = match &dump {
            Some(file) => {
                let file = file.try_clone().map_err(|err| err.to_string())?;
                let record = Record::new(session, file);
                Box::new(if dump_secrets {
                    record
                } else {
                    record.redacting()
                })
            }
            None => session,
        };
        Ok((session, reader.as_str().to_owned(), atr))
    });
    let mut shell = Shell::new(
        opener,
        Opts {
            yes: args.yes,
            dialect: args.dialect.tag_set(),
            secrets,
            card_key,
        },
    );
    let profile = if args.profile == "sim" {
        Profile::Sim
    } else {
        Profile::Uicc
    };
    if let Err(message) = shell.equip(args.reader.as_deref(), profile) {
        eprintln!("sim-doctor: {message}");
        return contract::ExitCode::Error;
    }
    let lines: Vec<String> = if let Some(script) = &args.command {
        cardsh::split_commands(script)
    } else if let Some(path) = &args.script {
        match std::fs::read_to_string(path) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(err) => {
                eprintln!("sim-doctor: {}: {err}", path.display());
                return contract::ExitCode::Error;
            }
        }
    } else {
        return interactive(&mut shell, args.json);
    };
    for line in lines {
        let reply = shell.exec(&line);
        if emit(&line, &reply, args.json).is_err() {
            return contract::ExitCode::Error;
        }
        if reply.quit {
            break;
        }
    }
    finish(&shell)
}

/// Opens the `--dump` file. An existing path is refused unless `force`; a symlink or any other
/// non-regular file is refused always (`O_NOFOLLOW` and `O_EXCL` stop a race from swapping one in).
fn open_dump(path: &Path, force: bool) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let shown = path.display();
    let existed = match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(format!(
                "{shown}: not a regular file; refusing to write the dump there"
            ))
        }
        Ok(_) if !force => return Err(format!("{shown} exists; pass --force to overwrite it")),
        Ok(_) => true,
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(err) => return Err(format!("{shown}: {err}")),
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if existed {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let file = options
        .open(path)
        .map_err(|err| format!("{shown}: {err}"))?;
    if !file.metadata().map_err(|err| err.to_string())?.is_file() {
        return Err(format!(
            "{shown}: not a regular file; refusing to write the dump there"
        ));
    }
    Ok(file)
}

fn finish(shell: &Shell) -> contract::ExitCode {
    if shell.failed == 0 {
        contract::ExitCode::Success
    } else {
        contract::ExitCode::Findings
    }
}

/// Prints one reply: the text for a person, one record for `--json`. Errors go to stderr as text.
fn emit(line: &str, reply: &cardsh::Reply, json: bool) -> io::Result<()> {
    if line.trim().is_empty() || line.trim_start().starts_with('#') {
        return Ok(());
    }
    let mut out = io::stdout().lock();
    if json {
        writeln!(out, "{}", reply.record(line.trim()))?;
    } else if !reply.ok {
        eprintln!("error: {}", reply.text);
    } else if !reply.text.is_empty() {
        writeln!(out, "{}", reply.text)?;
    }
    out.flush()
}

fn interactive(shell: &mut Shell, json: bool) -> contract::ExitCode {
    let tty = io::stdin().is_terminal();
    if tty && !json {
        println!("sim-doctor card: type `help`; `quit` leaves.");
    }
    // The shell reads until EOF or `quit`: Ctrl-C ends the process like any command line tool.
    // SAFETY: SIG_DFL is a valid disposition; no handler pointer is involved.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        if tty && !json {
            print!("{}> ", shell.pwd());
            let _ = io::stdout().flush();
        }
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let reply = shell.exec(&line);
        if emit(&line, &reply, json).is_err() || reply.quit {
            break;
        }
    }
    finish(shell)
}
