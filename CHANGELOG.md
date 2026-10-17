# Changelog

## Unreleased

### Added

- `gp create-sd`: create a supplementary Security Domain over an SCP03 channel
  (`--domain`, `--allow-to`, `--allow-from`), dry run unless `--yes`, with the
  registry pre-read refusals and the post-write re-read the other gp writes
  have. (#244)


All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `card` shell: VERIFY, UNBLOCK and CHANGE refuse a PIN or PUK the card reports blocked with SW `98 40` ("CHV blocked", ETSI TS 102 221) as well as `69 83`, before any secret is sent; the retry counter from `63 Cx` is reported as before (#195).
- `sms decode` reads the SCTS timestamp as swapped semi-octets with a signed quarter-hour zone; it printed raw byte values before.

### Added
- `card` shell: `echo STRING...` (print a string, no card interaction), `version` (print tool name and version, no card interaction), and `reset` (warm-reset the card by re-opening the session on the same reader and profile; no `--yes` needed) (#165).
- `export` and `fsdump` card-shell commands (#160): read-only dumps of the files in the current DF. `fsdump --json` prints a JSON object `{name, atr, files:[{path, fid, name, structure, size, record_count, data_hex, decoded, records, sw}]}` per EF/DF; `export [--filename F]` prints a pySim-shell import script (`select NAME` then `update_binary/update_record --data HEX`). Both never send a write APDU.
- `query_card_key` card-shell command and `--key-file PATH`: looks up a card in a pySim CardKeyProvider CSV by `--key`/`--value` and prints the requested `--fields` (pySim `query_card_key`). Reads the local file only, never sends APDUs; secret fields (KI/OPC/ADM keys, ...) are returned only when named in `--fields`, never by default (#164).
- `create_ef`, `create_df`, `resize_ef` and `delete_file` card-shell commands (CREATE FILE EF/DF, RESIZE FILE, DELETE FILE; destructive, dry run unless --yes) (#182).
- `update_imsi_plmn` card-shell command: rewrites the PLMN of the selected EF.IMSI and keeps the MSIN, read back to verify; gated behind `--yes`, dry run otherwise (#187).
- `verify_adm` card-shell command (VERIFY of ADM1..ADM5, default ADM1, key reference 0A..0E); `--pin-is-hex` asserts the source holds the ADM key as `hex:` and is refused before sending on a mismatch. Dry run unless --yes (#194).
- `terminal_capability`, `suspend_uicc` and `resume_uicc` card-shell commands (TERMINAL CAPABILITY INS 0xAA; SUSPEND/RESUME UICC INS 0x76; gated behind `--yes`, dry run prints the APDU; suspend can leave the card unusable until resumed or power-cycled) (#202).
- `edit_decoded` card-shell command: edit a transparent EF as JSON (`$EDITOR`, or `--json-file`), re-encode and write it back with UPDATE BINARY, then read it back. Supports EF.ICCID, EF.IMSI, EF.ACC, EF.FPLMN and raw files; other kinds are refused until their encoders exist. Dry run unless `--yes`; WARNING: overwrites the EF's content (#181).
- `edit_record_decoded` card-shell command: edit one record of a record-structured EF as JSON and write it back with UPDATE RECORD, then read it back. Supports EF.MSISDN; the capability and extension ids of the record are kept. Dry run unless `--yes`; WARNING: overwrites the record (#181).
- `fuzz ota` sends a TERMINAL PROFILE itself, once, when its calibration is a generic-error blind spot, then calibrates again; the profile is reported as `data.fuzz.ota.terminal_profile` (#211). A card that already judges envelopes gets no profile.
- `fuzz`: SIMTester crypto fuzzers 5-8 and 13-16 build their Command Packet (CC and ciphering) in `FuzzerSpec::secured_command_packet`; the `fuzz ota` sweep is not rewired onto them yet.
- OTA fuzzer table: SIMTester's seventeen fuzzers (`FuzzerFactory` 0-16) as `fuzz::FUZZERS`, with the counter-mode, PoR and KIC/KID algorithm fields and a Command Packet header builder. Fuzzers with a KIC or KID algorithm return no packet until the cryptographic checksum and ciphering are built (#209).
- `scan --tar --sms-deliver-report` (`--sdr`, SIMTester's `-sdr`): the TAR probes ask for SMS-DELIVER-REPORT as the proof-of-receipt mode (SPI2 `09`) instead of SMS-SUBMIT (SPI2 `29`, the default); reported as `data.tar.por_mode` (#207).
- `sim-doctor trace --show-raw-apdu`, `--no-suppress-select` and `--no-suppress-status`, as in pySim-trace (#216). SELECT and UICC STATUS rows are now hidden from the table by default (the JSON keeps every exchange); the raw hex is printed under each row with `--show-raw-apdu`.
- `sim-doctor trace` reads TCA Loader logs (`Command <hex>` / `Response <hex>` lines), detected automatically, as pySim's `tca-loader-log` source does (#215).
- `sim-doctor trace` reads RSPRO (osmo-remsim) pcap and pcapng captures: the modem-to-card and card-to-modem TPDUs inside TCP and the IPA multiplex are paired as pySim's `rspro-pyshark-pcap` pairs them, with no patched Wireshark (#214). A capture that moves between SIM bank slots is refused. Status messages are skipped; a capture holding both GSMTAP and RSPRO reads only the GSMTAP.
- `sim-doctor saip parse FILE [--json]`: offline decode of a SAIP profile package (the DER ProfileElement sequence) into JSON, each element named by its PE type in SAIP 3.3.1 order, a bounded TLV tree beneath it, and unknown PEs as raw hex. Named fields for the header, pinCodes, pukCodes, end and mf PEs, checked against a public SIMalliance sample. Parse only; personalization and templates are not included (#226).
- `sim-doctor esim-cert verify <chain> --root <ci>`: offline eSIM certificate and CI chain check. Parses DER or PEM certificates, verifies ecdsa-with-SHA256 P-256 signatures up to a CI root the caller supplies, and reports validity periods and KeyUsage per certificate (#231).
- `card --dump FILE` writes every APDU command and response to FILE in the `SIM_DOCTOR_RECORD` replay format; refuses an existing file unless `--force`, never writes through a symlink (#223). The data field of PIN, key and authentication instructions (VERIFY, CHANGE, ENABLE/DISABLE, RESET RETRY COUNTER, AUTHENTICATE) is redacted as FF, and so are the response data of AUTHENTICATE (RES, CK, IK, Kc), unless `--dump-secrets` (#223).
- `card -X` / `--exclusive` opens the reader with PC/SC exclusive access (SCARD_SHARE_EXCLUSIVE) instead of shared; opt-in, the default stays shared (#221).
- `sim-doctor euicc challenge`: GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7) prints the 16-byte eUICC challenge, read-only (#228).
- `sim-doctor readers` lists the PC/SC readers by name and index, needing no card (`--json` for an envelope); exits 2 when the PC/SC service is unreachable. `scan`, `shell` and `explore` take `--reader-index N` to select a reader by that index instead of by name, for readers that share a name (#220).
- `fuzz compare <RESULT_FILE>... [--json]`: compares two or more `fuzz ota --json` results, ranking keysets by accepted probes and listing the (TAR, keyset, mechanism) triples the runs disagree on. Offline; only triples every run probed are compared; a bad or oversized file refuses with exit 2 (#272).
- `gp cplc-set --kind pre-perso|perso --data HEX [--today]`: writes the CPLC pre-personalization (DGI 9F67) or personalization (DGI 9F66) block over SCP03 with one STORE DATA; dry run unless `--yes`, `--today` writes the date (#242).
- `gp status --list` (registry table) and `gp status --info` (one block per registry entry): read-only text over the GET STATUS data `gp status` already reads, no new APDUs (#254).
- `gp make-default --aid` (INSTALL [for make selectable] with the Card Reset / Default Selected privilege) and `gp rename-isd --new-aid` (STORE DATA `4F LEN AID`, renames the ISD; the result carries a lock-out warning). Both are dry runs unless `--yes`, need keys to send, refuse with nothing sent when the registry does not allow it, and verify the registry afterwards (#243).
- `gp install --make-default` sets the Card Reset (Default Selected) privilege, 0x04 in the first privilege byte, in the install (GP Card Spec v2.3.1 table 11-7; GlobalPlatformPro `CardReset`). Dry run unless --yes (#240).
- `sim-doctor gp personalize --aid <HEX> --data <BER-TLV HEX>`: INSTALL [for personalization] then STORE DATA over SCP03; dry run unless --yes, registry pre-read refuses an AID that is not on the card (#236).
- `sim-doctor scan --sffs` probes only the standard file identifiers (ETSI TS 102 221 / 3GPP TS 31.102 / 31.103 / 31.104 / 51.011) instead of the GSM 11.11 family ranges (#270).
- `fuzz ota --poke`: the OTA quick "poke" mode (issue #267), probing only the three TARs SIMTester's `-poke` probes (000000, B00001, B00010) with the quick keysets and mechanisms; the `fuzz.ota` report carries `"poke": true`.
- `scan --reserved-file-ids`: probe reserved file identifiers (7FF0-7FFF) inside an application; by default they are treated as aliases and skipped (#271).
- `sim-doctor gp delete-key`: DELETE KEY over SCP03 (GlobalPlatform Card Spec v2.3.1 11.2.2),
  deleting one key by `--key-id`/`--key-version` (tags D0/D2). Dry run unless `--yes`; keys
  only from `--keys-file`/`--keys-env`; post-delete GET DATA E0 verifies the key is gone (#235).
  Refuses (nothing sent) a delete of the key version the session authenticated with
  (`would-delete-session-key`) or of every key on the card (`would-delete-last-key-set`);
  `--allow-lockout` downgrades those two to a WARNING (still needs `--yes`).
- `gp install --bs <1-247>`: LOAD block size, as GlobalPlatformPro's `--bs` (default 240, unchanged). Only how the load file is split changes; shown in the dry run (#252).
- `scan --tar-filter <regex>`: SIMTester's `-stre` response filter for the TAR audit. A sweep probe whose response matches is reported as `filtered` and raises nothing (#264).
- `card --read-csv FILE` runs the `command` column of a CSV file through the card shell, one row per command (a command table, not pySim's provisioning CSV). `card --write-csv FILE` appends a redacted result log (`command,ok,text`; arguments become `<args redacted>`). Both keep the `--yes` gate and dry runs (part of #279; ICCID/IMSI/Ki provisioning import and export is not implemented).
- `sim-doctor euicc set-default-dp <ADDRESS>`: ES10a SetDefaultDpAddress (SGP.22 v2.5 clause 5.7.4), the eUICC default SM-DP+ address. A dry run that opens no reader unless `--yes`, one error kind per result code, and the configured addresses are re-read and checked after a write; never exposed over MCP (#227).
- SCP03 C-ENC, R-MAC, R-ENC and C-DECRYPTION, with `--mode` on the commands that take ISD keys to pick the secure-channel security level (#256).
- sim-doctor gp release-scp: release the SCP03 secure channel by closing its logical channel (MANAGE CHANNEL close, the same APDU gp channel close sends), dry run unless --yes, no keys taken (#261).
- `gp install -F` / `--no-felix`: refuse to guess the Install Parameters field, so `--params` becomes required (`params-required`, nothing sent); with no flag the default is unchanged (`C900`). GlobalPlatformPro DWIM switch, issue #253.
- `src/scp02.rs`: the SCP02 core, pySim-pinned: 3DES
  session key derivation, the card and host cryptograms under S-ENC, the B.1.2.2 C-MAC
  with its 8-byte ICV, the INITIALIZE UPDATE / EXTERNAL AUTHENTICATE builders, the
  response parser and the MANAGE CHANNEL release. Sends nothing; no `gp` subcommand (#255).
- `gp --key-kdf`: master key diversification with the named KDF templates `kdf3` (SCP03), `emv`, `visa2` and `visa` (3DES), from the KDD the card returns in INITIALIZE UPDATE; known-answer tested against GlobalPlatformPro's vectors (#248).
- `sim-doctor gp move --aid A --from S --to D`: move an object between Security Domains with INSTALL [for extradition] (`80 E6 10 00`, GlobalPlatform Card Spec v2.3.1 11.5.2.3.4), as GlobalPlatformPro `gppro --move/--to` does. One command, not a delete followed by an install: dry run unless `--yes`, offline without keys, both domains named in the plan, refusals with nothing sent, one SCP03 attempt, a registry re-read that must show the object in the destination (#245).
- `sim-doctor keygen`: offline Ki, OPc, ICCID and IMSI for one card from an operator secret, as pySim-prog.py's `-z`/`-j` autogen (#277). Every byte is derived through HKDF-SHA256 (RFC 5869) from a secret read with `-z/--secret-file` or `--secret-env` - never from argv, the clock or a fixed seed; `-j N` makes card N of a batch reproducible, and without it a fresh OS salt is drawn per run and printed. OPc is milenage's AES-CMC over Ki (`aka::opc`); the ICCID is `89` + MCC/MNC + a body filling to 18 + a Luhn check digit, the IMSI is 15 digits. Sends no APDU.
- PACE with the CAN: the PACE application selection, MSE:Set AT, the encrypted nonce, the generic mapping, the ephemeral ECDH and the authentication tokens, the SHA-256 key derivation function and the AES secure messaging channel that follows (wrap, unwrap, SSC). The CAN comes from a file or an environment variable and is never printed; PACE is authentication, not a write, so it is not behind `--yes`. Only secp256r1 of the four TR-03110 curves can be computed on, because this crate adds no P-384 or Brainpool package (#260).
- `sim-doctor euicc store-data <HEX|-> [--yes]`: send one operator-supplied ES10x request to the
  ISD-R as raw STORE DATA, the escape hatch for an ES10 function this tool does not implement.
  Dry run by default (every block CLA/INS/P1/P2/Lc and its payload bytes are printed and
  `card_touched` is false), `--yes` sends on the usual logical channel over the ISD-R, the
  payload is bounded at 8192 bytes from hex or stdin, and the reassembled answer is reported
  verbatim even when this tool cannot decode it. No keys are involved (not SCP03) and it is
  never exposed over MCP (#230).
- `sim-doctor erase`: the command the `erase` module is reachable from, as a top-level verb beside `gp`, `euicc` and `card` (pySim hangs `-e/--erase` on `prog.py`, and neither of this repo's two candidates is an honest host: `install` is the doctor-kit agent-config installer and never opens a card, and `gp install` is a GlobalPlatform LOAD/INSTALL, which this erase is not - it is UPDATE RECORD, INS DC, and no INS E0/E2 appears in it). `--class` and `--records` are required inputs with **no default**, because the reference reads both off the card being programmed (the `_files` table of the class, and the file size in the FCP of EF 8F0C / EF 000C over the record length) and a guess would write records of the wrong length or the wrong number; a run without them is refused, naming the missing fact (`class-unknown`, `records-unknown`). A dry run prints every APDU in reference order with `card_touched: false` and opens no reader at all. `--yes` sends over SCP03 with the crate's one authentication attempt (card cryptogram verified locally, EXTERNAL AUTHENTICATE not sent when it does not verify), keys from `--keys-file`/`--keys-env` only and never printed, EF.ICCID read and compared with `--confirm-iccid` before the first write, and one exchange per step with nothing retried and nothing sent after a failed step. Not available over MCP (#276).
- `erase`: erase before programming (`-e` parity). A dry run by default that names every EF and record that would be overwritten and by which instruction (SELECT by FID `00 A4 00 02 <fid> 00`, then UPDATE RECORD `00 DC <record> 04 <len> <data>`), with `card_touched: false`. Sending needs `--yes` **and** `--confirm-iccid <ICCID>`; the second acknowledgement is the shape `euicc reset` uses with `--confirm-eid`, because this is the one erase that cannot be scoped down to a single object the operator names. Every write is re-read before the next one, a refusal or an interrupt stops the run with nothing sent after it and nothing retried, and the help and the dry run both carry a WARNING that the operation is permanent and an interrupted one leaves the card undefined.
- `scan --csv FILE`: the same results as a CSV log in the SIMTester layout (`# id,Command data,Response data`), with RFC 4180 quoting and a guard on the cells a spreadsheet would read as a formula (#284).
- `sim-doctor profile list` / `profile probe` / `profile match`: the pySim card-profile
  database with the reference file, line and sentence behind every entry; a probe that
  sends pySim's own SELECTs and reports every candidate a card is compatible with
  rather than only a winner; and an unknown `-t` name refused before a reader is opened.
  `profile list` needs no card at all (issue #275).
- `gp receipt`: verify a GlobalPlatform receipt against a receipt generation key
  (issue #247). READ-ONLY and offline: no reader is opened. The signed data is
  `Confirmation Data || AID tail` and the signature is AES-CMAC (GP Card Spec
  v2.3.1 B.2.2) for an AES key, or the Retail MAC of B.1.2.2 with B.1.3 padding
  for a DES key; the AID tail is the one Tables C-11 to C-16 give for the
  operation named by `--kind`. The key comes from `--receipt-key-file` or
  `--receipt-key-env` and never appears in any output. Exit 0 only when the
  receipt verifies: an unverified receipt and a card that returned none are
  reported as different verdicts and neither is a pass.
- `sim-doctor fuzz ota --kic/--kid/--spi1/--spi2 HEX`: pin one header octet of the OTA sweep's Command Packet (KIC, KID, SPI1, SPI2) instead of sweeping it; not key material (#208).
- `card` shell: `set_status` command — SET STATUS (GlobalPlatform Card Spec v2.3.1 11.5.2.3.3, INS F0), gated behind `--yes` (dry run unless --yes), with scope `isd` (ISD state `initialized`/`secured`/`locked`/`terminated`; `terminated` also needs `--confirm-terminate`) or `app`/`apps` (`lock`/`unlock` of an applet or SSD by `--aid`); a state from the wrong scope is refused (#233).
- `scan --tar-uncapped` raises the TAR audit's probe bound to a ceiling of 1 000 000 probes (issue #266, part of it: the full 16 777 216-value space needs a streaming follow-up). A sweep that reaches the ceiling is reported as not exhausted with a WARNING. It sends one ENVELOPE per TAR; refused without `--tar`.
- `sim-doctor euicc get-certs` and `sim-doctor euicc get-eim-configuration-data`: the two SGP.32 (IoT eUICC) ES10b reads, GetCerts and GetEimConfigurationData, one read-only STORE DATA request each. The two certificates are reported by length and hex, the `getCertsError` TLV is reported as the error it is, and `counterValue` / `associationToken` are decoded as the DER INTEGERs they are rather than as the octets that carry them (#229).
- `gp install --cl-activated`, `--cl-notify`, `--cl-notify-remove`, `--cl-family`, `--cl-display-optional`, `--cl-contact` and `--cl-contactless`: the contactless install parameters of GlobalPlatform Amendment C, as one EF Contactless Parameters template beside the C9 application parameters, inside the existing dry-run-by-default, `--yes`, keys-from-file-or-env rules (#239).
- SCP03 session keys for AES-192 and AES-256 key sets: a `gp` key file or `--keys-env` of 48 or 64 hex digits authenticates over an AES-192 or AES-256 key set, verified against the pySim AES-192 and AES-256 SCP03 vectors (#259).
- `update_binary` and `update_record` card-shell commands (UPDATE BINARY/RECORD), gated behind `--yes`, with optional `--read-back` verify (#180).
- `terminate_df`, `terminate_ef` and `terminate_card_usage` card-shell commands (TERMINATE DF/EF/CARD USAGE; destructive, dry run unless --yes) (#184).
- `envelope` and `envelope_sms` card-shell commands: free-form ENVELOPE (INS C2, CLA `card.cla() | 0x80`) and an ENVELOPE SMS-PP DOWNLOAD wrapped in tag D1; gated behind `--yes`, dry run prints the APDU (#201).
- EXT1-EXT8 records decode to additional digits or subaddress and the next-record chain (#175).
- EF.ARR records decode to access rules: operations and the PIN/ADM condition (#172).
- EF.MWIS, EF.MBI, EF.CFIS and EF.SMSR decode to their fields instead of hex (#173).
- EF.PNN records decode to their full and short network names (GSM 7-bit or UCS2) (#174).
- `sim-doctor sms decode` reassembles concatenated SMS parts by reference and reports missing parts (#200).
- `sim-doctor sms decode`: offline SMS TPDU decoder (DELIVER, SUBMIT, STATUS-REPORT; GSM 7-bit, 8-bit, UCS2; UDH and concatenation) (#199).

- `decode`/reads: EF.5G_PROSE_ST, EF.5G_PROSE_DD, EF.5G_PROSE_DC, EF.5G_PROSE_U2NRU, EF.5G_PROSE_RU, EF.5G_PROSE_UIR, EF.5G_PROSE_U2URU, EF.5G_PROSE_EU (5G ProSe config EFs under DF.5G_ProSe), EF.PROSE_MON and EF.PROSE_RADIO_COM (ProSe EFs under DF.ProSe) decode to their fields per 3GPP TS 31.102 clauses 4.4.8 (ProSe) / 4.4.13 (5G ProSe) (#176).
- `sim-doctor ota-expanded`: offline OTA expanded remote application data format (TS 102 226 5.2): `encode` builds a Command Scripting template (definite tag `AA`, or indefinite `AE 80 ... 00 00`) around one or more C-APDUs adding no Le; `decode` reads a Response Scripting template of either coding, naming every R-APDU, the Bad format, Immediate Action and Script Chaining TLVs, and reporting the `62F1` truncation rule; `por` reads a Proof-of-Response Response Packet (TS 102 225 table 5, TS 31.115) with or without the SMS `02 71 00` user data header, and decodes the compact or expanded Remote Application structure inside it. Nothing is deciphered and no CC/RC is verified: the command takes no key (#205).
- `sim-doctor ota-crypto`: offline DES/3DES/AES-CBC encrypt and decrypt, cryptographic checksum sign and check (CBC-MAC, AES-CMAC), as pySim's OTA layer uses (#204).
- `decode`/reads: EF.LI, EF.RPLMNAcT, EF.VGCSCA and EF.VBSCA decode as a `TransRecEF` — a transparent EF split into fixed 2-octet records, each record decoded on its own with a short trailing remainder shown raw, matching pySim's `filesystem.py:1259` (`#178`).
- BIP channel handler: ENVELOPE commands per ETSI TS 102 223 — `envelope` (free-form ENVELOPE), `envelope_sms` (SMS-PP-DOWNLOAD D1 wrap), `bip_data_available` (D6 event download with Channel status + data length), and `bip_local_info` (PROVIDE LOCAL INFORMATION response as TERMINAL RESPONSE). All card-writing commands are dry runs unless `--yes` (#203).
- `decode`/reads: EF.SST decoded with two bits per service (allocated, activated) and EF.IST services named, from pySim's tables (#171).
- `card` shell: `decode_hex`, as in pySim-shell: decode hex with the selected file's decoder, offline (#169).
- `card` shell: `cardinfo` (reader, ATR, profile, class byte, ICCID, channels), as in pySim-shell (#161).
- `card` shell: `dir` (`--fids`, `--names`, `--apps`, `--all`) and `desc`, as in pySim-shell; both work from the shell's state and send nothing (#158, #159).
- `card` shell: `tree` (with `--json`, `--depth`, `--max`): print the current directory's file tree recursively from the file catalog, indented two spaces per level (#159).
- `card` shell: `history` command prints the command history, numbered from 1; `--json` returns the array as JSON.
- `card` shell: `run_script FILE` executes commands from a file, one per line; `#` starts a comment; capped at 1 MiB; write commands are dry runs unless `--yes` is provided.
- `desc`: reports the selected file's access conditions, decoded from the security attributes the SELECT response already carried (8C compact, AB expanded, 8B referenced to EF.ARR), as readable text like `READ: PIN1, UPDATE: ADM1` and as a JSON `access_conditions` field, as in pySim (#170).
- `card` shell: `get_identity` (TS 31.102 4.2.2): returns the SUCI/identity from the selected application. This read-only command is not gated by `--yes` and prints the APDU wire bytes (#179).
- `card` shell: `bulk_script FILE [--halt_on_error] [--tries N] [--pre_card_action CMD] [--on_stop_action CMD]` runs a script file against several cards in sequence by re-equipping for each card, as in pySim-shell (#163).
- `card`: a pySim-shell style shell over the card (#155). It keeps the equipped card, the logical channel and the
  selected file between commands; interactive, `-c "a; b"`, `--script FILE` and `--json` (one record per command).
  `equip`, `status`, `open_channel`, `close_channel`, `channel`, `quit`, `history`, `run_script`. Reads are sent; commands that change the card are
  dry runs unless `--yes`. The file commands arrive in the issues that follow.
- `card`: `apdu [--raw] [--expect-sw SW] [--expect-response-regex RE] [--yes] APDU` (#156): one raw APDU with GET RESPONSE
  followed, the channel applied to the class byte unless `--raw`, pySim's `x` wildcards in `--expect-sw`, and a dry run
  for any instruction that is not a read unless `--yes`.
- `card`: `select NAME|FID|AID|PATH`, `select_path` and `select_adf` (#157): select by FID, standard file name, AID,
  absolute or relative path, or application name (`ADF.USIM` through EF.DIR). The selection is kept per logical channel,
  the FCP is decoded in the reply, and `--profile sim` selects by FID with GSM 11.11 responses.
- `card`: `read_binary [--offset] [--length]`, `read_record N` and `read_records [--from] [--to]` (#167): generic reads of the
  selected EF with offset, length and record number, chunked past 256 bytes, one `6C xx` correction, empty records marked.
- `scan --scan-file-break` / `-b` (alias `--sfb`): stop probing a directory once the DFs and EFs found under it are the number
  its 2G-format SELECT response reports (TS 51.011 clause 9.2.1, bytes 15 and 16). A 2G-format directory response is now walked
  as a directory; every other response is read as before (#269).
- `card`: `read_binary_decoded`, `read_record_decoded`, `read_records_decoded`, `decode NAME HEX`, `files` (#168): a table of 212
  standard EF names (284 entries by directory: MF, DF.GSM, DF.TELECOM + sub-DFs, ADF.USIM, ADF.ISIM, DF.5GS, DF.WLAN, DF.HNB, DF.ProSe,
  DF.SNPN, ...) with identifier, structure and description, cross-checked against pySim; `select` takes the names; reads are decoded by the
  file's standard name and place (27 field decoders, BER-TLV files as a tag tree; the remaining files show their hex, labelled so).
- `card`: `verify_chv [--pin-nr N | --universal | --adm-nr N | --key-ref HEX]` and the PIN source `--chv-file` / `--chv-env` (#188).
  PIN1, PIN2, universal PIN and ADM keys; the value comes from the source (optionally per ICCID), never an argument or output.
  Dry run unless `--yes`; the tries are asked first (free), the last try needs `--allow-last-attempt`, one attempt per command.
- `card`: `unblock_chv [--pin-nr N | --universal]` (#189): UNBLOCK PIN with the PUK and the new PIN from the PIN source, same safety
  pattern as `verify_chv` (dry run unless `--yes`, values masked, last PUK try needs `--allow-last-attempt`, one attempt).
- `card`: `run_gsm_algorithm [--rand HEX] [--repeat N]` (#190): the GSM authentication probe, SRES and Kc, USIM GSM context or
  RUN GSM ALGORITHM (`--profile sim`), determinism check with `--repeat`; a dry run unless `--yes`.
- `card`: `change_chv [--pin-nr N | --universal | --adm-nr N | --key-ref HEX] [--allow-last-attempt] [--yes]` (#192): CHANGE CHV
  (INS 0x24, ISO/IEC 7816-4 7.5.3, 3GPP TS 31.102 7.1.3.1). The old and new PINs come from the PIN source (`pinN` and `new-pinN`
  / `upuk` and `new-universal`), are masked in the dry run, the try counter is asked first, and the old value is dropped from the
  session's verified set afterwards. A wrong value costs a try and can block the key.
- `card`: `enable_chv [--pin-nr N | --universal | --adm-nr N | --key-ref HEX] [--allow-last-attempt] [--yes]` (#193): ENABLE CHV
  (INS 0x28, ISO/IEC 7816-4 7.5.5, 3GPP TS 31.102 7.1.3.3). A case 1 command with no data field, dry run unless `--yes`.
- `card`: `disable_chv [--pin-nr N | --universal | --adm-nr N | --key-ref HEX] [--allow-last-attempt] [--yes]` (#193): DISABLE CHV
  (INS 0x26, ISO/IEC 7816-4 7.5.5, 3GPP TS 31.102 7.1.3.2). A case 1 command with no data field, dry run unless `--yes`.
- `card`: the `change_chv`, `enable_chv` and `disable_chv` shell commands join `verify_chv` and `unblock_chv` in warning that a
  wrong PIN or PUK costs a try and can block the key permanently (#192, #193).
- `card`: `prescan_pin [--mode verify|disable|skip]` (#196): the pre-scan PIN step, as SIMTester's `-vp`, `-dp` and `-sp`. `verify` is `verify_chv` and `disable` is `disable_chv` (same key selectors, dry run unless `--yes`, tries asked first, one attempt); `skip` sends nothing. Scan itself stays read-only.
- `card`: `authenticate [--rand] [--autn | --sqn N [--amf]] [--resync]` (#191): the UMTS AUTHENTICATE probe in the 3G context.
  Success (RES, CK, IK checked against the host's Milenage when `ki`/`opc` are given), synchronisation failure (AUTS opened:
  SQNms, MAC-S) and MAC failure are told apart; `--resync` sends once more with SQNms + 1. `aka` gains `autn` and `open_auts`.
- `card` shell: `service activate|deactivate|allocate|deallocate|check [--table UST|EST|SST|IST|PROSE] [N] [--yes]` (#183):
  write (UPDATE BINARY) the selected EF.UST/EF.EST/EF.IST/EF.5G_PROSE_ST (1-bit set/clear) or EF.SST (2-bit
  allocated/activated), reading the table first and growing it past the end when needed. `check` reads and
  decodes without writing. A dry run unless `--yes`.
- `card`: `set_data TAG HEX`, `delete_data TAG` and `delete_all` (#186): BER-TLV write/delete on the selected EF via SET DATA (0xDB) and
   RETRIEVE DATA (0xCB) per ETSI TS 102 221 11.3.2/11.3.1. `set_data` writes or replaces a single tag; `delete_data` removes one;
   `delete_all` enumerates tags with the 0x5C tag list then deletes each. All three are gated behind `--yes` and show a dry run
   with a WARNING first, and are rejected with `6A 80` when no BER-TLV EF is selected.
- `cat decode`: an offline Card Application Toolkit decoder (#198). Proactive commands, envelopes, terminal responses and
  bare comprehension TLVs; 44 command types, 14 envelope tags and 90 information elements named from pySim's tables, command
  qualifiers spelled out, about 40 elements decoded to fields, the rest kept as named hex. `--json` prints a `cat` envelope.
- `card` shell: `activate_file FILE_ID [--yes]` and `deactivate_file FILE_ID [--yes]` (#185): ACTIVATE FILE (`00 44`) and
  DEACTIVATE FILE (`00 04`) by two-octet file identifier, with the file ID carried in the data field (P1 = 0x00, P2 = 0x00)
  per TS 31.101 clause 11.1; both are gated behind `--yes` like the other card-changing commands, a dry run prints the exact
  APDU, and the change to the file's lifecycle state persists until reversed.
- `card` shell: `retrieve_tags` and `retrieve_data TAG` (#177): read-only BER-TLV reads of the selected EF via RETRIEVE DATA
  (0xCB) per ETSI TS 102 221 11.3.1. `retrieve_tags` lists the tag octets present (the 0x5C tag list); `retrieve_data`
  returns the value of one tag. Both are read-only, so the command is always sent and takes no `--yes`; a tag the card does
  not hold is reported as a refusal (`6A 82`), and the selected file must be an EF first.

- `gp aram add|delete-all|lock|config`: the ARA-M write side (issue #237). STORE DATA [Command-Store-REF-AR-DO] `80 E2 90 00` adds or replaces one rule, [Command-Delete] `F1 00` removes every rule, the single byte `A1` locks the applet's STORE DATA and GET DATA [Config] `80 CA DF 21` is the configuration handshake, all over an SCP03 channel with the same dry-run/`--yes`/keys-from-file-or-env/one-authentication-attempt pattern as `gp delete`, a rule list read over the secure channel before and after, and `verify-failed` when the card does not show the change. `delete-all` needs `--confirm-delete-all DELETE-ALL` on top of `--yes`; not exposed over MCP.

## [0.4.0]

sim-doctor now runs on [doctor-kit](https://crates.io/crates/doctor-kit) 0.2.2, the CLI skeleton shared by the doctor
tools. **Machine output is unchanged**: the `--json` envelopes (compact, sorted keys), the finding fingerprints, the SARIF
files (card-path locations), the exit codes 0/1/2/3/129/130 with `--fail-on` defaulting to `critical`, the `rules`, `why`,
`trace`, `ts48`, `gp`, `euicc`, `fuzz`, `modules`, `completions` and `ci` commands, the install file bodies, the MCP tool
names, schemas and wire text, and the `--help` command names are byte-identical to 0.3.0. They are pinned by
`tests/golden.rs` and the new `tests/golden_scan.rs`, which runs the real binary over a recorded card session (the goldens
were generated on the 0.3.0 code). What the kit does differently by default is kept as it was through its hooks: the
baseline file rules and refusals, the multiset `new` / `unchanged` labels, the JSON style, the MCP error texts, the
`install` file merge. **Human output is new**: `scan` prints a doctor-kit face by default (see Changed).

### Fixed (contract)

- `--sarif` and `--baseline` naming one file are refused (exit 2, nothing written) however the two paths are spelled
  (`x.json` and `sub/../x.json` are one file); before, only identical spellings were. The doctor/1 exit code 2 for errors
  and the MCP `ping` / `-32600` answers were already sim-doctor's; they are now also guaranteed by the kit's loop.

### Added

- `shell` and `explore`: an interactive shell and a full-screen explorer over the card (doctor-kit). The session reads the card
  once and shows the findings by category and, under `card`, the file system: master file, directories and files,
  one directory at a time, with what the walk read of an EF (`ls`, `cd`, `info`, `cat`, `decode`, `find`; `shell -c "..."`,
  `shell --json` for agents). They take `--reader`, `--dialect`, the walk bounds and `--tar`, read only, and are on by default;
  `cargo build --no-default-features` leaves them (and `reedline`) out.
- `scan --face rich|plain|compact|legacy`, `--theme mono|clinical|contrast`, `--color auto|always|never` and `--headless`.
  `--tui` is the findings view it always was (the kit's explorer does not show the walk's coverage, truncation and TAR-stop
  notes, so it did not replace it).

### Security

- The test seams `SIM_DOCTOR_TEST_REPLAY` (answer `scan` from a recorded log instead of a reader),
  `SIM_DOCTOR_TEST_SIGNAL_HOLD_MS` and `SIM_DOCTOR_TEST_WEDGE` (park a run at its first interrupt checkpoint, which
  existed before this release) are compiled only with the `test-seams` cargo feature. `cargo test` enables it through a
  dev-dependency on the package; a release build never has it, so an environment variable cannot make a shipped
  `sim-doctor` read a card from a file or hang. `tests/release_seams.rs` (run in CI with `--ignored`) builds the release
  binary and checks both its bytes and its behaviour.

### Changed

- **Human output of `scan` uses doctor-kit faces by default** (rich on a terminal, plain when piped), with the notes the full
  report carried as banners shown first: an `INCOMPLETE` banner when the score has coverage gaps, `TRUNCATED` with the bounds hit
  and why the walk stopped, a TAR audit that did not finish or has a blind spot, the score warning, the standing candidate-set
  warning, repeated identifiers, forbidden / refused files and per-file walk notes (details stay in `--json`). `--face legacy` prints the
  previous full report (files, TAR evidence); `--score` only matters there. The README capture is the new output.
  `--json`, `--sarif`, `--baseline` and the exit codes are unchanged.
- A closed stdout (`scan --json | head`) and an unwritable `--sarif` keep their exit code 2 and the printed `exit_code: 2`; the
  stderr sentence is now the kit's (`error: cannot write to stdout: ...`, `error: <path>: ...`). The MCP server answers a request
  with neither `id` nor a string `method` with `-32600` and a null `id`, as before.
- The report pipeline of `scan` (baseline gate and exit code, the one write of the report), the MCP server loop, the
  `install` file writer and the SIGINT / SIGTERM flag are doctor-kit's. Known edge, not in machine output:
  `install` refuses to write through a symlink and writes by temp file and rename (`ci install` already refused symlinks).
  The MCP child runner is the kit's `exec_self_with` with sim-doctor's own error texts.
- Library API: `sim_doctor::signals` is a shim over `doctor_kit::interrupt` (`install`, `interrupted` deprecated);
  `skill`, `fix` and `mcp` keep their names, with `skill::Agent`, `fix::{Agent, AGENTS}` and `mcp::{handle, process_line, serve}`
  as deprecated re-exports of the kit's (same names, the kit's signatures). Removed: `skill::{Target, targets, upsert_block,
  install}` and `fix::launch_argv`'s agent type (now the kit's `AgentSpec`, field `bypass`). `mcp::tools` and `mcp::run_self` are new;
  `scan::node_json` is now public. `modules --json` lists the same modules.
- `doctor-kit` 0.2.2 is a new dependency (with `toml`); `reedline` comes with the default `shell` feature.


### Changed

- Point URLs at the doctor-labs org (the repository moved from Vaibhav91one).

### Added

- `gp put-key` and `gp install --dap-key-file|--dap-key-env` (#115, completing #133 and #19): PUT KEY and DAP over the SCP03 channel. `gp put-key` adds or replaces the ISD's SCP03 AES-128 key set (ENC, MAC, DEK) with PUT KEY (GP Card Spec v2.3.1 11.8; every key AES-encrypted under the current static DEK, Amendment D 6.2.8; KCV per B.6), addressed with `--new-key-version`, `--replace-key-version` and `--key-id`. **It can permanently lock the card's administrative access**, and every output says so. The new keys come only from `--new-keys-file`/`--new-keys-env`, are never printed (the plan and `--trace` withhold the encrypted PUT KEY data as well; each new key's KCV is shown) and a stated KCV that does not match refuses the run before any card is touched. Dry run unless `--yes` (which needs the current keys including the DEK); same one-attempt SCP03 interlock; **refuses to add, replace or overwrite the key version the session authenticated with unless `--replace-current-keyset` is given** (`refusing-current-keyset`), and refuses a replaced version the card lacks or an added one it holds; after `90 00` the card's returned key version and KCVs must equal the computed ones and its key information must list the new keys (`card-kcv-mismatch`, `verify-failed`). DAP: `gp install` signs the Load File Data Block Hash (SHA-256/384/512) with a symmetric AES DAP key as AES-CMAC (Card Spec C.2, C.3, B.2.2), sends the hash in INSTALL [for load] and the `E2` DAP block before the load file, and refuses (nothing sent) when the Security Domain is not in the registry or lacks the DAP Verification privilege (`--dap-sd` names it; default the authenticated ISD). Not exposed over MCP. Not done: DES/RSA/ECC DAP keys, SHA-1, tokens, RSA/ECC/DES PUT KEY, 192/256-bit SCP03 key sets. Replay tests with wire vectors produced by pySim's own SCP03 and PUT KEY code; the DAP CMAC checked with python `cryptography` and openssl.
- `gp channel open|close`, `--channel N` on every `gp` command, `gp delete --aid` and `gp install --load` (#133, #19): logical channel management from the CLI and the first GlobalPlatform card writes. MANAGE CHANNEL opens a channel the card chooses and leaves it open; `--channel N` (0 to 19) runs a command, its SELECT and its SCP03 channel on it (class byte per GP Card Spec 11.1.4; the C-MAC covers the class byte as sent). `gp delete` sends DELETE (`80 E4`, `--related` for P2 `80`); `gp install` reads a CAP and sends INSTALL [for load], the LOAD blocks and INSTALL [for install and make selectable], through the ISD's SCP03 channel (C-MAC). **Safety, all enforced:** a dry run unless `--yes` (and `--yes` needs `--keys-file`/`--keys-env`); the dry run prints the target and the exact APDUs and sends no write, fully offline without keys; one authentication attempt with the local cryptogram pre-check, keys from file/env only and never printed; a GET STATUS pre-read that refuses an absent AID, the ISD, an unreadable registry, or an install over an AID already on the card, with nothing sent; each command sent once in order, stopping at the first refusal, with every GP status word reported under its own `data.error.kind`; a registry re-read that must confirm the result (`verify-failed`); Card Lock and Card Terminate privileges refused; not exposed over MCP. DAP signing is not part of this: it needs the Security Domain's DAP key, outside the SCP03 set, and belongs with PUT KEY (#115). Replay tests with wire vectors from an independent SCP03 model.
- `sim-doctor fuzz mutate` (#134): an allowlist-only APDU mutation fuzzer. It generates boundary-length, truncated, over-long, invalid-P1/P2 and unassigned-INS variations of SELECT, READ BINARY, READ RECORD, STATUS, GET DATA and GET RESPONSE; the INS byte comes from the command kind at construction, so nothing else can be produced, and a send guard with a documented denylist (PIN commands, UPDATE/APPEND/STORE DATA, AUTHENTICATE, PUT KEY, DELETE, INSTALL, MANAGE CHANNEL, ENVELOPE, ...) re-checks every APDU before transmit. `--max-cases` (default 1000, at most 10000), `--timeout`, `--seed` (same seed, same APDUs), `--dry-run` (prints the plan, sends nothing), `--stop-on-first-finding`. Every APDU and SW is in `data.audit.exchanges`; a success answer to an APDU the spec says to reject is a `fuzz/malformed-command-accepted` finding. **This change runs only against `--replay FILE` or the built-in `--mock` card; there is no real-reader path.** A reader run is a follow-up that would sit behind the existing `fuzz` interlock. Issue #134 cites #15 as the deferred fuzzer, but #15 is the TUI issue.
- `sim-doctor euicc notifications dump [--seq N] [-o FILE]` (ES10b RetrieveNotificationsList, lpac `notification dump`): reads the full signed pending notifications, read-only (nothing is removed), into a re-loadable JSON document (`sim-doctor-notification-dump/1`: sequence number, operation, address, ICCID, arm, transaction id and the signed bytes as hex). And `euicc notifications replay --from FILE [--yes]` (`sim_doctor::notif`): sends each dumped notification to the address inside its signed bytes as ES9+ HandleNotification over the #20 HTTPS transport. Replay reaches the network, so it is a dry run unless `--yes`, needs no card, never removes the notification from the eUICC and is not on MCP. New ES10 codecs `retrieve_notifications_request`, `decode_retrieve_notifications`, `decode_pending_notification`. Send path tested against a local TLS server; a live operator round trip is on #92 / #118 (#119).
- ES9+ HTTPS transport (`sim_doctor::es9_https::HttpsTransport`, an `Es9Transport`) and an HTTP backend selector (`sim_doctor::backend`: `SIM_DOCTOR_HTTP` = `https`|`stdio`, `SIM_DOCTOR_CA_BUNDLE`). New dependency `ureq` 3 (rustls, blocking, no async runtime or C TLS library); dev-dependencies `rcgen` and `rustls` for a local test server. Certificate verification is always on with no insecure option (lpac's curl backend verifies nothing). The default trust anchor is the bundled GSMA RSP2 Root CI1 (`certs/gsma-rsp2-root-ci1.pem`), as SGP.22 §4.5.2.2 requires and as a live SM-DP+ chain confirms; `SIM_DOCTOR_CA_BUNDLE=<pem>` replaces it and `webpki` selects the Mozilla roots explicitly. Redirects are never followed; 30 s timeout; 16 MiB response cap. No shipped command calls the transport yet, so the variables take effect once a command uses ES9+ (#118); there is no APDU selector (#20).
- `sim-doctor trace` reads pcap and pcapng captures of GSMTAP SIM APDUs (UDP 4729, as produced by SIMtrace2 and pySim-trace), detected by magic number. A small hand-written reader (classic pcap, pcapng EPB/SPB, Ethernet/loopback/raw/cooked, IPv4, UDP) instead of a pcap crate; the APDU sub-type is split into command and response as pySim does and fed to the existing decoder. Truncated or malformed files give an error, never a panic; TPDU sub-types are skipped (#109).
- `sim-doctor gp ara`: selects the ARA-M (AID `A00000015141434C00`) and reads every access rule with GET DATA [all] (`80 CA FF 40`), decoding each REF-AR-DO: applet AID (or all / default selected), device app hash (or any), APDU rule (always / never / header+mask filters), NFC rule and permission mask. A rule naming all applets and any device app with APDU access always sets `grants_all_apps_all_access`. A card that wants a secure channel (`6982`/`6985`) is reported as `requires_authentication`, not an error. No scan rule yet: `scan` does not select the ARA-M (#111).
- `sim-doctor gp status`: GET STATUS (`80 F2`, TLV format) for the ISD, applications, executable load files and load files with modules, with lifecycle and privilege names, following `63 10` up to 16 pages per scope; a scope that needs authentication says so. Also decodes Card Recognition Data (GET DATA tag 66) and lists any SCP01/SCP02 it offers as `weak_scp`.
- `sim-doctor gp status --keys-file PATH | --keys-env VAR [--key-version HEX]` reads the GlobalPlatform registry over an SCP03 secure channel (AES-128, C-MAC) opened with user-supplied ISD keys, for cards that refuse GET STATUS unauthenticated. It reuses `src/scp03.rs`. **Lockout safety:** exactly one authentication attempt per run, never retried; the card cryptogram from INITIALIZE UPDATE is checked locally first and a mismatch stops with "keys do not match this card" without sending EXTERNAL AUTHENTICATE. **Keys come from a file or an environment variable, never the command line, and are never printed** (output, `--trace`, errors); this is the one exception to the full-visibility rule, documented in AGENTS.md. A key may be written `KEY/KCV`, and a wrong KCV stops the run before a reader is opened. `data.secure_channel` carries the key version, the KCV of each supplied key and the card's key-information entry for that version (the card exposes no KCV in GET DATA). `data.registry_findings` adds `gp/weak-secure-channel`, `gp/isd-lifecycle`, `gp/app-locked` and `gp/app-excess-privilege` (entries in the lpac `gp` envelope, not doctor/1 findings). Replay tests use pySim's SCP03 vectors (#112).
- `sim-doctor gp select --aid HEX`: SELECT any application by AID and report the status word, FCI and DF name (#19). Sensitive-data encryption belongs with PUT KEY (#115).
- MCP: `gp_info`, `gp_ara` and `gp_status` tools (nine tools in total). `gp_status` takes no keys.
- Security rules for issue #40 and #110, all decided from data a read-only scan collects:
  `filesystem/config-ef-updatable-always` (high/medium: EF.UST, EST, AD, ACC, SPN, OPLMNwAcT, SUCI_Calc_Info or Routing_Indicator with UPDATE ALWays), `filesystem/ef-updatable-always` (medium, one finding per scan: any other EF with UPDATE ALWays), `privacy/suci-null-scheme` (high: EF.SUCI_Calc_Info puts the null scheme first or has no scheme with a provisioned home network public key, so the IMSI is sent in the clear on 5G) and `privacy/suci-not-provisioned` (medium: EF.UST marks 5GS service 122 or 123 but not 124). `filesystem/sensitive-ef-always` now also covers EF.5GS3GPPLOCI, 5GSN3GPPLOCI, 5GS3GPPNSC, 5GSN3GPPNSC and 5GAUTHKEYS under DF.5GS, and `identity/readable-without-pin` also covers EF.ADN and EF.FDN.
- `scan` decodes EF.SUCI_Calc_Info (`4F07`) and EF.Routing_Indicator (`4F0A`) under DF.5GS `5FC0` into `ef_contents`; the transparent-EF read cap rose from 64 to 255 octets so a key list fits.
- `rules explain` (text and `--json`) now carries each rule's `cwe` and specification `reference`. `docs/rule_docs/<namespace>/<name>.json` holds `{id, severity, description, remediation, cwe, reference}` for every rule; it is generated from the rule declarations and `tests/rule_docs.rs` fails when a file is missing, stale or orphaned (`UPDATE_RULE_DOCS=1 cargo test --test rule_docs` regenerates).
- A test pins the `--score` acceptance: ten medium-or-worse violations score under 30 with the unchanged `sim/1` formula, and the whole pipeline scores a badly misconfigured generated card under 30. Not done, and why: COMP128 v1/v2 detection and a Milenage configuration check need AUTHENTICATE probing or key material, neither of which a read-only scan has (#105).

- `sim-doctor euicc info|profiles|notifications`: read-only ES10 queries to the ISD-R on a logical channel (lpac `chip info`, `profile list`, `notification list`): EID, EUICCInfo1/2, profile list, notification metadata. lpac envelope under `--json`, sanitized table otherwise; a non-eUICC card is a clean `not-an-euicc` error, exit 1. Never changes a profile or notification. New ES10 codecs `get_eid_request`/`decode_get_eid` and `list_notification_request`/`decode_list_notification` (#116, #132).
- MCP: `euicc_info`, `euicc_profiles` and `euicc_notifications` tools (six tools in total).
- `euicc info` also shows the configured default SM-DP+ and root SM-DS addresses (ES10a GetEuiccConfiguredAddresses, `configured_addresses`), and every `euicc` subcommand takes `--max-segment BYTES` (1 to 255, default 120 as in lpac) to size STORE DATA blocks (#116). Not done: the "finding angle for #40" (untrusted CI keys, weak capabilities) is left for a later PR.
- `sim-doctor euicc nickname ICCID NAME` (ES10c SetNickname, lpac `profile nickname`), the first write of #117. A dry run by default: it reads the EID and profile list, prints EID, ICCID, current and new nickname, and sends nothing. `--yes` sends SetNickname, re-reads the profile list and fails with `verify-failed` unless the nickname changed. The ICCID and the name (at most 64 bytes of UTF-8, SGP.22 5.7.21) are validated before a reader is opened. Not exposed over MCP. New ES10 codecs `get_euicc_configured_addresses_request`/`decode_configured_addresses`, `set_nickname_request`/`decode_set_nickname`, `blocks_sized`/`store_data_sized` (#117).
- `sim-doctor euicc enable|disable ICCID|AID` (ES10c EnableProfile / DisableProfile with REFRESH, lpac `profile enable` / `profile disable`), the second write of #117, with the nickname safeguards: a dry run by default that states the consequence (enabling switches the active profile and the device loses its connection until it re-attaches; disabling the only enabled profile leaves none active), `--yes` to send, a verifying re-read (`verify-failed`), identifier validation before a reader is opened, and no MCP exposure. A pre-flight read refuses an unknown profile, enabling an enabled profile and disabling a disabled one with nothing sent. Every SGP.22 result code has its own error kind. New ES10 codecs `disable_profile_request`/`decode_disable_profile` (#117).
- `sim-doctor euicc delete ICCID|AID`, `euicc reset` and `euicc notifications remove SEQ` (ES10c DeleteProfile and eUICCMemoryReset, ES10b RemoveNotificationFromList; lpac `profile delete`, `chip purge`, `notification remove`), the third and last write PR of #117, with the same safeguards: dry run by default, `--yes` to send, a verifying re-read (`verify-failed`), validation before a reader is opened, one error kind per result code, no MCP exposure. `delete` refuses an enabled profile (`profile-enabled`) and says the erase is permanent. `reset` opts in per `--operational` / `--test` / `--smdp-address` (none by default), needs both `--yes` and `--confirm-eid` matching the card, and its dry run lists every profile it would erase. `notifications remove` pre-reads the list (`notification-not-found`) and says a removed notification is never sent to the operator. New ES10 codecs `memory_reset_request`/`decode_memory_reset`, `remove_notification_request`/`decode_remove_notification` (#117).
- `scan` decodes more EFs, read-only (SELECT, READ BINARY, READ RECORD) and shown in full in `ef_contents`: EF.FPLMN, EF.OPLMNwAcT, EF.HPLMNwAcT, EF.ACC, EF.LOCI, EF.PSLOCI, EF.EPSLOCI, EF.ADN (`6F3A`, and `4F3A` in a phonebook), EF.FDN, and the ISIM EF.IMPI, EF.IMPU and EF.P-CSCF (told apart from the USIM's EF.KeysPS by the ISIM AID) (#108).
- EF.MANUAREA (`3F00/0002`, a vendor-specific file with no standard identifier, as SIMTester reads it) is probed with one SELECT and READ BINARY and shown as hex when the card has it; a card without it is not an error (#102).
- Rule `exposure/risky-service-available` (low): EF.UST marks service 28 (SMS-PP data download) or 32 (RUN AT COMMAND) available, one finding per service (#108). EF.EST is decoded but not judged.

## [0.3.0] - 2026-10-09

### Changed (BREAKING)

`sim-doctor scan` adopts the cross-tool **doctor/1** output contract (docs/doctor-contract.md), shared with luasec, pcap-doctor, android-doctor and ble-doctor so one parser reads all five (Refs Vaibhav91one/android-doctor#161). No legacy flag; the old scan JSON is gone.

- `scan --json` prints `{schema:"doctor/1", tool, version, exit_code, score, findings, data}` instead of the lpac envelope `{type, payload:{code,message,data}}`. Findings are top-level with `id`, `fingerprint`, `severity`, `category`, `message`, `location:{kind,ref}`, `evidence[]`, `remedy`. `data.findings` became top-level `findings` (old shape kept as `data.findings_detail.findings`); `data.score` became top-level `score` `{value, label, model:"sim/1", coverage_gaps}` (old block: `data.score_detail`, now always present). The rest of `data` is unchanged. A scan that cannot run is also a doctor/1 envelope (exit 2, `findings: []`, `data.error`).
- Exit codes for `scan`: `0` no finding at or above `--fail-on`, `1` at least one, `2` usage error or the scan could not run (was 129 and 1), `3` a new finding against `--baseline`, `130` interrupted. A scan with findings used to exit 0.
- New `--fail-on <level>`, default `critical` (the closest value to the old "findings never fail the scan").
- `--baseline <FILE>` now READS a previous `scan --json` envelope and gates on new findings (exit 3), matching by fingerprint. It no longer writes a file: save a baseline with `sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > baseline.json`. `--diff` is removed. A baseline loader reads only `schema`, `data.run` and each finding's `id`, `fingerprint` and `severity`, so it holds no card data; a full envelope and the reduced one the Action writes (output `baseline`, `scripts/reduce-baseline.jq`) load identically. Do not commit a full `scan --json` envelope: it carries the ATR and EF contents.
- SARIF: the fingerprint key is `doctorFinding/v1` (was `simDoctorFinding/v1`) and the run carries `properties.score`.
- MCP: the `scan` tool now exposes `baseline`, `fail-on` and `sarif`; exit 3 is a normal result.
- GitHub Action: reads the doctor/1 envelope, fails on CLI exit 3, new input `fail-on`; the baseline file is a saved envelope.
- Card-derived text in the scan table, the TUI, `why` and the `fix` prompt goes through one sanitiser that strips control characters (ESC), bidi controls, zero-width characters and line/paragraph separators.
- `why` and `fix` read doctor/1 envelopes saved from `scan --json`.

### Fixed

- A baseline taken with `--severity` is read back with that threshold (it was written under `severity_threshold` and read under `severity`).
- `scan` works on real cards: a GET RESPONSE rejected at the GSM class (`6E 00`/`6D 00`) re-sends a read-only command once and collects at the command's own class; swSIM is unaffected (#64).
- The FCP tag table for real cards was wrong. The new default `--dialect ts-102-221` (ETSI TS 102 221: 80 size, 82 descriptor, 83 FID, 84 DF name) replaces it; `iec-7816-4-table-42` is a deprecated alias. A baseline taken under another dialect is refused by `--diff` (#69).
- An empty reader is reported as `no card in reader` (error kind `no-card`) instead of an unusable reader (#64).
- Tests no longer open an attached reader (#72).
- `scan` walks the USIM/ISIM applications by AID from EF.DIR (path form `3F00/ADF:<AID>/…`). Before this, real cards only showed the legacy DF.GSM/DF.TELECOM paths (#83).
- A real card no longer truncates the walk. `--max-nodes` now counts only files the card selected, as its help already said; absent probes still cost an exchange and are bounded by `--max-directories` × `--max-children`. Inside an application, the reserved identifiers 7FF0–7FFF are not walked again (#90).
- A card command stuck in a PC/SC exchange can be interrupted: after SIGINT/SIGTERM a watchdog ends the run about 3 s later with exit 130 and releases the reader (#88).
- The TAR probe and the fuzz OTA sweep send ENVELOPE as one APDU, so `--tar` works through real readers. Before, the header/data split was rejected by PC/SC and nothing was probed. The split is kept for the swicc-pcsc software reader only (#96).
- The no-TAR-evidence score warning no longer claims a value of 100 (#84).
- A tied or unusable TAR calibration is reported as a blind spot with no MSL-0 verdict, instead of classing every TAR as accepted and raising a false critical finding (#101).

### Added

- SCP03 core (key derivation, cryptograms, C-MAC, INITIALIZE UPDATE / EXTERNAL AUTHENTICATE builders), Milenage wrapper and the `auth/scp03-missing-mac` rule; vector-tested, never sent to a card. `rules_run` is now 2, so older baselines are refused by `--diff` (#22).
- RFC 6979 deterministic ECDSA P-256/SHA-256 signing, 64-byte r||s (#21).
- A generated-card corpus with a per-rule precision/recall gate (#47).
- Rules `auth/pin1-disabled`, `filesystem/sensitive-ef-always` and `identity/readable-without-pin`, decoded from compact/expanded/EF.ARR-referenced access rules (#40, partial).
- `sim-doctor gp info [--trace]`: read-only GlobalPlatform pass — ISD select, GET DATA for CPLC / card data / key information / sequence+confirmation counters / extended card resources, Card Recognition Data decode, AES+3DES key check values. Sends only SELECT, GET RESPONSE and GET DATA. Plus offline builders (CAP→load file, INSTALL/LOAD, MANAGE CHANNEL) for later use (#19, partial).
- `sim-doctor ts48 compare`: diffs a card's file system against the public GSMA TS.48 v7.0 test profile, using a derived file list with no keys. It takes the same walk-limit flags as `scan`. Matching TS.48 is not GCF/PTCRB conformance (#25).
- `sim-doctor fuzz apdu|ota`: CLA/INS discovery and a TAR × keyset × SPI sweep, bounded. It refuses to run without `--i-understand-this-can-brick-the-card`, and on any reader other than the swicc-pcsc software card it also needs `--allow-real-hardware` (#16).
- `sim-doctor scan` decodes the security-relevant EFs (ICCID, IMSI, MSISDN, EF.DIR, EF.AD, EF.SPN, service tables UST/EST) into `ef_contents`, and reads key files (EF.Keys/KeysPS) where the card allows; read-only (SELECT/READ only) (#108, #102).
- `sim-doctor trace`: an offline APDU-trace decoder (hex or `gp info --json --trace` input) that names ISO/UICC/GlobalPlatform commands and tracks the selected file; pcap input deferred (#109).
- A record/replay transport for hardware-free regression tests: `SIM_DOCTOR_RECORD` captures a session (0600, raw), and a recorded log replays through the walk in CI (#120).
- An SGP.26 test-PKI check: a committed manifest (URL + pinned SHA-256) and an ignored test that fetches the GSMA certs at run time and validates signing against the chain; no certs are committed (#73).
- Library modules, vector-tested and sending nothing on their own: SCP03t (#23), the SGP.22 Bound Profile Package builder (#17), ES10x STORE DATA and ES10b/ES10c codecs (#18), and the ES9+ message layer behind a transport trait (#20, partial; no HTTPS backend yet).
- Prebuilt `aarch64-unknown-linux-gnu` binary (Raspberry Pi, glibc 2.39 or later); CI uploads it as an artifact on every run (#91).

### Changed

- SGP.22 and TS.48 are public; the recorded GSMA member-access blockers were wrong and are resolved; TS.48 work is re-scoped to comparing a card with the public test profile (#26, #25).
- Full-visibility output: as an authorized on-card security tool, sim-doctor shows card values in full (IMSI, ICCID, MSISDN, file and key-file contents) with no runtime redaction. Real card data is still never committed to the repo; test fixtures are synthetic (#128).

## [0.2.0] - 2026-10-07

### Fixed

- `fix` hardening: the prompt sanitiser strips a wider invisible-character table (soft hyphen, variation selectors, tag characters, private use, fillers; unassigned code points outside the table are not covered), at most 20 findings are collected from a saved scan, the agent is spawned directly (not-installed is detected from the spawn error), and a signal-killed agent exits 128+signal; it strips zero-width joiners (U+200C/U+200D), the combining grapheme joiner and variation selectors from agent-bound text, so emoji ZWJ sequences and Persian/Indic shaping marks are removed; unassigned code points and some other Cf characters (e.g. U+0600-0605, U+06DD) are NOT stripped. `SIM_DOCTOR_HANDOFF_SKIP_APPROVALS=1` is documented and tested (#55).
- SIGTERM now sets the same interrupt flag as SIGINT, so a killed `scan --tui` restores the terminal and a killed scan exits 130; `sim-doctor mcp` ends on SIGTERM (#59).

### Added

- `sim-doctor ci install [--dir DIR] [--force] [--print-only]` writes `.github/workflows/sim-doctor.yml` running the action on pull requests, pinned to this version's tag; values are validated before writing, symlinks are never written through, and a differing file is kept without `--force`; the generated workflow has not been run on a hosted runner (#45).
- A composite GitHub Action (`action.yml`, `scripts/sim-doctor-action.sh`) gating CI on new findings against a committed baseline, with a PR comment and SARIF upload; script logic is tested locally, the hosted run is exercised only by the `action-selftest` workflow (#43).
- `sim-doctor scan --tui` shows the findings in a ratatui view (severity colours, a detail pane, the coverage and TAR-stop notes); it shows only what `--json` carries, conflicts with `--json` (exit 129), and falls back to the plain report with a stderr line when stdin or stdout is not a terminal; not tested against a real terminal in CI (#15).
- `sim-doctor mcp` serves `scan`, `rules_list` and `rules_explain` as MCP tools over stdio by running itself as a subprocess; `baseline`, `diff` and `sarif` are not exposed; agent-client acceptance beyond the handshake is unverified (#41).
- `sim-doctor fix <rule-id> --from FILE [--agent claude|codex|cursor] [--skip-approvals]` prints a prompt for one finding of a saved scan (card text fenced as untrusted) and can start a coding agent with its approvals kept; nothing is launched inside an agent (#44).
- `sim-doctor scan --sarif FILE` writes the findings as SARIF 2.1.0 (logical locations, partial coverage in run properties), written only after a completed scan; GitHub code-scanning acceptance is unverified (#42).
- `sim-doctor rules list [--json]`, `rules explain <id>` and `why <rule-id|FILE>` explain what a rule means and how to fix it without a card; the rule registry now refuses a rule with no summary or remediation (#46).
- `sim-doctor install [--agent claude|cursor|codex|opencode] [--print-only] [--dir DIR]` writes agent guidance:
  `.claude/skills/sim-doctor/SKILL.md`, `.cursor/rules/sim-doctor.mdc`, and a marked block in `AGENTS.md`
  that is replaced in place on re-run.
- Prebuilt binaries on tagged releases (macOS aarch64 and x86_64, Linux x86_64) and an `npx sim-doctor` launcher.
- Tagged-release publishing: the release workflow checks that the tag, `Cargo.toml` and `npm/package.json` agree,
  attaches binaries plus `.sha256` files to the GitHub release, then publishes to crates.io and npm (with provenance),
  skipping with a notice when a token is unset or the version already exists. crates.io package metadata added.
- The `npx` launcher verifies the downloaded binary's SHA-256 and has no-network tests (`npm test`).
- Illustrated logo (SIM card with a pulse line) as `docs/assets/logo-{light,dark}.svg` and `mark.svg`.
- README install section, CLI reference and logo; this changelog.

## [0.1.0] - 2026-10-06

First tagged state of the M1 path: `sim-doctor scan` opens a PC/SC session, walks the card's file
system and reports it as a table or one JSON envelope. Structure-only: one rule runs (`gsma/msl-zero-allowed`,
behind `--tar`), so a score of 100 does not mean a clean card.

### Added

- Crate skeleton with documented module boundaries (#29).
- APDU codec, status-word handling and the session composition layer (#31).
- TLV stream decoder, caller-supplied FCP tag table and EF metadata (#32).
- The DF-tree filesystem walker (#33).
- SIGINT handling and process-level exit-status tests (#34).
- The clap CLI surface for `scan`: `--json`, `--dialect`, `--reader`, the walk bounds (#35).
- Finding and rule model with namespaced rule IDs (#36).
- `--severity` filtering, `--score`, and JSON purity guarantees (#37).
- TAR scanner and the MSL=0 rule `gsma/msl-zero-allowed` (#38).
- CI: fmt, clippy `-D warnings`, test (#27), and the swSIM + swicc-pcsc software-card fixture (#30).

### Changed

- Switched the license to MIT.
- Closed resolved dependency blockers in AGENTS.md (#28).

- `gp crs list|info|activate|deactivate`: the Contactless Registry Service (CRS, GlobalPlatform
  Amendment C), reads on the CRS application plus two card-state writes gated behind `--yes`
  (#241).
