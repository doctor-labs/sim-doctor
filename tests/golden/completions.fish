# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_sim_doctor_global_optspecs
    string join \n h/help V/version
end

function __fish_sim_doctor_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_sim_doctor_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_sim_doctor_using_subcommand
    set -l cmd (__fish_sim_doctor_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -s V -l version -d 'Print version'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "modules" -d 'Describe the crate module roots and the layering between them'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "readers" -d 'List the PC/SC readers by name and index, for --reader or --reader-index'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "scan" -d 'Select a card\'s master file, walk everything under it, and report'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "ts48" -d 'Compare a card against the public GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "install" -d 'Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "ci" -d 'Write the GitHub Actions workflow that runs this repo\'s action on pull requests'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "completions" -d 'Write a shell completion script to stdout'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "mcp" -d 'Serve the scan and the rules as MCP tools over stdio'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "rules" -d 'List the rules a scan runs, or explain one, without a card'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "why" -d 'Explain a rule, or every rule in a saved `scan --json` envelope'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "fix" -d 'Hand one finding from a saved scan to a coding agent'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "gp" -d 'Read-only GlobalPlatform queries'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "trace" -d 'Decode a captured APDU trace offline (no card, no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "cat" -d 'Decode Card Application Toolkit data offline (no card, no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "sms" -d '`sms decode` decodes SMS TPDUs offline (TS 23.040): SMS-DELIVER, SMS-SUBMIT and STATUS-REPORT, addresses, DCS, the user-data header and concatenation, GSM 7-bit and UCS2 text. Sends nothing'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "saip" -d '`saip parse` decodes a SIMalliance eUICC profile package (SAIP, the DER ProfileElement sequence) offline into JSON: each element named by its PE type, the rest a bounded TLV tree. Parse only, no personalization. Sends nothing'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "ota-crypto" -d 'Offline OTA ciphers and checksums (DES, 3DES, AES-CBC encrypt/decrypt, CBC-MAC / AES-CMAC sign and check), as pySim\'s OTA layer uses them. No card and no reader: pure crypto over hex given on the command line'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "esim-cert" -d 'Verify an eSIM certificate chain offline, up to a CI root you supply'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "fuzz" -d 'APDU discovery and the OTA/SMS fuzz sweep'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "euicc" -d 'eUICC queries over ES10 (lpac: chip info, profile list, notification list), and the profile and notification writes'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "card" -d 'A pySim-shell style shell over the card: select files, read them, send APDUs'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand modules" -l json -d 'Emit the JSON envelope on stdout instead of a human-readable table'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand modules" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand readers" -l json -d 'Emit one JSON envelope (type "readers") on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand readers" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l dialect -d 'Which FCP tag table this card answers SELECT with' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l reader-index -d 'The reader to use, by its index in `sim-doctor readers` (counted from 0)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-depth -d 'Deepest path below the master file the walk descends into' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-children -d 'Identifiers probed per directory' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-nodes -d 'Files the card selected across the whole walk (default 16384)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-directories -d 'Directories whose children are enumerated' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l severity -d 'Drop findings below this severity' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l baseline -d 'Compare this run against a previous `scan --json` envelope (doctor/1)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l fail-on -d 'Exit 1 (3 under --baseline) when a finding is at or above this severity' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l sarif -d 'Also write the findings to FILE as SARIF 2.1.0' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l tar -d 'Which TARs to probe for MSL 0, and how many' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l face -d 'The human report: a doctor-kit face (rich, plain or compact), or the full legacy report' -r -f -a "rich\t''
plain\t''
compact\t''
legacy\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l theme -d 'The face\'s colours: mono, clinical or contrast (default: the tool\'s own)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l color -d 'Colour the face: auto (a terminal and no NO_COLOR), always or never' -r -f -a "auto\t''
always\t''
never\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l tui -d 'Show the findings in an interactive terminal view instead of the report'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -s b -l scan-file-break -l sfb -d 'Break after finding all files the card claims to have (DF count matches)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l sffs -d 'Follow standard identifiers only (ETSI TS 102 221 / 3GPP TS 31.102 / 31.103 / 31.104 / 51.011). When set, the walk probes only the file identifiers defined in the ETSI and 3GPP specifications, plus the files pySim can decode with standard names. This is stricter than the default (SimFamilies), which probes the broader GSM 11.11 family ranges (2Fxx, 4Fxx, 5Fxx, 6Fxx, 7Fxx). Corresponds to SIMTester\'s `-sffs` flag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l score -d 'Add one quality score for this card, for CI gating'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l terminal-profile -d 'Send a TERMINAL PROFILE to the card before the TAR audit'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l sms-deliver-report -d 'Ask for SMS-DELIVER-REPORT as the proof-of-receipt mode of the TAR probes, not SMS-SUBMIT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l reserved-file-ids -l sfrv -d 'Scan reserved file identifiers 7FF0-7FFF inside an application'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l headless -d 'A face in plain text without colour, for CI and pipes'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and not __fish_seen_subcommand_from compare help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and not __fish_seen_subcommand_from compare help" -f -a "compare" -d 'Walk the card and diff its file system against the GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and not __fish_seen_subcommand_from compare help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l dialect -d 'Which FCP tag table this card answers SELECT with (see `scan --help`)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-depth -d 'Deepest path below the master file the walk descends into' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-children -d 'Identifiers probed per directory' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-nodes -d 'Files the card selected across the whole walk (default 16384)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-directories -d 'Directories whose children are enumerated' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l json -d 'Emit one JSON envelope (type "ts48") on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -s b -l scan-file-break -l sfb -d 'Break after finding all files the card claims to have (DF count matches)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from help" -f -a "compare" -d 'Walk the card and diff its file system against the GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -l agent -d 'Install for one agent only; omit for all of them' -r -f -a "claude\t''
cursor\t''
codex\t''
opencode\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -l dir -d 'Project root to write under (default: the current directory)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -l print-only -d 'Print what would be written instead of writing it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and not __fish_seen_subcommand_from install help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and not __fish_seen_subcommand_from install help" -f -a "install" -d 'Write .github/workflows/sim-doctor.yml, pinned to this version\'s tag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and not __fish_seen_subcommand_from install help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l swsim -d 'Build the software card on the runner (CI has no card otherwise)' -r -f -a "true\t''
false\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l baseline -d 'Committed baseline path (letters, digits and . _ / - only)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l require-baseline -d 'Fail the job when the baseline file is missing' -r -f -a "true\t''
false\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l severity -d 'Pass --severity to the scan' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l ref -d 'The action ref to pin (default: v<this version>; it exists once that release is cut)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l dir -d 'Project root to write under (default: the current directory)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l force -d 'Overwrite a differing existing workflow'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l print-only -d 'Print the workflow instead of writing it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from help" -f -a "install" -d 'Write .github/workflows/sim-doctor.yml, pinned to this version\'s tag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand mcp" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -f -a "list" -d 'One row per rule: id, severity, summary'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -f -a "explain" -d 'What a rule means and how to fix it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from list" -l json -d 'Emit one JSON envelope of kind "rules" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from explain" -l json -d 'Emit one JSON envelope of kind "rules" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "list" -d 'One row per rule: id, severity, summary'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "explain" -d 'What a rule means and how to fix it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand why" -l json -d 'Emit one JSON envelope of kind "rules" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand why" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -l from -d 'A saved `sim-doctor scan --json` envelope holding a finding for that rule' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -l agent -d 'Start this coding agent with the prompt instead of only printing it' -r -f -a "claude\t''
codex\t''
cursor\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -l skip-approvals -d 'Pass the agent its flag that skips approval prompts (unverified for every CLI version)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "info" -d 'Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "ara" -d 'Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA [all], decoded (read-only, no keys)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "status" -d 'GlobalPlatform registry inventory: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "select" -d 'SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card\'s current selection'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "channel" -d 'Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "delete" -d 'Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "make-default" -d 'Make an installed application Default Selected over an SCP03 channel: INSTALL [for make selectable] with the Card Reset privilege (GlobalPlatform Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "rename-isd" -d 'Rename the Issuer Security Domain over an SCP03 channel: STORE DATA `4F LEN AID` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "install" -d 'Load a CAP file and install an applet over an SCP03 channel: INSTALL [for load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "put-key" -d 'Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD\'S ADMINISTRATIVE ACCESS'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "cplc-set" -d 'Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "personalize" -d 'Personalize an application or Security Domain over an SCP03 channel: INSTALL [for personalization] (P1 20) for the AID, then one STORE DATA with the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified against the spec text, see the source). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete make-default rename-isd install put-key cplc-set personalize help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l list -d 'Print the registry as a table: scope, AID, lifecycle, privileges'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l info -d 'Print each registry entry in detail, with its raw lifecycle and privilege bytes'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l aid -d 'The application AID, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -f -a "open" -d 'MANAGE CHANNEL open: the card picks the number and it is printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -f -a "close" -d 'MANAGE CHANNEL close of a channel opened earlier'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l aid -d 'The AID to delete, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l related -d 'Also delete related objects (P2 80): for a load file, its applications'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l aid -d 'The application AID, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from make-default" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l new-aid -d 'The new ISD AID, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from rename-isd" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l load -d 'The CAP file (a zip of javacard/*.cap components)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l module -d 'The Executable Module AID (the applet class). Optional when the CAP has one applet' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l app -d 'The application (instance) AID. Defaults to the module AID' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l params -d 'The Install Parameters field as TLV with the mandatory C9 tag (default C900: none)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l privileges -d 'Privileges, 1 or 3 bytes of hex (default 000000). Card Lock and Card Terminate are refused' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-key-file -d 'File holding the AES DAP key (hex, optionally KEY/KCV; chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-key-env -d 'Environment variable holding the AES DAP key' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-sd -d 'The Security Domain that verifies the DAP, 5 to 16 bytes of hex (default: the issuer security domain being authenticated)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-hash -d 'The Load File Data Block Hash the DAP signs' -r -f -a "sha256\t''
sha384\t''
sha512\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l make-default -d 'Make the applet default selected: sets the Card Reset privilege, 0x04 in the first privilege byte (GP Card Spec v2.3.1 table 11-7, the bit GlobalPlatformPro\'s --make-default sets). The card then selects this applet by default after reset, so it changes what the card runs first'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l new-key-version -d 'The Key Version Number of the new keys, 01 to 7F' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l replace-key-version -d 'P1: 00 (default) adds the key set; 01 to 7F replaces the key set with that version' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l key-id -d 'The Key Identifier of the first key (the other two follow at +1 and +2)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l new-keys-file -d 'File holding the new keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l new-keys-env -d 'Environment variable holding the new keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l replace-current-keyset -d 'Allow the request to add, replace or overwrite the key version this session authenticated with. Without it such a request is refused'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l kind -d 'pre-perso (DGI 9F67) or perso (DGI 9F66)' -r -f -a "pre-perso\t''
perso\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l data -d 'The eight data bytes of the block as 16 hex digits' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l today -d 'Write today\'s date (UTC) into the date bytes, overriding those in --data'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from cplc-set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l aid -d 'The application or Security Domain AID, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l data -d 'The BER-TLV personalization data, as hex; sent as the STORE DATA body' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from personalize" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "info" -d 'Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "ara" -d 'Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA [all], decoded (read-only, no keys)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "status" -d 'GlobalPlatform registry inventory: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "select" -d 'SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card\'s current selection'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "channel" -d 'Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "make-default" -d 'Make an installed application Default Selected over an SCP03 channel: INSTALL [for make selectable] with the Card Reset privilege (GlobalPlatform Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "rename-isd" -d 'Rename the Issuer Security Domain over an SCP03 channel: STORE DATA `4F LEN AID` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "install" -d 'Load a CAP file and install an applet over an SCP03 channel: INSTALL [for load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "put-key" -d 'Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD\'S ADMINISTRATIVE ACCESS'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "cplc-set" -d 'Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "personalize" -d 'Personalize an application or Security Domain over an SCP03 channel: INSTALL [for personalization] (P1 20) for the AID, then one STORE DATA with the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified against the spec text, see the source). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -l json -d 'Emit one JSON envelope of kind "trace" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -l show-raw-apdu -d 'Also print each exchange\'s raw command and response hex in the table'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -l no-suppress-select -d 'Keep SELECT rows in the table. They are hidden by default, as in pySim-trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -l no-suppress-status -d 'Keep UICC STATUS rows in the table. They are hidden by default, as in pySim-trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and not __fish_seen_subcommand_from decode help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and not __fish_seen_subcommand_from decode help" -f -a "decode" -d 'Decode CAT data given as hex arguments, or one object per line on stdin'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and not __fish_seen_subcommand_from decode help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and __fish_seen_subcommand_from decode" -l json -d 'Emit one JSON envelope of kind "cat" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and __fish_seen_subcommand_from decode" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and __fish_seen_subcommand_from help" -f -a "decode" -d 'Decode CAT data given as hex arguments, or one object per line on stdin'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand cat; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and not __fish_seen_subcommand_from decode help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and not __fish_seen_subcommand_from decode help" -f -a "decode" -d 'Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and not __fish_seen_subcommand_from decode help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and __fish_seen_subcommand_from decode" -l tpdu -d 'The hex is a bare TPDU, without the leading SMSC address the PDU format carries'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and __fish_seen_subcommand_from decode" -l json -d 'Emit one JSON envelope of kind "sms" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and __fish_seen_subcommand_from decode" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and __fish_seen_subcommand_from help" -f -a "decode" -d 'Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand sms; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and not __fish_seen_subcommand_from parse help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and not __fish_seen_subcommand_from parse help" -f -a "parse" -d 'Decode a SAIP profile package (DER, the concatenated ProfileElements) offline'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and not __fish_seen_subcommand_from parse help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and __fish_seen_subcommand_from parse" -l json -d 'Emit one JSON envelope of kind "saip" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and __fish_seen_subcommand_from parse" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and __fish_seen_subcommand_from help" -f -a "parse" -d 'Decode a SAIP profile package (DER, the concatenated ProfileElements) offline'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand saip; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and not __fish_seen_subcommand_from encrypt decrypt sign check help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and not __fish_seen_subcommand_from encrypt decrypt sign check help" -f -a "encrypt" -d 'Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and not __fish_seen_subcommand_from encrypt decrypt sign check help" -f -a "decrypt" -d 'Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and not __fish_seen_subcommand_from encrypt decrypt sign check help" -f -a "sign" -d 'Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and not __fish_seen_subcommand_from encrypt decrypt sign check help" -f -a "check" -d 'Recompute the checksum and compare it to --mac in constant time'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and not __fish_seen_subcommand_from encrypt decrypt sign check help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from encrypt" -l alg -d 'DES (8-byte key), 3DES (16- or 24-byte key) or AES (16/24/32-byte key)' -r -f -a "des\t''
3des\t'2-key (16-byte) or 3-key (24-byte) Triple DES'
aes\t'AES-128, AES-192 or AES-256 from the key length'"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from encrypt" -l key -d 'The key as hex; length selects the AES variant (16/24/32) or must match the algorithm (DES 8, 3DES 16 or 24)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from encrypt" -l iv -d 'The IV as hex (one block); all zeros when absent' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from encrypt" -l json -d 'Emit one JSON envelope of kind "ota-crypto" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from encrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from decrypt" -l alg -r -f -a "des\t''
3des\t'2-key (16-byte) or 3-key (24-byte) Triple DES'
aes\t'AES-128, AES-192 or AES-256 from the key length'"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from decrypt" -l key -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from decrypt" -l iv -d 'The IV as hex (one block); all zeros when absent' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from decrypt" -l json
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from decrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from sign" -l alg -r -f -a "des\t''
3des\t'2-key (16-byte) or 3-key (24-byte) Triple DES'
aes\t'AES-128, AES-192 or AES-256 from the key length'"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from sign" -l key -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from sign" -l mac-len -d 'Length of the MAC to return (default 8, the OTA checksum length)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from sign" -l json
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from sign" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from check" -l alg -r -f -a "des\t''
3des\t'2-key (16-byte) or 3-key (24-byte) Triple DES'
aes\t'AES-128, AES-192 or AES-256 from the key length'"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from check" -l key -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from check" -l mac -d 'The expected MAC as hex; its length sets the MAC length' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from check" -l json
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from check" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from help" -f -a "encrypt" -d 'Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from help" -f -a "decrypt" -d 'Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from help" -f -a "sign" -d 'Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from help" -f -a "check" -d 'Recompute the checksum and compare it to --mac in constant time'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ota-crypto; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and not __fish_seen_subcommand_from verify help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and not __fish_seen_subcommand_from verify help" -f -a "verify" -d 'Verify a certificate chain (leaf first) up to a CI root'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and not __fish_seen_subcommand_from verify help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and __fish_seen_subcommand_from verify" -l root -d 'The CI root you trust: a file holding exactly one certificate, PEM or DER' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and __fish_seen_subcommand_from verify" -l at -d 'Check validity at this UTC time, YYYYMMDDHHMMSS, instead of now' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and __fish_seen_subcommand_from verify" -l json -d 'Emit one JSON envelope of kind "esim-cert" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Verify a certificate chain (leaf first) up to a CI root'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand esim-cert; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate compare help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate compare help" -f -a "apdu" -d 'CLA discovery (level 1) or CLA+INS discovery (level 2) over a session'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate compare help" -f -a "ota" -d 'The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR scanner\'s ENVELOPE builder'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate compare help" -f -a "mutate" -d 'Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate compare help" -f -a "compare" -d 'Compares two or more `fuzz ota` JSON results: keysets ranked by how often the card accepted under them, and the (TAR, keyset, mechanism) triples the runs disagree on. Offline and read-only: it reads result files and sends nothing. Only triples every run probed are compared'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate compare help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l level -d '1 for CLA discovery, 2 for CLA+INS discovery' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l class -d 'The CLA level 2 probes INS values at, as two hex digits (e.g. A0). Required for --level 2' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l i-understand-this-can-brick-the-card -d 'Required. Without it, `fuzz` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l allow-real-hardware -d 'Required in addition to the opt-in above when the reader\'s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, `fuzz` refuses to run against anything that is not recognisably the software card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l quick -d 'Probe a small, documented subset instead of the full space'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l i-understand-this-can-brick-the-card -d 'Required. Without it, `fuzz` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l allow-real-hardware -d 'Required in addition to the opt-in above when the reader\'s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, `fuzz` refuses to run against anything that is not recognisably the software card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l quick -d 'Probe a small, documented subset instead of the full space'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l poke -d 'Like `--quick`, but probes only the three TARs SIMTester\'s `-poke` probes: 000000, B00001 and B00010 - the quick keysets and mechanisms still apply, so a run finishes in milliseconds'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l replay -d 'Answer from a recorded exchange log (one {"command","response"} JSON object per line, as SIM_DOCTOR_RECORD writes) instead of a card' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l max-cases -d 'Cases to send (1 to 10000)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l timeout -d 'Stop sending after this many seconds' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l seed -d 'PRNG seed. The same seed gives the same APDUs' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l mock -d 'Answer from the built-in strict mock card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l dry-run -d 'Print the planned APDUs and the allowlist/denylist; send nothing'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l stop-on-first-finding -d 'Stop after the first finding'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from compare" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from compare" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "apdu" -d 'CLA discovery (level 1) or CLA+INS discovery (level 2) over a session'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "ota" -d 'The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR scanner\'s ENVELOPE builder'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "mutate" -d 'Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "compare" -d 'Compares two or more `fuzz ota` JSON results: keysets ranked by how often the card accepted under them, and the (TAR, keyset, mechanism) triples the runs disagree on. Offline and read-only: it reads result files and sends nothing. Only triples every run probed are compared'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "info" -d 'EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "profiles" -d 'Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "challenge" -d 'GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7): the 16-byte challenge a profile download signs over (pySim `get_euicc_challenge`). Read-only'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "notifications" -d 'Pending notification metadata (lpac `notification list`); `dump` and `replay` below; `notifications remove <seq>` removes one'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "nickname" -d 'Set a profile\'s nickname (lpac `profile nickname`). A write: a dry run unless `--yes`, never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "enable" -d 'Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH). A dry run unless `--yes`: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "disable" -d 'Disable a profile (lpac `profile disable`, ES10c DisableProfile with REFRESH). A dry run unless `--yes`: disabling the only enabled profile leaves no active profile. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "delete" -d 'Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run unless `--yes`: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "reset" -d 'Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can erase every profile: nothing is selected by default, and sending needs both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles challenge notifications nickname enable disable delete reset help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from challenge" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from challenge" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from challenge" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from challenge" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from challenge" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "remove" -d 'Remove a notification from the eUICC\'s list (lpac `notification remove`, ES10b RemoveNotificationFromList). A dry run unless `--yes`: a removed notification is never sent to the operator\'s server. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "dump" -d 'Read the full signed pending notifications (lpac `notification dump`, ES10b RetrieveNotificationsList) as a re-loadable JSON document: hex of the signed bytes plus the decoded sequence number, operation, address and ICCID. Read-only: nothing is removed. Without `-o` and `--json` the document itself is printed. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "replay" -d 'Send the notifications of a dump file to their operators (ES9+ HandleNotification over HTTPS). A dry run unless `--yes`: this reaches the network and tells the operator\'s server about a profile event. Needs no card and removes nothing. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l yes -d 'Send SetNickname, then re-read the profile list and confirm. Without it nothing is changed: the target EID and ICCID, the current and the new nickname are printed and the command exits'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l yes -d 'Send the request, then re-read the profile list and confirm. Without it nothing is changed: the plan and its consequence are printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l yes -d 'Send the request, then re-read the profile list and confirm. Without it nothing is changed: the plan and its consequence are printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l yes -d 'Send DeleteProfile, then re-read the profile list and confirm. Without it nothing is changed: the profile and its consequence are printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l confirm-eid -d 'The card\'s EID (32 hex digits); must match the EID read from the card' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l operational -d 'Delete the operational profiles (resetOptions bit 0)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l test -d 'Delete the field-loaded test profiles (resetOptions bit 1)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l smdp-address -d 'Reset the default SM-DP+ address (resetOptions bit 2)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l yes -d 'Send the reset (needs `--confirm-eid`), then re-read and confirm. Without it nothing is changed: the profiles that would be erased are listed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "info" -d 'EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "profiles" -d 'Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "challenge" -d 'GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7): the 16-byte challenge a profile download signs over (pySim `get_euicc_challenge`). Read-only'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "notifications" -d 'Pending notification metadata (lpac `notification list`); `dump` and `replay` below; `notifications remove <seq>` removes one'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "nickname" -d 'Set a profile\'s nickname (lpac `profile nickname`). A write: a dry run unless `--yes`, never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH). A dry run unless `--yes`: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable a profile (lpac `profile disable`, ES10c DisableProfile with REFRESH). A dry run unless `--yes`: disabling the only enabled profile leaves no active profile. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run unless `--yes`: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "reset" -d 'Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can erase every profile: nothing is selected by default, and sending needs both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l reader -d 'The reader to use, matched against the driver\'s own name (default: the first reader)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l profile -d 'The command set the card speaks: uicc (class 00) or sim (class A0, GSM 11.11)' -r -f -a "uicc\t''
sim\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l dialect -d 'Which FCP tag table the card answers SELECT with (see `scan --help`)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -s c -d 'Run these `;`-separated commands and exit' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l script -d 'Run the commands in this file, one per line (`#` starts a comment), and exit' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l chv-file -d 'File holding PINs, PUKs and ADM keys for `verify_chv` / `unblock_chv` (`pin1=1234` per line; keep it chmod 600). Never a value on the command line: it would land in shell history' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l chv-env -d 'Environment variable holding the same text (entries separated by `;` or newlines)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l key-file -d 'pySim CardKeyProvider CSV file for `query_card_key` (ICCID,ADM1,OPC,...; one card per row). Read and checked before any reader is opened; secrets are never printed unless named in --fields. Keep it chmod 600' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l dump -d 'Write every APDU exchange (command and response, hex) to FILE as JSON lines, in the SIM_DOCTOR_RECORD replay format. The data field of secret instructions (VERIFY, CHANGE, ENABLE/DISABLE, RESET RETRY COUNTER, AUTHENTICATE) is redacted as FF bytes, and so are the response data of AUTHENTICATE (RES, CK, IK, Kc); such lines carry "redacted":true and no longer replay byte for byte. --dump-secrets records them raw. The file holds raw card data (ICCID, IMSI, file contents): review it before it goes anywhere. Refuses an existing file unless --force; never writes through a symlink or into a non-regular file. The file is owner-only (0600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l json -d 'Print every reply as one JSON record (for agents)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -s X -l exclusive -d 'Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE): no other process can use the card while this shell is open. Off by default, which shares it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l yes -d 'Send the commands that change the card (APDUs outside the read-only set, PIN checks, ...). Without it they print what they would send and the card is not touched by them'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l force -d 'Let --dump overwrite an existing regular file'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -l dump-secrets -d 'Record PINs and keys in plain text: the data field of VERIFY, CHANGE, ENABLE/DISABLE, RESET RETRY COUNTER and AUTHENTICATE, and the response data of AUTHENTICATE (RES, CK, IK, Kc), is written raw. Keep the file private. Needs --dump'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand card" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "modules" -d 'Describe the crate module roots and the layering between them'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "readers" -d 'List the PC/SC readers by name and index, for --reader or --reader-index'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "scan" -d 'Select a card\'s master file, walk everything under it, and report'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "ts48" -d 'Compare a card against the public GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "install" -d 'Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "ci" -d 'Write the GitHub Actions workflow that runs this repo\'s action on pull requests'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "completions" -d 'Write a shell completion script to stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "mcp" -d 'Serve the scan and the rules as MCP tools over stdio'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "rules" -d 'List the rules a scan runs, or explain one, without a card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "why" -d 'Explain a rule, or every rule in a saved `scan --json` envelope'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "fix" -d 'Hand one finding from a saved scan to a coding agent'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "gp" -d 'Read-only GlobalPlatform queries'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "trace" -d 'Decode a captured APDU trace offline (no card, no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "cat" -d 'Decode Card Application Toolkit data offline (no card, no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "sms" -d '`sms decode` decodes SMS TPDUs offline (TS 23.040): SMS-DELIVER, SMS-SUBMIT and STATUS-REPORT, addresses, DCS, the user-data header and concatenation, GSM 7-bit and UCS2 text. Sends nothing'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "saip" -d '`saip parse` decodes a SIMalliance eUICC profile package (SAIP, the DER ProfileElement sequence) offline into JSON: each element named by its PE type, the rest a bounded TLV tree. Parse only, no personalization. Sends nothing'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "ota-crypto" -d 'Offline OTA ciphers and checksums (DES, 3DES, AES-CBC encrypt/decrypt, CBC-MAC / AES-CMAC sign and check), as pySim\'s OTA layer uses them. No card and no reader: pure crypto over hex given on the command line'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "esim-cert" -d 'Verify an eSIM certificate chain offline, up to a CI root you supply'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "fuzz" -d 'APDU discovery and the OTA/SMS fuzz sweep'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "euicc" -d 'eUICC queries over ES10 (lpac: chip info, profile list, notification list), and the profile and notification writes'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "card" -d 'A pySim-shell style shell over the card: select files, read them, send APDUs'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules readers scan ts48 install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert fuzz euicc card help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ts48" -f -a "compare" -d 'Walk the card and diff its file system against the GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ci" -f -a "install" -d 'Write .github/workflows/sim-doctor.yml, pinned to this version\'s tag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "list" -d 'One row per rule: id, severity, summary'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "explain" -d 'What a rule means and how to fix it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "info" -d 'Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "ara" -d 'Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA [all], decoded (read-only, no keys)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "status" -d 'GlobalPlatform registry inventory: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "select" -d 'SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card\'s current selection'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "channel" -d 'Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "delete" -d 'Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "make-default" -d 'Make an installed application Default Selected over an SCP03 channel: INSTALL [for make selectable] with the Card Reset privilege (GlobalPlatform Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "rename-isd" -d 'Rename the Issuer Security Domain over an SCP03 channel: STORE DATA `4F LEN AID` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "install" -d 'Load a CAP file and install an applet over an SCP03 channel: INSTALL [for load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "put-key" -d 'Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD\'S ADMINISTRATIVE ACCESS'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "cplc-set" -d 'Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "personalize" -d 'Personalize an application or Security Domain over an SCP03 channel: INSTALL [for personalization] (P1 20) for the AID, then one STORE DATA with the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified against the spec text, see the source). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from cat" -f -a "decode" -d 'Decode CAT data given as hex arguments, or one object per line on stdin'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from sms" -f -a "decode" -d 'Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from saip" -f -a "parse" -d 'Decode a SAIP profile package (DER, the concatenated ProfileElements) offline'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ota-crypto" -f -a "encrypt" -d 'Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ota-crypto" -f -a "decrypt" -d 'Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ota-crypto" -f -a "sign" -d 'Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ota-crypto" -f -a "check" -d 'Recompute the checksum and compare it to --mac in constant time'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from esim-cert" -f -a "verify" -d 'Verify a certificate chain (leaf first) up to a CI root'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "apdu" -d 'CLA discovery (level 1) or CLA+INS discovery (level 2) over a session'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "ota" -d 'The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR scanner\'s ENVELOPE builder'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "mutate" -d 'Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "compare" -d 'Compares two or more `fuzz ota` JSON results: keysets ranked by how often the card accepted under them, and the (TAR, keyset, mechanism) triples the runs disagree on. Offline and read-only: it reads result files and sends nothing. Only triples every run probed are compared'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "info" -d 'EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "profiles" -d 'Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "challenge" -d 'GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7): the 16-byte challenge a profile download signs over (pySim `get_euicc_challenge`). Read-only'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "notifications" -d 'Pending notification metadata (lpac `notification list`); `dump` and `replay` below; `notifications remove <seq>` removes one'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "nickname" -d 'Set a profile\'s nickname (lpac `profile nickname`). A write: a dry run unless `--yes`, never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "enable" -d 'Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH). A dry run unless `--yes`: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "disable" -d 'Disable a profile (lpac `profile disable`, ES10c DisableProfile with REFRESH). A dry run unless `--yes`: disabling the only enabled profile leaves no active profile. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "delete" -d 'Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run unless `--yes`: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "reset" -d 'Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can erase every profile: nothing is selected by default, and sending needs both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP'
