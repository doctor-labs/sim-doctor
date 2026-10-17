#compdef sim-doctor

autoload -U is-at-least

_sim-doctor() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_sim-doctor_commands" \
"*::: :->sim-doctor" \
&& ret=0
    case $state in
    (sim-doctor)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-command-$line[1]:"
        case $line[1] in
            (modules)
_arguments "${_arguments_options[@]}" : \
'--json[Emit the JSON envelope on stdout instead of a human-readable table]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(readers)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope (type "readers") on stdout, and nothing else]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(scan)
_arguments "${_arguments_options[@]}" : \
'--dialect=[Which FCP tag table this card answers SELECT with]:TABLE:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'(--reader)--reader-index=[The reader to use, by its index in \`sim-doctor readers\` (counted from 0)]:N:_default' \
'--max-depth=[Deepest path below the master file the walk descends into]:N:_default' \
'--max-children=[Identifiers probed per directory]:N:_default' \
'--max-nodes=[Files the card selected across the whole walk (default 16384)]:N:_default' \
'--max-directories=[Directories whose children are enumerated]:N:_default' \
'--severity=[Drop findings below this severity]:LEVEL:_default' \
'--baseline=[Compare this run against a previous \`scan --json\` envelope (doctor/1)]:FILE:_files' \
'--fail-on=[Exit 1 (3 under --baseline) when a finding is at or above this severity]:LEVEL:_default' \
'--sarif=[Also write the findings to FILE as SARIF 2.1.0]:FILE:_files' \
'--csv=[The same results as a CSV log, in the layout SIMTester writes]:FILE:_files' \
'--tar=[Which TARs to probe for MSL 0, and how many]:SELECTION:_default' \
'--tar-filter=[SIMTester'\''s \`-stre\`\: skip TAR probes whose response matches this regex]:REGEX:_default' \
'--class=[The class byte the ENVELOPE and its CAT follow-ups are sent at\: etsi (CLA 80, the default) or gsm (CLA A0).]:CLASS:((etsi\:"CLA \`0x80\`, ETSI TS 102 221 clause 10.1.2. The default"
gsm\:"CLA \`0xA0\`, GSM 11.11. \`--class gsm\`"))' \
'(--json --tui)--face=[The human report\: a doctor-kit face (rich, plain or compact), or the full legacy report]:FACE:(rich plain compact legacy)' \
'(--json --tui)--theme=[The face'\''s colours\: mono, clinical or contrast (default\: the tool'\''s own)]:THEME:_default' \
'(--json --tui)--color=[Colour the face\: auto (a terminal and no NO_COLOR), always or never]:COLOR:(auto always never)' \
'-X[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--exclusive[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'(--json)--tui[Show the findings in an interactive terminal view instead of the report]' \
'-b[Break after finding all files the card claims to have (DF count matches)]' \
'--scan-file-break[Break after finding all files the card claims to have (DF count matches)]' \
'--sfb[Break after finding all files the card claims to have (DF count matches)]' \
'--sffs[Follow standard identifiers only (ETSI TS 102 221 / 3GPP TS 31.102 / 31.103 / 31.104 / 51.011). When set, the walk probes only the file identifiers defined in the ETSI and 3GPP specifications, plus the files pySim can decode with standard names. This is stricter than the default (SimFamilies), which probes the broader GSM 11.11 family ranges (2Fxx, 4Fxx, 5Fxx, 6Fxx, 7Fxx). Corresponds to SIMTester'\''s \`-sffs\` flag]' \
'--score[Add one quality score for this card, for CI gating]' \
'--terminal-profile[Send a TERMINAL PROFILE to the card before the TAR audit]' \
'--sms-deliver-report[Ask for SMS-DELIVER-REPORT as the proof-of-receipt mode of the TAR probes, not SMS-SUBMIT]' \
'--reserved-file-ids[Scan reserved file identifiers 7FF0-7FFF inside an application]' \
'--sfrv[Scan reserved file identifiers 7FF0-7FFF inside an application]' \
'--tar-uncapped[Raise the 4096-probe bound on the TAR audit to the full TAR space, 16 777 216 values (issue #266)]' \
'--yes[Send the uncapped TAR sweep. Required with --tar-uncapped]' \
'(--json --tui --face)--headless[A face in plain text without colour, for CI and pipes]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(profile)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__profile_commands" \
"*::: :->profile" \
&& ret=0

    case $state in
    (profile)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-profile-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope instead of the table]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(probe)
_arguments "${_arguments_options[@]}" : \
'--reader=[Which PC/SC reader to use]:NAME:_default' \
'-X[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--exclusive[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--json[Emit one JSON envelope instead of the report]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(match)
_arguments "${_arguments_options[@]}" : \
'--reader=[Which PC/SC reader to use]:NAME:_default' \
'-X[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--exclusive[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--json[Emit one JSON envelope instead of the report]' \
'-h[Print help]' \
'--help[Print help]' \
':name -- The `-t` name, spelled as `sim-doctor profile list` prints it:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__profile__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-profile-help-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(probe)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(match)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(cards)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__cards_commands" \
"*::: :->cards" \
&& ret=0

    case $state in
    (cards)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-cards-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope (type "cards") on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope (type "cards") on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':name -- The profile name, exactly as `cards list` prints it:_default' \
&& ret=0
;;
(fixture)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The profile name, exactly as `cards list` prints it:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__cards__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-cards-help-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fixture)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(ts48)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_sim-doctor__subcmd__ts48_commands" \
"*::: :->ts48" \
&& ret=0

    case $state in
    (ts48)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ts48-command-$line[1]:"
        case $line[1] in
            (compare)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--dialect=[Which FCP tag table this card answers SELECT with (see \`scan --help\`)]:TABLE:_default' \
'--max-depth=[Deepest path below the master file the walk descends into]:N:_default' \
'--max-children=[Identifiers probed per directory]:N:_default' \
'--max-nodes=[Files the card selected across the whole walk (default 16384)]:N:_default' \
'--max-directories=[Directories whose children are enumerated]:N:_default' \
'--json[Emit one JSON envelope (type "ts48") on stdout, and nothing else]' \
'-b[Break after finding all files the card claims to have (DF count matches)]' \
'--scan-file-break[Break after finding all files the card claims to have (DF count matches)]' \
'--sfb[Break after finding all files the card claims to have (DF count matches)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__ts48__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ts48-help-command-$line[1]:"
        case $line[1] in
            (compare)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(batch)
_arguments "${_arguments_options[@]}" : \
'--plan=[The plan\: a \`sim-doctor-batch-plan/1\` JSON document naming every card, its ICCID and the commands to send it. Read and checked in full before any card is touched]:PATH:_files' \
'--state=[The state file. The only record of which cards are programmed and verified; its absence means the batch has not started, and an unreadable one stops the run rather than restarting it]:PATH:_files' \
'--reader=[The reader to use, matched against the driver'\''s own name (default\: the first reader)]:NAME:_default' \
'--on-failure=[Whether a card that failed lets the run go on to the next one. \`stop\` (the default) ends the run at the first failure; \`continue\` goes on and the report says which card was left behind and why. A swapped card stops the run either way]:WHAT:(stop continue)' \
'--batch-name=[The batch'\''s name, recorded in the state file (default\: the plan'\''s \`batch\`, or \`batch\`)]:NAME:_default' \
'--handler=[A feeder instead of a person\: \`get = command\`, \`done = command\` and \`error = command\`, one per line (\`#\` starts a comment). The command is run directly, not through a shell]:PATH:_files' \
'(--chv-env)--chv-file=[File holding PINs, PUKs and ADM keys for plan commands that need them (\`pin1=1234\` per line; keep it chmod 600). Never a value on the command line\: it would land in shell history]:PATH:_files' \
'--chv-env=[Environment variable holding the same text (entries separated by \`;\` or newlines)]:VAR:_default' \
'-X[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--exclusive[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--yes[Send the batch. Without it, every card'\''s plan is printed and not one byte is sent]' \
'--retry-failed[Attempt again a card an earlier run failed on for a reason that will not fix itself. Cards that failed because no card was there are retried without this]' \
'--json[Print one JSON envelope on stdout, and nothing else]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(install)
_arguments "${_arguments_options[@]}" : \
'--agent=[Install for one agent only; omit for all of them]:AGENT:(claude cursor codex opencode)' \
'--dir=[Project root to write under (default\: the current directory)]:DIR:_files' \
'--print-only[Print what would be written instead of writing it]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(ci)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_sim-doctor__subcmd__ci_commands" \
"*::: :->ci" \
&& ret=0

    case $state in
    (ci)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ci-command-$line[1]:"
        case $line[1] in
            (install)
_arguments "${_arguments_options[@]}" : \
'--swsim=[Build the software card on the runner (CI has no card otherwise)]:SWSIM:(true false)' \
'--baseline=[Committed baseline path (letters, digits and . _ / - only)]:PATH:_default' \
'--require-baseline=[Fail the job when the baseline file is missing]:REQUIRE_BASELINE:(true false)' \
'--severity=[Pass --severity to the scan]:SEVERITY:_default' \
'--ref=[The action ref to pin (default\: v<this version>; it exists once that release is cut)]:REF:_default' \
'--dir=[Project root to write under (default\: the current directory)]:DIR:_files' \
'--force[Overwrite a differing existing workflow]' \
'--print-only[Print the workflow instead of writing it]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__ci__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ci-help-command-$line[1]:"
        case $line[1] in
            (install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(completions)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':shell -- The shell to generate for:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(mcp)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(rules)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__rules_commands" \
"*::: :->rules" \
&& ret=0

    case $state in
    (rules)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-rules-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "rules" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(explain)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "rules" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
':id -- The rule id, such as gsma/msl-zero-allowed:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__rules__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-rules-help-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(explain)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(why)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "rules" on stdout]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':target -- A rule id, or the path of a saved `sim-doctor scan --json` envelope:_default' \
&& ret=0
;;
(fix)
_arguments "${_arguments_options[@]}" : \
'--from=[A saved \`sim-doctor scan --json\` envelope holding a finding for that rule]:FILE:_default' \
'--agent=[Start this coding agent with the prompt instead of only printing it]:AGENT:(claude codex cursor)' \
'--skip-approvals[Pass the agent its flag that skips approval prompts (unverified for every CLI version)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':rule_id -- The rule id to fix, such as gsma/msl-zero-allowed:_default' \
&& ret=0
;;
(gp)
_arguments "${_arguments_options[@]}" : \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__gp_commands" \
"*::: :->gp" \
&& ret=0

    case $state in
    (gp)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-command-$line[1]:"
        case $line[1] in
            (cert)
_arguments "${_arguments_options[@]}" : \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__gp__subcmd__cert_commands" \
"*::: :->cert" \
&& ret=0

    case $state in
    (cert)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-cert-command-$line[1]:"
        case $line[1] in
            (read)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(construct)
_arguments "${_arguments_options[@]}" : \
'--cert-serial=[Certificate Serial Number, tag 93, as hex]:HEX:_default' \
'--cert-ca=[CA Identifier, tag 42, as hex\: which issuer'\''s key signs this]:HEX:_default' \
'--cert-subject=[Subject Identifier, tag 5F20, as hex\: the security domain this certificate names]:HEX:_default' \
'--cert-usage=[Key Usage, tag 95\: \`verification\` (82 00) or \`agreement\` (00). GPC v2.3.1 11.1.9 defines no other value]:USAGE:_default' \
'--cert-effective=[Effective Date, tag 5F25, as YYYYMMDD]:YYYYMMDD:_default' \
'--cert-expires=[Expiration Date, tag 5F24, as YYYYMMDD. Mandatory in every profile of the format]:YYYYMMDD:_default' \
'--cert-image-number=[Security Domain Image Number, tag 45, as hex]:HEX:_default' \
'--cert-discretionary=[Discretionary Data, tag 53, as hex\: a field of unspecified format, passed through as given]:HEX:_default' \
'--cert-authorizations=[Authorization rules, tag BF20, as hex, per Amendment F v1.4 Table B-1. Passed through as given\: this tool does not interpret them]:HEX:_default' \
'--cert-pubkey=[Subject public key, tag 7F49\: the uncompressed NIST P-256 point as 130 hex digits (04 || X || Y). \`gp cert sign\` derives it from the signing key and does not need this; \`gp cert construct\` does, and has no key to derive it from]:HEX:_default' \
'--cert-out=[Where to write the certificate\: the whole 7F21 TLV. Nothing is written without it]:PATH:_files' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Print the certificate as one JSON object instead of the table]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
'--cert-serial=[Certificate Serial Number, tag 93, as hex]:HEX:_default' \
'--cert-ca=[CA Identifier, tag 42, as hex\: which issuer'\''s key signs this]:HEX:_default' \
'--cert-subject=[Subject Identifier, tag 5F20, as hex\: the security domain this certificate names]:HEX:_default' \
'--cert-usage=[Key Usage, tag 95\: \`verification\` (82 00) or \`agreement\` (00). GPC v2.3.1 11.1.9 defines no other value]:USAGE:_default' \
'--cert-effective=[Effective Date, tag 5F25, as YYYYMMDD]:YYYYMMDD:_default' \
'--cert-expires=[Expiration Date, tag 5F24, as YYYYMMDD. Mandatory in every profile of the format]:YYYYMMDD:_default' \
'--cert-image-number=[Security Domain Image Number, tag 45, as hex]:HEX:_default' \
'--cert-discretionary=[Discretionary Data, tag 53, as hex\: a field of unspecified format, passed through as given]:HEX:_default' \
'--cert-authorizations=[Authorization rules, tag BF20, as hex, per Amendment F v1.4 Table B-1. Passed through as given\: this tool does not interpret them]:HEX:_default' \
'--cert-pubkey=[Subject public key, tag 7F49\: the uncompressed NIST P-256 point as 130 hex digits (04 || X || Y). \`gp cert sign\` derives it from the signing key and does not need this; \`gp cert construct\` does, and has no key to derive it from]:HEX:_default' \
'--cert-out=[Where to write the certificate\: the whole 7F21 TLV. Nothing is written without it]:PATH:_files' \
'--cert-key-file=[File holding the P-256 signing key (chmod 600)]:PATH:_files' \
'--cert-key-env=[Environment variable holding the P-256 signing key]:VAR:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Print the certificate as one JSON object instead of the table]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-cert-help-command-$line[1]:"
        case $line[1] in
            (read)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(construct)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(info)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(ara)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'(--list --info)--json[Emit one JSON envelope of kind "gp" on stdout]' \
'(--info)--list[Print the registry as a table\: scope, AID, lifecycle, privileges]' \
'--info[Print each registry entry in detail, with its raw lifecycle and privilege bytes]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(select)
_arguments "${_arguments_options[@]}" : \
'--aid=[The application AID, 5 to 16 bytes of hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(crs)
_arguments "${_arguments_options[@]}" : \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__gp__subcmd__crs_commands" \
"*::: :->crs" \
&& ret=0

    case $state in
    (crs)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-crs-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
'--aid=[Narrow the listing to applications whose AID starts with these bytes]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(info)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(activate)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':aid -- The application AID, 5 to 16 bytes of hex:_default' \
&& ret=0
;;
(deactivate)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':aid -- The application AID, 5 to 16 bytes of hex:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-crs-help-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(activate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(deactivate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(channel)
_arguments "${_arguments_options[@]}" : \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__gp__subcmd__channel_commands" \
"*::: :->channel" \
&& ret=0

    case $state in
    (channel)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-channel-command-$line[1]:"
        case $line[1] in
            (open)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(close)
_arguments "${_arguments_options[@]}" : \
'--channel=[The channel to close, 1 to 19]:N:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-channel-help-command-$line[1]:"
        case $line[1] in
            (open)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(close)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(release-scp)
_arguments "${_arguments_options[@]}" : \
'--channel=[The logical channel whose secure channel is released, 1 to 19]:N:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--yes[Send the MANAGE CHANNEL close. Without it nothing is sent]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
'--aid=[The AID to delete, 5 to 16 bytes of hex]:HEX:_default' \
'--dm-key-file=[File holding the AES token calculation key (hex, optionally KEY/KCV; chmod 600)]:PATH:_files' \
'--dm-key-env=[Environment variable holding the AES token calculation key]:VAR:_default' \
'--dm-token-file=[File holding a Delegated Management token your Card Issuer already signed (2 to 510 hex digits; chmod 600)]:PATH:_files' \
'--dm-token-env=[Environment variable holding the Delegated Management token]:VAR:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--related[Also delete related objects (P2 80)\: for a load file, its applications]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(make-default)
_arguments "${_arguments_options[@]}" : \
'--aid=[The application AID, 5 to 16 bytes of hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(rename-isd)
_arguments "${_arguments_options[@]}" : \
'--new-aid=[The new ISD AID, 5 to 16 bytes of hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(delete-key)
_arguments "${_arguments_options[@]}" : \
'--key-id=[The Key Identifier to delete (GP tag D0). If absent, every key id matches and only --key-version narrows the delete]:HEX:_default' \
'--key-version=[The Key Version Number to delete (GP tag D2). If absent, every version matches and only --key-id narrows the delete]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--related[Also delete related objects (P2 80)]' \
'--allow-lockout[Send a delete that would remove the key set this session authenticated with, or every key on the card, as a WARNING instead of refusing it. Still needs --yes; without it nothing is sent]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(install)
_arguments "${_arguments_options[@]}" : \
'--load=[The CAP file (a zip of javacard/*.cap components)]:CAP:_files' \
'(--load --module --app --package --params)--update=[Update the registry entry of this instance AID\: INSTALL \[for registry update\] (P1 40). The privileges and the install parameters sent REPLACE what the card holds, for good; the code of the applet is not replaced and the instance is not removed. Refuses --load, --package, --module, --app and --params]:HEX:_default' \
'(--update)--package=[The Executable Load File (package) AID. With --install-only, where no CAP is read, it names the package on the card. Defaults to the CAP package AID]:HEX:_default' \
'(--update)--module=[The Executable Module AID (the applet class). Optional when the CAP has one applet, and with --install-only it defaults to --app, then to --package]:HEX:_default' \
'(--update)--app=[The application (instance) AID. Defaults to the module AID]:HEX:_default' \
'(--update)--params=[The Install Parameters field as TLV with the mandatory C9 tag (default C900\: none; required with --no-felix)]:HEX:_default' \
'--privileges=[Privileges, 1 or 3 bytes of hex (default 000000). Card Lock and Card Terminate are refused. With --update, 000000 omits the field, which leaves the privileges the card holds alone]:HEX:_default' \
'--bs=[Data bytes per LOAD block, 1 to 247 (default 240; 255 minus the 8-byte SCP03 C-MAC). The load file is cut into blocks of this size, so a smaller one sends more, shorter LOAD commands. Changes only how the file is split\: the bytes loaded are the same. Shown in the dry run'\''s APDUs]:BYTES:_default' \
'*--cl-notify=[--cl-notify AID\: add this AID to the CREL notify list (EF A1 A3 4F). Repeatable; the AIDs go into one list in the order given]:AID:_default' \
'*--cl-notify-remove=[--cl-notify-remove AID\: remove this AID from the CREL notify list (EF A1 A4 4F). Repeatable. An AID given here and to --cl-notify is refused\: the card cannot be told to add and remove the same entry]:AID:_default' \
'--cl-family=[--cl-family HEX\: the Application Family id, one byte of hex (EF A1 87)]:HEX:_default' \
'--dap-key-file=[File holding the DAP keys (hex, one key per DAP block, optionally KEY/KCV; chmod 600). Several keys are several DAP blocks (Table 11-58)]:PATH:_files' \
'--dap-key-env=[Environment variable holding the DAP keys]:VAR:_default' \
'*--dap-domain=[The Security Domain that verifies a DAP block, 5 to 16 bytes of hex. Repeat it once per DAP block\: a Load File may carry several (Table 11-58). Without it every block is verified by the issuer security domain being authenticated]:HEX:_default' \
'--dap-alg=[The signature scheme of every key (GP Card Spec v2.3.1 C.3)\: AES-CMAC (B.2.2), the DES retail MAC (B.1.2.2) or ECDSA over P-256 (B.4.3). There is no RSA scheme\: this crate cannot sign RSASSA-PKCS1-v1_5 (B.3.1.1) or RSASSA-PSS (B.3.2.1)]:DAP_ALG:((aes\:"AES-CMAC (B.2.2)\: a 16 byte signature"
des\:"Single DES plus final triple DES MAC (B.1.2.2)\: an 8 byte signature"
ecc\:"ECDSA over P-256 with SHA-256 (B.4.3)\: plain \`r || s\`, 64 bytes"))' \
'--dap-hash=[The Load File Data Block Hash the DAP signs]:DAP_HASH:(sha256 sha384 sha512)' \
'--dm-key-file=[File holding the AES token calculation key (hex, optionally KEY/KCV; chmod 600)]:PATH:_files' \
'--dm-key-env=[Environment variable holding the AES token calculation key]:VAR:_default' \
'--dm-token-file=[File holding a Delegated Management token your Card Issuer already signed (2 to 510 hex digits; chmod 600)]:PATH:_files' \
'--dm-token-env=[Environment variable holding the Delegated Management token]:VAR:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'(--load --update)--install-only[Send INSTALL \[for install and make selectable\] only\: the module is already on the card. Refuses --load; needs --package]' \
'-F[Refuse to guess the install parameters\: --params becomes required (GlobalPlatformPro -F / --no-felix, issue #253)]' \
'--no-felix[Refuse to guess the install parameters\: --params becomes required (GlobalPlatformPro -F / --no-felix, issue #253)]' \
'(--update)--make-default[Make the applet default selected\: sets the Card Reset privilege, 0x04 in the first privilege byte (GP Card Spec v2.3.1 table 11-7, the bit GlobalPlatformPro'\''s --make-default sets). The card then selects this applet by default after reset, so it changes what the card runs first]' \
'--cl-activated[--cl-activated\: set the contactless activation state byte (EF A0 81)]' \
'--cl-display-optional[--cl-display-optional\: the display is not required for this application (EF A1 88 01)]' \
'--cl-contact[--cl-contact\: enable the contact interface (EF A0 A5 82, bit 80)]' \
'--cl-contactless[--cl-contactless\: enable the contactless interface (EF A0 A5 82, bit 40). With --cl-contact the mask is C0, both interfaces]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(create-sd)
_arguments "${_arguments_options[@]}" : \
'--domain=[The AID of the Security Domain to create, 5 to 16 bytes of hex]:HEX:_default' \
'--privileges=[Privileges, 1 or 3 bytes of hex (default 000000). The Security Domain privilege is always added. Card Lock and Card Terminate are refused]:HEX:_default' \
'--scp=[Secure Channel Protocol Information for the new domain (tag 81), hex]:HEX:_default' \
'--params=[Extra Install Parameter TLVs, without a C9 tag, hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--allow-to[allow-to (tag 82)\: any class may be extradited into the new domain]' \
'--allow-from[allow-from (tag 87)\: the new domain may be extradited out of it]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(put-key)
_arguments "${_arguments_options[@]}" : \
'--new-key-version=[The Key Version Number of the new keys, 01 to 7F]:HEX:_default' \
'--replace-key-version=[P1\: 00 (default) adds the key set; 01 to 7F replaces the key set with that version]:HEX:_default' \
'--key-id=[The Key Identifier of the first key (the other two follow at +1 and +2)]:HEX:_default' \
'--new-keys-file=[File holding the new keys (keep it chmod 600)]:PATH:_files' \
'--new-keys-env=[Environment variable holding the new keys]:VAR:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--replace-current-keyset[Allow the request to add, replace or overwrite the key version this session authenticated with. Without it such a request is refused]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(cplc-set)
_arguments "${_arguments_options[@]}" : \
'--kind=[pre-perso (DGI 9F67) or perso (DGI 9F66)]:KIND:(pre-perso perso)' \
'--data=[The eight data bytes of the block as 16 hex digits]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--today[Write today'\''s date (UTC) into the date bytes, overriding those in --data]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(personalize)
_arguments "${_arguments_options[@]}" : \
'--aid=[The application or Security Domain AID, 5 to 16 bytes of hex]:HEX:_default' \
'--data=[The BER-TLV personalization data, as hex; sent as the STORE DATA body]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(aram)
_arguments "${_arguments_options[@]}" : \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__gp__subcmd__aram_commands" \
"*::: :->aram" \
&& ret=0

    case $state in
    (aram)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-aram-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
'--aid=[The application the rule is for\: 5 to 16 bytes of hex, or the empty string for the empty AID-REF-DO that names every application]:HEX:_default' \
'--device-app-id=[The device application'\''s certificate hash or UUID, 20 or 32 bytes of hex. Empty (the default) matches any device application]:HEX:_default' \
'--pkg-ref=[The Android package name (PKG-REF-DO, an AOSP extension)]:NAME:_default' \
'(--apdu-never --apdu-always)--apdu-filter=[An APDU filter\: groups of 16 hex digits, 4 for CLA INS P1 P2 then 4 for the mask, repeated]:HEX:_default' \
'--android-permissions=[The eight Android UICC Carrier Privilege permission bytes (PERM-AR-DO, an AOSP extension)]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'(--aid)--aid-empty[No specific application\: the implicitly selected one on every channel (AID-REF-EMPTY-DO, C0)]' \
'(--apdu-always --apdu-filter)--apdu-never[Never allow the application'\''s APDUs (APDU-AR-DO D0 01 00)]' \
'(--apdu-never --apdu-filter)--apdu-always[Always allow the application'\''s APDUs (APDU-AR-DO D0 01 01)]' \
'(--nfc-always)--nfc-never[Never deliver the application'\''s NFC events (NFC-AR-DO D1 01 00)]' \
'(--nfc-never)--nfc-always[Always deliver the application'\''s NFC events (NFC-AR-DO D1 01 01)]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(delete-all)
_arguments "${_arguments_options[@]}" : \
'--confirm-delete-all=[Required acknowledgement beyond --yes\: the literal DELETE-ALL]:TEXT:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(lock)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(config)
_arguments "${_arguments_options[@]}" : \
'--major=[The major part of the device interface version to offer]:MAJOR:_default' \
'--minor=[The minor part of the device interface version to offer]:MINOR:_default' \
'--patch=[The patch part of the device interface version to offer]:PATCH:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-aram-help-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-all)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lock)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(config)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(move)
_arguments "${_arguments_options[@]}" : \
'--aid=[The AID of the object to move, 5 to 16 bytes of hex]:HEX:_default' \
'--from=[The AID of the Security Domain the object is in now, 5 to 16 bytes of hex. Checked against the object in the registry before anything is sent]:HEX:_default' \
'--to=[The AID of the destination Security Domain, 5 to 16 bytes of hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(receipt)
_arguments "${_arguments_options[@]}" : \
'(--response)--receipt=[The receipt bytes on their own, hex. Use --response to hand over the whole response instead]:HEX:_default' \
'--response=[The Data field of the card'\''s whole response, hex\: the Confirmation Structure of Table 11-13]:HEX:_default' \
'--confirmation-data=[The Confirmation Data the receipt is bound to (Table 11-14), hex. Needed with --receipt, because the signature covers it and it is not part of the receipt]:HEX:_default' \
'--kind=[Which receipt this is. It fixes which AIDs the signature covers]:KIND:_default' \
'--elf-aid=[Executable Load File AID, 5 to 16 bytes of hex (load, install, combined)]:HEX:_default' \
'--sd-aid=[Security Domain AID, 5 to 16 bytes of hex (load, combined)]:HEX:_default' \
'--app-aid=[Instance AID (install, combined), the deleted AID (delete), the application or ELF AID (extradite), the application AID (registry update). 5 to 16 bytes of hex]:HEX:_default' \
'--from-aid=[Old Security Domain AID (extradite, registry update), 5 to 16 bytes]:HEX:_default' \
'--to-aid=[New Security Domain AID (extradite, registry update), 5 to 16 bytes]:HEX:_default' \
'--privileges=[Privileges being written, 0 to 3 bytes of hex (registry update)]:HEX:_default' \
'--registry-params=[Registry Update Parameters being written, hex (registry update)]:HEX:_default' \
'--receipt-key-file=[File holding the receipt generation key (keep it chmod 600)]:PATH:_files' \
'--receipt-key-env=[Environment variable holding the receipt generation key]:VAR:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(store-data)
_arguments "${_arguments_options[@]}" : \
'--data=[The data field as hex, sent exactly as given]:HEX:_default' \
'--dgi-tag=[A DGI tag, 1 to 4 hex digits, e.g. 0036, 8137 or 9F66]:HEX:_default' \
'--dgi-value=[That DGI'\''s value as hex\: the BER-TLVs it carries]:HEX:_default' \
'--emv-perso=[EMV PersoData (DGI 9F66)\: exactly 8 bytes of hex]:HEX:_default' \
'--emv-pre-perso=[EMV PrePersoData (DGI 9F67)\: exactly 8 bytes of hex]:HEX:_default' \
'--structure=[P1 b5-b4\: none (00), dgi (01), ber-tlv (10). Defaults to dgi for a --dgi-tag, --emv-perso or --emv-pre-perso payload, none otherwise]:STRUCTURE:(none dgi ber-tlv)' \
'--encryption=[P1 b7-b6\: none (00), app (01), encrypted (11)]:PROTECTION:(none app encrypted)' \
'--block-size=[Data field bytes per block, 1 to 255]:BYTES:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--response[P1 b1\: let the card answer each block]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(secure-apdu)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-P+[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--profile=[Use a named card profile instead of the built-in default (#238)]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':apdu -- The APDU as hex\: CLA INS P1 P2, then Lc and the data, then Le, as the card would receive it (for example 00A40000023F00):_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-help-command-$line[1]:"
        case $line[1] in
            (cert)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert_commands" \
"*::: :->cert" \
&& ret=0

    case $state in
    (cert)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-help-cert-command-$line[1]:"
        case $line[1] in
            (read)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(construct)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ara)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(select)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(crs)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs_commands" \
"*::: :->crs" \
&& ret=0

    case $state in
    (crs)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-help-crs-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(activate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(deactivate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(channel)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel_commands" \
"*::: :->channel" \
&& ret=0

    case $state in
    (channel)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-help-channel-command-$line[1]:"
        case $line[1] in
            (open)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(close)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(release-scp)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(make-default)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rename-isd)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-key)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(create-sd)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(put-key)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(cplc-set)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(personalize)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(aram)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram_commands" \
"*::: :->aram" \
&& ret=0

    case $state in
    (aram)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-gp-help-aram-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-all)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lock)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(config)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(move)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(receipt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(store-data)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(secure-apdu)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(trace)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "trace" on stdout]' \
'--show-raw-apdu[Also print each exchange'\''s raw command and response hex in the table]' \
'--no-suppress-select[Keep SELECT rows in the table. They are hidden by default, as in pySim-trace]' \
'--no-suppress-status[Keep UICC STATUS rows in the table. They are hidden by default, as in pySim-trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::file -- A trace file; stdin when omitted or "-":_default' \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__cat_commands" \
"*::: :->cat" \
&& ret=0

    case $state in
    (cat)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-cat-command-$line[1]:"
        case $line[1] in
            (decode)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "cat" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
'*::hex -- Hex of a proactive command, envelope, terminal response or comprehension TLVs (spaces and `0x` allowed); stdin, one per line, when none is given or for "-":_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__cat__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-cat-help-command-$line[1]:"
        case $line[1] in
            (decode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(sms)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_sim-doctor__subcmd__sms_commands" \
"*::: :->sms" \
&& ret=0

    case $state in
    (sms)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-sms-command-$line[1]:"
        case $line[1] in
            (decode)
_arguments "${_arguments_options[@]}" : \
'--tpdu[The hex is a bare TPDU, without the leading SMSC address the PDU format carries]' \
'--json[Emit one JSON envelope of kind "sms" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
'*::hex -- Hex of a PDU (spaces and `0x` allowed); stdin, one per line, when none is given or for "-":_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__sms__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-sms-help-command-$line[1]:"
        case $line[1] in
            (decode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(saip)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_sim-doctor__subcmd__saip_commands" \
"*::: :->saip" \
&& ret=0

    case $state in
    (saip)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-saip-command-$line[1]:"
        case $line[1] in
            (parse)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "saip" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
':file -- Path to the profile package. Read-only; the file is capped at 8 MiB:_files' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__saip__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-saip-help-command-$line[1]:"
        case $line[1] in
            (parse)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(ota-crypto)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_sim-doctor__subcmd__ota-crypto_commands" \
"*::: :->ota-crypto" \
&& ret=0

    case $state in
    (ota-crypto)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ota-crypto-command-$line[1]:"
        case $line[1] in
            (encrypt)
_arguments "${_arguments_options[@]}" : \
'--alg=[DES (8-byte key), 3DES (16- or 24-byte key) or AES (16/24/32-byte key)]:ALG:((des\:""
3des\:"2-key (16-byte) or 3-key (24-byte) Triple DES"
aes\:"AES-128, AES-192 or AES-256 from the key length"))' \
'--key=[The key as hex; length selects the AES variant (16/24/32) or must match the algorithm (DES 8, 3DES 16 or 24)]:HEX:_default' \
'--iv=[The IV as hex (one block); all zeros when absent]:HEX:_default' \
'--json[Emit one JSON envelope of kind "ota-crypto" on stdout]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':data -- The data to encrypt, as hex:_default' \
&& ret=0
;;
(decrypt)
_arguments "${_arguments_options[@]}" : \
'--alg=[]:ALG:((des\:""
3des\:"2-key (16-byte) or 3-key (24-byte) Triple DES"
aes\:"AES-128, AES-192 or AES-256 from the key length"))' \
'--key=[]:HEX:_default' \
'--iv=[The IV as hex (one block); all zeros when absent]:HEX:_default' \
'--json[]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':data -- The ciphertext to decrypt, as hex:_default' \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
'--alg=[]:ALG:((des\:""
3des\:"2-key (16-byte) or 3-key (24-byte) Triple DES"
aes\:"AES-128, AES-192 or AES-256 from the key length"))' \
'--key=[]:HEX:_default' \
'--mac-len=[Length of the MAC to return (default 8, the OTA checksum length)]:N:_default' \
'--json[]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':data -- The data to sign, as hex:_default' \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
'--alg=[]:ALG:((des\:""
3des\:"2-key (16-byte) or 3-key (24-byte) Triple DES"
aes\:"AES-128, AES-192 or AES-256 from the key length"))' \
'--key=[]:HEX:_default' \
'--mac=[The expected MAC as hex; its length sets the MAC length]:HEX:_default' \
'--json[]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':data -- The data that was signed, as hex:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__ota-crypto__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ota-crypto-help-command-$line[1]:"
        case $line[1] in
            (encrypt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decrypt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(esim-cert)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__esim-cert_commands" \
"*::: :->esim-cert" \
&& ret=0

    case $state in
    (esim-cert)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-esim-cert-command-$line[1]:"
        case $line[1] in
            (verify)
_arguments "${_arguments_options[@]}" : \
'--root=[The CI root you trust\: a file holding exactly one certificate, PEM or DER]:ROOT:_default' \
'--at=[Check validity at this UTC time, YYYYMMDDHHMMSS, instead of now]:YYYYMMDDHHMMSS:_default' \
'--json[Emit one JSON envelope of kind "esim-cert" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
':chain -- The chain file\: PEM with CERTIFICATE blocks, or concatenated DER, leaf first:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__esim-cert__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-esim-cert-help-command-$line[1]:"
        case $line[1] in
            (verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(ota-expanded)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__ota-expanded_commands" \
"*::: :->ota-expanded" \
&& ret=0

    case $state in
    (ota-expanded)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ota-expanded-command-$line[1]:"
        case $line[1] in
            (encode)
_arguments "${_arguments_options[@]}" : \
'--indefinite[Use the indefinite length coding (tag AE 80 ... 00 00, TS 102 226 table 5.2a) instead of the default definite one (tag AA, table 5.2). TS 102 226 recommends the indefinite coding only for HTTPS and CoAP, not for SMS]' \
'--json[Emit one JSON envelope of kind "ota-expanded" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
'*::c_apdu -- The C-APDUs to script, hex (spaces and `0x` allowed), one per argument:_default' \
&& ret=0
;;
(decode)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope of kind "ota-expanded" on stdout]' \
'-h[Print help]' \
'--help[Print help]' \
'::hex -- Hex of the template (spaces and `0x` allowed); stdin when omitted or "-":_default' \
&& ret=0
;;
(por)
_arguments "${_arguments_options[@]}" : \
'--remote-format=[Read the secure data as a compact (TS 102 226 5.1.2) or expanded (5.2.2) Remote Application response]:REMOTE_FORMAT:((compact\:"TS 102 226 clause 5.1.2"
expanded\:"TS 102 226 clause 5.2.2, a Response Scripting template"))' \
'--json[Emit one JSON envelope of kind "ota-expanded" on stdout]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::hex -- Hex of the Response Packet, or of `02 71 00` followed by it; stdin when omitted or "-":_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__ota-expanded__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-ota-expanded-help-command-$line[1]:"
        case $line[1] in
            (encode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(por)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(keygen)
_arguments "${_arguments_options[@]}" : \
'-z+[File holding the secret (keep it chmod 600). Surrounding whitespace, the trailing newline an editor adds, is stripped]:PATH:_files' \
'--secret-file=[File holding the secret (keep it chmod 600). Surrounding whitespace, the trailing newline an editor adds, is stripped]:PATH:_files' \
'--secret-env=[Environment variable holding the secret]:VAR:_default' \
'-j+[Card number\: the Nth card of the batch, which makes every field of it reproducible for as long as the secret is. Without it a fresh salt is drawn from the OS on each run, the way pySim draws Ki from urandom]:N:_default' \
'--index=[Card number\: the Nth card of the batch, which makes every field of it reproducible for as long as the secret is. Without it a fresh salt is drawn from the OS on each run, the way pySim draws Ki from urandom]:N:_default' \
'--salt=[Random mode'\''s salt, 64 hex digits. It is printed with the card, so this is how a printed random card is regenerated. It is a public input, not a secret]:HEX:_default' \
'--mcc=[Mobile Country Code, 1 to 3 decimal digits, zero-padded to 3]:DIGITS:_default' \
'--mnc=[Mobile Network Code, at most --mnclen digits, zero-padded to that width]:DIGITS:_default' \
'--mnclen=[Width of the MNC\: 2 or 3, or 0 to keep the MNC'\''s own length (pySim'\''s \`auto\`)]:DIGITS:_default' \
'--json[Emit one JSON envelope of kind "keygen" on stdout]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(fuzz)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__fuzz_commands" \
"*::: :->fuzz" \
&& ret=0

    case $state in
    (fuzz)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-fuzz-command-$line[1]:"
        case $line[1] in
            (apdu)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--level=[1 for CLA discovery, 2 for CLA+INS discovery]:LEVEL:_default' \
'--class=[The CLA level 2 probes INS values at, as two hex digits (e.g. A0). Required for --level 2]:HEX:_default' \
'--i-understand-this-can-brick-the-card[Required. Without it, \`fuzz\` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)]' \
'--allow-real-hardware[Required in addition to the opt-in above when the reader'\''s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, \`fuzz\` refuses to run against anything that is not recognisably the software card]' \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'--quick[Probe a small, documented subset instead of the full space]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(ota)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--kic=[Pin the KIC octet (one hex byte, like 21) for every probe instead of sweeping it from the keyset. Header octet, not key material]:HEX:_default' \
'--kid=[Pin the KID octet (one hex byte, like 31) for every probe instead of sweeping it from the keyset. Header octet, not key material]:HEX:_default' \
'--spi1=[Pin the SPI1 octet (one hex byte, like 01) in every probe instead of sweeping it]:HEX:_default' \
'--spi2=[Pin the SPI2 octet (one hex byte, like 29) in every probe instead of sweeping it]:HEX:_default' \
'--class=[The class byte the ENVELOPE and its CAT follow-ups are sent at\: etsi (CLA 80, the default) or gsm (CLA A0).]:CLASS:((etsi\:"CLA \`0x80\`, ETSI TS 102 221 clause 10.1.2. The default"
gsm\:"CLA \`0xA0\`, GSM 11.11. \`--class gsm\`"))' \
'(--quick --poke --kic --kid --spi1 --spi2)--passthrough=[Vary TP-PID, TP-DCS, the TP-UDHI flag and the Command Packet Header inside one SMS-PP-DOWNLOAD, as SIMTester'\''s OTA fuzzer does, instead of sweeping TAR x keyset x mechanism]:MODE:((default\:"SIMTester'\''s -of\: four PIDs, nine DCS values, six CPHs, UDHI both ways. 432 envelopes, which fit the budget and run whole"
bruteforce\:"SIMTester'\''s -ofbf\: every PID and DCS octet. 786432 envelopes, which do not fit the budget, so this is a capped partial sweep and says so"))' \
'--i-understand-this-can-brick-the-card[Required. Without it, \`fuzz\` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)]' \
'--allow-real-hardware[Required in addition to the opt-in above when the reader'\''s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, \`fuzz\` refuses to run against anything that is not recognisably the software card]' \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'--quick[Probe a small, documented subset instead of the full space]' \
'(--quick)--poke[Like \`--quick\`, but probes only the three TARs SIMTester'\''s \`-poke\` probes\: 000000, B00001 and B00010 - the quick keysets and mechanisms still apply, so a run finishes in milliseconds]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(mutate)
_arguments "${_arguments_options[@]}" : \
'(--mock)--replay=[Answer from a recorded exchange log (one {"command","response"} JSON object per line, as SIM_DOCTOR_RECORD writes) instead of a card]:FILE:_files' \
'--max-cases=[Cases to send (1 to 10000)]:N:_default' \
'--timeout=[Stop sending after this many seconds]:SECONDS:_default' \
'--seed=[PRNG seed. The same seed gives the same APDUs]:SEED:_default' \
'--mock[Answer from the built-in strict mock card]' \
'--dry-run[Print the planned APDUs and the allowlist/denylist; send nothing]' \
'--stop-on-first-finding[Stop after the first finding]' \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(compare)
_arguments "${_arguments_options[@]}" : \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
'*::files -- Two or more `fuzz ota --json` result files, each at most 8 MiB:_files' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__fuzz__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-fuzz-help-command-$line[1]:"
        case $line[1] in
            (apdu)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ota)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(mutate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(compare)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(euicc)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_sim-doctor__subcmd__euicc_commands" \
"*::: :->euicc" \
&& ret=0

    case $state in
    (euicc)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-euicc-command-$line[1]:"
        case $line[1] in
            (info)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(profiles)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(challenge)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(get-certs)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(get-eim-configuration-data)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(notifications)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
":: :_sim-doctor__subcmd__euicc__subcmd__notifications_commands" \
"*::: :->notifications" \
&& ret=0

    case $state in
    (notifications)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-euicc-notifications-command-$line[1]:"
        case $line[1] in
            (remove)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send the request, then re-read the list and confirm. Without it nothing is changed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':seq -- Sequence number of the notification, as `euicc notifications` lists it:_default' \
&& ret=0
;;
(dump)
_arguments "${_arguments_options[@]}" : \
'--seq=[Only the notification with this sequence number (default\: all pending)]:N:_default' \
'-o+[Write the dump document to FILE (must not exist) instead of stdout]:FILE:_files' \
'--output=[Write the dump document to FILE (must not exist) instead of stdout]:FILE:_files' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(replay)
_arguments "${_arguments_options[@]}" : \
'--from=[A dump file written by \`notifications dump\` (or its \`--json\` output)]:FILE:_files' \
'--yes[Actually send. Without it nothing leaves this machine\: the targets and what would be sent are printed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-euicc-notifications-help-command-$line[1]:"
        case $line[1] in
            (remove)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(dump)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(replay)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(nickname)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send SetNickname, then re-read the profile list and confirm. Without it nothing is changed\: the target EID and ICCID, the current and the new nickname are printed and the command exits]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':iccid -- ICCID of the profile (18 to 20 digits):_default' \
':name -- The new nickname, at most 64 bytes of UTF-8; "" clears it:_default' \
&& ret=0
;;
(enable)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send the request, then re-read the profile list and confirm. Without it nothing is changed\: the plan and its consequence are printed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':id -- ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile:_default' \
&& ret=0
;;
(disable)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send the request, then re-read the profile list and confirm. Without it nothing is changed\: the plan and its consequence are printed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':id -- ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile:_default' \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send DeleteProfile, then re-read the profile list and confirm. Without it nothing is changed\: the profile and its consequence are printed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':id -- ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile:_default' \
&& ret=0
;;
(reset)
_arguments "${_arguments_options[@]}" : \
'--confirm-eid=[The card'\''s EID (32 hex digits); must match the EID read from the card]:EID:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--operational[Delete the operational profiles (resetOptions bit 0)]' \
'--test[Delete the field-loaded test profiles (resetOptions bit 1)]' \
'--smdp-address[Reset the default SM-DP+ address (resetOptions bit 2)]' \
'--yes[Send the reset (needs \`--confirm-eid\`), then re-read and confirm. Without it nothing is changed\: the profiles that would be erased are listed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(set-default-dp)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send SetDefaultDpAddress, then re-read the configured addresses and confirm. Without it nothing is sent and no reader is opened\: the exact request bytes are printed]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
':address -- The new default SM-DP+ address, as a UTF-8 string:_default' \
&& ret=0
;;
(store-data)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--aid=[ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)]:HEX:_default' \
'--max-segment=[Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks]:BYTES:_default' \
'--yes[Send it. Without it nothing is sent and no card is contacted\: the STORE DATA blocks it would become are printed, each with its CLA/INS/P1/P2/Lc and payload bytes, and \`card_touched\` is false]' \
'--json[Emit one lpac envelope on stdout, and nothing else]' \
'-h[Print help]' \
'--help[Print help]' \
'::payload -- The ES10x request as hex\: `BF3E00`, `bf 3e 00`, `bf3e\:00` and `0xBF3E00` all parse. `-`, or no argument at all, reads it from stdin. Bounded\: more than 8192 bytes is refused:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__euicc__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-euicc-help-command-$line[1]:"
        case $line[1] in
            (info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(profiles)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(challenge)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(get-certs)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(get-eim-configuration-data)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(notifications)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications_commands" \
"*::: :->notifications" \
&& ret=0

    case $state in
    (notifications)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-euicc-help-notifications-command-$line[1]:"
        case $line[1] in
            (remove)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(dump)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(replay)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(nickname)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enable)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(disable)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reset)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set-default-dp)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(store-data)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(card)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name (default\: the first reader)]:NAME:_default' \
'--profile=[The command set the card speaks\: uicc (class 00) or sim (class A0, GSM 11.11)]:PROFILE:(uicc sim)' \
'--dialect=[Which FCP tag table the card answers SELECT with (see \`scan --help\`)]:TABLE:_default' \
'(--script)-c+[Run these \`;\`-separated commands and exit]:COMMANDS:_default' \
'--script=[Run the commands in this file, one per line (\`#\` starts a comment), and exit]:PATH:_files' \
'(-c --script)--read-csv=[Run the commands in the \`command\` column of this CSV file, one per row, and exit. This is a command table, not pySim'\''s provisioning CSV (a file with iccid and imsi columns is checked as that layout instead, with no card write). Each row is one command exactly as typed; without \`--yes\` a row that changes the card is a dry run. WARNING\: terminate_df, terminate_ef, terminate_card_usage and deactivate_file can permanently disable a file or the card, and delete_data and delete_all permanently destroy data]:PATH:_files' \
'--write-csv=[Append a redacted result log to this CSV file\: one row per command run (\`command,ok,text\`), with the arguments replaced by \`<args redacted>\`. It is not pySim'\''s provisioning CSV and cannot be read back as one. A new file starts with the header row; blank and comment lines are not logged]:PATH:_files' \
'(--chv-env)--chv-file=[File holding PINs, PUKs and ADM keys for \`verify_chv\` / \`unblock_chv\` (\`pin1=1234\` per line; keep it chmod 600). Never a value on the command line\: it would land in shell history]:PATH:_files' \
'--chv-env=[Environment variable holding the same text (entries separated by \`;\` or newlines)]:VAR:_default' \
'--key-file=[pySim CardKeyProvider CSV file for \`query_card_key\` (ICCID,ADM1,OPC,...; one card per row). Read and checked before any reader is opened; secrets are never printed unless named in --fields. Keep it chmod 600]:PATH:_files' \
'--card-key-csv=[CSV card key provider, as pySim'\''s \`--csv\`\: a version-marked CSV whose key columns are encrypted at rest. Answers for the values \`--chv-file\` / \`--chv-env\` do not hold]:PATH:_files' \
'(--card-key-key-env)--card-key-key=[File holding the per-column transport keys that decrypt the CSV (\`PIN1=<hex>\` per line, keep it chmod 600). Never a value on the command line\: it would land in shell history]:PATH:_files' \
'(--card-key-key)--card-key-key-env=[Environment variable holding the same transport key text]:VAR:_default' \
'--dump=[Write every APDU exchange (command and response, hex) to FILE as JSON lines, in the SIM_DOCTOR_RECORD replay format. The data field of secret instructions (VERIFY, CHANGE, ENABLE/DISABLE, RESET RETRY COUNTER, AUTHENTICATE) is redacted as FF bytes, and so are the response data of AUTHENTICATE (RES, CK, IK, Kc); such lines carry "redacted"\:true and no longer replay byte for byte. --dump-secrets records them raw. The file holds raw card data (ICCID, IMSI, file contents)\: review it before it goes anywhere. Refuses an existing file unless --force; never writes through a symlink or into a non-regular file. The file is owner-only (0600)]:FILE:_files' \
'--json[Print every reply as one JSON record (for agents)]' \
'-X[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this shell is open. Off by default, which shares it]' \
'--exclusive[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this shell is open. Off by default, which shares it]' \
'--yes[Send the commands that change the card (APDUs outside the read-only set, PIN checks, ...). Without it they print what they would send and the card is not touched by them]' \
'--force[Let --dump overwrite an existing regular file]' \
'--dump-secrets[Record PINs and keys in plain text\: the data field of VERIFY, CHANGE, ENABLE/DISABLE, RESET RETRY COUNTER and AUTHENTICATE, and the response data of AUTHENTICATE (RES, CK, IK, Kc), is written raw. Keep the file private. Needs --dump]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(erase)
_arguments "${_arguments_options[@]}" : \
'--class=[The pySim card class being erased\: it decides which provisioning EFs are written and their record lengths (18/130/102 for magicsim, 18/74/50 for supersim, one EF of 18 for fakemagicsim). Required]:CLASS:(magicsim supersim fakemagicsim)' \
'--records=[How many record slots of each file to erase. Required, and never defaulted\: the reference derives it from the card]:N:_default' \
'--confirm-iccid=[The ICCID of the card to erase, as the reports print it. Read from EF.ICCID and compared before the first write; a card that is not this one is refused and nothing is erased]:ICCID:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--mode=[SCP03 security level of the secure channel\: mac (01, C-MAC only, the default), enc (03, command encryption), rmac (11), renc (31) or all (33). Any other level is refused before a reader is opened]:MODE:((mac\:"01\: C-MAC only"
enc\:"03\: C-MAC and command encryption (the card decrypts\: C-DECRYPTION)"
rmac\:"11\: C-MAC and R-MAC"
renc\:"31\: C-MAC, R-MAC and R-ENC"
all\:"33\: all four protections"))' \
'--key-kdf=[Diversify ONE master key from the key text with this KDF template, using the key diversification data the card returns in INITIALIZE UPDATE, and authenticate with the result (kdf3 is the SCP03 one; emv, visa2 and visa are 3DES and are refused). Known-answer tested against GlobalPlatformPro'\''s own vectors. The keys stay in the file or the environment variable\: a template name is not key material]:TEMPLATE:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'-X[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--exclusive[Open the reader in exclusive mode (PC/SC SCARD_SHARE_EXCLUSIVE)\: no other process can use the card while this runs. Off by default, which shares it]' \
'--dry-run[Print the plan and send nothing. This is already what happens without --yes; asking for it explicitly is still refused beside --yes, because one of the two asks for a send and the other asks for no send]' \
'--yes[Send the erase. Needs --class, --records, --confirm-iccid and a key source]' \
'--json[Emit one JSON envelope of kind "program-erase" on stdout]' \
'--s16[Speak the SCP03 S16 profile\: a 16-byte host challenge, and 16-byte cryptograms and C-MACs. Only a card that announces S16 (bit 0x01 of the "i" parameter) answers it, and a card that does not stops the run with nothing else sent]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-command-$line[1]:"
        case $line[1] in
            (modules)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(readers)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(scan)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(profile)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__profile_commands" \
"*::: :->profile" \
&& ret=0

    case $state in
    (profile)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-profile-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(probe)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(match)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(cards)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__cards_commands" \
"*::: :->cards" \
&& ret=0

    case $state in
    (cards)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-cards-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fixture)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(ts48)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__ts48_commands" \
"*::: :->ts48" \
&& ret=0

    case $state in
    (ts48)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-ts48-command-$line[1]:"
        case $line[1] in
            (compare)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(batch)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ci)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__ci_commands" \
"*::: :->ci" \
&& ret=0

    case $state in
    (ci)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-ci-command-$line[1]:"
        case $line[1] in
            (install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(mcp)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rules)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__rules_commands" \
"*::: :->rules" \
&& ret=0

    case $state in
    (rules)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-rules-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(explain)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(why)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fix)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gp)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__gp_commands" \
"*::: :->gp" \
&& ret=0

    case $state in
    (gp)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-gp-command-$line[1]:"
        case $line[1] in
            (cert)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert_commands" \
"*::: :->cert" \
&& ret=0

    case $state in
    (cert)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-gp-cert-command-$line[1]:"
        case $line[1] in
            (read)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(construct)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ara)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(select)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(crs)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs_commands" \
"*::: :->crs" \
&& ret=0

    case $state in
    (crs)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-gp-crs-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(activate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(deactivate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(channel)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel_commands" \
"*::: :->channel" \
&& ret=0

    case $state in
    (channel)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-gp-channel-command-$line[1]:"
        case $line[1] in
            (open)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(close)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(release-scp)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(make-default)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rename-isd)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-key)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(create-sd)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(put-key)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(cplc-set)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(personalize)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(aram)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram_commands" \
"*::: :->aram" \
&& ret=0

    case $state in
    (aram)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-gp-aram-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-all)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lock)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(config)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(move)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(receipt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(store-data)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(secure-apdu)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(trace)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__cat_commands" \
"*::: :->cat" \
&& ret=0

    case $state in
    (cat)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-cat-command-$line[1]:"
        case $line[1] in
            (decode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(sms)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__sms_commands" \
"*::: :->sms" \
&& ret=0

    case $state in
    (sms)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-sms-command-$line[1]:"
        case $line[1] in
            (decode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(saip)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__saip_commands" \
"*::: :->saip" \
&& ret=0

    case $state in
    (saip)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-saip-command-$line[1]:"
        case $line[1] in
            (parse)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(ota-crypto)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__ota-crypto_commands" \
"*::: :->ota-crypto" \
&& ret=0

    case $state in
    (ota-crypto)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-ota-crypto-command-$line[1]:"
        case $line[1] in
            (encrypt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decrypt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(esim-cert)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__esim-cert_commands" \
"*::: :->esim-cert" \
&& ret=0

    case $state in
    (esim-cert)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-esim-cert-command-$line[1]:"
        case $line[1] in
            (verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(ota-expanded)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__ota-expanded_commands" \
"*::: :->ota-expanded" \
&& ret=0

    case $state in
    (ota-expanded)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-ota-expanded-command-$line[1]:"
        case $line[1] in
            (encode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decode)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(por)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(keygen)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fuzz)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__fuzz_commands" \
"*::: :->fuzz" \
&& ret=0

    case $state in
    (fuzz)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-fuzz-command-$line[1]:"
        case $line[1] in
            (apdu)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ota)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(mutate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(compare)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(euicc)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__euicc_commands" \
"*::: :->euicc" \
&& ret=0

    case $state in
    (euicc)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-euicc-command-$line[1]:"
        case $line[1] in
            (info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(profiles)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(challenge)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(get-certs)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(get-eim-configuration-data)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(notifications)
_arguments "${_arguments_options[@]}" : \
":: :_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications_commands" \
"*::: :->notifications" \
&& ret=0

    case $state in
    (notifications)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:sim-doctor-help-euicc-notifications-command-$line[1]:"
        case $line[1] in
            (remove)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(dump)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(replay)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(nickname)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enable)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(disable)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reset)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set-default-dp)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(store-data)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(card)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(erase)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_sim-doctor_commands] )) ||
_sim-doctor_commands() {
    local commands; commands=(
'modules:Describe the crate module roots and the layering between them' \
'readers:List the PC/SC readers by name and index, for --reader or --reader-index' \
'scan:Select a card'\''s master file, walk everything under it, and report' \
'profile:Print the card-profile database, or probe a card against it' \
'cards:List known card profiles, show one, or write its fixture document' \
'ts48:Compare a card against the public GSMA TS.48 test profile' \
'batch:Program a batch of cards, one at a time, with a crash-safe state file' \
'install:Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project' \
'ci:Write the GitHub Actions workflow that runs this repo'\''s action on pull requests' \
'completions:Write a shell completion script to stdout' \
'mcp:Serve the scan and the rules as MCP tools over stdio' \
'rules:List the rules a scan runs, or explain one, without a card' \
'why:Explain a rule, or every rule in a saved \`scan --json\` envelope' \
'fix:Hand one finding from a saved scan to a coding agent' \
'gp:Read-only GlobalPlatform queries' \
'trace:Decode a captured APDU trace offline (no card, no reader)' \
'cat:Decode Card Application Toolkit data offline (no card, no reader)' \
'sms:\`sms decode\` decodes SMS TPDUs offline (TS 23.040)\: SMS-DELIVER, SMS-SUBMIT and STATUS-REPORT, addresses, DCS, the user-data header and concatenation, GSM 7-bit and UCS2 text. Sends nothing' \
'saip:\`saip parse\` decodes a SIMalliance eUICC profile package (SAIP, the DER ProfileElement sequence) offline into JSON\: each element named by its PE type, the rest a bounded TLV tree. Parse only, no personalization. Sends nothing' \
'ota-crypto:Offline OTA ciphers and checksums (DES, 3DES, AES-CBC encrypt/decrypt, CBC-MAC / AES-CMAC sign and check), as pySim'\''s OTA layer uses them. No card and no reader\: pure crypto over hex given on the command line' \
'esim-cert:Verify an eSIM certificate chain offline, up to a CI root you supply' \
'ota-expanded:Offline OTA expanded-command and Proof-of-Response decoder, as pySim'\''s OTA layer uses them. No card and no reader\: hex in, hex out' \
'keygen:Generate one card'\''s Ki, OPc, ICCID and IMSI from a secret you hold' \
'fuzz:APDU discovery and the OTA/SMS fuzz sweep' \
'euicc:eUICC queries over ES10 (lpac\: chip info, profile list, notification list), and the profile and notification writes' \
'card:A pySim-shell style shell over the card\: select files, read them, send APDUs' \
'erase:Erase the provisioning records before programming\: the reference programming tool'\''s -e/--erase, as a command of its own' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__batch_commands] )) ||
_sim-doctor__subcmd__batch_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor batch commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__card_commands] )) ||
_sim-doctor__subcmd__card_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor card commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards_commands] )) ||
_sim-doctor__subcmd__cards_commands() {
    local commands; commands=(
'list:Print the card table\: name, stated JavaCard and GlobalPlatform versions, stated EEPROM size, and which heading of the reference lists it' \
'show:Print one card profile in full, with every note and every provenance record' \
'fixture:Write one card profile'\''s fixture document to stdout' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor cards commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__fixture_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__fixture_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards fixture commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__help_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__help_commands() {
    local commands; commands=(
'list:Print the card table\: name, stated JavaCard and GlobalPlatform versions, stated EEPROM size, and which heading of the reference lists it' \
'show:Print one card profile in full, with every note and every provenance record' \
'fixture:Write one card profile'\''s fixture document to stdout' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor cards help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__help__subcmd__fixture_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__help__subcmd__fixture_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards help fixture commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__help__subcmd__list_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards help list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__help__subcmd__show_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards help show commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__list_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cards__subcmd__show_commands] )) ||
_sim-doctor__subcmd__cards__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cards show commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cat_commands] )) ||
_sim-doctor__subcmd__cat_commands() {
    local commands; commands=(
'decode:Decode CAT data given as hex arguments, or one object per line on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor cat commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cat__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__cat__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cat decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cat__subcmd__help_commands] )) ||
_sim-doctor__subcmd__cat__subcmd__help_commands() {
    local commands; commands=(
'decode:Decode CAT data given as hex arguments, or one object per line on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor cat help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cat__subcmd__help__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__cat__subcmd__help__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cat help decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__cat__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__cat__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor cat help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ci_commands] )) ||
_sim-doctor__subcmd__ci_commands() {
    local commands; commands=(
'install:Write .github/workflows/sim-doctor.yml, pinned to this version'\''s tag' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ci commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ci__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ci__subcmd__help_commands() {
    local commands; commands=(
'install:Write .github/workflows/sim-doctor.yml, pinned to this version'\''s tag' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ci help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ci__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ci__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ci help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ci__subcmd__help__subcmd__install_commands] )) ||
_sim-doctor__subcmd__ci__subcmd__help__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ci help install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ci__subcmd__install_commands] )) ||
_sim-doctor__subcmd__ci__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ci install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__completions_commands] )) ||
_sim-doctor__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor completions commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__erase_commands] )) ||
_sim-doctor__subcmd__erase_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor erase commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__esim-cert_commands] )) ||
_sim-doctor__subcmd__esim-cert_commands() {
    local commands; commands=(
'verify:Verify a certificate chain (leaf first) up to a CI root' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor esim-cert commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__esim-cert__subcmd__help_commands] )) ||
_sim-doctor__subcmd__esim-cert__subcmd__help_commands() {
    local commands; commands=(
'verify:Verify a certificate chain (leaf first) up to a CI root' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor esim-cert help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__esim-cert__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__esim-cert__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor esim-cert help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__esim-cert__subcmd__help__subcmd__verify_commands] )) ||
_sim-doctor__subcmd__esim-cert__subcmd__help__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor esim-cert help verify commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__esim-cert__subcmd__verify_commands] )) ||
_sim-doctor__subcmd__esim-cert__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor esim-cert verify commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc_commands] )) ||
_sim-doctor__subcmd__euicc_commands() {
    local commands; commands=(
'info:EID, EUICCInfo1 and EUICCInfo2 (lpac \`chip info\`)' \
'profiles:Installed profiles\: ICCID, state, class, nickname, provider, name (lpac \`profile list\`)' \
'challenge:GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7)\: the 16-byte challenge a profile download signs over (pySim \`get_euicc_challenge\`). Read-only' \
'get-certs:The EUM and eUICC CI certificates of an IoT eUICC (SGP.32 GetCerts, ES10b). Read-only\: one STORE DATA request, nothing on the card changes. The certificates are reported as their length and their hex, not parsed; the eUICC CI error TLV is reported as the error it is' \
'get-eim-configuration-data:What an IoT eUICC says about its EIM\: id, FQDN, id type, counter value, association token and every supported protocol (SGP.32 GetEimConfigurationData, ES10b). Read-only. The counter value and the association token are DER INTEGERs and are decoded as their value, not as the octets that carry it' \
'notifications:Pending notification metadata (lpac \`notification list\`); \`dump\` and \`replay\` below; \`notifications remove <seq>\` removes one' \
'nickname:Set a profile'\''s nickname (lpac \`profile nickname\`). A write\: a dry run unless \`--yes\`, never exposed over MCP' \
'enable:Enable a profile (lpac \`profile enable\`, ES10c EnableProfile with REFRESH). A dry run unless \`--yes\`\: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP' \
'disable:Disable a profile (lpac \`profile disable\`, ES10c DisableProfile with REFRESH). A dry run unless \`--yes\`\: disabling the only enabled profile leaves no active profile. Never exposed over MCP' \
'delete:Delete a profile (lpac \`profile delete\`, ES10c DeleteProfile). A dry run unless \`--yes\`\: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP' \
'reset:Reset the eUICC memory (lpac \`chip purge\`, ES10c eUICCMemoryReset). Can erase every profile\: nothing is selected by default, and sending needs both \`--yes\` and \`--confirm-eid <EID>\` matching the card. Never exposed over MCP' \
'set-default-dp:Set the default SM-DP+ address (ES10a SetDefaultDpAddress, SGP.22 v2.5 clause 5.7.4). A write\: a dry run that opens no reader unless \`--yes\`, and it changes where the eUICC looks for profiles. Never exposed over MCP' \
'store-data:One operator-supplied ES10x request, sent to the ISD-R as raw STORE DATA\: the escape hatch for a function this tool does not implement (pySim-shell \`do_es10x_store_data\`). A dry run unless \`--yes\`\: the card may act on an arbitrary ES10 request in ways this tool cannot undo. No keys are involved - this is not SCP03 - so none are asked for. The payload is bounded and refused above it, hex or stdin, and the card answer is reported verbatim even when this tool cannot decode it. Never exposed over MCP' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor euicc commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__challenge_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__challenge_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc challenge commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__disable_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__disable_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc disable commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__enable_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__enable_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc enable commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__get-certs_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__get-certs_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc get-certs commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__get-eim-configuration-data_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__get-eim-configuration-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc get-eim-configuration-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help_commands() {
    local commands; commands=(
'info:EID, EUICCInfo1 and EUICCInfo2 (lpac \`chip info\`)' \
'profiles:Installed profiles\: ICCID, state, class, nickname, provider, name (lpac \`profile list\`)' \
'challenge:GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7)\: the 16-byte challenge a profile download signs over (pySim \`get_euicc_challenge\`). Read-only' \
'get-certs:The EUM and eUICC CI certificates of an IoT eUICC (SGP.32 GetCerts, ES10b). Read-only\: one STORE DATA request, nothing on the card changes. The certificates are reported as their length and their hex, not parsed; the eUICC CI error TLV is reported as the error it is' \
'get-eim-configuration-data:What an IoT eUICC says about its EIM\: id, FQDN, id type, counter value, association token and every supported protocol (SGP.32 GetEimConfigurationData, ES10b). Read-only. The counter value and the association token are DER INTEGERs and are decoded as their value, not as the octets that carry it' \
'notifications:Pending notification metadata (lpac \`notification list\`); \`dump\` and \`replay\` below; \`notifications remove <seq>\` removes one' \
'nickname:Set a profile'\''s nickname (lpac \`profile nickname\`). A write\: a dry run unless \`--yes\`, never exposed over MCP' \
'enable:Enable a profile (lpac \`profile enable\`, ES10c EnableProfile with REFRESH). A dry run unless \`--yes\`\: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP' \
'disable:Disable a profile (lpac \`profile disable\`, ES10c DisableProfile with REFRESH). A dry run unless \`--yes\`\: disabling the only enabled profile leaves no active profile. Never exposed over MCP' \
'delete:Delete a profile (lpac \`profile delete\`, ES10c DeleteProfile). A dry run unless \`--yes\`\: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP' \
'reset:Reset the eUICC memory (lpac \`chip purge\`, ES10c eUICCMemoryReset). Can erase every profile\: nothing is selected by default, and sending needs both \`--yes\` and \`--confirm-eid <EID>\` matching the card. Never exposed over MCP' \
'set-default-dp:Set the default SM-DP+ address (ES10a SetDefaultDpAddress, SGP.22 v2.5 clause 5.7.4). A write\: a dry run that opens no reader unless \`--yes\`, and it changes where the eUICC looks for profiles. Never exposed over MCP' \
'store-data:One operator-supplied ES10x request, sent to the ISD-R as raw STORE DATA\: the escape hatch for a function this tool does not implement (pySim-shell \`do_es10x_store_data\`). A dry run unless \`--yes\`\: the card may act on an arbitrary ES10 request in ways this tool cannot undo. No keys are involved - this is not SCP03 - so none are asked for. The payload is bounded and refused above it, hex or stdin, and the card answer is reported verbatim even when this tool cannot decode it. Never exposed over MCP' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor euicc help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__challenge_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__challenge_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help challenge commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__disable_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__disable_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help disable commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__enable_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__enable_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help enable commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__get-certs_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__get-certs_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help get-certs commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__get-eim-configuration-data_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__get-eim-configuration-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help get-eim-configuration-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__info_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__nickname_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__nickname_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help nickname commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications_commands() {
    local commands; commands=(
'remove:Remove a notification from the eUICC'\''s list (lpac \`notification remove\`, ES10b RemoveNotificationFromList). A dry run unless \`--yes\`\: a removed notification is never sent to the operator'\''s server. Never exposed over MCP' \
'dump:Read the full signed pending notifications (lpac \`notification dump\`, ES10b RetrieveNotificationsList) as a re-loadable JSON document\: hex of the signed bytes plus the decoded sequence number, operation, address and ICCID. Read-only\: nothing is removed. Without \`-o\` and \`--json\` the document itself is printed. Never exposed over MCP' \
'replay:Send the notifications of a dump file to their operators (ES9+ HandleNotification over HTTPS). A dry run unless \`--yes\`\: this reaches the network and tells the operator'\''s server about a profile event. Needs no card and removes nothing. Never exposed over MCP' \
    )
    _describe -t commands 'sim-doctor euicc help notifications commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__dump_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__dump_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help notifications dump commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__remove_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help notifications remove commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__replay_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help notifications replay commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__profiles_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__profiles_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help profiles commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__reset_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__reset_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help reset commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__set-default-dp_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__set-default-dp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help set-default-dp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help__subcmd__store-data_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help__subcmd__store-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc help store-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__info_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__nickname_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__nickname_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc nickname commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications_commands() {
    local commands; commands=(
'remove:Remove a notification from the eUICC'\''s list (lpac \`notification remove\`, ES10b RemoveNotificationFromList). A dry run unless \`--yes\`\: a removed notification is never sent to the operator'\''s server. Never exposed over MCP' \
'dump:Read the full signed pending notifications (lpac \`notification dump\`, ES10b RetrieveNotificationsList) as a re-loadable JSON document\: hex of the signed bytes plus the decoded sequence number, operation, address and ICCID. Read-only\: nothing is removed. Without \`-o\` and \`--json\` the document itself is printed. Never exposed over MCP' \
'replay:Send the notifications of a dump file to their operators (ES9+ HandleNotification over HTTPS). A dry run unless \`--yes\`\: this reaches the network and tells the operator'\''s server about a profile event. Needs no card and removes nothing. Never exposed over MCP' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor euicc notifications commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__dump_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__dump_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications dump commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help_commands() {
    local commands; commands=(
'remove:Remove a notification from the eUICC'\''s list (lpac \`notification remove\`, ES10b RemoveNotificationFromList). A dry run unless \`--yes\`\: a removed notification is never sent to the operator'\''s server. Never exposed over MCP' \
'dump:Read the full signed pending notifications (lpac \`notification dump\`, ES10b RetrieveNotificationsList) as a re-loadable JSON document\: hex of the signed bytes plus the decoded sequence number, operation, address and ICCID. Read-only\: nothing is removed. Without \`-o\` and \`--json\` the document itself is printed. Never exposed over MCP' \
'replay:Send the notifications of a dump file to their operators (ES9+ HandleNotification over HTTPS). A dry run unless \`--yes\`\: this reaches the network and tells the operator'\''s server about a profile event. Needs no card and removes nothing. Never exposed over MCP' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor euicc notifications help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__dump_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__dump_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications help dump commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__remove_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications help remove commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__replay_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications help replay commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__remove_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications remove commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__replay_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__notifications__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc notifications replay commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__profiles_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__profiles_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc profiles commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__reset_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__reset_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc reset commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__set-default-dp_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__set-default-dp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc set-default-dp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__store-data_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__store-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor euicc store-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fix_commands] )) ||
_sim-doctor__subcmd__fix_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fix commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz_commands] )) ||
_sim-doctor__subcmd__fuzz_commands() {
    local commands; commands=(
'apdu:CLA discovery (level 1) or CLA+INS discovery (level 2) over a session' \
'ota:The OTA/SMS fuzz sweep\: TAR x keyset x mechanism, built on the TAR scanner'\''s ENVELOPE builder' \
'mutate:Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)' \
'compare:Compares two or more \`fuzz ota\` JSON results\: keysets ranked by how often the card accepted under them, and the (TAR, keyset, mechanism) triples the runs disagree on. Offline and read-only\: it reads result files and sends nothing. Only triples every run probed are compared' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor fuzz commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__apdu_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__apdu_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz apdu commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__compare_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz compare commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__help_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__help_commands() {
    local commands; commands=(
'apdu:CLA discovery (level 1) or CLA+INS discovery (level 2) over a session' \
'ota:The OTA/SMS fuzz sweep\: TAR x keyset x mechanism, built on the TAR scanner'\''s ENVELOPE builder' \
'mutate:Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)' \
'compare:Compares two or more \`fuzz ota\` JSON results\: keysets ranked by how often the card accepted under them, and the (TAR, keyset, mechanism) triples the runs disagree on. Offline and read-only\: it reads result files and sends nothing. Only triples every run probed are compared' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor fuzz help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__apdu_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__apdu_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz help apdu commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__compare_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz help compare commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__mutate_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__mutate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz help mutate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__ota_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__help__subcmd__ota_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz help ota commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__mutate_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__mutate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz mutate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__fuzz__subcmd__ota_commands] )) ||
_sim-doctor__subcmd__fuzz__subcmd__ota_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor fuzz ota commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp_commands] )) ||
_sim-doctor__subcmd__gp_commands() {
    local commands; commands=(
'cert:\`gp cert\`\: the GlobalPlatform card certificate of tag 7F21 (SCP11)' \
'info:Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA' \
'ara:Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA \[all\], decoded (read-only, no keys)' \
'status:GlobalPlatform registry inventory\: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication' \
'select:SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card'\''s current selection' \
'crs:Contactless Registry Service (CRS, GlobalPlatform Amendment C)\: list the applications held for contactless, read the service version and event counter, and activate or deactivate one application for contactless' \
'channel:Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N' \
'release-scp:Release the SCP03 secure channel on a logical channel\: close that logical channel with MANAGE CHANNEL, which is what ends the secure channel the card holds there. CHANGES CARD SESSION STATE' \
'delete:Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT' \
'make-default:Make an installed application Default Selected over an SCP03 channel\: INSTALL \[for make selectable\] with the Card Reset privilege (GlobalPlatform Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT' \
'rename-isd:Rename the Issuer Security Domain over an SCP03 channel\: STORE DATA \`4F LEN AID\` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT' \
'delete-key:Delete a key from the issuer security domain over an SCP03 channel (DELETE KEY, GlobalPlatform Card Spec v2.3.1 11.2.2). CHANGES CARD STATE' \
'install:Install an applet over an SCP03 channel (GlobalPlatform Card Spec v2.3.1 11.5, 11.6; v2.4 11.5.2.3.5). CHANGES CARD CONTENT\: every form writes to the card registry, and none of them can be undone' \
'create-sd:Create a supplementary Security Domain over an SCP03 channel\: INSTALL \[for install and make selectable\] carrying the Security Domain privileges and the allow-to / allow-from install parameters (GlobalPlatform Card Spec v2.3.1 11.5, Tables 11-43 and 11-49). CHANGES CARD CONTENT' \
'put-key:Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'\''S ADMINISTRATIVE ACCESS' \
'cplc-set:Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING\: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC' \
'personalize:Personalize an application or Security Domain over an SCP03 channel\: INSTALL \[for personalization\] (P1 20) for the AID, then one STORE DATA with the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified against the spec text, see the source). CHANGES CARD CONTENT' \
'aram:Add, delete or lock the secure element access rules the ARA-M holds\: STORE DATA \[Command-Store-REF-AR-DO\], \[Command-Delete\] and the fork'\''s lock, all over an SCP03 channel. CHANGES THE CARD'\''S ACCESS RULES' \
'move:Move an object (an application, a load file or a key object) from one Security Domain to another\: INSTALL \[for extradition\], P1 10 (GlobalPlatform Card Spec v2.3.1 11.5.2.3.4), which is ONE command and not a DELETE followed by an INSTALL. CHANGES CARD CONTENT' \
'receipt:Verify a GlobalPlatform receipt\: check that the receipt a Security Domain returned is the signature its receipt generation key makes over the response'\''s Confirmation Data and the AIDs the operation named (GlobalPlatform Card Specification v2.3.1 C.5, Tables C-11 to C-16; Confirmation Data is Table 11-14). READ-ONLY\: no card is opened and nothing is sent, so the receipt may come from a response you captured yourself' \
'store-data:Write data to the selected Application or issuer security domain with STORE DATA (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT' \
'secure-apdu:Send ONE raw APDU you wrote over the SCP03 secure channel and report the card'\''s answer verbatim. This is the raw escape hatch of the GP tool (\`gp -s\`), not a new kind of command. CAN WRITE TO THE CARD' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__ara_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__ara_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp ara commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram_commands() {
    local commands; commands=(
'add:Add or replace one access rule\: STORE DATA \[Command-Store-REF-AR-DO\], \`F0 { E2 { E1 { 4F|C0, C1, CA }, E3 { D0, D1, DB } } }\`' \
'delete-all:Delete EVERY access rule the ARA-M holds\: STORE DATA \[Command-Delete\] with an empty body (F1 00)' \
'lock:Lock the ARA-M'\''s STORE DATA (the single byte A1), so no rule can ever be added, changed or deleted again. pySim'\''s sysmocom ARA-M fork only' \
'config:The configuration handshake\: GET DATA \[Config\] (80 CA DF 21) offering the device'\''s interface version. Read-only, no --yes' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp aram commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__add_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram add commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__config_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__config_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram config commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__delete-all_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__delete-all_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram delete-all commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help_commands() {
    local commands; commands=(
'add:Add or replace one access rule\: STORE DATA \[Command-Store-REF-AR-DO\], \`F0 { E2 { E1 { 4F|C0, C1, CA }, E3 { D0, D1, DB } } }\`' \
'delete-all:Delete EVERY access rule the ARA-M holds\: STORE DATA \[Command-Delete\] with an empty body (F1 00)' \
'lock:Lock the ARA-M'\''s STORE DATA (the single byte A1), so no rule can ever be added, changed or deleted again. pySim'\''s sysmocom ARA-M fork only' \
'config:The configuration handshake\: GET DATA \[Config\] (80 CA DF 21) offering the device'\''s interface version. Read-only, no --yes' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp aram help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__add_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram help add commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__config_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__config_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram help config commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__delete-all_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__delete-all_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram help delete-all commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__lock_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__lock_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram help lock commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__aram__subcmd__lock_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__aram__subcmd__lock_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp aram lock commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert_commands() {
    local commands; commands=(
'read:Select the issuer security domain and READ BINARY the \`7F21\` card certificate, then decode it. Read-only\: no writing command is sent and no key is needed' \
'construct:Build a \`7F21\` card certificate offline, from the fields given. No card, no network and no clock\: the dates are yours, and the same inputs produce the same octets every run' \
'sign:Build a \`7F21\` card certificate offline and sign it with a P-256 key read from a file or an environment variable. Never from the command line, and never printed' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp cert commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__construct_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__construct_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert construct commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help_commands() {
    local commands; commands=(
'read:Select the issuer security domain and READ BINARY the \`7F21\` card certificate, then decode it. Read-only\: no writing command is sent and no key is needed' \
'construct:Build a \`7F21\` card certificate offline, from the fields given. No card, no network and no clock\: the dates are yours, and the same inputs produce the same octets every run' \
'sign:Build a \`7F21\` card certificate offline and sign it with a P-256 key read from a file or an environment variable. Never from the command line, and never printed' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp cert help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__construct_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__construct_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert help construct commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__read_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert help read commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert help sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__read_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert read commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cert__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cert__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cert sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel_commands() {
    local commands; commands=(
'open:MANAGE CHANNEL open\: the card picks the number and it is printed' \
'close:MANAGE CHANNEL close of a channel opened earlier' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp channel commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel__subcmd__close_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel__subcmd__close_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp channel close commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help_commands() {
    local commands; commands=(
'open:MANAGE CHANNEL open\: the card picks the number and it is printed' \
'close:MANAGE CHANNEL close of a channel opened earlier' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp channel help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__close_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__close_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp channel help close commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp channel help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__open_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__open_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp channel help open commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__channel__subcmd__open_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__channel__subcmd__open_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp channel open commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__cplc-set_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__cplc-set_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp cplc-set commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__create-sd_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__create-sd_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp create-sd commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs_commands() {
    local commands; commands=(
'list:List the applications the Contactless Registry Service holds for contactless, with their lifecycle, contactless state and registry data. Read-only, no keys' \
'info:Read the Contactless Registry Service version and event counter (GET DATA \[A5\]). Read-only, no keys' \
'activate:Activate one application for contactless (CRS SET STATUS with P2 01). CHANGES CARD STATE' \
'deactivate:Deactivate one application for contactless (CRS SET STATUS with P2 00). CHANGES CARD STATE' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp crs commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__activate_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__activate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs activate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__deactivate_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__deactivate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs deactivate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help_commands() {
    local commands; commands=(
'list:List the applications the Contactless Registry Service holds for contactless, with their lifecycle, contactless state and registry data. Read-only, no keys' \
'info:Read the Contactless Registry Service version and event counter (GET DATA \[A5\]). Read-only, no keys' \
'activate:Activate one application for contactless (CRS SET STATUS with P2 01). CHANGES CARD STATE' \
'deactivate:Deactivate one application for contactless (CRS SET STATUS with P2 00). CHANGES CARD STATE' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp crs help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__activate_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__activate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs help activate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__deactivate_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__deactivate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs help deactivate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__info_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs help info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__list_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs help list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__info_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__crs__subcmd__list_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__crs__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp crs list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__delete-key_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__delete-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp delete-key commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help_commands() {
    local commands; commands=(
'cert:\`gp cert\`\: the GlobalPlatform card certificate of tag 7F21 (SCP11)' \
'info:Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA' \
'ara:Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA \[all\], decoded (read-only, no keys)' \
'status:GlobalPlatform registry inventory\: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication' \
'select:SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card'\''s current selection' \
'crs:Contactless Registry Service (CRS, GlobalPlatform Amendment C)\: list the applications held for contactless, read the service version and event counter, and activate or deactivate one application for contactless' \
'channel:Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N' \
'release-scp:Release the SCP03 secure channel on a logical channel\: close that logical channel with MANAGE CHANNEL, which is what ends the secure channel the card holds there. CHANGES CARD SESSION STATE' \
'delete:Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT' \
'make-default:Make an installed application Default Selected over an SCP03 channel\: INSTALL \[for make selectable\] with the Card Reset privilege (GlobalPlatform Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT' \
'rename-isd:Rename the Issuer Security Domain over an SCP03 channel\: STORE DATA \`4F LEN AID\` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT' \
'delete-key:Delete a key from the issuer security domain over an SCP03 channel (DELETE KEY, GlobalPlatform Card Spec v2.3.1 11.2.2). CHANGES CARD STATE' \
'install:Install an applet over an SCP03 channel (GlobalPlatform Card Spec v2.3.1 11.5, 11.6; v2.4 11.5.2.3.5). CHANGES CARD CONTENT\: every form writes to the card registry, and none of them can be undone' \
'create-sd:Create a supplementary Security Domain over an SCP03 channel\: INSTALL \[for install and make selectable\] carrying the Security Domain privileges and the allow-to / allow-from install parameters (GlobalPlatform Card Spec v2.3.1 11.5, Tables 11-43 and 11-49). CHANGES CARD CONTENT' \
'put-key:Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'\''S ADMINISTRATIVE ACCESS' \
'cplc-set:Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING\: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC' \
'personalize:Personalize an application or Security Domain over an SCP03 channel\: INSTALL \[for personalization\] (P1 20) for the AID, then one STORE DATA with the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified against the spec text, see the source). CHANGES CARD CONTENT' \
'aram:Add, delete or lock the secure element access rules the ARA-M holds\: STORE DATA \[Command-Store-REF-AR-DO\], \[Command-Delete\] and the fork'\''s lock, all over an SCP03 channel. CHANGES THE CARD'\''S ACCESS RULES' \
'move:Move an object (an application, a load file or a key object) from one Security Domain to another\: INSTALL \[for extradition\], P1 10 (GlobalPlatform Card Spec v2.3.1 11.5.2.3.4), which is ONE command and not a DELETE followed by an INSTALL. CHANGES CARD CONTENT' \
'receipt:Verify a GlobalPlatform receipt\: check that the receipt a Security Domain returned is the signature its receipt generation key makes over the response'\''s Confirmation Data and the AIDs the operation named (GlobalPlatform Card Specification v2.3.1 C.5, Tables C-11 to C-16; Confirmation Data is Table 11-14). READ-ONLY\: no card is opened and nothing is sent, so the receipt may come from a response you captured yourself' \
'store-data:Write data to the selected Application or issuer security domain with STORE DATA (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT' \
'secure-apdu:Send ONE raw APDU you wrote over the SCP03 secure channel and report the card'\''s answer verbatim. This is the raw escape hatch of the GP tool (\`gp -s\`), not a new kind of command. CAN WRITE TO THE CARD' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__ara_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__ara_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help ara commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram_commands() {
    local commands; commands=(
'add:Add or replace one access rule\: STORE DATA \[Command-Store-REF-AR-DO\], \`F0 { E2 { E1 { 4F|C0, C1, CA }, E3 { D0, D1, DB } } }\`' \
'delete-all:Delete EVERY access rule the ARA-M holds\: STORE DATA \[Command-Delete\] with an empty body (F1 00)' \
'lock:Lock the ARA-M'\''s STORE DATA (the single byte A1), so no rule can ever be added, changed or deleted again. pySim'\''s sysmocom ARA-M fork only' \
'config:The configuration handshake\: GET DATA \[Config\] (80 CA DF 21) offering the device'\''s interface version. Read-only, no --yes' \
    )
    _describe -t commands 'sim-doctor gp help aram commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__add_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help aram add commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__config_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__config_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help aram config commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__delete-all_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__delete-all_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help aram delete-all commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__lock_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__lock_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help aram lock commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert_commands() {
    local commands; commands=(
'read:Select the issuer security domain and READ BINARY the \`7F21\` card certificate, then decode it. Read-only\: no writing command is sent and no key is needed' \
'construct:Build a \`7F21\` card certificate offline, from the fields given. No card, no network and no clock\: the dates are yours, and the same inputs produce the same octets every run' \
'sign:Build a \`7F21\` card certificate offline and sign it with a P-256 key read from a file or an environment variable. Never from the command line, and never printed' \
    )
    _describe -t commands 'sim-doctor gp help cert commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__construct_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__construct_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help cert construct commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__read_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help cert read commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help cert sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel_commands() {
    local commands; commands=(
'open:MANAGE CHANNEL open\: the card picks the number and it is printed' \
'close:MANAGE CHANNEL close of a channel opened earlier' \
    )
    _describe -t commands 'sim-doctor gp help channel commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__close_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__close_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help channel close commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__open_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__open_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help channel open commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__cplc-set_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__cplc-set_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help cplc-set commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__create-sd_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__create-sd_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help create-sd commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs_commands() {
    local commands; commands=(
'list:List the applications the Contactless Registry Service holds for contactless, with their lifecycle, contactless state and registry data. Read-only, no keys' \
'info:Read the Contactless Registry Service version and event counter (GET DATA \[A5\]). Read-only, no keys' \
'activate:Activate one application for contactless (CRS SET STATUS with P2 01). CHANGES CARD STATE' \
'deactivate:Deactivate one application for contactless (CRS SET STATUS with P2 00). CHANGES CARD STATE' \
    )
    _describe -t commands 'sim-doctor gp help crs commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__activate_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__activate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help crs activate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__deactivate_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__deactivate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help crs deactivate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__info_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help crs info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__list_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help crs list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__delete-key_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__delete-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help delete-key commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__info_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__install_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__make-default_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__make-default_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help make-default commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__move_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__move_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help move commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__personalize_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__personalize_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help personalize commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__put-key_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__put-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help put-key commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__receipt_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__receipt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help receipt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__release-scp_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__release-scp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help release-scp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__rename-isd_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__rename-isd_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help rename-isd commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__secure-apdu_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__secure-apdu_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help secure-apdu commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__select_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__select_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help select commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__status_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help status commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__store-data_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__store-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help store-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__info_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__install_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__make-default_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__make-default_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp make-default commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__move_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__move_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp move commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__personalize_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__personalize_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp personalize commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__put-key_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__put-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp put-key commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__receipt_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__receipt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp receipt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__release-scp_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__release-scp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp release-scp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__rename-isd_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__rename-isd_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp rename-isd commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__secure-apdu_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__secure-apdu_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp secure-apdu commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__select_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__select_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp select commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__status_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp status commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__store-data_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__store-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp store-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help_commands] )) ||
_sim-doctor__subcmd__help_commands() {
    local commands; commands=(
'modules:Describe the crate module roots and the layering between them' \
'readers:List the PC/SC readers by name and index, for --reader or --reader-index' \
'scan:Select a card'\''s master file, walk everything under it, and report' \
'profile:Print the card-profile database, or probe a card against it' \
'cards:List known card profiles, show one, or write its fixture document' \
'ts48:Compare a card against the public GSMA TS.48 test profile' \
'batch:Program a batch of cards, one at a time, with a crash-safe state file' \
'install:Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project' \
'ci:Write the GitHub Actions workflow that runs this repo'\''s action on pull requests' \
'completions:Write a shell completion script to stdout' \
'mcp:Serve the scan and the rules as MCP tools over stdio' \
'rules:List the rules a scan runs, or explain one, without a card' \
'why:Explain a rule, or every rule in a saved \`scan --json\` envelope' \
'fix:Hand one finding from a saved scan to a coding agent' \
'gp:Read-only GlobalPlatform queries' \
'trace:Decode a captured APDU trace offline (no card, no reader)' \
'cat:Decode Card Application Toolkit data offline (no card, no reader)' \
'sms:\`sms decode\` decodes SMS TPDUs offline (TS 23.040)\: SMS-DELIVER, SMS-SUBMIT and STATUS-REPORT, addresses, DCS, the user-data header and concatenation, GSM 7-bit and UCS2 text. Sends nothing' \
'saip:\`saip parse\` decodes a SIMalliance eUICC profile package (SAIP, the DER ProfileElement sequence) offline into JSON\: each element named by its PE type, the rest a bounded TLV tree. Parse only, no personalization. Sends nothing' \
'ota-crypto:Offline OTA ciphers and checksums (DES, 3DES, AES-CBC encrypt/decrypt, CBC-MAC / AES-CMAC sign and check), as pySim'\''s OTA layer uses them. No card and no reader\: pure crypto over hex given on the command line' \
'esim-cert:Verify an eSIM certificate chain offline, up to a CI root you supply' \
'ota-expanded:Offline OTA expanded-command and Proof-of-Response decoder, as pySim'\''s OTA layer uses them. No card and no reader\: hex in, hex out' \
'keygen:Generate one card'\''s Ki, OPc, ICCID and IMSI from a secret you hold' \
'fuzz:APDU discovery and the OTA/SMS fuzz sweep' \
'euicc:eUICC queries over ES10 (lpac\: chip info, profile list, notification list), and the profile and notification writes' \
'card:A pySim-shell style shell over the card\: select files, read them, send APDUs' \
'erase:Erase the provisioning records before programming\: the reference programming tool'\''s -e/--erase, as a command of its own' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__batch_commands] )) ||
_sim-doctor__subcmd__help__subcmd__batch_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help batch commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__card_commands] )) ||
_sim-doctor__subcmd__help__subcmd__card_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help card commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__cards_commands] )) ||
_sim-doctor__subcmd__help__subcmd__cards_commands() {
    local commands; commands=(
'list:Print the card table\: name, stated JavaCard and GlobalPlatform versions, stated EEPROM size, and which heading of the reference lists it' \
'show:Print one card profile in full, with every note and every provenance record' \
'fixture:Write one card profile'\''s fixture document to stdout' \
    )
    _describe -t commands 'sim-doctor help cards commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__cards__subcmd__fixture_commands] )) ||
_sim-doctor__subcmd__help__subcmd__cards__subcmd__fixture_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help cards fixture commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__cards__subcmd__list_commands] )) ||
_sim-doctor__subcmd__help__subcmd__cards__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help cards list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__cards__subcmd__show_commands] )) ||
_sim-doctor__subcmd__help__subcmd__cards__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help cards show commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__cat_commands] )) ||
_sim-doctor__subcmd__help__subcmd__cat_commands() {
    local commands; commands=(
'decode:Decode CAT data given as hex arguments, or one object per line on stdin' \
    )
    _describe -t commands 'sim-doctor help cat commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__cat__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__help__subcmd__cat__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help cat decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ci_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ci_commands() {
    local commands; commands=(
'install:Write .github/workflows/sim-doctor.yml, pinned to this version'\''s tag' \
    )
    _describe -t commands 'sim-doctor help ci commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ci__subcmd__install_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ci__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ci install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__completions_commands] )) ||
_sim-doctor__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help completions commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__erase_commands] )) ||
_sim-doctor__subcmd__help__subcmd__erase_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help erase commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__esim-cert_commands] )) ||
_sim-doctor__subcmd__help__subcmd__esim-cert_commands() {
    local commands; commands=(
'verify:Verify a certificate chain (leaf first) up to a CI root' \
    )
    _describe -t commands 'sim-doctor help esim-cert commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__esim-cert__subcmd__verify_commands] )) ||
_sim-doctor__subcmd__help__subcmd__esim-cert__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help esim-cert verify commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc_commands() {
    local commands; commands=(
'info:EID, EUICCInfo1 and EUICCInfo2 (lpac \`chip info\`)' \
'profiles:Installed profiles\: ICCID, state, class, nickname, provider, name (lpac \`profile list\`)' \
'challenge:GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7)\: the 16-byte challenge a profile download signs over (pySim \`get_euicc_challenge\`). Read-only' \
'get-certs:The EUM and eUICC CI certificates of an IoT eUICC (SGP.32 GetCerts, ES10b). Read-only\: one STORE DATA request, nothing on the card changes. The certificates are reported as their length and their hex, not parsed; the eUICC CI error TLV is reported as the error it is' \
'get-eim-configuration-data:What an IoT eUICC says about its EIM\: id, FQDN, id type, counter value, association token and every supported protocol (SGP.32 GetEimConfigurationData, ES10b). Read-only. The counter value and the association token are DER INTEGERs and are decoded as their value, not as the octets that carry it' \
'notifications:Pending notification metadata (lpac \`notification list\`); \`dump\` and \`replay\` below; \`notifications remove <seq>\` removes one' \
'nickname:Set a profile'\''s nickname (lpac \`profile nickname\`). A write\: a dry run unless \`--yes\`, never exposed over MCP' \
'enable:Enable a profile (lpac \`profile enable\`, ES10c EnableProfile with REFRESH). A dry run unless \`--yes\`\: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP' \
'disable:Disable a profile (lpac \`profile disable\`, ES10c DisableProfile with REFRESH). A dry run unless \`--yes\`\: disabling the only enabled profile leaves no active profile. Never exposed over MCP' \
'delete:Delete a profile (lpac \`profile delete\`, ES10c DeleteProfile). A dry run unless \`--yes\`\: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP' \
'reset:Reset the eUICC memory (lpac \`chip purge\`, ES10c eUICCMemoryReset). Can erase every profile\: nothing is selected by default, and sending needs both \`--yes\` and \`--confirm-eid <EID>\` matching the card. Never exposed over MCP' \
'set-default-dp:Set the default SM-DP+ address (ES10a SetDefaultDpAddress, SGP.22 v2.5 clause 5.7.4). A write\: a dry run that opens no reader unless \`--yes\`, and it changes where the eUICC looks for profiles. Never exposed over MCP' \
'store-data:One operator-supplied ES10x request, sent to the ISD-R as raw STORE DATA\: the escape hatch for a function this tool does not implement (pySim-shell \`do_es10x_store_data\`). A dry run unless \`--yes\`\: the card may act on an arbitrary ES10 request in ways this tool cannot undo. No keys are involved - this is not SCP03 - so none are asked for. The payload is bounded and refused above it, hex or stdin, and the card answer is reported verbatim even when this tool cannot decode it. Never exposed over MCP' \
    )
    _describe -t commands 'sim-doctor help euicc commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__challenge_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__challenge_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc challenge commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__disable_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__disable_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc disable commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__enable_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__enable_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc enable commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__get-certs_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__get-certs_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc get-certs commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__get-eim-configuration-data_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__get-eim-configuration-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc get-eim-configuration-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__info_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__nickname_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__nickname_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc nickname commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications_commands() {
    local commands; commands=(
'remove:Remove a notification from the eUICC'\''s list (lpac \`notification remove\`, ES10b RemoveNotificationFromList). A dry run unless \`--yes\`\: a removed notification is never sent to the operator'\''s server. Never exposed over MCP' \
'dump:Read the full signed pending notifications (lpac \`notification dump\`, ES10b RetrieveNotificationsList) as a re-loadable JSON document\: hex of the signed bytes plus the decoded sequence number, operation, address and ICCID. Read-only\: nothing is removed. Without \`-o\` and \`--json\` the document itself is printed. Never exposed over MCP' \
'replay:Send the notifications of a dump file to their operators (ES9+ HandleNotification over HTTPS). A dry run unless \`--yes\`\: this reaches the network and tells the operator'\''s server about a profile event. Needs no card and removes nothing. Never exposed over MCP' \
    )
    _describe -t commands 'sim-doctor help euicc notifications commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__dump_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__dump_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc notifications dump commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__remove_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc notifications remove commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__replay_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc notifications replay commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__profiles_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__profiles_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc profiles commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__reset_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__reset_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc reset commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__set-default-dp_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__set-default-dp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc set-default-dp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__euicc__subcmd__store-data_commands] )) ||
_sim-doctor__subcmd__help__subcmd__euicc__subcmd__store-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help euicc store-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__fix_commands] )) ||
_sim-doctor__subcmd__help__subcmd__fix_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help fix commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__fuzz_commands] )) ||
_sim-doctor__subcmd__help__subcmd__fuzz_commands() {
    local commands; commands=(
'apdu:CLA discovery (level 1) or CLA+INS discovery (level 2) over a session' \
'ota:The OTA/SMS fuzz sweep\: TAR x keyset x mechanism, built on the TAR scanner'\''s ENVELOPE builder' \
'mutate:Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)' \
'compare:Compares two or more \`fuzz ota\` JSON results\: keysets ranked by how often the card accepted under them, and the (TAR, keyset, mechanism) triples the runs disagree on. Offline and read-only\: it reads result files and sends nothing. Only triples every run probed are compared' \
    )
    _describe -t commands 'sim-doctor help fuzz commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__apdu_commands] )) ||
_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__apdu_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help fuzz apdu commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__compare_commands] )) ||
_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help fuzz compare commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__mutate_commands] )) ||
_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__mutate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help fuzz mutate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__ota_commands] )) ||
_sim-doctor__subcmd__help__subcmd__fuzz__subcmd__ota_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help fuzz ota commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp_commands() {
    local commands; commands=(
'cert:\`gp cert\`\: the GlobalPlatform card certificate of tag 7F21 (SCP11)' \
'info:Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA' \
'ara:Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA \[all\], decoded (read-only, no keys)' \
'status:GlobalPlatform registry inventory\: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication' \
'select:SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card'\''s current selection' \
'crs:Contactless Registry Service (CRS, GlobalPlatform Amendment C)\: list the applications held for contactless, read the service version and event counter, and activate or deactivate one application for contactless' \
'channel:Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N' \
'release-scp:Release the SCP03 secure channel on a logical channel\: close that logical channel with MANAGE CHANNEL, which is what ends the secure channel the card holds there. CHANGES CARD SESSION STATE' \
'delete:Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT' \
'make-default:Make an installed application Default Selected over an SCP03 channel\: INSTALL \[for make selectable\] with the Card Reset privilege (GlobalPlatform Card Spec v2.3.1 11.5, Table 11-7). CHANGES CARD CONTENT' \
'rename-isd:Rename the Issuer Security Domain over an SCP03 channel\: STORE DATA \`4F LEN AID\` (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT' \
'delete-key:Delete a key from the issuer security domain over an SCP03 channel (DELETE KEY, GlobalPlatform Card Spec v2.3.1 11.2.2). CHANGES CARD STATE' \
'install:Install an applet over an SCP03 channel (GlobalPlatform Card Spec v2.3.1 11.5, 11.6; v2.4 11.5.2.3.5). CHANGES CARD CONTENT\: every form writes to the card registry, and none of them can be undone' \
'create-sd:Create a supplementary Security Domain over an SCP03 channel\: INSTALL \[for install and make selectable\] carrying the Security Domain privileges and the allow-to / allow-from install parameters (GlobalPlatform Card Spec v2.3.1 11.5, Tables 11-43 and 11-49). CHANGES CARD CONTENT' \
'put-key:Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'\''S ADMINISTRATIVE ACCESS' \
'cplc-set:Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING\: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC' \
'personalize:Personalize an application or Security Domain over an SCP03 channel\: INSTALL \[for personalization\] (P1 20) for the AID, then one STORE DATA with the BER-TLV data (GlobalPlatform Card Spec v2.3.1; the layout is unverified against the spec text, see the source). CHANGES CARD CONTENT' \
'aram:Add, delete or lock the secure element access rules the ARA-M holds\: STORE DATA \[Command-Store-REF-AR-DO\], \[Command-Delete\] and the fork'\''s lock, all over an SCP03 channel. CHANGES THE CARD'\''S ACCESS RULES' \
'move:Move an object (an application, a load file or a key object) from one Security Domain to another\: INSTALL \[for extradition\], P1 10 (GlobalPlatform Card Spec v2.3.1 11.5.2.3.4), which is ONE command and not a DELETE followed by an INSTALL. CHANGES CARD CONTENT' \
'receipt:Verify a GlobalPlatform receipt\: check that the receipt a Security Domain returned is the signature its receipt generation key makes over the response'\''s Confirmation Data and the AIDs the operation named (GlobalPlatform Card Specification v2.3.1 C.5, Tables C-11 to C-16; Confirmation Data is Table 11-14). READ-ONLY\: no card is opened and nothing is sent, so the receipt may come from a response you captured yourself' \
'store-data:Write data to the selected Application or issuer security domain with STORE DATA (GlobalPlatform Card Spec v2.3.1 11.11). CHANGES CARD CONTENT' \
'secure-apdu:Send ONE raw APDU you wrote over the SCP03 secure channel and report the card'\''s answer verbatim. This is the raw escape hatch of the GP tool (\`gp -s\`), not a new kind of command. CAN WRITE TO THE CARD' \
    )
    _describe -t commands 'sim-doctor help gp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__ara_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__ara_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp ara commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram_commands() {
    local commands; commands=(
'add:Add or replace one access rule\: STORE DATA \[Command-Store-REF-AR-DO\], \`F0 { E2 { E1 { 4F|C0, C1, CA }, E3 { D0, D1, DB } } }\`' \
'delete-all:Delete EVERY access rule the ARA-M holds\: STORE DATA \[Command-Delete\] with an empty body (F1 00)' \
'lock:Lock the ARA-M'\''s STORE DATA (the single byte A1), so no rule can ever be added, changed or deleted again. pySim'\''s sysmocom ARA-M fork only' \
'config:The configuration handshake\: GET DATA \[Config\] (80 CA DF 21) offering the device'\''s interface version. Read-only, no --yes' \
    )
    _describe -t commands 'sim-doctor help gp aram commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__add_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp aram add commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__config_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__config_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp aram config commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__delete-all_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__delete-all_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp aram delete-all commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__lock_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__lock_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp aram lock commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert_commands() {
    local commands; commands=(
'read:Select the issuer security domain and READ BINARY the \`7F21\` card certificate, then decode it. Read-only\: no writing command is sent and no key is needed' \
'construct:Build a \`7F21\` card certificate offline, from the fields given. No card, no network and no clock\: the dates are yours, and the same inputs produce the same octets every run' \
'sign:Build a \`7F21\` card certificate offline and sign it with a P-256 key read from a file or an environment variable. Never from the command line, and never printed' \
    )
    _describe -t commands 'sim-doctor help gp cert commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__construct_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__construct_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp cert construct commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__read_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp cert read commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp cert sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel_commands() {
    local commands; commands=(
'open:MANAGE CHANNEL open\: the card picks the number and it is printed' \
'close:MANAGE CHANNEL close of a channel opened earlier' \
    )
    _describe -t commands 'sim-doctor help gp channel commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__close_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__close_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp channel close commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__open_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__open_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp channel open commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__cplc-set_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__cplc-set_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp cplc-set commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__create-sd_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__create-sd_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp create-sd commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs_commands() {
    local commands; commands=(
'list:List the applications the Contactless Registry Service holds for contactless, with their lifecycle, contactless state and registry data. Read-only, no keys' \
'info:Read the Contactless Registry Service version and event counter (GET DATA \[A5\]). Read-only, no keys' \
'activate:Activate one application for contactless (CRS SET STATUS with P2 01). CHANGES CARD STATE' \
'deactivate:Deactivate one application for contactless (CRS SET STATUS with P2 00). CHANGES CARD STATE' \
    )
    _describe -t commands 'sim-doctor help gp crs commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__activate_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__activate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp crs activate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__deactivate_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__deactivate_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp crs deactivate commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__info_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp crs info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__list_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp crs list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__delete-key_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__delete-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp delete-key commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__info_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp info commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__install_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__make-default_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__make-default_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp make-default commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__move_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__move_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp move commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__personalize_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__personalize_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp personalize commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__put-key_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__put-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp put-key commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__receipt_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__receipt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp receipt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__release-scp_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__release-scp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp release-scp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__rename-isd_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__rename-isd_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp rename-isd commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__secure-apdu_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__secure-apdu_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp secure-apdu commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__select_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__select_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp select commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__status_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp status commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__store-data_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__store-data_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp store-data commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__install_commands] )) ||
_sim-doctor__subcmd__help__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__keygen_commands] )) ||
_sim-doctor__subcmd__help__subcmd__keygen_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help keygen commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__mcp_commands] )) ||
_sim-doctor__subcmd__help__subcmd__mcp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help mcp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__modules_commands] )) ||
_sim-doctor__subcmd__help__subcmd__modules_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help modules commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-crypto_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-crypto_commands() {
    local commands; commands=(
'encrypt:Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex' \
'decrypt:Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex' \
'sign:Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES)' \
'check:Recompute the checksum and compare it to --mac in constant time' \
    )
    _describe -t commands 'sim-doctor help ota-crypto commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__check_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-crypto check commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__decrypt_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__decrypt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-crypto decrypt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__encrypt_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__encrypt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-crypto encrypt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-crypto__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-crypto sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-expanded_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-expanded_commands() {
    local commands; commands=(
'encode:Wrap one or more C-APDUs (hex each) in a Command Scripting template' \
'decode:Decode a Response Scripting template (TS 102 226 5.2.2), definite or indefinite' \
'por:Decode a Proof-of-Response Response Packet (TS 102 225 table 5, TS 31.115), with or without the SMS \`02 71 00\` user data header' \
    )
    _describe -t commands 'sim-doctor help ota-expanded commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-expanded__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-expanded__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-expanded decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-expanded__subcmd__encode_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-expanded__subcmd__encode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-expanded encode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ota-expanded__subcmd__por_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ota-expanded__subcmd__por_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ota-expanded por commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__profile_commands] )) ||
_sim-doctor__subcmd__help__subcmd__profile_commands() {
    local commands; commands=(
'list:Print the card-profile database with its provenance. Needs no card' \
'probe:Probe a card and report which profiles matched, with the evidence' \
'match:Check one named profile against a card. An unknown name is refused before any reader is opened' \
    )
    _describe -t commands 'sim-doctor help profile commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__profile__subcmd__list_commands] )) ||
_sim-doctor__subcmd__help__subcmd__profile__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help profile list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__profile__subcmd__match_commands] )) ||
_sim-doctor__subcmd__help__subcmd__profile__subcmd__match_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help profile match commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__profile__subcmd__probe_commands] )) ||
_sim-doctor__subcmd__help__subcmd__profile__subcmd__probe_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help profile probe commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__readers_commands] )) ||
_sim-doctor__subcmd__help__subcmd__readers_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help readers commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__rules_commands] )) ||
_sim-doctor__subcmd__help__subcmd__rules_commands() {
    local commands; commands=(
'list:One row per rule\: id, severity, summary' \
'explain:What a rule means and how to fix it' \
    )
    _describe -t commands 'sim-doctor help rules commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__rules__subcmd__explain_commands] )) ||
_sim-doctor__subcmd__help__subcmd__rules__subcmd__explain_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help rules explain commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__rules__subcmd__list_commands] )) ||
_sim-doctor__subcmd__help__subcmd__rules__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help rules list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__saip_commands] )) ||
_sim-doctor__subcmd__help__subcmd__saip_commands() {
    local commands; commands=(
'parse:Decode a SAIP profile package (DER, the concatenated ProfileElements) offline' \
    )
    _describe -t commands 'sim-doctor help saip commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__saip__subcmd__parse_commands] )) ||
_sim-doctor__subcmd__help__subcmd__saip__subcmd__parse_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help saip parse commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__scan_commands] )) ||
_sim-doctor__subcmd__help__subcmd__scan_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help scan commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__sms_commands] )) ||
_sim-doctor__subcmd__help__subcmd__sms_commands() {
    local commands; commands=(
'decode:Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin' \
    )
    _describe -t commands 'sim-doctor help sms commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__sms__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__help__subcmd__sms__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help sms decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__trace_commands] )) ||
_sim-doctor__subcmd__help__subcmd__trace_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help trace commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ts48_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ts48_commands() {
    local commands; commands=(
'compare:Walk the card and diff its file system against the GSMA TS.48 test profile' \
    )
    _describe -t commands 'sim-doctor help ts48 commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__ts48__subcmd__compare_commands] )) ||
_sim-doctor__subcmd__help__subcmd__ts48__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help ts48 compare commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__why_commands] )) ||
_sim-doctor__subcmd__help__subcmd__why_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help why commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__install_commands] )) ||
_sim-doctor__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor install commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__keygen_commands] )) ||
_sim-doctor__subcmd__keygen_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor keygen commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__mcp_commands] )) ||
_sim-doctor__subcmd__mcp_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor mcp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__modules_commands] )) ||
_sim-doctor__subcmd__modules_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor modules commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto_commands] )) ||
_sim-doctor__subcmd__ota-crypto_commands() {
    local commands; commands=(
'encrypt:Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex' \
'decrypt:Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex' \
'sign:Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES)' \
'check:Recompute the checksum and compare it to --mac in constant time' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ota-crypto commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__check_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto check commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__decrypt_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__decrypt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto decrypt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__encrypt_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__encrypt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto encrypt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__help_commands() {
    local commands; commands=(
'encrypt:Encrypt DATA (hex) with CBC, no padding, printing ciphertext as hex' \
'decrypt:Decrypt ciphertext (hex) with CBC, no padding, printing plaintext as hex' \
'sign:Compute an OTA checksum (AES-CMAC for AES, CBC-MAC for DES/3DES)' \
'check:Recompute the checksum and compare it to --mac in constant time' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ota-crypto help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__check_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto help check commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__decrypt_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__decrypt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto help decrypt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__encrypt_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__encrypt_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto help encrypt commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__help__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto help sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-crypto__subcmd__sign_commands] )) ||
_sim-doctor__subcmd__ota-crypto__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-crypto sign commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded_commands] )) ||
_sim-doctor__subcmd__ota-expanded_commands() {
    local commands; commands=(
'encode:Wrap one or more C-APDUs (hex each) in a Command Scripting template' \
'decode:Decode a Response Scripting template (TS 102 226 5.2.2), definite or indefinite' \
'por:Decode a Proof-of-Response Response Packet (TS 102 225 table 5, TS 31.115), with or without the SMS \`02 71 00\` user data header' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ota-expanded commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__encode_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__encode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded encode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__help_commands() {
    local commands; commands=(
'encode:Wrap one or more C-APDUs (hex each) in a Command Scripting template' \
'decode:Decode a Response Scripting template (TS 102 226 5.2.2), definite or indefinite' \
'por:Decode a Proof-of-Response Response Packet (TS 102 225 table 5, TS 31.115), with or without the SMS \`02 71 00\` user data header' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ota-expanded help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded help decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__encode_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__encode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded help encode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__por_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__help__subcmd__por_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded help por commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ota-expanded__subcmd__por_commands] )) ||
_sim-doctor__subcmd__ota-expanded__subcmd__por_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ota-expanded por commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile_commands] )) ||
_sim-doctor__subcmd__profile_commands() {
    local commands; commands=(
'list:Print the card-profile database with its provenance. Needs no card' \
'probe:Probe a card and report which profiles matched, with the evidence' \
'match:Check one named profile against a card. An unknown name is refused before any reader is opened' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor profile commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__help_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__help_commands() {
    local commands; commands=(
'list:Print the card-profile database with its provenance. Needs no card' \
'probe:Probe a card and report which profiles matched, with the evidence' \
'match:Check one named profile against a card. An unknown name is refused before any reader is opened' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor profile help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__help__subcmd__list_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile help list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__help__subcmd__match_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__help__subcmd__match_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile help match commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__help__subcmd__probe_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__help__subcmd__probe_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile help probe commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__list_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__match_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__match_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile match commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__profile__subcmd__probe_commands] )) ||
_sim-doctor__subcmd__profile__subcmd__probe_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor profile probe commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__readers_commands] )) ||
_sim-doctor__subcmd__readers_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor readers commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules_commands] )) ||
_sim-doctor__subcmd__rules_commands() {
    local commands; commands=(
'list:One row per rule\: id, severity, summary' \
'explain:What a rule means and how to fix it' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor rules commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules__subcmd__explain_commands] )) ||
_sim-doctor__subcmd__rules__subcmd__explain_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor rules explain commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules__subcmd__help_commands] )) ||
_sim-doctor__subcmd__rules__subcmd__help_commands() {
    local commands; commands=(
'list:One row per rule\: id, severity, summary' \
'explain:What a rule means and how to fix it' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor rules help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules__subcmd__help__subcmd__explain_commands] )) ||
_sim-doctor__subcmd__rules__subcmd__help__subcmd__explain_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor rules help explain commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__rules__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor rules help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules__subcmd__help__subcmd__list_commands] )) ||
_sim-doctor__subcmd__rules__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor rules help list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__rules__subcmd__list_commands] )) ||
_sim-doctor__subcmd__rules__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor rules list commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__saip_commands] )) ||
_sim-doctor__subcmd__saip_commands() {
    local commands; commands=(
'parse:Decode a SAIP profile package (DER, the concatenated ProfileElements) offline' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor saip commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__saip__subcmd__help_commands] )) ||
_sim-doctor__subcmd__saip__subcmd__help_commands() {
    local commands; commands=(
'parse:Decode a SAIP profile package (DER, the concatenated ProfileElements) offline' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor saip help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__saip__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__saip__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor saip help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__saip__subcmd__help__subcmd__parse_commands] )) ||
_sim-doctor__subcmd__saip__subcmd__help__subcmd__parse_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor saip help parse commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__saip__subcmd__parse_commands] )) ||
_sim-doctor__subcmd__saip__subcmd__parse_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor saip parse commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__scan_commands] )) ||
_sim-doctor__subcmd__scan_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor scan commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__sms_commands] )) ||
_sim-doctor__subcmd__sms_commands() {
    local commands; commands=(
'decode:Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor sms commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__sms__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__sms__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor sms decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__sms__subcmd__help_commands] )) ||
_sim-doctor__subcmd__sms__subcmd__help_commands() {
    local commands; commands=(
'decode:Decode SMS PDUs (SMS-DELIVER, SMS-SUBMIT, STATUS-REPORT) given as hex, or one per line on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor sms help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__sms__subcmd__help__subcmd__decode_commands] )) ||
_sim-doctor__subcmd__sms__subcmd__help__subcmd__decode_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor sms help decode commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__sms__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__sms__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor sms help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__trace_commands] )) ||
_sim-doctor__subcmd__trace_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor trace commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ts48_commands] )) ||
_sim-doctor__subcmd__ts48_commands() {
    local commands; commands=(
'compare:Walk the card and diff its file system against the GSMA TS.48 test profile' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ts48 commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ts48__subcmd__compare_commands] )) ||
_sim-doctor__subcmd__ts48__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ts48 compare commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ts48__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ts48__subcmd__help_commands() {
    local commands; commands=(
'compare:Walk the card and diff its file system against the GSMA TS.48 test profile' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor ts48 help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ts48__subcmd__help__subcmd__compare_commands] )) ||
_sim-doctor__subcmd__ts48__subcmd__help__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ts48 help compare commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__ts48__subcmd__help__subcmd__help_commands] )) ||
_sim-doctor__subcmd__ts48__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor ts48 help help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__why_commands] )) ||
_sim-doctor__subcmd__why_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor why commands' commands "$@"
}

if [ "$funcstack[1]" = "_sim-doctor" ]; then
    _sim-doctor "$@"
else
    compdef _sim-doctor sim-doctor
fi
