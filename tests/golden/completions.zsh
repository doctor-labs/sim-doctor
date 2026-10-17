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
'--tar=[Which TARs to probe for MSL 0, and how many]:SELECTION:_default' \
'(--json --tui)--face=[The human report\: a doctor-kit face (rich, plain or compact), or the full legacy report]:FACE:(rich plain compact legacy)' \
'(--json --tui)--theme=[The face'\''s colours\: mono, clinical or contrast (default\: the tool'\''s own)]:THEME:_default' \
'(--json --tui)--color=[Colour the face\: auto (a terminal and no NO_COLOR), always or never]:COLOR:(auto always never)' \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'(--json)--tui[Show the findings in an interactive terminal view instead of the report]' \
'--score[Add one quality score for this card, for CI gating]' \
'--terminal-profile[Send a TERMINAL PROFILE to the card before the TAR audit]' \
'--sms-deliver-report[Ask for SMS-DELIVER-REPORT as the proof-of-receipt mode of the TAR probes, not SMS-SUBMIT]' \
'(--json --tui --face)--headless[A face in plain text without colour, for CI and pipes]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
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
            (info)
_arguments "${_arguments_options[@]}" : \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
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
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(select)
_arguments "${_arguments_options[@]}" : \
'--aid=[The application AID, 5 to 16 bytes of hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(channel)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
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
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(close)
_arguments "${_arguments_options[@]}" : \
'--channel=[The channel to close, 1 to 19]:N:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'-h[Print help]' \
'--help[Print help]' \
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
(delete)
_arguments "${_arguments_options[@]}" : \
'--aid=[The AID to delete, 5 to 16 bytes of hex]:HEX:_default' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--related[Also delete related objects (P2 80)\: for a load file, its applications]' \
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
'--module=[The Executable Module AID (the applet class). Optional when the CAP has one applet]:HEX:_default' \
'--app=[The application (instance) AID. Defaults to the module AID]:HEX:_default' \
'--params=[The Install Parameters field as TLV with the mandatory C9 tag (default C900\: none)]:HEX:_default' \
'--privileges=[Privileges, 1 or 3 bytes of hex (default 000000). Card Lock and Card Terminate are refused]:HEX:_default' \
'--dap-key-file=[File holding the AES DAP key (hex, optionally KEY/KCV; chmod 600)]:PATH:_files' \
'--dap-key-env=[Environment variable holding the AES DAP key]:VAR:_default' \
'--dap-sd=[The Security Domain that verifies the DAP, 5 to 16 bytes of hex (default\: the issuer security domain being authenticated)]:HEX:_default' \
'--dap-hash=[The Load File Data Block Hash the DAP signs]:DAP_HASH:(sha256 sha384 sha512)' \
'--reader=[The reader to use, matched against the driver'\''s own name]:NAME:_default' \
'--keys-file=[File holding the keys (keep it chmod 600)]:PATH:_files' \
'--keys-env=[Environment variable holding the keys]:VAR:_default' \
'--key-version=[Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set]:HEX:_default' \
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
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
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--replace-current-keyset[Allow the request to add, replace or overwrite the key version this session authenticated with. Without it such a request is refused]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
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
'--channel=[Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it]:N:_default' \
'--today[Write today'\''s date (UTC) into the date bytes, overriding those in --data]' \
'--json[Emit one JSON envelope of kind "gp" on stdout]' \
'--trace[Add every APDU exchange (command and response hex) as data.trace]' \
'--yes[Send the commands. Without it nothing is written. Needs --keys-file or --keys-env]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
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
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(install)
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
'--i-understand-this-can-brick-the-card[Required. Without it, \`fuzz\` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)]' \
'--allow-real-hardware[Required in addition to the opt-in above when the reader'\''s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, \`fuzz\` refuses to run against anything that is not recognisably the software card]' \
'--json[Emit one JSON envelope on stdout, and nothing else]' \
'--quick[Probe a small, documented subset instead of the full space]' \
'-h[Print help]' \
'--help[Print help]' \
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
'(--chv-env)--chv-file=[File holding PINs, PUKs and ADM keys for \`verify_chv\` / \`unblock_chv\` (\`pin1=1234\` per line; keep it chmod 600). Never a value on the command line\: it would land in shell history]:PATH:_files' \
'--chv-env=[Environment variable holding the same text (entries separated by \`;\` or newlines)]:VAR:_default' \
'--key-file=[pySim CardKeyProvider CSV file for \`query_card_key\` (ICCID,ADM1,OPC,...; one card per row). Read and checked before any reader is opened; secrets are never printed unless named in --fields. Keep it chmod 600]:PATH:_files' \
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
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(install)
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
        esac
    ;;
esac
;;
(card)
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
'ts48:Compare a card against the public GSMA TS.48 test profile' \
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
'fuzz:APDU discovery and the OTA/SMS fuzz sweep' \
'euicc:eUICC queries over ES10 (lpac\: chip info, profile list, notification list), and the profile and notification writes' \
'card:A pySim-shell style shell over the card\: select files, read them, send APDUs' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__card_commands] )) ||
_sim-doctor__subcmd__card_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor card commands' commands "$@"
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
'notifications:Pending notification metadata (lpac \`notification list\`); \`dump\` and \`replay\` below; \`notifications remove <seq>\` removes one' \
'nickname:Set a profile'\''s nickname (lpac \`profile nickname\`). A write\: a dry run unless \`--yes\`, never exposed over MCP' \
'enable:Enable a profile (lpac \`profile enable\`, ES10c EnableProfile with REFRESH). A dry run unless \`--yes\`\: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP' \
'disable:Disable a profile (lpac \`profile disable\`, ES10c DisableProfile with REFRESH). A dry run unless \`--yes\`\: disabling the only enabled profile leaves no active profile. Never exposed over MCP' \
'delete:Delete a profile (lpac \`profile delete\`, ES10c DeleteProfile). A dry run unless \`--yes\`\: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP' \
'reset:Reset the eUICC memory (lpac \`chip purge\`, ES10c eUICCMemoryReset). Can erase every profile\: nothing is selected by default, and sending needs both \`--yes\` and \`--confirm-eid <EID>\` matching the card. Never exposed over MCP' \
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
(( $+functions[_sim-doctor__subcmd__euicc__subcmd__help_commands] )) ||
_sim-doctor__subcmd__euicc__subcmd__help_commands() {
    local commands; commands=(
'info:EID, EUICCInfo1 and EUICCInfo2 (lpac \`chip info\`)' \
'profiles:Installed profiles\: ICCID, state, class, nickname, provider, name (lpac \`profile list\`)' \
'challenge:GetEUICCChallenge (ES10b, SGP.22 v2.5 §5.7.7)\: the 16-byte challenge a profile download signs over (pySim \`get_euicc_challenge\`). Read-only' \
'notifications:Pending notification metadata (lpac \`notification list\`); \`dump\` and \`replay\` below; \`notifications remove <seq>\` removes one' \
'nickname:Set a profile'\''s nickname (lpac \`profile nickname\`). A write\: a dry run unless \`--yes\`, never exposed over MCP' \
'enable:Enable a profile (lpac \`profile enable\`, ES10c EnableProfile with REFRESH). A dry run unless \`--yes\`\: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP' \
'disable:Disable a profile (lpac \`profile disable\`, ES10c DisableProfile with REFRESH). A dry run unless \`--yes\`\: disabling the only enabled profile leaves no active profile. Never exposed over MCP' \
'delete:Delete a profile (lpac \`profile delete\`, ES10c DeleteProfile). A dry run unless \`--yes\`\: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP' \
'reset:Reset the eUICC memory (lpac \`chip purge\`, ES10c eUICCMemoryReset). Can erase every profile\: nothing is selected by default, and sending needs both \`--yes\` and \`--confirm-eid <EID>\` matching the card. Never exposed over MCP' \
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
'info:Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA' \
'ara:Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA \[all\], decoded (read-only, no keys)' \
'status:GlobalPlatform registry inventory\: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication' \
'select:SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card'\''s current selection' \
'channel:Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N' \
'delete:Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT' \
'install:Load a CAP file and install an applet over an SCP03 channel\: INSTALL \[for load\], LOAD, INSTALL \[for install and make selectable\] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT' \
'put-key:Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'\''S ADMINISTRATIVE ACCESS' \
'cplc-set:Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING\: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__ara_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__ara_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp ara commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__gp__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp delete commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help_commands() {
    local commands; commands=(
'info:Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA' \
'ara:Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA \[all\], decoded (read-only, no keys)' \
'status:GlobalPlatform registry inventory\: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication' \
'select:SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card'\''s current selection' \
'channel:Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N' \
'delete:Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT' \
'install:Load a CAP file and install an applet over an SCP03 channel\: INSTALL \[for load\], LOAD, INSTALL \[for install and make selectable\] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT' \
'put-key:Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'\''S ADMINISTRATIVE ACCESS' \
'cplc-set:Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING\: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor gp help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__ara_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__ara_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help ara commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help delete commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__gp__subcmd__help__subcmd__put-key_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__help__subcmd__put-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp help put-key commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__gp__subcmd__put-key_commands] )) ||
_sim-doctor__subcmd__gp__subcmd__put-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor gp put-key commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__help_commands] )) ||
_sim-doctor__subcmd__help_commands() {
    local commands; commands=(
'modules:Describe the crate module roots and the layering between them' \
'readers:List the PC/SC readers by name and index, for --reader or --reader-index' \
'scan:Select a card'\''s master file, walk everything under it, and report' \
'ts48:Compare a card against the public GSMA TS.48 test profile' \
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
'fuzz:APDU discovery and the OTA/SMS fuzz sweep' \
'euicc:eUICC queries over ES10 (lpac\: chip info, profile list, notification list), and the profile and notification writes' \
'card:A pySim-shell style shell over the card\: select files, read them, send APDUs' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'sim-doctor help commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__card_commands] )) ||
_sim-doctor__subcmd__help__subcmd__card_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help card commands' commands "$@"
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
'notifications:Pending notification metadata (lpac \`notification list\`); \`dump\` and \`replay\` below; \`notifications remove <seq>\` removes one' \
'nickname:Set a profile'\''s nickname (lpac \`profile nickname\`). A write\: a dry run unless \`--yes\`, never exposed over MCP' \
'enable:Enable a profile (lpac \`profile enable\`, ES10c EnableProfile with REFRESH). A dry run unless \`--yes\`\: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP' \
'disable:Disable a profile (lpac \`profile disable\`, ES10c DisableProfile with REFRESH). A dry run unless \`--yes\`\: disabling the only enabled profile leaves no active profile. Never exposed over MCP' \
'delete:Delete a profile (lpac \`profile delete\`, ES10c DeleteProfile). A dry run unless \`--yes\`\: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP' \
'reset:Reset the eUICC memory (lpac \`chip purge\`, ES10c eUICCMemoryReset). Can erase every profile\: nothing is selected by default, and sending needs both \`--yes\` and \`--confirm-eid <EID>\` matching the card. Never exposed over MCP' \
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
'info:Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA' \
'ara:Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA \[all\], decoded (read-only, no keys)' \
'status:GlobalPlatform registry inventory\: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication' \
'select:SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card'\''s current selection' \
'channel:Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N' \
'delete:Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT' \
'install:Load a CAP file and install an applet over an SCP03 channel\: INSTALL \[for load\], LOAD, INSTALL \[for install and make selectable\] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT' \
'put-key:Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD'\''S ADMINISTRATIVE ACCESS' \
'cplc-set:Write the CPLC pre-personalization or personalization block (STORE DATA with DGI 9F67 or 9F66, GlobalPlatformPro --set-pre-perso and --set-perso) over SCP03. WARNING\: this writes card-identifying CPLC data, and the change can be permanent on a card that locks its CPLC' \
    )
    _describe -t commands 'sim-doctor help gp commands' commands "$@"
}
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__ara_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__ara_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp ara commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__delete_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp delete commands' commands "$@"
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
(( $+functions[_sim-doctor__subcmd__help__subcmd__gp__subcmd__put-key_commands] )) ||
_sim-doctor__subcmd__help__subcmd__gp__subcmd__put-key_commands() {
    local commands; commands=()
    _describe -t commands 'sim-doctor help gp put-key commands' commands "$@"
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
