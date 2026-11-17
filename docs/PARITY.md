# sim-doctor parity benchmark (issue #154)

**Date:** 2026-11-16  
**Branch:** `agent/154-benchmark`  
**Workspace:** `/Users/vaibhavtomar/Desktop/doctor-labs/wt-s154` (worktree of `fd-sim`, `origin/main` @ `752b8c6`)

This document is an evidence-based parity snapshot against the reference tools named in
[doctor-labs/sim-doctor#154](https://github.com/doctor-labs/sim-doctor/issues/154): SRLabs **SIMTester**,
osmocom **pySim / pySim-shell**, and **GlobalPlatformPro** (martinpaljak), with optional mentions of
cardpeek / osmo-sim-auth where relevant.

## Scope and method

- **Binding inputs/docs read in-repo:** `AGENTS.md`, `README.md`, `docs/research-report.md`, `docs/doctor-contract.md`,
  `docs/swsim-fixture.md`, CLI surface (`src/main.rs`, `sim-doctor --help`), and implementation notes in
  `AGENTS.md` (TAR/OTA, `gp`, `euicc`, `card` shell, decoders, rules).
- **Reference tool environment checked (per issue instructions):** Instabbox sandbox `clean-1`,
  `/data/workspace/doctor-labs/tools/` and `/data/workspace/doctor-labs/tools/AVAILABLE.md`.
- **Runnable comparison policy:** run reference tools that are runnable over the same inputs sim-doctor handles and
  record results with quoted commands/versions. Record **“not compared”** honestly where a tool is unavailable or
  requires inputs/hardware not present (e.g. live cards). No fabricated runs or outputs.

## Reference tools on `clean-1` (evidence)

Manifest inspected on 2026-11-16:

```bash
instabox exec clean-1 --cwd /tmp --timeout 120 -- bash -lc \
  'ls -la /data/workspace/doctor-labs/tools 2>&1; echo "---"; cat /data/workspace/doctor-labs/tools/AVAILABLE.md 2>&1'
```

`AVAILABLE.md` (updated 2026-11-16 UTC on sandbox) lists avbtool, magiskboot, payload_dumper, MobSF rule data,
NetworkMiner fingerprint data, .NET runtime, avbroot, Zeek, etc. — **no `pysim`, `pySim-shell`, `SIMTester`,
`GlobalPlatformPro`, `cardpeek`, or `osmo-sim-auth` entries**.

Targeted searches on `clean-1` found no installed SIM reference tools:

```bash
instabox exec clean-1 --cwd /tmp --timeout 180 -- bash -lc \
  'find /data/workspace/doctor-labs -iname "*simtester*" -o -iname "*pysim*" -o -iname "*globalplatform*" -o -iname "*cardpeek*" -o -iname "gp.jar" -o -iname "*GlobalPlatform*" 2>&1 | head -120'
# (no matches)

instabox exec clean-1 --cwd /tmp --timeout 120 -- bash -lc \
  'python3 -m pip show pySim 2>&1 | head -40; echo "---"; command -v gp 2>&1 || true'
# WARNING: Package(s) not found: pySim
# (gp not found)
```

**Conclusion:** the named reference tools were **not runnable** on `clean-1` in the state observed during this
benchmark, so direct execution-based comparison against them on identical card inputs was **not possible** here.

## sim-doctor capabilities (observed from this repo state)

Evidence: `sim-doctor --help`, `AGENTS.md`, `README.md`, and source modules cited in `AGENTS.md`.

| Area | sim-doctor (this state) | Evidence |
|---|---|---|
| Core scan/walk | PC/SC scan of MF/DF/EF tree with bounds, dialect selection, truncation reporting, findings/rules, `doctor/1` JSON, SARIF, baseline/fail-on, TUI, shell/explore | `README.md`, `AGENTS.md` §3, `src/scan.rs`, `src/walk.rs`, `src/kit.rs` |
| TAR / OTA security | `--tar` probing (MSL 0 / TAR scanning logic described and implemented; differential-style calibration and bounded sweeps per `AGENTS.md` #24), OTA/CAT/SMS decode tooling (`cat`, SMS/OTA helpers in tree), APDU/OTA fuzz modes with strong interlocks (software-card by default) | `AGENTS.md` “TAR scanning and MSL=0”, `src/tar.rs`, `src/apdu_fuzz.rs`, `src/cat.rs`, `src/sms.rs`, `src/ota*.rs` |
| Filesystem / decoders | Walk + EF/DF handling, TS.48 compare, many EF/decoder paths and rule docs; interactive-style `card` shell with pySim-shell-like command names and state (read-only sends; writes dry-run unless `--yes`) | `AGENTS.md` §5.3/TS.48 notes, `src/cardsh.rs`, `src/card_cmd.rs`, `docs/rule_docs/`, `tests/corpus/cardsh_*.jsonl` |
| GlobalPlatform | Read-only `gp info/ara/status/select/channel`; SCP03 authenticated status (`--keys-file|--keys-env`, one attempt, no key echo); SCP02 establish (dry-run unless `--yes`); write ops `delete/install/put-key` (dry-run unless `--yes`, pre-checks, registry verify); logical channel handling; DAP options on install; not exposed as MCP write tools | `AGENTS.md` “GlobalPlatform reads/writes”, `src/gp.rs`, `src/scp03.rs`, `src/scp02.rs`, `src/apdu.rs` |
| eUICC / ES10 / ES9+ | Read-only `euicc info/profiles/notifications`; writes `nickname/enable/disable/delete/reset/notifications remove` with dry-run/confirm/re-verify safeguards; notification dump/replay (network on replay with `--yes`); ES10/ES9+ HTTPS backend design documented; not all writes exposed over MCP | `AGENTS.md` §5.4/§5.6, `src/euicc.rs`, `src/es10.rs`, `src/es9_https.rs`, `src/notif.rs` |
| Automation / agent UX | `doctor/1` envelope, stable exit codes, `--json/--sarif/--baseline/--fail-on`, MCP server (read-only tool subset incl. scan/rules/euicc reads/gp reads), `fix/why/rules/install/ci/completions`, replay/trace-oriented tests and corpus fixtures | `README.md`, `AGENTS.md` §3, `src/kit.rs`, `src/mcp.rs`, `tests/golden*.rs` |

## Feature matrix (sim-doctor vs reference tools)

Legend: **Yes/Partial/No/Unknown** for sim-doctor is based on inspected repo state above. For reference tools,
**Not compared (tool unavailable on clean-1; no live-card run)** means no executable/version/output evidence was
collected in this environment; expected strengths are summarized from #154/`AGENTS.md` context only and marked
accordingly.

| Axis | SRLabs SIMTester | osmocom pySim / pySim-shell | GlobalPlatformPro (martinpaljak) | sim-doctor (evidence) |
|---|---|---|---|---|
| **Filesystem traversal completeness** | Not compared (unavailable). Historically strong file/TAR scanning focus. | Not compared (unavailable). Known for interactive navigation and broad profile/EF handling. | Not compared (unavailable). GP/app lifecycle focused, not a general SIM FS scanner. | **Partial/Yes (card-dependent):** bounded PC/SC walk with truncation/limits reporting, dialect & candidate-set caveats, TS.48 compare; `card` shell for manual-style navigation commands implemented in-repo. No live-card run in this benchmark. |
| **EF/DF decoder coverage** | Not compared (unavailable). | Not compared (unavailable). Extensive EF decoders/profiles are a primary strength. | Not compared (unavailable). | **Partial:** decoder coverage expanded over time (`AGENTS.md` notes batches/rule docs), but exhaustive parity with pySim’s profile breadth not established by execution here. |
| **GP command coverage & SCP03/02/11 support** | Not compared (unavailable). | Not compared (unavailable). Has SCP/auth/key commands in shell contexts. | Not compared (unavailable). Reference GP client for list/install/delete/put-key etc.; rich SCP/profile support expected. | **Partial:** read APIs + SCP03 auth/read channeling, SCP02 establish path, delete/install/put-key (guarded), logical channels, DAP on install; **SCP11 not evidenced** in inspected docs/CLI; full GPP command breadth not execution-compared. |
| **OTA/TAR security tests** | Not compared (unavailable). Origin/reference for TAR/MSL-0 style testing; calibration-failure behavior is a key comparison point in #154 but not observed here. | Not compared (unavailable). OTA tooling exists in ecosystem; not run here. | Not compared (unavailable). | **Partial:** `--tar` MSL-0 probing and OTA/SMS/CAT decode/fuzz tooling present with safety interlocks; live-card calibration-failure parity vs SIMTester **not compared** (no tool, no live card). |
| **Output format & automation/agent-friendliness** | Not compared (unavailable). | Not compared (unavailable). Interactive shell strengths; machine-friendly output varies by command. | Not compared (unavailable). CLI/scriptable but format differs from doctor envelope. | **Yes (design goal, evidenced):** `doctor/1` JSON, exit-code semantics, SARIF, baselines, MCP, `fix/why/install/ci`, dry-run defaults and explicit safety gates for mutating ops. |
| **UX (interactive/manual navigation)** | Not compared (unavailable). | Not compared (unavailable). Interactive `pySim-shell` is the benchmark for manual select/ls/read workflows. | Not compared (unavailable). | **Partial:** `sim-doctor card` provides a pySim-shell-like interactive/scriptable surface and `shell/explore` for scan results, but full parity with pySim-shell command breadth/ergonomics **not execution-compared**. |

## Evidence-based parity gaps / follow-ups (from #154 intent, not closed by this doc)

Because runnable reference-tool executions were unavailable on `clean-1`, gaps below are **tracked as comparison
obligations** aligned to #154 rather than measured deltas from live runs:

1. **SIMTester TAR/MSL-0 behavior parity (especially calibration failure handling).**  
   *Evidence gap:* SIMTester not installed/runnable on `clean-1`; no live card. sim-doctor documents/implements
   differential TAR probing (`AGENTS.md` #24) but behavior under calibration failure vs SIMTester remains **not compared**.
2. **pySim/pySim-shell filesystem & decoder breadth + interactive manual navigation parity.**  
   *Evidence gap:* pySim/pySim-shell unavailable; sim-doctor has `card` shell and decoders, but side-by-side EF/profile
   coverage and interactive workflow completeness **not compared**.
3. **GlobalPlatformPro GP/SCP command and interoperability parity.**  
   *Evidence gap:* GlobalPlatformPro unavailable; sim-doctor GP implementation is substantial and guarded, but command
   matrix/SCP variants (notably SCP11, broader key/DAP scenarios) and real-card interoperability **not compared**.
4. **Optional references (cardpeek, osmo-sim-auth).**  
   *Evidence gap:* not present/runnable on `clean-1`; **not compared**.

> Per issue #154 deliverables, concrete follow-up issues should be filed/linked from this tracking issue by maintainers
> as gaps are validated with runnable tools and/or live cards. This document does not open or close issues.

## Inputs actually exercised in this benchmark

- **Runnable reference tools executed:** none (none available on `clean-1`; searches/manifest quoted above).
- **sim-doctor source/contract inspection:** yes (local repo files and CLI help/build context in this worktree).
- **Live SIM/UICC/eUICC card runs:** none (no PC/SC card session performed in this environment as part of this report).
- **Replay/fixture corpora present in repo (not executed as cross-tool comparisons):** `tests/corpus/*.jsonl`, TS.48
  derived list `tests/corpus/ts48/ts48-v7.0-files.json`.

## Honesty / limitations

- This is a **capability and environment snapshot**, not a measured performance/correctness bakeoff against running
  SIMTester/pySim/GlobalPlatformPro binaries.
- Where #154 states those tools are on `clean-1` under `/data/workspace/doctor-labs/tools/`, the observed manifest and
  filesystem searches on 2026-11-16 did **not** show them; the report records that mismatch as evidence.
- Any parity claim requiring identical live-card behavior remains **not compared** until the tools and suitable card
  inputs are available.
