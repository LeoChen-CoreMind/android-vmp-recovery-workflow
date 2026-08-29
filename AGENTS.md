# Repository Agent Instructions

These instructions apply to the entire `vmp-recovery-workflow` repository.

## Purpose

This repository implements a local, resumable Android 360 DexVMP recovery workflow:

```text
APK -> DEX extraction/import -> target confirmation -> private linker/SO dump
-> SO repair -> IDA dispatcher export -> Unicorn native confirmation
-> VMP method recovery when records exist -> independent validation
```

Operate only on targets and files supplied by the user. Keep customer APK, DEX, SO, logs, and case evidence local unless the user explicitly requests another destination.

## Prompt Routing

- For a new or continuing end-to-end case, read `prompts/local_autonomous_operator_zh.md`.
- For an open `BLOCKED` question, a corrected parameter, or recovery after a framework patch, also read `prompts/hot_update_operator_zh.md`.
- Stage-specific prompts in `prompts/` define additional gates. Read the matching prompt before diagnosing or changing that stage.
- `README.md` contains user-facing launch templates. Keep it synchronized when prompt paths or workflow behavior change.

The prompts and `skills/android-vmp-workflow-hot-update/` are repository-local resources. Do not install them globally unless the user explicitly asks.

## First Checks

Before operating a case or changing framework behavior:

1. Run `vmpwf doctor` or `py -3 .\vmpwf.py doctor`.
2. Run `git status --short`; preserve unrelated user changes.
3. Resolve all input paths and record file size and SHA-256.
4. For an existing case, read `case.json`, `checkpoint.json`, `questions.json`, `events.jsonl`, and `artifacts.json`.
5. Confirm whether the requested scope is a real device case, offline fixture regression, framework development, or hot-update recovery.

## Evidence Rules

- Every case conclusion must cite local evidence: command output, device inventory, disassembly, JSON contracts, logs, hashes, or repeatable execution results.
- Never infer current-case facts from filenames, old notes, fixture success, or another APK.
- Never transfer RVAs, offsets, handler meanings, opcode semantics, method keys, widths, or simulator constants between APKs or SO revisions.
- Treat ambiguous or conflicting evidence as `BLOCKED`. Report the conflict and ask the user/framework author for the smallest missing decision.
- Do not convert likely, plausible, or visually similar behavior into a confirmed result.
- Preserve original evidence and revision outputs. Do not overwrite or delete earlier failure artifacts.

## Workflow Operation

- Use the real profile `android-arm64-360-dexvmp` for customer/device work. `offline-fixture` proves orchestration only.
- Device actions require `--execute-device` and must use the selected case/device identity.
- Static DEX extraction failure may fall back to a user-provided DEX ZIP or directory. Do not fabricate a DEX.
- A DEX is not VMP-restored unless the restore stage records actual restored methods and independent validation proves the output.
- If all DEX inputs have `method_records=0`, record that no VMP methods are recoverable. Continue SO/dispatcher validation, but never claim `vmp_repaired=true`.
- Stop at the highest evidence level the case supports and clearly distinguish passed, skipped/not-applicable, and blocked stages.

## Device And SO Rules

- Reject ABI/profile mismatch before Frida or Unicorn execution.
- Before each device dump, verify and start the profile-owned, hash-pinned `tools/frida/media-server`.
- Use spawn-gating. Do not late-attach to an already running protected process.
- The supported SO dump path is `scripts/dump/so/run_gating.py` plus `scripts/dump/so/dump_linker.js`.
- Never call the removed `dump_libjiagu.js`.
- A valid private-linker dump needs current-process metadata such as load start/size and private `soinfo` or equivalent dynamic-table evidence.
- Do not accept a normal outer `libjiagu` mapping dump as the private linker.
- After SoFixer, validate ELF class/machine, program headers, PT_LOAD, PT_DYNAMIC, required dynamic tags, and symbol evidence.

## IDA And Simulation Rules

- Open the exact fixed SO from the current case revision and verify its SHA-256 before analysis.
- Keep IDA `image_base` separate from runtime `pointer_base`.
- Derive dispatcher roots and helpers from the current SO call chain, pointer slots, xrefs, and disassembly.
- Dispatcher recognition must use the strict patterns in `vmpwf/ida_patterns.py`. A later unrelated `BR` is not dispatcher evidence.
- IDA exports must contain 256 opcodes with valid current-image handlers.
- Validate the exported table with `scripts/simulation/unicorn_dispatch_confirmation.py` against the same SO.
- Dispatcher acceptance requires 256/256 matches, zero mismatches, zero invalid memory, zero unknown external calls, and matching SO/export hashes.
- Method-level Unicorn or literal-decoder results require real current-case method records and configuration. Dispatcher confirmation is not method restoration evidence.

## DEX Recovery Rules

- Enter VM method recovery only when real LM/VMP method records exist.
- Require a closed opcode table, legal references, decoded instruction widths, and final PC equal to `insns_size` for every recovered method.
- Preserve code-unit length and class-data encoding constraints during DEX writeback.
- Require a repair manifest that covers every expected method.
- Before claiming success, validate checksum/signature/map integrity and run Android `dexdump` plus Java-backed JADX.
- Record actual tool commands, return codes, stdout/stderr, and output hashes. Do not hide partial JADX errors.

## Hot Update Contract

- Hot update means stage-boundary reload and resume. It is not in-process Frida or Unicorn code replacement.
- Apply case updates only through `vmpwf resume --case ... --question ... --answer ...`.
- Do not edit `checkpoint.json`, `questions.json`, `events.jsonl`, stage records, or question status manually.
- Answer JSON must use fields accepted by `resume_case` and contain only author-provided or uniquely evidenced values.
- Select `invalidate_from` as the earliest stage whose inputs, configuration, or artifacts are actually invalid.
- Verify that `config_revision` increments, invalidated records move to `stage_history`, downstream dependencies rerun, events are appended, and old artifacts remain.
- A new `BLOCKED` question starts a new evidence investigation. Do not submit repeated speculative answers.

## Framework Changes

- Diagnose whether a failure is a target-specific unknown, environment issue, tool failure, or framework defect before editing code.
- A framework patch must not encode current-case RVAs, offsets, handler semantics, DEX bytes, or fixture-only assumptions as defaults.
- Prefer configuration/schema extensions for case-specific values and reusable strict parsers for structural rules.
- Use `apply_patch` for manual edits. Keep changes scoped and preserve unrelated worktree changes.
- Update relevant prompts, README, schemas, profiles, or stage contracts when public behavior changes.
- Add focused regression tests for every demonstrated framework defect.

## Verification

For framework or prompt changes, run at minimum:

```powershell
py -3 -m pytest .\tests -q
git diff --check
py -3 .\vmpwf.py doctor
```

For a new repository-local Skill, also run:

```powershell
py -3 "$env:USERPROFILE\.codex\skills\.system\skill-creator\scripts\quick_validate.py" <skill-dir>
```

For real case evidence, rerun the affected stage gate and verify artifact hashes. Tests alone do not prove an APK-specific result.

## Questions And Reporting

When author input is required, report:

```text
Stage / question ID / revision
Verified facts
Failure or ambiguity
Evidence paths and hashes
Rejected candidates
Smallest author input required
Proposed invalidate_from and resume command
```

Final reports must distinguish framework test success from real-case success and state whether any VMP methods were actually restored.

## Git

- Do not commit case evidence, customer binaries, IDA databases, generated reports, logs, or tool executables.
- Before committing, inspect `git status`, run the required checks, and review the staged diff.
- Push only when the user requests repository submission or the active task already includes updating GitHub.
