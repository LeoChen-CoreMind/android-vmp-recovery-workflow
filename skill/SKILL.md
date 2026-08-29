---
name: android-vmp-recovery-workflow
description: Orchestrate an authorized Android 360 DexVMP recovery case through target confirmation, SO dump/repair, IDA evidence export, static VM recovery, native simulation, user-supplied DEX restoration, and independent validation with resumable checkpoints.
metadata:
  short-description: Run the staged Android DexVMP recovery workflow
---

# Android VMP Recovery Workflow

Use the bundled `vmpwf` CLI in `vmp-recovery-workflow` for case state, stage
contracts, provenance and resumable failures.

## Required behavior

- Require an explicit package and user-supplied DEX input.
- Confirm ADB package identity, ABI, UID/root and SELinux before device stages.
- Keep SO dump, repair, IDA export, static recovery, native simulation, DEX
  restore and independent validation as separate checkpoints.
- Treat `handler_map.json`, width candidates and MCP responses as evidence, not
  as trusted final semantics.
- Fail closed on unknown opcodes, ambiguous widths, invalid references,
  simulator faults, checksum errors or class-data size changes.
- On recoverable failures, write `questions.json` and `checkpoint.json`, pause,
  and resume only after a JSON answer increments `config_revision`.
- Preserve original artifacts and record SHA-256 for every output.

## Commands

```text
vmpwf init --case <dir> --package <name> --dex <path>
vmpwf run --case <dir>
vmpwf status --case <dir>
vmpwf resume --case <dir> --question <id> --answer <json>
vmpwf install-global
```

The DEX is supplied by the user; this workflow does not dump DEX from the
device automatically. Existing scripts in `so_dump` are invoked through case
command configuration and are never edited by this Skill.
