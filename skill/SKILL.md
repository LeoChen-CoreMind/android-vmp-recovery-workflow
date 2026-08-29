---
name: android-vmp-recovery-workflow
description: Run a resumable Android 360 DexVMP case from customer APK and optional runtime DEX through SO dump/repair, IDA evidence export, native confirmation, VMP restoration, and independent validation.
metadata:
  short-description: Operate the APK-to-DexVMP recovery workflow
---

# Android VMP Recovery Workflow

Use the installed `vmpwf` CLI. Start with `vmpwf doctor`, then prefer:

```text
vmpwf recover --apk <apk> [--dex-dir <dir> | --dex-zip <zip>] --profile <profile>
```

Read [references/prompts/master_operator.md](references/prompts/master_operator.md) for autonomous operation and the matching stage prompt under `references/prompts/` before resolving a blocked stage.

Required invariants:

- Customer/runtime DEX files are unrepaired inputs until `dex-restore` and independent validation prove otherwise.
- Do not transfer RVAs, handler meanings, method keys, or simulator constants between APKs.
- Keep every recovery phase as a separate checkpoint.
- Device execution requires explicit `--execute-device`.
- Device execution uses the profile-owned, hash-verified `media-server`; redeploy it after reboot and use spawn-gating only.
- Reject a target ABI that is outside the selected profile before starting Frida or Unicorn.
- Fixture mode validates orchestration only and preserves fixture provenance.
- Real final validation requires restored-method coverage plus successful dexdump and JADX checks.
- Fail closed on ambiguous dump points, IDA widths, opcodes, references, simulator calls, code-unit lengths, or DEX integrity.
- Answer recoverable failures with `vmpwf resume`; it reloads at the stage boundary, invalidates downstream stages, and continues automatically.
- Preserve old artifacts and SHA-256 records. Do not modify the bundled static extractor while operating a case.
- Never call the removed `dump_libjiagu.js`; the runtime SO entrypoint is `run_gating.py` plus `dump_linker.js`.
