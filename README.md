# Android DexVMP Recovery Workflow

Portable orchestration for the staged Android DexVMP recovery workflow.

The repository keeps the workflow engine separate from the existing `so_dump`
scripts. It records immutable evidence, validates stage contracts, and pauses
on recoverable analysis failures so configuration can be updated and resumed.

## Quick start

```powershell
py -3 .\vmpwf.py init --case .\cases\demo `
  --package com.example.app --device debbff75 --dex C:\path\classes3.dex
py -3 .\vmpwf.py status --case .\cases\demo
py -3 .\vmpwf.py run --case .\cases\demo
```

Device actions (Frida/spawn-gating) are opt-in:

```powershell
py -3 .\vmpwf.py run --case .\cases\demo --execute-device
```

Install the bundled Codex Skill globally:

```powershell
py -3 .\vmpwf.py install-global
```

The engine is standard-library-only. External tools are invoked only when a
stage is enabled and their paths are configured in `case.json`.
