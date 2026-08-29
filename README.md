# Android 360 DexVMP Recovery Workflow

`vmpwf` is a resumable APK-to-DexVMP orchestration framework. It records case provenance, runs stage plugins, preserves immutable evidence by configuration revision, and pauses with structured questions when evidence is incomplete.

## Workflow

```text
APK ingest -> DEX static extraction/user fallback -> target confirmation
-> SO dump -> SO repair -> IDA JSON export -> static VM recovery
-> native simulation -> DEX restore -> independent validation
```

The bundled static extractor is an unchanged compatibility script. User/runtime DEX input remains classified as unrepaired until a real customer-specific IDA/simulation/restore chain proves otherwise.

A valid DEX set with zero VMP method records does not block target confirmation, SO dump/repair, IDA table export, or dispatcher-level Unicorn validation. The workflow records a pass-through DEX report with `vmp_repaired=false`; method-stream recovery is marked not required for that case.

The first device profile is ARM64-only. It rejects a 32-bit target before loading the ARM64 Frida or Unicorn components. SO layout offsets, IDA root/helper RVAs, and native simulation addresses are case configuration, never reusable defaults.

Native confirmation is implemented by `scripts/simulation/run_native_confirmation.py`. Set `simulation.outer`, `simulation.linker`, `simulation.binary`, and `simulation.config` in the case; the `native-sim` plugin invokes the runner automatically and writes a hash-bound `native_simulation.json` report.

Runtime SO recovery has one supported entrypoint: `scripts/dump/so/run_gating.py` loads `scripts/dump/so/dump_linker.js` with case-specific offsets. A simple post-`dlopen` dump of the outer `libjiagu` mapping is not accepted as the private linker because it lacks the private `soinfo` evidence, synthetic ELF reconstruction, and decrypted dynamic-table overlay required by later IDA analysis.

## Case layout

Cases are created under `cases/<package>/<case-id>/` with `input`, `dump/so`, `dump/dex`, `fix/so`, `fix/dex`, `ida`, `simulation`, `reports`, and `logs` directories. `case.json`, `checkpoint.json`, `questions.json`, `events.jsonl`, and `artifacts.json` hold state and provenance.

## Commands

```powershell
py -3 .\vmpwf.py doctor

py -3 .\vmpwf.py recover `
  --apk "C:\path\target.apk" `
  --dex-zip "C:\path\runtime-dex.zip" `
  --profile offline-fixture

py -3 .\vmpwf.py run --case .\cases\com.example.app\<case-id> --execute-device
py -3 .\vmpwf.py status --case <case-dir>
py -3 .\vmpwf.py plan --case <case-dir>
py -3 .\vmpwf.py validate --case <case-dir>
py -3 .\vmpwf.py resume --case <case-dir> --question q-0001 --answer answer.json
py -3 .\vmpwf.py install-global
```

`offline-fixture` validates orchestration and file contracts. Its reference IDA/VM evidence is explicitly not customer semantics. The normal `android-arm64-360-dexvmp` profile requires real device commands, customer-specific IDA output, and a real restoration result.

`resume` applies the answer, increments `config_revision`, archives invalidated stage records, and immediately continues from the first affected checkpoint. `artifacts.json` is append-only across revisions.

Real final validation fails closed unless Android SDK `dexdump` and Java-backed JADX accept every restored DEX. `doctor` resolves tools from `PATH` and automatically discovers the newest installed Android SDK Build Tools when `dexdump` is not on `PATH`. Fixture validation reports `validation_scope=orchestration-only` and `vmp_repaired=false`.

Repeatability requires identical customer inputs and restored DEX hashes. Runtime SO, IDA, and simulation intermediates are reported separately because ASLR-sensitive addresses and their bound hashes may vary between otherwise equivalent device launches.

## Development

```powershell
py -3 -m pip install -e .
py -3 -m pytest -q
```

SoFixer, Java/JADX, dexdump, and IDA remain locally configured external tools. The user-supplied, hash-pinned Frida 17.9.1 `media-server` is stored under `tools/frida/` because device preparation is part of the reproducible anti-debug workflow; its manifest records the expected size, SHA-256, version, and remote path.
