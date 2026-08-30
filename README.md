# Android 360 DexVMP Recovery Workflow

`vmpwf` is a resumable APK-to-DexVMP orchestration framework. It records case provenance, runs stage plugins, preserves immutable evidence by configuration revision, and pauses with structured questions when evidence is incomplete.

Repository automation rules are defined in `AGENTS.md`. Codex or another coding agent entering this repository should read it before operating a case or modifying the framework.

## Workflow

```text
APK ingest -> DEX static extraction/user fallback -> target confirmation
-> SO dump -> SO repair -> IDA JSON export -> static VM recovery
-> native simulation -> DEX restore -> independent validation
-> version-specific 360 feature removal -> signed APK repack validation
```

The bundled static extractor is an unchanged compatibility script. User/runtime DEX input remains classified as unrepaired until a real customer-specific IDA/simulation/restore chain proves otherwise.

A valid DEX set with zero VMP method records does not block target confirmation, SO dump/repair, IDA table export, or dispatcher-level Unicorn validation. The workflow records a pass-through DEX report with `vmp_repaired=false`; method-stream recovery is marked not required for that case.

The first device profile is ARM64-only. It rejects a 32-bit target before loading the ARM64 Frida or Unicorn components. SO layout offsets, IDA root/helper RVAs, and native simulation addresses are case configuration, never reusable defaults.

Native confirmation is implemented by `scripts/simulation/run_native_confirmation.py`. Set `simulation.outer`, `simulation.linker`, `simulation.binary`, and `simulation.config` in the case; the `native-sim` plugin invokes the runner automatically and writes a hash-bound `native_simulation.json` report.

Runtime SO recovery has one supported entrypoint: `scripts/dump/so/run_gating.py` loads `scripts/dump/so/dump_linker.js` with case-specific offsets. A simple post-`dlopen` dump of the outer `libjiagu` mapping is not accepted as the private linker because it lacks the private `soinfo` evidence, synthetic ELF reconstruction, and decrypted dynamic-table overlay required by later IDA analysis.

The reproducible Frida startup and anti-detection boundary is documented in [docs/frida-spawn-gating-anti-debug-zh.md](docs/frida-spawn-gating-anti-debug-zh.md). It covers the hash-pinned renamed server, reboot redeployment, spawn-gating lifecycle, empty spawn-identifier handling, pre-`JNI_OnLoad` timing, evidence logs, and the known crash risk of inline-hooking manually mapped private code.

The real 360 profile finishes with `apk-unpack-repack`. The operator reads `prompts/apk-unpack-repack.md` and `prompts/360-repack-version-adapter-zh.md`, builds a current-revision adapter, then executes and validates the signed APK. The adapter is deliberately per-version: another APK may inform the algorithm, but its Application class, DEX numbering, shell entries, bridge methods, call counts, descriptor substitutions, or signing behavior are never accepted as current evidence.

A concrete sanitized implementation example is documented in [docs/360-apk-repack-sanitized-case-study-zh.md](docs/360-apk-repack-sanitized-case-study-zh.md). Its companion adapter is `examples/apk-repack/sanitized-360-version-adapter.example.json`. `scripts/apk/patch_smali_calls.py` demonstrates exact-count scoped smali regex changes, while `scripts/apk/repack_from_adapter.py` demonstrates exact shell asset/SO removal, DEX injection, structured Manifest restoration, old-signature cleanup, apktool rebuild, alignment, and signing.

## Local AI Operator Prompt

The repository-only Chinese prompt is stored at `prompts/local_autonomous_operator_zh.md`. It is not installed into the global Codex Skill. For a new task, replace the paths in the following short launcher and give it to the AI; the referenced prompt contains the complete evidence, blocking, and author-question rules.

```text
请读取并严格执行：
C:\Users\Rabe\Desktop\360\vmp-recovery-workflow\prompts\local_autonomous_operator_zh.md

框架目录：
C:\Users\Rabe\Desktop\360\vmp-recovery-workflow

本次输入：
- APK：C:\path\target.apk
- DEX ZIP：C:\path\runtime-dex.zip（没有则写 null）
- DEX 目录：null
- 设备序列号：null
- 已有案件目录：null

请全程在本地使用 `vmpwf`、ADB/root、IDA Pro MCP 和 Unicorn 自动执行。所有结论必须有命令输出、日志、反汇编、JSON 或 SHA-256 证据。遇到框架缺陷、未知偏移、多个候选、证据冲突或需要作者选择时，立即按提示词规定的 BLOCKED 格式向我/框架作者提问；不要猜测，不要套用其他 APP 或 fixture 的参数。
```

Input variants:

```text
APK only: set DEX ZIP and DEX directory to null. The workflow tries static extraction first.
APK + DEX ZIP: provide the runtime dump ZIP as fallback/real DEX input.
APK + DEX directory: provide the directory containing classes*.dex.
Resume a case: set the existing case directory and keep the original APK/DEX paths for provenance checks.
```

The full prompt explicitly authorizes local device/tool operation but forbids uploading customer artifacts. It also requires the AI to stop and ask the author whenever case-specific facts cannot be derived from evidence. Do not replace those questions with guessed offsets, handler meanings, widths, opcodes, or method records.

## Hot Update Prompt And Skill

The workflow already implements resumable hot updates at stage boundaries:

- `vmpwf resume` applies a structured answer to an open question.
- `config_revision` increments on every accepted update.
- The selected stage and its downstream dependents are invalidated automatically.
- Previous stage records move to `stage_history`.
- Old revision artifacts and event history remain available.
- Configuration is not reloaded inside a running Frida hook or Unicorn execution.

Repository-only hot-update resources:

```text
Prompt: prompts/hot_update_operator_zh.md
Skill source: skills/android-vmp-workflow-hot-update/SKILL.md
```

These resources are not installed by `install-global`. Use the hot-update prompt when a case is `BLOCKED`, when an author supplies corrected offsets/configuration, or after a tested framework patch.

Quick launcher:

```text
请读取并严格执行：
C:\Users\Rabe\Desktop\360\vmp-recovery-workflow\prompts\hot_update_operator_zh.md

框架目录：
C:\Users\Rabe\Desktop\360\vmp-recovery-workflow

案件目录：C:\Users\Rabe\Desktop\360\vmp-recovery-workflow\cases\<package>\<case-id>
问题 ID：q-xxxx
作者提供的新信息：<配置 JSON、offset、DEX 路径、IDA response 或补丁说明>

只允许在阶段边界通过 `vmpwf resume` 应用更新。请验证 revision、stage_history、下游失效和旧产物保留。任何不能由当前案件证据唯一确定的值，都必须向我/框架作者提问，不得猜测。
```

## Case layout

Cases are created under `cases/<package>/<case-id>/` with `input`, `dump/so`, `dump/dex`, `fix/so`, `fix/dex`, `ida`, `simulation`, `repack/adapter`, `repack/output`, `reports`, and `logs` directories. `case.json`, `checkpoint.json`, `questions.json`, `events.jsonl`, and `artifacts.json` hold state and provenance.

## Commands

```powershell
py -3 .\vmpwf.py doctor

py -3 .\vmpwf.py recover `
  --apk "C:\path\target.apk" `
  --dex-zip "C:\path\runtime-dex.zip" `
  --profile android-arm64-360-dexvmp

py -3 .\vmpwf.py run --case .\cases\com.example.app\<case-id> --execute-device
py -3 .\vmpwf.py status --case <case-dir>
py -3 .\vmpwf.py plan --case <case-dir>
py -3 .\vmpwf.py validate --case <case-dir>
py -3 .\vmpwf.py resume --case <case-dir> --question q-0001 --answer answer.json
py -3 .\vmpwf.py install-global
```

`offline-fixture` validates orchestration and file contracts. Its reference IDA/VM evidence is explicitly not customer semantics and its repack stage is not applicable. The normal `android-arm64-360-dexvmp` profile requires real device commands, customer-specific IDA output, a real restoration result, and a current-version APK repack adapter. If the adapter is not supplied initially, the final stage writes an inventory/template and opens a structured question for the AI operator to resolve.

`resume` applies the answer, increments `config_revision`, archives invalidated stage records, and immediately continues from the first affected checkpoint. `artifacts.json` is append-only across revisions.

Real final validation requires Android SDK `dexdump` to accept every restored DEX. Java-backed JADX must either complete in default mode or report exactly the same error count and method set as the source DEX, with no restored method in that set, while fallback mode completes successfully. `doctor` resolves tools from `PATH` and automatically discovers the newest installed Android SDK Build Tools when `dexdump` is not on `PATH`. Fixture validation reports `validation_scope=orchestration-only` and `vmp_repaired=false`.

VM semantic maps fail closed on invoke receiver counts. An ART `InvokeType` selector is interpreted as `0=static`, `1=direct`, `2=virtual`, `3=super`, `4=interface`; static calls contain only prototype parameter words, while the other supported invoke kinds contain one additional receiver word.

Repeatability requires identical customer inputs and restored DEX hashes. Runtime SO, IDA, and simulation intermediates are reported separately because ASLR-sensitive addresses and their bound hashes may vary between otherwise equivalent device launches.

## Development

```powershell
py -3 -m pip install -e .
py -3 -m pytest -q
```

SoFixer, Java/JADX, dexdump, and IDA remain locally configured external tools. The user-supplied, hash-pinned Frida 17.9.1 `media-server` is stored under `tools/frida/` because device preparation is part of the reproducible anti-debug workflow; its manifest records the expected size, SHA-256, version, and remote path.
