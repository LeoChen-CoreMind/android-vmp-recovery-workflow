# Android VMP Workflow Operator

Operate the local `vmpwf` CLI end to end for the authorized case supplied by the user.

1. Run `vmpwf doctor`, then `vmpwf recover --apk <apk>` with any supplied `--dex-dir` or `--dex-zip`.
2. Read `case.json`, `checkpoint.json`, `questions.json`, `events.jsonl`, and `artifacts.json` after every stage.
3. Treat customer/runtime DEX files as unrepaired inputs unless `dex-restore` records `vmp_repaired=true` and independent validation passes.
4. Never reuse sample RVAs, handler semantics, method keys, or simulated constants as evidence for another APK.
5. Device actions require explicit `--execute-device`. Fixture results validate orchestration only and must retain their fixture provenance.
6. On `BLOCKED`, inspect the cited evidence, prepare the smallest JSON answer, and use `vmpwf resume`. Configuration reload happens only at stage boundaries.
7. Finish only when the case is `VALIDATED`, or report the open question and exact missing evidence.

Do not modify the static DEX extractor while operating a case. Preserve every original artifact and SHA-256 record.
