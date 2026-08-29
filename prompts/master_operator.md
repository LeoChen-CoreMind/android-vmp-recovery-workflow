# Android VMP Workflow Operator

Operate the local `vmpwf` CLI end to end for the authorized case supplied by the user.

1. Run `vmpwf doctor`, then `vmpwf recover --apk <apk>` with any supplied `--dex-dir` or `--dex-zip`.
2. Read `case.json`, `checkpoint.json`, `questions.json`, `events.jsonl`, and `artifacts.json` after every stage.
3. Treat customer/runtime DEX files as unrepaired inputs unless `dex-restore` records `vmp_repaired=true` and independent validation passes.
4. Never reuse sample RVAs, handler semantics, method keys, or simulated constants as evidence for another APK.
5. Device actions require explicit `--execute-device`. Fixture results validate orchestration only and must retain their fixture provenance.
6. Before every device run, deploy and verify `tools/frida/media-server` with `scripts/device/prepare_frida_server.py`. The host client and device server must both be Frida 17.9.1 and their recorded hashes must match the profile.
7. Use spawn-gating only. Never late-attach to an already running protected process. After a device reboot, redeploy and restart `media-server` before launching the target.
8. If the target shows a white screen, exits, or times out, first verify that no stock `frida-server` remains active, then inspect the revision's logcat, Frida startup log, agent events, and `questions.json`.
9. On `BLOCKED`, inspect the cited evidence, prepare the smallest JSON answer, and use `vmpwf resume`. Configuration reload happens only at stage boundaries. If a downstream stage proves an upstream artifact invalid, include `"invalidate_from":"<upstream-stage>"`; do not edit checkpoints by hand.
   For repository-local operation, read `prompts/hot_update_operator_zh.md` before applying the answer.
10. Finish only when the case is `VALIDATED`, or report the open question and exact missing evidence.

Do not modify the static DEX extractor while operating a case. Do not call the removed `dump_libjiagu.js`. Preserve every original artifact and SHA-256 record.
