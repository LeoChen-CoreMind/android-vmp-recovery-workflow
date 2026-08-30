# APK Unpack And Repack

This is the final stage for real 360 profiles and runs only after independent DEX validation. Read the current case revision, then read `prompts/360-repack-version-adapter-zh.md` before creating or answering an adapter question. Fixture profiles record this stage as not applicable.

For the concrete adaptation pattern, read `docs/360-apk-repack-sanitized-case-study-zh.md` and the schema-valid shape in `examples/apk-repack/sanitized-360-version-adapter.example.json`.

Do not remove files or rewrite DEX/Manifest data from shell-family keywords alone. A valid adapter is bound to the independent-validation evidence revision and its activation case revision, APK SHA-256, every DEX source/output SHA-256, exact ZIP entry names, evidenced Application/AppComponentFactory values, and explicit bridge-call semantics. Another APK, another 360 release, an older case revision, or a successful fixture may be used only as an algorithm reference.

When no adapter exists, preserve the generated inventory and template, report `BLOCKED`, and request only `apk_repack.adapter`. When an adapter exists, validate it against `schemas/apk-repack-adapter.schema.json` before executing its command. Distinguish entries that disappear from entries replaced at the same ZIP path, including a shell `classes.dex` replaced by a business primary DEX. Reject wildcard changes, ambiguous DEX ordering, unequal descriptor replacement, unproved no-op calls, hash conflicts, duplicate ZIP entries, missing mapped DEX files, or any mismatch in manifest/signature/tool validation.

Completion requires the signed output APK and immutable repack manifest, exact mapped DEX hashes, all adapter-declared shell entries absent, no duplicate ZIP entries, expected Application and AppComponentFactory, successful dexdump/JADX/zipalign/apksigner, and device acceptance when the adapter requires it. Record real return codes and logs. Business signature or piracy checks are separate target behavior and must not be removed unless the adapter contains independent current-version evidence and the user explicitly includes that work in scope.
