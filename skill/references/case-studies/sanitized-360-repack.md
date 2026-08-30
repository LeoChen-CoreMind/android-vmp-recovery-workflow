# Sanitized 360 APK Repack Case

Read this reference when preparing the final `apk-unpack-repack` adapter. All names, counts, and hashes below are illustrative; replace them with current-case evidence.

The reusable sequence is:

1. Inventory exact shell entries. Put entries that disappear in `remove_entries`; put a shell `classes.dex` replaced at the same path in `replace_entries` with the final DEX hash. Never use `libjiagu*.so` as a deletion rule.
2. Recover Application and AppComponentFactory from runtime/build evidence. The reference executor updates apktool-decoded XML structurally.
3. Inventory StubApp calls by owner, name, full descriptor, invoke form, result use, and fall-through behavior. The 2024 pattern `owner == StubApp || name == getOrigApplicationContext || returnType == Context` is unsafe because it matches unrelated methods.
4. Use `bridge_contracts.smali_patches` only on a declared smali tree. Each regex has file globs and an exact expected match count. Run `scripts/apk/patch_smali_calls.py --dry-run` first; a count mismatch must fail before writes.
5. A Context wrapper may be rewritten only after proving the argument is a Context and the following result use remains valid. A shell marker may become `nop` only when its return type is void and every current-version fall-through path was checked.
6. Reassemble and validate the patched DEX, then bind its path and hashes in `dex_layout`. The final APK executor does not discover instruction semantics.
7. Equal-length descriptor replacement is allowed only with exact occurrence and string-order evidence. The bridge class must already be present in the declared DEX set.
8. Use `scripts/apk/repack_from_adapter.py` as the reference executor for exact SO/asset removal, same-path DEX replacement, structured Manifest restoration, old-signature cleanup, apktool build, zipalign, and apksigner. Passwords remain in local environment variables.

Representative smali rules:

```json
{
  "id": "context-wrapper-to-framework-context",
  "files": ["smali*/com/example/**/*.smali"],
  "pattern": "^(?P<indent>[ \\t]*)invoke-static \\{(?P<register>[vp][0-9]+)\\}, Lcom/stub/StubApp;->getOrigApplicationContext\\(Landroid/content/Context;\\)Landroid/content/Context;[ \\t]*(?P<eol>\\r?)$",
  "replacement": "\\g<indent>invoke-virtual {\\g<register>}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;\\g<eol>",
  "expected_matches": 12,
  "flags": ["MULTILINE"],
  "evidence": ["current-version callsite inventory"]
}
```

```json
{
  "id": "confirmed-void-shell-markers-to-nop",
  "files": ["smali*/com/example/**/*.smali"],
  "pattern": "^(?P<indent>[ \\t]*)invoke-static(?:/range)? \\{[^}]*\\}, Lcom/stub/StubApp;->(?:interface11|interface22|interface24|mark)\\([^)]*\\)V[ \\t]*(?P<eol>\\r?)$",
  "replacement": "\\g<indent>nop\\g<eol>",
  "expected_matches": 4,
  "flags": ["MULTILINE"],
  "evidence": ["current-version void/fall-through proof"]
}
```

The complete repository example is `examples/apk-repack/sanitized-360-version-adapter.example.json`. It deliberately contains non-real hashes and cannot pass a real case hash gate.
