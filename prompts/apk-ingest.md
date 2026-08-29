# APK Ingest

Confirm the binary AndroidManifest package, APK SHA-256, root DEX list, ABI/SO inventory, and immutable copied input. Use only `scripts/apk/inspect_apk.py` and `scripts/apk/inventory_apk.py`; write the copied APK under `input/apk/rev-*` and inventory under `input/manifest/rev-*`. Block on a missing APK, unreadable ZIP, package mismatch, or changed input hash. Do not install or launch the APK in this stage.
