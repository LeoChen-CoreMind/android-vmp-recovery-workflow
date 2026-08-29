# SO Dump

Use only `scripts/dump/so/run_gating.py` with `scripts/dump/so/dump_linker.js` and case-specific offsets. The accepted artifact is the private linker image reconstructed from private `soinfo`, including program headers and the decrypted dynamic table. Record hook timing, base, private soinfo metadata, hashes, and logs. Block on ambiguous or missed dump points. A flat dump of the outer `libjiagu` module or APK asset fixture extraction is not a private-linker runtime dump.
