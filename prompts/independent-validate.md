# Independent Validation

Validate every restored DEX independently from the restoration code: magic/header size/endian, file size, SHA-1, Adler32, map_list bounds, output hashes, and repair-manifest coverage. For a real restoration, require Android SDK `dexdump -f` and Java-backed JADX to accept every output; store their commands and reports under `reports/`. Missing Java, JADX, or dexdump is a recoverable blocking question, not a skipped check.

Run repeatability validation and require a second restoration from the same inputs/config to produce identical output hashes. Fixture pass-through is explicitly `orchestration-only` and does not prove customer VMP restoration.
