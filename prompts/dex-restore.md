# DEX Restore

Run `scripts/fix/dex/enrich_vm_streams.py` and `scripts/fix/dex/restore_vmp_dex.py` only after static and native evidence pass. Write only validated code units to the matching user/static DEX. Check source units, unchanged code-item length, method fields, ULEB128 space, tries/debug-info layout, references, SHA-1, Adler32, and map_list.

Require `vmp_restore_manifest.json` to cover every VMP method recorded during DEX ingest. Java is not required to patch DEX bytes, but Java and JADX are mandatory in the next independent-validation stage. Block instead of silently rebuilding unsupported layouts or claiming success when the method-record count is zero.
