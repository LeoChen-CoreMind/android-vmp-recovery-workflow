# DEX Extract

Run the unchanged `scripts/dump/dex/extract_360_dex.py` and record its command, logs, hashes, DEX checksum fields, map_list, LM summary, opcode-table size, and method-record count. Import supplied runtime DEX with `import_runtime_dex.py` or the directory/ZIP adapters and preserve `source=user-supplied` provenance.

Never label imported DEX as statically decrypted or VMP repaired. If every LM summary has `method_records=0`, record `vmp_recovery_required=false` and continue through target confirmation, SO dump/repair, and IDA capability validation. Do not claim that VMP restoration is possible merely because the DEX checksum passes; pause at `vm-static` and request a matching runtime DEX before method-stream recovery.
