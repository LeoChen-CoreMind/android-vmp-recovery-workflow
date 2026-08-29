# DEX Extract

Run the unchanged `scripts/dump/dex/extract_360_dex.py` and record its command, logs, hashes, DEX checksum fields, map_list, LM summary, opcode-table size, and method-record count. Import supplied runtime DEX with `import_runtime_dex.py` or the directory/ZIP adapters and preserve `source=user-supplied` provenance.

Never label imported DEX as statically decrypted or VMP repaired. A structurally valid DEX is still insufficient when every LM summary has `method_records=0`; for a real VMP case, pause and request a matching runtime DEX through `dex_dir` or `dex_zip`. Do not continue to SO/IDA merely because the DEX checksum passes.
