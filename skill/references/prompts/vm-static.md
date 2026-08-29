# VM Static Recovery

Use only matching customer IDA evidence and the DEX files selected by `dex-extract`. Run the configured static command to produce `ida/tables/rev-*/vm_streams_enriched.json`; do not substitute fixture streams. Require every opcode row to be a complete `0..255` permutation, every reference index to be legal in its source DEX, zero unresolved opcodes/units, contiguous PCs, and final PC exactly equal to `insns_size`.

After semantic review, use `scripts/ida/bind_vm_evidence.py` to bind output to the current fixed SO, dispatch table, and simulation-config hashes with `semantics_confirmed=true`. If no VMP method records exist, return to `dex-extract` and request a matching runtime DEX. Never force widths or append padding merely to close tiling.
