# VM Static Recovery

Use only matching customer IDA evidence and the DEX files selected by `dex-extract`. If every selected DEX has zero VMP method records, pause here and request a matching runtime DEX; the earlier SO dump/repair and IDA capability stages remain valid. Otherwise run the configured static command to produce `ida/tables/rev-*/vm_streams_enriched.json`; do not substitute fixture streams. Require every opcode row to be a complete `0..255` permutation, every reference index to be legal in its source DEX, zero unresolved opcodes/units, contiguous PCs, and final PC exactly equal to `insns_size`.

For invoke handlers, interpret an observed ART `InvokeType` selector as `0=static`, `1=direct`, `2=virtual`, `3=super`, `4=interface`. Validate register words exactly: static calls contain only prototype parameter words; direct, virtual, super, and interface calls contain one additional receiver word. Reject semantic maps that only accept both counts or whose invoke kind conflicts with the observed selector.

After semantic review, use `scripts/ida/bind_vm_evidence.py` to bind output to the current fixed SO, dispatch table, and simulation-config hashes with `semantics_confirmed=true`. Never force widths or append padding merely to close tiling.
