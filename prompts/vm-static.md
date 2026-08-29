# VM Static Recovery

Use only matching customer IDA evidence. Require opcode-table permutations, valid references, zero unresolved opcodes, and final PC equal to `insns_size`. After semantic review, use `scripts/ida/bind_vm_evidence.py` to bind output to the current SO, dispatch table, and simulation-config hashes with `semantics_confirmed=true`. Never force widths to close tiling.
