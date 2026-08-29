# Native Simulation

Native confirmation is implemented in code, not in the prompt. Use `scripts/simulation/run_native_confirmation.py`, which invokes `unicorn_literal_decoder.py`, with case-specific outer/linker/binary/config paths and `vm_streams_enriched.json`. Simulate only units whose static meaning remains uncertain; execute the real recovered AArch64 decoder functions rather than a Python reimplementation.

Hard-fail unknown PLT/external calls, aborts, stack-guard failures, invalid memory, unsupported relocations, or inconsistent constants across methods. Require result hashes for streams, binary, and config and preserve instruction traces under `simulation/results/rev-*`. Never import simulator constants, PLT stubs, or relocation values from another APK.
