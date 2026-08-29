# Native Simulation

Use `scripts/simulation/run_native_confirmation.py` with case-specific outer/linker/binary/config paths. It must batch the selected stream units through real AArch64 functions, hard-fail unknown calls, aborts, stack failures, or invalid memory, and bind the result to the current streams, binary, and config hashes. Never import simulation constants from another APK. Confirm cross-method invariants.
