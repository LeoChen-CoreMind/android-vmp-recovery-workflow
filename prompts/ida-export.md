# IDA Export

Open the exact `fix/so/rev-*/..._fixed.so` recorded by `so-repair` in IDA Pro MCP and verify the MCP health input path and SHA-256 before analysis. Follow current-build `JNI_OnLoad`/RegisterNatives/interpreter wrapper pointer slots to the real dispatcher; never reuse a root RVA, decoder RVA, helper RVA, width, or handler meaning from another APK.

Populate the current request with case-specific `root_rva` and analysis evidence, run `scripts/ida/ida_dispatch_map.py`, then use `scripts/ida/build_mcp_response.py` to produce `ida/responses/rev-*/response.json`. The response must contain `status`, exact `binary_sha256`, 256 entries, one width candidate per opcode, `width_candidates`, evidence paths, `tool=ida-mcp`, and tool version.

Resume with an answer shaped like `{"ida":{"adapter":"ida-mcp","response":"<absolute response.json>"}}`. Block on an unresolved dispatcher root, non-code handler, multiple widths, missing opcode, or hash mismatch. Reference fixtures are not customer semantics.
