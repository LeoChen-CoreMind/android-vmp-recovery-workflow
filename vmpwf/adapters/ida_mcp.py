from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonIdaMcpAdapter:
    name = "ida-mcp"

    def export(self, request: dict[str, Any]) -> dict[str, Any]:
        response = request.get("response")
        if not response:
            raise RuntimeError("IDA MCP transport must produce a response JSON path")
        payload = json.loads(Path(response).read_text(encoding="utf-8"))
        missing = [key for key in ("status", "entries", "width_candidates", "evidence", "tool", "tool_version") if key not in payload]
        if missing:
            raise RuntimeError(f"IDA response missing fields: {missing}")
        return payload
