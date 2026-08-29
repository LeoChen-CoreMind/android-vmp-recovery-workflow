from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import file_record, sha256_file


class IdaAdapter:
    name = "base"

    def export(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class FixtureIdaAdapter(IdaAdapter):
    name = "fixture"

    def export(self, request: dict[str, Any]) -> dict[str, Any]:
        source = Path(request["fixture"])
        payload = json.loads(source.read_text(encoding="utf-8"))
        binary = Path(request["binary"])
        return {
            "status": "ok", "binary_sha256": sha256_file(binary) if binary.exists() else None,
            "entries": payload.get("entries", []),
            "width_candidates": payload.get("width_candidates", {}),
            "evidence": payload.get("evidence", []), "tool": "fixture",
            "tool_version": "local", "source": str(source.resolve()),
        }


class JsonIdaMcpAdapter(IdaAdapter):
    name = "ida-mcp"

    def export(self, request: dict[str, Any]) -> dict[str, Any]:
        # MCP transports differ between installations. The stable boundary is
        # a JSON request/response file; a bridge can replace this method later.
        response = request.get("response")
        if not response:
            raise RuntimeError("ida-mcp adapter requires --ida-response JSON")
        payload = json.loads(Path(response).read_text(encoding="utf-8"))
        required = ("status", "entries", "width_candidates", "evidence")
        missing = [key for key in required if key not in payload]
        if missing:
            raise RuntimeError(f"IDA MCP response missing fields: {missing}")
        return payload
