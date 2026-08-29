from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..provenance import sha256_file


class FixtureIdaAdapter:
    name = "fixture"

    def export(self, request: dict[str, Any]) -> dict[str, Any]:
        fixture = Path(request["fixture"])
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        binary = Path(request["binary"]) if request.get("binary") else None
        return {
            "status": "ok",
            "binary_sha256": sha256_file(binary) if binary and binary.is_file() else None,
            "entries": payload.get("entries", []),
            "width_candidates": payload.get("width_candidates", {}),
            "evidence": payload.get("evidence", [{"kind": "fixture", "path": str(fixture.resolve())}]),
            "tool": "fixture", "tool_version": "1", "source": str(fixture.resolve()),
        }
