from __future__ import annotations

from typing import Any


class BasePlugin:
    version = "1.0.0"

    def plan(self, context) -> dict[str, Any]:
        return {"stage": self.id, "plugin": type(self).__name__, "profile": context.case.get("profile")}

    def validate(self, context, result: dict[str, Any]) -> dict[str, Any]:
        return {"ok": bool(result.get("ok", True)), "checks": result.get("checks", [])}
