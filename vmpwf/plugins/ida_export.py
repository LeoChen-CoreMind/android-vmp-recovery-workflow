from __future__ import annotations

import json
from pathlib import Path

from ..adapters import FixtureIdaAdapter, JsonIdaMcpAdapter
from ..core import StageBlocked
from ..provenance import file_record, sha256_file
from ..validation import validate_dispatch_map
from .common import BasePlugin


class IdaExport(BasePlugin):
    id = "ida-export"

    def run(self, context):
        fixed = context.case.get("artifacts", {}).get("so_fixed", [])
        binary = fixed[0] if fixed else ""
        config = {**context.profile.get("ida", {}), **context.case.get("ida", {})}
        output = context.revision_dir("ida/tables") / "dispatch_map.json"
        request = {"binary": binary, "architecture": config.get("architecture", context.profile.get("architecture", "AArch64")),
                   "image_base": config.get("image_base", "0x0"),
                   "root_rva": config.get("root_rva"), "output": str(output),
                   "requested_tables": ["dispatch", "width_candidates", "unit_decoders", "format_helpers"]}
        request_path = context.revision_dir("ida/requests") / "request.json"
        request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
        try:
            if config.get("adapter", "fixture") == "fixture":
                fixture = Path(config.get("fixture", context.repo_root / "fixtures/com.jumi.tv/handler_map.json"))
                if not fixture.is_absolute():
                    fixture = context.repo_root / fixture
                request["fixture"] = str(fixture)
                result = FixtureIdaAdapter().export(request)
            else:
                request["response"] = config.get("response")
                result = JsonIdaMcpAdapter().export(request)
        except Exception as exc:
            raise StageBlocked(context.question(self.id, f"IDA export failed: {exc}", [str(request_path)], ["ida"])) from exc
        if result.get("status") != "ok" or not isinstance(result.get("entries"), list):
            raise StageBlocked(context.question(self.id, "IDA response contract failed", [str(request_path)]))
        expected_binary_hash = sha256_file(Path(binary)) if binary and Path(binary).is_file() else None
        if expected_binary_hash and result.get("binary_sha256") != expected_binary_hash:
            raise StageBlocked(context.question(
                self.id, "IDA response belongs to a different binary",
                [f"expected={expected_binary_hash}", f"observed={result.get('binary_sha256')}"]))
        checks = validate_dispatch_map(result, allow_contextual=bool(context.profile.get("fixture")))
        if not checks["ok"]:
            raise StageBlocked(context.question(
                self.id, "IDA dispatch table is incomplete or ambiguous",
                [json.dumps(checks, ensure_ascii=False)], ["ida"]))
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        context.case.setdefault("artifacts", {})["ida_table"] = str(output.resolve()); context.save_case()
        return {"ok": True, "source": result.get("tool"), "entry_count": len(result["entries"]),
                "binary_sha256": result.get("binary_sha256"), "checks": checks,
                "artifacts": [file_record(request_path, context.case_dir), file_record(output, context.case_dir)]}
