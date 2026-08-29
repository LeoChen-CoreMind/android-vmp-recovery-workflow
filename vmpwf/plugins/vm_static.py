from __future__ import annotations

import json
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record
from ..validation import validate_vm_streams
from .common import BasePlugin


class VmStatic(BasePlugin):
    id = "vm-static"

    def run(self, context):
        if context.profile.get("fixture"):
            fixture = Path(context.profile["vm"]["streams_fixture"])
            if not fixture.is_absolute():
                fixture = context.repo_root / fixture
            payload = json.loads(fixture.read_text(encoding="utf-8"))
            methods = payload.get("methods", [])
            if not isinstance(methods, list):
                raise StageBlocked(context.question(self.id, "VM fixture has no methods list", [str(fixture)]))
            checks = validate_vm_streams(payload)
            if not checks["ok"]:
                raise StageBlocked(context.question(self.id, "VM fixture failed stream validation", [json.dumps(checks)]))
            output = context.revision_dir("ida/tables") / "vm_streams_enriched.json"
            output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            context.case.setdefault("artifacts", {})["vm_streams"] = str(output.resolve()); context.save_case()
            return {"ok": True, "source": "reference-fixture", "methods": len(methods), "checks": checks,
                    "artifacts": [file_record(output, context.case_dir, fixture_origin=str(fixture.resolve()))]}
        summaries = context.case.get("vmp_inventory", [])
        if not any(isinstance(item.get("method_records"), int) and item["method_records"] > 0
                   for item in summaries if isinstance(item, dict)):
            raise StageBlocked(context.question(
                self.id,
                "No recoverable VMP method records were found; SO/IDA validation may complete, but VM recovery requires a matching runtime DEX",
                [json.dumps(summaries, ensure_ascii=False)], ["dex_dir", "dex_zip"]))
        command = context.profile.get("commands", {}).get("vm-static") or context.case.get("commands", {}).get("vm-static")
        if not command:
            raise StageBlocked(context.question(self.id, "Static VM command is not configured", [], ["commands.vm-static"]))
        output = context.revision_dir("ida/tables") / "vm_streams_enriched.json"
        dispatch = context.case.get("artifacts", {}).get("ida_table", "")
        dex_dir = str(Path(context.case["dex_inputs"][0]).parent) if context.case.get("dex_inputs") else ""
        values = {"case": str(context.case_dir), "output": str(output), "dispatch": dispatch, "dex_dir": dex_dir}
        result = run_command([str(value).format(**values) for value in command], context.case_dir, timeout=600)
        if result["returncode"]:
            raise StageBlocked(context.question(self.id, "Static VM recovery failed", [result["stderr"]]))
        if not output.is_file():
            configured = context.case.get("artifacts", {}).get("vm_streams")
            output = Path(configured) if configured else output
        if not output.is_file():
            raise StageBlocked(context.question(self.id, "Static VM recovery produced no stream JSON", [result["stdout"]]))
        payload = json.loads(output.read_text(encoding="utf-8"))
        checks = validate_vm_streams(payload, require_evidence=True)
        if not checks["ok"]:
            raise StageBlocked(context.question(self.id, "Static VM streams did not close cleanly", [json.dumps(checks)]))
        ida_hash = context.case.get("stage_records", {}).get("ida-export", {}).get("result", {}).get("binary_sha256")
        if payload.get("evidence", {}).get("binary_sha256") != ida_hash:
            raise StageBlocked(context.question(self.id, "VM streams belong to a different SO", [str(output)]))
        context.case.setdefault("artifacts", {})["vm_streams"] = str(output.resolve()); context.save_case()
        return {"ok": True, "source": "command", "command": result, "checks": checks,
                "artifacts": [file_record(output, context.case_dir)]}
