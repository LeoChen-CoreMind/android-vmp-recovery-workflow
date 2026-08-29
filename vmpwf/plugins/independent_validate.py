from __future__ import annotations

import json
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record
from ..tooling import resolve_tool
from ..validation import lm_summary, valid_dex_file
from .common import BasePlugin


class IndependentValidate(BasePlugin):
    id = "independent-validate"

    def run(self, context):
        paths = context.case.get("artifacts", {}).get("restored_dex") or context.case.get("dex_inputs", [])
        files = []
        for item in paths:
            path = Path(item)
            if not valid_dex_file(path):
                raise StageBlocked(context.question(self.id, "DEX validation failed", [str(path)]))
            files.append({**file_record(path, context.case_dir), "valid_dex": True, "lm": lm_summary(path)})
        if not files:
            raise StageBlocked(context.question(self.id, "No DEX outputs are available for validation", []))
        restore_result = context.case.get("stage_records", {}).get("dex-restore", {}).get("result", {})
        fixture = bool(context.profile.get("fixture"))
        vmp_required = bool(context.case.get("vmp_recovery_required", True))
        tool_results = []
        if not fixture:
            if vmp_required and not restore_result.get("vmp_repaired"):
                raise StageBlocked(context.question(self.id, "DEX restoration was not proven", ["dex-restore"]))
            configured_tools = {**context.profile.get("tools", {}), **context.case.get("tools", {})}
            java = resolve_tool("java", configured_tools.get("java"))
            jadx = resolve_tool("jadx", configured_tools.get("jadx"))
            dexdump = resolve_tool("dexdump", configured_tools.get("dexdump"))
            missing = [name for name, value in (("java", java), ("jadx", jadx), ("dexdump", dexdump)) if not value]
            if missing:
                raise StageBlocked(context.question(
                    self.id, "Independent validation tools are unavailable",
                    [", ".join(missing)], ["tools"]))
            for index, item in enumerate(files, 1):
                dex = item["path"]
                dump_result = run_command([dexdump, "-f", dex], context.case_dir, timeout=300)
                jadx_dir = context.case_dir / "reports" / f"jadx-{index:02d}"
                jadx_result = run_command([jadx, "-d", str(jadx_dir), dex], context.case_dir, timeout=900)
                tool_results.append({"dex": dex, "dexdump": dump_result, "jadx": jadx_result})
                if dump_result["returncode"] or jadx_result["returncode"]:
                    raise StageBlocked(context.question(
                        self.id, "dexdump or JADX rejected a restored DEX",
                        [dump_result["stderr"], jadx_result["stderr"], dex]))
        report = {"status": "ok", "files": files, "tools": {
            "java": resolve_tool("java"), "jadx": resolve_tool("jadx"),
            "dexdump": resolve_tool("dexdump"), "codex": resolve_tool("codex")},
            "vmp_repair_required": vmp_required,
            "vmp_repair_claimed": bool(restore_result.get("vmp_repaired")),
            "fixture_pass_through": fixture,
            "validation_scope": (
                "orchestration-only" if fixture
                else "restored-dex" if vmp_required
                else "dispatcher-only-no-vmp-methods"
            ),
            "tool_results": tool_results}
        output = context.revision_dir("reports") / "validation.json"
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        context.case.setdefault("artifacts", {})["validation_report"] = str(output.resolve())
        context.save_case()
        return {"ok": True, "source": "independent-validator", "report": report,
                "artifacts": [file_record(output, context.case_dir)]}
