from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record
from ..validation import valid_dex_file
from .common import BasePlugin


class DexRestore(BasePlugin):
    id = "dex-restore"

    def run(self, context):
        if context.profile.get("fixture"):
            output = context.revision_dir("fix/dex")
            artifacts = []
            for source_name in context.case.get("dex_inputs", []):
                source = Path(source_name)
                target = output / source.name
                shutil.copy2(source, target)
                artifacts.append(file_record(target, context.case_dir, source="fixture-pass-through",
                                             vmp_repaired=False,
                                             note="Reference workflow validation only; customer VMP methods remain unrepaired."))
            if not artifacts:
                raise StageBlocked(context.question(self.id, "No DEX inputs are available", ["dex_inputs"]))
            context.case.setdefault("artifacts", {})["restored_dex"] = [item["path"] for item in artifacts]
            context.save_case()
            return {"ok": True, "source": "fixture-pass-through", "vmp_repaired": False,
                    "artifacts": artifacts}
        command = context.profile.get("commands", {}).get("dex-restore") or context.case.get("commands", {}).get("dex-restore")
        if not command:
            raise StageBlocked(context.question(self.id, "DEX restore command is not configured", [], ["commands.dex-restore"]))
        output_dir = context.revision_dir("fix/dex")
        manifest_path = output_dir / "vmp_restore_manifest.json"
        values = {"case": str(context.case_dir), "output": str(output_dir), "manifest": str(manifest_path),
                  "streams": str(context.case.get("artifacts", {}).get("vm_streams", ""))}
        result = run_command([str(value).format(**values) for value in command], context.case_dir, timeout=600)
        if result["returncode"]:
            raise StageBlocked(context.question(self.id, "DEX restore failed", [result["stderr"]]))
        outputs = [file_record(path, context.case_dir, source="vmp-restored", vmp_repaired=True)
                   for path in output_dir.glob("*.dex") if valid_dex_file(path)]
        if not outputs:
            raise StageBlocked(context.question(self.id, "DEX restore produced no valid DEX", [result["stdout"]]))
        if not manifest_path.is_file():
            raise StageBlocked(context.question(self.id, "DEX restore produced no repair manifest", [str(manifest_path)]))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        method_count = sum(len(item.get("methods", [])) for item in manifest.get("outputs", []))
        expected = sum(item.get("method_records", 0) for item in context.case.get("vmp_inventory", []))
        if method_count <= 0 or (expected and method_count != expected):
            raise StageBlocked(context.question(
                self.id, "DEX repair manifest does not cover all VMP methods",
                [f"expected={expected}, restored={method_count}", str(manifest_path)]))
        context.case.setdefault("artifacts", {})["restored_dex"] = [item["path"] for item in outputs]
        context.case["artifacts"]["restore_manifest"] = str(manifest_path.resolve()); context.save_case()
        return {"ok": True, "source": "command", "vmp_repaired": True,
                "restored_methods": method_count,
                "artifacts": [*outputs, file_record(manifest_path, context.case_dir)]}
