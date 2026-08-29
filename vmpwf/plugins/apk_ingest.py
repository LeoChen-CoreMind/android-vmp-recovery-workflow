from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record
from .common import BasePlugin


class ApkIngest(BasePlugin):
    id = "apk-ingest"

    def run(self, context):
        source = Path(context.case["apk"])
        if not source.is_file():
            raise StageBlocked(context.question(self.id, "APK input was not found", [str(source)], ["apk"]))
        target_dir = context.revision_dir("input/apk")
        target = target_dir / source.name
        shutil.copy2(source, target)
        output = context.revision_dir("input/manifest") / "apk_inventory.json"
        script = context.repo_root / "scripts/apk/inspect_apk.py"
        command = [sys.executable, str(script), str(target), "--output", str(output)]
        result = run_command(command, context.repo_root, timeout=120)
        if result["returncode"]:
            raise StageBlocked(context.question(self.id, "APK inventory failed", [result["stderr"]]))
        inventory = json.loads(output.read_text(encoding="utf-8"))
        observed = inventory.get("package")
        if observed and context.case.get("package") and observed != context.case["package"]:
            raise StageBlocked(context.question(self.id, "APK package does not match the case", [str(output)], ["package"]))
        if observed:
            context.case["package"] = observed
        context.case["apk_ingested"] = str(target.resolve())
        context.case["apk_inventory"] = str(output.resolve())
        context.save_case()
        return {"ok": True, "package": context.case.get("package"), "inventory": inventory,
                "artifacts": [file_record(target, context.case_dir, source="customer-apk"),
                              file_record(output, context.case_dir, source="generated-manifest")]}
