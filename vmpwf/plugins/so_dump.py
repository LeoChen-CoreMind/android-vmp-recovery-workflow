from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record
from .common import BasePlugin


class SoDump(BasePlugin):
    id = "so-dump"

    def run(self, context):
        output = context.revision_dir("dump/so/raw")
        if context.profile.get("fixture"):
            apk = Path(context.case.get("apk_ingested", context.case["apk"]))
            artifacts = []
            with zipfile.ZipFile(apk) as archive:
                candidates = [name for name in archive.namelist() if name.endswith(".so") and "jiagu" in name.lower()]
                for name in candidates:
                    target = output / Path(name).name
                    target.write_bytes(archive.read(name))
                    artifacts.append(file_record(target, context.case_dir, source="fixture-apk-asset", zip_name=name))
            if not artifacts:
                raise StageBlocked(context.question(self.id, "APK contains no Jiagu SO fixture", [str(apk)]))
            context.case.setdefault("artifacts", {})["so_dump"] = [item["path"] for item in artifacts]
            context.save_case()
            return {"ok": True, "source": "fixture-apk-asset", "artifacts": artifacts}
        if not context.execute_device:
            raise StageBlocked(context.question(self.id, "SO dump requires --execute-device", [], ["execute_device"]))
        command = context.profile.get("commands", {}).get("so-dump") or context.case.get("commands", {}).get("so-dump")
        if not command:
            config = context.case.get("so_dump_config", {})
            required = {
                "manualLoadFunctionOffset", "exactDumpOffset", "handleGlobalOffset",
                "soinfoLoadStartOffset", "soinfoPhdrOffset", "soinfoLoadSizeOffset",
                "soinfoPhnumOffset", "soinfoDynamicOffset", "soinfoLoadBiasOffset",
                "soinfoNameOffset", "manualLoaderSignature",
                "exactDumpInstructionMask", "exactDumpInstructionValue",
            }
            missing = sorted(key for key in required if config.get(key) is None)
            signature = config.get("manualLoaderSignature")
            if not isinstance(signature, list) or not signature:
                missing.append("manualLoaderSignature(non-empty array)")
            if missing:
                raise StageBlocked(context.question(
                    self.id, "SO dump offsets are not configured for this build",
                    ["missing: " + ", ".join(missing)], ["so_dump_config"]))
            config_path = context.revision_dir("dump/so/metadata") / "dump-config.json"
            config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
            command = [sys.executable, str(context.repo_root / "scripts/dump/so/run_gating.py"),
                       "--package", context.case["package"], "--script", str(context.repo_root / "scripts/dump/so/dump_linker.js"),
                       "--config", str(config_path), "--output-dir", str(output)]
            if context.case.get("device_serial"):
                command += ["--device", context.case["device_serial"]]
        result = run_command([str(value).format(case=str(context.case_dir), package=context.case["package"], output=str(output), repo=str(context.repo_root)) for value in command], context.case_dir, timeout=600)
        if result["returncode"]:
            raise StageBlocked(context.question(self.id, "SO dump command failed", [result["stderr"], result["stdout"]]))
        artifacts = [file_record(path, context.case_dir, source="device-dump") for path in output.glob("*.so")]
        if not artifacts:
            raise StageBlocked(context.question(self.id, "SO dump produced no files", [result["stdout"]]))
        context.case.setdefault("artifacts", {})["so_dump"] = [item["path"] for item in artifacts]
        context.save_case()
        return {"ok": True, "source": "device-dump", "artifacts": artifacts, "command": result}
