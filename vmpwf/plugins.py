from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .adapters import FixtureIdaAdapter, JsonIdaMcpAdapter
from .core import (Context, STAGES, StageBlocked, append_event, file_record,
                   read_json, run_command, validate_files)


class BasePlugin:
    version = "0.1.0"

    def plan(self, context: Context) -> dict[str, Any]:
        return {"stage": self.id, "enabled": True}

    def validate(self, context: Context, result: dict[str, Any]) -> dict[str, Any]:
        return {"ok": result.get("returncode", 0) == 0, "checks": []}


class TargetConfirm(BasePlugin):
    id = "target-confirm"

    def run(self, context: Context) -> dict[str, Any]:
        package = context.case["package"]
        serial = context.case.get("device_serial")
        prefix = ["adb"] + (["-s", serial] if serial else [])
        results = {
            "devices": run_command(prefix + ["devices"]),
            "id": run_command(prefix + ["shell", "id"]),
            "getenforce": run_command(prefix + ["shell", "getenforce"]),
            "pm_path": run_command(prefix + ["shell", "pm", "path", package]),
            "package": run_command(prefix + ["shell", "dumpsys", "package", package]),
        }
        joined = results["id"]["stdout"]
        if results["id"]["returncode"] != 0 or "uid=0" not in joined:
            raise StageBlocked(context.question(self.id, "ADB root capability was not confirmed", ["target-confirm/id"]))
        if results["pm_path"]["returncode"] != 0 or "package:" not in results["pm_path"]["stdout"]:
            raise StageBlocked(context.question(self.id, f"Package {package} was not found on the selected device", ["target-confirm/pm_path"], ["package", "device_serial"]))
        text = results["package"]["stdout"]
        abi = re.search(r"primaryCpuAbi=([^\s]+)", text)
        version = re.search(r"versionName=([^\s]+)", text)
        context.case["target_observed"] = {
            "abi": abi.group(1) if abi else None,
            "version": version.group(1) if version else None,
            "root": True, "selinux": results["getenforce"]["stdout"].strip(),
            "raw": {key: value["stdout"][-4000:] for key, value in results.items()},
        }
        if context.case.get("require_target_confirmation", True) and not context.case.get("target_confirmed"):
            raise StageBlocked(context.question(
                self.id,
                "Target identity was observed but not confirmed by the user",
                ["target_observed"], ["target_confirmed"], "warning"))
        context.save_case()
        return {"target": context.case["target_observed"], "commands": results}


class CommandPlugin(BasePlugin):
    command_key = None
    artifact_keys: list[str] = []

    def run(self, context: Context) -> dict[str, Any]:
        command = context.case.get("commands", {}).get(self.command_key or self.id)
        if not command:
            return {"skipped": True, "reason": "no command configured"}
        if isinstance(command, str):
            command = command.split()
        if self.id == "so-dump" and not context.execute_device:
            return {"skipped": True, "reason": "device execution disabled; pass --execute-device"}
        result = run_command(command, cwd=context.case_dir,
                             timeout=int(context.case.get("command_timeout", 180)))
        result["files"] = validate_files(context.case.get("artifacts", {}), self.artifact_keys)
        if result["returncode"] != 0:
            raise StageBlocked(context.question(self.id, f"command failed with exit code {result['returncode']}", [self.id]))
        return result

    def validate(self, context: Context, result: dict[str, Any]) -> dict[str, Any]:
        if result.get("skipped"):
            return {"ok": True, "checks": ["skipped"]}
        return {"ok": result.get("returncode") == 0, "checks": ["command-exit-zero"]}


class SoDump(CommandPlugin):
    id = "so-dump"; command_key = "so-dump"
    artifact_keys = ["so_dump", "linker_dump"]


class SoRepair(CommandPlugin):
    id = "so-repair"; command_key = "so-repair"
    artifact_keys = ["so_fixed", "linker_fixed"]


class IdaExport(BasePlugin):
    id = "ida-export"

    def run(self, context: Context) -> dict[str, Any]:
        config = context.case.get("ida", {})
        request = {"binary": config.get("binary", ""), "architecture": "AArch64",
                   "image_base": config.get("image_base", "0x0"), "root_rva": config.get("root_rva"),
                   "output": config.get("output", str(context.artifacts_dir / "dispatch_map.json")),
                   "requested_tables": ["dispatch", "width_candidates", "unit_decoders", "format_helpers"]}
        adapter_name = config.get("adapter", "fixture")
        if adapter_name == "fixture":
            request["fixture"] = config.get("fixture")
            result = FixtureIdaAdapter().export(request)
        else:
            request["response"] = config.get("response")
            result = JsonIdaMcpAdapter().export(request)
        Path(request["output"]).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        result["output"] = request["output"]
        return result

    def validate(self, context: Context, result: dict[str, Any]) -> dict[str, Any]:
        ok = result.get("status") == "ok" and isinstance(result.get("entries"), list)
        return {"ok": ok, "checks": ["ida-json-contract"]}


class VmStatic(CommandPlugin):
    id = "vm-static"; command_key = "vm-static"
    artifact_keys = ["static_probe", "vm_streams"]


class NativeSim(CommandPlugin):
    id = "native-sim"; command_key = "native-sim"
    artifact_keys = ["simulation"]


class DexRestore(CommandPlugin):
    id = "dex-restore"; command_key = "dex-restore"
    artifact_keys = ["restored_dex"]


class IndependentValidate(CommandPlugin):
    id = "independent-validate"; command_key = "independent-validate"
    artifact_keys = ["validated_outputs"]


PLUGINS = {plugin.id: plugin for plugin in [TargetConfirm(), SoDump(), SoRepair(), IdaExport(), VmStatic(), NativeSim(), DexRestore(), IndependentValidate()]}
