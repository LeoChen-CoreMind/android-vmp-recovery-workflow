from __future__ import annotations

import json
import re

from ..provenance import file_record

from ..core import StageBlocked, run_command
from .common import BasePlugin


class TargetConfirm(BasePlugin):
    id = "target-confirm"

    @staticmethod
    def _match(pattern, text):
        match = re.search(pattern, text, re.MULTILINE)
        return match.group(1) if match else None

    def run(self, context):
        if context.profile.get("fixture"):
            observed = {"package": context.case["package"], "source": "fixture",
                        "device_serial": context.case.get("device_serial")}
            context.case["target_observed"] = observed; context.save_case()
            return {"ok": True, "source": "fixture", "target": observed}
        if not context.execute_device:
            raise StageBlocked(context.question(self.id, "Device execution is disabled", [], ["execute_device"]))
        prefix = ["adb"] + (["-s", context.case["device_serial"]] if context.case.get("device_serial") else [])
        shell_identity = run_command(prefix + ["shell", "id"])
        root_identity = shell_identity
        root_method = "adbd"
        if "uid=0" not in shell_identity["stdout"]:
            root_identity = run_command(prefix + ["shell", "su", "-c", "id"])
            root_method = "su"
        enforce = run_command(prefix + ["shell", "getenforce"])
        package = run_command(prefix + ["shell", "dumpsys", "package", context.case["package"]])
        path = run_command(prefix + ["shell", "pm", "path", context.case["package"]])
        adb_version = run_command(["adb", "version"])
        if root_identity["returncode"] or "uid=0" not in root_identity["stdout"] or "package:" not in path["stdout"]:
            raise StageBlocked(context.question(
                self.id, "ADB root or target package was not confirmed",
                [shell_identity["stdout"], root_identity["stdout"], path["stdout"]],
                ["device_serial"]))
        abi = self._match(r"primaryCpuAbi=([^\s]+)", package["stdout"])
        install_paths = [line.removeprefix("package:").strip()
                         for line in path["stdout"].splitlines() if line.startswith("package:")]
        observed = {
            "package": context.case["package"], "version_name": self._match(r"versionName=([^\s]+)", package["stdout"]),
            "version_code": self._match(r"versionCode=(\d+)", package["stdout"]),
            "uid": self._match(r"userId=(\d+)", package["stdout"]),
            "install_paths": install_paths, "root": True, "root_method": root_method,
            "selinux": enforce["stdout"].strip(), "abi": abi, "source": "adb",
            "adb_version": (adb_version["stdout"].splitlines() or [None])[0],
        }
        inventory_path = context.revision_dir("input/manifest") / "target_observed.json"
        inventory_path.write_text(json.dumps(observed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        context.case["target_observed"] = observed
        context.case.setdefault("artifacts", {})["target_observed"] = str(inventory_path.resolve())
        context.save_case()
        supported = context.profile.get("supported_abis", [])
        if supported and abi not in supported:
            raise StageBlocked(context.question(
                self.id, f"Target ABI {abi or 'unknown'} is not supported by profile {context.case.get('profile')}",
                [str(inventory_path.resolve()) + "#/abi"], ["profile"]))
        return {"ok": True, "source": "adb", "target": observed,
                "artifacts": [file_record(inventory_path, context.case_dir, source="adb-inventory")]}
