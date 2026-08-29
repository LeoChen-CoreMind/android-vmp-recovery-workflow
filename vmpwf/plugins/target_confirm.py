from __future__ import annotations

import json
import re
import time

from ..provenance import file_record

from ..core import StageBlocked, run_command
from .common import BasePlugin


class TargetConfirm(BasePlugin):
    id = "target-confirm"

    @staticmethod
    def _match(pattern, text):
        match = re.search(pattern, text, re.MULTILINE)
        return match.group(1) if match else None

    @staticmethod
    def _runtime_abi(executable):
        name = (executable or "").strip().lower()
        if name.endswith("app_process64"):
            return "arm64-v8a"
        if name.endswith("app_process32") or name.endswith("app_process"):
            return "armeabi-v7a"
        return None

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
        package_abi = self._match(r"primaryCpuAbi=([^\s]+)", package["stdout"])
        if package_abi in {"null", "none", "unknown"}:
            package_abi = None
        pid_result = run_command(prefix + ["shell", "pidof", context.case["package"]])
        if not pid_result["stdout"].strip():
            run_command(prefix + ["shell", "monkey", "-p", context.case["package"],
                                  "-c", "android.intent.category.LAUNCHER", "1"], timeout=30)
            for _ in range(10):
                time.sleep(0.3)
                pid_result = run_command(prefix + ["shell", "pidof", context.case["package"]])
                if pid_result["stdout"].strip():
                    break
        pid = (pid_result["stdout"].split() or [None])[0]
        process_executable = None
        process_maps = ""
        if pid:
            if root_method == "adbd":
                process_executable_result = run_command(prefix + ["shell", "readlink", f"/proc/{pid}/exe"])
                maps_result = run_command(prefix + ["shell", "cat", f"/proc/{pid}/maps"])
            else:
                process_executable_result = run_command(
                    prefix + ["shell", "su", "-c", f"readlink /proc/{pid}/exe"])
                maps_result = run_command(prefix + ["shell", "su", "-c", f"cat /proc/{pid}/maps"])
            process_executable = process_executable_result["stdout"].strip() or None
            process_maps = maps_result["stdout"]
        runtime_abi = self._runtime_abi(process_executable)
        abi = package_abi or runtime_abi
        install_paths = [line.removeprefix("package:").strip()
                         for line in path["stdout"].splitlines() if line.startswith("package:")]
        map_evidence = [line for line in process_maps.splitlines()
                        if any(value in line.lower() for value in ("jiagu", "linker"))]
        observed = {
            "package": context.case["package"], "version_name": self._match(r"versionName=([^\s]+)", package["stdout"]),
            "version_code": self._match(r"versionCode=(\d+)", package["stdout"]),
            "uid": self._match(r"userId=(\d+)", package["stdout"]),
            "install_paths": install_paths, "root": True, "root_method": root_method,
            "selinux": enforce["stdout"].strip(), "abi": abi, "source": "adb",
            "package_manager_abi": package_abi, "runtime_abi": runtime_abi,
            "pid": pid, "process_executable": process_executable,
            "runtime_map_evidence": map_evidence,
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
