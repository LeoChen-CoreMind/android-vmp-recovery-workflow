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

    @staticmethod
    def _private_metadata_errors(payload):
        required = ("reason", "privateSoinfo", "loadStart", "loadBias", "phdr", "phnum",
                    "privateDynamic", "elfBase", "dumpSize", "elf", "dynamic")
        errors = [f"missing {key}" for key in required if payload.get(key) is None]
        elf = payload.get("elf") if isinstance(payload.get("elf"), dict) else {}
        dynamic = payload.get("dynamic") if isinstance(payload.get("dynamic"), dict) else {}
        if elf.get("loadCount", 0) <= 0 or elf.get("imageSpan", 0) <= 0:
            errors.append("invalid PT_LOAD metadata")
        for key in ("hasStrtab", "hasSymtab", "hasStrsz", "hasSyment"):
            if dynamic.get(key) is not True:
                errors.append(f"dynamic.{key} is not true")
        if dynamic.get("hasHash") is not True and dynamic.get("hasGnuHash") is not True:
            errors.append("dynamic hash table is missing")
        return errors

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
        # Load case-level dump policy before either generated or explicit commands;
        # metadata validation must use the same pointer requirements in both modes.
        config = context.case.get("so_dump_config", {})
        command = context.profile.get("commands", {}).get("so-dump") or context.case.get("commands", {}).get("so-dump")
        if not command:
            required = {
                "manualLoadFunctionOffset",
                "soinfoLoadStartOffset", "soinfoPhdrOffset", "soinfoLoadSizeOffset",
                "soinfoPhnumOffset", "soinfoDynamicOffset", "soinfoLoadBiasOffset",
                "soinfoNameOffset", "manualLoaderSignature",
            }
            if not config.get("dumpOnManualLoaderReturn") and not config.get("dumpWhenRuntimePointersReady"):
                required.update({"exactDumpOffset", "handleGlobalOffset",
                                 "exactDumpInstructionMask", "exactDumpInstructionValue"})
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
                       "--config", str(config_path), "--output-dir", str(output),
                       "--log-dir", str(context.revision_dir("logs"))]
            if context.case.get("device_serial"):
                command += ["--device", context.case["device_serial"]]
            tools = {**context.profile.get("tools", {}), **context.case.get("tools", {})}
            server = tools.get("frida_server")
            if server:
                server_path = Path(server)
                if not server_path.is_absolute():
                    server_path = context.repo_root / server_path
                command += ["--server", str(server_path)]
            if tools.get("frida_server_remote"):
                command += ["--remote-server", str(tools["frida_server_remote"])]
            if tools.get("frida_server_version"):
                command += ["--server-version", str(tools["frida_server_version"])]
            if tools.get("frida_server_sha256"):
                command += ["--server-sha256", str(tools["frida_server_sha256"])]
        result = run_command([str(value).format(case=str(context.case_dir), package=context.case["package"], output=str(output), repo=str(context.repo_root)) for value in command], context.case_dir, timeout=600)
        if result["returncode"]:
            raise StageBlocked(context.question(
                self.id, "SO dump command failed",
                [result["stderr"], result["stdout"], str(context.revision_dir("logs"))]))
        so_paths = sorted(output.glob("*.so"))
        if not so_paths:
            raise StageBlocked(context.question(self.id, "SO dump produced no files", [result["stdout"]]))
        artifacts = []
        metadata_artifacts = []
        metadata_paths = []
        for path in so_paths:
            metadata_path = Path(str(path) + ".json")
            if not metadata_path.is_file():
                raise StageBlocked(context.question(
                    self.id, "Private linker dump metadata is missing", [str(path), str(metadata_path)]))
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise StageBlocked(context.question(
                    self.id, "Private linker dump metadata is invalid", [str(metadata_path), str(exc)])) from exc
            errors = self._private_metadata_errors(metadata)
            required_pointer_offsets = config.get("requiredNonZeroPointerOffsets", [])
            runtime_pointers = metadata.get("runtimePointers")
            if required_pointer_offsets and (
                    not isinstance(runtime_pointers, dict)
                    or len(runtime_pointers) != len(required_pointer_offsets)
                    or any(value in (None, "0x0") for value in runtime_pointers.values())):
                errors.append("required runtime pointer evidence is incomplete")
            if errors:
                raise StageBlocked(context.question(
                    self.id, "Private linker dump evidence is incomplete", [str(metadata_path), *errors]))
            artifacts.append(file_record(path, context.case_dir, source="private-linker-device-dump",
                                         metadata=str(metadata_path.resolve())))
            metadata_artifacts.append(file_record(
                metadata_path, context.case_dir, source="private-linker-metadata"))
            metadata_paths.append(str(metadata_path.resolve()))
        context.case.setdefault("artifacts", {})["so_dump"] = [item["path"] for item in artifacts]
        context.case["artifacts"]["so_dump_metadata"] = metadata_paths
        context.save_case()
        return {"ok": True, "source": "private-linker-device-dump",
                "artifacts": [*artifacts, *metadata_artifacts], "command": result}
