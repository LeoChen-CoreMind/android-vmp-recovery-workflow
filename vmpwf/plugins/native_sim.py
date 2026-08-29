from __future__ import annotations

import json
import sys
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record, sha256_file
from .common import BasePlugin


class NativeSim(BasePlugin):
    id = "native-sim"

    def run(self, context):
        streams_path = context.case.get("artifacts", {}).get("vm_streams")
        if context.profile.get("fixture"):
            fixture_name = context.profile.get("simulation", {}).get("fixture")
            fixture = Path(fixture_name) if fixture_name else None
            if fixture and not fixture.is_absolute():
                fixture = context.repo_root / fixture
            if not fixture or not fixture.is_file():
                raise StageBlocked(context.question(self.id, "Native simulation fixture is missing", [str(fixture)]))
            result = json.loads(fixture.read_text(encoding="utf-8"))
            if (result.get("confirmed") is not True or result.get("unknown_external_calls") != 0
                    or result.get("invalid_memory") or result.get("errors")):
                raise StageBlocked(context.question(self.id, "Native simulation fixture contract failed", [str(fixture)]))
            result.update(source="reference-fixture",
                          note="Actual reference execution; it is not evidence for the customer APK.")
            output = context.revision_dir("simulation/results") / "native_simulation.json"
            output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            context.case.setdefault("artifacts", {})["simulation"] = str(output.resolve()); context.save_case()
            return {"ok": True, **result,
                    "artifacts": [file_record(output, context.case_dir, fixture_origin=str(fixture.resolve()))]}
        command = context.profile.get("commands", {}).get("native-sim") or context.case.get("commands", {}).get("native-sim")
        output = context.revision_dir("simulation/results") / "native_simulation.json"
        simulation = {**context.profile.get("simulation", {}), **context.case.get("simulation", {})}
        if not command and all(simulation.get(key) for key in ("outer", "linker", "binary", "config")):
            command = [
                sys.executable, str(context.repo_root / "scripts/simulation/run_native_confirmation.py"),
                "--streams", "{streams}", "--outer", str(simulation["outer"]),
                "--linker", str(simulation["linker"]), "--binary", str(simulation["binary"]),
                "--config", str(simulation["config"]), "--output", "{output}",
            ]
        if not command:
            raise StageBlocked(context.question(
                self.id, "Native simulation inputs are not configured", [],
                ["simulation.outer", "simulation.linker", "simulation.binary", "simulation.config"]))
        values = {"case": str(context.case_dir), "output": str(output), "streams": str(streams_path or "")}
        result = run_command([str(value).format(**values) for value in command], context.case_dir, timeout=600)
        if result["returncode"]:
            raise StageBlocked(context.question(
                self.id, "Native simulation failed",
                [str(output), result["stderr"], result["stdout"]]))
        if output.is_file():
            payload = json.loads(output.read_text(encoding="utf-8"))
        else:
            try:
                payload = json.loads(result["stdout"])
            except json.JSONDecodeError as exc:
                raise StageBlocked(context.question(self.id, "Native simulation produced no result contract", [result["stdout"]])) from exc
            output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        invalid = payload.get("invalid_memory", [])
        if (payload.get("confirmed") is not True or payload.get("unknown_external_calls", 0) != 0
                or invalid or payload.get("abort") or payload.get("stack_guard_failed")):
            raise StageBlocked(context.question(self.id, "Native simulation evidence did not pass", [json.dumps(payload)]))
        expected_streams_hash = sha256_file(Path(streams_path)) if streams_path else None
        if not expected_streams_hash or payload.get("streams_sha256") != expected_streams_hash:
            raise StageBlocked(context.question(self.id, "Native simulation result belongs to different VM streams", [str(output)]))
        for key in ("binary_sha256", "config_sha256"):
            value = payload.get(key)
            if (not isinstance(value, str) or len(value) != 64
                    or any(character not in "0123456789abcdefABCDEF" for character in value)):
                raise StageBlocked(context.question(self.id, f"Native simulation result is missing {key}", [str(output)]))
        context.case.setdefault("artifacts", {})["simulation"] = str(output.resolve()); context.save_case()
        return {"ok": True, "source": "command", "command": result, **payload,
                "artifacts": [file_record(output, context.case_dir)]}
