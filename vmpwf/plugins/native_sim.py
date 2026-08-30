from __future__ import annotations

import json
import sys
from pathlib import Path

from ..core import StageBlocked, atomic_json, run_command
from ..provenance import file_record, sha256_file
from .common import BasePlugin


class NativeSim(BasePlugin):
    id = "native-sim"

    def _promote_streams(self, context, streams_path: Path, report_path: Path,
                         payload: dict) -> tuple[Path, dict]:
        streams = json.loads(streams_path.read_text(encoding="utf-8"))
        results = {
            (item.get("method_idx"), item.get("pc")): item
            for item in payload.get("results", [])
        }
        expected = 0
        for method in streams.get("methods", []):
            for instruction in method.get("instructions", []):
                evidence = instruction.get("literal_mode1_unicorn")
                if not isinstance(evidence, dict):
                    continue
                expected += 1
                identity = (method.get("method_idx"), instruction.get("pc"))
                result = results.get(identity)
                if not result or result.get("matched") is not True:
                    raise StageBlocked(context.question(
                        self.id, "Native simulation did not cover every literal request",
                        [str(report_path), json.dumps(identity)],
                    ))
                evidence.update({
                    "engine": "unicorn-arm64",
                    "actual_decoded_unit": f"{int(result['actual_decoded_unit']) & 0xFFFF:04x}",
                    "matched": True,
                })
        if expected != payload.get("request_count") or len(results) != expected:
            raise StageBlocked(context.question(
                self.id, "Native simulation result coverage does not match VM streams",
                [str(report_path), str(streams_path)],
            ))

        report_hash = sha256_file(report_path)
        streams["literal_decoder"] = {
            **streams.get("literal_decoder", {}),
            "engine": "unicorn-arm64",
            "request_count": expected,
            "confirmed": True,
            "confirmation_report": str(report_path.resolve()),
            "confirmation_report_sha256": report_hash,
            "source_streams_sha256": payload["streams_sha256"],
            "binary_sha256": payload["binary_sha256"],
            "config_sha256": payload["config_sha256"],
        }
        promoted = context.revision_dir("ida/tables") / "vm_streams_native_confirmed.json"
        atomic_json(promoted, streams)
        return promoted, streams

    def run(self, context):
        streams_path = context.case.get("artifacts", {}).get("vm_streams")
        if not context.profile.get("fixture") and not context.case.get("vmp_recovery_required", True):
            configured = context.case.get("simulation", {}).get("dispatch_confirmation")
            confirmation = Path(configured) if configured else None
            if not confirmation or not confirmation.is_file():
                raise StageBlocked(context.question(
                    self.id,
                    "Dispatcher-level native confirmation is required when no VMP methods are present",
                    [str(confirmation) if confirmation else "missing: simulation.dispatch_confirmation"],
                    ["simulation"],
                ))
            payload = json.loads(confirmation.read_text(encoding="utf-8"))
            ida_result = context.case.get("stage_records", {}).get("ida-export", {}).get("result", {})
            invalid = payload.get("invalid_memory", [])
            if (
                payload.get("confirmed") is not True
                or payload.get("scope") != "dispatch-table"
                or payload.get("request_count") != 256
                or payload.get("matched_count") != 256
                or payload.get("mismatches")
                or invalid
                or payload.get("unknown_external_calls", 0) != 0
            ):
                raise StageBlocked(context.question(
                    self.id, "Dispatcher native confirmation did not pass", [str(confirmation)]
                ))
            if payload.get("binary_sha256") != ida_result.get("binary_sha256"):
                raise StageBlocked(context.question(
                    self.id, "Dispatcher confirmation belongs to a different SO", [str(confirmation)]
                ))
            output = context.revision_dir("simulation/results") / "native_simulation.json"
            output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            context.case.setdefault("artifacts", {})["simulation"] = str(output.resolve())
            context.save_case()
            return {
                "ok": True,
                "source": "unicorn-dispatch-confirmation",
                **payload,
                "artifacts": [file_record(output, context.case_dir, source_evidence=str(confirmation.resolve()))],
            }
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
        promoted, _ = self._promote_streams(context, Path(streams_path), output, payload)
        artifacts = context.case.setdefault("artifacts", {})
        artifacts["simulation"] = str(output.resolve())
        artifacts["vm_streams"] = str(promoted.resolve())
        context.save_case()
        return {"ok": True, "source": "command", "command": result, **payload,
                "confirmed_streams": str(promoted.resolve()),
                "artifacts": [
                    file_record(output, context.case_dir),
                    file_record(promoted, context.case_dir,
                                source_evidence=str(output.resolve())),
                ]}
