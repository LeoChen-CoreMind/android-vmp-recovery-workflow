from __future__ import annotations

import json
import re
from pathlib import Path

from ..core import StageBlocked, run_command, run_logged_command
from ..provenance import file_record, sha256_file
from ..tooling import resolve_tool
from ..validation import lm_summary, valid_dex_file
from .common import BasePlugin


class IndependentValidate(BasePlugin):
    id = "independent-validate"

    @staticmethod
    def _jadx_error_contract(result: dict) -> dict:
        text = "\n".join([
            Path(result["stdout_log"]).read_text(encoding="utf-8", errors="replace"),
            Path(result["stderr_log"]).read_text(encoding="utf-8", errors="replace"),
        ])
        methods = sorted(set(re.findall(r"ERROR -\s+Method:\s+([^\r\n]+)", text)))
        counts = [int(value) for value in re.findall(
            r"(?:errors occurred in following nodes|finished with errors, count:)\s*(\d+)", text
        )]
        return {"error_count": max(counts, default=len(methods)), "error_methods": methods}

    def _validate_jadx(self, context, jadx: str, restored: Path, source: Path,
                       methods: list[dict], index: int, report_dir: Path) -> dict:
        default_dir = report_dir / f"jadx-{index:02d}-default"
        default = run_logged_command(
            [jadx, "--log-level", "ERROR", "-d", str(default_dir), str(restored)],
            report_dir / f"jadx-{index:02d}-default.stdout.log",
            report_dir / f"jadx-{index:02d}-default.stderr.log",
            context.case_dir, timeout=900,
        )
        if default["returncode"] == 0:
            return {"accepted_mode": "default", "default": default}

        baseline_dir = report_dir / f"jadx-{index:02d}-baseline"
        baseline = run_logged_command(
            [jadx, "--log-level", "ERROR", "-d", str(baseline_dir), str(source)],
            report_dir / f"jadx-{index:02d}-baseline.stdout.log",
            report_dir / f"jadx-{index:02d}-baseline.stderr.log",
            context.case_dir, timeout=900,
        )
        fallback_dir = report_dir / f"jadx-{index:02d}-fallback"
        fallback = run_logged_command(
            [jadx, "--log-level", "ERROR", "--decompilation-mode", "fallback",
             "-d", str(fallback_dir), str(restored)],
            report_dir / f"jadx-{index:02d}-fallback.stdout.log",
            report_dir / f"jadx-{index:02d}-fallback.stderr.log",
            context.case_dir, timeout=900,
        )
        restored_errors = self._jadx_error_contract(default)
        baseline_errors = self._jadx_error_contract(baseline)
        recovered_prefixes = [
            item["class"].removeprefix("L").removesuffix(";").replace("/", ".")
            + "." + item["method"] + "(" for item in methods
        ]
        recovered_errors = [
            method for method in restored_errors["error_methods"]
            if any(method.startswith(prefix) for prefix in recovered_prefixes)
        ]
        accepted = (
            fallback["returncode"] == 0
            and restored_errors == baseline_errors
            and not recovered_errors
        )
        result = {
            "accepted_mode": "fallback-with-baseline-equivalence" if accepted else None,
            "default": default, "baseline": baseline, "fallback": fallback,
            "default_errors": restored_errors, "baseline_errors": baseline_errors,
            "recovered_method_errors": recovered_errors,
        }
        if not accepted:
            raise StageBlocked(context.question(
                self.id, "JADX rejected restored code beyond the source DEX baseline",
                [json.dumps(result, ensure_ascii=False)],
            ))
        return result

    def _repeat_restore(self, context, expected_paths: list[Path], report_dir: Path) -> dict:
        command = context.profile.get("commands", {}).get("dex-restore") or context.case.get("commands", {}).get("dex-restore")
        streams = context.case.get("artifacts", {}).get("vm_streams")
        if not command or not streams:
            raise StageBlocked(context.question(
                self.id, "DEX repeatability command is not configured", [], ["commands.dex-restore"]
            ))
        output_dir = report_dir / "repeat-restore"
        manifest = output_dir / "vmp_restore_manifest.json"
        values = {"case": str(context.case_dir), "output": str(output_dir),
                  "manifest": str(manifest), "streams": str(streams)}
        result = run_command([str(value).format(**values) for value in command],
                             context.case_dir, timeout=600)
        if result["returncode"]:
            raise StageBlocked(context.question(
                self.id, "DEX repeatability restoration failed", [json.dumps(result, ensure_ascii=False)]
            ))
        repeated = {path.name: sha256_file(path) for path in output_dir.glob("*.dex")}
        expected = {path.name: sha256_file(path) for path in expected_paths}
        if repeated != expected:
            raise StageBlocked(context.question(
                self.id, "DEX repeatability hashes do not match", [json.dumps({
                    "expected": expected, "repeated": repeated,
                }, ensure_ascii=False)]
            ))
        return {"command": result, "hashes": expected, "manifest": str(manifest.resolve())}

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
        repeatability = None
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
            report_dir = context.revision_dir("reports") / "tool-logs"
            manifest_path = context.case.get("artifacts", {}).get("restore_manifest")
            manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8")) if manifest_path else {}
            manifest_by_output = {
                str(Path(entry["output"]).resolve()): entry for entry in manifest.get("outputs", [])
            }
            restored_paths = []
            for index, item in enumerate(files, 1):
                dex = Path(item["path"])
                restored_paths.append(dex)
                dump_result = run_logged_command(
                    [dexdump, "-f", str(dex)],
                    report_dir / f"dexdump-{index:02d}.stdout.log",
                    report_dir / f"dexdump-{index:02d}.stderr.log",
                    context.case_dir, timeout=300,
                )
                manifest_entry = manifest_by_output.get(str(dex.resolve()))
                if not manifest_entry:
                    raise StageBlocked(context.question(
                        self.id, "Restored DEX is missing from repair manifest", [str(dex)]
                    ))
                jadx_result = self._validate_jadx(
                    context, jadx, dex, Path(manifest_entry["source"]),
                    manifest_entry.get("methods", []), index, report_dir,
                )
                tool_results.append({"dex": str(dex), "dexdump": dump_result, "jadx": jadx_result})
                if dump_result["returncode"]:
                    raise StageBlocked(context.question(
                        self.id, "dexdump or JADX rejected a restored DEX",
                        [json.dumps({"dexdump": dump_result, "jadx": jadx_result}, ensure_ascii=False), str(dex)]))
            repeatability = self._repeat_restore(context, restored_paths, report_dir)
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
            "tool_results": tool_results,
            "repeatability": repeatability}
        output = context.revision_dir("reports") / "validation.json"
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        context.case.setdefault("artifacts", {})["validation_report"] = str(output.resolve())
        context.save_case()
        return {"ok": True, "source": "independent-validator", "report": report,
                "artifacts": [file_record(output, context.case_dir)]}
