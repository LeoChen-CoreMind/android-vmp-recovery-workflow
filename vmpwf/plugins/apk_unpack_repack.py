from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ..core import StageBlocked, atomic_json, run_logged_command
from ..provenance import file_record, sha256_file
from ..tooling import resolve_tool
from .common import BasePlugin


class ApkUnpackRepack(BasePlugin):
    id = "apk-unpack-repack"
    version = "1.1.0"

    @staticmethod
    def _resolve(case_dir: Path, value: str) -> Path:
        path = Path(value).expanduser()
        return path.resolve() if path.is_absolute() else (case_dir / path).resolve()

    @staticmethod
    def _sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _inventory(self, context) -> tuple[Path, Path]:
        output_dir = context.revision_dir("repack/adapter")
        apk = Path(context.case.get("apk_ingested") or context.case.get("apk", ""))
        zip_entries: list[dict[str, Any]] = []
        duplicates: list[str] = []
        if apk.is_file() and zipfile.is_zipfile(apk):
            with zipfile.ZipFile(apk) as archive:
                names = [item.filename for item in archive.infolist()]
                duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
                zip_entries = [
                    {"name": item.filename, "size": item.file_size, "crc32": f"{item.CRC:08x}"}
                    for item in archive.infolist()
                ]
        dex_paths = context.case.get("artifacts", {}).get("restored_dex") or context.case.get("dex_inputs", [])
        inventory = {
            "evidence_revision": context.case.get("stage_records", {}).get(
                "independent-validate", {}
            ).get("config_revision", context.revision),
            "case_revision": context.revision,
            "package": context.case.get("package"),
            "apk": file_record(apk, context.case_dir) if apk.is_file() else {"path": str(apk), "missing": True},
            "restored_dex": [file_record(Path(item), context.case_dir) for item in dex_paths if Path(item).is_file()],
            "zip_entries": zip_entries,
            "duplicate_zip_entries": duplicates,
            "note": "Inventory is observation only. Candidate names are not authorization to remove entries.",
        }
        inventory_path = output_dir / "apk_inventory.json"
        atomic_json(inventory_path, inventory)
        template = {
            "schema_version": 1,
            "adapter_id": f"{context.case.get('package')}-revision-{context.revision}",
            "evidence_revision": inventory["evidence_revision"],
            "case_revision": context.revision + 1,
            "package": context.case.get("package"),
            "apk_sha256": inventory.get("apk", {}).get("sha256"),
            "_instructions": [
                "Copy this file to an answer workspace before editing; resume will activate it at the next revision.",
                "Every value must be derived from this APK revision; do not reuse another 360 version's facts.",
                "Validate against schemas/apk-repack-adapter.schema.json before resume.",
            ],
        }
        template_path = output_dir / "adapter.template.json"
        atomic_json(template_path, template)
        return inventory_path, template_path

    def _load_adapter(self, context, configured: str) -> tuple[Path, dict[str, Any]]:
        path = self._resolve(context.case_dir, configured)
        if not path.is_file():
            raise StageBlocked(context.question(
                self.id, "APK repack adapter does not exist",
                [str(path)], ["apk_repack.adapter"],
            ))
        try:
            adapter = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageBlocked(context.question(
                self.id, "APK repack adapter is not valid JSON", [str(path), str(exc)],
                ["apk_repack.adapter"],
            )) from exc
        schema_path = context.repo_root / "schemas/apk-repack-adapter.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema).iter_errors(adapter),
            key=lambda item: tuple(str(part) for part in item.path),
        )
        if errors:
            evidence = [str(path)] + [f"/{'/'.join(map(str, error.path))}: {error.message}" for error in errors[:20]]
            raise StageBlocked(context.question(
                self.id, "APK repack adapter failed schema validation", evidence,
                ["apk_repack.adapter"],
            ))
        evidence_dir = context.revision_dir("repack/adapter")
        try:
            path.relative_to(evidence_dir.resolve())
            evidence_path = path
        except ValueError:
            evidence_path = evidence_dir / f"adapter.{sha256_file(path)[:16]}.json"
            if not evidence_path.exists():
                shutil.copy2(path, evidence_path)
        return evidence_path, adapter

    def _validate_adapter_facts(self, context, adapter: dict[str, Any], adapter_path: Path) -> Path:
        apk = Path(context.case.get("apk_ingested") or context.case.get("apk", ""))
        conflicts = []
        if not apk.is_file():
            conflicts.append(f"missing APK: {apk}")
        elif sha256_file(apk) != adapter["apk_sha256"]:
            conflicts.append(f"APK SHA-256 expected={adapter['apk_sha256']} actual={sha256_file(apk)}")
        if adapter["case_revision"] != context.revision:
            conflicts.append(f"adapter revision={adapter['case_revision']} case revision={context.revision}")
        validation_revision = context.case.get("stage_records", {}).get(
            "independent-validate", {}
        ).get("config_revision")
        if validation_revision is not None and adapter["evidence_revision"] != validation_revision:
            conflicts.append(
                f"adapter evidence revision={adapter['evidence_revision']} "
                f"independent validation revision={validation_revision}"
            )
        if adapter["package"] != context.case.get("package"):
            conflicts.append(f"adapter package={adapter['package']} case package={context.case.get('package')}")

        targets = [item["target"] for item in adapter["dex_layout"]]
        if len(targets) != len(set(targets)):
            conflicts.append("DEX target names are not unique")
        allowed_dex = {
            str(Path(item).resolve()) for item in
            (context.case.get("artifacts", {}).get("restored_dex") or context.case.get("dex_inputs", []))
        }
        for item in adapter["dex_layout"]:
            source = self._resolve(context.case_dir, item["source"])
            if not source.is_file():
                conflicts.append(f"missing DEX source: {source}")
            elif sha256_file(source) != item["source_sha256"]:
                conflicts.append(
                    f"DEX SHA-256 mismatch {source}: expected={item['source_sha256']} actual={sha256_file(source)}"
                )
            if str(source) not in allowed_dex:
                conflicts.append(f"DEX source is not a current restored/input DEX: {source}")
        if apk.is_file() and zipfile.is_zipfile(apk):
            with zipfile.ZipFile(apk) as archive:
                source_names = set(archive.namelist())
            replace_names = [item["name"] for item in adapter["replace_entries"]]
            missing_changes = sorted((set(adapter["remove_entries"]) | set(replace_names)) - source_names)
            if missing_changes:
                conflicts.append(f"declared removal/replacement entries are absent from source APK: {missing_changes}")
        replace_names = [item["name"] for item in adapter["replace_entries"]]
        if len(replace_names) != len(set(replace_names)):
            conflicts.append("replacement entry names are not unique")
        overlap = sorted(set(adapter["remove_entries"]) & set(replace_names))
        if overlap:
            conflicts.append(f"entries cannot be both removed and replaced: {overlap}")
        for entry in [*adapter["remove_entries"], *replace_names]:
            if any(marker in entry for marker in ("*", "?", "[", "]", "\\")) or entry.startswith("/") or ".." in Path(entry).parts:
                conflicts.append(f"changed entry is not an exact normalized ZIP path: {entry}")
        for replacement in adapter["bridge_contracts"]["descriptor_replacements"]:
            try:
                old = replacement["old"].encode("ascii")
                new = replacement["new"].encode("ascii")
            except UnicodeEncodeError:
                conflicts.append(f"descriptor replacement is not ASCII: {replacement['old']} -> {replacement['new']}")
                continue
            if len(old) != len(new):
                conflicts.append(f"descriptor replacement changes encoded length: {replacement['old']} -> {replacement['new']}")
            unknown_targets = sorted(set(replacement["targets"]) - set(targets))
            if unknown_targets:
                conflicts.append(f"descriptor replacement references unmapped DEX targets: {unknown_targets}")
        for patch in adapter["bridge_contracts"].get("smali_patches", []):
            flags = 0
            for name in patch.get("flags", []):
                flags |= {"MULTILINE": re.MULTILINE, "DOTALL": re.DOTALL}[name]
            try:
                re.compile(patch["pattern"], flags)
            except re.error as exc:
                conflicts.append(f"invalid smali regex {patch['id']}: {exc}")
            for pattern in patch["files"]:
                candidate = Path(pattern)
                if candidate.is_absolute() or ".." in candidate.parts or "\\" in pattern:
                    conflicts.append(f"unsafe smali file glob in {patch['id']}: {pattern}")
        if conflicts:
            raise StageBlocked(context.question(
                self.id, "APK repack adapter conflicts with current case evidence",
                [str(adapter_path), *conflicts], ["apk_repack.adapter"],
            ))
        return apk

    @staticmethod
    def _application_attributes(xmltree: str) -> str:
        lines = xmltree.splitlines()
        for index, line in enumerate(lines):
            if line.lstrip().startswith("E: application"):
                block = [line]
                for following in lines[index + 1:]:
                    stripped = following.lstrip()
                    if stripped.startswith("E:"):
                        break
                    block.append(following)
                return "\n".join(block)
        return ""

    def _validate_output(self, context, adapter: dict[str, Any], output_apk: Path,
                         output_dir: Path, log_dir: Path) -> dict[str, Any]:
        if not output_apk.is_file() or not zipfile.is_zipfile(output_apk):
            raise StageBlocked(context.question(
                self.id, "APK repack command produced no valid APK ZIP", [str(output_apk)]
            ))
        with zipfile.ZipFile(output_apk) as archive:
            names = [item.filename for item in archive.infolist()]
            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            if duplicates:
                raise StageBlocked(context.question(
                    self.id, "Repacked APK contains duplicate ZIP entries", duplicates
                ))
            present_removed = sorted(set(adapter["remove_entries"]) & set(names))
            if present_removed:
                raise StageBlocked(context.question(
                    self.id, "Adapter-declared shell entries remain in the APK", present_removed
                ))
            for replacement in adapter["replace_entries"]:
                name = replacement["name"]
                if name not in names:
                    raise StageBlocked(context.question(
                        self.id, "Adapter-declared replacement entry is missing from the APK", [name]
                    ))
                digest = self._sha256_bytes(archive.read(name))
                if digest != replacement["output_sha256"]:
                    raise StageBlocked(context.question(
                        self.id, "Replacement entry hash does not match adapter",
                        [f"{name}: expected={replacement['output_sha256']} actual={digest}"],
                    ))
            mapped_targets = {item["target"] for item in adapter["dex_layout"]}
            actual_dex = {name for name in names if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", name)}
            if actual_dex != mapped_targets:
                raise StageBlocked(context.question(
                    self.id, "Repacked APK DEX layout does not exactly match adapter",
                    [f"expected={sorted(mapped_targets)}", f"actual={sorted(actual_dex)}"],
                ))
            replacements_by_target: dict[str, list[dict[str, Any]]] = {}
            for replacement in adapter["bridge_contracts"]["descriptor_replacements"]:
                for target in replacement["targets"]:
                    replacements_by_target.setdefault(target, []).append(replacement)
            extracted = output_dir / "validated-dex"
            extracted.mkdir(parents=True, exist_ok=True)
            dex_records = []
            for mapping in adapter["dex_layout"]:
                target = mapping["target"]
                if target not in names:
                    raise StageBlocked(context.question(self.id, "Mapped DEX is missing from repacked APK", [target]))
                data = archive.read(target)
                digest = self._sha256_bytes(data)
                if digest != mapping["output_sha256"]:
                    raise StageBlocked(context.question(
                        self.id, "Mapped DEX hash does not match adapter",
                        [f"{target}: expected={mapping['output_sha256']} actual={digest}"],
                    ))
                if not data.startswith(b"dex\n"):
                    raise StageBlocked(context.question(self.id, "Mapped APK entry is not a DEX", [target]))
                for replacement in replacements_by_target.get(target, []):
                    old = replacement["old"].encode("ascii")
                    new = replacement["new"].encode("ascii")
                    if data.count(old) != 0 or data.count(new) != replacement["expected_occurrences"]:
                        raise StageBlocked(context.question(
                            self.id, "Repacked DEX descriptor replacement does not match adapter",
                            [target, replacement["old"], replacement["new"],
                             f"old_count={data.count(old)}", f"new_count={data.count(new)}"],
                        ))
                path = extracted / target
                path.write_bytes(data)
                dex_records.append(file_record(path, context.case_dir, zip_entry=target))

        configured = {**context.profile.get("tools", {}), **context.case.get("tools", {})}
        required = {name: resolve_tool(name, configured.get(name)) for name in
                    ("aapt2", "dexdump", "jadx", "zipalign", "apksigner")}
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise StageBlocked(context.question(
                self.id, "APK repack validation tools are unavailable", missing, ["tools"]
            ))

        tool_results: dict[str, Any] = {}
        aapt2 = run_logged_command(
            [required["aapt2"], "dump", "xmltree", "--file", "AndroidManifest.xml", str(output_apk)],
            log_dir / "aapt2-xmltree.stdout.log", log_dir / "aapt2-xmltree.stderr.log",
            context.case_dir, timeout=300,
        )
        if aapt2["returncode"]:
            raise StageBlocked(context.question(self.id, "aapt2 rejected the repacked manifest", [json.dumps(aapt2)]))
        application = self._application_attributes(aapt2["stdout"])
        expected_application = adapter["manifest"]["application"]["value"]
        expected_factory = adapter["manifest"]["app_component_factory"]["value"]
        application_match = re.search(r"android:name\([^\n]*\)=\"([^\"]+)\"", application)
        factory_match = re.search(r"android:appComponentFactory\([^\n]*\)=\"([^\"]+)\"", application)
        if (application_match.group(1) if application_match else None) != expected_application:
            raise StageBlocked(context.question(self.id, "Repacked manifest Application does not match adapter", [application]))
        if (factory_match.group(1) if factory_match else None) != expected_factory:
            raise StageBlocked(context.question(self.id, "Repacked manifest AppComponentFactory does not match adapter", [application]))
        tool_results["aapt2"] = aapt2

        dexdump_results = []
        for index, record in enumerate(dex_records, 1):
            result = run_logged_command(
                [required["dexdump"], "-f", record["path"]],
                log_dir / f"dexdump-{index:02d}.stdout.log", log_dir / f"dexdump-{index:02d}.stderr.log",
                context.case_dir, timeout=600,
            )
            dexdump_results.append(result)
            if result["returncode"]:
                raise StageBlocked(context.question(self.id, "dexdump rejected a DEX in the repacked APK", [record["path"]]))
        tool_results["dexdump"] = dexdump_results

        jadx = run_logged_command(
            [required["jadx"], "--log-level", "ERROR", "-d", str(output_dir / "jadx"), str(output_apk)],
            log_dir / "jadx.stdout.log", log_dir / "jadx.stderr.log",
            context.case_dir, timeout=1800,
        )
        tool_results["jadx"] = jadx
        if jadx["returncode"]:
            raise StageBlocked(context.question(
                self.id, "JADX reported errors for the repacked APK",
                [json.dumps({"returncode": jadx["returncode"], "stdout_log": jadx["stdout_log"], "stderr_log": jadx["stderr_log"]})],
            ))

        zipalign = run_logged_command(
            [required["zipalign"], "-c", "-P", "16", "-v", "4", str(output_apk)],
            log_dir / "zipalign.stdout.log", log_dir / "zipalign.stderr.log",
            context.case_dir, timeout=300,
        )
        tool_results["zipalign"] = zipalign
        if zipalign["returncode"]:
            raise StageBlocked(context.question(self.id, "zipalign rejected the repacked APK", [json.dumps(zipalign)]))

        signature = run_logged_command(
            [required["apksigner"], "verify", "--verbose", "--print-certs", str(output_apk)],
            log_dir / "apksigner.stdout.log", log_dir / "apksigner.stderr.log",
            context.case_dir, timeout=300,
        )
        tool_results["apksigner"] = signature
        expected_cert = adapter["signing"]["certificate_sha256"].lower()
        certificate_hashes = {
            re.sub(r"[^0-9a-f]", "", value.lower())
            for value in re.findall(r"certificate SHA-256 digest:\s*([0-9a-f:]+)", signature["stdout"], re.I)
        }
        missing_schemes = [scheme for scheme in adapter["signing"]["required_schemes"]
                           if f"verifiedusing{scheme}scheme" not in re.sub(r"[^a-z0-9]", "", signature["stdout"].lower())
                           or not re.search(rf"Verified using {re.escape(scheme)}(?:\.\d+)? scheme[^:]*:\s*true", signature["stdout"], re.I)]
        if signature["returncode"] or expected_cert not in certificate_hashes or missing_schemes:
            raise StageBlocked(context.question(
                self.id, "APK signature verification does not match adapter",
                [f"certificate={expected_cert}", f"missing_schemes={missing_schemes}", signature["stdout_log"]],
            ))

        if adapter["validation"]["device"]:
            if not context.execute_device:
                raise StageBlocked(context.question(
                    self.id, "Device acceptance is required by the APK repack adapter",
                    [adapter["device"]["launch_component"]], ["execute_device"],
                ))
            values = {"case": str(context.case_dir), "apk": str(output_apk),
                      "device": str(context.case.get("device_serial") or ""),
                      "component": adapter["device"]["launch_component"]}
            command = [str(item).format(**values) for item in adapter["device"]["command"]]
            device = run_logged_command(
                command, log_dir / "device.stdout.log", log_dir / "device.stderr.log",
                context.case_dir, timeout=adapter["device"]["acceptance_window_seconds"] + 300,
            )
            tool_results["device"] = device
            if device["returncode"]:
                raise StageBlocked(context.question(self.id, "Device acceptance command failed", [json.dumps(device)]))

        return {"zip_entry_count": len(names), "duplicate_entries": [], "dex": dex_records,
                "removed_entries_absent": adapter["remove_entries"],
                "replaced_entries": adapter["replace_entries"], "tools": tool_results}

    def run(self, context):
        profile_config = context.profile.get("apk_repack", {})
        case_config = context.case.get("apk_repack", {})
        config = {**profile_config, **case_config}
        if context.profile.get("fixture") or not config.get("enabled"):
            return {"ok": True, "applicable": False, "repacked": False,
                    "reason": "fixture" if context.profile.get("fixture") else "disabled", "artifacts": []}

        configured_adapter = config.get("adapter")
        if not configured_adapter:
            inventory, template = self._inventory(context)
            raise StageBlocked(context.question(
                self.id, "A current-revision 360 APK repack adapter is required",
                [str(inventory), str(template), str(context.repo_root / "schemas/apk-repack-adapter.schema.json")],
                ["apk_repack.adapter"],
            ))
        adapter_path, adapter = self._load_adapter(context, configured_adapter)
        source_apk = self._validate_adapter_facts(context, adapter, adapter_path)

        output_dir = context.revision_dir("repack/output")
        log_dir = context.revision_dir("logs/repack")
        output_apk = self._resolve(output_dir, adapter["executor"]["output_apk"])
        try:
            output_apk.relative_to(output_dir.resolve())
        except ValueError:
            raise StageBlocked(context.question(
                self.id, "APK repack output must stay inside the current revision output directory",
                [str(output_apk), str(output_dir)], ["apk_repack.adapter"],
            ))
        values = {"case": str(context.case_dir), "adapter": str(adapter_path),
                  "repo": str(context.repo_root), "python": str(__import__("sys").executable),
                  "source_apk": str(source_apk), "output": str(output_apk),
                  "output_dir": str(output_dir)}
        command = [str(item).format(**values) for item in adapter["executor"]["command"]]
        execution = run_logged_command(
            command, log_dir / "executor.stdout.log", log_dir / "executor.stderr.log",
            context.case_dir, timeout=int(context.case.get("command_timeout", 1800)),
        )
        if execution["returncode"]:
            raise StageBlocked(context.question(
                self.id, "APK repack executor failed",
                [str(adapter_path), json.dumps(execution, ensure_ascii=False)], ["apk_repack.adapter"],
            ))

        validation = self._validate_output(context, adapter, output_apk, output_dir, log_dir)
        manifest = {
            "status": "ok", "applicable": True, "repacked": True,
            "case_revision": context.revision,
            "adapter": file_record(adapter_path, context.case_dir),
            "source_apk": file_record(source_apk, context.case_dir),
            "output_apk": file_record(output_apk, context.case_dir),
            "executor": execution, "validation": validation,
        }
        manifest_path = output_dir / "apk_repack_manifest.json"
        atomic_json(manifest_path, manifest)
        artifacts = [file_record(output_apk, context.case_dir, source="version-adapted-repack"),
                     file_record(manifest_path, context.case_dir), file_record(adapter_path, context.case_dir)]
        artifacts.extend(file_record(path, context.case_dir) for path in sorted(log_dir.glob("*.log")))
        context.case.setdefault("artifacts", {})["repacked_apk"] = str(output_apk)
        context.case["artifacts"]["repack_manifest"] = str(manifest_path)
        context.save_case()
        return {"ok": True, "applicable": True, "repacked": True,
                "output_apk": str(output_apk), "manifest": str(manifest_path), "artifacts": artifacts}
