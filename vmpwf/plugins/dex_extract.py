from __future__ import annotations

import json
import sys
from pathlib import Path

from ..adapters import import_dex_directory, import_dex_zip
from ..core import StageBlocked, run_command
from ..provenance import file_record
from ..validation import lm_summary, valid_dex_file
from .common import BasePlugin


class DexExtract(BasePlugin):
    id = "dex-extract"

    def run(self, context):
        static_dir = context.revision_dir("dump/dex/static")
        extractor = context.repo_root / "scripts/dump/dex/extract_360_dex.py"
        apk = Path(context.case.get("apk_ingested", context.case["apk"]))
        command = [sys.executable, str(extractor), str(apk), "-o", str(static_dir),
                   "--known-seeds-only", "--force"]
        static_result = run_command(command, context.repo_root, timeout=int(context.profile.get("static_extract_timeout", 120)))
        static_outputs = [file_record(path, context.case_dir, source="static-extractor")
                          for path in sorted(static_dir.glob("*.dex")) if valid_dex_file(path)]

        imported = []
        destination = context.revision_dir("input/dex")
        if context.case.get("dex_zip"):
            imported = import_dex_zip(Path(context.case["dex_zip"]), destination, context.case_dir)
        elif context.case.get("dex_dir"):
            imported = import_dex_directory(Path(context.case["dex_dir"]), destination, context.case_dir)
        elif context.case.get("dex_inputs"):
            temp_dir = destination / "provided"
            temp_dir.mkdir(parents=True, exist_ok=True)
            for index, item in enumerate(context.case["dex_inputs"], 1):
                path = Path(item)
                if valid_dex_file(path):
                    target = temp_dir / ("classes.dex" if index == 1 else f"classes{index}.dex")
                    target.write_bytes(path.read_bytes())
            imported = import_dex_directory(temp_dir, destination / "normalized", context.case_dir)

        selected = imported or static_outputs
        if not selected:
            evidence = [static_result.get("stderr", ""), static_result.get("stdout", "")]
            raise StageBlocked(context.question(
                self.id, "Static extraction produced no valid DEX; provide --dex-dir or --dex-zip",
                evidence, ["dex_dir", "dex_zip"]))
        dex_paths = [item["path"] for item in selected]
        summaries = [{"path": path, **lm_summary(Path(path))} for path in dex_paths]
        if not context.profile.get("fixture") and not any(
                isinstance(item.get("method_records"), int) and item["method_records"] > 0
                for item in summaries):
            raise StageBlocked(context.question(
                self.id,
                "No recoverable VMP method records were found; provide a matching runtime DEX",
                [json.dumps(summaries, ensure_ascii=False)], ["dex_dir", "dex_zip"]))
        context.case["dex_inputs"] = dex_paths
        context.case["vmp_inventory"] = summaries
        context.save_case()
        manifest = {"static": {"returncode": static_result["returncode"], "outputs": static_outputs,
                               "stderr": static_result.get("stderr", "")[-4000:]},
                    "selected_source": "user-supplied" if imported else "static-extractor",
                    "outputs": selected, "vmp": summaries}
        manifest_path = context.revision_dir("dump/dex/records") / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"ok": True, "source": manifest["selected_source"], "dexes": selected,
                "vmp": summaries, "artifacts": [*selected, file_record(manifest_path, context.case_dir)]}
