from __future__ import annotations

import shutil
from pathlib import Path

from ..core import StageBlocked, run_command
from ..provenance import file_record
from ..validation import inspect_elf
from .common import BasePlugin


class SoRepair(BasePlugin):
    id = "so-repair"

    def run(self, context):
        sources = [Path(path) for path in context.case.get("artifacts", {}).get("so_dump", [])]
        if not sources:
            sources = list((context.case_dir / "dump/so/raw").glob("rev-*/*.so"))
        if not sources:
            raise StageBlocked(context.question(self.id, "No SO dump is available", ["dump/so/raw"]))
        output = context.revision_dir("fix/so")
        artifacts = []
        commands = []
        for source in sources:
            target = output / (source.stem + "_fixed.so")
            if context.profile.get("fixture"):
                shutil.copy2(source, target)
                mode = "fixture-pass-through"
            else:
                tool = context.profile.get("tools", {}).get("sofixer") or context.case.get("tools", {}).get("sofixer")
                if not tool:
                    raise StageBlocked(context.question(self.id, "SoFixer path is not configured", [], ["tools.sofixer"]))
                result = run_command([tool, "-s", str(source), "-o", str(target)], context.case_dir, timeout=300)
                if result["returncode"]:
                    raise StageBlocked(context.question(self.id, "SoFixer failed", [result["stderr"]]))
                commands.append(result)
                mode = "sofixer"
            validation = inspect_elf(target)
            if not validation.get("ok"):
                raise StageBlocked(context.question(self.id, "Repaired SO failed ELF validation", [str(target)]))
            if not context.profile.get("fixture"):
                errors = []
                if validation.get("machine") != 183:
                    errors.append("ELF machine is not AArch64")
                if validation.get("pt_dynamic", 0) <= 0:
                    errors.append("PT_DYNAMIC is missing")
                if validation.get("dynamic_missing"):
                    errors.append("missing dynamic tags: " + ", ".join(validation["dynamic_missing"]))
                if not validation.get("has_sysv_hash") and not validation.get("has_gnu_hash"):
                    errors.append("dynamic hash table is missing")
                if not isinstance(validation.get("symbol_count"), int) or validation["symbol_count"] <= 0:
                    errors.append("dynamic symbol count is unavailable")
                if errors:
                    raise StageBlocked(context.question(
                        self.id, "Repaired SO failed dynamic symbol validation", [str(target), *errors]))
            artifacts.append(file_record(target, context.case_dir, source=mode, elf=validation))
        context.case.setdefault("artifacts", {})["so_fixed"] = [item["path"] for item in artifacts]
        context.save_case()
        return {"ok": True, "source": "fixture" if context.profile.get("fixture") else "sofixer",
                "commands": commands, "artifacts": artifacts}
