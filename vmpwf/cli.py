from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .core import StageBlocked, install_skill, read_json
from .engine import (init_case, load_context, resume_case, run_workflow,
                     validate_case, workflow_plan)
from .models import STAGES
from .tooling import resolve_tool


REPO_ROOT = Path(__file__).resolve().parent.parent


def inspect_package(apk: Path) -> str:
    script = REPO_ROOT / "scripts/apk/inspect_apk.py"
    completed = subprocess.run([sys.executable, str(script), str(apk)], capture_output=True, text=True, timeout=120)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "APK inspection failed")
    package = json.loads(completed.stdout).get("package")
    if not package:
        raise RuntimeError("AndroidManifest package could not be determined")
    return package


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="vmpwf", description="Android 360 DexVMP recovery workflow")
    sub = root.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--case", type=Path, required=True); init.add_argument("--package")
    init.add_argument("--device"); init.add_argument("--dex", action="append", default=[])
    init.add_argument("--dex-dir"); init.add_argument("--dex-zip"); init.add_argument("--apk", type=Path, required=True)
    init.add_argument("--profile", default="android-arm64-360-dexvmp")
    recover = sub.add_parser("recover")
    recover.add_argument("--apk", type=Path, required=True); recover.add_argument("--dex-dir")
    recover.add_argument("--dex-zip"); recover.add_argument("--device")
    recover.add_argument("--profile", default="android-arm64-360-dexvmp")
    recover.add_argument("--case-root", type=Path, default=REPO_ROOT / "cases")
    recover.add_argument("--execute-device", action="store_true")
    for name in ("status", "inspect", "plan", "validate"):
        command = sub.add_parser(name); command.add_argument("--case", type=Path, required=True)
    run = sub.add_parser("run"); run.add_argument("--case", type=Path, required=True)
    run.add_argument("--execute-device", action="store_true"); run.add_argument("--until", choices=STAGES)
    resume = sub.add_parser("resume"); resume.add_argument("--case", type=Path, required=True)
    resume.add_argument("--question", required=True); resume.add_argument("--answer", type=Path, required=True)
    sub.add_parser("install-global"); sub.add_parser("doctor")
    return root


def doctor() -> dict:
    required = [
        REPO_ROOT / "workflow/workflow.json", REPO_ROOT / "scripts/apk/inspect_apk.py",
        REPO_ROOT / "scripts/dump/dex/extract_360_dex.py", REPO_ROOT / "skill/SKILL.md",
        REPO_ROOT / "scripts/simulation/run_native_confirmation.py",
    ]
    tools = {name: resolve_tool(name) for name in
             ("adb", "frida", "java", "jadx", "dexdump", "codex", "git", "gh")}
    modules = {name: importlib.util.find_spec(name) is not None
               for name in ("frida", "unicorn", "capstone", "jsonschema")}
    return {"status": "ok" if all(path.is_file() for path in required) else "error",
            "python": sys.version.split()[0], "required_files": {str(path): path.is_file() for path in required},
            "tools": tools, "python_modules": modules,
            "device_execution_ready": bool(tools["adb"] and modules["frida"]),
            "native_simulation_ready": bool(modules["unicorn"] and modules["capstone"]),
            "real_dex_validation_ready": bool(tools["java"] and tools["jadx"] and tools["dexdump"])}


def _summary(case: dict) -> dict:
    return {"case_id": case.get("case_id"), "package": case.get("package"), "state": case.get("state"),
            "config_revision": case.get("config_revision"), "open_questions": case.get("open_questions", []),
            "stages": {key: value.get("status") for key, value in case.get("stage_records", {}).items()}}


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            apk = args.apk.resolve(); package = args.package or inspect_package(apk)
            case = init_case(args.case.resolve(), package, args.device, args.dex, str(apk), args.profile,
                             args.dex_dir, args.dex_zip)
            print(json.dumps(case, ensure_ascii=False, indent=2)); return 0
        if args.command == "recover":
            apk = args.apk.resolve(); package = inspect_package(apk)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            case_dir = args.case_root.resolve() / package / f"{package}-{stamp}"
            init_case(case_dir, package, args.device, [], str(apk), args.profile, args.dex_dir, args.dex_zip)
            result = run_workflow(load_context(case_dir, args.execute_device))
            print(json.dumps({"case": str(case_dir), **_summary(result)}, ensure_ascii=False, indent=2)); return 0
        if args.command in ("status", "inspect"):
            payload = read_json(args.case / "case.json")
            if payload is None: raise FileNotFoundError(args.case / "case.json")
            print(json.dumps(_summary(payload) if args.command == "status" else payload, ensure_ascii=False, indent=2)); return 0
        if args.command == "plan":
            print(json.dumps(workflow_plan(load_context(args.case)), ensure_ascii=False, indent=2)); return 0
        if args.command == "validate":
            print(json.dumps(validate_case(load_context(args.case)), ensure_ascii=False, indent=2)); return 0
        if args.command == "run":
            result = run_workflow(load_context(args.case, args.execute_device), args.until)
            print(json.dumps(_summary(result), ensure_ascii=False, indent=2)); return 0
        if args.command == "resume":
            result = resume_case(load_context(args.case), args.question, args.answer)
            result = run_workflow(load_context(args.case, bool(result.get("execute_device"))))
            print(json.dumps(_summary(result), ensure_ascii=False, indent=2)); return 0
        if args.command == "install-global":
            print(str(install_skill())); return 0
        if args.command == "doctor":
            payload = doctor(); print(json.dumps(payload, ensure_ascii=False, indent=2)); return 0 if payload["status"] == "ok" else 2
    except StageBlocked as exc:
        print(json.dumps({"status": "blocked", "question": exc.question}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"vmpwf: error: {exc}", file=sys.stderr); return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
