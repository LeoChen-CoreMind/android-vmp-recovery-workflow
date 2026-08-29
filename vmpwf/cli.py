from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import install_skill, read_json
from .engine import init_case, load_context, resume_case, run_workflow


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="vmpwf", description="Android DexVMP recovery workflow orchestrator")
    sub = root.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--case", type=Path, required=True)
    init.add_argument("--package", required=True); init.add_argument("--device")
    init.add_argument("--dex", action="append", default=[]); init.add_argument("--apk")
    init.add_argument("--profile", default="android-arm64-360-dexvmp")
    init.add_argument("--confirm-target", action="store_true")
    for name in ("status", "inspect"):
        command = sub.add_parser(name); command.add_argument("--case", type=Path, required=True)
    run = sub.add_parser("run"); run.add_argument("--case", type=Path, required=True)
    run.add_argument("--execute-device", action="store_true"); run.add_argument("--until", choices=[
        "target-confirm", "so-dump", "so-repair", "ida-export", "vm-static", "native-sim", "dex-restore", "independent-validate"])
    resume = sub.add_parser("resume"); resume.add_argument("--case", type=Path, required=True)
    resume.add_argument("--question", required=True); resume.add_argument("--answer", type=Path, required=True)
    sub.add_parser("install-global")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            case = init_case(args.case, args.package, args.device, args.dex, args.apk, args.profile)
            if args.confirm_target:
                case["target_confirmed"] = True
                (args.case / "case.json").write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(case, ensure_ascii=False, indent=2)); return 0
        if args.command in ("status", "inspect"):
            path = args.case / "case.json"; payload = read_json(path)
            if payload is None: raise FileNotFoundError(path)
            if args.command == "status":
                payload = {"case_id": payload.get("case_id"), "state": payload.get("state"),
                           "config_revision": payload.get("config_revision"),
                           "open_questions": payload.get("open_questions", []),
                           "stages": {k: v.get("status") for k, v in payload.get("stage_records", {}).items()}}
            print(json.dumps(payload, ensure_ascii=False, indent=2)); return 0
        if args.command == "run":
            result = run_workflow(load_context(args.case, args.execute_device), args.until)
            print(json.dumps({"case_id": result["case_id"], "state": result["state"]}, ensure_ascii=False)); return 0
        if args.command == "resume":
            result = resume_case(load_context(args.case), args.question, args.answer)
            print(json.dumps({"case_id": result["case_id"], "state": result["state"],
                              "config_revision": result["config_revision"]}, ensure_ascii=False)); return 0
        if args.command == "install-global":
            print(str(install_skill())); return 0
    except Exception as exc:
        print(f"vmpwf: error: {exc}", file=sys.stderr); return 2
    return 2
