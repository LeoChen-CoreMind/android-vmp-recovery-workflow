from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import (Context, DOWNSTREAM, STAGES, STAGE_SUCCESS, StageBlocked,
                   append_event, atomic_json, file_record, now, read_json)
from .plugins import PLUGINS


def init_case(case_dir: Path, package: str, device: str | None, dex: list[str],
              apk: str | None, profile: str) -> dict[str, Any]:
    case_dir.mkdir(parents=True, exist_ok=True)
    case_id = f"{package}-{now()[:10]}"
    case = {
        "schema_version": 1, "case_id": case_id, "package": package,
        "device_serial": device, "dex_inputs": [str(Path(x).resolve()) for x in dex],
        "apk": str(Path(apk).resolve()) if apk else None, "profile": profile,
        "config_revision": 1, "state": "INIT", "stage_records": {},
        "commands": {}, "ida": {"adapter": "fixture"},
        "require_target_confirmation": True,
    }
    atomic_json(case_dir / "case.json", case)
    atomic_json(case_dir / "questions.json", [])
    atomic_json(case_dir / "artifacts.json", [])
    atomic_json(case_dir / "checkpoint.json", {"case_id": case_id, "state": "INIT", "updated_at": now()})
    append_event(case_dir, {"type": "case-created", "case_id": case_id})
    return case


def load_context(case_dir: Path, execute_device: bool = False) -> Context:
    case = read_json(case_dir / "case.json")
    if not case:
        raise FileNotFoundError(f"missing case.json in {case_dir}")
    return Context(case_dir.resolve(), case, execute_device)


def run_workflow(context: Context, until: str | None = None) -> dict[str, Any]:
    start = 0
    for index, stage in enumerate(STAGES):
        if context.case.get("stage_records", {}).get(stage, {}).get("status") == "completed":
            start = index + 1
    for stage in STAGES[start:]:
        plugin = PLUGINS[stage]
        started = now()
        append_event(context.case_dir, {"type": "stage-start", "stage": stage,
                                         "config_revision": context.case.get("config_revision", 1)})
        try:
            result = plugin.run(context)
            validation = plugin.validate(context, result)
            if not validation.get("ok", False):
                raise StageBlocked(context.question(stage, "stage validation failed", [stage]))
            skipped = bool(result.get("skipped"))
            record = {"status": "skipped" if skipped else "completed", "started_at": started, "ended_at": now(),
                      "plugin_version": plugin.version, "config_revision": context.case.get("config_revision", 1),
                      "result": result, "validation": validation}
            context.case.setdefault("stage_records", {})[stage] = record
            artifact_records = []
            for key, value in context.case.get("artifacts", {}).items():
                values = value if isinstance(value, list) else [value]
                for item in values:
                    path = Path(item)
                    if path.is_file():
                        artifact_records.append({"key": key, **file_record(path, context.case_dir)})
            atomic_json(context.case_dir / "artifacts.json", artifact_records)
            if not skipped:
                context.case["state"] = STAGE_SUCCESS[stage]
            context.save_case()
            atomic_json(context.case_dir / "checkpoint.json", {"case_id": context.case["case_id"],
                      "stage": stage, "state": context.case["state"],
                      "config_revision": context.case.get("config_revision", 1), "updated_at": now()})
            append_event(context.case_dir, {"type": "stage-complete", "stage": stage,
                                             "status": record["status"], "state": context.case["state"]})
            if until == stage:
                break
        except StageBlocked:
            raise
    return context.case


def resume_case(context: Context, question_id: str, answer_path: Path) -> dict[str, Any]:
    questions = read_json(context.case_dir / "questions.json", []) or []
    question = next((q for q in questions if q["id"] == question_id and q.get("status") == "open"), None)
    if question is None:
        raise ValueError(f"open question not found: {question_id}")
    answer = read_json(answer_path)
    if not isinstance(answer, dict):
        raise ValueError("answer must be a JSON object")
    allowed = {"commands", "ida", "artifacts", "profile", "device_serial",
               "target_confirmed", "dex_inputs", "apk", "command_timeout"}
    unknown = sorted(set(answer) - allowed)
    if unknown:
        raise ValueError(f"answer contains immutable or unknown fields: {unknown}")
    for key, value in answer.items():
        if key == "commands" and isinstance(value, dict):
            context.case.setdefault("commands", {}).update(value)
        elif key == "ida" and isinstance(value, dict):
            context.case.setdefault("ida", {}).update(value)
        else:
            context.case[key] = value
    context.case["config_revision"] = int(context.case.get("config_revision", 1)) + 1
    question["status"] = "answered"; question["answer"] = answer; question["answered_at"] = now()
    atomic_json(context.case_dir / "questions.json", questions)
    stage = question["stage"]
    for downstream in [stage] + list(DOWNSTREAM.get(stage, [])):
        context.case.get("stage_records", {}).pop(downstream, None)
    context.case["open_questions"] = [q["id"] for q in questions if q.get("status") == "open"]
    context.case["state"] = "INIT" if stage == "target-confirm" else "BLOCKED"
    context.save_case()
    append_event(context.case_dir, {"type": "config-updated", "question_id": question_id,
                                     "config_revision": context.case["config_revision"]})
    return context.case
