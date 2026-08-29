from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import (Context, StageBlocked, append_event, atomic_json,
                   create_case_layout, now, read_json)
from .hot_reload import load_workflow
from .models import DOWNSTREAM, STAGES, STAGE_SUCCESS
from .plugins import PLUGINS


def init_case(case_dir: Path, package: str, device: str | None, dex: list[str],
              apk: str | None, profile: str, dex_dir: str | None = None,
              dex_zip: str | None = None) -> dict[str, Any]:
    create_case_layout(case_dir)
    case_id = case_dir.name
    case = {
        "schema_version": 2, "case_id": case_id, "package": package,
        "device_serial": device, "dex_inputs": [str(Path(item).resolve()) for item in dex],
        "dex_dir": str(Path(dex_dir).resolve()) if dex_dir else None,
        "dex_zip": str(Path(dex_zip).resolve()) if dex_zip else None,
        "apk": str(Path(apk).resolve()) if apk else None, "profile": profile,
        "config_revision": 1, "state": "INIT", "stage_records": {},
        "commands": {}, "ida": {}, "simulation": {}, "tools": {}, "artifacts": {},
    }
    atomic_json(case_dir / "case.json", case)
    atomic_json(case_dir / "questions.json", [])
    atomic_json(case_dir / "artifacts.json", [])
    atomic_json(case_dir / "checkpoint.json", {"case_id": case_id, "state": "INIT", "updated_at": now()})
    append_event(case_dir, {"type": "case-created", "case_id": case_id, "profile": profile})
    return case


def load_context(case_dir: Path, execute_device: bool = False) -> Context:
    case = read_json(case_dir / "case.json")
    if not case:
        raise FileNotFoundError(f"missing case.json in {case_dir}")
    return Context(case_dir.resolve(), case, execute_device or bool(case.get("execute_device")))


def _append_artifacts(context: Context, stage: str, stage_record: dict[str, Any]) -> None:
    """Append new provenance entries without dropping invalidated revisions."""
    path = context.case_dir / "artifacts.json"
    records = read_json(path, []) or []
    known = {(item.get("stage"), item.get("config_revision"), item.get("path"), item.get("sha256"))
             for item in records}
    for artifact in stage_record.get("result", {}).get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        item = {"stage": stage, "config_revision": stage_record.get("config_revision"), **artifact}
        key = (item.get("stage"), item.get("config_revision"), item.get("path"), item.get("sha256"))
        if key not in known:
            records.append(item)
            known.add(key)
    atomic_json(path, records)


def _input_artifacts(context: Context, stage: str) -> list[dict[str, Any]]:
    dependencies = read_json(context.repo_root / "workflow/dependencies.json", {}) or {}
    records = []
    for dependency in dependencies.get(stage, []):
        result = context.case.get("stage_records", {}).get(dependency, {}).get("result", {})
        records.extend(item for item in result.get("artifacts", []) if isinstance(item, dict))
    return records


def run_workflow(context: Context, until: str | None = None) -> dict[str, Any]:
    while True:
        workflow, _, workflow_hash = context.reload_boundary()
        stages = workflow.get("stages", STAGES)
        stage = next((item for item in stages
                      if context.case.get("stage_records", {}).get(item, {}).get("status") != "completed"), None)
        if stage is None:
            break
        dependencies = read_json(context.repo_root / "workflow/dependencies.json", {}) or {}
        incomplete = [item for item in dependencies.get(stage, [])
                      if context.case.get("stage_records", {}).get(item, {}).get("status") != "completed"]
        if incomplete:
            raise RuntimeError(f"stage {stage} has incomplete dependencies: {incomplete}")
        plugin = PLUGINS[stage]
        started = now()
        input_artifacts = _input_artifacts(context, stage)
        append_event(context.case_dir, {"type": "stage-start", "stage": stage,
                                        "config_revision": context.revision, "workflow_hash": workflow_hash})
        result = plugin.run(context)
        validation = plugin.validate(context, result)
        if not validation.get("ok"):
            raise StageBlocked(context.question(stage, "Stage validation failed", [stage]))
        record = {"status": "completed", "started_at": started, "ended_at": now(),
                  "plugin_version": plugin.version, "config_revision": context.revision,
                  "workflow_hash": workflow_hash, "input_artifacts": input_artifacts,
                  "output_artifacts": [item for item in result.get("artifacts", []) if isinstance(item, dict)],
                  "tools": {"plugin": type(plugin).__name__, "plugin_version": plugin.version},
                  "result": result, "validation": validation}
        context.case.setdefault("stage_records", {})[stage] = record
        context.case["state"] = STAGE_SUCCESS[stage]
        context.save_case()
        _append_artifacts(context, stage, record)
        atomic_json(context.case_dir / "checkpoint.json", {
            "case_id": context.case["case_id"], "stage": stage,
            "state": context.case["state"], "config_revision": context.revision,
            "workflow_hash": workflow_hash, "updated_at": now(),
        })
        append_event(context.case_dir, {"type": "stage-complete", "stage": stage,
                                        "state": context.case["state"]})
        if until == stage:
            break
    return context.case


def resume_case(context: Context, question_id: str, answer_path: Path) -> dict[str, Any]:
    questions = read_json(context.case_dir / "questions.json", []) or []
    question = next((item for item in questions if item["id"] == question_id and item.get("status") == "open"), None)
    if not question:
        raise ValueError(f"open question not found: {question_id}")
    answer = read_json(answer_path)
    if not isinstance(answer, dict):
        raise ValueError("answer must be a JSON object")
    allowed = {"commands", "ida", "simulation", "artifacts", "profile", "device_serial", "dex_inputs",
               "dex_dir", "dex_zip", "apk", "tools", "command_timeout", "target_confirmed",
               "execute_device", "so_dump_config"}
    unknown = sorted(set(answer) - allowed)
    if unknown:
        raise ValueError(f"answer contains immutable or unknown fields: {unknown}")
    for key, value in answer.items():
        if key in {"commands", "ida", "simulation", "artifacts", "tools"} and isinstance(value, dict):
            context.case.setdefault(key, {}).update(value)
        else:
            context.case[key] = value
    context.case["config_revision"] = context.revision + 1
    question["status"] = "answered"; question["answer"] = answer; question["answered_at"] = now()
    atomic_json(context.case_dir / "questions.json", questions)
    stage = question["stage"]
    invalidated = []
    for affected in [stage, *DOWNSTREAM.get(stage, [])]:
        previous = context.case.get("stage_records", {}).pop(affected, None)
        if previous:
            context.case.setdefault("stage_history", {}).setdefault(affected, []).append({
                **previous, "invalidated_at": now(), "invalidated_by": question_id,
            })
            invalidated.append(affected)
    context.case["open_questions"] = [item["id"] for item in questions if item.get("status") == "open"]
    context.case["state"] = "INIT"
    for completed_stage in STAGES:
        if context.case.get("stage_records", {}).get(completed_stage, {}).get("status") != "completed":
            break
        context.case["state"] = STAGE_SUCCESS[completed_stage]
    context.save_case()
    atomic_json(context.case_dir / "checkpoint.json", {
        "case_id": context.case["case_id"], "stage": stage,
        "state": context.case["state"], "config_revision": context.revision,
        "invalidated_stages": invalidated, "updated_at": now(),
    })
    append_event(context.case_dir, {"type": "config-updated", "question_id": question_id,
                                    "stage": stage, "config_revision": context.revision,
                                    "invalidated_stages": invalidated})
    return context.case


def workflow_plan(context: Context) -> dict:
    workflow, profile, workflow_hash = load_workflow(context.repo_root, context.case.get("profile", "android-arm64-360-dexvmp"))
    return {"workflow": workflow.get("id"), "profile": context.case.get("profile"),
            "workflow_hash": workflow_hash,
            "stages": [PLUGINS[stage].plan(context) for stage in workflow.get("stages", STAGES)],
            "fixture": bool(profile.get("fixture"))}


def validate_case(context: Context) -> dict:
    configured = context.case.get("artifacts", {}).get("validation_report")
    report = Path(configured) if configured else context.case_dir / "reports/validation.json"
    if report.is_file():
        return json.loads(report.read_text(encoding="utf-8"))
    result = PLUGINS["independent-validate"].run(context)
    return result["report"]
