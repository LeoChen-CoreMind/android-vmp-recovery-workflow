from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

STAGES = [
    "target-confirm",
    "so-dump",
    "so-repair",
    "ida-export",
    "vm-static",
    "native-sim",
    "dex-restore",
    "independent-validate",
]
STAGE_STATES = [
    "INIT", "TARGET_CONFIRMED", "SO_DUMPED", "SO_REPAIRED",
    "IDA_EXTRACTED", "SIMULATION_CONFIRMED", "DEX_RESTORED", "VALIDATED",
    "BLOCKED",
]
STAGE_SUCCESS = {
    "target-confirm": "TARGET_CONFIRMED", "so-dump": "SO_DUMPED",
    "so-repair": "SO_REPAIRED", "ida-export": "IDA_EXTRACTED",
    "vm-static": "IDA_EXTRACTED", "native-sim": "SIMULATION_CONFIRMED",
    "dex-restore": "DEX_RESTORED", "independent-validate": "VALIDATED",
}
DOWNSTREAM = {stage: STAGES[index + 1:] for index, stage in enumerate(STAGES)}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, root: Path | None = None) -> dict[str, Any]:
    path = path.resolve()
    record: dict[str, Any] = {
        "path": str(path), "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if root is not None:
        try:
            record["relative"] = str(path.relative_to(root.resolve()))
        except ValueError:
            record["relative"] = None
    return record


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def append_event(case_dir: Path, event: dict[str, Any]) -> None:
    event = {"timestamp": now(), **event}
    with (case_dir / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")


class StagePlugin(Protocol):
    id: str
    version: str

    def plan(self, context: "Context") -> dict[str, Any]: ...
    def run(self, context: "Context") -> dict[str, Any]: ...
    def validate(self, context: "Context", result: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class Context:
    case_dir: Path
    case: dict[str, Any]
    execute_device: bool = False

    @property
    def artifacts_dir(self) -> Path:
        value = self.case.get("artifacts_dir", "artifacts")
        path = self.case_dir / value
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_case(self) -> None:
        atomic_json(self.case_dir / "case.json", self.case)

    def question(self, stage: str, message: str, evidence: list[str] | None = None,
                 fields: list[str] | None = None, severity: str = "error") -> dict[str, Any]:
        questions = read_json(self.case_dir / "questions.json", []) or []
        question = {
            "id": f"q-{len(questions) + 1:04d}", "stage": stage,
            "severity": severity, "message": message,
            "evidence": evidence or [], "expected": {"type": "object", "fields": fields or []},
            "status": "open", "created_at": now(),
        }
        questions.append(question)
        atomic_json(self.case_dir / "questions.json", questions)
        self.case["state"] = "BLOCKED"
        self.case.setdefault("open_questions", []).append(question["id"])
        self.save_case()
        atomic_json(self.case_dir / "checkpoint.json", {
            "case_id": self.case.get("case_id"), "stage": stage,
            "state": "BLOCKED", "config_revision": self.case.get("config_revision", 1),
            "question_id": question["id"], "updated_at": now(),
        })
        append_event(self.case_dir, {"type": "question", "question": question})
        return question


class StageBlocked(RuntimeError):
    def __init__(self, question: dict[str, Any]):
        super().__init__(question["message"])
        self.question = question


def run_command(command: list[str], cwd: Path | None = None, timeout: int = 120,
                env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, cwd=str(cwd) if cwd else None,
                                   capture_output=True, text=True, timeout=timeout,
                                   env=env)
        return {"command": command, "returncode": completed.returncode,
                "stdout": completed.stdout[-20000:], "stderr": completed.stderr[-20000:]}
    except FileNotFoundError as exc:
        return {"command": command, "returncode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "returncode": 124,
                "stdout": (exc.stdout or "")[-20000:], "stderr": "timeout"}


def validate_files(source: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    records = []
    missing = []
    for key in keys:
        value = source.get(key)
        if not value:
            continue
        paths = value if isinstance(value, list) else [value]
        for item in paths:
            path = Path(item)
            if path.exists() and path.is_file():
                records.append(file_record(path))
            else:
                missing.append(str(path))
    return {"ok": not missing, "artifacts": records, "missing": missing}


def install_skill() -> Path:
    source = Path(__file__).resolve().parent.parent / "skill"
    codex_home = os.environ.get("CODEX_HOME")
    destination = Path(codex_home) if codex_home else Path.home() / ".codex"
    destination = destination / "skills" / "android-vmp-recovery-workflow"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    return destination
