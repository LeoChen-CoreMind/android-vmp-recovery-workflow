from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .hot_reload import load_workflow
from .models import CASE_DIRS
from .provenance import file_record, sha256_file


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    profile_snapshot: dict[str, Any] | None = field(default=None, repr=False)
    workflow_hash: str | None = field(default=None, repr=False)

    @property
    def repo_root(self) -> Path:
        return Path(__file__).resolve().parent.parent

    @property
    def revision(self) -> int:
        return int(self.case.get("config_revision", 1))

    @property
    def profile(self) -> dict[str, Any]:
        if self.profile_snapshot is not None:
            return self.profile_snapshot
        _, profile, _ = load_workflow(self.repo_root, self.case.get("profile", "android-arm64-360-dexvmp"))
        return profile

    def reload(self) -> None:
        current = read_json(self.case_dir / "case.json")
        if current:
            self.case = current

    def reload_boundary(self) -> tuple[dict[str, Any], dict[str, Any], str]:
        """Reload case/workflow configuration exactly once at a stage boundary."""
        self.reload()
        workflow, profile, workflow_hash = load_workflow(
            self.repo_root, self.case.get("profile", "android-arm64-360-dexvmp")
        )
        self.profile_snapshot = profile
        self.workflow_hash = workflow_hash
        return workflow, profile, workflow_hash

    @property
    def artifacts_dir(self) -> Path:
        path = self.case_dir
        path.mkdir(parents=True, exist_ok=True)
        return path

    def revision_dir(self, relative: str) -> Path:
        path = self.case_dir / relative / f"rev-{self.revision:04d}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_case(self) -> None:
        atomic_json(self.case_dir / "case.json", self.case)

    def question(self, stage: str, message: str, evidence: list[str] | None = None,
                 fields: list[str] | None = None, severity: str = "error") -> dict[str, Any]:
        questions = read_json(self.case_dir / "questions.json", []) or []
        existing = next((item for item in questions
                         if item.get("stage") == stage and item.get("message") == message
                         and item.get("status") == "open"), None)
        if existing:
            return existing
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
    actual = command
    if os.name == "nt" and command and Path(command[0]).suffix.lower() in {".cmd", ".bat"}:
        actual = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c",
                  subprocess.list2cmdline(command)]
    try:
        completed = subprocess.run(actual, cwd=str(cwd) if cwd else None,
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=timeout,
                                   env=env)
        return {"command": command, "returncode": completed.returncode,
                "stdout": completed.stdout[-20000:], "stderr": completed.stderr[-20000:]}
    except FileNotFoundError as exc:
        return {"command": command, "returncode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "returncode": 124,
                "stdout": (exc.stdout or "")[-20000:], "stderr": "timeout"}
    except OSError as exc:
        return {"command": command, "returncode": 126, "stdout": "", "stderr": str(exc)}


def run_logged_command(command: list[str], stdout_path: Path, stderr_path: Path,
                       cwd: Path | None = None, timeout: int = 120) -> dict[str, Any]:
    actual = command
    if os.name == "nt" and command and Path(command[0]).suffix.lower() in {".cmd", ".bat"}:
        actual = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c",
                  subprocess.list2cmdline(command)]
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    returncode = 126
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            completed = subprocess.run(actual, cwd=str(cwd) if cwd else None,
                                       stdout=stdout, stderr=stderr, timeout=timeout)
            returncode = completed.returncode
        except FileNotFoundError as exc:
            returncode = 127
            stderr.write(str(exc).encode("utf-8", errors="replace"))
        except subprocess.TimeoutExpired:
            returncode = 124
            stderr.write(b"timeout")
        except OSError as exc:
            stderr.write(str(exc).encode("utf-8", errors="replace"))
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    return {
        "command": command, "returncode": returncode,
        "stdout_log": str(stdout_path.resolve()), "stderr_log": str(stderr_path.resolve()),
        "stdout": stdout_text[-20000:], "stderr": stderr_text[-20000:],
    }


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


def create_case_layout(case_dir: Path) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    for relative in CASE_DIRS:
        (case_dir / relative).mkdir(parents=True, exist_ok=True)
