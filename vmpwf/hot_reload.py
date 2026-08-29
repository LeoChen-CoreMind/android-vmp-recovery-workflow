from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def load_workflow(repo_root: Path, profile_name: str) -> tuple[dict, dict, str]:
    workflow = load_json(repo_root / "workflow" / "workflow.json", {})
    profile = load_json(repo_root / "workflow" / "profiles" / f"{profile_name}.json", {})
    payload = json.dumps({"workflow": workflow, "profile": profile}, sort_keys=True).encode()
    return workflow, profile, hashlib.sha256(payload).hexdigest()


def load_stage(repo_root: Path, stage: str) -> dict:
    return load_json(repo_root / "workflow" / "stages" / f"{stage}.json", {})
