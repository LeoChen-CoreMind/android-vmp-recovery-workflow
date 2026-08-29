from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


def _version_key(path: Path) -> tuple[int, ...]:
    values = tuple(int(value) for value in re.findall(r"\d+", path.parent.name))
    return values or (0,)


def android_sdk_roots() -> list[Path]:
    candidates = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        str(Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Android/Sdk"),
    ]
    roots: list[Path] = []
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.is_dir() and path not in roots:
            roots.append(path)
    return roots


def find_android_build_tool(name: str) -> str | None:
    executable = f"{name}.exe" if os.name == "nt" else name
    matches: list[Path] = []
    for sdk_root in android_sdk_roots():
        matches.extend(path for path in (sdk_root / "build-tools").glob(f"*/{executable}") if path.is_file())
    if not matches:
        return None
    return str(max(matches, key=_version_key).resolve())


def resolve_tool(name: str, configured: str | None = None) -> str | None:
    if configured:
        configured_path = Path(configured).expanduser()
        if configured_path.is_file():
            return str(configured_path.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
    resolved = shutil.which(name)
    if resolved:
        return resolved
    if name == "dexdump":
        return find_android_build_tool(name)
    return None
