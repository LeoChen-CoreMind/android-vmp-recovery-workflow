from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, root: Path | None = None, **extra: Any) -> dict[str, Any]:
    resolved = path.resolve()
    result: dict[str, Any] = {
        "path": str(resolved), "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved), **extra,
    }
    if root:
        try:
            result["relative"] = str(resolved.relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            result["relative"] = None
    return result
