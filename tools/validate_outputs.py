#!/usr/bin/env python3
"""Minimal independent validation hook; replace/extend with dexdump and JADX."""
import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, default=Path.cwd())
    args = parser.parse_args()
    case = json.loads((args.case / "case.json").read_text(encoding="utf-8"))
    outputs = []
    for key, value in case.get("artifacts", {}).items():
        for item in (value if isinstance(value, list) else [value]):
            path = Path(item)
            if path.is_file():
                outputs.append({"key": key, "path": str(path), "sha256": sha256(path), "size": path.stat().st_size})
    (args.case / "validated-artifacts.json").write_text(json.dumps(outputs, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "files": len(outputs)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
