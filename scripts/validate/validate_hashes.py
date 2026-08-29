#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vmpwf.provenance import sha256_file


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("manifest", type=Path); parser.add_argument("--root", type=Path, default=Path.cwd()); args = parser.parse_args()
    expected = json.loads(args.manifest.read_text(encoding="utf-8")); failures = []
    for item in expected.get("files", []):
        path = args.root / item["path"]
        if not path.is_file() or sha256_file(path) != item["sha256"]: failures.append(str(path))
    print(json.dumps({"ok": not failures, "failures": failures}, indent=2)); return 0 if not failures else 2


if __name__ == "__main__": raise SystemExit(main())
