#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", type=Path); parser.add_argument("--fixture", type=Path, required=True); parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    result = {"status": "ok", "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest() if args.binary and args.binary.is_file() else None,
              "entries": fixture.get("entries", []), "width_candidates": fixture.get("width_candidates", {}),
              "evidence": fixture.get("evidence", [{"source": str(args.fixture.resolve()), "kind": "fixture"}]),
              "tool": "fixture", "tool_version": "1"}
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8"); print(json.dumps(result)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
