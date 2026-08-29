#!/usr/bin/env python3
"""Wrap a case-specific IDA dispatch export in the workflow response contract."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--dispatch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, action="append", default=[])
    parser.add_argument("--tool-version", default="ida-pro-mcp")
    args = parser.parse_args()

    dispatch = json.loads(args.dispatch.read_text(encoding="utf-8"))
    entries = dispatch.get("entries")
    if not isinstance(entries, list) or len(entries) != 256:
        raise ValueError("dispatch export must contain exactly 256 entries")
    evidence = [{"kind": "ida-dispatch-export", "path": str(args.dispatch.resolve())}]
    for path in args.evidence:
        if not path.is_file():
            raise FileNotFoundError(path)
        evidence.append({
            "kind": "ida-analysis-evidence",
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    payload = {
        "status": "ok",
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "entries": entries,
        "width_candidates": {
            str(item["opcode"]): item.get("pc_width_candidates", []) for item in entries
        },
        "evidence": evidence,
        "tool": "ida-mcp",
        "tool_version": args.tool_version,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "output": str(args.output), "entries": len(entries)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
