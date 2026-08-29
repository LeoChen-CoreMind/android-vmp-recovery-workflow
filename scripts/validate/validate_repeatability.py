#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vmpwf.provenance import sha256_file


DETERMINISTIC_PREFIXES = ("input/apk/", "input/dex/", "fix/dex/")
RUNTIME_EVIDENCE_PREFIXES = ("dump/so/", "fix/so/", "ida/tables/", "simulation/results/")


def snapshot(root: Path, prefixes: tuple[str, ...] = DETERMINISTIC_PREFIXES) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(root)).replace("\\", "/")
        if relative.startswith(prefixes):
            result[relative] = sha256_file(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--include-runtime-evidence", action="store_true",
                        help="also require ASLR-sensitive SO/IDA/simulation intermediates to match")
    args = parser.parse_args()
    prefixes = (DETERMINISTIC_PREFIXES + RUNTIME_EVIDENCE_PREFIXES
                if args.include_runtime_evidence else DETERMINISTIC_PREFIXES)
    left, right = snapshot(args.first, prefixes), snapshot(args.second, prefixes)
    runtime_left = snapshot(args.first, RUNTIME_EVIDENCE_PREFIXES)
    runtime_right = snapshot(args.second, RUNTIME_EVIDENCE_PREFIXES)
    result = {"ok": left == right, "only_first": sorted(set(left) - set(right)),
              "only_second": sorted(set(right) - set(left)),
              "changed": sorted(key for key in set(left) & set(right) if left[key] != right[key]),
              "scope": "all-evidence" if args.include_runtime_evidence else "inputs-and-restored-dex",
              "runtime_evidence_changed": sorted(
                  key for key in set(runtime_left) & set(runtime_right)
                  if runtime_left[key] != runtime_right[key]),
              "note": "Runtime SO, IDA, and simulation evidence can contain ASLR-bound hashes; changes are reported but are not restoration failures by default."}
    print(json.dumps(result, indent=2)); return 0 if result["ok"] else 2


if __name__ == "__main__": raise SystemExit(main())
