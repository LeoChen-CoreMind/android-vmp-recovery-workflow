#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vmpwf.provenance import sha256_file


def snapshot(root: Path) -> dict[str, str]:
    prefixes = ("input/apk/", "input/dex/", "dump/so/", "fix/", "ida/tables/", "simulation/results/")
    result = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(root)).replace("\\", "/")
        if relative.startswith(prefixes):
            result[relative] = sha256_file(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("first", type=Path); parser.add_argument("second", type=Path); args = parser.parse_args()
    left, right = snapshot(args.first), snapshot(args.second)
    result = {"ok": left == right, "only_first": sorted(set(left) - set(right)),
              "only_second": sorted(set(right) - set(left)),
              "changed": sorted(key for key in set(left) & set(right) if left[key] != right[key])}
    print(json.dumps(result, indent=2)); return 0 if result["ok"] else 2


if __name__ == "__main__": raise SystemExit(main())
