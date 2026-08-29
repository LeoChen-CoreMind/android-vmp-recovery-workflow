#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vmpwf.provenance import file_record
from vmpwf.validation import lm_summary, valid_dex_file


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("dex", type=Path, nargs="+"); args = parser.parse_args()
    results = [{**file_record(path), "valid": valid_dex_file(path), "lm": lm_summary(path)} for path in args.dex]
    print(json.dumps(results, ensure_ascii=False, indent=2)); return 0 if all(item["valid"] for item in results) else 2


if __name__ == "__main__": raise SystemExit(main())
