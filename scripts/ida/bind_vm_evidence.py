#!/usr/bin/env python3
"""Bind VM streams to the exact binary, dispatch table, and simulator config."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Attach case-specific provenance to enriched VM streams")
    parser.add_argument("--streams", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--dispatch", type=Path, required=True)
    parser.add_argument("--sim-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--semantics-confirmed", action="store_true", required=True)
    args = parser.parse_args()

    payload = json.loads(args.streams.read_text(encoding="utf-8"))
    payload["evidence"] = {
        "semantics_confirmed": True,
        "binary_sha256": sha256_file(args.binary),
        "dispatch_sha256": sha256_file(args.dispatch),
        "simulation_config_sha256": sha256_file(args.sim_config),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), **payload["evidence"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
