#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


FLAG_NAMES = {"MULTILINE": re.MULTILINE, "DOTALL": re.DOTALL}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_glob(root: Path, pattern: str) -> list[Path]:
    candidate = Path(pattern)
    if candidate.is_absolute() or ".." in candidate.parts or "\\" in pattern:
        raise ValueError(f"unsafe smali file glob: {pattern}")
    return sorted(path for path in root.glob(pattern) if path.is_file())


def apply_patches(root: Path, patches: list[dict[str, Any]], dry_run: bool = False) -> dict[str, Any]:
    root = root.resolve()
    texts: dict[Path, str] = {}
    original: dict[Path, bytes] = {}
    records = []

    for patch in patches:
        flags = 0
        for name in patch.get("flags", []):
            if name not in FLAG_NAMES:
                raise ValueError(f"unknown regex flag in {patch['id']}: {name}")
            flags |= FLAG_NAMES[name]
        expression = re.compile(patch["pattern"], flags)
        paths = []
        for pattern in patch["files"]:
            paths.extend(normalized_glob(root, pattern))
        paths = sorted(set(paths))
        if not paths:
            raise ValueError(f"smali patch {patch['id']} matched no files")

        matches = 0
        per_file = []
        replacements: dict[Path, str] = {}
        for path in paths:
            if path not in texts:
                data = path.read_bytes()
                original[path] = data
                texts[path] = data.decode("utf-8")
            replaced, count = expression.subn(patch["replacement"], texts[path])
            if count:
                replacements[path] = replaced
                per_file.append({"path": str(path), "matches": count})
                matches += count
        if matches != patch["expected_matches"]:
            raise ValueError(
                f"smali patch {patch['id']} expected {patch['expected_matches']} matches, found {matches}"
            )
        texts.update(replacements)
        records.append({
            "id": patch["id"], "expected_matches": patch["expected_matches"],
            "actual_matches": matches, "files": per_file,
        })

    changed = []
    for path, text in texts.items():
        before = original[path]
        after = text.encode("utf-8")
        if before == after:
            continue
        changed.append({
            "path": str(path), "before_sha256": sha256_bytes(before),
            "after_sha256": sha256_bytes(after), "size_before": len(before), "size_after": len(after),
        })
    if not dry_run:
        for item in changed:
            Path(item["path"]).write_bytes(texts[Path(item["path"])].encode("utf-8"))
    return {"status": "ok", "dry_run": dry_run, "patches": records, "changed_files": changed}


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply evidence-bound regex patches to a smali tree")
    parser.add_argument("--smali-root", required=True, type=Path)
    parser.add_argument("--adapter", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    adapter = json.loads(args.adapter.read_text(encoding="utf-8"))
    patches = adapter.get("bridge_contracts", {}).get("smali_patches", [])
    if not patches:
        raise ValueError("adapter contains no bridge_contracts.smali_patches")
    result = apply_patches(args.smali_root, patches, args.dry_run)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
