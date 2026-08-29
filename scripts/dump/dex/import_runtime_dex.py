#!/usr/bin/env python3
"""Import user-supplied DEX files while recording provenance."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import zipfile
import zlib
from pathlib import Path


def valid_dex(data: bytes) -> bool:
    if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
        return False
    u32 = lambda off: struct.unpack_from("<I", data, off)[0]
    if u32(0x20) != len(data) or u32(0x24) != 0x70 or u32(0x28) != 0x12345678:
        return False
    if data[12:32] != hashlib.sha1(data[32:]).digest() or u32(8) != zlib.adler32(data[12:]) & 0xFFFFFFFF:
        return False
    map_off = u32(0x34)
    return map_off + 4 <= len(data) and map_off + 4 + u32(map_off) * 12 <= len(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--dex-dir", type=Path)
    source.add_argument("--dex-zip", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    items = []
    if args.dex_zip:
        with zipfile.ZipFile(args.dex_zip) as archive:
            candidates = [(name, archive.read(name)) for name in archive.namelist() if name.lower().endswith(".dex")]
    else:
        candidates = [(str(path), path.read_bytes()) for path in sorted(args.dex_dir.glob("*.dex"))]
    for index, (name, data) in enumerate(candidates, 1):
        if not valid_dex(data):
            raise SystemExit(f"invalid DEX: {name}")
        target = args.output / ("classes.dex" if index == 1 else f"classes{index}.dex")
        target.write_bytes(data)
        items.append({"source": name, "path": str(target.resolve()), "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "valid_dex": True})
    if not items:
        raise SystemExit("no DEX files found")
    manifest = {"source_type": "user-supplied", "outputs": items}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
