#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        raise ValueError("ELF magic missing")
    elf_class, endian = data[4], data[5]
    if endian != 1 or elf_class not in (1, 2):
        raise ValueError("only little-endian ELF32/ELF64 is supported")
    if elf_class == 2:
        machine, phoff, phentsize, phnum = struct.unpack_from("<H", data, 18)[0], struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<H", data, 54)[0], struct.unpack_from("<H", data, 56)[0]
    else:
        machine, phoff, phentsize, phnum = struct.unpack_from("<H", data, 18)[0], struct.unpack_from("<I", data, 28)[0], struct.unpack_from("<H", data, 42)[0], struct.unpack_from("<H", data, 44)[0]
    if phoff + phentsize * phnum > len(data):
        raise ValueError("program headers out of range")
    types = [struct.unpack_from("<I", data, phoff + index * phentsize)[0] for index in range(phnum)]
    return {"class": 64 if elf_class == 2 else 32, "machine": machine, "phnum": phnum,
            "pt_load": types.count(1), "pt_dynamic": types.count(2), "ok": types.count(1) > 0}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("elf", type=Path); args = parser.parse_args()
    result = inspect(args.elf); print(json.dumps(result, indent=2)); return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
