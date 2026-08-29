#!/usr/bin/env python3
"""Inspect an APK without Android SDK dependencies."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _length8(data: bytes, offset: int) -> tuple[int, int]:
    value = data[offset]
    if value & 0x80:
        return ((value & 0x7F) << 8) | data[offset + 1], offset + 2
    return value, offset + 1


def _length16(data: bytes, offset: int) -> tuple[int, int]:
    value = _u16(data, offset)
    if value & 0x8000:
        return ((value & 0x7FFF) << 16) | _u16(data, offset + 2), offset + 4
    return value, offset + 2


def axml_strings(data: bytes) -> list[str]:
    cursor = _u16(data, 2)
    while cursor + 8 <= len(data):
        chunk_type, header_size, chunk_size = _u16(data, cursor), _u16(data, cursor + 2), _u32(data, cursor + 4)
        if chunk_size < header_size or cursor + chunk_size > len(data):
            break
        if chunk_type == 0x0001:
            count = _u32(data, cursor + 8)
            flags = _u32(data, cursor + 16)
            strings_start = _u32(data, cursor + 20)
            offsets = [_u32(data, cursor + header_size + i * 4) for i in range(count)]
            result = []
            for relative in offsets:
                pos = cursor + strings_start + relative
                if flags & 0x100:
                    _, pos = _length8(data, pos)
                    byte_len, pos = _length8(data, pos)
                    result.append(data[pos:pos + byte_len].decode("utf-8", "replace"))
                else:
                    char_len, pos = _length16(data, pos)
                    result.append(data[pos:pos + char_len * 2].decode("utf-16le", "replace"))
            return result
        cursor += chunk_size
    return []


def manifest_package(data: bytes) -> str | None:
    if data.lstrip().startswith(b"<"):
        try:
            return ET.fromstring(data).attrib.get("package")
        except ET.ParseError:
            return None
    strings = axml_strings(data)
    if not strings:
        return None
    cursor = _u16(data, 2)
    while cursor + 36 <= len(data):
        chunk_type, header_size, chunk_size = _u16(data, cursor), _u16(data, cursor + 2), _u32(data, cursor + 4)
        if chunk_size < header_size or cursor + chunk_size > len(data):
            break
        if chunk_type == 0x0102:
            name_idx = _u32(data, cursor + 20)
            attr_start, attr_size, attr_count = _u16(data, cursor + 24), _u16(data, cursor + 26), _u16(data, cursor + 28)
            if name_idx < len(strings) and strings[name_idx] == "manifest":
                base = cursor + 16 + attr_start
                for index in range(attr_count):
                    attr = base + index * attr_size
                    attr_name, raw_idx = _u32(data, attr + 4), _u32(data, attr + 8)
                    if attr_name < len(strings) and strings[attr_name] == "package":
                        value_idx = raw_idx if raw_idx != 0xFFFFFFFF else _u32(data, attr + 16)
                        return strings[value_idx] if value_idx < len(strings) else None
        cursor += chunk_size
    return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect(apk: Path) -> dict:
    with zipfile.ZipFile(apk) as archive:
        manifest = archive.read("AndroidManifest.xml")
        entries = []
        root_dex = []
        shared_objects = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.filename.endswith(".dex") or info.filename.endswith(".so") or info.filename.startswith("assets/"):
                data = archive.read(info)
                item = {"name": info.filename, "size": len(data), "sha256": sha256_bytes(data)}
                entries.append(item)
                if "/" not in info.filename and info.filename.startswith("classes") and info.filename.endswith(".dex"):
                    root_dex.append(item)
                if info.filename.endswith(".so"):
                    shared_objects.append(item)
    return {
        "package": manifest_package(manifest),
        "apk": {"path": str(apk.resolve()), "size": apk.stat().st_size,
                "sha256": sha256_bytes(apk.read_bytes())},
        "root_dex": root_dex,
        "shared_objects": shared_objects,
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = inspect(args.apk.resolve())
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
