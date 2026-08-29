from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest


def minimal_dex() -> bytes:
    data = bytearray(0x74)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<I", data, 0x20, len(data))
    struct.pack_into("<I", data, 0x24, 0x70)
    struct.pack_into("<I", data, 0x28, 0x12345678)
    struct.pack_into("<I", data, 0x34, 0x70)
    struct.pack_into("<I", data, 0x70, 0)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def minimal_elf32() -> bytes:
    data = bytearray(0x100)
    data[:16] = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 3, 40, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    struct.pack_into("<IIIIIIII", data, 52, 1, 0, 0, 0, len(data), len(data), 5, 0x1000)
    return bytes(data)


@pytest.fixture
def sample_inputs(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.fixture"/>')
        archive.writestr("classes.dex", minimal_dex())
        archive.writestr("assets/libjiagu.so", minimal_elf32())
    dex_zip = tmp_path / "runtime.zip"
    with zipfile.ZipFile(dex_zip, "w") as archive:
        archive.writestr("com.example.fixture/classes1_decrypted.dex", minimal_dex())
        archive.writestr("com.example.fixture/classes2_decrypted.dex", minimal_dex())
    return apk, dex_zip
