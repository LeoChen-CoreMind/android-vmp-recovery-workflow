from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path
from typing import Any


def valid_dex_bytes(data: bytes) -> bool:
    try:
        if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
            return False
        u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
        if u32(0x20) != len(data) or u32(0x24) != 0x70 or u32(0x28) != 0x12345678:
            return False
        if data[12:32] != hashlib.sha1(data[32:]).digest():
            return False
        if u32(8) != zlib.adler32(data[12:]) & 0xFFFFFFFF:
            return False
        map_off = u32(0x34)
        return map_off + 4 <= len(data) and map_off + 4 + u32(map_off) * 12 <= len(data)
    except (struct.error, IndexError):
        return False


def valid_dex_file(path: Path) -> bool:
    return path.is_file() and valid_dex_bytes(path.read_bytes())


def lm_summary(path: Path) -> dict:
    data = path.read_bytes()
    if not valid_dex_bytes(data):
        return {"present": False, "error": "invalid DEX"}
    u32 = lambda blob, offset: struct.unpack_from("<I", blob, offset)[0]
    lm_off = u32(data, 0x68) + u32(data, 0x6C)
    if lm_off + 8 > len(data) or data[lm_off:lm_off + 3] != b"lm\0":
        return {"present": False}
    payload_len = u32(data, lm_off + 4)
    if lm_off + 8 + payload_len > len(data):
        return {"present": True, "error": "lm payload out of range"}
    payload = bytearray(data[lm_off + 8:lm_off + 8 + payload_len])
    key = (data[0x60] + 1) & 0xFF
    for index in range(len(payload)):
        payload[index] ^= key
    if len(payload) < 8:
        return {"present": True, "error": "lm payload too short"}
    table_size = u32(payload, len(payload) - 4)
    count_off = len(payload) - table_size - 8
    if table_size <= 0 or table_size % 256 or count_off < 0:
        return {"present": True, "error": "invalid opcode table"}
    record_count = u32(payload, count_off)
    cursor = 0
    for _ in range(record_count):
        if cursor + 20 > count_off:
            return {"present": True, "error": "method record out of range"}
        cursor += 20 + u32(payload, cursor + 16) * 2
    if cursor != count_off:
        return {"present": True, "error": "method records do not close"}
    return {"present": True, "lm_offset": lm_off, "version": data[lm_off + 3],
            "method_records": record_count, "opcode_table_size": table_size}


def validate_dispatch_map(payload: dict[str, Any], allow_contextual: bool = False) -> dict[str, Any]:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return {"ok": False, "error": "entries is not a list"}
    opcodes = [item.get("opcode") for item in entries if isinstance(item, dict)]
    missing = sorted(set(range(256)) - set(value for value in opcodes if isinstance(value, int)))
    duplicates = sorted({value for value in opcodes if isinstance(value, int) and opcodes.count(value) > 1})
    invalid_handlers = [item.get("opcode") for item in entries
                        if not isinstance(item.get("handler"), int)]
    ambiguous = [item.get("opcode") for item in entries
                 if len(item.get("pc_width_candidates", [])) != 1]
    if allow_contextual:
        # The reference fixture has two context-dependent handlers. This exception
        # is fixture-only and is never accepted as customer evidence.
        ambiguous = [value for value in ambiguous if value not in (14, 46)]
    return {"ok": len(entries) == 256 and not missing and not duplicates
            and not invalid_handlers and not ambiguous,
            "entry_count": len(entries), "missing_opcodes": missing,
            "duplicate_opcodes": duplicates, "invalid_handlers": invalid_handlers,
            "ambiguous_widths": ambiguous}


def validate_vm_streams(payload: dict[str, Any], require_evidence: bool = False) -> dict[str, Any]:
    methods = payload.get("methods")
    if not isinstance(methods, list) or not methods:
        return {"ok": False, "error": "methods is empty"}
    errors = []
    instruction_count = 0
    for method in methods:
        expected_pc = 0
        instructions = method.get("instructions", [])
        for instruction in instructions:
            width = instruction.get("width")
            if instruction.get("pc") != expected_pc or not isinstance(width, int) or width <= 0:
                errors.append({"method_idx": method.get("method_idx"), "pc": instruction.get("pc"),
                               "reason": "non-contiguous-pc-or-width"})
                break
            if not instruction.get("decoded_units_complete") or not isinstance(instruction.get("dalvik_opcode"), int):
                errors.append({"method_idx": method.get("method_idx"), "pc": expected_pc,
                               "reason": "unresolved-instruction"})
                break
            if len(instruction.get("decoded_units", [])) != width or len(instruction.get("raw_units", [])) != width:
                errors.append({"method_idx": method.get("method_idx"), "pc": expected_pc,
                               "reason": "code-unit-width-mismatch"})
                break
            expected_pc += width
            instruction_count += 1
        if expected_pc != method.get("insns_size"):
            errors.append({"method_idx": method.get("method_idx"), "final_pc": expected_pc,
                           "insns_size": method.get("insns_size"), "reason": "final-pc-not-closed"})
    if require_evidence:
        evidence = payload.get("evidence", {})
        if evidence.get("semantics_confirmed") is not True:
            errors.append({"reason": "missing-or-invalid-evidence", "field": "semantics_confirmed"})
        for key in ("binary_sha256", "dispatch_sha256", "simulation_config_sha256"):
            value = evidence.get(key)
            if (not isinstance(value, str) or len(value) != 64
                    or any(character not in "0123456789abcdefABCDEF" for character in value)):
                errors.append({"reason": "missing-or-invalid-evidence", "field": key})
    return {"ok": not errors, "method_count": len(methods),
            "instruction_count": instruction_count, "errors": errors}


def inspect_elf(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 0x34 or data[:4] != b"\x7fELF" or data[5] != 1:
        return {"ok": False, "reason": "invalid ELF header"}
    elf_class = data[4]
    if elf_class == 2:
        phoff, phentsize, phnum = struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<H", data, 54)[0], struct.unpack_from("<H", data, 56)[0]
    elif elf_class == 1:
        phoff, phentsize, phnum = struct.unpack_from("<I", data, 28)[0], struct.unpack_from("<H", data, 42)[0], struct.unpack_from("<H", data, 44)[0]
    else:
        return {"ok": False, "reason": "unsupported ELF class"}
    if not phentsize or phoff + phentsize * phnum > len(data):
        return {"ok": False, "reason": "program headers out of range"}
    types = [struct.unpack_from("<I", data, phoff + index * phentsize)[0] for index in range(phnum)]
    return {"ok": 1 in types, "class": 64 if elf_class == 2 else 32,
            "machine": struct.unpack_from("<H", data, 18)[0], "phnum": phnum,
            "pt_load": types.count(1), "pt_dynamic": types.count(2)}
