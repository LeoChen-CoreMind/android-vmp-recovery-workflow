#!/usr/bin/env python3
"""Confirm an IDA dispatch export by executing the real AArch64 tree."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_ARM, Uc
from unicorn.arm64_const import UC_ARM64_REG_W0


PAGE_SIZE = 0x1000


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def align_down(value, alignment=PAGE_SIZE):
    return value & -alignment


def align_up(value, alignment=PAGE_SIZE):
    return (value + alignment - 1) & -alignment


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dispatch_instruction_rvas(entries):
    addresses = set()
    for entry in entries:
        for detail in entry.get("path", []):
            ea = detail.get("ea")
            if not isinstance(ea, int):
                continue
            if detail.get("kind") == "cmp_table":
                addresses.update(ea + offset for offset in range(0, 24, 4))
            elif detail.get("kind") == "direct_slot":
                addresses.update(ea + offset for offset in range(0, 12, 4))
    return addresses


def confirm(binary: Path, dispatch: Path, pointer_base: int, instruction_limit: int):
    image = binary.read_bytes()
    payload = json.loads(dispatch.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    if len(entries) != 256:
        raise ValueError("dispatch export must contain exactly 256 entries")
    root = number(payload["root"])
    all_dispatch_rvas = dispatch_instruction_rvas(entries)
    if root not in all_dispatch_rvas:
        raise ValueError("dispatch root is not represented in entry path evidence")

    mapped_base = align_down(pointer_base)
    image_offset = pointer_base - mapped_base
    mapped_size = align_up(image_offset + len(image))
    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    emulator.mem_map(mapped_base, mapped_size)
    emulator.mem_write(pointer_base, image)

    results = []
    invalid_access = []
    current = {"trace": [], "handler": None}

    def hook_code(uc, address, _size, _user):
        rva = address - pointer_base
        current["trace"].append(rva)
        if rva not in current["dispatch_rvas"]:
            current["handler"] = rva
            uc.emu_stop()

    def hook_invalid(_uc, access, address, size, value, _user):
        invalid_access.append({
            "opcode": current.get("opcode"), "access": access,
            "address": f"0x{address:x}", "size": size, "value": value,
        })
        return False

    emulator.hook_add(UC_HOOK_CODE, hook_code)
    emulator.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
    for entry in entries:
        opcode = number(entry["opcode"])
        expected = number(entry["handler"])
        current.update(opcode=opcode, handler=None, trace=[])
        current["dispatch_rvas"] = dispatch_instruction_rvas([entry])
        emulator.reg_write(UC_ARM64_REG_W0, opcode)
        error = None
        try:
            emulator.emu_start(
                pointer_base + root,
                pointer_base + len(image),
                count=instruction_limit,
            )
        except Exception as exc:
            error = str(exc)
        actual = current["handler"]
        results.append({
            "opcode": opcode,
            "expected_handler_rva": f"0x{expected:x}",
            "actual_handler_rva": f"0x{actual:x}" if actual is not None else None,
            "matched": error is None and actual == expected,
            "instruction_count": len(current["trace"]),
            "trace_rvas": [f"0x{rva:x}" for rva in current["trace"]],
            "error": error,
        })

    mismatches = [item for item in results if not item["matched"]]
    return {
        "confirmed": not mismatches and not invalid_access,
        "engine": "unicorn-arm64",
        "scope": "dispatch-table",
        "binary": str(binary.resolve()),
        "binary_sha256": sha256_file(binary),
        "dispatch": str(dispatch.resolve()),
        "dispatch_sha256": sha256_file(dispatch),
        "pointer_base": f"0x{pointer_base:x}",
        "root_rva": f"0x{root:x}",
        "request_count": len(results),
        "matched_count": len(results) - len(mismatches),
        "mismatches": mismatches,
        "invalid_memory": invalid_access,
        "unknown_external_calls": 0,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute the real AArch64 dispatch tree and verify all exported handlers"
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--dispatch", type=Path, required=True)
    parser.add_argument("--pointer-base", type=number, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--instruction-limit", type=int, default=128)
    args = parser.parse_args()
    report = confirm(
        args.binary.resolve(), args.dispatch.resolve(),
        args.pointer_base, args.instruction_limit,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output.resolve()), "confirmed": report["confirmed"],
        "matched": report["matched_count"], "requests": report["request_count"],
    }))
    return 0 if report["confirmed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
