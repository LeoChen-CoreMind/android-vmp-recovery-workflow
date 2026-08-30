#!/usr/bin/env python3
"""Confirm Frida fetch-decoder samples with the exact fixed AArch64 image."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X26,
)


PAGE_SIZE = 0x1000
IMAGE_BASE = 0x20000000
OBJECT_BASE = 0x30000000
STREAM_BASE = 0x30010000
TLS_BASE = 0x30030000
STACK_BASE = 0x40000000
STACK_SIZE = 0x20000
STOP_BASE = 0x50000000
def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & -alignment


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def value_from_safe_read(value):
    if isinstance(value, dict):
        if value.get("ok") is not True:
            raise ValueError(f"sample read failed: {value}")
        value = value.get("value")
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def normalize_samples(payload) -> list[dict]:
    events = payload.get("events", []) if isinstance(payload, dict) else payload
    if not isinstance(events, list):
        raise ValueError("sample input must be a JSON list or an object with events")
    samples = []
    for event in events:
        if not isinstance(event, dict) or event.get("event") != "vm-target-decoder-sample":
            continue
        samples.append({
            "method_idx": int(event["methodIndex"]),
            "key": value_from_safe_read(event["key"]) & 0xFF,
            "unit_index": int(event["unitIndex"]),
            "raw_unit": value_from_safe_read(event["rawUnit"]) & 0xFFFF,
            "fvp": int(event["fvp"]),
            "expected_decoded_unit": int(event["decodedUnit"]) & 0xFFFF,
            "sequence": event.get("sequence"),
            "stream_offset_units": event.get("streamOffsetUnits"),
        })
    if not samples:
        raise ValueError("no vm-target-decoder-sample events found")
    return samples


def execute_sample(image: bytes, sample: dict, decoder_start_rva: int, instruction_limit: int):
    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    emulator.mem_map(IMAGE_BASE, align_up(len(image)))
    emulator.mem_write(IMAGE_BASE, image)
    emulator.mem_map(OBJECT_BASE, PAGE_SIZE)
    stream_size = align_up(max(PAGE_SIZE, (sample["unit_index"] + 1) * 2))
    emulator.mem_map(STREAM_BASE, stream_size)
    emulator.mem_map(TLS_BASE, PAGE_SIZE)
    emulator.mem_map(STACK_BASE, STACK_SIZE)
    emulator.mem_map(STOP_BASE, PAGE_SIZE)

    emulator.mem_write(OBJECT_BASE, struct.pack("<Q", STREAM_BASE))
    emulator.mem_write(OBJECT_BASE + 8, bytes([sample["key"]]))
    emulator.mem_write(OBJECT_BASE + 0x18, struct.pack("<I", sample["method_idx"]))
    emulator.mem_write(
        STREAM_BASE + sample["unit_index"] * 2,
        struct.pack("<H", sample["raw_unit"]),
    )
    cookie = 0x1122334455667788
    emulator.mem_write(TLS_BASE + 0x28, struct.pack("<Q", cookie))
    stack = STACK_BASE + STACK_SIZE // 2
    emulator.mem_write(stack + 0x48, struct.pack("<Q", cookie))
    emulator.mem_write(stack + 0x90, struct.pack("<QQ", OBJECT_BASE, STOP_BASE))

    invalid_memory = []
    trace = []

    def hook_code(uc, address, _size, _user):
        if address == STOP_BASE:
            uc.emu_stop()
            return
        trace.append(address - IMAGE_BASE)

    def hook_invalid(_uc, access, address, size, value, _user):
        invalid_memory.append({
            "access": access,
            "address": f"0x{address:x}",
            "size": size,
            "value": value,
        })
        return False

    emulator.hook_add(UC_HOOK_CODE, hook_code)
    emulator.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
    emulator.reg_write(UC_ARM64_REG_SP, stack)
    emulator.reg_write(UC_ARM64_REG_LR, STOP_BASE)
    emulator.reg_write(UC_ARM64_REG_X19, OBJECT_BASE)
    emulator.reg_write(UC_ARM64_REG_X20, sample["unit_index"])
    emulator.reg_write(UC_ARM64_REG_X22, 0 if sample["fvp"] == 1 else 1)
    emulator.reg_write(UC_ARM64_REG_X25, TLS_BASE)
    emulator.reg_write(UC_ARM64_REG_X26, STREAM_BASE)

    error = None
    try:
        emulator.emu_start(
            IMAGE_BASE + decoder_start_rva,
            STOP_BASE + 4,
            count=instruction_limit,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    actual = emulator.reg_read(UC_ARM64_REG_W0) & 0xFFFF
    return {
        **sample,
        "actual_decoded_unit": actual,
        "matched": error is None and not invalid_memory and actual == sample["expected_decoded_unit"],
        "instruction_count": len(trace),
        "trace_rvas": [f"0x{rva:x}" for rva in trace],
        "invalid_memory": invalid_memory,
        "error": error,
    }


def confirm_samples(binary: Path, samples: list[dict], decoder_start_rva: int,
                    instruction_limit: int) -> dict:
    image = binary.read_bytes()
    results = [
        execute_sample(image, sample, decoder_start_rva, instruction_limit)
        for sample in samples
    ]
    mismatches = [item for item in results if not item["matched"]]
    invalid_memory = [
        {"sequence": item.get("sequence"), **error}
        for item in results for error in item["invalid_memory"]
    ]
    return {
        "confirmed": not mismatches,
        "engine": "unicorn-arm64",
        "scope": "fetch-decoder-samples",
        "binary": str(binary.resolve()),
        "binary_sha256": sha256_bytes(image),
        "decoder_start_rva": f"0x{decoder_start_rva:x}",
        "request_count": len(results),
        "matched_count": len(results) - len(mismatches),
        "mismatches": mismatches,
        "invalid_memory": invalid_memory,
        "unknown_external_calls": 0,
        "results": results,
    }


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute the exact fixed-SO fetch decoder for Frida runtime samples"
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--decoder-start-rva", type=number, required=True)
    parser.add_argument("--instruction-limit", type=int, default=256)
    args = parser.parse_args()
    samples = normalize_samples(json.loads(args.samples.read_text(encoding="utf-8")))
    report = confirm_samples(
        args.binary.resolve(), samples, args.decoder_start_rva, args.instruction_limit
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output.resolve()),
        "confirmed": report["confirmed"],
        "matched": report["matched_count"],
        "requests": report["request_count"],
    }))
    return 0 if report["confirmed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
