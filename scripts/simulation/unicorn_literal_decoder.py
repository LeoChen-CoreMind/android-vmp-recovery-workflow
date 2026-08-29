#!/usr/bin/env python3
import argparse
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from unicorn import (
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_HOOK_MEM_INVALID,
    UC_MODE_ARM,
    Uc,
    UcError,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
)


ROOT = Path(__file__).resolve().parent

PAGE_SIZE = 0x1000
OUTER_BASE = 0x10000000
LINKER_BASE = 0x20000000
HEAP_BASE = 0x30000000
HEAP_SIZE = 0x100000
STACK_BASE = 0x40000000
STACK_SIZE = 0x200000
STOP_BASE = 0x50000000

REQUIRED_CONFIG = {
    "interpreter_wrap_rva", "program_base_rva", "program_entry",
    "program_global_rva", "outer_rela_rva", "outer_rela_size",
    "relative_relocation_type", "dynstr_rva", "dynstr_size",
    "symtab_rva", "symtab_size", "symtab_entry_size",
    "plt_rela_rva", "plt_rela_size", "plt_stub_rva",
    "got_base_rva", "plt_stub_size", "got_slot_size",
}


def align_up(value, alignment=PAGE_SIZE):
    return (value + alignment - 1) & -alignment


def load_config(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_CONFIG - set(payload))
    if missing:
        raise ValueError("simulation config missing fields: " + ", ".join(missing))
    result = {}
    for key, value in payload.items():
        result[key] = int(value, 0) if isinstance(value, str) else value
    return result


class LiteralDecoder:
    def __init__(self, outer_path, linker_path, config_path, trace_limit=64):
        self.outer = Path(outer_path).read_bytes()
        self.linker = Path(linker_path).read_bytes()
        self.config = load_config(config_path)
        self.trace_limit = trace_limit
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.plt_symbols = self._load_plt_symbols()
        self.unit_cache = {}

    def _load_plt_symbols(self):
        config = self.config
        dynstr_start = config["dynstr_rva"]
        dynstr = self.outer[dynstr_start:dynstr_start + config["dynstr_size"]]
        symbols = []
        symtab_end = config["symtab_rva"] + config["symtab_size"]
        for offset in range(config["symtab_rva"], symtab_end, config["symtab_entry_size"]):
            name_offset, _info, _other, _shndx, _value, _size = struct.unpack_from(
                "<IBBHQQ", self.outer, offset
            )
            end = dynstr.find(bytes([0]), name_offset)
            if end < 0:
                end = len(dynstr)
            symbols.append(dynstr[name_offset:end].decode(errors="replace"))

        result = {}
        rela_offset = config["plt_rela_rva"]
        rela_size = config["plt_rela_size"]
        for offset in range(rela_offset, rela_offset + rela_size, 24):
            got_offset, info, _addend = struct.unpack_from("<QQq", self.outer, offset)
            symbol_index = info >> 32
            if symbol_index >= len(symbols):
                continue
            slot = (got_offset - config["got_base_rva"]) // config["got_slot_size"]
            stub_rva = config["plt_stub_rva"] + slot * config["plt_stub_size"]
            result[stub_rva] = symbols[symbol_index]
        return result

    def _map_image(self, uc, base, image):
        uc.mem_map(base, align_up(len(image)))
        uc.mem_write(base, image)

    def _apply_outer_relative_relocations(self, uc):
        applied = 0
        start = self.config["outer_rela_rva"]
        end = start + self.config["outer_rela_size"]
        for offset in range(start, end, 24):
            target_rva, info, addend = struct.unpack_from("<QQq", self.outer, offset)
            if (info & 0xFFFFFFFF) != self.config["relative_relocation_type"]:
                continue
            uc.mem_write(
                OUTER_BASE + target_rva,
                struct.pack("<Q", OUTER_BASE + addend),
            )
            applied += 1
        return applied

    def decode_byte(self, method_key, raw_byte):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._map_image(uc, OUTER_BASE, self.outer)
        self._map_image(uc, LINKER_BASE, self.linker)
        relative_relocations = self._apply_outer_relative_relocations(uc)
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(STOP_BASE, PAGE_SIZE)

        heap_cursor = HEAP_BASE
        frame = HEAP_BASE + 0x80000
        code_units = HEAP_BASE + 0x81000
        uc.mem_write(frame, struct.pack("<Q", code_units) + bytes([method_key & 0xFF]) + bytes(0x77))
        uc.mem_write(code_units, bytes(PAGE_SIZE))

        trace = []
        external_calls = []
        invalid_access = []

        def hook_code(emu, address, size, _):
            nonlocal heap_cursor
            rva = address - OUTER_BASE
            symbol = self.plt_symbols.get(rva)
            if symbol in {"_Znwm", "_Znam", "malloc"}:
                requested = emu.reg_read(UC_ARM64_REG_X0)
                allocated = heap_cursor
                heap_cursor = align_up(heap_cursor + max(requested, 1), 0x10)
                if heap_cursor >= HEAP_BASE + 0x70000:
                    raise RuntimeError("模拟堆空间耗尽")
                emu.mem_write(allocated, bytes(max(requested, 1)))
                emu.reg_write(UC_ARM64_REG_X0, allocated)
                emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
                external_calls.append({
                    "kind": "alloc",
                    "symbol": symbol,
                    "size": requested,
                    "result": allocated,
                })
                return
            if symbol == "calloc":
                requested = emu.reg_read(UC_ARM64_REG_X0) * emu.reg_read(UC_ARM64_REG_X1)
                allocated = heap_cursor
                heap_cursor = align_up(heap_cursor + max(requested, 1), 0x10)
                emu.mem_write(allocated, bytes(max(requested, 1)))
                emu.reg_write(UC_ARM64_REG_X0, allocated)
                emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
                external_calls.append({
                    "kind": "alloc",
                    "symbol": symbol,
                    "size": requested,
                    "result": allocated,
                })
                return
            if symbol in {"_ZdlPv", "_ZdaPv", "free"}:
                external_calls.append({
                    "kind": "free",
                    "symbol": symbol,
                    "pointer": emu.reg_read(UC_ARM64_REG_X0),
                })
                emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
                return
            if symbol == "memset":
                destination = emu.reg_read(UC_ARM64_REG_X0)
                value = emu.reg_read(UC_ARM64_REG_X1) & 0xFF
                length = emu.reg_read(UC_ARM64_REG_X2)
                emu.mem_write(destination, bytes([value]) * length)
                emu.reg_write(UC_ARM64_REG_X0, destination)
                emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
                external_calls.append({"kind": "memset", "size": length})
                return
            if symbol in {"memcpy", "memmove"}:
                destination = emu.reg_read(UC_ARM64_REG_X0)
                source = emu.reg_read(UC_ARM64_REG_X1)
                length = emu.reg_read(UC_ARM64_REG_X2)
                emu.mem_write(destination, bytes(emu.mem_read(source, length)))
                emu.reg_write(UC_ARM64_REG_X0, destination)
                emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
                external_calls.append({"kind": symbol, "size": length})
                return
            if symbol in {"abort", "__stack_chk_fail"}:
                raise RuntimeError(f"解释器进入异常外部调用 {symbol}")
            if symbol is not None:
                raise RuntimeError(f"尚未实现的解释器外部调用: {symbol} @ 0x{rva:x}")
            if address == STOP_BASE:
                emu.emu_stop()
                return
            if len(trace) >= self.trace_limit:
                trace.pop(0)
            raw = bytes(emu.mem_read(address, size))
            insn = next(self.cs.disasm(raw, address), None)
            trace.append(
                f"0x{address:016x}: {insn.mnemonic} {insn.op_str}" if insn
                else f"0x{address:016x}: {raw.hex()}"
            )

        def hook_invalid(_emu, access, address, size, value, _):
            invalid_access.append({
                "access": access,
                "address": address,
                "size": size,
                "value": value,
            })
            return False

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)

        stack_top = STACK_BASE + STACK_SIZE - 0x100
        uc.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
        uc.reg_write(UC_ARM64_REG_SP, stack_top)
        uc.reg_write(UC_ARM64_REG_LR, STOP_BASE)
        uc.reg_write(UC_ARM64_REG_X0, LINKER_BASE + self.config["program_base_rva"])
        uc.reg_write(UC_ARM64_REG_X1, self.config["program_entry"])
        uc.reg_write(UC_ARM64_REG_X2, LINKER_BASE + self.config["program_global_rva"])
        uc.reg_write(UC_ARM64_REG_X3, frame)
        uc.reg_write(UC_ARM64_REG_X4, raw_byte & 0xFF)

        try:
            uc.emu_start(
                OUTER_BASE + self.config["interpreter_wrap_rva"],
                STOP_BASE + 4,
                count=self.config.get("max_instruction_count", 2_000_000),
            )
        except (UcError, RuntimeError) as exc:
            raise RuntimeError(json.dumps({
                "error": str(exc),
                "pc": f"0x{uc.reg_read(UC_ARM64_REG_PC):x}",
                "raw_byte": raw_byte & 0xFF,
                "method_key": method_key & 0xFF,
                "invalid_access": invalid_access,
                "external_calls": external_calls,
                "relative_relocations": relative_relocations,
                "trace_tail": trace,
            }, ensure_ascii=False, indent=2)) from exc

        return {
            "method_key": method_key & 0xFF,
            "raw_byte": raw_byte & 0xFF,
            "decoded_byte": uc.reg_read(UC_ARM64_REG_X0) & 0xFF,
            "relative_relocations": relative_relocations,
            "external_calls": external_calls,
            "trace_tail": trace,
        }

    def decode_unit(self, method_key, raw_unit):
        cache_key = (method_key & 0xFF, raw_unit & 0xFFFF)
        cached = self.unit_cache.get(cache_key)
        if cached is not None:
            return dict(cached)
        low = self.decode_byte(method_key, raw_unit & 0xFF)
        high = self.decode_byte(method_key, (raw_unit >> 8) & 0xFF)
        decoded = (method_key | (method_key << 8)) ^ (
            low["decoded_byte"] | (high["decoded_byte"] << 8)
        )
        result = {
            "engine": "unicorn-arm64",
            "interpreter_entry_rva": f"{self.config['interpreter_wrap_rva']:x}",
            "relative_relocations": low["relative_relocations"],
            "method_key": method_key & 0xFF,
            "raw_unit": f"{raw_unit & 0xFFFF:04x}",
            "transformed_low": low["decoded_byte"],
            "transformed_high": high["decoded_byte"],
            "decoded_unit": f"{decoded & 0xFFFF:04x}",
        }
        self.unit_cache[cache_key] = result
        return dict(result)


def parse_int(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(
        description="用 Unicorn 执行 360 原生解释器，恢复 sub_8BD88 mode=1 单元"
    )
    parser.add_argument("--outer", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True,
                        help="case-specific native addresses and ELF/PLT layout")
    parser.add_argument("--key", type=parse_int, required=True)
    parser.add_argument("--unit", type=parse_int, action="append", required=True)
    parser.add_argument("--trace-limit", type=int, default=32)
    args = parser.parse_args()

    decoder = LiteralDecoder(args.outer, args.linker, args.config, args.trace_limit)
    results = [decoder.decode_unit(args.key, unit) for unit in args.unit]
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
