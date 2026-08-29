import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vmpwf.ida_patterns import (  # noqa: E402
    canonical_register,
    is_cmp_dispatch_pattern,
    is_direct_dispatch_pattern,
)

import ida_bytes
import ida_funcs
import ida_gdl
import idautils
import idc


WORK_DIR = Path(__file__).resolve().parent


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


request_path = os.environ.get("VMPWF_IDA_REQUEST")
if not request_path:
    raise RuntimeError("VMPWF_IDA_REQUEST must point to the case-specific IDA request JSON")
REQUEST = json.loads(Path(request_path).read_text(encoding="utf-8"))
ANALYSIS = REQUEST.get("analysis", {})
required = {"image_size", "unit_decoders", "format_helpers", "noreturn_helpers"}
missing = sorted(required - set(ANALYSIS))
if REQUEST.get("root_rva") is None or missing:
    raise RuntimeError("IDA request is missing case-specific fields: root_rva, " + ", ".join(missing))

LOAD_BASE = number(REQUEST.get("image_base", 0))
IMAGE_SIZE = number(ANALYSIS["image_size"])
POINTER_BASE = number(ANALYSIS.get("pointer_base", LOAD_BASE))
ROOT = number(REQUEST["root_rva"])
OUTPUT = Path(REQUEST["output"])
UNIT_DECODERS = {number(value) for value in ANALYSIS["unit_decoders"]}
FORMAT_HELPERS = {number(value) for value in ANALYSIS["format_helpers"]}
NORETURN_HELPERS = {number(value) for value in ANALYSIS["noreturn_helpers"]}
HANDLER_WIDTH_OVERRIDES = {
    number(key): number(value) for key, value in ANALYSIS.get("handler_width_overrides", {}).items()
}


def normalize_pointer(value):
    if POINTER_BASE <= value < POINTER_BASE + IMAGE_SIZE:
        return value - POINTER_BASE
    if 0 <= value < IMAGE_SIZE:
        return value
    return None


def next_head(ea):
    return idc.next_head(ea, ea + 0x80)


def condition_true(condition, left, right):
    condition = condition.upper()
    if condition == "EQ":
        return left == right
    if condition == "NE":
        return left != right
    if condition in ("LT", "LO", "CC"):
        return left < right
    if condition in ("LE", "LS"):
        return left <= right
    if condition in ("GT", "HI"):
        return left > right
    if condition in ("GE", "HS", "CS"):
        return left >= right
    return None


def data_refs(ea):
    return [ref for ref in idautils.DataRefsFrom(ea) if 0 <= ref < IMAGE_SIZE]


def decode_dispatch_node(ea, opcode):
    mnemonic = idc.print_insn_mnem(ea).upper()
    if mnemonic == "CMP" and idc.print_operand(ea, 0).upper() in ("W0", "X0"):
        immediate = idc.get_operand_value(ea, 1)
        adrp = next_head(ea)
        cset = next_head(adrp)
        add = next_head(cset)
        load = next_head(add)
        branch = next_head(load)
        if not is_cmp_dispatch_pattern(
                [idc.print_insn_mnem(item) for item in (adrp, cset, add, load, branch)],
                idc.print_operand(load, 0),
                idc.print_operand(branch, 0)):
            return None, {"kind": "unparsed_cmp", "ea": ea}
        condition = idc.print_operand(cset, 1)
        refs = data_refs(add) or data_refs(adrp)
        table = refs[-1] if refs else None
        if table is None:
            return None, {"kind": "unparsed_cmp", "ea": ea}
        test = condition_true(condition, opcode, immediate)
        if test is None:
            return None, {"kind": "unknown_condition", "condition": condition, "ea": ea}
        index = 1 if test else 0
        raw = ida_bytes.get_qword(table + index * 8)
        return normalize_pointer(raw), {
            "kind": "cmp_table",
            "ea": ea,
            "immediate": immediate,
            "condition": condition,
            "table": table,
            "index": index,
            "raw": raw,
        }

    if mnemonic == "ADRP":
        first = next_head(ea)
        second = next_head(first)
        if is_direct_dispatch_pattern(
                [mnemonic, idc.print_insn_mnem(first), idc.print_insn_mnem(second)],
                idc.print_operand(first, 0),
                idc.print_operand(second, 0)):
            refs = data_refs(first)
            if not refs:
                return None, {"kind": "unparsed_direct", "ea": ea}
            slot = refs[-1]
            raw = ida_bytes.get_qword(slot)
            return normalize_pointer(raw), {
                "kind": "direct_slot", "ea": ea, "slot": slot, "raw": raw
            }

    return None, {"kind": "leaf", "ea": ea}


def resolve_opcode(opcode):
    current = ROOT
    seen = set()
    path = []
    for _ in range(128):
        if current is None:
            return None, "invalid_pointer", path
        if current in seen:
            return current, "loop", path
        seen.add(current)
        nxt, detail = decode_dispatch_node(current, opcode)
        path.append(detail)
        if detail["kind"] in ("leaf", "unparsed_cmp", "unparsed_direct", "unknown_condition"):
            return current, detail["kind"], path
        if nxt is None:
            raw = detail.get("raw", 0)
            return raw, "non_code_pointer", path
        current = nxt
    return current, "too_deep", path


def memory_operand(operand):
    return operand.upper().replace(" ", "")


def operand_registers(operand):
    return [
        canonical_register(register)
        for register in re.findall(r"\b[WX]\d+\b", operand.upper())
    ]


def previous_heads(start, end):
    return list(idautils.Heads(start, end))


def infer_index_values(register, heads, before):
    for ea in reversed([head for head in heads if head < before]):
        destination = canonical_register(idc.print_operand(ea, 0))
        if destination != register:
            continue
        mnemonic = idc.print_insn_mnem(ea).upper()
        if mnemonic == "CSET":
            return [0, 1]
        if mnemonic == "MOV" and idc.get_operand_type(ea, 1) == idc.o_imm:
            return [idc.get_operand_value(ea, 1)]
        if mnemonic == "AND" and idc.get_operand_type(ea, 2) == idc.o_imm:
            mask = idc.get_operand_value(ea, 2)
            values = sorted({value & mask for value in range(256)})
            return values if len(values) <= 16 else []
        if mnemonic == "UBFX" and idc.get_operand_type(ea, 3) == idc.o_imm:
            width = idc.get_operand_value(ea, 3)
            return list(range(1 << width)) if 0 < width <= 4 else []
        return []
    return []


def find_address_reference(register, heads, before):
    for ea in reversed([head for head in heads if head < before]):
        if canonical_register(idc.print_operand(ea, 0)) != register:
            continue
        refs = data_refs(ea)
        if refs:
            return refs[-1]
    return None


def infer_format_helper_width(target, constants):
    if target in {0x7F4A4, 0x7F504}:
        return 3
    if target == 0x7FC78:
        return 2
    if target == 0x7F0D0 and "X0" in constants:
        return 2 + (constants["X0"] & 1)
    if target == 0x80034:
        return 3
    if target == 0x851E8 and "X1" in constants:
        start_index = constants["X1"]
        if 0 <= start_index <= 0x20:
            return start_index + 2
    return None


def resolve_indirect_successors(block, entry):
    heads = previous_heads(entry, block.end_ea)
    if not heads:
        return [], None
    branch_ea = heads[-1]
    if idc.print_insn_mnem(branch_ea).upper() != "BR":
        return [], None
    branch_register = canonical_register(idc.print_operand(branch_ea, 0))
    if branch_register is None:
        return [], None

    load_ea = None
    load_operand = None
    for ea in reversed(heads[:-1]):
        if canonical_register(idc.print_operand(ea, 0)) != branch_register:
            continue
        if idc.print_insn_mnem(ea).upper() != "LDR":
            return [], None
        load_ea = ea
        load_operand = idc.print_operand(ea, 1)
        break
    if load_ea is None:
        return [], None

    registers = operand_registers(load_operand)
    if not registers:
        return [], None
    base_register = registers[0]
    index_register = registers[1] if len(registers) > 1 else None
    table = None
    refs = data_refs(load_ea)
    if refs:
        table = refs[-1]
    if table is None:
        table = find_address_reference(base_register, heads, load_ea)
    if table is None:
        return [], None

    indices = [0]
    if index_register is not None:
        indices = infer_index_values(index_register, heads, load_ea)
        if not indices:
            return [], None

    targets = []
    entries = []
    for index in indices:
        raw = ida_bytes.get_qword(table + index * 8)
        target = normalize_pointer(raw)
        entries.append({"index": index, "raw": raw, "target": target})
        if target is not None and target not in targets:
            targets.append(target)
    return targets, {
        "kind": "indirect_table",
        "branch": branch_ea,
        "load": load_ea,
        "table": table,
        "entries": entries,
    }


def infer_pc_width(handler):
    if handler in HANDLER_WIDTH_OVERRIDES:
        units = HANDLER_WIDTH_OVERRIDES[handler]
        return [{
            "bytes": units * 2,
            "units": units,
            "source": "handler_override",
        }]

    block_cache = {}

    def containing_block(address):
        function = ida_funcs.get_func(address)
        if function is None:
            return None
        if function.start_ea not in block_cache:
            block_cache[function.start_ea] = list(
                ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS)
            )
        return next((
            block for block in block_cache[function.start_ea]
            if block.start_ea <= address < block.end_ea
        ), None)

    containing = containing_block(handler)
    if containing is None:
        return []

    candidates = []
    decoder_calls = []
    format_calls = []
    variable_pc_sources = []
    terminal_returns = []
    indirect_tables = []
    work = [(containing.start_ea, handler, {}, {}, {"X25": 0}, 0)]
    seen = set()
    processed = 0
    while work and processed < 5000:
        block_start, entry, registers, constants, unit_sources, depth = work.pop()
        processed += 1
        state_key = (block_start, entry, tuple(sorted(
            (register, value[0]) for register, value in registers.items()
        )), tuple(sorted(constants.items())), tuple(sorted(unit_sources.items())))
        if state_key in seen or depth > 64:
            continue
        seen.add(state_key)
        block = containing_block(entry)
        if block is None:
            continue

        current = dict(registers)
        current_constants = dict(constants)
        current_unit_sources = dict(unit_sources)
        path_finished = False
        for ea in idautils.Heads(entry, block.end_ea):
            mnemonic = idc.print_insn_mnem(ea).upper()
            op0_text = idc.print_operand(ea, 0).upper()
            op1_text = idc.print_operand(ea, 1).upper()
            destination = canonical_register(op0_text)

            if mnemonic == "LDR" and destination and memory_operand(op1_text) == "[X22]":
                current[destination] = (0, ea)
                current_constants.pop(destination, None)
                current_unit_sources.pop(destination, None)
                continue

            if mnemonic == "MOV" and destination:
                source = canonical_register(op1_text)
                if source in current:
                    current[destination] = current[source]
                else:
                    current.pop(destination, None)
                if op1_text in ("WZR", "XZR"):
                    current_constants[destination] = 0
                    current_unit_sources.pop(destination, None)
                elif idc.get_operand_type(ea, 1) == idc.o_imm:
                    current_constants[destination] = idc.get_operand_value(ea, 1)
                    current_unit_sources.pop(destination, None)
                elif source in current_constants:
                    current_constants[destination] = current_constants[source]
                else:
                    current_constants.pop(destination, None)
                if source in current_unit_sources:
                    current_unit_sources[destination] = current_unit_sources[source]
                elif idc.get_operand_type(ea, 1) != idc.o_imm:
                    current_unit_sources.pop(destination, None)
                continue

            if mnemonic in ("ADD", "SUB") and destination:
                source = canonical_register(op1_text)
                source_is_pc = source in current
                third_registers = operand_registers(idc.print_operand(ea, 2))
                third_register = third_registers[0] if third_registers else None
                if source in current and idc.get_operand_type(ea, 2) == idc.o_imm:
                    immediate = idc.get_operand_value(ea, 2)
                    if mnemonic == "SUB":
                        immediate = -immediate
                    offset, load_ea = current[source]
                    current[destination] = (offset + immediate, load_ea)
                else:
                    current.pop(destination, None)
                if source in current_constants and idc.get_operand_type(ea, 2) == idc.o_imm:
                    immediate = idc.get_operand_value(ea, 2)
                    if mnemonic == "SUB":
                        immediate = -immediate
                    current_constants[destination] = current_constants[source] + immediate
                else:
                    current_constants.pop(destination, None)
                if source in current_unit_sources and idc.get_operand_type(ea, 2) == idc.o_imm:
                    current_unit_sources[destination] = current_unit_sources[source]
                elif source_is_pc and third_register in current_unit_sources:
                    unit_index = current_unit_sources[third_register]
                    variable_pc_sources.append({
                        "ea": ea,
                        "unit_index": unit_index,
                        "register": third_register,
                    })
                    current_unit_sources[destination] = unit_index
                else:
                    current_unit_sources.pop(destination, None)
                continue

            if mnemonic in ("AND", "UBFX", "SBFX", "LSL", "LSR", "ASR") and destination:
                source = canonical_register(op1_text)
                current.pop(destination, None)
                current_constants.pop(destination, None)
                if source in current_unit_sources:
                    current_unit_sources[destination] = current_unit_sources[source]
                else:
                    current_unit_sources.pop(destination, None)
                continue

            if mnemonic == "STR" and memory_operand(op1_text) == "[X22]":
                source = canonical_register(op0_text)
                if source in current:
                    immediate, load_ea = current[source]
                    if 0 < immediate <= 0x40 and immediate % 2 == 0:
                        candidates.append({
                            "bytes": immediate,
                            "units": immediate // 2,
                            "load": load_ea,
                            "store": ea,
                            "blocks": depth + 1,
                        })
                path_finished = True
                break

            if mnemonic in ("BL", "BLR"):
                target = idc.get_operand_value(ea, 0) if mnemonic == "BL" else None
                if target in NORETURN_HELPERS:
                    path_finished = True
                    break
                decoded_unit_index = None
                if target in UNIT_DECODERS and "X1" in current_constants:
                    unit_index = current_constants["X1"]
                    if 0 <= unit_index <= 0x20:
                        decoded_unit_index = unit_index
                        decoder_calls.append({
                            "call": ea,
                            "decoder": target,
                            "unit_index": unit_index,
                        })
                helper_width = infer_format_helper_width(target, current_constants)
                if target in FORMAT_HELPERS and helper_width is not None:
                    format_calls.append({
                        "call": ea,
                        "helper": target,
                        "units": helper_width,
                    })
                for index in range(19):
                    current.pop(f"X{index}", None)
                    current_constants.pop(f"X{index}", None)
                    current_unit_sources.pop(f"X{index}", None)
                if decoded_unit_index is not None:
                    current_unit_sources["X0"] = decoded_unit_index
                continue

            if mnemonic == "RET":
                terminal_returns.append({"ea": ea, "units": 1})
                path_finished = True
                break

            if destination and mnemonic not in (
                    "CMP", "CMN", "TST", "STR", "STRB", "STRH", "STP"):
                current.pop(destination, None)
                current_constants.pop(destination, None)
                current_unit_sources.pop(destination, None)

        if path_finished:
            continue
        successors = [successor.start_ea for successor in block.succs()]
        if not successors and not decoder_calls and not format_calls and not variable_pc_sources:
            targets, table_detail = resolve_indirect_successors(block, entry)
            if table_detail is not None:
                indirect_tables.append(table_detail)
                successors.extend(targets)
        for successor_address in successors:
            successor = containing_block(successor_address)
            if successor is None:
                continue
            work.append((
                successor.start_ea,
                successor_address,
                current,
                current_constants,
                current_unit_sources,
                depth + 1,
            ))

    pc_unique = {}
    for candidate in candidates:
        candidate["source"] = "pc_write"
        pc_unique.setdefault(candidate["units"], candidate)

    format_candidates = {}
    if decoder_calls:
        max_index = max(call["unit_index"] for call in decoder_calls)
        units = max_index + 1
        format_candidates[units] = {
            "bytes": units * 2,
            "units": units,
            "source": "decoder_max_index",
            "decoder_max_index": max_index,
            "decoder_calls": decoder_calls,
        }
    for call in format_calls:
        units = call["units"]
        candidate = format_candidates.setdefault(units, {
            "bytes": units * 2,
            "units": units,
            "source": "format_helper",
            "format_calls": [],
        })
        candidate.setdefault("format_calls", []).append(call)
    if variable_pc_sources:
        max_index = max(item["unit_index"] for item in variable_pc_sources)
        units = max_index + 1
        format_candidates.setdefault(units, {
            "bytes": units * 2,
            "units": units,
            "source": "variable_pc_source",
            "variable_pc_sources": variable_pc_sources,
        })
    if not format_candidates and terminal_returns:
        format_candidates[1] = {
            "bytes": 2,
            "units": 1,
            "source": "terminal_return",
            "terminal_returns": terminal_returns,
        }

    unique = format_candidates if format_candidates else pc_unique
    if format_candidates:
        for units, candidate in unique.items():
            if units in pc_unique:
                candidate["matching_pc_write"] = pc_unique[units]
    if indirect_tables:
        for candidate in unique.values():
            candidate["indirect_tables"] = indirect_tables
    return [unique[key] for key in sorted(unique)]


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    for opcode in range(256):
        handler, status, path = resolve_opcode(opcode)
        valid_handler = handler if isinstance(handler, int) and 0 <= handler < IMAGE_SIZE else None
        entries.append({
            "opcode": opcode,
            "handler": valid_handler,
            "status": status,
            "pc_width_candidates": infer_pc_width(valid_handler) if valid_handler is not None else [],
            "path": path,
        })
    payload = {
        "load_base": LOAD_BASE,
        "image_size": IMAGE_SIZE,
        "root": ROOT,
        "entries": entries,
    }
    OUTPUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    summary = {}
    for entry in entries:
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1
    print(json.dumps({"output": str(OUTPUT), "status_counts": summary}, ensure_ascii=False))


main()
