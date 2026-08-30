import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vmpwf.ida_patterns import (  # noqa: E402
    MAX_DISPATCH_GAP,
    canonical_register,
    decoder_max_unit_index,
    exact_memory_register,
    is_control_flow_mnemonic,
    is_cmp_dispatch_pattern,
    is_dispatch_prefetch_address,
    is_direct_dispatch_pattern,
    is_load_branch_tail,
    select_width_evidence,
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
UNIT_DECODER_SPANS = {
    number(key): number(value)
    for key, value in ANALYSIS.get("unit_decoder_spans", {}).items()
}
if any(value <= 0 for value in UNIT_DECODER_SPANS.values()):
    raise RuntimeError("unit_decoder_spans values must be positive")
PC_POINTER_REGISTERS = {
    canonical_register(value)
    for value in ANALYSIS.get("pc_pointer_registers", ["X22"])
}
PC_POINTER_REGISTERS.discard(None)
if not PC_POINTER_REGISTERS:
    raise RuntimeError("pc_pointer_registers must contain at least one register")
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


def dispatch_tail(load):
    heads = [load]
    destinations = []
    current = load
    for _ in range(MAX_DISPATCH_GAP + 1):
        current = next_head(current)
        if current == idc.BADADDR:
            break
        mnemonic = idc.print_insn_mnem(current).upper()
        heads.append(current)
        if mnemonic == "BR":
            return heads, destinations
        if is_control_flow_mnemonic(mnemonic):
            break
        destinations.append(idc.print_operand(current, 0))
    return heads, destinations


def decode_dispatch_node(ea, opcode):
    mnemonic = idc.print_insn_mnem(ea).upper()
    if mnemonic == "CMP" and idc.print_operand(ea, 0).upper() in ("W0", "X0"):
        immediate = idc.get_operand_value(ea, 1)
        adrp = next_head(ea)
        cset = next_head(adrp)
        add = next_head(cset)
        load = next_head(add)
        tail, destinations = dispatch_tail(load)
        branch = tail[-1]
        if not is_cmp_dispatch_pattern(
                [idc.print_insn_mnem(item) for item in (adrp, cset, add, *tail)],
                idc.print_operand(load, 0),
                idc.print_operand(branch, 0),
                destinations):
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
            "instruction_rvas": [ea, adrp, cset, add, *tail],
            "immediate": immediate,
            "condition": condition,
            "table": table,
            "index": index,
            "raw": raw,
        }

    if mnemonic == "ADRP":
        first = next_head(ea)
        tail, destinations = dispatch_tail(first)
        branch = tail[-1]
        if is_direct_dispatch_pattern(
                [mnemonic, *[idc.print_insn_mnem(item) for item in tail]],
                idc.print_operand(first, 0),
                idc.print_operand(branch, 0),
                destinations):
            refs = data_refs(first)
            if not refs:
                return None, {"kind": "unparsed_direct", "ea": ea}
            slot = refs[-1]
            raw = ida_bytes.get_qword(slot)
            return normalize_pointer(raw), {
                "kind": "direct_slot", "ea": ea,
                "instruction_rvas": [ea, *tail],
                "slot": slot, "raw": raw
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


def infer_format_helper_width(target, constants, helper_stack=()):
    if target not in FORMAT_HELPERS or target in helper_stack:
        return None
    function = ida_funcs.get_func(target)
    if function is None:
        return None

    blocks = list(ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS))

    def containing_block(address):
        return next((
            block for block in blocks
            if block.start_ea <= address < block.end_ea
        ), None)

    initial = containing_block(target)
    if initial is None:
        return None

    decoder_calls = []
    nested_helpers = []
    work = [(target, dict(constants), 0)]
    seen = set()
    processed = 0
    while work and processed < 5000:
        entry, inherited_constants, depth = work.pop()
        processed += 1
        block = containing_block(entry)
        if block is None or depth > 64:
            continue
        state_key = (block.start_ea, entry, tuple(sorted(inherited_constants.items())))
        if state_key in seen:
            continue
        seen.add(state_key)
        current_constants = dict(inherited_constants)

        for ea in idautils.Heads(entry, block.end_ea):
            mnemonic = idc.print_insn_mnem(ea).upper()
            op0_text = idc.print_operand(ea, 0).upper()
            op1_text = idc.print_operand(ea, 1).upper()
            destination = canonical_register(op0_text)

            if mnemonic == "MOV" and destination:
                source = canonical_register(op1_text)
                if op1_text in ("WZR", "XZR"):
                    current_constants[destination] = 0
                elif idc.get_operand_type(ea, 1) == idc.o_imm:
                    current_constants[destination] = idc.get_operand_value(ea, 1)
                elif source in current_constants:
                    current_constants[destination] = current_constants[source]
                else:
                    current_constants.pop(destination, None)
                continue

            if mnemonic in ("ADD", "SUB") and destination:
                source = canonical_register(op1_text)
                if source in current_constants and idc.get_operand_type(ea, 2) == idc.o_imm:
                    immediate = idc.get_operand_value(ea, 2)
                    if mnemonic == "SUB":
                        immediate = -immediate
                    current_constants[destination] = current_constants[source] + immediate
                else:
                    current_constants.pop(destination, None)
                continue

            if mnemonic == "BL":
                call_target = idc.get_operand_value(ea, 0)
                if call_target in UNIT_DECODERS and "X1" in current_constants:
                    unit_index = current_constants["X1"]
                    if 0 <= unit_index <= 0x20:
                        unit_count = UNIT_DECODER_SPANS.get(call_target, 1)
                        decoder_calls.append({
                            "call": ea,
                            "decoder": call_target,
                            "unit_index": unit_index,
                            "unit_count": unit_count,
                            "max_unit_index": decoder_max_unit_index(
                                unit_index, unit_count
                            ),
                        })
                elif call_target in FORMAT_HELPERS:
                    nested = infer_format_helper_width(
                        call_target,
                        current_constants,
                        (*helper_stack, target),
                    )
                    if nested is not None:
                        nested_helpers.append({
                            "call": ea,
                            "helper": call_target,
                            **nested,
                        })
                for index in range(19):
                    current_constants.pop(f"X{index}", None)
                continue

            if destination and mnemonic not in (
                    "CMP", "CMN", "TST", "STR", "STRB", "STRH", "STP"):
                current_constants.pop(destination, None)

        for successor in block.succs():
            work.append((successor.start_ea, current_constants, depth + 1))

    max_indices = [call["max_unit_index"] for call in decoder_calls]
    max_indices.extend(item["max_unit_index"] for item in nested_helpers)
    if not max_indices:
        return None
    max_index = max(max_indices)
    return {
        "units": max_index + 1,
        "max_unit_index": max_index,
        "decoder_calls": decoder_calls,
        "nested_helpers": nested_helpers,
    }


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
    candidate_heads = heads[max(0, len(heads) - MAX_DISPATCH_GAP - 2):-1]
    for ea in reversed(candidate_heads):
        if idc.print_insn_mnem(ea).upper() != "LDR":
            continue
        tail = heads[heads.index(ea):]
        destinations = [idc.print_operand(item, 0) for item in tail[1:-1]]
        if not is_load_branch_tail(
                [idc.print_insn_mnem(item) for item in tail],
                idc.print_operand(ea, 0),
                idc.print_operand(branch_ea, 0),
                destinations):
            continue
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
    root_function = ida_funcs.get_func(ROOT)
    root_function_start = root_function.start_ea if root_function is not None else ROOT
    prefetch_function_starts = {root_function_start}
    previous = idc.prev_head(ROOT, max(0, ROOT - 0x100))
    previous_function = ida_funcs.get_func(previous)
    if previous_function is not None and previous_function.end_ea == ROOT:
        prefetch_function_starts.add(previous_function.start_ea)

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

            if (mnemonic == "LDR" and destination
                    and exact_memory_register(op1_text) in PC_POINTER_REGISTERS):
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

            if (mnemonic == "STR"
                    and exact_memory_register(op1_text) in PC_POINTER_REGISTERS):
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
                        unit_count = UNIT_DECODER_SPANS.get(target, 1)
                        decoded_unit_index = unit_index
                        decoder_calls.append({
                            "call": ea,
                            "decoder": target,
                            "unit_index": unit_index,
                            "unit_count": unit_count,
                            "max_unit_index": decoder_max_unit_index(
                                unit_index, unit_count
                            ),
                        })
                helper_evidence = infer_format_helper_width(target, current_constants)
                if helper_evidence is not None:
                    format_calls.append({
                        "call": ea,
                        "helper": target,
                        **helper_evidence,
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
            successor_function = ida_funcs.get_func(successor_address)
            if (successor_function is not None
                    and is_dispatch_prefetch_address(
                        successor_address,
                        ROOT,
                        successor_function.start_ea,
                        prefetch_function_starts,
                    )):
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
    operand_widths = []
    if decoder_calls:
        max_index = max(call["max_unit_index"] for call in decoder_calls)
        operand_widths.append(max_index + 1)
    for call in format_calls:
        operand_widths.append(call["units"])
    if operand_widths:
        units = max(operand_widths)
        format_candidates[units] = {
            "bytes": units * 2,
            "units": units,
            "source": "operand_coverage",
        }
        if decoder_calls:
            format_candidates[units]["decoder_max_index"] = max(
                call["max_unit_index"] for call in decoder_calls
            )
            format_candidates[units]["decoder_calls"] = decoder_calls
        if format_calls:
            format_candidates[units]["format_calls"] = format_calls
    if not format_candidates and not pc_unique and terminal_returns:
        format_candidates[1] = {
            "bytes": 2,
            "units": 1,
            "source": "terminal_return",
            "terminal_returns": terminal_returns,
        }

    unique = select_width_evidence(pc_unique, format_candidates)
    if variable_pc_sources:
        for candidate in unique.values():
            candidate["variable_pc_sources"] = variable_pc_sources
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
