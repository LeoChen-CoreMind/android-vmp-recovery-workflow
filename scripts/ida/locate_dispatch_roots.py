"""IDA Pro script: locate case-specific byte dispatch roots.

Run inside the exact fixed SO IDB.  It deliberately reports candidates rather
than selecting one silently; callers must inspect evidence before exporting a
handler table.
"""
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vmpwf.ida_patterns import (  # noqa: E402
    is_cmp_dispatch_pattern,
    is_direct_dispatch_pattern,
)

import ida_bytes
import ida_funcs
import idautils
import idc


REQUEST_PATH = os.environ.get("VMPWF_IDA_REQUEST")
if not REQUEST_PATH:
    raise RuntimeError("VMPWF_IDA_REQUEST must point to the case request JSON")
REQUEST = json.loads(Path(REQUEST_PATH).read_text(encoding="utf-8"))
ANALYSIS = REQUEST.get("analysis", {})


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


pointer_base = number(ANALYSIS.get("pointer_base", REQUEST.get("image_base", 0)))
image_size = number(ANALYSIS.get("image_size", 0))
output = Path(ANALYSIS.get("dispatch_candidates", "dispatch_candidates.json"))


def normalize(value):
    if pointer_base <= value < pointer_base + image_size:
        return value - pointer_base
    if 0 <= value < image_size:
        return value
    return None


def next_head(ea):
    if ea in (None, idc.BADADDR):
        return idc.BADADDR
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
    return [ref for ref in idautils.DataRefsFrom(ea) if 0 <= ref < image_size]


def dispatch_step(ea, opcode):
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
        selected = condition_true(condition, opcode, immediate)
        if selected is None:
            return None, {"kind": "unknown_condition", "ea": ea}
        index = 1 if selected else 0
        raw = ida_bytes.get_qword(table + index * 8)
        return normalize(raw), {
            "kind": "cmp_table", "ea": ea, "immediate": immediate,
            "condition": condition, "table": table, "index": index,
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
            if refs:
                slot = refs[-1]
                raw = ida_bytes.get_qword(slot)
                return normalize(raw), {"kind": "direct_slot", "ea": ea, "slot": slot, "raw": raw}
    return None, {"kind": "leaf", "ea": ea}


def resolve(root, opcode):
    current = root
    seen = set()
    path = []
    for depth in range(256):
        if current is None:
            return None, "invalid_pointer", depth, path
        if current in seen:
            return current, "loop", depth, path
        seen.add(current)
        target, detail = dispatch_step(current, opcode)
        path.append(detail)
        if detail["kind"] in ("leaf", "unparsed_cmp", "unparsed_direct", "unknown_condition"):
            return current, detail["kind"], depth, path
        if target is None:
            return None, "non_code_pointer", depth, path
        current = target
    return current, "too_deep", 256, path


def candidate_roots():
    branch_nodes = {}
    for ea in idautils.Heads(0, image_size):
        if idc.print_insn_mnem(ea).upper() != "CMP":
            continue
        if idc.print_operand(ea, 0).upper() not in ("W0", "X0"):
            continue
        if idc.get_operand_type(ea, 1) != idc.o_imm:
            continue
        _, detail = dispatch_step(ea, 0)
        if detail["kind"] != "cmp_table":
            continue
        table = detail["table"]
        targets = [normalize(ida_bytes.get_qword(table + index * 8)) for index in (0, 1)]
        if any(target is None for target in targets) or targets[0] == targets[1]:
            continue
        branch_nodes[ea] = {
            "immediate": idc.get_operand_value(ea, 1),
            "targets": targets,
        }

    def structural_score(root):
        work = [root]
        seen = set()
        leaves = set()
        while work and len(seen) < 4096:
            current = work.pop()
            if current in seen:
                continue
            seen.add(current)
            node = branch_nodes.get(current)
            if node is None:
                leaves.add(current)
                continue
            work.extend(node["targets"])
        return len(seen), len(seen & set(branch_nodes)), len(leaves)

    structural = []
    for ea, node in branch_nodes.items():
        reachable, comparisons, leaves = structural_score(ea)
        if comparisons >= 4 or leaves >= 8:
            structural.append({
                "root": ea,
                "root_immediate": node["immediate"],
                "reachable_nodes": reachable,
                "comparison_nodes": comparisons,
                "structural_leaves": leaves,
            })

    candidates = []
    for structural_item in sorted(
            structural,
            key=lambda item: (item["comparison_nodes"], item["structural_leaves"]),
            reverse=True)[:128]:
        ea = structural_item["root"]
        leaves = []
        statuses = {}
        depths = []
        for opcode in range(256):
            leaf, status, depth, _ = resolve(ea, opcode)
            leaves.append(leaf)
            statuses[status] = statuses.get(status, 0) + 1
            depths.append(depth)
        valid = sum(leaf is not None for leaf in leaves)
        unique = len(set(leaf for leaf in leaves if leaf is not None))
        function = ida_funcs.get_func(ea)
        candidates.append({
            "root_rva": f"0x{ea:x}",
            "function_rva": f"0x{function.start_ea:x}" if function else None,
            "root_immediate": structural_item["root_immediate"],
            "reachable_nodes": structural_item["reachable_nodes"],
            "comparison_nodes": structural_item["comparison_nodes"],
            "structural_leaves": structural_item["structural_leaves"],
            "valid_inputs": valid,
            "unique_leaf_handlers": unique,
            "min_depth": min(depths),
            "max_depth": max(depths),
            "statuses": statuses,
        })
    return sorted(candidates, key=lambda item: (
        item["valid_inputs"], item["unique_leaf_handlers"],
        item["comparison_nodes"], item["max_depth"]
    ), reverse=True)


result = {
    "binary": REQUEST.get("binary"),
    "pointer_base": hex(pointer_base),
    "image_size": hex(image_size),
    "candidates": candidate_roots(),
    "selection_required": True,
}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"output": str(output), "candidates": len(result["candidates"])}, ensure_ascii=False))
