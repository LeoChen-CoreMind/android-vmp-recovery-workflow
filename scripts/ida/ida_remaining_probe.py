import json
import os
from collections import Counter, defaultdict
from pathlib import Path

import ida_funcs
import ida_gdl
import idautils
import idc


WORK_DIR = Path(__file__).resolve().parent
request_path = os.environ.get("VMPWF_IDA_REQUEST")
if not request_path:
    raise RuntimeError("VMPWF_IDA_REQUEST must point to the case-specific IDA request JSON")
REQUEST = json.loads(Path(request_path).read_text(encoding="utf-8"))
ANALYSIS = REQUEST.get("analysis", {})
if "image_size" not in ANALYSIS:
    raise RuntimeError("IDA request analysis.image_size is required")
IMAGE_SIZE = int(ANALYSIS["image_size"], 0) if isinstance(ANALYSIS["image_size"], str) else int(ANALYSIS["image_size"])
INPUT = Path(REQUEST["output"])
OUTPUT = Path(ANALYSIS.get("remaining_output", INPUT.with_name("remaining_probe.json")))


def block_for_address(function, address):
    for block in ida_gdl.FlowChart(function):
        if block.start_ea <= address < block.end_ea:
            return block
    return None


def inspect_entry(entry):
    handler = entry["handler"]
    function = ida_funcs.get_func(handler)
    if function is None:
        return {"opcode": entry["opcode"], "handler": handler, "error": "no_function"}
    block = block_for_address(function, handler)
    if block is None:
        return {"opcode": entry["opcode"], "handler": handler, "error": "no_block"}

    calls = []
    data_refs = []
    terminals = []
    instructions = []
    for ea in idautils.Heads(handler, block.end_ea):
        mnemonic = idc.print_insn_mnem(ea).upper()
        instructions.append({"ea": ea, "text": idc.generate_disasm_line(ea, 0) or ""})
        if mnemonic == "BL":
            target = idc.get_operand_value(ea, 0)
            calls.append({"ea": ea, "target": target, "name": idc.get_name(target) or ""})
        if mnemonic in ("ADRP", "LDR"):
            for reference in idautils.DataRefsFrom(ea):
                if 0 <= reference < IMAGE_SIZE:
                    data_refs.append({"ea": ea, "target": reference})
        if mnemonic in ("BR", "RET"):
            terminals.append({"ea": ea, "mnemonic": mnemonic})

    return {
        "opcode": entry["opcode"],
        "handler": handler,
        "function": function.start_ea,
        "block_start": block.start_ea,
        "block_end": block.end_ea,
        "calls": calls,
        "data_refs": data_refs,
        "terminals": terminals,
        "instructions": instructions,
    }


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    dispatch = json.loads(INPUT.read_text(encoding="utf-8"))
    all_details = [inspect_entry(entry) for entry in dispatch["entries"]]
    unknown = [
        entry for entry in dispatch["entries"]
        if not entry.get("pc_width_candidates")
    ]
    details = [
        detail for detail in all_details
        if detail["opcode"] in {entry["opcode"] for entry in unknown}
    ]

    width_by_opcode = {}
    for entry in dispatch["entries"]:
        candidates = entry.get("pc_width_candidates", [])
        if len(candidates) == 1:
            width_by_opcode[entry["opcode"]] = candidates[0]["units"]

    call_target_stats = defaultdict(lambda: {
        "name": "",
        "known_widths": Counter(),
        "known_examples": [],
        "unknown_examples": [],
    })
    for detail in all_details:
        for call in detail.get("calls", []):
            target = call["target"]
            stats = call_target_stats[target]
            stats["name"] = call["name"]
            width = width_by_opcode.get(detail["opcode"])
            example = {"opcode": detail["opcode"], "handler": detail["handler"]}
            if width is None:
                if len(stats["unknown_examples"]) < 16:
                    stats["unknown_examples"].append(example)
            else:
                stats["known_widths"][width] += 1
                if len(stats["known_examples"]) < 16:
                    example["width"] = width
                    stats["known_examples"].append(example)

    groups = Counter()
    examples = defaultdict(list)
    for detail in details:
        signature = tuple(
            (call["target"], call["name"])
            for call in detail.get("calls", [])
        )
        if not signature:
            signature = ((None, "no_direct_calls"),)
        groups[signature] += 1
        if len(examples[signature]) < 12:
            examples[signature].append({
                "opcode": detail["opcode"],
                "handler": detail["handler"],
            })

    grouped = []
    for signature, count in groups.most_common():
        grouped.append({
            "count": count,
            "calls": [
                {"target": target, "name": name}
                for target, name in signature
            ],
            "examples": examples[signature],
        })

    payload = {
        "unknown_count": len(details),
        "groups": grouped,
        "call_target_stats": [
            {
                "target": target,
                "name": stats["name"],
                "known_widths": dict(sorted(stats["known_widths"].items())),
                "known_examples": stats["known_examples"],
                "unknown_examples": stats["unknown_examples"],
            }
            for target, stats in sorted(
                call_target_stats.items(),
                key=lambda item: (
                    -len(item[1]["unknown_examples"]),
                    item[0],
                ),
            )
            if stats["unknown_examples"]
        ],
        "details": details,
    }
    OUTPUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(OUTPUT),
        "unknown_count": len(details),
        "group_count": len(grouped),
    }, ensure_ascii=False))


main()
