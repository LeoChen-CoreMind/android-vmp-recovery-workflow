#!/usr/bin/env python3
"""Build case-bound Dalvik streams from the current inventory and semantic map.

This command deliberately has no historical opcode fallback.  Every VM opcode
used by the inventory must be present in the case-specific semantic map.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_RECOVERY = ROOT / "one_click_restore.py"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_recovery(path: Path):
    spec = importlib.util.spec_from_file_location("case_recovery", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fail(message: str) -> None:
    raise ValueError(message)


def signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def mode1_unit(raw: int, key: int) -> int:
    raw &= 0xFFFF
    key &= 0xFF
    high_delta = ((raw >> 8) - 58 - key) & 0xFFFFFFFF
    low_delta = ((raw & 0xFF) - 58 - key) & 0xFFFFFFFF
    high_mask = 0xB7 if high_delta & 0x40 else 0xB2
    low_mask = 0xB7 if low_delta & 0x40 else 0xB2
    transformed = (((high_delta ^ high_mask) & 0xFF) << 8) | (
        (low_delta ^ low_mask) & 0xFF
    )
    return ((key | (key << 8)) ^ transformed) & 0xFFFF


def proto_words(recovery, dex: bytes, proto_idx: int) -> int:
    count = recovery.u32(dex, 0x48)
    table = recovery.u32(dex, 0x4C)
    if not 0 <= proto_idx < count:
        fail(f"proto_idx out of range: {proto_idx}")
    params_off = recovery.u32(dex, table + proto_idx * 12 + 8)
    if not params_off:
        return 0
    size = recovery.u32(dex, params_off)
    words = 0
    for index in range(size):
        descriptor = recovery.type_descriptor(dex, recovery.u16(dex, params_off + 4 + index * 2))
        words += 2 if descriptor[:1] in {"J", "D"} else 1
    return words


def method_reference(recovery, dex: bytes, index: int) -> dict:
    info = recovery.method_info(dex, index)
    return {
        "kind": "method", "index": index, "class": info["class"],
        "name": info["name"], "descriptor": info["proto_idx"],
        "parameter_words": proto_words(recovery, dex, info["proto_idx"]),
    }


def field_reference(recovery, dex: bytes, index: int) -> dict:
    count, table = recovery.u32(dex, 0x50), recovery.u32(dex, 0x54)
    if not 0 <= index < count:
        fail(f"field_idx out of range: {index}")
    off = table + index * 8
    return {
        "kind": "field", "index": index,
        "class": recovery.type_descriptor(dex, recovery.u16(dex, off)),
        "descriptor": recovery.type_descriptor(dex, recovery.u16(dex, off + 2)),
        "name": recovery.dex_string(dex, recovery.u32(dex, off + 4)),
    }


def type_reference(recovery, dex: bytes, index: int) -> dict:
    return {"kind": "type", "index": index,
            "descriptor": recovery.type_descriptor(dex, index)}


def string_reference(recovery, dex: bytes, index: int) -> dict:
    return {"kind": "string", "index": index,
            "value": recovery.dex_string(dex, index)}


def parse_unit(value: str) -> int:
    return int(value, 16)


def regs_35c(first: int, packed: int) -> list[int]:
    count = (first >> 12) & 0xF
    if count > 5:
        fail(f"35c register count out of range: {count}")
    return [packed & 0xF, (packed >> 4) & 0xF, (packed >> 8) & 0xF,
            (packed >> 12) & 0xF, (first >> 8) & 0xF][:count]


def expected_invoke_register_words(kind: str, parameter_words: int) -> int:
    static_kinds = {"invoke-static", "invoke-static/range"}
    receiver_kinds = {
        "invoke-direct", "invoke-direct/range",
        "invoke-interface", "invoke-interface/range",
        "invoke-super", "invoke-super/range",
        "invoke-virtual", "invoke-virtual/range",
    }
    if kind in static_kinds:
        return parameter_words
    if kind in receiver_kinds:
        return parameter_words + 1
    fail(f"unsupported invoke kind: {kind}")


def enrich_instruction(recovery, dex: bytes, method: dict, item: dict,
                       semantic: dict, occurrence: dict | None,
                       literal_helper_rva: str | None) -> dict:
    vm_opcode = int(item["opcode"])
    width = int(item["width"])
    raw = [parse_unit(value) for value in item["raw_units"]]
    if len(raw) != width:
        fail(f"method {method['method_idx']} pc {item['pc']}: unit width mismatch")
    if occurrence is not None:
        if occurrence.get("dex_sha256") != method["dex_sha256"] or occurrence.get("pc") != item["pc"]:
            fail(f"method {method['method_idx']} pc {item['pc']}: candidate matrix mismatch")
    fmt = semantic["format"]
    key = int(method["key"])
    fvp_one = bool(method["fvp"])
    decoded = [parse_unit(item["decoded_unit"])]
    if width >= 2:
        decoded.append(recovery.operand_unit(raw[1], key, fvp_one))
    if width >= 3:
        decoded.append(recovery.index_unit(raw[2], key) if fmt in {"35c", "3rc"}
                        else mode1_unit(raw[2], key))
    result = {
        "pc": int(item["pc"]), "opcode": vm_opcode, "vm_opcode": vm_opcode,
        "width": width, "raw_units": [f"{v:04x}" for v in raw],
        "decoded_units": [f"{v:04x}" for v in decoded],
        "decoded_units_complete": True, "handler_rva": semantic["handler_rva"],
        "format": fmt, "kind": semantic["kind"],
        "dalvik_opcode": int(semantic["dalvik_opcode"]), "operands": {},
    }
    unit0 = decoded[0]
    op1 = recovery.operand_unit(raw[1], key, fvp_one) if width >= 2 else None
    op2_index = recovery.index_unit(raw[2], key) if width >= 3 and fmt in {"35c", "3rc"} else None
    op2_mode1 = mode1_unit(raw[2], key) if width >= 3 and fmt == "31i" else None
    high = (unit0 >> 8) & 0xFF
    registers_size = int(method["registers_size"])

    def reg_check(value: int, label: str) -> None:
        if not 0 <= value < registers_size:
            fail(f"method {method['method_idx']} pc {item['pc']}: {label} register {value} out of range")

    if fmt == "11n":
        reg_check(high & 0xF, "dest")
        result["operands"] = {"dest": high & 0xF, "literal": signed((unit0 >> 12) & 0xF, 4)}
    elif fmt in {"10x"}:
        if width != 1:
            fail("10x width mismatch")
    elif fmt == "12x":
        reg_check(high & 0xF, "dest")
        reg_check(high >> 4, "source")
        result["operands"] = {"dest": high & 0xF, "source": high >> 4}
    elif fmt == "11x":
        reg_check(high, "dest")
        result["operands"] = {"dest": high}
    elif fmt in {"21c-field", "21c-type", "21c-string", "21s", "21h", "21t"}:
        reg_check(high, "register")
        if op1 is None:
            fail("missing unit1")
        result["operands"] = {"register": high, "unit1": op1}
        if fmt.endswith("field"):
            result["reference"] = field_reference(recovery, dex, op1)
            result["operands"]["field_idx"] = op1
        elif fmt.endswith("type"):
            result["reference"] = type_reference(recovery, dex, op1)
            result["operands"]["type_idx"] = op1
        elif fmt.endswith("string"):
            result["reference"] = string_reference(recovery, dex, op1)
            result["operands"]["string_idx"] = op1
        elif fmt == "21s":
            result["operands"]["literal"] = signed(op1, 16)
        elif fmt == "21h":
            result["operands"]["literal"] = signed(op1 << 16, 32)
        else:
            result["operands"]["offset"] = signed(op1, 16)
    elif fmt in {"22c-field", "22c-type", "22t"}:
        if op1 is None:
            fail("missing unit1")
        reg_a, reg_b = high & 0xF, high >> 4
        reg_check(reg_a, "A")
        reg_check(reg_b, "B")
        result["operands"] = {"a": reg_a, "b": reg_b, "unit1": op1}
        if fmt == "22t":
            result["operands"]["offset"] = signed(op1, 16)
        elif fmt.endswith("field"):
            result["reference"] = field_reference(recovery, dex, op1)
            result["operands"]["field_idx"] = op1
        else:
            result["reference"] = type_reference(recovery, dex, op1)
            result["operands"]["type_idx"] = op1
    elif fmt == "23x":
        if op1 is None:
            fail("missing unit1")
        reg_a, reg_b, reg_c = high, op1 & 0xFF, op1 >> 8
        for label, value in (("A", reg_a), ("B", reg_b), ("C", reg_c)):
            reg_check(value, label)
        result["operands"] = {"a": reg_a, "b": reg_b, "c": reg_c}
    elif fmt == "35c":
        if op1 is None or op2_index is None:
            fail("missing invoke units")
        info = recovery.method_info(dex, op1)
        parameter_words = proto_words(recovery, dex, info["proto_idx"])
        expected = expected_invoke_register_words(semantic["kind"], parameter_words)
        regs = regs_35c(unit0, op2_index)
        if len(regs) != expected:
            fail(
                f"method {method['method_idx']} pc {item['pc']}: "
                f"{semantic['kind']} register words {len(regs)} != {expected}"
            )
        for value in regs:
            reg_check(value, "invoke")
        result["reference"] = method_reference(recovery, dex, op1)
        result["operands"] = {"method_idx": op1, "registers": regs}
    elif fmt == "3rc":
        if op1 is None or op2_index is None:
            fail("missing range invoke units")
        info = recovery.method_info(dex, op1)
        parameter_words = proto_words(recovery, dex, info["proto_idx"])
        expected = expected_invoke_register_words(semantic["kind"], parameter_words)
        count = high
        start = op2_index
        if count != expected or start + count > registers_size:
            fail(
                f"method {method['method_idx']} pc {item['pc']}: "
                f"{semantic['kind']} range words/bounds invalid "
                f"(count={count}, expected={expected}, start={start}, "
                f"registers={registers_size})"
            )
        result["reference"] = method_reference(recovery, dex, op1)
        result["operands"] = {"method_idx": op1, "start": start, "count": count}
    elif fmt == "10t":
        result["operands"] = {"offset": signed((unit0 >> 8) & 0xFF, 8)}
    elif fmt == "31i":
        if op1 is None or op2_mode1 is None:
            fail("missing const/32 units")
        reg_check(high, "dest")
        literal_unsigned = op1 | (op2_mode1 << 16)
        result["operands"] = {"dest": high, "literal": signed(literal_unsigned, 32),
                               "literal_unsigned": literal_unsigned,
                               "literal_hex": f"{literal_unsigned:08x}"}
        if not literal_helper_rva:
            fail("semantic map is missing decoder.literal32_helper_rva")
        result["literal_mode1_unicorn"] = {
            "engine": "pending-case-native-confirmation",
            "method_key": int(method["key"]), "raw_unit": f"{raw[2]:04x}",
            "decoded_unit": f"{op2_mode1:04x}", "helper_rva": literal_helper_rva,
        }
    else:
        fail(f"unsupported case semantic format: {fmt}")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve current-case VM streams using semantic evidence")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--semantic-map", type=Path, required=True)
    parser.add_argument("--candidate-matrix", type=Path, required=True)
    parser.add_argument("--dispatch", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sim-config", type=Path, required=True,
                        help="case-specific native simulation config whose hash is bound")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--recovery", type=Path, default=DEFAULT_RECOVERY)
    args = parser.parse_args()

    recovery = load_recovery(args.recovery.resolve())
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    semantic_map = json.loads(args.semantic_map.read_text(encoding="utf-8"))
    matrix = json.loads(args.candidate_matrix.read_text(encoding="utf-8"))
    dispatch = json.loads(args.dispatch.read_text(encoding="utf-8"))
    if semantic_map.get("semantics_confirmed") is not True:
        fail("semantic map is not confirmed")
    if semantic_map.get("fixed_so_sha256") != sha256_file(args.binary):
        fail("semantic map fixed SO hash mismatch")
    if semantic_map.get("dispatch_sha256") != sha256_file(args.dispatch):
        fail("semantic map dispatch hash mismatch")
    if not args.sim_config.is_file():
        fail(f"simulation config does not exist: {args.sim_config}")
    entries = dispatch.get("entries", [])
    if len(entries) != 256 or {int(x.get("opcode", -1)) for x in entries} != set(range(256)):
        fail("dispatch is not a complete 256-entry map")
    semantics = {int(k): value for k, value in semantic_map.get("opcodes", {}).items()}
    literal_helper_rva = semantic_map.get("decoder", {}).get("literal32_helper_rva")
    matrix_occ = {(int(x["method_idx"]), int(x["pc"])): x for x in matrix.get("occurrences", [])}
    used = {int(x) for x in inventory.get("used_opcodes", [])}
    if used != set(semantics):
        fail(f"semantic map opcode coverage mismatch: missing={sorted(used-set(semantics))} extra={sorted(set(semantics)-used)}")

    methods = []
    literal_requests = []
    for source in inventory["methods"]:
        dex_path = Path(source["dex"]).resolve()
        dex = dex_path.read_bytes()
        if sha256_file(dex_path) != source["dex_sha256"]:
            fail(f"DEX hash mismatch: {dex_path}")
        boundaries = {int(x["pc"]) for x in source["instructions"]}
        boundaries.add(int(source["insns_size"]))
        output = {key: source[key] for key in ("dex", "dex_sha256", "method_idx", "class", "method",
                                                "code_off", "registers_size", "ins_size", "insns_size",
                                                "selector", "row", "key", "fvp")}
        output["dex_path"] = str(dex_path)
        output["instructions"] = []
        expected_pc = 0
        for item in source["instructions"]:
            pc = int(item["pc"])
            if pc != expected_pc:
                fail(f"method {source['method_idx']}: non-contiguous PC at {pc}, expected {expected_pc}")
            vm_opcode = int(item["opcode"])
            semantic = semantics.get(vm_opcode)
            if semantic is None or int(semantic["width"]) != int(item["width"]):
                fail(f"method {source['method_idx']} pc {pc}: semantic width/opcode mismatch")
            enriched = enrich_instruction(recovery, dex, source, item, semantic,
                                           matrix_occ.get((int(source["method_idx"]), pc)),
                                           literal_helper_rva)
            fmt = semantic["format"]
            if fmt in {"10t", "21t", "22t"}:
                target = pc + int(enriched["operands"]["offset"])
                if target not in boundaries:
                    fail(f"method {source['method_idx']} pc {pc}: branch target {target} is not an instruction boundary")
                enriched["branch_target"] = target
            if vm_opcode == 98:
                literal_requests.append({"method_idx": source["method_idx"], "pc": pc,
                                         **enriched["literal_mode1_unicorn"]})
            output["instructions"].append(enriched)
            expected_pc += int(item["width"])
        if expected_pc != int(source["insns_size"]):
            fail(f"method {source['method_idx']}: final PC {expected_pc} != insns_size")
        output["instruction_count"] = len(output["instructions"])
        methods.append(output)

    payload = {
        "schema_version": 2, "source": "case-specific-inventory-semantic-map",
        "global_valid_fvp": sorted({int(m["fvp"]) for m in methods}),
        "methods": methods,
        "literal_decoder": {
            "engine": "pending-case-native-confirmation",
            "helper_rva": literal_helper_rva,
            "requests": literal_requests,
        },
        "evidence": {
            "semantics_confirmed": True,
            "binary_sha256": sha256_file(args.binary),
            "dispatch_sha256": sha256_file(args.dispatch),
            "simulation_config_sha256": sha256_file(args.sim_config),
        },
        "provenance": {
            "inventory": str(args.inventory.resolve()), "inventory_sha256": sha256_file(args.inventory),
            "semantic_map": str(args.semantic_map.resolve()), "semantic_map_sha256": sha256_file(args.semantic_map),
            "candidate_matrix": str(args.candidate_matrix.resolve()), "candidate_matrix_sha256": sha256_file(args.candidate_matrix),
            "binary": str(args.binary.resolve()), "binary_sha256": sha256_file(args.binary),
            "dispatch": str(args.dispatch.resolve()), "dispatch_sha256": sha256_file(args.dispatch),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "methods": len(methods),
                      "instructions": sum(m["instruction_count"] for m in methods),
                      "literal_requests": len(literal_requests)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
