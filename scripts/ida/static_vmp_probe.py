#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts" / "simulation"))

from unicorn_literal_decoder import LiteralDecoder


DEFAULT_RECOVERY = REPO_ROOT / "scripts" / "fix" / "dex" / "one_click_restore.py"
DEFAULT_STREAM_OUTPUT = ROOT / "vm_streams.json"


def parse_u8(value):
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFF:
        raise argparse.ArgumentTypeError("selector must be in range 0..255")
    return parsed


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_selector_evidence(path, selector, binary_sha256):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("confirmed") is not True:
        raise RuntimeError("selector evidence is not confirmed")
    if payload.get("selector") != selector:
        raise RuntimeError("selector evidence does not match --selector")
    if payload.get("binary_sha256") != binary_sha256:
        raise RuntimeError("selector evidence belongs to a different fixed SO")
    if payload.get("method_key_formula") != "ins_size^class_idx^registers_size^name_idx^selector^0x2c":
        raise RuntimeError("selector evidence has an unsupported method-key formula")
    confirmations = payload.get("runtime_method_confirmations")
    if not isinstance(confirmations, list) or len(confirmations) < 2:
        raise RuntimeError("selector evidence needs at least two runtime method confirmations")
    return payload


def load_recovery(path):
    spec = importlib.util.spec_from_file_location("static_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_width_map(path):
    dispatch = json.loads(path.read_text(encoding="utf-8"))
    widths = {}
    unresolved = {}
    for entry in dispatch["entries"]:
        candidates = entry.get("pc_width_candidates", [])
        if len(candidates) == 1:
            widths[entry["opcode"]] = candidates[0]["units"]
        else:
            unresolved[entry["opcode"]] = [
                candidate["units"] for candidate in candidates
            ]
    return widths, unresolved


def resolve_contextual_width(opcode, decoded, widths):
    if opcode == 14:
        # sub_83268 is called with W0=1. High-byte values 0 or 1 exit early;
        # larger values take the path that decodes units 2 and 3.
        return 1 if ((decoded >> 8) & 0xFF) <= 1 else 4
    if opcode == 46:
        # sub_83268 is called with W0=0. A nonzero unit-0 high nibble takes
        # the path that decodes units 2 and 3; zero exits without more units.
        return 4 if ((decoded >> 12) & 0xF) >= 1 else 1
    return widths.get(opcode)


def tile_method(raw_units, table_row, key, fvp_one, widths, unresolved,
                fetch_unit, operand_unit, index_unit, literal_decoder):
    pc = 0
    trace = []
    while pc < len(raw_units):
        decoded = fetch_unit(raw_units[pc], key, fvp_one)
        opcode = table_row[decoded & 0xFF]
        width = resolve_contextual_width(opcode, decoded, widths)
        if width is None:
            return {
                "success": False,
                "pc": pc,
                "opcode": opcode,
                "decoded_unit": f"{decoded:04x}",
                "width_candidates": unresolved.get(opcode, []),
                "reason": "ambiguous_width" if unresolved.get(opcode) else "unknown_width",
                "instruction_count": len(trace),
                "trace_prefix": trace[:64],
            }
        next_pc = pc + width
        available_width = min(width, len(raw_units) - pc)
        decoded_units = [decoded]
        literal_mode1 = None
        if available_width >= 2:
            decoded_units.append(operand_unit(raw_units[pc + 1], key, fvp_one))
        if available_width >= 3:
            if opcode == 198:
                literal_mode1 = literal_decoder.decode_unit(key, raw_units[pc + 2])
                decoded_units.append(int(literal_mode1["decoded_unit"], 16))
            else:
                decoded_units.append(index_unit(raw_units[pc + 2], key))
        trace_item = {
            "pc": pc,
            "opcode": opcode,
            "width": width,
            "raw_units": [f"{unit:04x}" for unit in raw_units[pc:pc + available_width]],
            "decoded_unit": f"{decoded:04x}",
            "decoded_units": [f"{unit:04x}" for unit in decoded_units],
            "decoded_units_complete": available_width <= 3,
        }
        if literal_mode1 is not None:
            trace_item["literal_mode1_unicorn"] = literal_mode1
        trace.append(trace_item)
        if next_pc > len(raw_units):
            return {
                "success": False,
                "pc": pc,
                "opcode": opcode,
                "width": width,
                "next_pc": next_pc,
                "reason": "final_pc_overflow",
                "instruction_count": len(trace),
                "trace_prefix": trace[:64],
            }
        pc = next_pc
    return {
        "success": pc == len(raw_units),
        "final_pc": pc,
        "instruction_count": len(trace),
        "trace": trace,
        "trace_prefix": trace[:64],
        "opcode_histogram": {
            str(opcode): sum(1 for item in trace if item["opcode"] == opcode)
            for opcode in sorted({item["opcode"] for item in trace})
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Probe dumped DEX VMP metadata without modifying DEX files")
    parser.add_argument("--recovery", type=Path, default=DEFAULT_RECOVERY)
    parser.add_argument("--shell", type=Path, required=True)
    parser.add_argument("--dex-dir", type=Path, required=True)
    parser.add_argument("--handler-map", type=Path, required=True)
    parser.add_argument("--outer", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--sim-config", type=Path, required=True)
    parser.add_argument("--selector", type=parse_u8, required=True)
    parser.add_argument("--selector-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stream-output", type=Path, required=True)
    parser.add_argument("--semantics-confirmed", action="store_true",
                        help="assert that opcode meanings were confirmed for this exact binary/table")
    args = parser.parse_args()

    recovery = load_recovery(args.recovery.resolve())
    literal_decoder = LiteralDecoder(
        args.outer.resolve(), args.linker.resolve(), args.sim_config.resolve()
    )
    widths, unresolved_widths = load_width_map(args.handler_map.resolve())
    binary_sha256 = sha256_file(args.linker.resolve())
    selector_evidence = load_selector_evidence(
        args.selector_evidence.resolve(), args.selector, binary_sha256
    )
    shell = args.shell.read_bytes()
    container = recovery.parse_qh_container(shell)
    table_key, seed_out = recovery.make_key(container["raw_config"], 222, 0)
    config_selector = args.selector

    report = {
        "shell": str(args.shell.resolve()),
        "raw_config_size": len(container["raw_config"]),
        "table_key": table_key.hex(),
        "seed_out": seed_out,
        "selector": config_selector,
        "selector_source": "runtime-evidence",
        "selector_evidence": str(args.selector_evidence.resolve()),
        "selector_evidence_sha256": sha256_file(args.selector_evidence.resolve()),
        "method_key_formula": selector_evidence["method_key_formula"],
        "dex_files": [],
    }
    for dex_path in sorted(args.dex_dir.glob("classes*.dex")):
        dex = dex_path.read_bytes()
        lm = recovery.parse_lm(dex)
        item = {"path": str(dex_path.resolve()), "size": len(dex), "has_lm": lm is not None}
        if lm is not None:
            table = recovery.rc4x(lm["table_cipher"], table_key)
            rows = len(table) // 256
            item.update({
                "lm_offset": lm["lm_off"],
                "lm_version": lm["version"],
                "xor_key": lm["xor_key"],
                "table_rows": rows,
                "permutation_rows": sum(
                    1 for row in range(rows)
                    if len(set(table[row * 256:(row + 1) * 256])) == 256
                ),
                "table_sha256": recovery.sha256(table),
                "records": [],
            })
            for record in lm["records"]:
                info = recovery.method_info(dex, record["method_idx"])
                code_off = record["code_off"]
                registers_size = recovery.u16(dex, code_off)
                ins_size = recovery.u16(dex, code_off + 2)
                insns_size = recovery.u32(dex, code_off + 12)
                code = recovery.checked(dex, code_off + 16, insns_size * 2, "VMP code units")
                raw_units = list(struct.unpack("<" + "H" * insns_size, code))
                base_key = (ins_size ^ info["class_idx"] ^ registers_size ^
                            info["name_idx"] ^ 0x2C) & 0xFF
                method_key = config_selector ^ base_key
                row_index = config_selector % rows
                table_row = table[row_index * 256:(row_index + 1) * 256]
                opcode_prefixes = {}
                width_tiling = {}
                for fvp_one in (True, False):
                    decoded_prefix = []
                    for unit in raw_units[:64]:
                        decoded = recovery.fetch_unit(unit, method_key, fvp_one)
                        decoded_prefix.append({
                            "unit": f"{decoded:04x}",
                            "vm_opcode": table_row[decoded & 0xFF],
                        })
                    opcode_prefixes[str(1 if fvp_one else 0)] = decoded_prefix
                    width_tiling[str(1 if fvp_one else 0)] = tile_method(
                        raw_units,
                        table_row,
                        method_key,
                        fvp_one,
                        widths,
                        unresolved_widths,
                        recovery.fetch_unit,
                        recovery.operand_unit,
                        recovery.index_unit,
                        literal_decoder,
                    )
                candidates = []
                for candidate_selector in range(256):
                    key = candidate_selector ^ base_key
                    candidate_row = candidate_selector % rows
                    candidate_table_row = table[candidate_row * 256:(candidate_row + 1) * 256]
                    for fvp_one in (True, False):
                        try:
                            _, trace = recovery.decode_vmp_candidate(
                                dex, raw_units, candidate_table_row, key, fvp_one, registers_size
                            )
                        except recovery.RecoveryError:
                            continue
                        candidates.append({
                            "selector": candidate_selector,
                            "row": candidate_row,
                            "key": key,
                            "fvp": 1 if fvp_one else 0,
                            "instruction_count": len(trace),
                        })
                item["records"].append({
                    **record,
                    "class": info["class"],
                    "method": info["name"],
                    "registers_size": registers_size,
                    "ins_size": ins_size,
                    "insns_size": insns_size,
                    "base_key": base_key,
                    "selector": config_selector,
                    "row": row_index,
                    "key": method_key,
                    "opcode_prefixes_by_fvp": opcode_prefixes,
                    "width_tiling_by_fvp": width_tiling,
                    "unique_width_fvp": [
                        int(fvp) for fvp, result in width_tiling.items()
                        if result["success"]
                    ],
                    "known_semantics_candidates": candidates,
                    "raw_prefix": [f"{unit:04x}" for unit in raw_units[:32]],
                })
        report["dex_files"].append(item)

    vmp_records = [
        record
        for dex_item in report["dex_files"]
        for record in dex_item.get("records", [])
    ]
    successful_fvp_sets = [set(record["unique_width_fvp"]) for record in vmp_records]
    global_valid_fvp = sorted(set.intersection(*successful_fvp_sets)) if successful_fvp_sets else []
    report["global_valid_fvp"] = global_valid_fvp

    stream_report = {
        "evidence": {
            "semantics_confirmed": args.semantics_confirmed,
            "binary_sha256": binary_sha256,
            "dispatch_sha256": sha256_file(args.handler_map.resolve()),
            "simulation_config_sha256": sha256_file(args.sim_config.resolve()),
        },
        "global_valid_fvp": global_valid_fvp,
        "literal_decoder": {
            "engine": "unicorn-arm64",
            "outer": str(args.outer.resolve()),
            "linker": str(args.linker.resolve()),
            "config": str(args.sim_config.resolve()),
            "interpreter_entry_rva": f"{literal_decoder.config['interpreter_wrap_rva']:x}",
        },
        "methods": [],
    }
    if len(global_valid_fvp) == 1:
        selected_fvp = global_valid_fvp[0]
        for record in vmp_records:
            selected = record["width_tiling_by_fvp"][str(selected_fvp)]
            record["selected_fvp"] = selected_fvp
            trace = selected["trace"]
            stream_report["methods"].append({
                "method_idx": record["method_idx"],
                "class": record["class"],
                "method": record["method"],
                "code_off": record["code_off"],
                "insns_size": record["insns_size"],
                "selector": record["selector"],
                "row": record["row"],
                "key": record["key"],
                "fvp": selected_fvp,
                "instruction_count": selected["instruction_count"],
                "used_opcodes": sorted({item["opcode"] for item in trace}),
                "instructions": trace,
            })

    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.stream_output.write_text(
        json.dumps(stream_report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output.resolve()),
        "stream_output": str(args.stream_output.resolve()),
        "table_key": table_key.hex(),
        "global_valid_fvp": global_valid_fvp,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
