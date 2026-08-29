#!/usr/bin/env python3
import argparse
import importlib.util
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_RECOVERY = ROOT / "one_click_restore.py"


def load_recovery(path):
    spec = importlib.util.spec_from_file_location("static_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signed(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def proto_descriptor(recovery, dex, proto_idx):
    count, table = recovery.u32(dex, 0x48), recovery.u32(dex, 0x4C)
    recovery.require(0 <= proto_idx < count, f"proto_idx 越界: {proto_idx}")
    off = table + proto_idx * 12
    return_type = recovery.type_descriptor(dex, recovery.u32(dex, off + 4))
    params_off = recovery.u32(dex, off + 8)
    params = []
    if params_off:
        size = recovery.u32(dex, params_off)
        recovery.checked(dex, params_off + 4, size * 2, "type_list")
        params = [
            recovery.type_descriptor(dex, recovery.u16(dex, params_off + 4 + idx * 2))
            for idx in range(size)
        ]
    return f"({''.join(params)}){return_type}"


def method_reference(recovery, dex, method_idx):
    info = recovery.method_info(dex, method_idx)
    return {
        "kind": "method",
        "index": method_idx,
        "class": info["class"],
        "name": info["name"],
        "descriptor": proto_descriptor(recovery, dex, info["proto_idx"]),
    }


def field_reference(recovery, dex, field_idx):
    count, table = recovery.u32(dex, 0x50), recovery.u32(dex, 0x54)
    recovery.require(0 <= field_idx < count, f"field_idx 越界: {field_idx}")
    off = table + field_idx * 8
    class_idx = recovery.u16(dex, off)
    type_idx = recovery.u16(dex, off + 2)
    name_idx = recovery.u32(dex, off + 4)
    return {
        "kind": "field",
        "index": field_idx,
        "class": recovery.type_descriptor(dex, class_idx),
        "name": recovery.dex_string(dex, name_idx),
        "descriptor": recovery.type_descriptor(dex, type_idx),
    }


def type_reference(recovery, dex, type_idx):
    return {
        "kind": "type",
        "index": type_idx,
        "descriptor": recovery.type_descriptor(dex, type_idx),
    }


def string_reference(recovery, dex, string_idx):
    return {
        "kind": "string",
        "index": string_idx,
        "value": recovery.dex_string(dex, string_idx),
    }


def field_opcode(family, descriptor):
    suffix = {
        "J": ("wide", 1),
        "D": ("wide", 1),
        "L": ("object", 2),
        "[": ("object", 2),
        "Z": ("boolean", 3),
        "B": ("byte", 4),
        "C": ("char", 5),
        "S": ("short", 6),
    }.get(descriptor[:1], (None, 0))
    names = {"iget": 0x52, "iput": 0x59, "sput": 0x67}
    name = family if suffix[0] is None else f"{family}-{suffix[0]}"
    return name, names[family] + suffix[1]


def decode_35c_registers(unit0, unit2):
    count = (unit0 >> 12) & 0xF
    registers = [
        unit2 & 0xF,
        (unit2 >> 4) & 0xF,
        (unit2 >> 8) & 0xF,
        (unit2 >> 12) & 0xF,
        (unit0 >> 8) & 0xF,
    ]
    return registers[:count]


def enrich_instruction(recovery, dex, item):
    opcode = item["opcode"]
    units = [int(value, 16) for value in item["decoded_units"]]
    unit0 = units[0]
    result = dict(item)
    result["operands"] = {}

    if opcode == 7:
        result.update(kind="const/4", dalvik_opcode=0x12)
        result["operands"] = {"dest": (unit0 >> 8) & 0xF, "literal": signed(unit0 >> 12, 4)}
    elif opcode == 26:
        result.update(kind="new-instance", dalvik_opcode=0x22)
        result["operands"] = {"dest": unit0 >> 8, "type_idx": units[1]}
        result["reference"] = type_reference(recovery, dex, units[1])
    elif opcode == 35:
        result["operands"] = {"value": (unit0 >> 8) & 0xF, "object": unit0 >> 12, "field_idx": units[1]}
        result["reference"] = field_reference(recovery, dex, units[1])
        kind, dalvik_opcode = field_opcode("iput", result["reference"]["descriptor"])
        result.update(kind=kind, dalvik_opcode=dalvik_opcode)
    elif opcode == 36:
        result.update(kind="aput-object", dalvik_opcode=0x4D)
        result["operands"] = {"value": unit0 >> 8, "array": units[1] & 0xFF, "index": units[1] >> 8}
    elif opcode == 38:
        result.update(kind="move-object", dalvik_opcode=0x07)
        result["operands"] = {"dest": (unit0 >> 8) & 0xF, "source": unit0 >> 12}
    elif opcode in (39, 86, 160, 233):
        modes = {
            39: ("invoke-direct", 0x70),
            86: ("invoke-super", 0x6F),
            160: ("invoke-static", 0x71),
            233: ("invoke-virtual", 0x6E),
        }
        result.update(kind=modes[opcode][0], dalvik_opcode=modes[opcode][1])
        result["operands"] = {
            "method_idx": units[1],
            "registers": decode_35c_registers(unit0, units[2]),
        }
        result["reference"] = method_reference(recovery, dex, units[1])
    elif opcode == 49:
        result.update(kind="if-eqz", dalvik_opcode=0x38)
        result["operands"] = {"register": unit0 >> 8, "offset": signed(units[1], 16)}
    elif opcode == 60:
        result.update(kind="goto", dalvik_opcode=0x28)
        result["operands"] = {"offset": signed(unit0 >> 8, 8)}
    elif opcode == 73:
        result.update(kind="const/16", dalvik_opcode=0x13)
        result["operands"] = {"dest": unit0 >> 8, "literal": signed(units[1], 16)}
    elif opcode == 100:
        result.update(kind="check-cast", dalvik_opcode=0x1F)
        result["operands"] = {"register": unit0 >> 8, "type_idx": units[1]}
        result["reference"] = type_reference(recovery, dex, units[1])
    elif opcode == 121:
        result.update(kind="mul-float/2addr", dalvik_opcode=0xC8)
        result["operands"] = {"dest": (unit0 >> 8) & 0xF, "source": unit0 >> 12}
    elif opcode == 123:
        result.update(kind="return-void", dalvik_opcode=0x0E)
    elif opcode == 140:
        result.update(kind="new-array", dalvik_opcode=0x23)
        result["operands"] = {
            "dest": (unit0 >> 8) & 0xF,
            "size": unit0 >> 12,
            "type_idx": units[1],
        }
        result["reference"] = type_reference(recovery, dex, units[1])
    elif opcode == 157:
        result["operands"] = {"dest": (unit0 >> 8) & 0xF, "object": unit0 >> 12, "field_idx": units[1]}
        result["reference"] = field_reference(recovery, dex, units[1])
        kind, dalvik_opcode = field_opcode("iget", result["reference"]["descriptor"])
        result.update(kind=kind, dalvik_opcode=dalvik_opcode)
    elif opcode == 166:
        result.update(kind="float-to-int", dalvik_opcode=0x87)
        result["operands"] = {"dest": (unit0 >> 8) & 0xF, "source": unit0 >> 12}
    elif opcode == 172:
        result.update(kind="if-nez", dalvik_opcode=0x39)
        result["operands"] = {"register": unit0 >> 8, "offset": signed(units[1], 16)}
    elif opcode == 175:
        result.update(kind="const-string", dalvik_opcode=0x1A)
        result["operands"] = {"dest": unit0 >> 8, "string_idx": units[1]}
        result["reference"] = string_reference(recovery, dex, units[1])
    elif opcode == 188:
        result.update(kind="int-to-float", dalvik_opcode=0x82)
        result["operands"] = {"dest": (unit0 >> 8) & 0xF, "source": unit0 >> 12}
    elif opcode == 192:
        result.update(kind="move-result-object", dalvik_opcode=0x0C)
        result["operands"] = {"dest": unit0 >> 8}
    elif opcode == 198:
        result.update(kind="const", dalvik_opcode=0x14)
        literal_unsigned = (units[2] << 16) | units[1]
        result["operands"] = {
            "dest": unit0 >> 8,
            "literal": signed(literal_unsigned, 32),
            "literal_unsigned": literal_unsigned,
            "literal_hex": f"{literal_unsigned:08x}",
        }
    elif opcode == 222:
        result.update(kind="move-result", dalvik_opcode=0x0A)
        result["operands"] = {"dest": unit0 >> 8}
    elif opcode == 244:
        result.update(kind="const/high16", dalvik_opcode=0x15)
        result["operands"] = {"dest": unit0 >> 8, "literal": signed(units[1] << 16, 32)}
    else:
        result.update(kind="unresolved", dalvik_opcode=None)
    return result


def main():
    parser = argparse.ArgumentParser(description="Resolve static VM stream operands and DEX references")
    parser.add_argument("--recovery", type=Path, default=DEFAULT_RECOVERY)
    parser.add_argument("--probe", type=Path, default=ROOT / "static_probe.json")
    parser.add_argument("--streams", type=Path, default=ROOT / "vm_streams.json")
    parser.add_argument("--output", type=Path, default=ROOT / "vm_streams_enriched.json")
    args = parser.parse_args()

    recovery = load_recovery(args.recovery.resolve())
    probe = json.loads(args.probe.read_text(encoding="utf-8"))
    streams = json.loads(args.streams.read_text(encoding="utf-8"))
    locations = {}
    for dex_item in probe["dex_files"]:
        for record in dex_item.get("records", []):
            locations[(record["class"], record["method"], record["method_idx"])] = dex_item["path"]

    enriched = dict(streams)
    enriched["methods"] = []
    for method in streams["methods"]:
        key = (method["class"], method["method"], method["method_idx"])
        dex_path = Path(locations[key])
        dex = dex_path.read_bytes()
        output_method = dict(method)
        output_method["dex_path"] = str(dex_path)
        output_method["instructions"] = [
            enrich_instruction(recovery, dex, item) for item in method["instructions"]
        ]
        enriched["methods"].append(output_method)

    args.output.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "methods": len(enriched["methods"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
