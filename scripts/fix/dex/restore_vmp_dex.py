#!/usr/bin/env python3
import argparse
import importlib.util
import json
import struct
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_RECOVERY = ROOT / "one_click_restore.py"


def load_recovery(path):
    spec = importlib.util.spec_from_file_location("static_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rebuild_method_units(recovery, dex, method):
    code_off = method["code_off"]
    insns_size = recovery.u32(dex, code_off + 12)
    recovery.require(insns_size == method["insns_size"], "insns_size 与恢复流不一致")
    raw = recovery.checked(dex, code_off + 16, insns_size * 2, "VMP code units")
    source_units = list(struct.unpack("<" + "H" * insns_size, raw))

    expected_raw = []
    restored = []
    for instruction in method["instructions"]:
        recovery.require(instruction["decoded_units_complete"], "存在未闭合的解码单元")
        dalvik_opcode = instruction.get("dalvik_opcode")
        recovery.require(isinstance(dalvik_opcode, int), "存在未解析的 Dalvik opcode")
        raw_units = [int(value, 16) for value in instruction["raw_units"]]
        decoded_units = [int(value, 16) for value in instruction["decoded_units"]]
        recovery.require(
            len(raw_units) == instruction["width"] == len(decoded_units),
            "指令宽度与 code unit 数量不一致",
        )
        expected_raw.extend(raw_units)
        restored.append((decoded_units[0] & 0xFF00) | dalvik_opcode)
        restored.extend(decoded_units[1:])

    recovery.require(expected_raw == source_units, "源 DEX code units 与恢复取证记录不一致")
    recovery.require(len(restored) == insns_size, "恢复后的 code unit 数量变化")
    return restored


def restore_dex(recovery, source_path, methods, output_path):
    source = source_path.read_bytes()
    patched = bytearray(source)
    method_reports = []

    for method in methods:
        info = recovery.method_info(source, method["method_idx"])
        recovery.require(info["class"] == method["class"], "方法 class 与恢复流不一致")
        recovery.require(info["name"] == method["method"], "方法名与恢复流不一致")
        restored_units = rebuild_method_units(recovery, source, method)

        fields = recovery.find_method_field(source, method["method_idx"], info["class_idx"])
        recovery.require(
            fields["access"] & recovery.ACC_NATIVE and fields["code_off"] == 0,
            "目标方法不是 native/code_off=0 状态",
        )
        replacement = (
            recovery.encode_uleb(fields["access"] & ~recovery.ACC_NATIVE)
            + recovery.encode_uleb(method["code_off"])
        )
        old_len = fields["access_len"] + fields["code_len"]
        recovery.require(len(replacement) == old_len, "class_data 原地修补长度变化")
        patched[fields["access_off"]:fields["access_off"] + old_len] = replacement

        restored_code = struct.pack("<" + "H" * len(restored_units), *restored_units)
        start = method["code_off"] + 16
        patched[start:start + len(restored_code)] = restored_code
        method_reports.append({
            "method_idx": method["method_idx"],
            "class": method["class"],
            "method": method["method"],
            "code_off": method["code_off"],
            "instruction_count": method["instruction_count"],
            "code_units": len(restored_units),
            "source_units_verified": True,
        })

    final = recovery.repair_dex(bytes(patched))
    validation = recovery.validate_dex(final)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(final)
    return {
        "source": str(source_path.resolve()),
        "source_sha256": recovery.sha256(source),
        "output": str(output_path.resolve()),
        "methods": method_reports,
        **validation,
    }


def main():
    parser = argparse.ArgumentParser(
        description="回写经 Unicorn 原生解释器验证的 360 DexVMP Dalvik 指令"
    )
    parser.add_argument("--recovery", type=Path, default=DEFAULT_RECOVERY)
    parser.add_argument("--streams", type=Path, default=ROOT / "vm_streams_enriched.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "recovered_dex")
    parser.add_argument("--manifest", type=Path, default=ROOT / "vmp_restore_manifest.json")
    args = parser.parse_args()

    recovery = load_recovery(args.recovery.resolve())
    streams = json.loads(args.streams.read_text(encoding="utf-8"))
    recovery.require(streams.get("global_valid_fvp") == [1], "全局 FVP 不是唯一的 mode=1")
    recovery.require(
        streams.get("literal_decoder", {}).get("engine") == "unicorn-arm64",
        "const/32 高半部没有 Unicorn 取证标记",
    )

    grouped = defaultdict(list)
    for method in streams["methods"]:
        grouped[Path(method["dex_path"])].append(method)
    recovery.require(grouped, "恢复流中没有 VMP 方法")

    outputs = []
    for source_path, methods in sorted(grouped.items(), key=lambda item: str(item[0])):
        output_path = args.output_dir / f"{source_path.stem}_unicorn_restored.dex"
        outputs.append(restore_dex(recovery, source_path, methods, output_path))

    manifest = {
        "decoder": streams["literal_decoder"],
        "global_valid_fvp": streams["global_valid_fvp"],
        "outputs": outputs,
    }
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "manifest": str(args.manifest.resolve()),
        "outputs": [item["output"] for item in outputs],
        "methods": sum(len(item["methods"]) for item in outputs),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
