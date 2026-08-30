#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import zlib
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree

from jsonschema import Draft202012Validator


ANDROID_NS = "http://schemas.android.com/apk/res/android"
ElementTree.register_namespace("android", ANDROID_NS)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], cwd: Path | None = None, timeout: int = 1800) -> dict[str, Any]:
    actual = command
    if os.name == "nt" and command and Path(command[0]).suffix.lower() in {".bat", ".cmd"}:
        actual = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", subprocess.list2cmdline(command)]
    completed = subprocess.run(
        actual, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    result = {"command": command, "returncode": completed.returncode,
              "stdout": completed.stdout, "stderr": completed.stderr}
    if completed.returncode:
        raise RuntimeError(json.dumps(result, ensure_ascii=False))
    return result


def decoded_path(root: Path, zip_name: str) -> Path:
    pure = PurePosixPath(zip_name)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ValueError(f"unsafe APK entry path: {zip_name}")
    path = root.joinpath(*pure.parts).resolve()
    path.relative_to(root.resolve())
    return path


def patch_dex(source: Path, target_name: str, adapter: dict[str, Any]) -> bytes:
    data = bytearray(source.read_bytes())
    if not data.startswith(b"dex\n"):
        raise ValueError(f"not a DEX file: {source}")
    for replacement in adapter["bridge_contracts"]["descriptor_replacements"]:
        if target_name not in replacement["targets"]:
            continue
        old = replacement["old"].encode("ascii")
        new = replacement["new"].encode("ascii")
        if len(old) != len(new):
            raise ValueError(f"descriptor replacement changes length: {replacement['old']}")
        count = data.count(old)
        if count != replacement["expected_occurrences"]:
            raise ValueError(
                f"{target_name} descriptor {replacement['old']} expected "
                f"{replacement['expected_occurrences']} occurrences, found {count}"
            )
        data[:] = data.replace(old, new)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def restore_manifest(path: Path, adapter: dict[str, Any]) -> dict[str, Any]:
    tree = ElementTree.parse(path)
    root = tree.getroot()
    application = root.find("application")
    if application is None:
        raise ValueError("decoded manifest has no application element")
    updates = {
        "name": adapter["manifest"]["application"]["value"],
        "appComponentFactory": adapter["manifest"]["app_component_factory"]["value"],
    }
    for name, value in updates.items():
        key = f"{{{ANDROID_NS}}}{name}"
        if value is None:
            application.attrib.pop(key, None)
        else:
            application.set(key, value)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return updates


def prepare_decoded_tree(source_apk: Path, adapter: dict[str, Any], decoded: Path,
                         apktool: str) -> dict[str, Any]:
    if decoded.exists():
        raise ValueError(f"work directory already exists: {decoded}")
    decode = run([apktool, "d", "-f", "-s", "-o", str(decoded), str(source_apk)])
    removed = []
    for name in adapter["remove_entries"]:
        path = decoded_path(decoded, name)
        if not path.is_file():
            raise ValueError(f"declared shell entry was not decoded: {name}")
        path.unlink()
        removed.append(name)

    cleared_signatures = []
    for relative in ("META-INF", "original/META-INF"):
        path = decoded_path(decoded, relative)
        if path.is_dir():
            shutil.rmtree(path)
            cleared_signatures.append(relative)

    for path in decoded.glob("classes*.dex"):
        if path.is_file():
            path.unlink()
    dex_outputs = []
    dex_targets = {mapping["target"] for mapping in adapter["dex_layout"]}
    unsupported_replacements = sorted(
        item["name"] for item in adapter["replace_entries"] if item["name"] not in dex_targets
    )
    if unsupported_replacements:
        raise ValueError(
            "reference executor only supports same-path DEX replacements; provide a custom executor for: "
            + ", ".join(unsupported_replacements)
        )
    for mapping in adapter["dex_layout"]:
        source = Path(mapping["source"]).expanduser().resolve()
        if sha256_file(source) != mapping["source_sha256"]:
            raise ValueError(f"source DEX hash mismatch: {source}")
        data = patch_dex(source, mapping["target"], adapter)
        output_hash = hashlib.sha256(data).hexdigest()
        if output_hash != mapping["output_sha256"]:
            raise ValueError(
                f"output DEX hash mismatch for {mapping['target']}: "
                f"expected={mapping['output_sha256']} actual={output_hash}"
            )
        target = decoded_path(decoded, mapping["target"])
        target.write_bytes(data)
        dex_outputs.append({"target": mapping["target"], "sha256": output_hash, "size": len(data)})
    manifest = restore_manifest(decoded / "AndroidManifest.xml", adapter)
    return {"decode": decode, "removed_entries": removed,
            "cleared_old_signature_directories": cleared_signatures,
            "dex_outputs": dex_outputs, "manifest": manifest}


def validate_adapter(adapter: dict[str, Any], schema: Path) -> None:
    payload = json.loads(schema.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(payload).iter_errors(adapter),
        key=lambda item: tuple(str(part) for part in item.path),
    )
    if errors:
        raise ValueError("; ".join(error.message for error in errors[:20]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Reference executor for a version-bound 360 APK repack adapter")
    parser.add_argument("--source-apk", required=True, type=Path)
    parser.add_argument("--adapter", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--key-alias", required=True)
    parser.add_argument("--ks-pass-env", default="APK_REPACK_KS_PASS")
    parser.add_argument("--key-pass-env", default="APK_REPACK_KEY_PASS")
    parser.add_argument("--apktool", default="apktool")
    parser.add_argument("--zipalign", default="zipalign")
    parser.add_argument("--apksigner", default="apksigner")
    args = parser.parse_args()

    adapter = json.loads(args.adapter.read_text(encoding="utf-8"))
    validate_adapter(adapter, args.schema)
    source_apk = args.source_apk.resolve()
    if sha256_file(source_apk) != adapter["apk_sha256"]:
        raise ValueError("source APK SHA-256 does not match adapter")
    for name in (args.ks_pass_env, args.key_pass_env):
        if name not in os.environ:
            raise ValueError(f"required signing password environment variable is missing: {name}")

    work_dir = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=False)
    decoded = work_dir / "decoded"
    prepared = prepare_decoded_tree(source_apk, adapter, decoded, args.apktool)
    unsigned = work_dir / "unsigned.apk"
    aligned = work_dir / "aligned.apk"
    build = run([args.apktool, "b", str(decoded), "-o", str(unsigned)])
    align = run([args.zipalign, "-f", "-P", "16", "4", str(unsigned), str(aligned)])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sign = run([
        args.apksigner, "sign", "--ks", str(args.keystore.resolve()),
        "--ks-key-alias", args.key_alias, "--ks-pass", f"env:{args.ks_pass_env}",
        "--key-pass", f"env:{args.key_pass_env}", "--out", str(args.output.resolve()), str(aligned),
    ])
    result = {
        "status": "ok", "source_apk_sha256": sha256_file(source_apk),
        "output_apk": str(args.output.resolve()), "output_apk_sha256": sha256_file(args.output),
        "prepared": prepared, "build": build, "align": align, "sign": sign,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
