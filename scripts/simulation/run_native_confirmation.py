#!/usr/bin/env python3
"""Batch native confirmation runner for case-specific DexVMP stream evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from .unicorn_literal_decoder import LiteralDecoder
except ImportError:
    from unicorn_literal_decoder import LiteralDecoder


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def number(value: Any) -> int:
    if isinstance(value, str):
        text = value.strip()
        return int(text, 0) if text.lower().startswith(("0x", "+0x", "-0x")) else int(text, 16)
    return int(value)


def collect_requests(streams: dict[str, Any]) -> list[dict[str, Any]]:
    explicit = streams.get("native_confirmation_requests")
    if isinstance(explicit, list):
        source = explicit
    else:
        source = []
        for method in streams.get("methods", []):
            for instruction in method.get("instructions", []):
                evidence = instruction.get("literal_mode1_unicorn") or instruction.get("native_confirmation")
                if not isinstance(evidence, dict):
                    continue
                source.append({
                    "method_idx": method.get("method_idx"),
                    "pc": instruction.get("pc"),
                    "key": evidence.get("method_key", method.get("key")),
                    "raw_unit": evidence.get("raw_unit"),
                    "expected_decoded_unit": evidence.get("decoded_unit"),
                })

    requests = []
    seen = set()
    for item in source:
        required = (item.get("key"), item.get("raw_unit"), item.get("expected_decoded_unit"))
        if any(value is None for value in required):
            raise ValueError(f"native confirmation request is incomplete: {item}")
        request = {
            "method_idx": item.get("method_idx"), "pc": item.get("pc"),
            "key": number(item["key"]) & 0xFF,
            "raw_unit": number(item["raw_unit"]) & 0xFFFF,
            "expected_decoded_unit": number(item["expected_decoded_unit"]) & 0xFFFF,
        }
        identity = (request["method_idx"], request["pc"], request["key"], request["raw_unit"])
        if identity not in seen:
            requests.append(request)
            seen.add(identity)
    return requests


def confirm_requests(requests: list[dict[str, Any]], decoder: Any) -> dict[str, Any]:
    results = []
    errors = []
    constants: dict[tuple[int, int], set[int]] = {}
    for request in requests:
        try:
            decoded = decoder.decode_unit(request["key"], request["raw_unit"])
            actual = number(decoded["decoded_unit"]) & 0xFFFF
            matched = actual == request["expected_decoded_unit"]
            result = {**request, "actual_decoded_unit": actual, "matched": matched,
                      "interpreter_entry_rva": decoded.get("interpreter_entry_rva")}
            results.append(result)
            constants.setdefault((request["key"], request["raw_unit"]), set()).add(actual)
            if not matched:
                errors.append({"reason": "decoded-unit-mismatch", **result})
        except Exception as exc:
            error_text = str(exc)
            try:
                native_error = json.loads(error_text)
            except json.JSONDecodeError:
                native_error = None
            errors.append({"reason": "native-execution-failed", **request,
                           "error": error_text, "native_error": native_error})

    inconsistent = [
        {"key": key, "raw_unit": raw, "decoded_values": sorted(values)}
        for (key, raw), values in constants.items() if len(values) != 1
    ]
    errors.extend({"reason": "cross-method-constant-mismatch", **item} for item in inconsistent)
    return {"results": results, "errors": errors,
            "cross_method_constants_consistent": not inconsistent}


def run(args: argparse.Namespace) -> dict[str, Any]:
    streams_path = args.streams.resolve()
    outer = args.outer.resolve()
    linker = args.linker.resolve()
    binary = args.binary.resolve()
    config = args.config.resolve()
    streams = json.loads(streams_path.read_text(encoding="utf-8"))
    requests = collect_requests(streams)

    streams_hash = sha256_file(streams_path)
    binary_hash = sha256_file(binary)
    config_hash = sha256_file(config)
    precondition_errors = []
    evidence = streams.get("evidence", {})
    if evidence.get("binary_sha256") != binary_hash:
        precondition_errors.append({"reason": "binary-hash-mismatch", "expected": evidence.get("binary_sha256"),
                                    "actual": binary_hash})
    if evidence.get("simulation_config_sha256") != config_hash:
        precondition_errors.append({"reason": "config-hash-mismatch",
                                    "expected": evidence.get("simulation_config_sha256"), "actual": config_hash})
    if not requests:
        precondition_errors.append({"reason": "no-native-confirmation-requests"})

    confirmation = {"results": [], "errors": [], "cross_method_constants_consistent": False}
    if not precondition_errors:
        decoder = LiteralDecoder(outer, linker, config, args.trace_limit)
        confirmation = confirm_requests(requests, decoder)
    errors = [*precondition_errors, *confirmation["errors"]]
    invalid_memory = [access for item in errors
                      for access in (item.get("native_error") or {}).get("invalid_access", [])]
    error_text = "\n".join(item.get("error", "") for item in errors)
    return {
        "confirmed": not errors and bool(requests),
        "engine": "unicorn-arm64",
        "request_count": len(requests),
        "streams_sha256": streams_hash,
        "binary_sha256": binary_hash,
        "outer_sha256": sha256_file(outer),
        "linker_sha256": sha256_file(linker),
        "config_sha256": config_hash,
        "unknown_external_calls": sum(
            marker in item.get("error", "")
            for item in errors for marker in ("尚未实现的解释器外部调用", "unknown external call")),
        "invalid_memory": invalid_memory,
        "abort": "abort" in error_text,
        "stack_guard_failed": "stack_chk_fail" in error_text,
        "cross_method_constants_consistent": confirmation["cross_method_constants_consistent"],
        "results": confirmation["results"],
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Confirm selected DexVMP code units by executing real native functions")
    parser.add_argument("--streams", type=Path, required=True)
    parser.add_argument("--outer", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True, help="SO whose hash is bound to the IDA/VM evidence")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trace-limit", type=int, default=64)
    args = parser.parse_args()
    report = run(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "confirmed": report["confirmed"],
                      "requests": report["request_count"], "errors": len(report["errors"])}, ensure_ascii=False))
    return 0 if report["confirmed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
