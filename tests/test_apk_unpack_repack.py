from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vmpwf.core import StageBlocked
from vmpwf.engine import init_case, load_context, resume_case, run_workflow
from vmpwf.plugins import PLUGINS
from vmpwf.provenance import sha256_file


def adapter_payload(case_dir: Path, apk: Path, dex: Path) -> dict:
    return {
        "schema_version": 1,
        "adapter_id": "test-version-adapter",
        "evidence_revision": 1,
        "case_revision": 1,
        "package": "com.example.fixture",
        "apk_sha256": sha256_file(apk),
        "shell": {
            "family": "360",
            "version": "test-only",
            "fingerprints": [{"kind": "zip-entry", "value": "assets/libjiagu.so", "evidence": [str(apk)]}],
        },
        "manifest": {
            "application": {"value": "com.example.RealApplication", "evidence": ["dump metadata"]},
            "app_component_factory": {"value": "android.app.AppComponentFactory", "evidence": ["dump metadata"]},
        },
        "dex_layout": [{
            "source": str(dex), "source_sha256": sha256_file(dex), "target": "classes.dex",
            "output_sha256": sha256_file(dex), "evidence": ["restored DEX manifest"],
        }],
        "remove_entries": ["assets/libjiagu.so"],
        "replace_entries": [],
        "bridge_contracts": {"descriptor_replacements": [], "calls": [], "smali_patches": []},
        "executor": {"command": ["missing-test-executor"], "output_apk": "test.apk"},
        "signing": {"certificate_sha256": "0" * 64, "required_schemes": ["v2"]},
        "validation": {"manifest": True, "dexdump": True, "jadx": True,
                       "zipalign": True, "signature": True, "device": False},
    }


def test_fixture_records_repack_as_not_applicable(tmp_path, sample_inputs):
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture", dex_zip=str(dex_zip))
    result = run_workflow(load_context(case_dir))
    repack = result["stage_records"]["apk-unpack-repack"]["result"]
    assert result["state"] == "VALIDATED"
    assert repack == {"ok": True, "applicable": False, "repacked": False,
                      "reason": "fixture", "artifacts": []}


def test_real_profile_without_adapter_generates_inventory_and_blocks(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "android-arm64-360-dexvmp")
    with pytest.raises(StageBlocked) as blocked:
        PLUGINS["apk-unpack-repack"].run(load_context(case_dir))
    assert blocked.value.question["expected"]["fields"] == ["apk_repack.adapter"]
    assert (case_dir / "repack/adapter/rev-0001/apk_inventory.json").is_file()
    assert (case_dir / "repack/adapter/rev-0001/adapter.template.json").is_file()


def test_adapter_hash_conflict_blocks_before_executor(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\0" + b"\0" * 128)
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [str(dex)], str(apk), "android-arm64-360-dexvmp")
    adapter = adapter_payload(case_dir, apk, dex)
    adapter["apk_sha256"] = "f" * 64
    adapter_path = case_dir / "adapter.json"
    adapter_path.write_text(json.dumps(adapter), encoding="utf-8")
    context = load_context(case_dir)
    context.case["apk_repack"] = {"adapter": str(adapter_path)}
    context.save_case()
    with pytest.raises(StageBlocked) as blocked:
        PLUGINS["apk-unpack-repack"].run(load_context(case_dir))
    assert "conflicts with current case evidence" in blocked.value.question["message"]


def test_adapter_schema_rejects_wildcard_removal(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\0" + b"\0" * 128)
    payload = adapter_payload(tmp_path, apk, dex)
    payload["remove_entries"] = ["assets/libjiagu*.so"]
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/apk-repack-adapter.schema.json").read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(payload))


def test_adapter_schema_supports_same_path_shell_dex_replacement(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\0" + b"\0" * 128)
    payload = adapter_payload(tmp_path, apk, dex)
    payload["remove_entries"] = []
    payload["replace_entries"] = [{
        "name": "classes.dex", "output_sha256": sha256_file(dex),
        "evidence": ["shell primary DEX replaced by restored business primary DEX"],
    }]
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/apk-repack-adapter.schema.json").read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema).iter_errors(payload))


def test_adapter_schema_keeps_smali_patches_optional(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\0" + b"\0" * 128)
    payload = adapter_payload(tmp_path, apk, dex)
    payload["bridge_contracts"].pop("smali_patches")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/apk-repack-adapter.schema.json").read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema).iter_errors(payload))


def test_resume_accepts_apk_repack_answer(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture")
    context = load_context(case_dir)
    question = context.question("apk-unpack-repack", "need adapter", [], ["apk_repack.adapter"])
    answer = case_dir / "answer.json"
    answer.write_text(json.dumps({
        "apk_repack": {"enabled": True, "adapter": str(case_dir / "adapter.json")},
        "invalidate_from": "apk-unpack-repack",
    }), encoding="utf-8")
    result = resume_case(load_context(case_dir), question["id"], answer)
    assert result["config_revision"] == 2
    assert result["apk_repack"]["enabled"] is True
