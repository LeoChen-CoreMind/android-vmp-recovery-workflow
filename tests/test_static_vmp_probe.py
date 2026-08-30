import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ida" / "static_vmp_probe.py"


def load_probe():
    spec = importlib.util.spec_from_file_location("static_vmp_probe_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_evidence(path, **overrides):
    payload = {
        "confirmed": True,
        "selector": 37,
        "binary_sha256": "a" * 64,
        "method_key_formula": "ins_size^class_idx^registers_size^name_idx^selector^0x2c",
        "runtime_method_confirmations": [{"method_idx": 1}, {"method_idx": 2}],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_selector_evidence_accepts_matching_runtime_proof(tmp_path):
    probe = load_probe()
    evidence = tmp_path / "selector.json"
    write_evidence(evidence)

    payload = probe.load_selector_evidence(evidence, 37, "a" * 64)

    assert payload["selector"] == 37


@pytest.mark.parametrize(
    ("overrides", "selector", "binary_sha256", "message"),
    [
        ({"confirmed": False}, 37, "a" * 64, "not confirmed"),
        ({"selector": 60}, 37, "a" * 64, "does not match"),
        ({"binary_sha256": "b" * 64}, 37, "a" * 64, "different fixed SO"),
        ({"runtime_method_confirmations": [{"method_idx": 1}]}, 37, "a" * 64,
         "at least two"),
    ],
)
def test_load_selector_evidence_fails_closed(
    tmp_path, overrides, selector, binary_sha256, message
):
    probe = load_probe()
    evidence = tmp_path / "selector.json"
    write_evidence(evidence, **overrides)

    with pytest.raises(RuntimeError, match=message):
        probe.load_selector_evidence(evidence, selector, binary_sha256)
