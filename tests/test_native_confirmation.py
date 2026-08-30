import json
from pathlib import Path

from scripts.simulation.run_native_confirmation import collect_requests, confirm_requests
import pytest

from scripts.fix.dex.enrich_vm_streams import expected_invoke_register_words, mode1_unit
from vmpwf.engine import init_case, load_context
from vmpwf.plugins.native_sim import NativeSim
from vmpwf.provenance import sha256_file
import vmpwf.plugins.native_sim as native_module


class FakeDecoder:
    def __init__(self, values):
        self.values = values

    def decode_unit(self, key, raw_unit):
        return {"decoded_unit": f"{self.values[(key, raw_unit)]:04x}",
                "interpreter_entry_rva": "1234"}


def test_mode1_static_decoder_applies_bytewise_truncation():
    def reference_byte(raw_byte, key):
        delta = (raw_byte - 58 - key) & 0xFF
        mask = 0xB7 if delta & 0x40 else 0xB2
        return key ^ (delta ^ mask)

    keys = (0, 1, 0x3F, 0x80, 0xFF)
    raw_bytes = (0, 1, 0x39, 0x3A, 0x7F, 0x80, 0xFE, 0xFF)
    for key in keys:
        for low in raw_bytes:
            for high in raw_bytes:
                expected = reference_byte(low, key) | (reference_byte(high, key) << 8)
                assert mode1_unit(low | (high << 8), key) == expected


@pytest.mark.parametrize(("kind", "parameters", "expected"), [
    ("invoke-static", 0, 0),
    ("invoke-static/range", 3, 3),
    ("invoke-direct", 0, 1),
    ("invoke-interface", 2, 3),
    ("invoke-super", 1, 2),
    ("invoke-virtual/range", 4, 5),
])
def test_invoke_register_words_require_exact_receiver_semantics(kind, parameters, expected):
    assert expected_invoke_register_words(kind, parameters) == expected


def test_invoke_register_words_reject_unknown_kind():
    with pytest.raises(ValueError, match="unsupported invoke kind"):
        expected_invoke_register_words("invoke-unknown", 1)


def test_fixture_native_requests_are_batch_confirmable():
    root = Path(__file__).resolve().parents[1]
    streams = json.loads((root / "fixtures/com.jumi.tv/vm_streams_enriched.json").read_text(encoding="utf-8"))
    requests = collect_requests(streams)
    assert len(requests) == 8
    values = {(item["key"], item["raw_unit"]): item["expected_decoded_unit"] for item in requests}
    result = confirm_requests(requests, FakeDecoder(values))
    assert not result["errors"]
    assert result["cross_method_constants_consistent"]


def test_native_confirmation_rejects_mismatch():
    requests = [{"method_idx": 1, "pc": 2, "key": 3, "raw_unit": 4,
                 "expected_decoded_unit": 5}]
    result = confirm_requests(requests, FakeDecoder({(3, 4): 6}))
    assert result["errors"][0]["reason"] == "decoded-unit-mismatch"


def test_plugin_uses_bundled_runner_when_simulation_paths_are_set(tmp_path, sample_inputs, monkeypatch):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "android-arm64-360-dexvmp")
    streams = tmp_path / "streams.json"
    streams.write_text(json.dumps({
        "methods": [{
            "method_idx": 7,
            "instructions": [{
                "pc": 3,
                "literal_mode1_unicorn": {
                    "engine": "pending-case-native-confirmation",
                    "decoded_unit": "1234",
                },
            }],
        }],
        "literal_decoder": {"engine": "pending-case-native-confirmation"},
    }), encoding="utf-8")
    paths = {}
    for name in ("outer", "linker", "binary", "config"):
        path = tmp_path / name
        path.write_bytes(name.encode())
        paths[name] = str(path)
    context = load_context(case_dir)
    context.profile_snapshot = {}
    context.case["artifacts"]["vm_streams"] = str(streams)
    context.case["simulation"] = paths
    context.save_case()

    def fake(command, *args, **kwargs):
        assert any("run_native_confirmation.py" in value for value in command)
        output = Path(command[command.index("--output") + 1])
        report = {
            "confirmed": True, "unknown_external_calls": 0, "invalid_memory": [],
            "abort": False, "stack_guard_failed": False,
            "streams_sha256": sha256_file(streams),
            "binary_sha256": sha256_file(Path(paths["binary"])),
            "config_sha256": sha256_file(Path(paths["config"])),
            "request_count": 1,
            "results": [{
                "method_idx": 7, "pc": 3, "matched": True,
                "actual_decoded_unit": 0x1234,
            }],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report), encoding="utf-8")
        return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(native_module, "run_command", fake)
    result = NativeSim().run(context)
    assert result["confirmed"] is True
    assert Path(result["artifacts"][0]["path"]).is_file()
    promoted = Path(result["confirmed_streams"])
    promoted_payload = json.loads(promoted.read_text(encoding="utf-8"))
    assert promoted_payload["literal_decoder"]["engine"] == "unicorn-arm64"
    assert promoted_payload["literal_decoder"]["request_count"] == 1
    assert promoted_payload["methods"][0]["instructions"][0]["literal_mode1_unicorn"]["matched"] is True
