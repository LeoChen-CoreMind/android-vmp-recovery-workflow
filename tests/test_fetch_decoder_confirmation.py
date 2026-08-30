import json
import struct

from scripts.simulation.unicorn_fetch_decoder_confirmation import (
    confirm_samples,
    normalize_samples,
)


def test_fetch_decoder_confirmation_executes_real_aarch64(tmp_path):
    start = 0x100
    image = bytearray(start + 8)
    struct.pack_into("<II", image, start, 0x52800000, 0xD65F03C0)  # mov w0, #0; ret
    binary = tmp_path / "decoder.so"
    binary.write_bytes(image)
    samples = [{
        "method_idx": 1,
        "key": 2,
        "unit_index": 0,
        "raw_unit": 3,
        "fvp": 1,
        "expected_decoded_unit": 0,
        "sequence": 4,
        "stream_offset_units": 0,
    }]
    report = confirm_samples(binary, samples, start, 16)
    assert report["confirmed"] is True
    assert report["matched_count"] == 1
    assert report["invalid_memory"] == []
    assert report["unknown_external_calls"] == 0


def test_fetch_decoder_confirmation_rejects_mismatch(tmp_path):
    start = 0x100
    image = bytearray(start + 8)
    struct.pack_into("<II", image, start, 0x52800000, 0xD65F03C0)
    binary = tmp_path / "decoder.so"
    binary.write_bytes(image)
    sample = {
        "method_idx": 1, "key": 2, "unit_index": 0, "raw_unit": 3,
        "fvp": 0, "expected_decoded_unit": 1, "sequence": None,
        "stream_offset_units": None,
    }
    report = confirm_samples(binary, [sample], start, 16)
    assert report["confirmed"] is False
    assert report["matched_count"] == 0
    assert report["mismatches"][0]["actual_decoded_unit"] == 0


def test_fetch_decoder_samples_are_normalized_from_agent_events():
    payload = [
        {"event": "ignored"},
        {
            "event": "vm-target-decoder-sample",
            "methodIndex": 42,
            "key": {"ok": True, "value": 9},
            "unitIndex": 2,
            "rawUnit": {"ok": True, "value": 0xD4A1},
            "fvp": 1,
            "decodedUnit": 0x1234,
            "sequence": 7,
            "streamOffsetUnits": 4,
        },
    ]
    assert normalize_samples(payload) == [{
        "method_idx": 42,
        "key": 9,
        "unit_index": 2,
        "raw_unit": 0xD4A1,
        "fvp": 1,
        "expected_decoded_unit": 0x1234,
        "sequence": 7,
        "stream_offset_units": 4,
    }]
