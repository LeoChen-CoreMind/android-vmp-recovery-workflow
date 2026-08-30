import json
from pathlib import Path

from vmpwf.validation import (lm_summary, valid_dex_bytes,
                              validate_dispatch_map, validate_vm_streams)
from vmpwf.plugins.independent_validate import IndependentValidate

from conftest import minimal_dex


def test_minimal_dex_validation(tmp_path):
    data = minimal_dex()
    path = tmp_path / "classes.dex"; path.write_bytes(data)
    assert valid_dex_bytes(data)
    assert lm_summary(path) == {"present": False}


def test_reference_contracts_are_complete():
    root = Path(__file__).resolve().parents[1]
    dispatch = json.loads((root / "fixtures/com.jumi.tv/handler_map.json").read_text(encoding="utf-8"))
    streams = json.loads((root / "fixtures/com.jumi.tv/vm_streams_enriched.json").read_text(encoding="utf-8"))
    assert not validate_dispatch_map(dispatch)["ok"]
    assert validate_dispatch_map(dispatch, allow_contextual=True)["ok"]
    assert validate_vm_streams(streams)["ok"]
    assert not validate_vm_streams(streams, require_evidence=True)["ok"]


def test_vm_stream_closure_rejects_bad_final_pc():
    payload = {"methods": [{"method_idx": 1, "insns_size": 2, "instructions": [
        {"pc": 0, "width": 1, "decoded_units_complete": True, "dalvik_opcode": 14,
         "decoded_units": ["000e"], "raw_units": ["0000"]}
    ]}]}
    result = validate_vm_streams(payload)
    assert not result["ok"]
    assert result["errors"][-1]["reason"] == "final-pc-not-closed"


def test_jadx_error_contract_records_count_and_methods(tmp_path):
    stdout = tmp_path / "jadx.stdout.log"
    stderr = tmp_path / "jadx.stderr.log"
    stdout.write_text(
        "ERROR - 2 errors occurred in following nodes:\n"
        "ERROR -   Method: a.b.C.first():void\n"
        "ERROR -   Method: d.e.F.second(int):int\n"
        "ERROR - finished with errors, count: 2\n",
        encoding="utf-8",
    )
    stderr.write_text("", encoding="utf-8")
    contract = IndependentValidate._jadx_error_contract({
        "stdout_log": str(stdout), "stderr_log": str(stderr),
    })
    assert contract == {
        "error_count": 2,
        "error_methods": ["a.b.C.first():void", "d.e.F.second(int):int"],
    }
