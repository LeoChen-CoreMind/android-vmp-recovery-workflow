import pytest

from vmpwf.core import StageBlocked
from vmpwf.engine import init_case, load_context, run_workflow
from vmpwf.plugins.vm_static import VmStatic


def test_zip_fallback(tmp_path, sample_inputs):
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture", dex_zip=str(dex_zip))
    result = run_workflow(load_context(case_dir), until="dex-extract")
    assert result["state"] == "DEX_READY"
    assert len(result["dex_inputs"]) == 2
    assert result["stage_records"]["dex-extract"]["result"]["source"] == "user-supplied"


def test_zero_vmp_records_do_not_block_device_setup_or_so_stages(tmp_path, sample_inputs):
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk),
              "android-arm64-360-dexvmp", dex_zip=str(dex_zip))
    result = run_workflow(load_context(case_dir), until="dex-extract")
    assert result["state"] == "DEX_READY"
    assert result["vmp_recovery_required"] is False
    assert result["vmp_method_records"] == 0

    with pytest.raises(StageBlocked) as blocked:
        VmStatic().run(load_context(case_dir))
    assert blocked.value.question["stage"] == "vm-static"
