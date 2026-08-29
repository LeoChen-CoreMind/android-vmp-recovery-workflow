from vmpwf.engine import init_case, load_context, run_workflow


def test_zip_fallback(tmp_path, sample_inputs):
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture", dex_zip=str(dex_zip))
    result = run_workflow(load_context(case_dir), until="dex-extract")
    assert result["state"] == "DEX_READY"
    assert len(result["dex_inputs"]) == 2
    assert result["stage_records"]["dex-extract"]["result"]["source"] == "user-supplied"
