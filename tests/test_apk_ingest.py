from vmpwf.engine import init_case, load_context, run_workflow


def test_apk_ingest(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture")
    result = run_workflow(load_context(case_dir), until="apk-ingest")
    assert result["state"] == "APK_INGESTED"
    assert (case_dir / "input/manifest/rev-0001/apk_inventory.json").is_file()
