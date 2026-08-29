from vmpwf.engine import init_case, load_context, run_workflow


def test_offline_fixture_full_chain(tmp_path, sample_inputs):
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture", dex_zip=str(dex_zip))
    result = run_workflow(load_context(case_dir))
    assert result["state"] == "VALIDATED"
    assert result["stage_records"]["dex-restore"]["result"]["vmp_repaired"] is False
    assert (case_dir / "reports/rev-0001/validation.json").is_file()
