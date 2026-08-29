from vmpwf.engine import init_case


def test_case_layout(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    case = init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture")
    assert case["state"] == "INIT"
    for path in ("input/apk", "dump/so/raw", "dump/dex/static", "fix/so", "fix/dex", "ida/tables", "simulation/results"):
        assert (case_dir / path).is_dir()
