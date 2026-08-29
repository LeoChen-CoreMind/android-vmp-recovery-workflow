from vmpwf.cli import doctor, inspect_package, main


def test_doctor_and_package(sample_inputs):
    apk, _ = sample_inputs
    assert doctor()["status"] == "ok"
    assert inspect_package(apk) == "com.example.fixture"


def test_init_cli_accepts_apk_path(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    assert main(["init", "--case", str(tmp_path / "case"), "--apk", str(apk),
                 "--profile", "offline-fixture"]) == 0
