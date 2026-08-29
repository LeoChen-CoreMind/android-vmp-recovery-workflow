import json

from vmpwf.engine import init_case, load_context, resume_case, run_workflow


def test_resume_increments_revision(tmp_path, sample_inputs):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture")
    context = load_context(case_dir)
    question = context.question("ida-export", "need table", [], ["ida"])
    answer = case_dir / "answer.json"
    answer.write_text(json.dumps({"ida": {"adapter": "fixture"}}), encoding="utf-8")
    result = resume_case(load_context(case_dir), question["id"], answer)
    assert result["config_revision"] == 2
    assert json.loads((case_dir / "questions.json").read_text())[0]["status"] == "answered"


def test_hot_reload_preserves_artifact_ledger_and_stage_history(tmp_path, sample_inputs):
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture", dex_zip=str(dex_zip))
    run_workflow(load_context(case_dir))
    before = json.loads((case_dir / "artifacts.json").read_text(encoding="utf-8"))
    old_report = case_dir / "reports/rev-0001/validation.json"
    context = load_context(case_dir)
    question = context.question("ida-export", "replace fixture table", [], ["ida"])
    answer = case_dir / "answer.json"
    answer.write_text(json.dumps({"ida": {"adapter": "fixture"}}), encoding="utf-8")
    resumed = resume_case(load_context(case_dir), question["id"], answer)
    assert resumed["state"] == "SO_REPAIRED"
    assert resumed["stage_history"]["ida-export"]
    run_workflow(load_context(case_dir))
    after = json.loads((case_dir / "artifacts.json").read_text(encoding="utf-8"))
    assert len(after) > len(before)
    assert old_report.is_file()
    assert (case_dir / "reports/rev-0002/validation.json").is_file()
    ida_revisions = {item["config_revision"] for item in after if item["stage"] == "ida-export"}
    assert ida_revisions == {1, 2}
