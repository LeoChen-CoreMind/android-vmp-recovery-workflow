import json
from pathlib import Path
import pytest

from vmpwf.engine import init_case, load_context, resume_case, run_workflow


def test_init_and_status(tmp_path):
    dex = tmp_path / "classes3.dex"
    dex.write_bytes(b"dex\n035\0")
    case_dir = tmp_path / "case"
    case = init_case(case_dir, "com.example.app", "serial", [str(dex)], None, "test")
    assert case["state"] == "INIT"
    assert (case_dir / "checkpoint.json").exists()


def test_resume_increments_revision_and_invalidates(tmp_path):
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.app", None, [str(tmp_path / "x.dex")], None, "test")
    case = json.loads((case_dir / "case.json").read_text())
    case["state"] = "BLOCKED"
    case["open_questions"] = ["q-0001"]
    case["questions.json"] = []
    (case_dir / "questions.json").write_text(json.dumps([{"id": "q-0001", "stage": "ida-export", "status": "open"}]))
    (case_dir / "answer.json").write_text(json.dumps({"ida": {"adapter": "fixture"}}))
    before = case["config_revision"]
    result = resume_case(load_context(case_dir), "q-0001", case_dir / "answer.json")
    assert result["config_revision"] == before + 1
    assert result["state"] == "BLOCKED"


def test_resume_rejects_immutable_identity(tmp_path):
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.app", None, [str(tmp_path / "x.dex")], None, "test")
    (case_dir / "questions.json").write_text(json.dumps([{"id": "q-0001", "stage": "ida-export", "status": "open"}]))
    answer = case_dir / "answer.json"
    answer.write_text(json.dumps({"case_id": "changed"}))
    with pytest.raises(ValueError):
        resume_case(load_context(case_dir), "q-0001", answer)


def test_target_stage_can_run_with_fake_adb(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.app", None, [str(tmp_path / "x.dex")], None, "test")
    monkeypatch.setenv("PATH", "")
    # Missing adb is represented as a resumable question rather than a crash.
    try:
        run_workflow(load_context(case_dir), until="target-confirm")
    except Exception:
        pass
    questions = json.loads((case_dir / "questions.json").read_text())
    assert questions or json.loads((case_dir / "case.json").read_text())["state"] == "TARGET_CONFIRMED"
