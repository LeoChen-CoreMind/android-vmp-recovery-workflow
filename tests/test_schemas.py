import json
from pathlib import Path

from jsonschema import Draft202012Validator

from vmpwf.engine import init_case, load_context, run_workflow


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate(schema_path, payload):
    Draft202012Validator(load(schema_path)).validate(payload)


def test_generated_case_files_match_schemas(tmp_path, sample_inputs):
    root = Path(__file__).resolve().parents[1]
    apk, dex_zip = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", None, [], str(apk), "offline-fixture", dex_zip=str(dex_zip))
    run_workflow(load_context(case_dir))

    validate(root / "schemas/case.schema.json", load(case_dir / "case.json"))
    validate(root / "schemas/checkpoint.schema.json", load(case_dir / "checkpoint.json"))
    for artifact in load(case_dir / "artifacts.json"):
        validate(root / "schemas/artifact.schema.json", artifact)

    question = load_context(case_dir).question("ida-export", "schema check", [], ["ida"])
    validate(root / "schemas/question.schema.json", question)


def test_workflow_and_stage_definitions_match_schemas():
    root = Path(__file__).resolve().parents[1]
    validate(root / "schemas/case.schema.json", load(root / "case.example.json"))
    validate(root / "schemas/workflow.schema.json", load(root / "workflow/workflow.json"))
    for path in (root / "workflow/stages").glob("*.json"):
        validate(root / "schemas/stage.schema.json", load(path))
    assert "apk-unpack-repack" in load(root / "workflow/workflow.json")["stages"]
    assert load(root / "workflow/dependencies.json")["apk-unpack-repack"] == ["independent-validate"]
