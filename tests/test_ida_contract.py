from pathlib import Path

from vmpwf.adapters import FixtureIdaAdapter


def test_fixture_ida_contract():
    root = Path(__file__).resolve().parents[1]
    result = FixtureIdaAdapter().export({"fixture": str(root / "fixtures/com.jumi.tv/handler_map.json"), "binary": ""})
    assert result["status"] == "ok"
    assert len(result["entries"]) == 256
    assert result["tool"] == "fixture"


def test_mcp_response_builder_is_installed():
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts/ida/build_mcp_response.py"
    prompt = (root / "prompts/ida-export.md").read_text(encoding="utf-8")
    assert script.is_file()
    assert "build_mcp_response.py" in prompt
    assert '"response":"<absolute response.json>"' in prompt
