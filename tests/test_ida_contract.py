from pathlib import Path

from vmpwf.adapters import FixtureIdaAdapter


def test_fixture_ida_contract():
    root = Path(__file__).resolve().parents[1]
    result = FixtureIdaAdapter().export({"fixture": str(root / "fixtures/com.jumi.tv/handler_map.json"), "binary": ""})
    assert result["status"] == "ok"
    assert len(result["entries"]) == 256
    assert result["tool"] == "fixture"
