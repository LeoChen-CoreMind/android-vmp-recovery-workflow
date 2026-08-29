from pathlib import Path

from vmpwf.adapters import FixtureIdaAdapter
from vmpwf.ida_patterns import is_cmp_dispatch_pattern, is_direct_dispatch_pattern
from vmpwf.validation import validate_dispatch_map


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
    assert "pointer_base" in prompt
    assert '"response":"<absolute response.json>"' in prompt


def test_cmp_dispatch_pattern_requires_exact_six_instruction_stub():
    assert is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "BR"], "X8", "X8"
    )
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "LDUR"], "X8", "X8"
    )
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "BR"], "X8", "X9"
    )


def test_direct_dispatch_pattern_requires_matching_load_and_branch_registers():
    assert is_direct_dispatch_pattern(["ADRP", "LDR", "BR"], "W10", "X10")
    assert not is_direct_dispatch_pattern(["ADRP", "LDR", "BR"], "X10", "X11")


def test_dispatch_only_validation_allows_unresolved_widths():
    payload = {
        "entries": [
            {"opcode": opcode, "handler": 0x1000 + opcode * 4, "pc_width_candidates": []}
            for opcode in range(256)
        ]
    }
    dispatch_only = validate_dispatch_map(payload, require_widths=False)
    method_recovery = validate_dispatch_map(payload, require_widths=True)
    assert dispatch_only["ok"] is True
    assert dispatch_only["dispatch_ok"] is True
    assert dispatch_only["ambiguous_widths"] == list(range(256))
    assert method_recovery["ok"] is False
