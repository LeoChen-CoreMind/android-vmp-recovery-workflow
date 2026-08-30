from pathlib import Path
import importlib.util

from vmpwf.adapters import FixtureIdaAdapter
from vmpwf.ida_patterns import (
    decoder_max_unit_index,
    exact_memory_register,
    is_cmp_dispatch_pattern,
    is_dispatch_prefetch_address,
    is_direct_dispatch_pattern,
    select_width_evidence,
)
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


def test_cmp_dispatch_pattern_accepts_bounded_safe_gap():
    assert is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "BR"], "X8", "X8"
    )
    assert is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "LDUR", "SUB", "LSR", "BR"],
        "X8",
        "X8",
        ["X9", "X9", "X25"],
    )
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "LDUR"], "X8", "X8"
    )
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "BR"], "X8", "X9"
    )


def test_cmp_dispatch_pattern_rejects_unsafe_or_unbounded_gap():
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "MOV", "BR"],
        "X8",
        "X8",
        ["W8"],
    )
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "BL", "BR"],
        "X8",
        "X8",
        ["X0"],
    )
    assert not is_cmp_dispatch_pattern(
        ["ADRP", "CSET", "ADD", "LDR", "NOP", "NOP", "NOP", "NOP", "BR"],
        "X8",
        "X8",
        ["", "", "", ""],
    )


def test_direct_dispatch_pattern_requires_matching_load_and_branch_registers():
    assert is_direct_dispatch_pattern(["ADRP", "LDR", "BR"], "W10", "X10")
    assert is_direct_dispatch_pattern(
        ["ADRP", "LDR", "NOP", "BR"], "W10", "X10", [""]
    )
    assert not is_direct_dispatch_pattern(["ADRP", "LDR", "BR"], "X10", "X11")


def test_pc_pointer_register_and_multi_unit_decoder_helpers():
    assert exact_memory_register("[X27]") == "X27"
    assert exact_memory_register("[w22]") == "X22"
    assert exact_memory_register("[X27,#8]") is None
    assert decoder_max_unit_index(3, 2) == 4


def test_dispatch_prefetch_backedge_is_not_handler_width_evidence():
    prefetch_functions = {0x1300, 0x1340}
    assert is_dispatch_prefetch_address(
        0x1300, 0x1340, 0x1300, prefetch_functions
    )
    assert not is_dispatch_prefetch_address(
        0x1400, 0x1340, 0x1300, prefetch_functions
    )
    assert not is_dispatch_prefetch_address(
        0x1300, 0x1340, 0x1200, prefetch_functions
    )


def test_decoder_operand_coverage_dominates_branch_pc_write():
    pc = {3: {"units": 3, "source": "pc_write"}}
    decoder = {1: {"units": 1, "source": "decoder_max_index"}}
    selected = select_width_evidence(pc, decoder)
    assert list(selected) == [1]
    assert selected[1]["conflicting_pc_writes"] == [pc[3]]


def test_decoder_coverage_above_pc_write_still_wins():
    pc = {3: {"units": 3, "source": "pc_write"}}
    decoder = {4: {"units": 4, "source": "decoder_max_index"}}
    selected = select_width_evidence(pc, decoder)
    assert list(selected) == [4]
    assert selected[4]["conflicting_pc_writes"] == [pc[3]]


def test_matching_pc_write_is_recorded_as_corroboration():
    pc = {3: {"units": 3, "source": "pc_write"}}
    decoder = {3: {"units": 3, "source": "decoder_max_index"}}
    selected = select_width_evidence(pc, decoder)
    assert selected[3]["matching_pc_writes"] == [pc[3]]


def test_unicorn_confirmation_prefers_recorded_dispatch_instruction_rvas():
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts/simulation/unicorn_dispatch_confirmation.py"
    spec = importlib.util.spec_from_file_location("unicorn_dispatch_confirmation", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    entries = [{
        "path": [{
            "kind": "cmp_table",
            "ea": 0x100,
            "instruction_rvas": [0x100, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x118, 0x11C],
        }]
    }]
    assert module.dispatch_instruction_rvas(entries) == {
        0x100, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x118, 0x11C
    }


def test_unicorn_confirmation_initializes_dispatch_scratch_frame():
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts/simulation/unicorn_dispatch_confirmation.py").read_text(
        encoding="utf-8"
    )
    assert "scratch_frame" in script
    assert "UC_ARM64_REG_X29" in script
    assert "UC_ARM64_REG_X19" in script
    assert "UC_ARM64_REG_SP" in script


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
