from pathlib import Path

from vmpwf.cli import doctor


def test_private_linker_dumper_is_the_only_runtime_entrypoint():
    root = Path(__file__).resolve().parents[1]
    plugin = (root / "vmpwf/plugins/so_dump.py").read_text(encoding="utf-8")
    assert "dump_linker.js" in plugin
    assert "dump_libjiagu.js" not in plugin
    assert not (root / "scripts/dump/so/dump_libjiagu.js").exists()


def test_doctor_requires_private_linker_dump_scripts():
    required = doctor()["required_files"]
    assert required[str(Path(__file__).resolve().parents[1] / "scripts/dump/so/run_gating.py")]
    assert required[str(Path(__file__).resolve().parents[1] / "scripts/dump/so/dump_linker.js")]
