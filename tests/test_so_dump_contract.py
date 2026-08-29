from pathlib import Path

from vmpwf.cli import doctor
from vmpwf.plugins.so_dump import SoDump


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
    assert required[str(Path(__file__).resolve().parents[1] / "scripts/device/prepare_frida_server.py")]
    assert required[str(Path(__file__).resolve().parents[1] / "tools/frida/media-server")]


def test_private_linker_metadata_gate():
    payload = {
        "reason": "pre-JNI_OnLoad", "privateSoinfo": "0x1", "loadStart": "0x2",
        "loadBias": "0x2", "phdr": "0x3", "phnum": 6, "privateDynamic": "0x4",
        "elfBase": "0x2", "dumpSize": 4096,
        "elf": {"loadCount": 2, "imageSpan": 4096},
        "dynamic": {"hasStrtab": True, "hasSymtab": True, "hasStrsz": True,
                    "hasSyment": True, "hasHash": True, "hasGnuHash": False},
    }
    assert SoDump._private_metadata_errors(payload) == []
    payload["dynamic"]["hasHash"] = False
    assert "dynamic hash table is missing" in SoDump._private_metadata_errors(payload)


def test_spawn_runner_owns_custom_server_and_diagnostics():
    root = Path(__file__).resolve().parents[1]
    runner = (root / "scripts/dump/so/run_gating.py").read_text(encoding="utf-8")
    agent = (root / "scripts/dump/so/dump_linker.js").read_text(encoding="utf-8")
    profile = (root / "workflow/profiles/android-arm64-360-dexvmp.json").read_text(encoding="utf-8")
    assert "--server" in runner and "prepare_frida_server.py" in runner
    assert "enable_spawn_gating" in runner and "logcat.txt" in runner
    assert "dumpOnManualLoaderReturn" in agent
    assert "dumpWhenRuntimePointersReady" in agent
    assert "spawn-gated-runtime-pointers-ready" in agent
    assert "manual-loader-return-before-target-symbol-lookup" in agent
    assert "late attach fallback" not in agent
    assert "tryLateDump" not in agent
    assert "mapped ELF program headers are invalid" in agent
    assert "parseProgramHeaders(soinfo.phdr, 56, soinfo.phnum)" in agent
    assert '"frida_server": "tools/frida/media-server"' in profile
    prepare = (root / "scripts/device/prepare_frida_server.py").read_text(encoding="utf-8")
    assert '["frida", "--version"]' in prepare


def test_custom_server_manifest_matches_binary():
    import hashlib
    import json

    root = Path(__file__).resolve().parents[1]
    binary = root / "tools/frida/media-server"
    manifest = json.loads((root / "tools/frida/manifest.json").read_text(encoding="utf-8"))
    assert binary.stat().st_size == manifest["size"]
    assert hashlib.sha256(binary.read_bytes()).hexdigest().upper() == manifest["sha256"]


def test_prompt_and_agent_runtime_contracts_match():
    root = Path(__file__).resolve().parents[1]
    prompt = (root / "prompts/so-dump.md").read_text(encoding="utf-8")
    agent = (root / "scripts/dump/so/dump_linker.js").read_text(encoding="utf-8")
    assert "Do not use late attach" in prompt
    assert "late attach" not in agent.lower()
    assert "dumpOnManualLoaderReturn" in agent
