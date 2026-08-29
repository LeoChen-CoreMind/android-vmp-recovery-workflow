from pathlib import Path

from vmpwf.tooling import find_android_build_tool, resolve_tool


def test_android_build_tool_uses_latest_version(tmp_path, monkeypatch):
    sdk = tmp_path / "Sdk"
    old = sdk / "build-tools/34.0.0/dexdump.exe"
    latest = sdk / "build-tools/36.1.0/dexdump.exe"
    old.parent.mkdir(parents=True)
    latest.parent.mkdir(parents=True)
    old.write_bytes(b"old")
    latest.write_bytes(b"latest")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    monkeypatch.setenv("ANDROID_HOME", str(tmp_path / "missing"))
    monkeypatch.setattr("vmpwf.tooling.android_sdk_roots", lambda: [sdk])
    assert find_android_build_tool("dexdump") == str(latest.resolve())


def test_resolve_configured_tool(tmp_path):
    tool = tmp_path / "custom-dexdump.exe"
    tool.write_bytes(b"tool")
    assert resolve_tool("dexdump", str(tool)) == str(tool.resolve())
