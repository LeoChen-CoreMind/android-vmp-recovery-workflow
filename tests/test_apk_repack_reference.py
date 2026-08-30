from __future__ import annotations

import importlib.util
import hashlib
import json
import struct
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts/apk" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_smali_patcher_applies_scoped_exact_count(tmp_path):
    module = load_script("patch_smali_calls.py")
    smali = tmp_path / "smali/com/example/Caller.smali"
    smali.parent.mkdir(parents=True)
    smali.write_text(
        "    invoke-static {v1}, Lcom/stub/StubApp;->getOrigApplicationContext"
        "(Landroid/content/Context;)Landroid/content/Context;\n"
        "    move-result-object v1\n",
        encoding="utf-8",
    )
    patches = [{
        "id": "context", "files": ["smali/**/*.smali"],
        "pattern": r"^(?P<i>[ \t]*)invoke-static \{(?P<r>[vp][0-9]+)\}, "
                   r"Lcom/stub/StubApp;->getOrigApplicationContext"
                   r"\(Landroid/content/Context;\)Landroid/content/Context;[ \t]*(?P<eol>\r?)$",
        "replacement": r"\g<i>invoke-virtual {\g<r>}, "
                       r"Landroid/content/Context;->getApplicationContext()Landroid/content/Context;\g<eol>",
        "expected_matches": 1, "flags": ["MULTILINE"], "evidence": ["test"],
    }]
    result = module.apply_patches(tmp_path, patches)
    assert result["patches"][0]["actual_matches"] == 1
    assert "invoke-virtual {v1}" in smali.read_text(encoding="utf-8")


def test_smali_patcher_count_mismatch_writes_nothing(tmp_path):
    module = load_script("patch_smali_calls.py")
    smali = tmp_path / "smali/Caller.smali"
    smali.parent.mkdir(parents=True)
    original = "    invoke-static {}, Lcom/stub/StubApp;->mark()V\n"
    smali.write_text(original, encoding="utf-8")
    patches = [{
        "id": "void", "files": ["smali/**/*.smali"],
        "pattern": r"(?m)^(?P<i>[ \t]*)invoke-static \{\}, Lcom/stub/StubApp;->mark\(\)V(?P<eol>\r?)$",
        "replacement": r"\g<i>nop\g<eol>", "expected_matches": 2, "evidence": ["test"],
    }]
    with pytest.raises(ValueError, match="expected 2 matches, found 1"):
        module.apply_patches(tmp_path, patches)
    assert smali.read_text(encoding="utf-8") == original


def test_sanitized_adapter_example_matches_schema():
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "schemas/apk-repack-adapter.schema.json").read_text(encoding="utf-8"))
    example = json.loads((ROOT / "examples/apk-repack/sanitized-360-version-adapter.example.json").read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema).iter_errors(example))


def test_reference_executor_prepares_exact_shell_removal_dex_and_manifest(tmp_path, monkeypatch):
    module = load_script("repack_from_adapter.py")
    source_apk = tmp_path / "source.apk"
    source_apk.write_bytes(b"example APK input")
    dex_source = tmp_path / "business.dex"
    data = bytearray(0x90)
    data[:8] = b"dex\n035\0"
    data[0x70:0x70 + len(b"Lcom/stub/StubApp;")] = b"Lcom/stub/StubApp;"
    dex_source.write_bytes(data)
    adapter = {
        "remove_entries": ["assets/libjiagu_a64.so"],
        "replace_entries": [{"name": "classes.dex", "output_sha256": ""}],
        "dex_layout": [{
            "source": str(dex_source), "source_sha256": module.sha256_file(dex_source),
            "target": "classes.dex", "output_sha256": "",
        }],
        "manifest": {
            "application": {"value": "com.example.RealApplication"},
            "app_component_factory": {"value": "android.app.AppComponentFactory"},
        },
        "bridge_contracts": {
            "descriptor_replacements": [{
                "old": "Lcom/stub/StubApp;", "new": "Lcom/ref/AppPatch;",
                "expected_occurrences": 1, "targets": ["classes.dex"],
            }]
        },
    }
    patched = module.patch_dex(dex_source, "classes.dex", adapter)
    output_hash = hashlib.sha256(patched).hexdigest()
    adapter["replace_entries"][0]["output_sha256"] = output_hash
    adapter["dex_layout"][0]["output_sha256"] = output_hash

    def fake_run(command, cwd=None, timeout=1800):
        decoded = Path(command[command.index("-o") + 1])
        (decoded / "assets").mkdir(parents=True)
        (decoded / "assets/libjiagu_a64.so").write_bytes(b"shell")
        (decoded / "classes.dex").write_bytes(b"old shell dex")
        (decoded / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            '<application android:name="com.stub.StubApp"/></manifest>',
            encoding="utf-8",
        )
        return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(module, "run", fake_run)
    decoded = tmp_path / "decoded"
    result = module.prepare_decoded_tree(source_apk, adapter, decoded, "apktool")
    assert result["removed_entries"] == ["assets/libjiagu_a64.so"]
    assert not (decoded / "assets/libjiagu_a64.so").exists()
    output = (decoded / "classes.dex").read_bytes()
    assert b"Lcom/stub/StubApp;" not in output
    assert output.count(b"Lcom/ref/AppPatch;") == 1
    assert output[12:32] == hashlib.sha1(output[32:]).digest()
    assert struct.unpack("<I", output[8:12])[0] == zlib.adler32(output[12:]) & 0xFFFFFFFF
    manifest = (decoded / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert "com.example.RealApplication" in manifest
    assert "android.app.AppComponentFactory" in manifest
