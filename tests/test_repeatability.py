from scripts.validate.validate_repeatability import (
    DETERMINISTIC_PREFIXES,
    RUNTIME_EVIDENCE_PREFIXES,
    snapshot,
)


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_runtime_so_changes_do_not_change_default_repeatability_scope(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        write(root, "input/apk/app.apk", b"apk")
        write(root, "input/dex/classes.dex", b"input-dex")
        write(root, "fix/dex/classes.dex", b"restored-dex")
    write(first, "dump/so/raw/linker.so", b"runtime-address-a")
    write(second, "dump/so/raw/linker.so", b"runtime-address-b")

    assert snapshot(first, DETERMINISTIC_PREFIXES) == snapshot(second, DETERMINISTIC_PREFIXES)
    assert snapshot(first, RUNTIME_EVIDENCE_PREFIXES) != snapshot(second, RUNTIME_EVIDENCE_PREFIXES)


def test_restored_dex_change_fails_repeatability_scope(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write(first, "fix/dex/classes.dex", b"restored-a")
    write(second, "fix/dex/classes.dex", b"restored-b")
    assert snapshot(first, DETERMINISTIC_PREFIXES) != snapshot(second, DETERMINISTIC_PREFIXES)
