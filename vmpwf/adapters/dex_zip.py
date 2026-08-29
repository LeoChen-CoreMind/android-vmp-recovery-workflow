from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath

from ..provenance import file_record
from ..validation import valid_dex_bytes


def _key(name: str) -> tuple[int, str]:
    stem = PurePosixPath(name).stem.lower().replace("_decrypted", "")
    suffix = stem.removeprefix("classes")
    return (1 if not suffix else int(suffix) if suffix.isdigit() else 9999, name)


def import_dex_zip(source: Path, destination: Path, case_root: Path) -> list[dict]:
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    with zipfile.ZipFile(source) as archive:
        names = sorted((name for name in archive.namelist() if name.lower().endswith(".dex")), key=_key)
        for index, name in enumerate(names, 1):
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                continue
            data = archive.read(name)
            if not valid_dex_bytes(data):
                continue
            target = destination / ("classes.dex" if index == 1 else f"classes{index}.dex")
            target.write_bytes(data)
            results.append(file_record(target, case_root, source="user-supplied",
                                       source_path=f"{source.resolve()}!/{name}"))
    return results
