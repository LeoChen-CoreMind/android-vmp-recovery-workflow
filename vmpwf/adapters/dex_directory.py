from __future__ import annotations

import shutil
from pathlib import Path

from ..provenance import file_record
from ..validation import valid_dex_file


def dex_sort_key(path: Path) -> tuple[int, str]:
    stem = path.stem.lower().replace("_decrypted", "")
    suffix = stem.removeprefix("classes")
    return (1 if not suffix else int(suffix) if suffix.isdigit() else 9999, path.name)


def import_dex_directory(source: Path, destination: Path, case_root: Path) -> list[dict]:
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    for index, path in enumerate(sorted(source.glob("*.dex"), key=dex_sort_key), 1):
        if not valid_dex_file(path):
            continue
        target = destination / ("classes.dex" if index == 1 else f"classes{index}.dex")
        shutil.copy2(path, target)
        results.append(file_record(target, case_root, source="user-supplied", source_path=str(path.resolve())))
    return results
