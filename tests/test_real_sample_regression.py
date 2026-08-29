import json
from pathlib import Path

import pytest

from vmpwf.adapters import import_dex_zip
from vmpwf.cli import inspect_package
from vmpwf.validation import lm_summary


def test_jumi_runtime_dump_regression(tmp_path):
    workspace = Path(__file__).resolve().parents[2]
    apk = workspace / "剧迷TV.apk"
    dex_zip = workspace / "com.jumi.tv.zip"
    if not apk.is_file() or not dex_zip.is_file():
        pytest.skip("local authorized regression samples are not present")
    assert inspect_package(apk) == "com.jumi.tv"
    imported = import_dex_zip(dex_zip, tmp_path / "dex", tmp_path)
    assert [item["sha256"] for item in imported] == [
        "54dd21d2ef4c68106a019e797ab24a611225c7b4b6e0b46f216f86a33b851d53",
        "ad0151e0d485ad7db9d6d7b1a02f15a2d709ebba50692bc32ab2b606eebfa421",
        "d8d5ad7fcccdd0519cae24b483c40693cfb1ba1231d4163ff16fce9f8211b5fc",
    ]
    summaries = [lm_summary(Path(item["path"])) for item in imported]
    assert sum(item["method_records"] for item in summaries) == 23
    assert all(item["opcode_table_size"] == 25600 for item in summaries)
