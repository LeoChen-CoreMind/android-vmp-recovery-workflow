import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("relative", [
    "scripts/ida/static_vmp_probe.py",
    "scripts/ida/bind_vm_evidence.py",
    "scripts/fix/dex/enrich_vm_streams.py",
    "scripts/fix/dex/restore_vmp_dex.py",
    "scripts/simulation/unicorn_literal_decoder.py",
    "scripts/simulation/unicorn_fetch_decoder_confirmation.py",
    "scripts/simulation/run_native_confirmation.py",
])
def test_script_help_entrypoints(relative):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / relative), "--help"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
