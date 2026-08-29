import sys

from vmpwf.core import run_command


def test_run_command_replaces_non_utf8_output(tmp_path):
    result = run_command([
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(bytes([255, 254])); sys.stderr.buffer.write(bytes([253]))",
    ], tmp_path)
    assert result["returncode"] == 0
    assert result["stdout"]
    assert result["stderr"]
