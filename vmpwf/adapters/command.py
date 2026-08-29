from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core import run_command


class CommandAdapter:
    def run(self, command: list[str], cwd: Path, timeout: int = 300) -> dict[str, Any]:
        return run_command(command, cwd=cwd, timeout=timeout)
