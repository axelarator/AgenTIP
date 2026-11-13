"""The lint rules in pyproject.toml hold for the whole tree."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def test_ruff_is_clean():
    ruff = shutil.which("ruff", path=str(Path(sys.executable).parent)) or shutil.which("ruff")
    if ruff is None:
        pytest.skip("ruff is not installed (pip install -e '.[test]')")
    done = subprocess.run([ruff, "check", str(REPO)], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout[-3000:]
