from __future__ import annotations

import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def short_path() -> Iterator[Path]:
    root = Path.cwd() / ".pytest-tmp" / secrets.token_hex(4)
    root.mkdir(mode=0o700, parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)
