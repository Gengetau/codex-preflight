import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def _git_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ROOT / "test-tmp"))


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest, _git_ceiling: None) -> Iterator[Path]:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.nodeid)
    path = ROOT / "test-tmp" / f"{safe_name}-{uuid4().hex}"
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
