from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def isolate_engine_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests independent of a developer's ambient engine configuration."""
    for name in list(os.environ):
        if name.startswith("CRAFTSEC_") or name == "HF_TOKEN":
            monkeypatch.delenv(name, raising=False)
