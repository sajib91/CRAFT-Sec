from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from craftsec.api.app import create_app
from craftsec.core.settings import Settings

SAMPLE_SOURCE = """\
import sqlite3


def connect(value):
    return sqlite3.connect(value)
"""


@dataclass(frozen=True)
class ApiContext:
    client: TestClient
    app: FastAPI
    settings: Settings
    root: Path

    def payload(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "workspaceRoot": str(self.root),
            "filePath": str(self.root / "app.py"),
        }
        payload.update(overrides)
        return payload


def build_client(root: Path, **settings_overrides: object) -> TestClient:
    """Create a test client with isolated runtime settings."""
    settings = Settings(
        _env_file=None,
        workspace_roots=[root],
        log_level="ERROR",
        **settings_overrides,
    )
    return TestClient(create_app(settings), raise_server_exceptions=False)


@pytest.fixture
def api(tmp_path: Path) -> Iterator[ApiContext]:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text(SAMPLE_SOURCE, encoding="utf-8")
    (root / "notes.md").write_text("# Not a source file\n", encoding="utf-8")

    settings = Settings(
        _env_file=None,
        workspace_roots=[root],
        log_level="ERROR",
    )
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield ApiContext(client=client, app=app, settings=settings, root=root)
