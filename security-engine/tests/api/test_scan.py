from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from craftsec.api.app import create_app
from craftsec.core.settings import Settings


def test_scan_file_reports_real_metadata_and_explicit_unavailable_stages(api) -> None:
    response = api.client.post("/api/v1/scan/file", json=api.payload())

    assert response.status_code == 200
    body = response.json()
    expected_bytes = (api.root / "app.py").read_bytes()

    assert body["operation"] == "scan_file"
    assert body["status"] == "partial"
    assert body["apiVersion"] == "v1"
    assert body["result"] is None
    assert body["findings"] == []
    assert body["analysisAvailable"] is False
    assert body["filesScanned"] == 1
    assert body["file"]["size"] == len(expected_bytes)
    assert body["file"]["sha256"] == hashlib.sha256(expected_bytes).hexdigest()
    assert body["file"]["languageId"] == "python"
    assert body["file"]["path"] == str((api.root / "app.py").resolve())
    assert body["scope"]["uris"] == [body["file"]["uri"]]
    assert [stage["stage"] for stage in body["stages"]] == [
        "file_snapshot",
        "static_evidence",
        "detection",
    ]
    assert [stage["status"] for stage in body["stages"]] == [
        "ok",
        "unavailable",
        "unavailable",
    ]
    assert body["stages"][1]["reasonCode"] == "E_ANALYZER_UNAVAILABLE"
    assert body["stages"][2]["reasonCode"] == "E_DETECTOR_UNAVAILABLE"


def test_scan_file_accepts_a_relative_path(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": "app.py"},
    )

    assert response.status_code == 200
    assert response.json()["file"]["path"] == str((api.root / "app.py").resolve())


def test_scan_file_hashes_supplied_source_text_instead_of_the_disk_copy(api) -> None:
    supplied = "def supplied_from_editor():\n    return 1\n"
    disk = (api.root / "app.py").read_text(encoding="utf-8")
    assert supplied != disk

    response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(sourceText=supplied, languageId="python"),
    )

    assert response.status_code == 200
    body = response.json()
    data = supplied.encode("utf-8")
    assert body["file"]["size"] == len(data)
    assert body["file"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert body["file"]["path"] == str((api.root / "app.py").resolve())
    assert body["filesScanned"] == 1
    assert body["analysisAvailable"] is False


def test_scan_file_validates_a_selection_against_supplied_source_text(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(
            sourceText="short = 1\n",
            selection={
                "start": {"line": 3, "character": 0},
                "end": {"line": 3, "character": 1},
            },
        ),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "selection" in response.json()["detail"].lower()


def test_scan_file_still_requires_supplied_source_to_match_an_allowed_path(
    api,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("outside = True\n", encoding="utf-8")

    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": str(outside), "sourceText": "safe = 1\n"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "E_PATH_OUTSIDE_WORKSPACE"


def test_scan_file_enforces_the_file_size_limit_for_supplied_source_text(api) -> None:
    settings = Settings(
        _env_file=None,
        workspace_roots=[api.root],
        log_level="CRITICAL",
        max_file_bytes=16,
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/api/v1/scan/file",
            json=api.payload(sourceText="x" * 32),
        )

    assert response.status_code == 413
    assert response.json()["code"] == "E_FILE_TOO_LARGE"


def test_scan_file_rejects_nul_bytes_in_supplied_source_text(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(sourceText="value = 1\x00"),
    )

    assert response.status_code == 415
    assert response.json()["code"] == "E_UNSUPPORTED_FILE"


def test_scan_file_accepts_a_selection_inside_the_file(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(
            selection={
                "start": {"line": 3, "character": 4},
                "end": {"line": 3, "character": 17},
            }
        ),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "partial"


def test_scan_file_rejects_a_selection_outside_the_file(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(
            selection={
                "start": {"line": 99, "character": 0},
                "end": {"line": 99, "character": 1},
            }
        ),
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "E_VALIDATION"
    assert "selection" in body["detail"].lower()


def test_scan_workspace_discovers_sources_and_ignores_generated_directories(api) -> None:
    package = api.root / "src"
    package.mkdir()
    (package / "util.js").write_text("export const value = 1;\n", encoding="utf-8")
    node_modules = api.root / "node_modules"
    node_modules.mkdir()
    (node_modules / "ignored.js").write_text("export const ignored = 1;\n", encoding="utf-8")
    git_dir = api.root / ".git"
    git_dir.mkdir()
    (git_dir / "ignored.py").write_text("ignored = True\n", encoding="utf-8")
    (api.root / "image.bin").write_bytes(b"\x00\x01\x02")

    response = api.client.post(
        "/api/v1/scan/workspace",
        json={"workspaceFolders": [{"name": "workspace", "path": str(api.root)}]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == "scan_workspace"
    assert body["status"] == "partial"
    assert body["analysisAvailable"] is False
    assert body["findings"] == []
    assert body["filesScanned"] == 2
    assert len(body["scope"]["uris"]) == 2
    assert all(uri.endswith((".py", ".js")) for uri in body["scope"]["uris"])
    assert body["stages"][0]["stage"] == "workspace_snapshot"
    assert body["stages"][0]["data"] == {"fileCount": 2, "rootCount": 1}
    assert body["stages"][1]["reasonCode"] == "E_ANALYZER_UNAVAILABLE"
    assert body["stages"][2]["reasonCode"] == "E_DETECTOR_UNAVAILABLE"


def test_scan_workspace_accepts_an_empty_workspace(api) -> None:
    empty = api.root / "empty"
    empty.mkdir()

    response = api.client.post(
        "/api/v1/scan/workspace",
        json={"workspaceFolders": [{"name": "empty", "path": str(empty)}]},
    )

    assert response.status_code == 200
    assert response.json()["filesScanned"] == 0
    assert response.json()["scope"]["uris"] == []


def test_scan_workspace_rejects_roots_outside_the_allowlist(api, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()

    response = api.client.post(
        "/api/v1/scan/workspace",
        json={"workspaceFolders": [{"name": "outside", "path": str(outside)}]},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "E_ROOT_NOT_ALLOWED"


def test_scan_file_rejects_traversal_outside_the_workspace(api, tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n", encoding="utf-8")

    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": "../outside.py"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "E_PATH_OUTSIDE_WORKSPACE"


def test_scan_file_rejects_a_symlink_that_escapes_the_workspace(api, tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n", encoding="utf-8")
    link = api.root / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are unavailable on this platform")

    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": str(link)},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "E_PATH_OUTSIDE_WORKSPACE"


def test_scan_file_returns_problem_details_for_missing_files(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": "missing.py"},
    )

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "E_NOT_FOUND"


def test_scan_file_rejects_binary_content(api) -> None:
    binary = api.root / "binary.py"
    binary.write_bytes(b"value = 1\x00\x02\x03")

    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": "binary.py"},
    )

    assert response.status_code == 415
    assert response.json()["code"] == "E_UNSUPPORTED_FILE"


def test_scan_file_rejects_invalid_utf8(api) -> None:
    invalid = api.root / "invalid.py"
    invalid.write_bytes(b"\xff\xfevalue = 1\n")

    response = api.client.post(
        "/api/v1/scan/file",
        json={"workspaceRoot": str(api.root), "filePath": "invalid.py"},
    )

    assert response.status_code == 415
    assert response.json()["code"] == "E_UNSUPPORTED_FILE"


def test_scan_file_enforces_the_file_size_limit(api) -> None:
    settings = Settings(
        _env_file=None,
        workspace_roots=[api.root],
        log_level="CRITICAL",
        max_file_bytes=16,
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/api/v1/scan/file",
            json={"workspaceRoot": str(api.root), "filePath": "app.py"},
        )

    assert response.status_code == 413
    assert response.json()["code"] == "E_FILE_TOO_LARGE"


def test_scan_workspace_enforces_the_file_count_limit(api) -> None:
    (api.root / "second.py").write_text("second = True\n", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        workspace_roots=[api.root],
        log_level="CRITICAL",
        max_workspace_files=1,
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/api/v1/scan/workspace",
            json={"workspaceFolders": [{"name": "workspace", "path": str(api.root)}]},
        )

    assert response.status_code == 413
    assert response.json()["code"] == "E_WORKSPACE_TOO_LARGE"
