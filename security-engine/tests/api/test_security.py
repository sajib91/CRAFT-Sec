from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from craftsec.api.app import create_app
from craftsec.core.settings import Settings


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    settings = Settings(
        _env_file=None,
        workspace_roots=[tmp_path],
        log_level="ERROR",
        **overrides,
    )
    return TestClient(create_app(settings), raise_server_exceptions=False)


def test_bearer_auth_is_enforced_when_a_token_is_configured(tmp_path: Path) -> None:
    with _client(tmp_path, api_token="test-token-value") as client:
        missing = client.get("/api/v1/health")
        wrong = client.get(
            "/api/v1/health",
            headers={"Authorization": "Bearer wrong-token"},
        )
        malformed = client.get(
            "/api/v1/health",
            headers={"Authorization": "Basic test-token-value"},
        )
        accepted = client.get(
            "/api/v1/health",
            headers={"Authorization": "bearer test-token-value"},
        )

    assert missing.status_code == 401
    assert missing.headers["WWW-Authenticate"] == "Bearer"
    assert missing.json()["code"] == "E_UNAUTHORIZED"
    assert wrong.status_code == 401
    assert malformed.status_code == 401
    assert accepted.status_code == 200
    assert "test-token-value" not in accepted.text


def test_auth_does_not_block_preflight_or_the_local_index(tmp_path: Path) -> None:
    with _client(tmp_path, api_token="test-token-value") as client:
        preflight = client.options("/api/v1/health")
        index = client.get("/")

    assert preflight.status_code != 401
    assert index.status_code == 200
    assert index.json()["service"] == "craftsec-engine"


def test_cors_allows_only_configured_origins(tmp_path: Path) -> None:
    with _client(tmp_path, cors_origins=["http://localhost:3000"]) as client:
        allowed = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        actual = client.get(
            "/api/v1/health",
            headers={"Origin": "http://localhost:3000"},
        )
        denied = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )

    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    assert allowed.headers["X-Request-ID"]
    assert allowed.headers.get("Access-Control-Allow-Credentials") != "true"
    assert actual.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    assert actual.headers.get("Access-Control-Expose-Headers") == "X-Request-ID"
    assert "Access-Control-Allow-Origin" not in denied.headers


def test_cors_headers_are_absent_by_default(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        response = client.get(
            "/api/v1/health",
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_cors_preflight_bypasses_bearer_auth(tmp_path: Path) -> None:
    with _client(
        tmp_path,
        api_token="test-token-value",
        cors_origins=["http://localhost:3000"],
    ) as client:
        response = client.options(
            "/api/v1/scan/file",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"


def test_cors_headers_are_present_on_error_responses(tmp_path: Path) -> None:
    with _client(tmp_path, cors_origins=["http://localhost:3000"]) as client:
        response = client.post(
            "/api/v1/scan/file",
            json={},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 422
    assert response.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"


def test_declared_oversized_requests_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    with _client(tmp_path, max_request_bytes=1024) as client:
        response = client.post(
            "/api/v1/scan/file",
            json={
                "workspaceRoot": str(tmp_path),
                "filePath": "app.py",
                "selectedText": "x" * 4096,
            },
        )

    assert response.status_code == 413
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "E_REQUEST_TOO_LARGE"
    assert body["requestId"] == response.headers["X-Request-ID"]


def test_requests_within_the_limit_still_succeed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    with _client(tmp_path, max_request_bytes=1024) as client:
        response = client.post(
            "/api/v1/scan/file",
            json={"workspaceRoot": str(tmp_path), "filePath": "app.py"},
        )

    assert response.status_code == 200


def test_streamed_oversized_requests_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    def chunks():
        yield (
            b'{"workspaceRoot": "'
            + str(tmp_path).encode()
            + b'", "filePath": "app.py", "selectedText": "'
        )
        yield b"x" * 2048
        yield b'"}'

    with _client(tmp_path, max_request_bytes=1024) as client:
        response = client.post(
            "/api/v1/scan/file",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "E_REQUEST_TOO_LARGE"
    assert response.json()["requestId"] == response.headers["X-Request-ID"]
