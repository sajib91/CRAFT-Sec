from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from craftsec.api.app import create_app
from craftsec.core.settings import Settings


def test_validation_errors_use_rfc9457_problem_details(api) -> None:
    response = api.client.post("/api/v1/scan/file", json={})

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["type"] == "https://craftsec.local/errors/E_VALIDATION"
    assert body["title"] == "Request validation failed"
    assert body["status"] == 422
    assert body["code"] == "E_VALIDATION"
    assert body["instance"] == "/api/v1/scan/file"
    assert body["retryable"] is False
    assert body["requestId"] == response.headers["X-Request-ID"]
    assert body["details"]["errors"]
    locations = [error["location"] for error in body["details"]["errors"]]
    assert ["body", "filePath"] in locations
    assert ["body", "workspaceRoot"] in locations


def test_malformed_json_returns_a_problem_detail(api) -> None:
    response = api.client.post(
        "/api/v1/scan/file",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "E_VALIDATION"


def test_unknown_route_returns_a_problem_detail(api) -> None:
    response = api.client.get("/api/v1/unknown")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "E_NOT_FOUND"
    assert response.json()["instance"] == "/api/v1/unknown"


def test_method_not_allowed_returns_a_problem_detail(api) -> None:
    response = api.client.get("/api/v1/scan/file")

    assert response.status_code == 405
    assert response.json()["code"] == "E_METHOD_NOT_ALLOWED"


def test_valid_request_id_is_echoed(api) -> None:
    response = api.client.get(
        "/api/v1/health",
        headers={"X-Request-ID": "test-request-123"},
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-request-123"


def test_invalid_request_id_is_replaced(api) -> None:
    response = api.client.get(
        "/api/v1/health",
        headers={"X-Request-ID": "bad id!"},
    )

    assert response.status_code == 200
    generated = response.headers["X-Request-ID"]
    assert generated != "bad id!"
    assert len(generated) == 32


def test_unhandled_errors_are_sanitized(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, workspace_roots=[tmp_path], log_level="CRITICAL")
    app = create_app(settings)

    @app.get("/api/v1/__test__/boom", include_in_schema=False)
    def boom() -> None:
        raise RuntimeError("leaked-internal-detail")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/__test__/boom")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "E_INTERNAL"
    assert body["detail"] == "The security engine could not complete the request."
    assert "leaked-internal-detail" not in response.text
    assert body["requestId"] == response.headers["X-Request-ID"]
