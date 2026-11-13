from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from craftsec.api.app import create_app
from craftsec.core.orchestrator import Orchestrator
from craftsec.core.pipeline import StageResult, StageStatus
from craftsec.core.settings import Settings

EXPECTED_CAPABILITIES = {
    "scan_file",
    "scan_workspace",
    "detection_analyze",
    "explanation_analyze",
    "features_extract",
    "counterfactual_analyze",
    "prevention_steer",
    "repair_generate",
    "verification_run",
}


class AvailableStage:
    available = True

    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, context: object) -> StageResult:
        del context
        return StageResult(stage=self.name, status=StageStatus.OK)


def test_health_reports_service_and_no_enabled_research_capabilities(api) -> None:
    response = api.client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "craftsec-engine"
    assert body["status"] == "ok"
    assert body["version"]
    assert body["apiVersion"] == "v1"
    assert body["sandboxBackend"] == "docker"
    assert body["uptimeSeconds"] >= 0
    assert body["timestamp"].endswith("+00:00") or body["timestamp"].endswith("Z")
    assert set(body["capabilities"]) == EXPECTED_CAPABILITIES
    assert all(value is False for value in body["capabilities"].values())


def test_health_reflects_only_the_stages_that_are_available(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, workspace_roots=[tmp_path], log_level="ERROR")
    stages = {
        "static_evidence": AvailableStage("static_evidence"),
        "detection": AvailableStage("detection"),
    }
    app = create_app(settings, Orchestrator(settings, stages))

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    capabilities = response.json()["capabilities"]
    assert capabilities["scan_file"] is True
    assert capabilities["scan_workspace"] is True
    assert capabilities["detection_analyze"] is True
    assert capabilities["features_extract"] is False
    assert capabilities["verification_run"] is False


def test_health_never_contains_configured_secret(tmp_path: Path) -> None:
    token = "local-test-token-value"
    settings = Settings(
        _env_file=None,
        workspace_roots=[tmp_path],
        log_level="ERROR",
        api_token=token,
    )
    app = create_app(settings)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert token not in response.text
    assert "apiToken" not in response.text
