from __future__ import annotations

from pathlib import Path

import pytest

from craftsec.api.schemas.scan import FileContext


def _file_uri(api) -> str:
    return (api.root / "app.py").resolve().as_uri()


def _range() -> dict[str, object]:
    return {
        "start": {"line": 3, "character": 4},
        "end": {"line": 3, "character": 17},
    }


def _validation_messages(response) -> str:
    errors = response.json()["details"]["errors"]
    return " ".join(error.get("message", "") for error in errors).lower()


def _assert_unavailable(
    response,
    *,
    operation: str,
    stage_names: list[str],
    reason_codes: list[str],
) -> dict[str, object]:
    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == operation
    assert body["status"] == "partial"
    assert body["result"]["analysisAvailable"] is False
    assert [stage["stage"] for stage in body["stages"]] == ["file_snapshot", *stage_names]
    assert [stage["status"] for stage in body["stages"]] == [
        "ok",
        *["unavailable"] * len(stage_names),
    ]
    assert [stage["reasonCode"] for stage in body["stages"][1:]] == reason_codes
    return body


def test_detection_returns_no_fabricated_findings(api) -> None:
    response = api.client.post("/api/v1/detection/analyze", json=api.payload())

    body = _assert_unavailable(
        response,
        operation="detection_analyze",
        stage_names=["static_evidence", "detection"],
        reason_codes=["E_ANALYZER_UNAVAILABLE", "E_DETECTOR_UNAVAILABLE"],
    )
    assert body["result"]["findings"] == []
    assert body["result"]["evidenceSources"] == []
    assert body["result"]["scoreKind"] is None


def test_explanation_returns_no_fabricated_graph(api) -> None:
    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(findingId="finding-1"),
    )

    body = _assert_unavailable(
        response,
        operation="explanation_analyze",
        stage_names=["explanation"],
        reason_codes=["E_EXPLANATION_UNAVAILABLE"],
    )
    assert body["result"]["findingId"] == "finding-1"
    assert body["result"]["graph"] is None
    assert body["result"]["claimKinds"] == []
    assert body["result"]["limitations"] == []


def test_explanation_accepts_a_typed_finding(api) -> None:
    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(
            finding={
                "id": "finding-1",
                "message": "Potential SQL injection",
                "severity": "high",
                "cwe": "CWE-89",
                "location": {"uri": _file_uri(api), "range": _range()},
            }
        ),
    )

    assert response.status_code == 200
    assert response.json()["result"]["findingId"] == "finding-1"
    assert response.json()["result"]["analysisAvailable"] is False


def test_feature_extraction_returns_no_fabricated_features(api) -> None:
    response = api.client.post(
        "/api/v1/features/extract",
        json=api.payload(layer=12, hookPoint="blocks.12.hook_resid_post", aggregation="mean"),
    )

    body = _assert_unavailable(
        response,
        operation="features_extract",
        stage_names=["model_capture", "sae_features", "feature_aggregation"],
        reason_codes=[
            "E_MODEL_UNAVAILABLE",
            "E_SAE_UNAVAILABLE",
            "E_FEATURE_UNAVAILABLE",
        ],
    )
    assert body["result"]["features"] == []
    assert body["result"]["coverage"] is None
    assert body["result"]["aggregation"] == "mean"


def test_counterfactual_returns_no_fabricated_effects(api) -> None:
    response = api.client.post(
        "/api/v1/counterfactual/analyze",
        json=api.payload(
            findingId="finding-1",
            interventions=[{"kind": "ablate", "featureIndices": [12], "strength": 1.0}],
            budget=10,
            seed=7,
        ),
    )

    body = _assert_unavailable(
        response,
        operation="counterfactual_analyze",
        stage_names=["counterfactual"],
        reason_codes=["E_COUNTERFACTUAL_UNAVAILABLE"],
    )
    assert body["result"]["scope"] == "model_intervention"
    assert body["result"]["effects"] == []
    assert body["result"]["validity"] is None
    assert body["result"]["budget"] == 10


def test_prevention_returns_no_fabricated_steering_plan(api) -> None:
    response = api.client.post(
        "/api/v1/prevention/steer",
        json=api.payload(
            featureIndices=[12],
            strength=1.0,
            targetMetric="vulnerability_score",
            explicitOptIn=True,
        ),
    )

    body = _assert_unavailable(
        response,
        operation="prevention_steer",
        stage_names=["steering_plan", "steering_evaluation"],
        reason_codes=["E_STEERING_UNAVAILABLE", "E_STEERING_UNAVAILABLE"],
    )
    assert body["result"]["plan"] is None
    assert body["result"]["guardrails"] == []
    assert body["result"]["evaluation"] is None


def test_repair_returns_no_fabricated_patch(api) -> None:
    response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding={
                "findingId": "finding-1",
                "documentUri": _file_uri(api),
                "range": _range(),
                "cwe": "CWE-89",
            }
        ),
    )

    body = _assert_unavailable(
        response,
        operation="repair_generate",
        stage_names=["repair"],
        reason_codes=["E_REPAIR_UNAVAILABLE"],
    )
    assert body["result"]["patch"] is None
    assert body["result"]["touchedFiles"] == []
    assert body["result"]["rationale"] == []
    assert body["result"]["riskNotes"] == []
    assert body["result"]["requiresApproval"] is True
    assert body["result"]["metadata"] == {}


def test_verification_is_not_run_without_a_verifier(api) -> None:
    response = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(patch="diff --git a/app.py b/app.py\n"),
    )

    body = _assert_unavailable(
        response,
        operation="verification_run",
        stage_names=["verification"],
        reason_codes=["E_VERIFICATION_UNAVAILABLE"],
    )
    assert body["result"]["verdict"] == "not_run"
    assert body["result"]["checks"] == []
    assert body["result"]["sandboxBackend"] == "docker"
    assert body["result"]["limitations"]


def test_explanation_requires_a_finding_target(api) -> None:
    response = api.client.post("/api/v1/explanation/analyze", json=api.payload())

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "finding" in _validation_messages(response)


def test_explanation_rejects_a_finding_for_another_file(api, tmp_path: Path) -> None:
    other = tmp_path / "other.py"
    other.write_text("other = True\n", encoding="utf-8")

    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(
            finding={
                "id": "finding-1",
                "message": "Potential issue",
                "severity": "high",
                "location": {
                    "uri": other.resolve().as_uri(),
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 1},
                    },
                },
            }
        ),
    )

    assert response.status_code == 422
    assert "does not match" in response.json()["detail"]


def test_prevention_requires_explicit_opt_in(api) -> None:
    response = api.client.post(
        "/api/v1/prevention/steer",
        json=api.payload(featureIndices=[12], targetMetric="vulnerability_score"),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "explicitoptin" in _validation_messages(response)


def test_counterfactual_requires_at_least_one_intervention(api) -> None:
    response = api.client.post(
        "/api/v1/counterfactual/analyze",
        json=api.payload(findingId="finding-1", interventions=[]),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"


def test_verification_rejects_execution_without_the_sandbox_profile(api) -> None:
    response = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(
            patch="diff --git a/app.py b/app.py\n",
            profile="static_only",
            runExecution=True,
        ),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "runexecution" in _validation_messages(response)


def test_repair_rejects_a_finding_for_another_file(api, tmp_path: Path) -> None:
    other = tmp_path / "other.py"
    other.write_text("other = True\n", encoding="utf-8")

    response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding={
                "findingId": "finding-1",
                "documentUri": other.resolve().as_uri(),
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
            }
        ),
    )

    assert response.status_code == 422
    assert "does not match" in response.json()["detail"]


def test_invalid_range_order_is_rejected() -> None:
    with pytest.raises(ValueError):
        FileContext.model_validate(
            {
                "workspaceRoot": ".",
                "filePath": "app.py",
                "selection": {
                    "start": {"line": 2, "character": 0},
                    "end": {"line": 1, "character": 0},
                },
            }
        )
