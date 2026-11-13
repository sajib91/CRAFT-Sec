"""Contract tests for the shared CRAFT-Sec JSON Schemas.

The same schemas and fixtures are exercised by the JavaScript suite in
``vscode-extension/test/unit/sharedContracts.test.js``. These tests are the
Python side of that shared contract; they validate the schemas themselves, every
valid fixture, and the negative cases that protect score and availability
semantics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"
FIXTURE_DIR = REPO_ROOT / "shared" / "fixtures" / "contracts"
MANIFEST = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))

EXPECTED_CONTRACTS = {
    "ScanRequest",
    "ScanResult",
    "VulnerabilityFinding",
    "FeatureExtractionResult",
    "CounterfactualResult",
    "SteeringResult",
    "ExplanationResult",
    "RepairCandidate",
    "VerificationResult",
    "ExperimentMetadata",
}

FINDING_REQUIRED_FIELDS = [
    "findingId",
    "filePath",
    "location",
    "cwe",
    "severity",
    "evidenceSources",
    "riskScore",
    "explanation",
    "suggestedRemediation",
    "provenance",
]


def _load_schemas() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_file: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        if path.name == "manifest.json":
            continue
        schema = json.loads(path.read_text(encoding="utf-8"))
        by_id[schema["$id"]] = schema
        by_file[path.name] = schema
    return by_id, by_file


SCHEMAS_BY_ID, SCHEMAS_BY_FILE = _load_schemas()
REGISTRY = Registry().with_resources(
    (
        schema_id,
        Resource.from_contents(schema, default_specification=DRAFT202012),
    )
    for schema_id, schema in SCHEMAS_BY_ID.items()
)


def validator_for(contract: str) -> Draft202012Validator:
    """Return a validator for one contract named in the manifest."""
    entry = MANIFEST["schemas"][contract]
    return Draft202012Validator(SCHEMAS_BY_FILE[entry["schema"]], registry=REGISTRY)


def load_fixture(relative_path: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / relative_path).read_text(encoding="utf-8"))


def error_summary(errors: list[Any]) -> str:
    return "\n".join(
        f"{'/'.join(str(part) for part in error.path) or '<root>'}: "
        f"{error.validator}: {error.message}"
        for error in errors
    )


VALID_CASES = [
    pytest.param(
        contract,
        fixture,
        id=f"{contract}-{Path(fixture).stem}",
    )
    for contract, entry in MANIFEST["schemas"].items()
    for fixture in entry["validFixtures"]
]

INVALID_CASES = [
    pytest.param(
        case["schema"],
        case["fixture"],
        case["keyword"],
        id=Path(case["fixture"]).stem,
    )
    for case in MANIFEST["invalidFixtures"]
]


@pytest.mark.parametrize("contract,fixture", VALID_CASES)
def test_valid_fixtures_validate(contract: str, fixture: str) -> None:
    errors = list(validator_for(contract).iter_errors(load_fixture(f"valid/{fixture}")))
    assert errors == [], f"{fixture} did not validate:\n{error_summary(errors)}"


@pytest.mark.parametrize("contract,fixture,expected_keyword", INVALID_CASES)
def test_invalid_fixtures_are_rejected(
    contract: str,
    fixture: str,
    expected_keyword: str,
) -> None:
    errors = list(validator_for(contract).iter_errors(load_fixture(fixture)))
    assert errors, f"{fixture} unexpectedly validated"
    keywords = {error.validator for error in errors}
    assert expected_keyword in keywords, (
        f"{fixture} failed for {sorted(keywords)}, not the expected "
        f"{expected_keyword!r}:\n{error_summary(errors)}"
    )


@pytest.mark.parametrize("schema_file", sorted(SCHEMAS_BY_FILE), ids=sorted(SCHEMAS_BY_FILE))
def test_schemas_are_valid_draft_2020_12(schema_file: str) -> None:
    schema = SCHEMAS_BY_FILE[schema_file]
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].startswith("https://craftsec.local/schemas/v1/")
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize(
    "schema_file",
    sorted(name for name in SCHEMAS_BY_FILE if name != "common.json"),
)
def test_payload_schemas_reject_unknown_fields(schema_file: str) -> None:
    assert SCHEMAS_BY_FILE[schema_file]["additionalProperties"] is False


def test_manifest_contract_version_matches_the_version_file() -> None:
    version = (SCHEMA_DIR / "VERSION").read_text(encoding="utf-8").strip()
    assert MANIFEST["contractVersion"] == version
    assert MANIFEST["jsonSchemaDialect"] == "https://json-schema.org/draft/2020-12/schema"


def test_manifest_declares_the_requested_contracts() -> None:
    assert set(MANIFEST["schemas"]) == EXPECTED_CONTRACTS


def test_manifest_references_every_schema_and_fixture() -> None:
    referenced_schemas = {entry["schema"] for entry in MANIFEST["schemas"].values()}
    assert referenced_schemas == set(SCHEMAS_BY_FILE) - {"common.json"}

    referenced_valid = {
        fixture for entry in MANIFEST["schemas"].values() for fixture in entry["validFixtures"]
    }
    actual_valid = {path.name for path in (FIXTURE_DIR / "valid").glob("*.json")}
    assert referenced_valid == actual_valid

    referenced_invalid = {case["fixture"] for case in MANIFEST["invalidFixtures"]}
    actual_invalid = {f"invalid/{path.name}" for path in (FIXTURE_DIR / "invalid").glob("*.json")}
    assert referenced_invalid == actual_invalid


@pytest.mark.parametrize("field", FINDING_REQUIRED_FIELDS)
def test_finding_requires_every_documented_field(field: str) -> None:
    finding = load_fixture("valid/vulnerability-finding-heuristic.json")
    del finding[field]
    assert not validator_for("VulnerabilityFinding").is_valid(finding), (
        f"VulnerabilityFinding accepted a finding without {field}"
    )


@pytest.mark.parametrize("field", ["line", "column"])
def test_finding_location_requires_line_and_column(field: str) -> None:
    finding = load_fixture("valid/vulnerability-finding-heuristic.json")
    del finding["location"]["start"][field]
    assert not validator_for("VulnerabilityFinding").is_valid(finding)


@pytest.mark.parametrize("field", ["value", "kind", "interpretation"])
def test_risk_score_requires_explicit_semantics(field: str) -> None:
    finding = load_fixture("valid/vulnerability-finding-heuristic.json")
    del finding["riskScore"][field]
    assert not validator_for("VulnerabilityFinding").is_valid(finding)


def test_heuristic_score_rejects_a_calibrated_probability_interpretation() -> None:
    finding = load_fixture("valid/vulnerability-finding-heuristic.json")
    finding["riskScore"]["interpretation"] = "calibrated_probability"
    assert not validator_for("VulnerabilityFinding").is_valid(finding)


def test_heuristic_score_rejects_calibrator_evidence() -> None:
    finding = load_fixture("valid/vulnerability-finding-heuristic.json")
    calibrated = load_fixture("valid/vulnerability-finding-calibrated.json")
    finding["riskScore"]["calibrator"] = calibrated["riskScore"]["calibrator"]
    assert not validator_for("VulnerabilityFinding").is_valid(finding)


def test_calibrated_score_requires_a_calibrator() -> None:
    finding = load_fixture("valid/vulnerability-finding-calibrated.json")
    del finding["riskScore"]["calibrator"]
    assert not validator_for("VulnerabilityFinding").is_valid(finding)


def test_calibrated_score_rejects_values_outside_the_unit_interval() -> None:
    finding = load_fixture("valid/vulnerability-finding-calibrated.json")
    finding["riskScore"]["value"] = 1.2
    assert not validator_for("VulnerabilityFinding").is_valid(finding)


def test_model_logit_is_never_labelled_as_a_probability() -> None:
    finding = load_fixture("valid/vulnerability-finding-heuristic.json")
    finding["riskScore"] = {
        "value": 2.4,
        "kind": "model_logit",
        "interpretation": "model_score_not_calibrated",
    }
    validator = validator_for("VulnerabilityFinding")
    assert validator.is_valid(finding)

    finding["riskScore"]["interpretation"] = "calibrated_probability"
    assert not validator.is_valid(finding)


def test_unavailable_scan_with_empty_findings_remains_valid() -> None:
    result = load_fixture("valid/scan-result.json")
    result["analysisAvailable"] = False
    result["status"] = "partial"
    result["findings"] = []
    assert validator_for("ScanResult").is_valid(result)
