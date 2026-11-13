from __future__ import annotations

REQUIRED_OPERATIONS = {
    ("get", "/api/v1/health"),
    ("post", "/api/v1/scan/file"),
    ("post", "/api/v1/scan/workspace"),
    ("post", "/api/v1/detection/analyze"),
    ("post", "/api/v1/explanation/analyze"),
    ("post", "/api/v1/features/extract"),
    ("post", "/api/v1/counterfactual/analyze"),
    ("post", "/api/v1/prevention/steer"),
    ("post", "/api/v1/repair/generate"),
    ("post", "/api/v1/verification/run"),
}


def test_openapi_exposes_exactly_the_versioned_operations(api) -> None:
    response = api.client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    operations = {(method, path) for path, methods in schema["paths"].items() for method in methods}
    assert operations == REQUIRED_OPERATIONS
    assert schema["info"]["title"] == "CRAFT-Sec Security Engine API"
    assert schema["info"]["version"] == "0.1.0"


def test_every_operation_documents_success_and_problem_details(api) -> None:
    schema = api.client.get("/openapi.json").json()

    operation_ids: set[str] = set()
    for path, methods in schema["paths"].items():
        for method, operation in methods.items():
            assert operation.get("summary"), f"{method.upper()} {path} has no summary"
            assert operation.get("tags"), f"{method.upper()} {path} has no tags"
            assert operation.get("operationId"), f"{method.upper()} {path} has no operationId"
            operation_ids.add(operation["operationId"])
            assert "200" in operation["responses"]
            assert "422" in operation["responses"]
            validation_schema = operation["responses"]["422"]["content"][
                "application/problem+json"
            ]["schema"]
            assert validation_schema["$ref"].endswith("/ProblemDetail")

    assert len(operation_ids) == len(REQUIRED_OPERATIONS)


def test_problem_detail_schema_is_generated(api) -> None:
    schema = api.client.get("/openapi.json").json()

    problem = schema["components"]["schemas"]["ProblemDetail"]
    for field in ("type", "title", "status", "code", "detail", "instance", "requestId"):
        assert field in problem["properties"]
    bearer = schema["components"]["securitySchemes"]["BearerAuth"]
    assert bearer["type"] == "http"
    assert bearer["scheme"] == "bearer"


def test_interactive_documentation_is_available(api) -> None:
    docs = api.client.get("/docs")
    openapi = api.client.get("/openapi.json")

    assert docs.status_code == 200
    assert "text/html" in docs.headers["content-type"]
    assert openapi.status_code == 200
    assert openapi.headers["content-type"].startswith("application/json")
