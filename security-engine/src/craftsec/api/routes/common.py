"""Shared OpenAPI error-response declarations."""

from __future__ import annotations

from craftsec.api.schemas.common import ProblemDetail

COMMON_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": ProblemDetail, "description": "Invalid request."},
    401: {"model": ProblemDetail, "description": "Bearer token required or invalid."},
    403: {"model": ProblemDetail, "description": "Path or security policy denied."},
    404: {"model": ProblemDetail, "description": "File or route not found."},
    409: {"model": ProblemDetail, "description": "Request conflicts with engine state."},
    413: {"model": ProblemDetail, "description": "Request or file exceeds a configured limit."},
    415: {"model": ProblemDetail, "description": "Unsupported file type or encoding."},
    422: {"model": ProblemDetail, "description": "Schema validation failed."},
    500: {"model": ProblemDetail, "description": "Sanitized internal engine error."},
}
