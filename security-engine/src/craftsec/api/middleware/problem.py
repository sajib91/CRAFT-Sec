"""Shared RFC 9457 problem-detail response helpers."""

from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse

from craftsec.api.schemas.common import ProblemDetail
from craftsec.config import ERROR_TYPE_BASE, PROBLEM_MEDIA_TYPE


def problem_payload(
    *,
    request_id: str,
    instance: str,
    status: int,
    code: str,
    title: str,
    detail: str,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    problem = ProblemDetail(
        type=f"{ERROR_TYPE_BASE}/{code}",
        title=title,
        status=status,
        code=code,
        detail=detail,
        instance=instance,
        retryable=retryable,
        request_id=request_id,
        details=details,
    )
    return problem.model_dump(by_alias=True, mode="json")


def problem_response(
    *,
    request_id: str,
    instance: str,
    status: int,
    code: str,
    title: str,
    detail: str,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content=problem_payload(
            request_id=request_id,
            instance=instance,
            status=status,
            code=code,
            title=title,
            detail=detail,
            retryable=retryable,
            details=details,
        ),
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )
