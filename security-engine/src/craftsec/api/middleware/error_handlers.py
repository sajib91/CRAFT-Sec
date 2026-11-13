"""Exception-to-problem-detail handlers."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from craftsec.api.middleware.problem import problem_response
from craftsec.config import REQUEST_ID_HEADER
from craftsec.core.errors import AppError, InternalAppError
from craftsec.core.logging import get_logger

logger = get_logger("craftsec.api.errors")


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "-"))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> Response:
        return problem_response(
            request_id=_request_id(request),
            instance=request.url.path,
            status=exc.status_code,
            code=exc.code,
            title=exc.title,
            detail=exc.detail,
            retryable=exc.retryable,
            details=exc.details,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> Response:
        errors: list[dict[str, Any]] = []
        for error in exc.errors():
            errors.append(
                {
                    "location": [str(part) for part in error.get("loc", ())],
                    "message": error.get("msg", "Invalid value."),
                    "type": error.get("type", "value_error"),
                }
            )
        return problem_response(
            request_id=_request_id(request),
            instance=request.url.path,
            status=422,
            code="E_VALIDATION",
            title="Request validation failed",
            detail="One or more request fields are invalid.",
            details={"errors": errors},
        )

    @app.exception_handler(ResponseValidationError)
    async def response_validation_error_handler(
        request: Request,
        exc: ResponseValidationError,
    ) -> Response:
        logger.exception(
            "Response validation failed.",
            extra={"request_id": _request_id(request), "path": request.url.path},
        )
        return _internal_response(request)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> Response:
        code = {
            404: "E_NOT_FOUND",
            405: "E_METHOD_NOT_ALLOWED",
            413: "E_REQUEST_TOO_LARGE",
            415: "E_UNSUPPORTED_FILE",
        }.get(exc.status_code, "E_HTTP")
        title = {
            404: "Resource not found",
            405: "Method not allowed",
            413: "Request too large",
            415: "Unsupported file",
        }.get(exc.status_code, "Request failed")
        detail = str(exc.detail) if exc.detail else title
        return problem_response(
            request_id=_request_id(request),
            instance=request.url.path,
            status=exc.status_code,
            code=code,
            title=title,
            detail=detail,
            headers=cast(dict[str, str] | None, exc.headers),
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> Response:
        logger.exception(
            "Unhandled API exception.",
            extra={"request_id": _request_id(request), "path": request.url.path},
        )
        del exc
        return _internal_response(request)


def _internal_response(request: Request) -> Response:
    request_id = _request_id(request)
    error = InternalAppError()
    return problem_response(
        request_id=request_id,
        instance=request.url.path,
        status=error.status_code,
        code=error.code,
        title=error.title,
        detail=error.detail,
        headers={REQUEST_ID_HEADER: request_id},
    )
