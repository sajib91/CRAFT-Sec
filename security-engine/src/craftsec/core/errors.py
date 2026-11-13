"""Typed application errors that map to RFC 9457 problem details."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """An expected, client-visible error.

    The raised exception carries only sanitized information. Internal exception
    text and stack traces are logged by the API layer and never returned.
    """

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        title: str,
        detail: str,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.title = title
        self.detail = detail
        self.retryable = retryable
        self.details = details
        self.headers = headers or {}


class ValidationAppError(AppError):
    def __init__(self, detail: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            status_code=422,
            code="E_VALIDATION",
            title="Request validation failed",
            detail=detail,
            details=details,
        )


class NotFoundAppError(AppError):
    def __init__(self, detail: str = "The requested resource does not exist.") -> None:
        super().__init__(
            status_code=404,
            code="E_NOT_FOUND",
            title="Resource not found",
            detail=detail,
        )


class ConflictAppError(AppError):
    def __init__(self, detail: str, *, code: str = "E_CONFLICT") -> None:
        super().__init__(
            status_code=409,
            code=code,
            title="Request conflict",
            detail=detail,
        )


class CapabilityUnavailableError(AppError):
    def __init__(self, *, code: str, detail: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            status_code=409,
            code=code,
            title="Capability unavailable",
            detail=detail,
            details=details,
        )


class SecurityAppError(AppError):
    def __init__(self, detail: str, *, code: str = "E_SECURITY") -> None:
        super().__init__(
            status_code=403,
            code=code,
            title="Request denied",
            detail=detail,
        )


class ResourceLimitAppError(AppError):
    def __init__(self, detail: str, *, code: str = "E_RESOURCE") -> None:
        super().__init__(
            status_code=413,
            code=code,
            title="Request too large",
            detail=detail,
            details=None,
        )


class UnsupportedMediaAppError(AppError):
    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=415,
            code="E_UNSUPPORTED_FILE",
            title="Unsupported file",
            detail=detail,
        )


class InternalAppError(AppError):
    def __init__(self, detail: str = "The security engine could not complete the request.") -> None:
        super().__init__(
            status_code=500,
            code="E_INTERNAL",
            title="Internal engine error",
            detail=detail,
        )
