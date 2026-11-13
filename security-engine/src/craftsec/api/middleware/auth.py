"""Optional per-launch bearer-token enforcement for API routes."""

from __future__ import annotations

import secrets

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from craftsec.api.middleware.problem import problem_response
from craftsec.api.middleware.request_context import request_id_from_scope


class BearerTokenMiddleware:
    """Require ``Authorization: Bearer`` when a token is configured.

    The token is supplied at process launch, never embedded in source, query
    strings, logs, or URLs. When no token is configured the middleware is a
    pass-through for local development.
    """

    def __init__(self, app: ASGIApp, token: str | None, api_prefix: str = "/api/") -> None:
        self.app = app
        self.token = token
        self.api_prefix = api_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or self.token is None
            or scope.get("method") == "OPTIONS"
            or not str(scope.get("path", "")).startswith(self.api_prefix)
        ):
            await self.app(scope, receive, send)
            return

        authorization = Headers(scope=scope).get("authorization", "")
        scheme, _, supplied = authorization.partition(" ")
        if scheme.lower() != "bearer" or not supplied:
            await self._deny(scope, send)
            return
        if not secrets.compare_digest(supplied, self.token):
            await self._deny(scope, send)
            return
        await self.app(scope, receive, send)

    async def _deny(self, scope: Scope, send: Send) -> None:
        response = problem_response(
            request_id=request_id_from_scope(scope),
            instance=str(scope.get("path", "")),
            status=401,
            code="E_UNAUTHORIZED",
            title="Authentication required",
            detail="A valid bearer token is required for this API.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, _unused_receive, send)


async def _unused_receive() -> dict[str, object]:
    return {"type": "http.request", "body": b"", "more_body": False}
