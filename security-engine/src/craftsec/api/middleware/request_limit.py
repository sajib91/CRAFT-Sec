"""Hard request-body limits for JSON API calls."""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from craftsec.api.middleware.problem import problem_response
from craftsec.api.middleware.request_context import request_id_from_scope


class RequestSizeLimitMiddleware:
    """Reject oversized bodies before buffering them.

    ``Content-Length`` is checked first. Chunked or dishonest requests are
    counted as they stream and rejected when the configured limit is exceeded.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        content_length = Headers(scope=scope).get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                declared = 0
            if declared > self.max_bytes:
                await self._reject(scope, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # FastAPI converts arbitrary receive-time exceptions into a
                    # generic 400. HTTPException is re-raised and reaches the
                    # structured 413 handler.
                    raise StarletteHTTPException(
                        status_code=413,
                        detail=f"Request bodies are limited to {self.max_bytes} bytes.",
                    )
            return message

        await self.app(scope, limited_receive, send)

    async def _reject(self, scope: Scope, send: Send) -> None:
        response = problem_response(
            request_id=request_id_from_scope(scope),
            instance=str(scope.get("path", "")),
            status=413,
            code="E_REQUEST_TOO_LARGE",
            title="Request too large",
            detail=f"Request bodies are limited to {self.max_bytes} bytes.",
        )
        await response(scope, _empty_receive, send)


async def _empty_receive() -> dict[str, object]:
    return {"type": "http.request", "body": b"", "more_body": False}
