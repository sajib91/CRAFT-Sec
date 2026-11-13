"""Request identifiers and structured access logging."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from craftsec.config import REQUEST_ID_HEADER
from craftsec.core.logging import get_logger

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_ACCESS_LOGGER = get_logger("craftsec.api.access")


def request_id_from_scope(scope: Scope) -> str:
    state = scope.get("state") or {}
    return str(state.get("request_id") or "-")


class RequestContextMiddleware:
    """Attach a request ID, echo it, and emit one structured access log line."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        supplied = headers.get(REQUEST_ID_HEADER)
        request_id = (
            supplied if supplied and _REQUEST_ID_PATTERN.fullmatch(supplied) else uuid.uuid4().hex
        )
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        started = time.perf_counter()
        status_code = 500

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                response_headers = MutableHeaders(scope=message)
                response_headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception:
            _ACCESS_LOGGER.exception(
                "Unhandled request failure.",
                extra={
                    "request_id": request_id,
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                },
            )
            raise
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            _ACCESS_LOGGER.log(
                logging.INFO,
                "request.complete",
                extra={
                    "request_id": request_id,
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "statusCode": status_code,
                    "durationMs": duration_ms,
                },
            )
