"""Structured JSON logging without source, tokens, or request bodies."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from craftsec.core.settings import Settings

LOGGER_NAME = "craftsec"
_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    """Render one JSON object per log line with optional request context."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["requestId"] = request_id

        for key in ("method", "path", "statusCode", "durationMs", "operation"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(settings: Settings) -> logging.Logger:
    """Configure the ``craftsec`` logger once and return it.

    Uvicorn's access logger stays enabled for the CLI, but the application
    request logger emits the structured access record.
    """
    global _CONFIGURED
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(settings.log_level)
    logger.propagate = False

    if not _CONFIGURED:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        _CONFIGURED = True

    return logger


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    return logging.getLogger(name)
