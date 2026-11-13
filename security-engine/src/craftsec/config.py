"""Application-level constants and settings accessors.

Runtime values are environment-backed through :class:`craftsec.core.settings.Settings`.
This module contains no credentials and must not grow hardcoded secrets.
"""

from __future__ import annotations

from functools import lru_cache

from craftsec.core.settings import Settings

SERVICE_NAME = "craftsec-engine"
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"
ERROR_TYPE_BASE = "https://craftsec.local/errors"
PROBLEM_MEDIA_TYPE = "application/problem+json"
REQUEST_ID_HEADER = "X-Request-ID"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance.

    Tests and embedded callers should construct ``Settings`` explicitly instead
    of relying on this cache.
    """
    return Settings()


def clear_settings_cache() -> None:
    """Clear the process-wide settings cache (used by tests and reloads)."""
    get_settings.cache_clear()
