"""Liveness and capability summary endpoint."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from craftsec import __version__
from craftsec.api.dependencies import get_orchestrator, get_settings
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.common import HealthResponse
from craftsec.config import API_VERSION, SERVICE_NAME
from craftsec.core.orchestrator import Orchestrator
from craftsec.core.settings import Settings

router = APIRouter(tags=["system"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Report engine liveness and available capabilities",
    responses=COMMON_ERROR_RESPONSES,
)
def health(
    request: Request,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthResponse:
    started_at = float(getattr(request.app.state, "started_at", time.monotonic()))
    return HealthResponse(
        service=SERVICE_NAME,
        status="ok",
        version=__version__,
        api_version=API_VERSION,
        timestamp=datetime.now(UTC),
        uptime_seconds=max(0.0, time.monotonic() - started_at),
        capabilities=orchestrator.capabilities(),
        sandbox_backend=settings.sandbox_backend,
    )
