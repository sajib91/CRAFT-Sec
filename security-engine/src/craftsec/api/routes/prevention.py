"""Activation-steering prevention endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.prevention import PreventionRequest, PreventionResponse
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/prevention", tags=["prevention"])


@router.post(
    "/steer",
    response_model=PreventionResponse,
    summary="Plan and evaluate explicit activation steering",
    responses=COMMON_ERROR_RESPONSES,
)
def steer_prevention(
    payload: PreventionRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> PreventionResponse:
    return orchestrator.prevention_steer(payload, request_id)
