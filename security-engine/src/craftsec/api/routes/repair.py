"""Repair proposal endpoint. Patches are never applied by the engine."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.repair import RepairRequest, RepairResponse
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/repair", tags=["repair"])


@router.post(
    "/generate",
    response_model=RepairResponse,
    summary="Generate a repository-aware repair proposal for explicit review",
    responses=COMMON_ERROR_RESPONSES,
)
def generate_repair(
    payload: RepairRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> RepairResponse:
    return orchestrator.repair_generate(payload, request_id)
