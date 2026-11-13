"""Independent verification endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.verification import VerificationRequest, VerificationResponse
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/verification", tags=["verification"])


@router.post(
    "/run",
    response_model=VerificationResponse,
    summary="Run independent security and functional checks when available",
    responses=COMMON_ERROR_RESPONSES,
)
def run_verification(
    payload: VerificationRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> VerificationResponse:
    return orchestrator.verification_run(payload, request_id)
