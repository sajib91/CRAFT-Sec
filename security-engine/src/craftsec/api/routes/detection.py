"""Detection endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.analysis import DetectionRequest, DetectionResponse
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/detection", tags=["detection"])


@router.post(
    "/analyze",
    response_model=DetectionResponse,
    summary="Analyze static and model evidence for a file",
    responses=COMMON_ERROR_RESPONSES,
)
def analyze_detection(
    payload: DetectionRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> DetectionResponse:
    return orchestrator.detection_analyze(payload, request_id)
