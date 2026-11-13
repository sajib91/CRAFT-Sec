"""Counterfactual analysis endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.counterfactual import CounterfactualRequest, CounterfactualResponse
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/counterfactual", tags=["counterfactual"])


@router.post(
    "/analyze",
    response_model=CounterfactualResponse,
    summary="Estimate model-internal feature interventions for a finding",
    responses=COMMON_ERROR_RESPONSES,
)
def analyze_counterfactual(
    payload: CounterfactualRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> CounterfactualResponse:
    return orchestrator.counterfactual_analyze(payload, request_id)
