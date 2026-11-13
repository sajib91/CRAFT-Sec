"""SAE feature extraction endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.features import FeatureExtractionRequest, FeatureExtractionResponse
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/features", tags=["features"])


@router.post(
    "/extract",
    response_model=FeatureExtractionResponse,
    summary="Extract genuine SAE features for a file when artifacts are available",
    responses=COMMON_ERROR_RESPONSES,
)
def extract_features(
    payload: FeatureExtractionRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> FeatureExtractionResponse:
    return orchestrator.features_extract(payload, request_id)
