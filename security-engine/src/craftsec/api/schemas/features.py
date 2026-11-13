"""SAE feature extraction contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from craftsec.api.schemas.common import APIModel, OperationResponse
from craftsec.api.schemas.scan import FileContext


class FeatureExtractionRequest(FileContext):
    sae_artifact_id: str | None = Field(default=None, max_length=200)
    layer: int | None = Field(default=None, ge=0, le=1000)
    hook_point: str | None = Field(default=None, max_length=200)
    aggregation: Literal["max", "mean", "count"] = "max"


class FeatureExtractionResult(APIModel):
    analysis_available: bool
    sae_artifact_id: str | None = None
    features: list[dict[str, Any]] = Field(default_factory=list)
    coverage: float | None = Field(default=None, ge=0, le=1)
    aggregation: str | None = None


class FeatureExtractionResponse(OperationResponse):
    result: FeatureExtractionResult | None = None
