"""Activation-steering prevention contracts."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field, model_validator

from craftsec.api.schemas.common import APIModel, OperationResponse
from craftsec.api.schemas.scan import FileContext


class PreventionRequest(FileContext):
    feature_indices: list[Annotated[int, Field(ge=0)]] = Field(min_length=1, max_length=64)
    strength: float = Field(default=1.0, ge=0.0, le=100.0)
    target_metric: str = Field(min_length=1, max_length=200)
    explicit_opt_in: bool = False

    @model_validator(mode="after")
    def _require_opt_in(self) -> PreventionRequest:
        if not self.explicit_opt_in:
            raise ValueError("activation steering requires explicitOptIn=true")
        return self


class PreventionResult(APIModel):
    analysis_available: bool
    plan: dict[str, Any] | None = None
    guardrails: list[str] = Field(default_factory=list)
    evaluation: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list)


class PreventionResponse(OperationResponse):
    result: PreventionResult | None = None
