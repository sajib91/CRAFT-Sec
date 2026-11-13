"""Counterfactual analysis contracts.

Effects are model-internal interventions, not real-world causal effects.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from craftsec.api.schemas.common import APIModel, OperationResponse
from craftsec.api.schemas.scan import FileContext


class Intervention(APIModel):
    kind: Literal["ablate", "amplify", "scale"]
    feature_indices: list[Annotated[int, Field(ge=0)]] = Field(min_length=1, max_length=64)
    strength: float = Field(default=1.0, ge=-100.0, le=100.0)


class CounterfactualRequest(FileContext):
    finding_id: str = Field(min_length=1, max_length=200)
    interventions: list[Intervention] = Field(min_length=1, max_length=8)
    budget: int = Field(default=200, ge=1, le=10_000)
    seed: int = Field(default=0, ge=0, le=2**31 - 1)


class CounterfactualResult(APIModel):
    analysis_available: bool
    scope: Literal["model_intervention"] = "model_intervention"
    effects: list[dict[str, Any]] = Field(default_factory=list)
    validity: dict[str, Any] | None = None
    budget: int


class CounterfactualResponse(OperationResponse):
    result: CounterfactualResult | None = None
