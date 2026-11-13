"""Detection and explanation contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from craftsec.api.schemas.common import APIModel, Finding, OperationResponse
from craftsec.api.schemas.scan import FileContext


class DetectionRequest(FileContext):
    finding_ids: list[str] = Field(default_factory=list, max_length=1000)
    min_severity: Literal["critical", "high", "medium", "low", "info"] | None = None


class DetectionResult(APIModel):
    analysis_available: bool
    findings: list[Finding] = Field(default_factory=list)
    evidence_sources: list[str] = Field(default_factory=list)
    score_kind: Literal["heuristic", "model_logit", "calibrated"] | None = None


class DetectionResponse(OperationResponse):
    result: DetectionResult | None = None


class ExplanationRequest(FileContext):
    finding: Finding | None = None
    finding_id: str | None = Field(default=None, min_length=1, max_length=200)
    include_feature_evidence: bool = True

    @model_validator(mode="after")
    def _require_target(self) -> ExplanationRequest:
        if self.finding is None and self.finding_id is None:
            raise ValueError("provide a finding or findingId")
        return self


class ExplanationResult(APIModel):
    analysis_available: bool
    finding_id: str | None = None
    graph: dict[str, Any] | None = None
    claim_kinds: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ExplanationResponse(OperationResponse):
    result: ExplanationResult | None = None
