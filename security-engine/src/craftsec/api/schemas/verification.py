"""Independent verification contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from craftsec.api.schemas.common import APIModel, OperationResponse
from craftsec.api.schemas.scan import FileContext


class VerificationRequest(FileContext):
    repair_id: str | None = Field(default=None, min_length=1, max_length=200)
    patch: str | None = Field(default=None, max_length=5_000_000)
    profile: Literal["static_only", "sandbox"] = "static_only"
    run_execution: bool = False

    @model_validator(mode="after")
    def _require_target(self) -> VerificationRequest:
        if self.repair_id is None and self.patch is None:
            raise ValueError("provide a repairId or patch")
        if self.run_execution and self.profile != "sandbox":
            raise ValueError("runExecution requires profile=sandbox")
        return self


class VerificationResult(APIModel):
    analysis_available: bool
    verdict: Literal["passed", "failed", "inconclusive", "not_run"] = "not_run"
    checks: list[dict[str, Any]] = Field(default_factory=list)
    sandbox_backend: str
    limitations: list[str] = Field(default_factory=list)


class VerificationResponse(OperationResponse):
    result: VerificationResult | None = None
