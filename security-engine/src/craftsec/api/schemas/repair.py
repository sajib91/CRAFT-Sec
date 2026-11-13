"""Repository-aware repair proposal contracts.

The engine returns proposals only. It never applies a patch to user source.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from craftsec.api.schemas.common import APIModel, OperationResponse, Range
from craftsec.api.schemas.scan import FileContext


class RepairFindingContext(APIModel):
    finding_id: str = Field(min_length=1, max_length=200)
    document_uri: str | None = Field(default=None, max_length=4096)
    range: Range
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    rule_id: str | None = Field(default=None, max_length=500)


class RepairRequest(FileContext):
    finding: RepairFindingContext
    snapshot_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class RepairResult(APIModel):
    analysis_available: bool
    patch: str | None = None
    touched_files: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    risk_notes: list[str] = Field(default_factory=list)
    requires_approval: Literal[True] = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepairResponse(OperationResponse):
    result: RepairResult | None = None
