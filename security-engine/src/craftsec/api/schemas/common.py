"""Shared API models: aliases, problem details, stage reports, and findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from craftsec.core.pipeline import PipelineStatus, StageStatus


def to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class APIModel(BaseModel):
    """Base model whose JSON representation uses the extension's camelCase."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        serialize_by_alias=True,
        extra="forbid",
    )


class ProblemDetail(APIModel):
    """RFC 9457 problem details returned with ``application/problem+json``."""

    type: str
    title: str
    status: int
    code: str
    detail: str
    instance: str
    retryable: bool = False
    request_id: str
    details: dict[str, Any] | None = None


class Position(APIModel):
    line: int = Field(ge=0)
    character: int = Field(ge=0)


class Range(APIModel):
    start: Position
    end: Position

    @model_validator(mode="after")
    def _validate_order(self) -> Range:
        if (self.end.line, self.end.character) < (self.start.line, self.start.character):
            raise ValueError("end must not precede start")
        return self


class SourceReference(APIModel):
    label: str = Field(min_length=1, max_length=500)
    url: str | None = Field(default=None, max_length=2048)
    uri: str | None = Field(default=None, max_length=2048)
    range: Range | None = None

    @model_validator(mode="after")
    def _validate_target(self) -> SourceReference:
        if self.range is not None and self.uri is None:
            raise ValueError("a source-reference range requires a uri")
        return self


class RepairInfo(APIModel):
    eligible: bool
    description: str | None = Field(default=None, max_length=5000)


class FindingLocation(APIModel):
    uri: str = Field(min_length=1, max_length=4096)
    range: Range


class Finding(APIModel):
    """Backend finding contract consumed by the VS Code diagnostics layer."""

    id: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=5000)
    severity: Literal["critical", "high", "medium", "low", "info"]
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    rule_id: str | None = Field(default=None, max_length=500)
    location: FindingLocation
    evidence: str | None = Field(default=None, max_length=100_000)
    explanation: str | None = Field(default=None, max_length=100_000)
    source_references: list[SourceReference] = Field(default_factory=list, max_length=50)
    repair: RepairInfo | None = None


class ScanScope(APIModel):
    uris: list[str] = Field(default_factory=list)


class FileInfo(APIModel):
    path: str
    uri: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    language_id: str | None = None


class StageReport(APIModel):
    stage: str
    status: StageStatus
    reason_code: str | None = None
    detail: str | None = None
    warnings: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class OperationResponse(APIModel):
    operation: str
    status: PipelineStatus
    api_version: str
    request_id: str
    stages: list[StageReport]
    warnings: list[str] = Field(default_factory=list)
    result: dict[str, Any] | None = None


class HealthResponse(APIModel):
    service: str
    status: Literal["ok"]
    version: str
    api_version: str
    timestamp: datetime
    uptime_seconds: float = Field(ge=0)
    capabilities: dict[str, bool]
    sandbox_backend: str
