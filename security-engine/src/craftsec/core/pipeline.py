"""Composable analysis pipeline primitives.

Stages report explicit statuses. A missing capability is represented as
``unavailable`` and is never converted into an empty successful result.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

from craftsec.core.settings import Settings


class StageStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class PipelineStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class StageContext:
    """Inputs shared by every stage in one operation."""

    operation: str
    request_id: str
    settings: Settings
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class StageResult:
    """One stage's explicit outcome and JSON-safe metadata."""

    stage: str
    status: StageStatus
    reason_code: str | None = None
    detail: str | None = None
    warnings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.status, StageStatus):
            raise TypeError("StageResult.status must be a StageStatus value.")
        if not self.stage:
            raise ValueError("StageResult.stage must be a non-empty name.")


@dataclass(slots=True)
class PipelineExecution:
    """The ordered result of running a pipeline."""

    status: PipelineStatus
    stages: list[StageResult]
    warnings: list[str] = field(default_factory=list)


class PipelineStage(Protocol):
    name: str
    available: bool

    def run(self, context: StageContext) -> StageResult: ...


@dataclass(frozen=True, slots=True)
class UnavailableStage:
    """A declared stage whose implementation is not present."""

    name: str
    reason_code: str
    detail: str
    available: bool = False

    def run(self, context: StageContext) -> StageResult:
        del context
        return StageResult(
            stage=self.name,
            status=StageStatus.UNAVAILABLE,
            reason_code=self.reason_code,
            detail=self.detail,
        )


def derive_pipeline_status(results: Iterable[StageResult]) -> PipelineStatus:
    """Derive an honest aggregate status from ordered stage results."""
    statuses = [result.status for result in results]
    if not statuses:
        return PipelineStatus.UNAVAILABLE
    if StageStatus.FAILED in statuses:
        return PipelineStatus.FAILED
    if all(status is StageStatus.OK for status in statuses):
        return PipelineStatus.COMPLETED
    if any(status is StageStatus.OK or status is StageStatus.PARTIAL for status in statuses):
        return PipelineStatus.PARTIAL
    return PipelineStatus.UNAVAILABLE


def combine_stage_results(results: Iterable[StageResult]) -> PipelineExecution:
    """Build an execution record while preserving warnings in order."""
    stages = list(results)
    warnings: list[str] = []
    for stage in stages:
        warnings.extend(stage.warnings)
    return PipelineExecution(
        status=derive_pipeline_status(stages),
        stages=stages,
        warnings=list(dict.fromkeys(warnings)),
    )


class Pipeline:
    """Run named stages sequentially.

    Stages run in-process for the current lightweight operations. Long-running
    model work belongs behind a bounded worker or job runner; this layer does
    not create fake background execution.
    """

    def __init__(self, stages: Iterable[PipelineStage]) -> None:
        self.stages = list(stages)
        names = [stage.name for stage in self.stages]
        if len(names) != len(set(names)):
            raise ValueError("Pipeline stage names must be unique.")
        if not self.stages:
            raise ValueError("A pipeline must contain at least one stage.")

    def run(self, context: StageContext) -> PipelineExecution:
        results: list[StageResult] = []
        for stage in self.stages:
            result = stage.run(context)
            if not isinstance(result, StageResult):
                raise TypeError(f"Stage {stage.name} did not return a StageResult.")
            results.append(replace(result, stage=stage.name))
        return combine_stage_results(results)
