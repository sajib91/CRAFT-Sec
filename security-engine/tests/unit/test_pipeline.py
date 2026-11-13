from __future__ import annotations

from dataclasses import dataclass

import pytest

from craftsec.core.orchestrator import Orchestrator
from craftsec.core.pipeline import (
    Pipeline,
    PipelineStatus,
    StageContext,
    StageResult,
    StageStatus,
    UnavailableStage,
    combine_stage_results,
    derive_pipeline_status,
)
from craftsec.core.settings import Settings


@dataclass
class FixedStage:
    name: str
    status: StageStatus
    available: bool = True
    warnings: tuple[str, ...] = ()

    def run(self, context: StageContext) -> StageResult:
        del context
        return StageResult(
            stage=self.name,
            status=self.status,
            warnings=list(self.warnings),
        )


def test_derive_pipeline_status_is_explicit() -> None:
    assert derive_pipeline_status([]) is PipelineStatus.UNAVAILABLE
    assert derive_pipeline_status([StageResult("a", StageStatus.OK)]) is PipelineStatus.COMPLETED
    assert (
        derive_pipeline_status(
            [StageResult("a", StageStatus.OK), StageResult("b", StageStatus.UNAVAILABLE)]
        )
        is PipelineStatus.PARTIAL
    )
    assert (
        derive_pipeline_status(
            [StageResult("a", StageStatus.PARTIAL), StageResult("b", StageStatus.SKIPPED)]
        )
        is PipelineStatus.PARTIAL
    )
    assert (
        derive_pipeline_status([StageResult("a", StageStatus.UNAVAILABLE)])
        is PipelineStatus.UNAVAILABLE
    )
    assert (
        derive_pipeline_status(
            [StageResult("a", StageStatus.OK), StageResult("b", StageStatus.FAILED)]
        )
        is PipelineStatus.FAILED
    )


def test_pipeline_runs_stages_in_order_and_deduplicates_warnings() -> None:
    pipeline = Pipeline(
        [
            FixedStage("one", StageStatus.OK, warnings=("shared", "first")),
            FixedStage("two", StageStatus.UNAVAILABLE, warnings=("shared", "second")),
        ]
    )
    execution = pipeline.run(
        StageContext(operation="test", request_id="req-1", settings=Settings(_env_file=None))
    )

    assert [stage.stage for stage in execution.stages] == ["one", "two"]
    assert execution.status is PipelineStatus.PARTIAL
    assert execution.warnings == ["shared", "first", "second"]


def test_pipeline_normalizes_a_stage_result_name() -> None:
    pipeline = Pipeline([FixedStage("declared", StageStatus.OK)])
    execution = pipeline.run(
        StageContext(operation="test", request_id="req-1", settings=Settings(_env_file=None))
    )

    assert execution.stages[0].stage == "declared"


def test_pipeline_rejects_empty_or_duplicate_stage_names() -> None:
    with pytest.raises(ValueError):
        Pipeline([])
    with pytest.raises(ValueError):
        Pipeline(
            [
                FixedStage("duplicate", StageStatus.OK),
                FixedStage("duplicate", StageStatus.UNAVAILABLE),
            ]
        )


def test_stage_result_enforces_status_and_name_types() -> None:
    with pytest.raises(TypeError):
        StageResult("stage", "ok")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        StageResult("", StageStatus.OK)


def test_unavailable_stage_reports_its_reason_without_running() -> None:
    stage = UnavailableStage("detector", "E_DETECTOR_UNAVAILABLE", "No detector.")
    result = stage.run(
        StageContext(operation="test", request_id="req-1", settings=Settings(_env_file=None))
    )

    assert result.status is StageStatus.UNAVAILABLE
    assert result.reason_code == "E_DETECTOR_UNAVAILABLE"
    assert result.detail == "No detector."


def test_combine_stage_results_preserves_order() -> None:
    execution = combine_stage_results(
        [
            StageResult("first", StageStatus.OK),
            StageResult("second", StageStatus.UNAVAILABLE),
        ]
    )

    assert [stage.stage for stage in execution.stages] == ["first", "second"]
    assert execution.status is PipelineStatus.PARTIAL


def test_orchestrator_capabilities_require_every_operation_stage() -> None:
    settings = Settings(_env_file=None)
    orchestrator = Orchestrator(
        settings,
        {
            "static_evidence": FixedStage("static_evidence", StageStatus.OK),
            "detection": FixedStage("detection", StageStatus.OK),
        },
    )

    capabilities = orchestrator.capabilities()

    assert capabilities["scan_file"] is True
    assert capabilities["scan_workspace"] is True
    assert capabilities["detection_analyze"] is True
    assert capabilities["explanation_analyze"] is False
    assert capabilities["verification_run"] is False


def test_orchestrator_rejects_mismatched_stage_keys() -> None:
    with pytest.raises(ValueError):
        Orchestrator(
            Settings(_env_file=None),
            {"static_evidence": FixedStage("other", StageStatus.OK)},
        )
