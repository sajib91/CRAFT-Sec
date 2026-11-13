"""Operation orchestration over explicit pipeline stages.

The default registry contains declared but unimplemented research stages. The
orchestrator may inspect files and build scope metadata, but it never turns an
unavailable stage into a successful empty analysis.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from craftsec.api.schemas import (
    CounterfactualRequest,
    CounterfactualResponse,
    CounterfactualResult,
    DetectionRequest,
    DetectionResponse,
    DetectionResult,
    ExplanationRequest,
    ExplanationResponse,
    ExplanationResult,
    FeatureExtractionRequest,
    FeatureExtractionResponse,
    FeatureExtractionResult,
    FileInfo,
    PreventionRequest,
    PreventionResponse,
    PreventionResult,
    RepairRequest,
    RepairResponse,
    RepairResult,
    ScanFileRequest,
    ScanFileResponse,
    ScanScope,
    ScanWorkspaceRequest,
    ScanWorkspaceResponse,
    StageReport,
    VerificationRequest,
    VerificationResponse,
    VerificationResult,
)
from craftsec.config import API_VERSION
from craftsec.core.errors import (
    AppError,
    InternalAppError,
    ResourceLimitAppError,
    ValidationAppError,
)
from craftsec.core.logging import get_logger
from craftsec.core.paths import (
    FileSnapshot,
    SourceFile,
    ensure_allowed_root,
    enumerate_workspace_sources,
    inspect_source_file,
    inspect_source_text,
    validate_selection,
)
from craftsec.core.pipeline import (
    Pipeline,
    PipelineExecution,
    PipelineStage,
    PipelineStatus,
    StageContext,
    StageResult,
    StageStatus,
    UnavailableStage,
    combine_stage_results,
)
from craftsec.core.settings import Settings

DEFAULT_STAGE_DEFINITIONS: dict[str, tuple[str, str]] = {
    "static_evidence": (
        "E_ANALYZER_UNAVAILABLE",
        "No static analyzer adapter is implemented or enabled.",
    ),
    "detection": (
        "E_DETECTOR_UNAVAILABLE",
        "No evidence-fusion detector is implemented.",
    ),
    "explanation": (
        "E_EXPLANATION_UNAVAILABLE",
        "No explanation-graph builder is implemented.",
    ),
    "model_capture": (
        "E_MODEL_UNAVAILABLE",
        "No model runtime or activation capture is configured.",
    ),
    "sae_features": (
        "E_SAE_UNAVAILABLE",
        "No compatible SAE artifact is registered.",
    ),
    "feature_aggregation": (
        "E_FEATURE_UNAVAILABLE",
        "No feature aggregation implementation is available.",
    ),
    "counterfactual": (
        "E_COUNTERFACTUAL_UNAVAILABLE",
        "No counterfactual engine is implemented.",
    ),
    "steering_plan": (
        "E_STEERING_UNAVAILABLE",
        "No interaction-aware steering planner is implemented.",
    ),
    "steering_evaluation": (
        "E_STEERING_UNAVAILABLE",
        "No paired steering evaluation harness is implemented.",
    ),
    "repair": (
        "E_REPAIR_UNAVAILABLE",
        "No repository-aware repair generator is implemented.",
    ),
    "verification": (
        "E_VERIFICATION_UNAVAILABLE",
        "No independent verification implementation or adequate sandbox is available.",
    ),
}

OPERATION_STAGES: dict[str, tuple[str, ...]] = {
    "scan_file": ("static_evidence", "detection"),
    "scan_workspace": ("static_evidence", "detection"),
    "detection_analyze": ("static_evidence", "detection"),
    "explanation_analyze": ("explanation",),
    "features_extract": ("model_capture", "sae_features", "feature_aggregation"),
    "counterfactual_analyze": ("counterfactual",),
    "prevention_steer": ("steering_plan", "steering_evaluation"),
    "repair_generate": ("repair",),
    "verification_run": ("verification",),
}


class Orchestrator:
    """Select a pipeline for each operation and build typed responses."""

    def __init__(
        self,
        settings: Settings,
        stages: Mapping[str, PipelineStage] | None = None,
    ) -> None:
        self.settings = settings
        self.logger = get_logger("craftsec.orchestrator")
        self.stages: dict[str, PipelineStage] = {
            name: UnavailableStage(name=name, reason_code=code, detail=detail)
            for name, (code, detail) in DEFAULT_STAGE_DEFINITIONS.items()
        }
        if stages:
            for name, stage in stages.items():
                if stage.name != name:
                    raise ValueError(f"Stage registry key {name!r} does not match stage.name.")
                self.stages[name] = stage

    def capabilities(self) -> dict[str, bool]:
        return {
            operation: all(getattr(self.stages[name], "available", False) for name in stage_names)
            for operation, stage_names in OPERATION_STAGES.items()
        }

    def scan_file(self, request: ScanFileRequest, request_id: str) -> ScanFileResponse:
        root = ensure_allowed_root(request.workspace_root, self.settings)
        snapshot = self._snapshot(root, request)
        self._validate_requested_selection(snapshot, request)
        execution = self._execute(
            "scan_file",
            request_id,
            self._payload(snapshot, request.language_id),
        )
        combined = self._with_snapshot(
            StageResult(
                stage="file_snapshot",
                status=StageStatus.OK,
                data={
                    "size": snapshot.size,
                    "sha256": snapshot.sha256,
                    "languageId": snapshot.language_id,
                },
            ),
            execution,
        )
        return ScanFileResponse(
            **self._base_fields("scan_file", request_id, combined),
            findings=[],
            scope=ScanScope(uris=[snapshot.uri]),
            files_scanned=1,
            analysis_available=self._analysis_available(execution),
            file=FileInfo(
                path=str(snapshot.path),
                uri=snapshot.uri,
                size=snapshot.size,
                sha256=snapshot.sha256,
                language_id=request.language_id or snapshot.language_id,
            ),
        )

    def scan_workspace(
        self,
        request: ScanWorkspaceRequest,
        request_id: str,
    ) -> ScanWorkspaceResponse:
        files: dict[str, SourceFile] = {}
        roots = []
        for folder in request.workspace_folders:
            root = ensure_allowed_root(folder.path, self.settings)
            roots.append(root)
            for source in enumerate_workspace_sources(root, self.settings):
                files[source.uri] = source
                if len(files) > self.settings.max_workspace_files:
                    raise ResourceLimitAppError(
                        "The workspace exceeds the configured file scan limit.",
                        code="E_WORKSPACE_TOO_LARGE",
                    )
        execution = self._execute(
            "scan_workspace",
            request_id,
            {
                "workspaceRoots": [str(root) for root in roots],
                "fileCount": len(files),
            },
        )
        combined = self._with_snapshot(
            StageResult(
                stage="workspace_snapshot",
                status=StageStatus.OK,
                data={"fileCount": len(files), "rootCount": len(roots)},
            ),
            execution,
        )
        return ScanWorkspaceResponse(
            **self._base_fields("scan_workspace", request_id, combined),
            findings=[],
            scope=ScanScope(uris=list(files)),
            files_scanned=len(files),
            analysis_available=self._analysis_available(execution),
        )

    def detection_analyze(self, request: DetectionRequest, request_id: str) -> DetectionResponse:
        snapshot = self._inspect(request)
        execution = self._execute(
            "detection_analyze",
            request_id,
            self._payload(snapshot, request.language_id),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return DetectionResponse(
            **self._base_fields("detection_analyze", request_id, combined),
            result=DetectionResult(
                analysis_available=self._analysis_available(execution),
                findings=[],
                evidence_sources=[],
                score_kind=None,
            ),
        )

    def explanation_analyze(
        self,
        request: ExplanationRequest,
        request_id: str,
    ) -> ExplanationResponse:
        snapshot = self._inspect(request)
        if request.finding is not None and request.finding.location.uri != snapshot.uri:
            raise ValidationAppError("The finding location does not match the inspected file.")
        finding_id = request.finding.id if request.finding else request.finding_id
        execution = self._execute(
            "explanation_analyze",
            request_id,
            self._payload(snapshot, request.language_id, findingId=finding_id),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return ExplanationResponse(
            **self._base_fields("explanation_analyze", request_id, combined),
            result=ExplanationResult(
                analysis_available=self._analysis_available(execution),
                finding_id=finding_id,
                graph=None,
                claim_kinds=[],
                limitations=[],
            ),
        )

    def features_extract(
        self,
        request: FeatureExtractionRequest,
        request_id: str,
    ) -> FeatureExtractionResponse:
        snapshot = self._inspect(request)
        execution = self._execute(
            "features_extract",
            request_id,
            self._payload(
                snapshot,
                request.language_id,
                saeArtifactId=request.sae_artifact_id,
                layer=request.layer,
                hookPoint=request.hook_point,
                aggregation=request.aggregation,
            ),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return FeatureExtractionResponse(
            **self._base_fields("features_extract", request_id, combined),
            result=FeatureExtractionResult(
                analysis_available=self._analysis_available(execution),
                sae_artifact_id=request.sae_artifact_id,
                features=[],
                coverage=None,
                aggregation=request.aggregation,
            ),
        )

    def counterfactual_analyze(
        self,
        request: CounterfactualRequest,
        request_id: str,
    ) -> CounterfactualResponse:
        snapshot = self._inspect(request)
        execution = self._execute(
            "counterfactual_analyze",
            request_id,
            self._payload(
                snapshot,
                request.language_id,
                findingId=request.finding_id,
                interventions=[item.model_dump(mode="json") for item in request.interventions],
                budget=request.budget,
                seed=request.seed,
            ),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return CounterfactualResponse(
            **self._base_fields("counterfactual_analyze", request_id, combined),
            result=CounterfactualResult(
                analysis_available=self._analysis_available(execution),
                effects=[],
                validity=None,
                budget=request.budget,
            ),
        )

    def prevention_steer(
        self,
        request: PreventionRequest,
        request_id: str,
    ) -> PreventionResponse:
        snapshot = self._inspect(request)
        execution = self._execute(
            "prevention_steer",
            request_id,
            self._payload(
                snapshot,
                request.language_id,
                featureIndices=list(request.feature_indices),
                strength=request.strength,
                targetMetric=request.target_metric,
            ),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return PreventionResponse(
            **self._base_fields("prevention_steer", request_id, combined),
            result=PreventionResult(
                analysis_available=self._analysis_available(execution),
                plan=None,
                guardrails=[],
                evaluation=None,
                limitations=[],
            ),
        )

    def repair_generate(self, request: RepairRequest, request_id: str) -> RepairResponse:
        snapshot = self._inspect(request)
        if request.finding.document_uri and request.finding.document_uri != snapshot.uri:
            raise ValidationAppError("The finding location does not match the inspected file.")
        execution = self._execute(
            "repair_generate",
            request_id,
            self._payload(
                snapshot,
                request.language_id,
                finding=request.finding.model_dump(mode="json"),
                snapshotHash=request.snapshot_hash,
            ),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return RepairResponse(
            **self._base_fields("repair_generate", request_id, combined),
            result=RepairResult(
                analysis_available=self._analysis_available(execution),
                patch=None,
                touched_files=[],
                rationale=[],
                risk_notes=[],
                metadata={},
            ),
        )

    def verification_run(
        self,
        request: VerificationRequest,
        request_id: str,
    ) -> VerificationResponse:
        snapshot = self._inspect(request)
        execution = self._execute(
            "verification_run",
            request_id,
            self._payload(
                snapshot,
                request.language_id,
                repairId=request.repair_id,
                hasPatch=request.patch is not None,
                profile=request.profile,
                runExecution=request.run_execution,
                sandboxBackend=self.settings.sandbox_backend,
            ),
        )
        combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
        return VerificationResponse(
            **self._base_fields("verification_run", request_id, combined),
            result=VerificationResult(
                analysis_available=self._analysis_available(execution),
                verdict="not_run",
                checks=[],
                sandbox_backend=self.settings.sandbox_backend,
                limitations=[
                    "Verification is not run when no verifier or adequate sandbox is available."
                ],
            ),
        )

    def _snapshot(self, root: Path, request: Any) -> FileSnapshot:
        if request.source_text is not None:
            return inspect_source_text(
                root,
                request.file_path,
                request.source_text,
                self.settings,
            )
        return inspect_source_file(root, request.file_path, self.settings)

    def _inspect(self, request: Any) -> FileSnapshot:
        root = ensure_allowed_root(request.workspace_root, self.settings)
        snapshot = self._snapshot(root, request)
        if request.selection is not None:
            validate_selection(
                snapshot.text,
                request.selection.start.line,
                request.selection.start.character,
                request.selection.end.line,
                request.selection.end.character,
            )
        return snapshot

    def _validate_requested_selection(
        self,
        snapshot: FileSnapshot,
        request: ScanFileRequest,
    ) -> None:
        if request.selection is None:
            return
        validate_selection(
            snapshot.text,
            request.selection.start.line,
            request.selection.start.character,
            request.selection.end.line,
            request.selection.end.character,
        )

    def _execute(
        self,
        operation: str,
        request_id: str,
        payload: Mapping[str, Any],
    ) -> PipelineExecution:
        stage_names = OPERATION_STAGES[operation]
        pipeline = Pipeline(self.stages[name] for name in stage_names)
        context = StageContext(
            operation=operation,
            request_id=request_id,
            settings=self.settings,
            payload=payload,
        )
        try:
            execution = pipeline.run(context)
        except AppError:
            raise
        except Exception:
            self.logger.exception(
                "Pipeline execution failed.",
                extra={"request_id": request_id, "operation": operation},
            )
            raise InternalAppError() from None
        if execution.status is PipelineStatus.FAILED:
            self.logger.error(
                "Pipeline reported a failed stage.",
                extra={"request_id": request_id, "operation": operation},
            )
            raise InternalAppError()
        return execution

    def _with_snapshot(
        self,
        snapshot: StageResult,
        execution: PipelineExecution,
    ) -> PipelineExecution:
        return combine_stage_results([snapshot, *execution.stages])

    def _snapshot_result(self, snapshot: FileSnapshot) -> StageResult:
        return StageResult(
            stage="file_snapshot",
            status=StageStatus.OK,
            data={
                "size": snapshot.size,
                "sha256": snapshot.sha256,
                "languageId": snapshot.language_id,
            },
        )

    def _analysis_available(self, execution: PipelineExecution) -> bool:
        return execution.status in {PipelineStatus.COMPLETED, PipelineStatus.PARTIAL}

    def _payload(
        self,
        snapshot: FileSnapshot,
        language_id: str | None,
        **extra: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "filePath": str(snapshot.path),
            "documentUri": snapshot.uri,
            "languageId": language_id or snapshot.language_id,
            "sha256": snapshot.sha256,
        }
        payload.update({key: value for key, value in extra.items() if value is not None})
        return payload

    def _base_fields(
        self,
        operation: str,
        request_id: str,
        combined: PipelineExecution,
    ) -> dict[str, Any]:
        return {
            "operation": operation,
            "status": combined.status,
            "api_version": API_VERSION,
            "request_id": request_id,
            "stages": [
                StageReport(
                    stage=result.stage,
                    status=result.status,
                    reason_code=result.reason_code,
                    detail=result.detail,
                    warnings=result.warnings,
                    data=result.data,
                )
                for result in combined.stages
            ],
            "warnings": combined.warnings,
        }


__all__ = ["DEFAULT_STAGE_DEFINITIONS", "OPERATION_STAGES", "Orchestrator"]
