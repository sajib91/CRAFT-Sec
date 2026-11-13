"""Pydantic request and response schemas for the versioned API."""

from craftsec.api.schemas.analysis import (
    DetectionRequest,
    DetectionResponse,
    DetectionResult,
    ExplanationRequest,
    ExplanationResponse,
    ExplanationResult,
)
from craftsec.api.schemas.common import (
    APIModel,
    FileInfo,
    Finding,
    FindingLocation,
    HealthResponse,
    OperationResponse,
    Position,
    ProblemDetail,
    Range,
    RepairInfo,
    ScanScope,
    SourceReference,
    StageReport,
)
from craftsec.api.schemas.counterfactual import (
    CounterfactualRequest,
    CounterfactualResponse,
    CounterfactualResult,
    Intervention,
)
from craftsec.api.schemas.features import (
    FeatureExtractionRequest,
    FeatureExtractionResponse,
    FeatureExtractionResult,
)
from craftsec.api.schemas.prevention import (
    PreventionRequest,
    PreventionResponse,
    PreventionResult,
)
from craftsec.api.schemas.repair import (
    RepairFindingContext,
    RepairRequest,
    RepairResponse,
    RepairResult,
)
from craftsec.api.schemas.scan import (
    FileContext,
    ScanFileRequest,
    ScanFileResponse,
    ScanResponse,
    ScanWorkspaceRequest,
    ScanWorkspaceResponse,
    WorkspaceFolder,
)
from craftsec.api.schemas.verification import (
    VerificationRequest,
    VerificationResponse,
    VerificationResult,
)

__all__ = [
    "APIModel",
    "CounterfactualRequest",
    "CounterfactualResponse",
    "CounterfactualResult",
    "DetectionRequest",
    "DetectionResponse",
    "DetectionResult",
    "ExplanationRequest",
    "ExplanationResponse",
    "ExplanationResult",
    "FeatureExtractionRequest",
    "FeatureExtractionResponse",
    "FeatureExtractionResult",
    "FileContext",
    "FileInfo",
    "Finding",
    "FindingLocation",
    "HealthResponse",
    "Intervention",
    "OperationResponse",
    "Position",
    "PreventionRequest",
    "PreventionResponse",
    "PreventionResult",
    "ProblemDetail",
    "Range",
    "RepairFindingContext",
    "RepairInfo",
    "RepairRequest",
    "RepairResponse",
    "RepairResult",
    "ScanFileRequest",
    "ScanFileResponse",
    "ScanResponse",
    "ScanScope",
    "ScanWorkspaceRequest",
    "ScanWorkspaceResponse",
    "SourceReference",
    "StageReport",
    "VerificationRequest",
    "VerificationResponse",
    "VerificationResult",
    "WorkspaceFolder",
]
