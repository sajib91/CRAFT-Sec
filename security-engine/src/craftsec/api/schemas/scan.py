"""Scan request and response contracts."""

from __future__ import annotations

from pydantic import AliasChoices, Field

from craftsec.api.schemas.common import (
    APIModel,
    FileInfo,
    Finding,
    OperationResponse,
    Range,
    ScanScope,
)


class FileContext(APIModel):
    """Common editor/file context accepted by analysis endpoints."""

    workspace_root: str = Field(
        min_length=1,
        max_length=4096,
        validation_alias=AliasChoices("workspaceRoot", "workspaceFolder"),
        serialization_alias="workspaceRoot",
    )
    workspace_folder_name: str | None = Field(default=None, max_length=200)
    file_path: str = Field(min_length=1, max_length=4096)
    document_uri: str | None = Field(default=None, max_length=4096)
    language_id: str | None = Field(default=None, max_length=100)
    document_version: int | None = Field(default=None, ge=0)
    selection: Range | None = None
    selected_text: str | None = Field(default=None, max_length=2_000_000)
    source_text: str | None = Field(
        default=None,
        max_length=2_000_000,
        description=(
            "Current editor text supplied by the client. When present, it is inspected instead "
            "of re-reading the file from disk. The file path must still resolve inside the "
            "workspace root and the configured file-size limit is enforced."
        ),
    )


class ScanFileRequest(FileContext):
    pass


class WorkspaceFolder(APIModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=4096)
    uri: str | None = Field(default=None, max_length=4096)


class ScanWorkspaceRequest(APIModel):
    workspace_folders: list[WorkspaceFolder] = Field(min_length=1, max_length=50)


class ScanResponse(OperationResponse):
    findings: list[Finding] = Field(default_factory=list, max_length=100_000)
    scope: ScanScope
    files_scanned: int = Field(ge=0)
    analysis_available: bool


class ScanFileResponse(ScanResponse):
    file: FileInfo


class ScanWorkspaceResponse(ScanResponse):
    pass
