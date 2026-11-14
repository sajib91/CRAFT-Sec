"""Workspace containment, source discovery, and file inspection.

All paths are resolved before use. Symlinks that escape an allowed workspace
root are rejected, and workspace traversal never follows symlinked directories.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from craftsec.core.errors import (
    NotFoundAppError,
    ResourceLimitAppError,
    SecurityAppError,
    UnsupportedMediaAppError,
    ValidationAppError,
)
from craftsec.core.settings import Settings

SOURCE_EXTENSIONS = frozenset(
    {
        ".bash",
        ".c",
        ".cc",
        ".cfg",
        ".cjs",
        ".cpp",
        ".cs",
        ".css",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kt",
        ".kts",
        ".mjs",
        ".php",
        ".properties",
        ".py",
        ".pyi",
        ".pyw",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".sql",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".vue",
        ".xml",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
SOURCE_FILENAMES = frozenset({"Dockerfile", "Makefile", "Procfile"})
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        ".vscode-test",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)

_LANGUAGE_BY_SUFFIX = {
    ".bash": "shellscript",
    ".c": "c",
    ".cc": "cpp",
    ".cjs": "javascript",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".go": "go",
    ".h": "c",
    ".hpp": "cpp",
    ".html": "html",
    ".java": "java",
    ".js": "javascript",
    ".json": "json",
    ".jsx": "javascriptreact",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".mjs": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "shellscript",
    ".sql": "sql",
    ".swift": "swift",
    ".toml": "toml",
    ".ts": "typescript",
    ".tsx": "typescriptreact",
    ".vue": "vue",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".zsh": "shellscript",
}


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """One inspected source file. ``text`` is never serialized by the API."""

    path: Path
    uri: str
    size: int
    sha256: str
    text: str
    language_id: str | None


@dataclass(frozen=True, slots=True)
class SourceFile:
    """Metadata for one source file discovered in a workspace."""

    path: Path
    uri: str
    size: int
    language_id: str | None


def language_for_path(path: Path) -> str | None:
    return _LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def is_source_file(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTENSIONS or path.name in SOURCE_FILENAMES


def _resolved_allowed_roots(settings: Settings) -> list[Path]:
    roots: list[Path] = []
    for root in settings.workspace_roots:
        try:
            roots.append(Path(root).expanduser().resolve())
        except OSError:
            continue
    return roots


def _is_within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def ensure_allowed_root(value: str | os.PathLike[str], settings: Settings) -> Path:
    """Resolve a requested workspace root and verify the allowlist."""
    try:
        candidate = Path(value).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise NotFoundAppError("The requested workspace root does not exist.") from None
    if not candidate.is_dir():
        raise NotFoundAppError("The requested workspace root is not a directory.")
    if not any(_is_within(candidate, root) for root in _resolved_allowed_roots(settings)):
        raise SecurityAppError(
            "The requested workspace root is outside the configured allowlist.",
            code="E_ROOT_NOT_ALLOWED",
        )
    return candidate


def resolve_file(root: Path, value: str | os.PathLike[str], settings: Settings) -> Path:
    """Resolve a file path inside ``root`` without following escaping symlinks."""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise NotFoundAppError("The requested file does not exist.") from None
    if not resolved.is_file():
        raise NotFoundAppError("The requested path is not a file.")
    if not _is_within(resolved, root):
        raise SecurityAppError(
            "The requested file is outside the workspace root.",
            code="E_PATH_OUTSIDE_WORKSPACE",
        )
    return resolved


def _validate_source_bytes(data: bytes, settings: Settings) -> str:
    """Enforce scan limits, reject binary content, and decode UTF-8 text."""
    if len(data) > settings.max_file_bytes:
        raise ResourceLimitAppError(
            f"The file exceeds the {settings.max_file_bytes}-byte analysis limit.",
            code="E_FILE_TOO_LARGE",
        )
    if b"\x00" in data[:8192]:
        raise UnsupportedMediaAppError("Binary files are not supported for source analysis.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise UnsupportedMediaAppError("Source files must be valid UTF-8 text.") from None


def inspect_source_file(
    root: Path,
    value: str | os.PathLike[str],
    settings: Settings,
) -> FileSnapshot:
    """Read, hash, decode, and validate one source file."""
    path = resolve_file(root, value, settings)
    try:
        size = path.stat().st_size
    except OSError:
        raise NotFoundAppError("The requested file could not be read.") from None
    if size > settings.max_file_bytes:
        raise ResourceLimitAppError(
            f"The file exceeds the {settings.max_file_bytes}-byte analysis limit.",
            code="E_FILE_TOO_LARGE",
        )

    try:
        with path.open("rb") as handle:
            data = handle.read(settings.max_file_bytes + 1)
    except OSError:
        raise SecurityAppError("The requested file could not be read.") from None
    text = _validate_source_bytes(data, settings)

    return FileSnapshot(
        path=path,
        uri=path.as_uri(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        text=text,
        language_id=language_for_path(path),
    )


def inspect_source_text(
    root: Path,
    value: str | os.PathLike[str],
    source_text: str,
    settings: Settings,
) -> FileSnapshot:
    """Inspect caller-supplied source text while preserving path containment.

    The path must still resolve to a regular file inside ``root``. The supplied
    text, not the on-disk bytes, is hashed and analysed, which lets an editor
    scan its current buffer without silently accepting a different file.
    """
    path = resolve_file(root, value, settings)
    try:
        data = source_text.encode("utf-8")
    except UnicodeEncodeError:
        raise UnsupportedMediaAppError("Source text must be valid UTF-8 text.") from None

    text = _validate_source_bytes(data, settings)
    return FileSnapshot(
        path=path,
        uri=path.as_uri(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        text=text,
        language_id=language_for_path(path),
    )


def enumerate_workspace_sources(root: Path, settings: Settings) -> list[SourceFile]:
    """Collect source-file metadata without following symlinks."""
    files: list[SourceFile] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in IGNORED_DIRECTORIES and not (current / name).is_symlink()
        )
        for name in sorted(filenames):
            path = current / name
            if path.is_symlink() or not is_source_file(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > settings.max_file_bytes:
                continue
            if len(files) >= settings.max_workspace_files:
                raise ResourceLimitAppError(
                    f"The workspace exceeds the {settings.max_workspace_files}-file scan limit.",
                    code="E_WORKSPACE_TOO_LARGE",
                )
            files.append(
                SourceFile(
                    path=path,
                    uri=path.as_uri(),
                    size=size,
                    language_id=language_for_path(path),
                )
            )
    return files


def validate_selection(
    text: str,
    start_line: int,
    start_character: int,
    end_line: int,
    end_character: int,
) -> None:
    """Reject a selection that does not fit the inspected file."""
    lines = text.splitlines() or [""]

    def check(line: int, character: int) -> None:
        if line >= len(lines):
            raise ValueError(f"line {line} is outside the file")
        if character > len(lines[line]):
            raise ValueError(f"character {character} is outside line {line}")

    try:
        check(start_line, start_character)
        check(end_line, end_character)
    except ValueError as error:
        raise ValidationAppError(f"The selection is outside the file: {error}.") from None
