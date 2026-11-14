"""Repository-level source metadata extraction.

The walker never follows symlinks and reuses the engine's ignored-directory
policy. Unsupported, oversized, binary, invalid-UTF-8, and unreadable files are
reported in ``skipped_files`` instead of being silently omitted. Syntax errors
are metadata, not fatal errors: a file with recoverable parse errors remains in
the result with ``parse_ok=False``.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from craftsec.core.paths import IGNORED_DIRECTORIES, is_source_file
from craftsec.parsing.functions import extract_functions
from craftsec.parsing.languages import detect_language
from craftsec.parsing.models import SupportedLanguage
from craftsec.parsing.parser import parse_source

_CLASS_NODE_TYPES = frozenset({"class", "class_declaration", "class_definition"})


@dataclass(frozen=True, slots=True)
class RepositoryFileMetadata:
    """Indexing metadata for one supported source file."""

    path: str
    language: SupportedLanguage
    size_bytes: int
    sha256: str | None
    line_count: int
    function_count: int
    class_count: int
    syntax_error_count: int
    parse_ok: bool


@dataclass(frozen=True, slots=True)
class SkippedFile:
    """A candidate file that was deliberately not parsed."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class RepositoryMetadata:
    """Deterministic summary of a repository's supported source files."""

    root: str
    files: tuple[RepositoryFileMetadata, ...]
    skipped_files: tuple[SkippedFile, ...]
    language_counts: dict[str, int]
    total_bytes: int
    total_lines: int
    total_functions: int
    total_classes: int
    files_with_syntax_errors: int
    truncated: bool
    warnings: tuple[str, ...]

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped_files)


def extract_repository_metadata(
    root: str | Path,
    *,
    max_files: int = 10_000,
    max_file_bytes: int = 1_048_576,
    include_hashes: bool = True,
) -> RepositoryMetadata:
    """Walk a repository and summarize supported Python and JavaScript files."""
    if max_files < 1:
        raise ValueError("max_files must be at least 1")
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be at least 1")

    try:
        root_path = Path(root).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise ValueError("repository root does not exist") from None
    if not root_path.is_dir():
        raise ValueError("repository root must be a directory")

    files: list[RepositoryFileMetadata] = []
    skipped: list[SkippedFile] = []
    warnings: list[str] = []
    language_counts: dict[str, int] = {}
    total_bytes = 0
    total_lines = 0
    total_functions = 0
    total_classes = 0
    files_with_syntax_errors = 0
    processed = 0
    truncated = False

    for directory, dirnames, filenames in os.walk(root_path, followlinks=False):
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

            if processed >= max_files:
                truncated = True
                warnings.append(f"repository walk stopped after {max_files} candidate source files")
                break
            processed += 1
            relative = path.relative_to(root_path).as_posix()

            detection = detect_language(path=path)
            if detection.language is None:
                skipped.append(SkippedFile(path=relative, reason="unsupported_language"))
                continue

            try:
                with path.open("rb") as handle:
                    data = handle.read(max_file_bytes + 1)
            except OSError:
                skipped.append(SkippedFile(path=relative, reason="read_error"))
                continue

            if len(data) > max_file_bytes:
                skipped.append(SkippedFile(path=relative, reason="too_large"))
                continue
            if b"\x00" in data[:8192]:
                skipped.append(SkippedFile(path=relative, reason="binary"))
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                skipped.append(SkippedFile(path=relative, reason="invalid_utf8"))
                continue

            parsed = parse_source(text, path=path, language=detection.language)
            functions = extract_functions(parsed)
            class_count = _count_nodes(parsed.root_node, _CLASS_NODE_TYPES)
            line_count = len(text.splitlines())
            file_metadata = RepositoryFileMetadata(
                path=relative,
                language=detection.language,
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest() if include_hashes else None,
                line_count=line_count,
                function_count=len(functions),
                class_count=class_count,
                syntax_error_count=parsed.error_count,
                parse_ok=not parsed.has_syntax_errors,
            )
            files.append(file_metadata)
            language_counts[detection.language.value] = (
                language_counts.get(detection.language.value, 0) + 1
            )
            total_bytes += file_metadata.size_bytes
            total_lines += line_count
            total_functions += len(functions)
            total_classes += class_count
            if not file_metadata.parse_ok:
                files_with_syntax_errors += 1

        if truncated:
            break

    return RepositoryMetadata(
        root=str(root_path),
        files=tuple(files),
        skipped_files=tuple(skipped),
        language_counts=dict(sorted(language_counts.items())),
        total_bytes=total_bytes,
        total_lines=total_lines,
        total_functions=total_functions,
        total_classes=total_classes,
        files_with_syntax_errors=files_with_syntax_errors,
        truncated=truncated,
        warnings=tuple(warnings),
    )


def _count_nodes(root, node_types: frozenset[str]) -> int:
    count = 0
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_named and node.type in node_types:
            count += 1
        stack.extend(node.children)
    return count
