"""Immutable models shared by the source-preprocessing pipeline.

Every token, function, and chunk carries an exact span in the original source.
A span records UTF-8 byte offsets (for tree-sitter and lossless slicing), Python
character offsets, zero-based line numbers, byte columns, and UTF-16 columns
(the coordinate system used by VS Code and the Language Server Protocol).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

LineEnding = Literal["lf", "crlf", "cr", "mixed", "none"]


class SupportedLanguage(StrEnum):
    """Languages the preprocessing layer can parse in this phase."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"


class DetectionSource(StrEnum):
    """How a language was identified."""

    EXPLICIT = "explicit"
    EXTENSION = "extension"
    SHEBANG = "shebang"
    CONTENT = "content"
    UNKNOWN = "unknown"


class ChunkKind(StrEnum):
    """The syntactic unit represented by a code chunk."""

    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"
    ERROR = "error"


class FunctionKind(StrEnum):
    """The kind of function-like symbol that was extracted."""

    FUNCTION = "function"
    METHOD = "method"
    ARROW = "arrow_function"
    LAMBDA = "lambda"


@dataclass(frozen=True, slots=True)
class LanguageDetection:
    """A language decision plus the evidence that produced it."""

    language: SupportedLanguage | None
    source: DetectionSource
    detail: str | None = None

    @property
    def detected(self) -> bool:
        return self.language is not None


@dataclass(frozen=True, slots=True)
class SourcePoint:
    """One exact, zero-based point in a source file.

    ``byte_offset`` and ``char_offset`` are absolute offsets into the original
    text. ``line`` is zero-based. ``column`` is a UTF-8 byte column, matching
    tree-sitter. ``character`` is a UTF-16 code-unit column, matching VS Code
    and LSP positions.
    """

    byte_offset: int
    char_offset: int
    line: int
    column: int
    character: int

    def __post_init__(self) -> None:
        if min(self.byte_offset, self.char_offset, self.line, self.column, self.character) < 0:
            raise ValueError("source point values must be non-negative")

    def as_lsp_position(self) -> dict[str, int]:
        """Return a VS Code/LSP-compatible position."""
        return {"line": self.line, "character": self.character}


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A half-open range in the original source."""

    start: SourcePoint
    end: SourcePoint

    def __post_init__(self) -> None:
        if self.end.byte_offset < self.start.byte_offset:
            raise ValueError("source span end must not precede start")

    @property
    def byte_length(self) -> int:
        return self.end.byte_offset - self.start.byte_offset

    @property
    def char_length(self) -> int:
        return self.end.char_offset - self.start.char_offset

    def as_lsp_range(self) -> dict[str, dict[str, int]]:
        """Return a VS Code/LSP-compatible range."""
        return {
            "start": self.start.as_lsp_position(),
            "end": self.end.as_lsp_position(),
        }


@dataclass(frozen=True, slots=True)
class SourceMap:
    """Map normalized UTF-8 byte boundaries back to original byte boundaries.

    ``offsets[i]`` is the original byte offset for normalized byte boundary
    ``i``. The tuple always has ``normalized_size + 1`` entries.
    """

    offsets: tuple[int, ...]
    original_size: int
    normalized_size: int

    def __post_init__(self) -> None:
        if len(self.offsets) != self.normalized_size + 1:
            raise ValueError("source map must contain one entry per byte boundary")
        if self.offsets[0] < 0 or self.offsets[-1] > self.original_size:
            raise ValueError("source map offsets are outside the original source")

    def map_offset(self, normalized_offset: int) -> int:
        """Translate a normalized byte offset to the original byte offset."""
        if not 0 <= normalized_offset <= self.normalized_size:
            raise ValueError("normalized offset is outside the source")
        return self.offsets[normalized_offset]


@dataclass(frozen=True, slots=True)
class NormalizedSource:
    """Original text plus a canonical line-ending/BOM-free view."""

    original_text: str
    text: str
    source_map: SourceMap
    had_bom: bool
    line_ending: LineEnding

    @property
    def changed(self) -> bool:
        return self.original_text != self.text

    @property
    def original_size(self) -> int:
        return self.source_map.original_size

    @property
    def normalized_size(self) -> int:
        return self.source_map.normalized_size


@dataclass(frozen=True, slots=True)
class ParseDiagnostic:
    """A recoverable syntax error or missing node reported by tree-sitter."""

    kind: Literal["error", "missing"]
    message: str
    node_type: str
    span: SourceSpan

    @property
    def line(self) -> int:
        return self.span.start.line


@dataclass(frozen=True, slots=True)
class Token:
    """One terminal tree-sitter token with its exact original span."""

    kind: str
    text: str
    span: SourceSpan
    named: bool
    is_comment: bool = False
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class FunctionSymbol:
    """A named function, method, arrow function, or lambda."""

    name: str | None
    qualified_name: str | None
    kind: FunctionKind
    span: SourceSpan
    name_span: SourceSpan | None
    parameters: tuple[str, ...]
    parameter_names: tuple[str, ...]
    is_async: bool
    is_generator: bool
    is_method: bool
    container_name: str | None


@dataclass(frozen=True, slots=True)
class CodeChunk:
    """A source slice suitable for model context or evidence display."""

    chunk_id: str
    kind: ChunkKind
    span: SourceSpan
    text: str
    symbol_name: str | None = None
    part_index: int = 0
    part_count: int = 1

    def __post_init__(self) -> None:
        if self.part_count < 1 or not 0 <= self.part_index < self.part_count:
            raise ValueError("chunk part index is outside its part count")
