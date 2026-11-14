"""High-level source-preprocessing entry points."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from craftsec.parsing.chunking import chunk_source
from craftsec.parsing.functions import extract_functions
from craftsec.parsing.models import (
    CodeChunk,
    FunctionSymbol,
    NormalizedSource,
    ParseDiagnostic,
    SupportedLanguage,
    Token,
)
from craftsec.parsing.parser import ParsedSource, parse_source
from craftsec.parsing.tokens import tokenize_source


@dataclass(frozen=True, slots=True)
class PreprocessedSource:
    """All preprocessing products for one source file."""

    parsed: ParsedSource
    tokens: tuple[Token, ...]
    functions: tuple[FunctionSymbol, ...]
    chunks: tuple[CodeChunk, ...]

    @property
    def language(self) -> SupportedLanguage:
        return self.parsed.language

    @property
    def path(self) -> str | None:
        return self.parsed.path

    @property
    def text(self) -> str:
        return self.parsed.text

    @property
    def normalized(self) -> NormalizedSource:
        return self.parsed.normalized

    @property
    def diagnostics(self) -> tuple[ParseDiagnostic, ...]:
        return self.parsed.diagnostics

    @property
    def has_syntax_errors(self) -> bool:
        return self.parsed.has_syntax_errors


def preprocess_source(
    source: str,
    *,
    path: str | Path | None = None,
    language: SupportedLanguage | str | None = None,
    language_id: str | None = None,
    max_chars: int = 4000,
    overlap_lines: int = 0,
) -> PreprocessedSource:
    """Detect, normalize, parse, tokenize, chunk, and extract functions."""
    parsed = parse_source(
        source,
        path=path,
        language=language,
        language_id=language_id,
    )
    return PreprocessedSource(
        parsed=parsed,
        tokens=tokenize_source(parsed),
        functions=extract_functions(parsed),
        chunks=chunk_source(parsed, max_chars=max_chars, overlap_lines=overlap_lines),
    )


def preprocess_file(
    path: str | Path,
    *,
    language_id: str | None = None,
    max_chars: int = 4000,
    overlap_lines: int = 0,
) -> PreprocessedSource:
    """Read a UTF-8 source file and preprocess it.

    Callers handling untrusted paths should use the workspace containment layer
    in :mod:`craftsec.core.paths` before invoking this helper.
    """
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    return preprocess_source(
        text,
        path=file_path,
        language_id=language_id,
        max_chars=max_chars,
        overlap_lines=overlap_lines,
    )
