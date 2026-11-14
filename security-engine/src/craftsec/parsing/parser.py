"""Tree-sitter parsing with recoverable syntax diagnostics.

The parser returns a tree even for invalid source. Callers must inspect
``has_syntax_errors`` before claiming complete coverage; tokens and functions
are still available for the portions tree-sitter recovered.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Node, Parser, Tree

from craftsec.parsing.languages import (
    UnsupportedLanguageError,
    detect_language,
    require_language,
    tree_sitter_language,
)
from craftsec.parsing.locations import LineIndex
from craftsec.parsing.models import (
    NormalizedSource,
    ParseDiagnostic,
    SourceMap,
    SourceSpan,
    SupportedLanguage,
)
from craftsec.parsing.normalization import normalize_source

_MAX_DIAGNOSTICS = 200


@dataclass(frozen=True, slots=True)
class ParsedSource:
    """One source file parsed with tree-sitter."""

    language: SupportedLanguage
    path: str | None
    text: str
    normalized: NormalizedSource
    tree: Tree
    line_index: LineIndex
    diagnostics: tuple[ParseDiagnostic, ...]

    @property
    def root_node(self) -> Node:
        return self.tree.root_node

    @property
    def has_syntax_errors(self) -> bool:
        return bool(self.diagnostics) or self.root_node.has_error

    @property
    def error_count(self) -> int:
        return len(self.diagnostics)

    def span_from_normalized_bytes(self, start_byte: int, end_byte: int) -> SourceSpan:
        """Map a normalized tree-sitter range to an exact original span."""
        start = self.normalized.source_map.map_offset(start_byte)
        end = self.normalized.source_map.map_offset(end_byte)
        return self.line_index.span_from_bytes(start, end)

    def span_for_node(self, node: Node) -> SourceSpan:
        return self.span_from_normalized_bytes(node.start_byte, node.end_byte)

    def text_for_span(self, span: SourceSpan) -> str:
        """Return the exact original text covered by a span."""
        return self.text[span.start.char_offset : span.end.char_offset]

    def text_for_node(self, node: Node) -> str:
        return self.text_for_span(self.span_for_node(node))


def parse_source(
    source: str,
    *,
    path: str | Path | None = None,
    language: SupportedLanguage | str | None = None,
    language_id: str | None = None,
) -> ParsedSource:
    """Parse Python or JavaScript without failing on syntax errors."""
    resolved_language = _resolve_language(
        source,
        path=path,
        language=language,
        language_id=language_id,
    )
    try:
        normalized = normalize_source(source)
    except UnicodeEncodeError as error:
        raise ValueError("source text must be valid UTF-8 text") from error

    parser = Parser(tree_sitter_language(resolved_language))
    tree = parser.parse(normalized.text.encode("utf-8"))
    line_index = LineIndex(
        source,
        display_prefix_bytes=len("\ufeff".encode("utf-8")) if normalized.had_bom else 0,
        display_prefix_chars=1 if normalized.had_bom else 0,
    )
    diagnostics = _collect_diagnostics(tree.root_node, normalized.source_map, line_index)
    return ParsedSource(
        language=resolved_language,
        path=str(path) if path is not None else None,
        text=source,
        normalized=normalized,
        tree=tree,
        line_index=line_index,
        diagnostics=diagnostics,
    )


def _resolve_language(
    source: str,
    *,
    path: str | Path | None,
    language: SupportedLanguage | str | None,
    language_id: str | None,
) -> SupportedLanguage:
    if language is not None:
        if isinstance(language, SupportedLanguage):
            return language
        try:
            return SupportedLanguage(language.lower())
        except ValueError:
            raise UnsupportedLanguageError(
                path=path,
                language_id=language_id,
                detail=f"unsupported language {language!r}",
            ) from None

    detection = detect_language(path=path, text=source, language_id=language_id)
    return require_language(detection, path=path)


def _collect_diagnostics(
    root: Node,
    source_map: SourceMap,
    line_index: LineIndex,
) -> tuple[ParseDiagnostic, ...]:
    diagnostics: list[ParseDiagnostic] = []
    stack = [root]
    while stack and len(diagnostics) < _MAX_DIAGNOSTICS:
        node = stack.pop()
        if node.is_missing:
            diagnostics.append(
                ParseDiagnostic(
                    kind="missing",
                    message=f"Missing {node.type}",
                    node_type=node.type,
                    span=_span_for_node(node, source_map, line_index),
                )
            )
        elif node.is_error:
            diagnostics.append(
                ParseDiagnostic(
                    kind="error",
                    message="Unexpected or invalid syntax",
                    node_type=node.type,
                    span=_span_for_node(node, source_map, line_index),
                )
            )
        stack.extend(reversed(node.children))

    if root.has_error and not diagnostics:
        diagnostics.append(
            ParseDiagnostic(
                kind="error",
                message="The source contains a syntax error",
                node_type=root.type,
                span=_span_for_node(root, source_map, line_index),
            )
        )
    return tuple(diagnostics)


def _span_for_node(node: Node, source_map: SourceMap, line_index: LineIndex) -> SourceSpan:
    start = source_map.map_offset(node.start_byte)
    end = source_map.map_offset(node.end_byte)
    return line_index.span_from_bytes(start, end)
