"""Syntax-aware code chunking for model context and evidence display.

Chunks are built from top-level tree-sitter nodes. Functions and classes get
their own chunks; runs of other top-level statements are grouped into module
chunks. Oversized chunks are split on line boundaries (or at a hard character
limit for a single oversized line) while retaining exact original spans.
"""

from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Node

from craftsec.parsing.models import ChunkKind, CodeChunk, SourceSpan, SupportedLanguage
from craftsec.parsing.parser import ParsedSource

_JS_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_expression",
        "generator_function",
    }
)
_JS_DECLARATION_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
    }
)


@dataclass(frozen=True, slots=True)
class _PendingChunk:
    kind: ChunkKind
    span: SourceSpan
    text: str
    symbol_name: str | None = None
    part_index: int = 0
    part_count: int = 1


def chunk_source(
    parsed: ParsedSource,
    *,
    max_chars: int = 4000,
    overlap_lines: int = 0,
) -> tuple[CodeChunk, ...]:
    """Return deterministic chunks that retain exact source spans."""
    if max_chars < 1:
        raise ValueError("max_chars must be at least 1")
    if overlap_lines < 0:
        raise ValueError("overlap_lines must not be negative")

    parts: list[_PendingChunk] = []
    for base_chunk in _base_chunks(parsed):
        parts.extend(_split_chunk(parsed, base_chunk, max_chars, overlap_lines))

    return tuple(
        CodeChunk(
            chunk_id=f"chunk-{index:04d}",
            kind=part.kind,
            span=part.span,
            text=part.text,
            symbol_name=part.symbol_name,
            part_index=part.part_index,
            part_count=part.part_count,
        )
        for index, part in enumerate(parts, start=1)
    )


def _base_chunks(parsed: ParsedSource) -> list[_PendingChunk]:
    root = parsed.root_node
    children = [child for child in root.named_children if child.end_byte > child.start_byte]
    if not children:
        return _fallback_chunk(parsed)

    chunks: list[_PendingChunk] = []
    pending_start: int | None = None
    pending_end: int | None = None

    def flush_pending() -> None:
        nonlocal pending_start, pending_end
        if pending_start is None or pending_end is None:
            return
        span = parsed.span_from_normalized_bytes(pending_start, pending_end)
        chunks.append(
            _PendingChunk(
                kind=ChunkKind.MODULE,
                span=span,
                text=parsed.text_for_span(span),
            )
        )
        pending_start = None
        pending_end = None

    for node in children:
        classified = _classify_top_level(parsed, node)
        if classified is None:
            if pending_start is None:
                pending_start = node.start_byte
            pending_end = node.end_byte
            continue

        flush_pending()
        kind, symbol_name = classified
        span = parsed.span_for_node(node)
        chunks.append(
            _PendingChunk(
                kind=kind,
                span=span,
                text=parsed.text_for_span(span),
                symbol_name=symbol_name,
            )
        )

    flush_pending()
    return chunks or _fallback_chunk(parsed)


def _fallback_chunk(parsed: ParsedSource) -> list[_PendingChunk]:
    start_char = 1 if parsed.normalized.had_bom else 0
    if start_char >= len(parsed.text):
        return []
    span = parsed.line_index.span_from_chars(start_char, len(parsed.text))
    return [
        _PendingChunk(
            kind=ChunkKind.ERROR if parsed.has_syntax_errors else ChunkKind.MODULE,
            span=span,
            text=parsed.text_for_span(span),
        )
    ]


def _classify_top_level(parsed: ParsedSource, node: Node) -> tuple[ChunkKind, str | None] | None:
    if node.type == "ERROR":
        return ChunkKind.ERROR, None

    if parsed.language is SupportedLanguage.PYTHON:
        if node.type == "function_definition":
            return ChunkKind.FUNCTION, _field_text(parsed, node, "name")
        if node.type == "class_definition":
            return ChunkKind.CLASS, _field_text(parsed, node, "name")
        if node.type == "decorated_definition":
            target = _first_child_of_type(node, {"class_definition", "function_definition"})
            if target is not None:
                kind = ChunkKind.CLASS if target.type == "class_definition" else ChunkKind.FUNCTION
                return kind, _field_text(parsed, target, "name")
        return None

    if node.type in {"function_declaration", "generator_function_declaration"}:
        return ChunkKind.FUNCTION, _field_text(parsed, node, "name")
    if node.type == "class_declaration":
        return ChunkKind.CLASS, _field_text(parsed, node, "name")
    if node.type == "method_definition":
        return ChunkKind.FUNCTION, _field_text(parsed, node, "name")
    if node.type == "export_statement":
        target = _first_child_of_type(
            node,
            _JS_DECLARATION_TYPES
            | _JS_FUNCTION_TYPES
            | {"class", "lexical_declaration", "variable_declaration"},
        )
        if target is None:
            return None
        if target.type in {"class", "class_declaration"}:
            return ChunkKind.CLASS, _field_text(parsed, target, "name")
        if target.type in _JS_DECLARATION_TYPES or target.type in _JS_FUNCTION_TYPES:
            return ChunkKind.FUNCTION, _field_text(parsed, target, "name")
        function_name = _declarator_function_name(parsed, target)
        if function_name is not None:
            return ChunkKind.FUNCTION, function_name
        return None
    if node.type in {"lexical_declaration", "variable_declaration"}:
        function_name = _declarator_function_name(parsed, node)
        if function_name is not None:
            return ChunkKind.FUNCTION, function_name
    return None


def _field_text(parsed: ParsedSource, node: Node, field: str) -> str | None:
    child = node.child_by_field_name(field)
    if child is None:
        return None
    text = parsed.text_for_node(child).strip()
    return text or None


def _first_child_of_type(node: Node, types: set[str] | frozenset[str]) -> Node | None:
    for child in node.named_children:
        if child.type in types:
            return child
    return None


def _declarator_function_name(parsed: ParsedSource, declaration: Node) -> str | None:
    for declarator in declaration.named_children:
        if declarator.type != "variable_declarator":
            continue
        value = declarator.child_by_field_name("value")
        if value is None or value.type not in _JS_FUNCTION_TYPES:
            continue
        name = declarator.child_by_field_name("name")
        if name is not None:
            text = parsed.text_for_node(name).strip()
            if text:
                return text
    return None


def _split_chunk(
    parsed: ParsedSource,
    chunk: _PendingChunk,
    max_chars: int,
    overlap_lines: int,
) -> list[_PendingChunk]:
    if len(chunk.text) <= max_chars:
        return [chunk]

    ranges = _split_ranges(chunk.text, max_chars, overlap_lines)
    if not ranges:
        return [chunk]

    base_char = chunk.span.start.char_offset
    return [
        _PendingChunk(
            kind=chunk.kind,
            span=parsed.line_index.span_from_chars(base_char + start, base_char + end),
            text=chunk.text[start:end],
            symbol_name=chunk.symbol_name,
            part_index=index,
            part_count=len(ranges),
        )
        for index, (start, end) in enumerate(ranges)
    ]


def _split_ranges(text: str, max_chars: int, overlap_lines: int) -> list[tuple[int, int]]:
    lines: list[tuple[int, int]] = []
    line_start = 0
    for index, character in enumerate(text):
        if character == "\n":
            lines.append((line_start, index + 1))
            line_start = index + 1
    if line_start < len(text):
        lines.append((line_start, len(text)))
    if not lines:
        return []

    ranges: list[tuple[int, int]] = []
    line_index = 0
    while line_index < len(lines):
        start, end = lines[line_index]
        if end - start > max_chars:
            piece_start = start
            while piece_start < end:
                piece_end = min(piece_start + max_chars, end)
                ranges.append((piece_start, piece_end))
                piece_start = piece_end
            line_index += 1
            continue

        group_end = line_index
        group_end_offset = end
        while group_end + 1 < len(lines):
            next_end = lines[group_end + 1][1]
            if next_end - start > max_chars:
                break
            group_end += 1
            group_end_offset = next_end

        ranges.append((start, group_end_offset))
        next_line = group_end + 1
        if overlap_lines and next_line < len(lines):
            next_line = max(next_line - overlap_lines, line_index + 1)
        line_index = next_line

    return ranges
