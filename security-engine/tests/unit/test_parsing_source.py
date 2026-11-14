from __future__ import annotations

import pytest

from craftsec.parsing import (
    DetectionSource,
    SupportedLanguage,
    UnsupportedLanguageError,
    detect_language,
    normalize_source,
    parse_source,
    require_language,
    tokenize_source,
)
from craftsec.parsing.locations import LineIndex


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("module.py", SupportedLanguage.PYTHON),
        ("stub.PYI", SupportedLanguage.PYTHON),
        ("script.js", SupportedLanguage.JAVASCRIPT),
        ("component.jsx", SupportedLanguage.JAVASCRIPT),
        ("module.mjs", SupportedLanguage.JAVASCRIPT),
        ("common.cjs", SupportedLanguage.JAVASCRIPT),
    ],
)
def test_detects_supported_extensions(path: str, expected: SupportedLanguage) -> None:
    detection = detect_language(path=path)

    assert detection.language is expected
    assert detection.source is DetectionSource.EXTENSION
    assert detection.detected is True


def test_explicit_language_id_wins_over_extension_and_content() -> None:
    detection = detect_language(
        path="notes.py",
        text="const value = 1;",
        language_id=" JavaScript ",
    )

    assert detection.language is SupportedLanguage.JAVASCRIPT
    assert detection.source is DetectionSource.EXPLICIT
    assert detection.detail == " JavaScript "


def test_explicit_language_id_is_authoritative_even_when_unsupported() -> None:
    detection = detect_language(path="module.py", language_id="typescript")

    assert detection.language is None
    assert detection.source is DetectionSource.EXPLICIT
    assert detection.detected is False
    assert detection.detail is not None
    assert "unsupported language id" in detection.detail

    with pytest.raises(UnsupportedLanguageError, match="Supported languages"):
        require_language(detection, path="module.py")


def test_unsupported_extension_does_not_fall_back_to_content() -> None:
    detection = detect_language(
        path="module.ts",
        text="def function_like_name():\n    pass\n",
    )

    assert detection.language is None
    assert detection.source is DetectionSource.UNKNOWN
    assert detection.detail is not None
    assert "unsupported source extension" in detection.detail


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("#!/usr/bin/env python3\nprint('ok')\n", SupportedLanguage.PYTHON),
        ("#!/usr/bin/env node\nconsole.log('ok')\n", SupportedLanguage.JAVASCRIPT),
    ],
)
def test_detects_shebang_for_extensionless_files(text: str, expected: SupportedLanguage) -> None:
    detection = detect_language(path="script", text=text)

    assert detection.language is expected
    assert detection.source is DetectionSource.SHEBANG


def test_detects_unambiguous_extensionless_content() -> None:
    python_detection = detect_language(
        path="script",
        text="import os\n\ndef run():\n    pass\n",
    )
    javascript_detection = detect_language(
        path="script",
        text="const value = 1;\nconsole.log(value);\n",
    )

    assert python_detection.language is SupportedLanguage.PYTHON
    assert python_detection.source is DetectionSource.CONTENT
    assert javascript_detection.language is SupportedLanguage.JAVASCRIPT
    assert javascript_detection.source is DetectionSource.CONTENT


def test_ambiguous_or_empty_content_is_unknown() -> None:
    ambiguous = detect_language(path="script", text="import os\nconsole.log(value);\n")
    empty = detect_language(path="script", text="")
    nothing = detect_language()

    assert ambiguous.language is None
    assert ambiguous.source is DetectionSource.UNKNOWN
    assert empty.language is None
    assert empty.source is DetectionSource.UNKNOWN
    assert nothing.language is None
    assert nothing.source is DetectionSource.UNKNOWN


def test_normalize_removes_bom_and_maps_crlf_to_original_offsets() -> None:
    raw = "\ufeffa\r\nb\r\n"

    normalized = normalize_source(raw)

    assert normalized.had_bom is True
    assert normalized.line_ending == "crlf"
    assert normalized.changed is True
    assert normalized.text == "a\nb\n"
    assert normalized.original_size == 9
    assert normalized.normalized_size == 4
    assert normalized.source_map.offsets == (3, 4, 6, 7, 9)
    assert normalized.source_map.map_offset(0) == 3
    assert normalized.source_map.map_offset(1) == 4
    assert normalized.source_map.map_offset(2) == 6
    assert normalized.source_map.map_offset(3) == 7
    assert normalized.source_map.map_offset(4) == 9


@pytest.mark.parametrize(
    ("source", "expected", "line_ending"),
    [
        ("a = 1\nb = 2\n", "a = 1\nb = 2\n", "lf"),
        ("a = 1\r\nb = 2\r\n", "a = 1\nb = 2\n", "crlf"),
        ("a = 1\rb = 2\r", "a = 1\nb = 2\n", "cr"),
        ("a\r\nb\nc", "a\nb\nc", "mixed"),
        ("single line", "single line", "none"),
    ],
)
def test_normalizes_line_endings_without_changing_code(
    source: str, expected: str, line_ending: str
) -> None:
    normalized = normalize_source(source)

    assert normalized.text == expected
    assert normalized.line_ending == line_ending
    assert normalized.had_bom is False


def test_normalization_preserves_indentation_and_byte_identity() -> None:
    source = "def f():\n\tif True:\n        return 'ok'\n"

    normalized = normalize_source(source)

    assert normalized.changed is False
    assert normalized.text == source
    assert normalized.source_map.offsets == tuple(range(len(source.encode("utf-8")) + 1))


def test_source_map_rejects_offsets_outside_the_source() -> None:
    source_map = normalize_source("a\n").source_map

    with pytest.raises(ValueError, match="outside the source"):
        source_map.map_offset(-1)
    with pytest.raises(ValueError, match="outside the source"):
        source_map.map_offset(source_map.normalized_size + 1)


def test_line_index_converts_utf8_bytes_and_utf16_characters() -> None:
    source = "x = 'é😀'\nnext\n"
    index = LineIndex(source)

    assert index.line_count == 2
    assert index.point_from_char(5) == index.point_from_byte(5)
    assert index.point_from_char(5).column == 5
    assert index.point_from_char(6) == index.point_from_byte(7)
    assert index.point_from_char(6).column == 7
    assert index.point_from_char(6).character == 6
    assert index.point_from_char(7) == index.point_from_byte(11)
    assert index.point_from_char(7).column == 11
    assert index.point_from_char(7).character == 8
    assert index.point_from_char(9).line == 1
    assert index.point_from_char(9).column == 0
    assert index.point_from_char(9).character == 0

    span = index.span_from_chars(5, 7)
    assert source[span.start.char_offset : span.end.char_offset] == "é😀"
    assert span.byte_length == 6
    assert span.char_length == 2
    assert span.as_lsp_range() == {
        "start": {"line": 0, "character": 5},
        "end": {"line": 0, "character": 8},
    }


def test_line_index_rejects_out_of_range_offsets() -> None:
    index = LineIndex("abc\n")

    with pytest.raises(ValueError, match="outside the source"):
        index.point_from_char(5)
    with pytest.raises(ValueError, match="outside the source"):
        index.point_from_byte(5)
    with pytest.raises(ValueError, match="must not precede"):
        index.span_from_chars(2, 1)


def test_parse_valid_python_preserves_exact_text() -> None:
    source = "def add(a: int, b: int) -> int:\n    return a + b\n"

    parsed = parse_source(source, path="add.py")

    assert parsed.language is SupportedLanguage.PYTHON
    assert parsed.path == "add.py"
    assert parsed.text == source
    assert parsed.diagnostics == ()
    assert parsed.has_syntax_errors is False
    assert parsed.error_count == 0
    assert parsed.root_node.type == "module"
    function_node = parsed.root_node.named_children[0]
    assert (
        parsed.text_for_node(function_node) == "def add(a: int, b: int) -> int:\n    return a + b"
    )


def test_parse_valid_javascript_preserves_exact_text() -> None:
    source = "export function add(a, b) {\n  return a + b;\n}\n"

    parsed = parse_source(source, path="add.js")

    assert parsed.language is SupportedLanguage.JAVASCRIPT
    assert parsed.has_syntax_errors is False
    assert parsed.root_node.type == "program"
    assert parsed.text_for_node(parsed.root_node) == source


def test_parse_invalid_python_reports_diagnostics_without_raising() -> None:
    source = "def broken(:\n    return 1\n"

    parsed = parse_source(source, path="bad.py")

    assert parsed.has_syntax_errors is True
    assert parsed.error_count == len(parsed.diagnostics)
    assert parsed.diagnostics
    assert any(diagnostic.kind == "missing" for diagnostic in parsed.diagnostics)
    for diagnostic in parsed.diagnostics:
        assert diagnostic.kind in {"error", "missing"}
        assert diagnostic.span.start.byte_offset >= 0
        assert diagnostic.span.end.byte_offset <= len(source.encode("utf-8"))
        assert diagnostic.span.start.line >= 0
    assert parsed.diagnostics[0].line == 0
    assert "broken" in [token.text for token in tokenize_source(parsed)]


def test_parse_invalid_javascript_reports_error_diagnostics() -> None:
    source = "function broken( {\n  return 1;\n}\n"

    parsed = parse_source(source, path="bad.js")

    assert parsed.has_syntax_errors is True
    assert parsed.diagnostics
    assert all(diagnostic.kind == "error" for diagnostic in parsed.diagnostics)
    assert all(diagnostic.node_type == "ERROR" for diagnostic in parsed.diagnostics)
    assert parsed.text_for_node(parsed.root_node) == source


def test_empty_source_parses_without_chunks_or_tokens() -> None:
    parsed = parse_source("", path="empty.py")

    assert parsed.has_syntax_errors is False
    assert parsed.root_node.type == "module"
    assert tokenize_source(parsed) == ()


def test_parse_rejects_unsupported_or_invalid_text() -> None:
    with pytest.raises(UnsupportedLanguageError, match="Supported languages"):
        parse_source("const value = 1;\n", path="module.ts")

    with pytest.raises(ValueError, match="valid UTF-8"):
        parse_source("\ud800", path="invalid.py")

    with pytest.raises(UnsupportedLanguageError, match="Supported languages"):
        parse_source("x = 1\n", path="script", language="typescript")


def test_explicit_language_parses_unusual_extension() -> None:
    parsed = parse_source(
        "x = 1\n",
        path="snippet.txt",
        language_id="python",
    )

    assert parsed.language is SupportedLanguage.PYTHON
    assert parsed.has_syntax_errors is False


def test_tokenize_source_keeps_comments_and_exact_slices() -> None:
    source = "# note\ndef greet(name):\n    return f'hi {name}'\n"

    tokens = tokenize_source(parse_source(source, path="tokens.py"))

    assert tokens
    comment = tokens[0]
    assert comment.kind == "comment"
    assert comment.text == "# note"
    assert comment.is_comment is True
    assert all(
        token.text == source[token.span.start.char_offset : token.span.end.char_offset]
        for token in tokens
    )
    assert all(token.text for token in tokens)
    assert not any(token.text.isspace() for token in tokens)
    assert any(token.kind == "def" and token.named is False for token in tokens)
    assert all(
        previous.span.end.byte_offset <= current.span.start.byte_offset
        for previous, current in zip(tokens, tokens[1:], strict=False)
    )


def test_token_positions_use_utf16_columns_for_vscode() -> None:
    source = 'value = "😀"\n'

    tokens = tokenize_source(parse_source(source, path="emoji.py"))
    content = next(token for token in tokens if token.kind == "string_content")

    assert content.text == "😀"
    assert content.span.start.byte_offset == 9
    assert content.span.start.char_offset == 9
    assert content.span.start.column == 9
    assert content.span.start.character == 9
    assert content.span.end.byte_offset == 13
    assert content.span.end.column == 13
    assert content.span.end.character == 11
    assert content.span.as_lsp_range() == {
        "start": {"line": 0, "character": 9},
        "end": {"line": 0, "character": 11},
    }


def test_tokens_map_back_through_bom_and_crlf_normalization() -> None:
    source = "\ufeffdef greet():\r\n    return 'ok'\r\n"

    parsed = parse_source(source, path="windows.py")
    tokens = tokenize_source(parsed)

    assert parsed.normalized.had_bom is True
    assert parsed.normalized.line_ending == "crlf"
    name = next(token for token in tokens if token.text == "greet")
    assert name.span.start.line == 0
    assert name.span.start.char_offset == source.index("greet")
    assert name.span.start.byte_offset == len(source[: source.index("greet")].encode("utf-8"))
    assert name.span.start.column == 4
    assert name.span.start.character == 4
    assert parsed.text_for_span(name.span) == "greet"

    return_token = next(token for token in tokens if token.text == "return")
    assert return_token.span.start.line == 1
    assert return_token.span.start.column == 4
    assert return_token.span.start.character == 4
    assert parsed.text_for_span(return_token.span) == "return"
