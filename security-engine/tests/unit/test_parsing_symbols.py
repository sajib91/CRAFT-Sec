from __future__ import annotations

import pytest

from craftsec.parsing import (
    ChunkKind,
    FunctionKind,
    SupportedLanguage,
    UnsupportedLanguageError,
    chunk_source,
    parse_source,
    preprocess_file,
    preprocess_source,
)

PYTHON_SOURCE = """import os


def top(a: int, b=1, /, c: str = "x", *args: int, d: int = 2, **kwargs) -> None:
    def nested():
        yield 1
    return None


class C:
    @staticmethod
    def method(self, x, *rest, **kw):
        return x


square = lambda value: value * value
pairs = sorted(items, key=lambda item: item[0])
"""

JAVASCRIPT_SOURCE = """export function add(a, b = 1, ...rest) { return a + b; }
const double = (value) => value * 2;
const baz = function () { return 1; };
const wrapped = function inner(x) { return x; };
const destructured = ({a, b: alias}, [first, ...others]) => a + alias;
const obj = { shorthand(x) { return x; } };
class Greeter {
  async *entries({name = "x"} = {}) { yield name; }
}
function* counter() { yield 1; }
export default async function () { return 1; }
"""


def test_extracts_python_functions_methods_and_lambdas() -> None:
    result = preprocess_source(PYTHON_SOURCE, path="symbols.py")

    assert result.language is SupportedLanguage.PYTHON
    assert not result.has_syntax_errors
    assert [(function.name, function.qualified_name) for function in result.functions] == [
        ("top", "top"),
        ("nested", "top.nested"),
        ("method", "C.method"),
        ("square", "square"),
        (None, None),
    ]

    top, nested, method, square, anonymous = result.functions

    assert top.kind is FunctionKind.FUNCTION
    assert top.is_async is False
    assert top.is_generator is False
    assert top.is_method is False
    assert top.container_name is None
    assert top.parameters == (
        "a: int",
        "b=1",
        'c: str = "x"',
        "*args: int",
        "d: int = 2",
        "**kwargs",
    )
    assert top.parameter_names == ("a", "b", "c", "args", "d", "kwargs")

    assert nested.kind is FunctionKind.FUNCTION
    assert nested.is_generator is True
    assert nested.span.start.line == 4

    assert method.kind is FunctionKind.METHOD
    assert method.is_method is True
    assert method.container_name == "C"
    assert method.parameters == ("self", "x", "*rest", "**kw")
    assert method.parameter_names == ("self", "x", "rest", "kw")
    assert method.name_span is not None
    name_span = method.name_span
    assert result.text[name_span.start.char_offset : name_span.end.char_offset] == "method"
    method_text = result.text[method.span.start.char_offset : method.span.end.char_offset]
    assert method_text.startswith("@staticmethod")
    assert method_text.endswith("return x")

    assert square.kind is FunctionKind.LAMBDA
    assert square.name == "square"
    assert square.parameter_names == ("value",)

    assert anonymous.kind is FunctionKind.LAMBDA
    assert anonymous.name is None
    assert anonymous.parameter_names == ("item",)


def test_nested_yield_does_not_mark_outer_function_as_generator() -> None:
    source = "def outer():\n    def inner():\n        yield 1\n    return inner\n"

    functions = preprocess_source(source, path="nested.py").functions

    assert [(function.name, function.is_generator) for function in functions] == [
        ("outer", False),
        ("inner", True),
    ]


def test_decorated_async_generator_span_includes_decorator() -> None:
    source = "@cache\nasync def stream(items):\n    yield from items\n"

    function = preprocess_source(source, path="stream.py").functions[0]

    assert function.name == "stream"
    assert function.is_async is True
    assert function.is_generator is True
    assert function.span.start.line == 0
    assert function.span.end.line == 2
    function_text = source[function.span.start.char_offset : function.span.end.char_offset]
    assert function_text.startswith("@cache")
    assert function_text.endswith("yield from items")
    assert function.name_span is not None
    name_span = function.name_span
    assert source[name_span.start.char_offset : name_span.end.char_offset] == "stream"


def test_extracts_javascript_function_forms() -> None:
    result = preprocess_source(JAVASCRIPT_SOURCE, path="symbols.js")

    assert result.language is SupportedLanguage.JAVASCRIPT
    assert not result.has_syntax_errors
    assert [(function.name, function.qualified_name) for function in result.functions] == [
        ("add", "add"),
        ("double", "double"),
        ("baz", "baz"),
        ("inner", "inner"),
        ("destructured", "destructured"),
        ("shorthand", "shorthand"),
        ("entries", "Greeter.entries"),
        ("counter", "counter"),
        (None, None),
    ]

    add, double, baz, inner, destructured, shorthand, entries, counter, anonymous = result.functions

    assert add.kind is FunctionKind.FUNCTION
    assert add.parameters == ("a", "b = 1", "...rest")
    assert add.parameter_names == ("a", "b", "rest")

    assert double.kind is FunctionKind.ARROW
    assert double.parameter_names == ("value",)

    assert baz.kind is FunctionKind.FUNCTION
    assert baz.name == "baz"
    assert baz.parameter_names == ()

    assert inner.kind is FunctionKind.FUNCTION
    assert inner.name == "inner"
    assert inner.parameter_names == ("x",)

    assert destructured.kind is FunctionKind.ARROW
    assert destructured.parameters == ("{a, b: alias}", "[first, ...others]")
    assert destructured.parameter_names == ("a", "alias", "first", "others")

    assert shorthand.kind is FunctionKind.METHOD
    assert shorthand.is_method is True
    assert shorthand.container_name == "obj"
    assert shorthand.qualified_name == "shorthand"

    assert entries.kind is FunctionKind.METHOD
    assert entries.is_method is True
    assert entries.is_async is True
    assert entries.is_generator is True
    assert entries.container_name == "Greeter"
    assert entries.parameter_names == ("name",)

    assert counter.kind is FunctionKind.FUNCTION
    assert counter.is_generator is True
    assert counter.is_async is False

    assert anonymous.kind is FunctionKind.FUNCTION
    assert anonymous.name is None
    assert anonymous.is_async is True


def test_chunks_python_functions_classes_and_leading_module_statements() -> None:
    source = (
        "import os\n\n\n"
        "def first():\n    return 1\n\n\n"
        'class Widget:\n    def render(self):\n        return "ok"\n'
    )

    result = preprocess_source(source, path="module.py")
    chunks = result.chunks
    repeated = preprocess_source(source, path="module.py").chunks

    assert [chunk.kind for chunk in chunks] == [
        ChunkKind.MODULE,
        ChunkKind.FUNCTION,
        ChunkKind.CLASS,
    ]
    assert [chunk.symbol_name for chunk in chunks] == [None, "first", "Widget"]
    assert [chunk.chunk_id for chunk in chunks] == ["chunk-0001", "chunk-0002", "chunk-0003"]
    assert [chunk.chunk_id for chunk in repeated] == [chunk.chunk_id for chunk in chunks]
    for chunk in chunks:
        assert source[chunk.span.start.char_offset : chunk.span.end.char_offset] == chunk.text
        assert chunk.part_count == 1
        assert chunk.part_index == 0


def test_decorated_python_function_is_one_function_chunk() -> None:
    source = "@decorator\ndef wrapped():\n    return 1\n"

    chunks = preprocess_source(source, path="decorated.py").chunks

    assert len(chunks) == 1
    assert chunks[0].kind is ChunkKind.FUNCTION
    assert chunks[0].symbol_name == "wrapped"
    assert chunks[0].text == "@decorator\ndef wrapped():\n    return 1"
    assert chunks[0].span.start.line == 0


def test_chunks_javascript_declarations_and_exports() -> None:
    source = (
        "export function add(a, b) {\n  return a + b;\n}\n"
        "const twice = (x) => x * 2;\n"
        "const obj = { method() { return 1; } };\n"
        "class Box {}\n"
        "export default async function () { return 1; }\n"
    )

    chunks = preprocess_source(source, path="chunks.js").chunks

    assert [chunk.kind for chunk in chunks] == [
        ChunkKind.FUNCTION,
        ChunkKind.FUNCTION,
        ChunkKind.MODULE,
        ChunkKind.CLASS,
        ChunkKind.FUNCTION,
    ]
    assert [chunk.symbol_name for chunk in chunks] == ["add", "twice", None, "Box", None]
    assert chunks[0].text.startswith("export function add")
    assert chunks[-1].text.startswith("export default async function")


def test_oversized_chunk_is_split_on_line_boundaries_with_exact_spans() -> None:
    source = "def long():\n" + "".join(f"    value{index} = {index}\n" for index in range(1, 11))
    source += "    return value1\n"

    chunks = preprocess_source(source, path="long.py", max_chars=50).chunks

    assert len(chunks) > 1
    assert all(chunk.kind is ChunkKind.FUNCTION for chunk in chunks)
    assert all(chunk.symbol_name == "long" for chunk in chunks)
    assert all(len(chunk.text) <= 50 for chunk in chunks)
    assert [chunk.part_index for chunk in chunks] == list(range(len(chunks)))
    assert all(chunk.part_count == len(chunks) for chunk in chunks)
    assert (
        "".join(chunk.text for chunk in chunks)
        == source[chunks[0].span.start.char_offset : chunks[-1].span.end.char_offset]
    )
    for previous, current in zip(chunks, chunks[1:], strict=False):
        assert previous.span.end.char_offset == current.span.start.char_offset


def test_single_oversized_line_is_hard_split() -> None:
    source = "x = '" + "a" * 120 + "'\n"

    chunks = preprocess_source(source, path="long_line.py", max_chars=25).chunks

    assert len(chunks) > 1
    assert all(chunk.kind is ChunkKind.MODULE for chunk in chunks)
    assert all(len(chunk.text) <= 25 for chunk in chunks)
    assert (
        "".join(chunk.text for chunk in chunks)
        == source[chunks[0].span.start.char_offset : chunks[-1].span.end.char_offset]
    )
    for previous, current in zip(chunks, chunks[1:], strict=False):
        assert previous.span.end.byte_offset == current.span.start.byte_offset


def test_overlap_lines_repeats_the_previous_boundary_line() -> None:
    source = "def long():\n" + "".join(f"    value{index} = {index}\n" for index in range(1, 13))
    source += "    return value1\n"

    chunks = preprocess_source(source, path="long.py", max_chars=50, overlap_lines=1).chunks

    assert len(chunks) > 1
    for previous, current in zip(chunks, chunks[1:], strict=False):
        assert current.span.start.byte_offset < previous.span.end.byte_offset
        assert current.span.start.line == previous.span.end.line - 1


def test_invalid_sources_still_produce_recovered_symbols_and_chunks() -> None:
    python_result = preprocess_source(
        "def ok():\n    return 1\n\ndef broken(:\n    return 2\n",
        path="broken.py",
    )

    assert python_result.has_syntax_errors is True
    assert python_result.diagnostics
    assert "ok" in [function.name for function in python_result.functions]
    assert any(chunk.kind is ChunkKind.FUNCTION for chunk in python_result.chunks)
    for chunk in python_result.chunks:
        assert (
            python_result.text[chunk.span.start.char_offset : chunk.span.end.char_offset]
            == chunk.text
        )

    javascript_result = preprocess_source(
        "function broken( {\n  return 1;\n}\n",
        path="broken.js",
    )

    assert javascript_result.has_syntax_errors is True
    assert javascript_result.diagnostics
    assert any(chunk.kind is ChunkKind.ERROR for chunk in javascript_result.chunks)
    for chunk in javascript_result.chunks:
        assert (
            javascript_result.text[chunk.span.start.char_offset : chunk.span.end.char_offset]
            == chunk.text
        )


def test_empty_source_has_no_chunks() -> None:
    result = preprocess_source("", path="empty.py")

    assert result.chunks == ()
    assert result.functions == ()
    assert result.tokens == ()


def test_chunk_options_are_validated() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        preprocess_source("x = 1\n", path="x.py", max_chars=0)
    with pytest.raises(ValueError, match="must not be negative"):
        chunk_source(parse_source("x = 1\n", path="x.py"), overlap_lines=-1)


def test_bom_and_crlf_are_preserved_in_chunks_but_not_in_columns() -> None:
    source = "\ufeffdef answer():\r\n    return 42\r\n"

    result = preprocess_source(source, path="bom.py")
    chunk = result.chunks[0]

    assert result.normalized.had_bom is True
    assert result.normalized.line_ending == "crlf"
    assert chunk.kind is ChunkKind.FUNCTION
    assert chunk.span.start.line == 0
    assert chunk.span.start.column == 0
    assert chunk.span.start.character == 0
    assert chunk.text == "def answer():\r\n    return 42"
    assert source[chunk.span.start.char_offset : chunk.span.end.char_offset] == chunk.text


def test_preprocess_file_reads_utf8_and_uses_the_path(tmp_path) -> None:
    path = tmp_path / "module.py"
    path.write_text("@decorator\ndef run(value):\n    return value\n", encoding="utf-8")

    result = preprocess_file(path)

    assert result.path == str(path)
    assert result.language is SupportedLanguage.PYTHON
    assert not result.has_syntax_errors
    assert [(function.name, function.qualified_name) for function in result.functions] == [
        ("run", "run")
    ]
    assert result.chunks[0].text == "@decorator\ndef run(value):\n    return value"


def test_preprocess_file_requires_a_supported_language(tmp_path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(UnsupportedLanguageError, match="Supported languages"):
        preprocess_file(path)

    result = preprocess_file(path, language_id="python")
    assert result.language is SupportedLanguage.PYTHON
