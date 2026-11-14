from __future__ import annotations

import pytest

from craftsec.parsing.models import SupportedLanguage
from craftsec.program_analysis import (
    CFGEdgeKind,
    CFGNodeKind,
    InstructionKind,
    analyze_source,
    build_cfg,
    build_function_cfg,
    build_module_cfg,
)
from craftsec.program_analysis.cfg import ControlFlowGraph


def block_with_text(graph: ControlFlowGraph, text: str):
    matches = [block for block in graph.blocks if text in block.text]
    assert len(matches) == 1, f"expected one block containing {text!r}, got {matches!r}"
    return matches[0]


def block_with_instruction(graph: ControlFlowGraph, kind: InstructionKind):
    matches = [
        block
        for block in graph.blocks
        if any(statement.kind is kind for statement in block.statements)
    ]
    assert len(matches) == 1, f"expected one block with {kind.value!r}, got {matches!r}"
    return matches[0]


def assert_exact_spans(parsed, graph: ControlFlowGraph) -> None:
    for block in graph.blocks:
        assert parsed.text_for_span(block.span) == block.text
        for instruction in block.statements:
            assert parsed.text_for_span(instruction.span) == instruction.text
    for edge in graph.edges:
        assert edge.source in graph.graph
        assert edge.target in graph.graph
        assert 0 <= edge.span.start.byte_offset <= edge.span.end.byte_offset


def test_python_straight_line_blocks_and_branch_edges() -> None:
    source = """x = 1
y = x + 2
if y > 2:
    z = y
else:
    z = 0
print(z)
"""
    analysis = analyze_source(source, path="linear.py")
    cfg = analysis.cfg.module

    assert cfg.scope_name == "<module>"
    assert cfg.function is None
    assert cfg.block(cfg.entry_id).kind is CFGNodeKind.ENTRY
    assert cfg.block(cfg.exit_id).kind is CFGNodeKind.EXIT
    assert cfg.block(cfg.entry_id).statements == ()

    first = block_with_text(cfg, "x = 1")
    assert first.text == "x = 1\ny = x + 2\nif y > 2"
    assert [statement.kind for statement in first.statements] == [
        InstructionKind.ASSIGNMENT,
        InstructionKind.ASSIGNMENT,
        InstructionKind.CONDITION,
    ]

    then_block = block_with_text(cfg, "z = y")
    else_block = block_with_text(cfg, "z = 0")
    print_block = block_with_text(cfg, "print(z)")

    outgoing = {edge.kind: edge.target for edge in cfg.edges if edge.source == first.block_id}
    assert outgoing[CFGEdgeKind.TRUE] == then_block.block_id
    assert outgoing[CFGEdgeKind.FALSE] == else_block.block_id
    assert {edge.source for edge in cfg.edges if edge.target == print_block.block_id} == {
        then_block.block_id,
        else_block.block_id,
    }
    assert cfg.successors(first) == (then_block, else_block)
    assert set(cfg.predecessors(print_block)) == {then_block, else_block}
    assert cfg.reachable_blocks() == frozenset(block.block_id for block in cfg.blocks)

    assert_exact_spans(analysis.parsed, cfg)
    assert cfg.graph.number_of_nodes() == len(cfg.blocks)
    for edge in cfg.edges:
        attributes = cfg.graph[edge.source][edge.target]
        assert edge.kind.value in attributes["kinds"]
        assert attributes["count"] >= 1
        assert cfg.edge_details(edge.source, edge.target)


def test_python_loop_break_continue_and_for_else() -> None:
    source = """def scan(items, limit):
    for item in items:
        if item == limit:
            break
        if item is None:
            continue
        found.append(item)
    else:
        found = []
    return found
"""
    analysis = analyze_source(source, path="loop.py")
    graph = analysis.cfg.function_graph("scan")

    loop_header = block_with_text(graph, "for item in items")
    assert loop_header.statements[0].kind is InstructionKind.LOOP
    assert [definition.name for definition in graph.parameters[0].definitions] == [
        "items",
        "limit",
    ]

    break_block = block_with_text(graph, "break")
    continue_block = block_with_text(graph, "continue")
    loop_exit = block_with_text(graph, "found = []")
    return_block = block_with_text(graph, "return found")

    break_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.BREAK]
    continue_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.CONTINUE]
    loop_back_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.LOOP_BACK]

    assert [(edge.source, edge.target) for edge in break_edges] == [
        (break_block.block_id, return_block.block_id)
    ]
    assert [(edge.source, edge.target) for edge in continue_edges] == [
        (continue_block.block_id, loop_header.block_id)
    ]
    assert all(edge.target == loop_header.block_id for edge in loop_back_edges)
    assert any(
        edge.source == loop_header.block_id and edge.target == loop_exit.block_id
        for edge in graph.edges
        if edge.kind is CFGEdgeKind.FALSE
    )
    assert return_block.terminator is not None
    assert return_block.terminator.kind is InstructionKind.RETURN

    assert_exact_spans(analysis.parsed, graph)


def test_python_try_except_else_finally_paths() -> None:
    source = """def load(path):
    try:
        data = read(path)
    except OSError as exc:
        data = None
    else:
        data = data.strip()
    finally:
        closed = True
    return data
"""
    analysis = analyze_source(source, path="try.py")
    graph = analysis.cfg.function_graph("load")

    try_block = block_with_text(graph, "try:")
    handler_block = block_with_instruction(graph, InstructionKind.CASE)
    finalizer_block = block_with_text(graph, "closed = True")
    return_block = block_with_text(graph, "return data")
    assert handler_block.text.startswith("except OSError")

    exception_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.EXCEPTION]
    assert len(exception_edges) == 1
    assert exception_edges[0].source == try_block.block_id
    assert exception_edges[0].target == handler_block.block_id
    assert exception_edges[0].label == "OSError as exc"

    assert any(
        edge.source == handler_block.block_id and edge.target == finalizer_block.block_id
        for edge in graph.edges
    )
    assert return_block is finalizer_block
    assert finalizer_block.terminator is not None
    assert finalizer_block.terminator.kind is InstructionKind.RETURN
    assert [definition.name for definition in handler_block.statements[0].definitions] == ["exc"]
    assert graph.reachable_blocks() == frozenset(block.block_id for block in graph.blocks)
    assert_exact_spans(analysis.parsed, graph)


def test_python_match_cases_and_exhaustiveness() -> None:
    source = """def classify(v):
    match v:
        case 1:
            x = 1
        case 2:
            x = 2
    return x
"""
    analysis = analyze_source(source, path="match.py")
    graph = analysis.cfg.function_graph("classify")

    dispatch = block_with_instruction(graph, InstructionKind.MATCH)
    assert dispatch.statements[-1].kind is InstructionKind.MATCH
    case_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.CASE]
    assert [edge.label for edge in case_edges] == ["1", "2"]
    assert {edge.source for edge in case_edges} == {dispatch.block_id}
    no_match_edges = [
        edge
        for edge in graph.edges
        if edge.kind is CFGEdgeKind.FALSE and edge.label == "no_matching_case"
    ]
    assert len(no_match_edges) == 1

    wildcard_source = """def classify(v):
    match v:
        case 1:
            x = 1
        case _:
            x = 0
    return x
"""
    wildcard = analyze_source(wildcard_source, path="match_wildcard.py")
    wildcard_graph = wildcard.cfg.function_graph("classify")
    assert [edge.label for edge in wildcard_graph.edges if edge.kind is CFGEdgeKind.CASE] == [
        "1",
        "_",
    ]
    assert not any(
        edge.label == "no_matching_case"
        for edge in wildcard_graph.edges
        if edge.kind is CFGEdgeKind.FALSE
    )

    assert_exact_spans(analysis.parsed, graph)
    assert_exact_spans(wildcard.parsed, wildcard_graph)


def test_function_scopes_and_module_declaration_is_opaque() -> None:
    source = """def outer(a, b=2):
    def inner(c):
        return c
    return inner(a)
"""
    analysis = analyze_source(source, path="scopes.py")
    module = analysis.cfg.module
    outer = analysis.cfg.function_graph("outer")
    inner = analysis.cfg.function_graph("outer.inner")

    declaration = block_with_text(module, "def outer")
    assert declaration.statements[0].kind is InstructionKind.FUNCTION
    assert "return" not in declaration.text
    assert module.calls == ()
    assert [definition.name for definition in declaration.statements[0].definitions] == ["outer"]

    assert outer.function is not None
    assert inner.function is not None
    assert outer.scope_id != inner.scope_id
    assert outer.block(outer.entry_id).text == "a, b"
    assert [definition.name for definition in outer.parameters[0].definitions] == ["a", "b"]
    assert [definition.name for definition in inner.parameters[0].definitions] == ["c"]

    scopes = {scope.scope_name: scope for scope in analysis.cfg.scopes}
    assert scopes["outer"].parent_scope_id == "module"
    assert scopes["outer.inner"].parent_scope_id == outer.scope_id
    assert analysis.cfg.function_graph(outer.scope_id) is outer

    with pytest.raises(KeyError):
        analysis.cfg.function_graph("missing")

    assert_exact_spans(analysis.parsed, module)
    assert_exact_spans(analysis.parsed, outer)
    assert_exact_spans(analysis.parsed, inner)


def test_javascript_switch_cases_fallthrough_break_and_default() -> None:
    source = """function pick(v) {
  switch (v) {
    case 1:
      x = "one";
      break;
    case 2:
    case 3:
      x = "many";
      break;
    default:
      x = "other";
  }
  return x;
}
"""
    analysis = analyze_source(source, path="switch.js")
    assert analysis.parsed.language is SupportedLanguage.JAVASCRIPT
    graph = analysis.cfg.function_graph("pick")

    dispatch = block_with_text(graph, "(v)")
    assert dispatch.statements[-1].kind is InstructionKind.SWITCH
    assert [use.name for use in dispatch.statements[-1].uses] == ["v"]

    case_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.CASE]
    assert [edge.label for edge in case_edges] == ["1", "2", "3"]
    default_edges = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.DEFAULT]
    assert [edge.label for edge in default_edges] == ["default"]

    case_two = block_with_text(graph, "case 2:")
    case_three = block_with_text(graph, "case 3:")
    fallthrough = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.FALLTHROUGH]
    assert [(edge.source, edge.target) for edge in fallthrough] == [
        (case_two.block_id, case_three.block_id)
    ]
    assert any(edge.source == case_two.block_id for edge in graph.edges)
    assert len([edge for edge in graph.edges if edge.kind is CFGEdgeKind.BREAK]) == 2
    assert graph.reachable_blocks() == frozenset(block.block_id for block in graph.blocks)
    assert_exact_spans(analysis.parsed, graph)


def test_javascript_for_continue_break_for_of_and_update() -> None:
    source = """function scan(items) {
  for (let i = 0; i < 3; i++) {
    if (i === 1) continue;
    if (i === 2) break;
    use(i);
  }
  for (const item of items) { use(item); }
  return items;
}
"""
    analysis = analyze_source(source, path="loops.js")
    graph = analysis.cfg.function_graph("scan")

    update = next(
        instruction
        for instruction in graph.instructions
        if instruction.kind is InstructionKind.LOOP_UPDATE
    )
    assert update.text == "i++"
    assert [definition.name for definition in update.definitions] == ["i"]
    update_block = next(block for block in graph.blocks if update in block.statements)
    condition_block = block_with_text(graph, "i < 3")
    for_of_header = block_with_text(graph, "for (const item of items)")

    continue_edge = next(edge for edge in graph.edges if edge.kind is CFGEdgeKind.CONTINUE)
    assert continue_edge.target == update_block.block_id

    loop_backs = [edge for edge in graph.edges if edge.kind is CFGEdgeKind.LOOP_BACK]
    assert any(edge.target == condition_block.block_id for edge in loop_backs)
    assert any(edge.target == for_of_header.block_id for edge in loop_backs)

    break_edge = next(edge for edge in graph.edges if edge.kind is CFGEdgeKind.BREAK)
    assert break_edge.target == for_of_header.block_id

    loop_target = next(
        instruction
        for instruction in graph.instructions
        if instruction.kind is InstructionKind.LOOP_TARGET
    )
    assert loop_target.text == "item"
    assert [definition.category.value for definition in loop_target.definitions] == ["loop_target"]
    assert graph.reachable_blocks() == frozenset(block.block_id for block in graph.blocks)
    assert_exact_spans(analysis.parsed, graph)


def test_empty_source_and_unreachable_blocks_are_represented() -> None:
    empty = analyze_source("", path="empty.py")
    cfg = empty.cfg.module
    assert [(block.kind, block.text) for block in cfg.blocks] == [
        (CFGNodeKind.ENTRY, ""),
        (CFGNodeKind.EXIT, ""),
    ]
    assert [(edge.kind, edge.label) for edge in cfg.edges] == [(CFGEdgeKind.NORMAL, None)]
    assert cfg.reachable_blocks() == {cfg.entry_id, cfg.exit_id}

    source = """def f():
    return 1
    x = 2
"""
    analysis = analyze_source(source, path="dead.py")
    graph = analysis.cfg.function_graph("f")
    dead = block_with_text(graph, "x = 2")
    assert dead.block_id not in graph.reachable_blocks()
    assert any(edge.source == dead.block_id for edge in graph.edges)


def test_exact_locations_for_bom_crlf_and_utf8_utf16_columns() -> None:
    source = '\ufeffx = "é"; y = x\r\nif y:\r\n  z = y\r\n'
    analysis = analyze_source(source, path="spans.py")
    cfg = analysis.cfg.module
    parsed = analysis.parsed

    assert parsed.text == source
    entry = cfg.block(cfg.entry_id)
    assert entry.span.start.byte_offset == 3
    assert entry.span.start.char_offset == 1

    first = block_with_text(cfg, "x =")
    assert first.text == 'x = "é"; y = x\r\nif y'
    assert parsed.text_for_span(first.span) == first.text

    use_x = next(
        occurrence
        for instruction in first.statements
        for occurrence in instruction.uses
        if occurrence.name == "x"
    )
    assert use_x.span.start.line == 0
    assert use_x.span.start.char_offset == 14
    assert use_x.span.start.column == 14
    assert use_x.span.start.character == 13
    assert parsed.text[use_x.span.start.char_offset : use_x.span.end.char_offset] == "x"

    condition = next(
        instruction
        for instruction in first.statements
        if instruction.kind is InstructionKind.CONDITION
    )
    assert condition.span.start.line == 1
    assert condition.span.start.column == 3
    assert condition.span.start.character == 3
    assert parsed.text_for_span(condition.span) == "y"

    assert_exact_spans(parsed, cfg)


def test_direct_cfg_builders_and_aliases_are_equivalent() -> None:
    source = "def f(a):\n    return a\n"
    analysis = build_cfg(source, path="direct.py")
    module = build_module_cfg(source, path="direct.py")
    function = build_function_cfg(source, "f", path="direct.py")

    assert module.to_dict() == analysis.module.to_dict()
    assert function.to_dict() == analysis.function_graph("f").to_dict()
    assert analysis.function_graph("f") == function
