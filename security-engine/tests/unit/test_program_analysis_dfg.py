from __future__ import annotations

import pytest

from craftsec.parsing.models import SupportedLanguage
from craftsec.program_analysis import (
    DFGEdgeKind,
    DFGNodeKind,
    analyze_source,
    build_cfg,
    build_dfg,
)
from craftsec.program_analysis.dfg import DataFlowGraph


def reaching_lines(graph: DataFlowGraph, use) -> set[int]:
    return {
        graph.node(edge.source).span.start.line
        for edge in graph.incoming_edges(use)
        if edge.kind in {DFGEdgeKind.DEF_USE, DFGEdgeKind.CLOSURE}
    }


def test_branch_merge_reaching_definitions_and_reassignment_kill() -> None:
    source = """def f(flag):
    x = 1
    if flag:
        x = 2
    y = x
    x = 3
    z = x
    return y + z
"""
    analysis = analyze_source(source, path="branch.py")
    graph = analysis.dfg.function_graph("f")

    assert [node.span.start.line for node in graph.definitions_for("x")] == [1, 3, 5]
    branch_use = next(node for node in graph.uses_for("x") if node.span.start.line == 4)
    killed_use = next(node for node in graph.uses_for("x") if node.span.start.line == 6)
    assert reaching_lines(graph, branch_use) == {1, 3}
    assert reaching_lines(graph, killed_use) == {5}

    use_y = next(node for node in graph.uses_for("y") if node.span.start.line == 7)
    use_z = next(node for node in graph.uses_for("z") if node.span.start.line == 7)
    assert reaching_lines(graph, use_y) == {4}
    assert reaching_lines(graph, use_z) == {6}

    parameter = graph.parameters[0]
    assert parameter.name == "flag"
    assert any(
        edge.kind is DFGEdgeKind.PARAMETER_BINDING and edge.target == parameter.node_id
        for edge in graph.edges
    )
    assert all(node.scope_id == graph.scope_id for node in graph.nodes)
    dependencies = graph.dependencies("x")
    assert all(edge.variable == "x" for edge in dependencies)
    assert {graph.node(edge.source).span.start.line for edge in dependencies} == {1, 3, 5}
    assert all(edge.kind is DFGEdgeKind.DEF_USE for edge in dependencies)


def test_loop_carried_reaching_definitions() -> None:
    source = """def f(n):
    total = 0
    while n > 0:
        total += n
        n -= 1
    return total
"""
    graph = analyze_source(source, path="loop.py").dfg.function_graph("f")

    total_before_update = next(
        node for node in graph.uses_for("total") if node.span.start.line == 3
    )
    total_at_return = next(node for node in graph.uses_for("total") if node.span.start.line == 5)
    n_at_loop = next(node for node in graph.uses_for("n") if node.span.start.line == 2)
    n_before_update = next(node for node in graph.uses_for("n") if node.span.start.line == 3)

    assert reaching_lines(graph, total_before_update) == {1, 3}
    assert reaching_lines(graph, total_at_return) == {1, 3}
    assert reaching_lines(graph, n_at_loop) == {0, 4}
    assert reaching_lines(graph, n_before_update) == {0, 4}
    assert any(
        edge.kind is DFGEdgeKind.DEF_USE
        and graph.node(edge.source).span.start.line == 3
        and edge.target == total_before_update.node_id
        for edge in graph.edges
    )
    assert graph.unresolved_uses() == ()


def test_augmented_assignment_kills_and_rebinds_parameter() -> None:
    source = """def f(n):
    n += 1
    n = n * 2
    return n
"""
    graph = analyze_source(source, path="augmented.py").dfg.function_graph("f")

    parameter = graph.parameters[0]
    assert parameter.kind is DFGNodeKind.PARAMETER
    assert parameter.name == "n"
    use_in_augmented = next(node for node in graph.uses_for("n") if node.span.start.line == 1)
    use_in_assignment = next(node for node in graph.uses_for("n") if node.span.start.line == 2)
    use_in_return = next(node for node in graph.uses_for("n") if node.span.start.line == 3)

    assert reaching_lines(graph, use_in_augmented) == {0}
    assert reaching_lines(graph, use_in_assignment) == {1}
    assert reaching_lines(graph, use_in_return) == {2}
    assert all(edge.kind is DFGEdgeKind.DEF_USE for edge in graph.incoming_edges(use_in_return))


def test_calls_arguments_results_and_return_values() -> None:
    source = """def f(x):
    y = g(x, 1)
    return h(y)
"""
    graph = analyze_source(source, path="calls.py").dfg.function_graph("f")

    g_call = next(node for node in graph.calls if node.name == "g")
    h_call = next(node for node in graph.calls if node.name == "h")
    assert g_call.kind is DFGNodeKind.CALL
    assert g_call.text == "g(x, 1)"
    assert h_call.text == "h(y)"

    callee_edges = [
        edge for edge in graph.incoming_edges(g_call) if edge.kind is DFGEdgeKind.CALLEE
    ]
    argument_edges = [
        edge for edge in graph.incoming_edges(g_call) if edge.kind is DFGEdgeKind.ARGUMENT
    ]
    assert [graph.node(edge.source).name for edge in callee_edges] == ["g"]
    assert [graph.node(edge.source).name for edge in argument_edges] == ["x"]

    result_edges = [
        edge for edge in graph.outgoing_edges(g_call) if edge.kind is DFGEdgeKind.CALL_RESULT
    ]
    assert len(result_edges) == 1
    result = graph.node(result_edges[0].target)
    assert result.name == "y"
    assert result.span.start.line == 1

    return_node = graph.returns[0]
    assert any(
        edge.kind is DFGEdgeKind.RETURN_VALUE and edge.source == h_call.node_id
        for edge in graph.incoming_edges(return_node)
    )
    assert {node.name for node in graph.unresolved_uses()} == {"g", "h"}


def test_return_and_raise_value_relationships() -> None:
    source = """def f(x):
    if x:
        return x
    raise ValueError(x)
"""
    graph = analyze_source(source, path="raise.py").dfg.function_graph("f")

    return_node = graph.returns[0]
    raise_node = graph.raises[0]
    assert return_node.kind is DFGNodeKind.RETURN
    assert raise_node.kind is DFGNodeKind.RAISE

    returned = {
        graph.node(edge.source).name
        for edge in graph.incoming_edges(return_node)
        if edge.kind is DFGEdgeKind.RETURN_VALUE
    }
    assert returned == {"x"}
    raised = {
        graph.node(edge.source).name
        for edge in graph.incoming_edges(raise_node)
        if edge.kind is DFGEdgeKind.RAISE_VALUE
    }
    assert raised == {"ValueError", "x"}
    raise_call = next(node for node in graph.calls if node.name == "ValueError")
    assert any(
        edge.kind is DFGEdgeKind.RAISE_VALUE and edge.source == raise_call.node_id
        for edge in graph.incoming_edges(raise_node)
    )
    assert any(
        edge.kind is DFGEdgeKind.RETURNS_TO and edge.target == graph.exit_id
        for edge in graph.outgoing_edges(return_node)
    )
    assert any(
        edge.kind is DFGEdgeKind.RAISES_TO and edge.target == graph.exit_id
        for edge in graph.outgoing_edges(raise_node)
    )
    assert {node.name for node in graph.unresolved_uses()} == {"ValueError"}


def test_nested_function_closure_edge_and_scope_isolation() -> None:
    source = """def outer(a):
    x = a
    def inner(b):
        return x + b
    return inner
"""
    analysis = analyze_source(source, path="closure.py")
    outer = analysis.dfg.function_graph("outer")
    inner = analysis.dfg.function_graph("outer.inner")

    outer_def_x = outer.definitions_for("x")[0]
    inner_use_x = next(node for node in inner.uses_for("x") if node.name == "x")
    closure_edges = [
        edge for edge in inner.incoming_edges(inner_use_x) if edge.kind is DFGEdgeKind.CLOSURE
    ]
    assert len(closure_edges) == 1
    assert closure_edges[0].source == outer_def_x.node_id
    assert closure_edges[0].variable == "x"
    assert closure_edges[0].span == inner_use_x.span

    assert outer.uses_for("b") == ()
    assert all(node.scope_id == outer.scope_id for node in outer.nodes)
    assert all(node.scope_id == inner.scope_id for node in inner.nodes)
    assert inner_use_x.scope_id == inner.scope_id
    assert outer.scope_id != inner.scope_id
    assert inner.unresolved_uses() == ()


def test_module_definitions_resolve_function_closures_but_stay_opaque() -> None:
    source = """value = 1
def f():
    return value
"""
    analysis = analyze_source(source, path="module_closure.py")
    module = analysis.dfg.module
    function = analysis.dfg.function_graph("f")

    assert [node.name for node in module.definitions_for()] == ["value", "f"]
    assert module.uses_for("value") == ()
    assert all(node.scope_id == "module" for node in module.nodes)

    module_def = module.definitions_for("value")[0]
    function_use = function.uses_for("value")[0]
    closure_edges = [edge for edge in function.edges if edge.kind is DFGEdgeKind.CLOSURE]
    assert len(closure_edges) == 1
    assert closure_edges[0].source == module_def.node_id
    assert closure_edges[0].target == function_use.node_id
    assert function_use.resolved is True


def test_unresolved_uses_do_not_invent_definitions() -> None:
    source = """def f():
    return missing + len([])
"""
    graph = analyze_source(source, path="unresolved.py").dfg.function_graph("f")
    unresolved = {node.name: node for node in graph.unresolved_uses()}

    assert set(unresolved) == {"missing", "len"}
    for node in unresolved.values():
        assert node.resolved is False
        assert not any(
            edge.kind in {DFGEdgeKind.DEF_USE, DFGEdgeKind.CLOSURE}
            for edge in graph.incoming_edges(node)
        )
    len_call = next(node for node in graph.calls if node.name == "len")
    assert any(
        edge.kind is DFGEdgeKind.CALLEE and edge.source == unresolved["len"].node_id
        for edge in graph.incoming_edges(len_call)
    )


def test_javascript_declarations_calls_and_function_scope() -> None:
    source = """const x = 1;
function add(a, b) {
  const sum = a + b;
  return sum;
}
const result = add(x, 2);
"""
    analysis = analyze_source(source, path="calls.js")
    assert analysis.parsed.language is SupportedLanguage.JAVASCRIPT
    module = analysis.dfg.module
    function = analysis.dfg.function_graph("add")

    assert module.definitions_for("x")[0].span.start.line == 0
    assert module.definitions_for("add")[0].span.start.line == 1
    assert module.definitions_for("result")[0].span.start.line == 5
    call = next(node for node in module.calls if node.name == "add")
    assert any(
        edge.kind is DFGEdgeKind.CALL_RESULT and module.node(edge.target).name == "result"
        for edge in module.outgoing_edges(call)
    )
    assert any(
        edge.kind is DFGEdgeKind.ARGUMENT and module.node(edge.source).name == "x"
        for edge in module.incoming_edges(call)
    )

    assert [node.name for node in function.parameters] == ["a", "b"]
    assert reaching_lines(function, function.uses_for("a")[0]) == {1}
    assert reaching_lines(function, function.uses_for("b")[0]) == {1}
    assert function.definitions_for("sum")[0].span.start.line == 2
    assert function.returns[0].span.start.line == 3
    assert module.uses_for("a") == ()
    assert all(node.scope_id != module.scope_id for node in function.nodes)


def test_dfg_graph_invariants_and_deterministic_builds() -> None:
    source = """def f(a):
    x = a
    if x > 0:
        x = transform(x)
    return x
"""
    first = analyze_source(source, path="invariants.py")
    second = analyze_source(source, path="invariants.py")
    assert first.dfg.to_dict() == second.dfg.to_dict()

    graph = first.dfg.function_graph("f")
    assert graph.graph.number_of_nodes() == len(graph.nodes)
    assert [node.node_id for node in graph.nodes] == [node_id for node_id in graph.graph.nodes]
    for node in graph.nodes:
        assert first.parsed.text_for_span(node.span) == node.text
    for edge in graph.edges:
        assert edge.source in graph.graph
        assert edge.target in graph.graph
        if edge.kind in {DFGEdgeKind.DEF_USE, DFGEdgeKind.CLOSURE}:
            assert graph.node(edge.target).name == edge.variable
        assert 0 <= edge.span.start.byte_offset <= edge.span.end.byte_offset

    summary = graph.summary()
    assert summary["scope_name"] == "f"
    assert summary["parameters"] == ["a"]
    assert summary["definitions"] == len(graph.definitions)
    assert summary["uses"] == len(graph.uses)
    assert summary["dependencies"] == len(graph.def_use_edges)

    empty = analyze_source("", path="empty.py")
    assert [node.kind for node in empty.dfg.module.nodes] == [
        DFGNodeKind.MODULE_ENTRY,
        DFGNodeKind.MODULE_EXIT,
    ]
    assert empty.dfg.module.edges == ()


def test_build_dfg_reuses_supplied_cfg_and_rejects_unknown_scope() -> None:
    source = "def f(x):\n    return x\n"
    cfg = build_cfg(source, path="direct.py")
    dfg = build_dfg(cfg.parsed, cfg=cfg)
    assert dfg.cfg is cfg
    assert dfg.function_graph("f").scope_id == cfg.function_graph("f").scope_id

    with pytest.raises(KeyError):
        dfg.function_graph("missing")
