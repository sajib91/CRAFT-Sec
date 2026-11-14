from __future__ import annotations

import json

import networkx as nx
import pytest

from craftsec.parsing import parse_source
from craftsec.program_analysis import (
    analyze_control_flow,
    analyze_data_flow,
    analyze_file,
    analyze_parsed,
    analyze_source,
    build_cfg,
    build_control_flow_graph,
    build_data_flow_graph,
    build_dfg,
)


def test_analyze_parsed_matches_direct_builders() -> None:
    source = """def f(x):
    y = x + 1
    return y
"""
    parsed = parse_source(source, path="manual.py")
    analysis = analyze_parsed(parsed)
    cfg = build_cfg(parsed)
    dfg = build_dfg(parsed, cfg=cfg)

    assert analysis.parsed is parsed
    assert analysis.cfg.to_dict() == cfg.to_dict()
    assert analysis.dfg.to_dict() == dfg.to_dict()
    assert analysis.module_cfg.to_dict() == cfg.module.to_dict()
    assert analysis.module_dfg.to_dict() == dfg.module.to_dict()
    assert analysis.function_cfg("f").to_dict() == cfg.function_graph("f").to_dict()
    assert analysis.function_dfg("f").to_dict() == dfg.function_graph("f").to_dict()


def test_analyze_file_reads_source_and_detects_language(tmp_path) -> None:
    path = tmp_path / "sample.js"
    source = "function add(a, b) {\n  return a + b;\n}\n"
    path.write_text(source, encoding="utf-8")

    analysis = analyze_file(path)

    assert analysis.parsed.path == str(path)
    assert analysis.parsed.language.value == "javascript"
    assert analysis.parsed.text == source
    assert analysis.cfg.function_graph("add").parameters[0].text == "a, b"
    assert analysis.dfg.function_graph("add").returns[0].text == "return a + b;"


def test_public_aliases_return_the_same_products() -> None:
    source = "def f(x):\n    return x\n"

    cfg = build_cfg(source, path="aliases.py")
    dfg = build_dfg(source, path="aliases.py")

    assert build_control_flow_graph(source, path="aliases.py").to_dict() == cfg.to_dict()
    assert analyze_control_flow(source, path="aliases.py").to_dict() == cfg.to_dict()
    assert build_data_flow_graph(source, path="aliases.py").to_dict() == dfg.to_dict()
    assert analyze_data_flow(source, path="aliases.py").to_dict() == dfg.to_dict()


def test_serialized_analysis_is_json_safe_and_uses_networkx() -> None:
    source = 'def f(x):\n    note = "é"; return note\n'
    analysis = analyze_source(source, path="serialize.py")

    payload = analysis.to_dict()
    encoded = json.dumps(payload)
    assert '"lsp"' in encoded
    assert payload["language"] == "python"
    assert payload["cfg"]["module"]["kind"] == "module"
    blocks = payload["cfg"]["module"]["blocks"]
    assert blocks[0]["kind"] == "entry"
    assert blocks[0]["span"]["lsp"] == {
        "start": {"line": 0, "character": 0},
        "end": {"line": 0, "character": 0},
    }
    for block in blocks:
        for statement in block["statements"]:
            assert set(statement["span"]["lsp"]) == {"start", "end"}

    assert isinstance(analysis.cfg.graph, nx.DiGraph)
    assert isinstance(analysis.dfg.graph, nx.DiGraph)
    assert analysis.cfg.graph.nodes[analysis.cfg.entry_id]["kind"] == "entry"
    dfg_node = analysis.dfg.function_graph("f").nodes[2]
    assert analysis.dfg.function_graph("f").graph.nodes[dfg_node.node_id]["node"] == dfg_node


def test_syntax_errors_still_produce_partial_graphs() -> None:
    analysis = analyze_source("def broken(:\n    x =\n", path="broken.py")

    assert analysis.parsed.has_syntax_errors
    assert analysis.cfg.module.blocks
    assert analysis.dfg.module.nodes
    assert any(block.text for block in analysis.cfg.module.blocks)


def test_missing_scope_is_reported() -> None:
    analysis = analyze_source("def f():\n    pass\n", path="scope.py")

    with pytest.raises(KeyError):
        analysis.function_cfg("missing")
    with pytest.raises(KeyError):
        analysis.function_dfg("missing")
