"""Intraprocedural data-flow graph construction.

Definitions and uses are extracted from the same instructions that form the
CFG. Reaching definitions are computed with a forward fixed-point analysis over
basic blocks, so branch merges and loop back-edges produce real def-use edges.
Function parameters are entry definitions; calls record callee and argument
relationships; explicit returns and raises receive value edges plus edges to
the function exit.

The analysis is intraprocedural. Cross-function argument/return propagation is
not attempted, and closure reads are resolved only to the most recent lexical
definition in an enclosing scope. See ``docs/program-analysis.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import networkx as nx

from craftsec.parsing.models import FunctionSymbol, SourceSpan, SupportedLanguage
from craftsec.parsing.parser import ParsedSource
from craftsec.program_analysis.cfg import (
    ControlFlowAnalysis,
    ControlFlowGraph,
    _ensure_parsed,
    build_cfg,
)
from craftsec.program_analysis.models import (
    BasicBlock,
    DFGEdge,
    DFGEdgeKind,
    DFGNode,
    DFGNodeKind,
    Instruction,
    InstructionKind,
    VariableCategory,
    VariableOccurrence,
    span_to_dict,
)


@dataclass(frozen=True, slots=True)
class DataFlowGraph:
    """A def-use graph for one module or function."""

    parsed: ParsedSource
    scope_id: str
    scope_name: str
    function: FunctionSymbol | None
    graph: nx.DiGraph
    entry_id: str
    exit_id: str
    nodes: tuple[DFGNode, ...]
    edges: tuple[DFGEdge, ...]

    @property
    def definitions(self) -> tuple[DFGNode, ...]:
        return self.definitions_for()

    @property
    def uses(self) -> tuple[DFGNode, ...]:
        return self.uses_for()

    @property
    def parameters(self) -> tuple[DFGNode, ...]:
        return tuple(node for node in self.nodes if node.kind is DFGNodeKind.PARAMETER)

    @property
    def returns(self) -> tuple[DFGNode, ...]:
        return tuple(node for node in self.nodes if node.kind is DFGNodeKind.RETURN)

    @property
    def raises(self) -> tuple[DFGNode, ...]:
        return tuple(node for node in self.nodes if node.kind is DFGNodeKind.RAISE)

    @property
    def calls(self) -> tuple[DFGNode, ...]:
        return tuple(node for node in self.nodes if node.kind is DFGNodeKind.CALL)

    @property
    def def_use_edges(self) -> tuple[DFGEdge, ...]:
        return tuple(
            edge for edge in self.edges if edge.kind in {DFGEdgeKind.DEF_USE, DFGEdgeKind.CLOSURE}
        )

    def definitions_for(self, variable: str | None = None) -> tuple[DFGNode, ...]:
        return tuple(
            node
            for node in self.nodes
            if node.kind in {DFGNodeKind.DEFINITION, DFGNodeKind.PARAMETER}
            and (variable is None or node.name == variable)
        )

    def uses_for(self, variable: str | None = None) -> tuple[DFGNode, ...]:
        return tuple(
            node
            for node in self.nodes
            if node.kind is DFGNodeKind.USE and (variable is None or node.name == variable)
        )

    def dependencies(self, variable: str | None = None) -> tuple[DFGEdge, ...]:
        data_kinds = {
            DFGEdgeKind.DEF_USE,
            DFGEdgeKind.CLOSURE,
            DFGEdgeKind.ARGUMENT,
            DFGEdgeKind.CALLEE,
            DFGEdgeKind.CALL_RESULT,
            DFGEdgeKind.RETURN_VALUE,
            DFGEdgeKind.RAISE_VALUE,
        }
        return tuple(
            edge
            for edge in self.edges
            if edge.kind in data_kinds and (variable is None or edge.variable == variable)
        )

    def node(self, node_id: str) -> DFGNode:
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise KeyError(f"unknown DFG node: {node_id}")

    def unresolved_uses(self) -> tuple[DFGNode, ...]:
        return tuple(
            node for node in self.nodes if node.kind is DFGNodeKind.USE and not node.resolved
        )

    def incoming_edges(self, node: str | DFGNode) -> tuple[DFGEdge, ...]:
        node_id = node.node_id if isinstance(node, DFGNode) else node
        return tuple(edge for edge in self.edges if edge.target == node_id)

    def outgoing_edges(self, node: str | DFGNode) -> tuple[DFGEdge, ...]:
        node_id = node.node_id if isinstance(node, DFGNode) else node
        return tuple(edge for edge in self.edges if edge.source == node_id)

    def variables(self) -> tuple[str, ...]:
        names = {
            node.name
            for node in self.nodes
            if node.name is not None
            and node.kind
            in {
                DFGNodeKind.DEFINITION,
                DFGNodeKind.PARAMETER,
                DFGNodeKind.USE,
            }
        }
        return tuple(sorted(names))

    def summary(self) -> dict[str, object]:
        return {
            "scope_id": self.scope_id,
            "scope_name": self.scope_name,
            "parameters": [node.name for node in self.parameters],
            "definitions": len(self.definitions),
            "uses": len(self.uses),
            "unresolved_uses": len(self.unresolved_uses()),
            "calls": len(self.calls),
            "returns": len(self.returns),
            "dependencies": len(self.def_use_edges),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "scope_id": self.scope_id,
            "scope_name": self.scope_name,
            "kind": "function" if self.function is not None else "module",
            "entry": self.entry_id,
            "exit": self.exit_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


@dataclass(frozen=True, slots=True)
class DataFlowAnalysis:
    """Module and function-level DFGs for one parsed source file."""

    parsed: ParsedSource
    module: DataFlowGraph
    functions: tuple[DataFlowGraph, ...]
    cfg: ControlFlowAnalysis

    @property
    def function_graphs(self) -> tuple[DataFlowGraph, ...]:
        return self.functions

    @property
    def function_dfgs(self) -> tuple[DataFlowGraph, ...]:
        return self.functions

    @property
    def graph(self) -> nx.DiGraph:
        return self.module.graph

    @property
    def nodes(self) -> tuple[DFGNode, ...]:
        return self.module.nodes

    @property
    def edges(self) -> tuple[DFGEdge, ...]:
        return self.module.edges

    @property
    def definitions(self) -> tuple[DFGNode, ...]:
        return self.module.definitions

    @property
    def uses(self) -> tuple[DFGNode, ...]:
        return self.module.uses

    @property
    def parameters(self) -> tuple[DFGNode, ...]:
        return self.module.parameters

    @property
    def returns(self) -> tuple[DFGNode, ...]:
        return self.module.returns

    @property
    def calls(self) -> tuple[DFGNode, ...]:
        return self.module.calls

    def function_graph(self, name: str) -> DataFlowGraph:
        for graph in self.functions:
            if name in {graph.scope_id, graph.scope_name}:
                return graph
            if graph.function is not None and name in {
                graph.function.name,
                graph.function.qualified_name,
            }:
                return graph
        raise KeyError(f"unknown function scope: {name}")

    graph_for = function_graph
    dfg_for = function_graph

    def definitions_for(self, variable: str | None = None) -> tuple[DFGNode, ...]:
        return self.module.definitions_for(variable)

    def uses_for(self, variable: str | None = None) -> tuple[DFGNode, ...]:
        return self.module.uses_for(variable)

    def dependencies(self, variable: str | None = None) -> tuple[DFGEdge, ...]:
        return self.module.dependencies(variable)

    def summaries(self) -> dict[str, dict[str, object]]:
        result = {self.module.scope_id: self.module.summary()}
        for graph in self.functions:
            result[graph.scope_id] = graph.summary()
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "module": self.module.to_dict(),
            "functions": [graph.to_dict() for graph in self.functions],
        }


@dataclass(slots=True)
class _InstructionNodes:
    defs: list[tuple[VariableOccurrence, str]]
    uses: list[tuple[VariableOccurrence, str]]
    calls: list[tuple[object, str]]
    return_node: str | None = None
    raise_node: str | None = None


class _DFGBuilder:
    def __init__(self, parsed: ParsedSource, cfg: ControlFlowAnalysis) -> None:
        self.parsed = parsed
        self.cfg = cfg
        self._nodes: dict[str, DFGNode] = {}
        self._node_order: list[str] = []
        self._edges: list[DFGEdge] = []
        self._edge_keys: set[tuple[str, str, DFGEdgeKind]] = set()
        self._parent_scope: dict[str, str | None] = {"module": None}
        for index, graph in enumerate(cfg.functions):
            scope = cfg.scopes[index] if index < len(cfg.scopes) else None
            self._parent_scope[graph.scope_id] = (
                scope.parent_scope_id if scope is not None else "module"
            )
        self._defs_by_scope: dict[str, dict[str, list[DFGNode]]] = {"module": {}}
        self._scope_start: dict[str, int] = {"module": 0}

    def build(self) -> DataFlowAnalysis:
        module = self._build_scope(self.cfg.module)
        functions = tuple(self._build_scope(graph) for graph in self.cfg.functions)
        return DataFlowAnalysis(
            parsed=self.parsed,
            module=module,
            functions=functions,
            cfg=self.cfg,
        )

    # ------------------------------------------------------------------ scope

    def _build_scope(self, cfg_graph: ControlFlowGraph) -> DataFlowGraph:
        scope_id = cfg_graph.scope_id
        node_start = len(self._node_order)
        edge_start = len(self._edges)
        entry_id = f"{scope_id}:entry"
        exit_id = f"{scope_id}:exit"
        entry_kind = (
            DFGNodeKind.MODULE_ENTRY if cfg_graph.function is None else DFGNodeKind.FUNCTION_ENTRY
        )
        exit_kind = (
            DFGNodeKind.MODULE_EXIT if cfg_graph.function is None else DFGNodeKind.FUNCTION_EXIT
        )
        entry_block = cfg_graph.block(cfg_graph.entry_id)
        exit_block = cfg_graph.block(cfg_graph.exit_id)
        self._add_node(
            DFGNode(
                node_id=entry_id,
                kind=entry_kind,
                span=entry_block.span,
                text=entry_block.text,
                scope_id=scope_id,
            )
        )
        self._add_node(
            DFGNode(
                node_id=exit_id,
                kind=exit_kind,
                span=exit_block.span,
                text=exit_block.text,
                scope_id=scope_id,
            )
        )

        instruction_nodes: dict[str, _InstructionNodes] = {}
        for block in cfg_graph.blocks:
            for instruction in block.statements:
                instruction_nodes[instruction.instruction_id] = self._create_occurrence_nodes(
                    scope_id, block, instruction
                )

        for record in instruction_nodes.values():
            for _occurrence, node_id in record.defs:
                node = self._nodes[node_id]
                if node.kind is DFGNodeKind.PARAMETER:
                    self._add_edge(
                        entry_id,
                        node_id,
                        DFGEdgeKind.PARAMETER_BINDING,
                        node.name,
                        node.span,
                    )

        block_in, _block_out = self._reaching_definitions(cfg_graph, instruction_nodes)
        self._connect_def_use(cfg_graph, instruction_nodes, block_in)
        self._connect_calls(cfg_graph, instruction_nodes)
        self._connect_returns(cfg_graph, instruction_nodes, exit_id)
        self._resolve_closures(cfg_graph, instruction_nodes)
        self._finalize_resolution(cfg_graph, instruction_nodes)

        self._register_scope_defs(scope_id)

        scope_node_ids = self._node_order[node_start:]
        scope_edges = self._edges[edge_start:]
        nodes = tuple(self._nodes[node_id] for node_id in scope_node_ids)
        graph = nx.DiGraph()
        for node in nodes:
            graph.add_node(
                node.node_id,
                kind=node.kind.value,
                name=node.name,
                span=node.span,
                span_dict=span_to_dict(node.span),
                text=node.text,
                scope_id=node.scope_id,
                block_id=node.block_id,
                instruction_id=node.instruction_id,
                category=node.category.value if node.category else None,
                role=node.role.value if node.role else None,
                call_id=node.call_id,
                resolved=node.resolved,
                node=node,
            )
        for edge in scope_edges:
            graph.add_edge(
                edge.source,
                edge.target,
                kind=edge.kind.value,
                variable=edge.variable,
                span=edge.span,
                span_dict=span_to_dict(edge.span),
            )
        return DataFlowGraph(
            parsed=self.parsed,
            scope_id=scope_id,
            scope_name=cfg_graph.scope_name,
            function=cfg_graph.function,
            graph=graph,
            entry_id=entry_id,
            exit_id=exit_id,
            nodes=nodes,
            edges=tuple(scope_edges),
        )

    def _create_occurrence_nodes(
        self,
        scope_id: str,
        block: BasicBlock,
        instruction: Instruction,
    ) -> _InstructionNodes:
        record = _InstructionNodes(defs=[], uses=[], calls=[])
        for index, occurrence in enumerate(instruction.definitions):
            node_id = f"{instruction.instruction_id}:d{index}"
            kind = (
                DFGNodeKind.PARAMETER
                if occurrence.category is VariableCategory.PARAMETER
                else DFGNodeKind.DEFINITION
            )
            self._add_node(
                DFGNode(
                    node_id=node_id,
                    kind=kind,
                    span=occurrence.span,
                    text=occurrence.text,
                    scope_id=scope_id,
                    block_id=block.block_id,
                    instruction_id=instruction.instruction_id,
                    name=occurrence.name,
                    category=occurrence.category,
                    role=occurrence.role,
                )
            )
            record.defs.append((occurrence, node_id))

        for index, occurrence in enumerate(instruction.uses):
            node_id = f"{instruction.instruction_id}:u{index}"
            self._add_node(
                DFGNode(
                    node_id=node_id,
                    kind=DFGNodeKind.USE,
                    span=occurrence.span,
                    text=occurrence.text,
                    scope_id=scope_id,
                    block_id=block.block_id,
                    instruction_id=instruction.instruction_id,
                    name=occurrence.name,
                    category=occurrence.category,
                    role=occurrence.role,
                )
            )
            record.uses.append((occurrence, node_id))

        for call in instruction.calls:
            node_id = f"{instruction.instruction_id}:{call.call_id}"
            self._add_node(
                DFGNode(
                    node_id=node_id,
                    kind=DFGNodeKind.CALL,
                    span=call.span,
                    text=self.parsed.text_for_span(call.span),
                    scope_id=scope_id,
                    block_id=block.block_id,
                    instruction_id=instruction.instruction_id,
                    name=call.callee,
                    call_id=call.call_id,
                )
            )
            record.calls.append((call, node_id))

        if instruction.kind is InstructionKind.RETURN:
            node_id = f"{instruction.instruction_id}:return"
            self._add_node(
                DFGNode(
                    node_id=node_id,
                    kind=DFGNodeKind.RETURN,
                    span=instruction.span,
                    text=instruction.text,
                    scope_id=scope_id,
                    block_id=block.block_id,
                    instruction_id=instruction.instruction_id,
                )
            )
            record.return_node = node_id
        elif instruction.kind is InstructionKind.RAISE:
            node_id = f"{instruction.instruction_id}:raise"
            self._add_node(
                DFGNode(
                    node_id=node_id,
                    kind=DFGNodeKind.RAISE,
                    span=instruction.span,
                    text=instruction.text,
                    scope_id=scope_id,
                    block_id=block.block_id,
                    instruction_id=instruction.instruction_id,
                )
            )
            record.raise_node = node_id
        return record

    # --------------------------------------------------------------- dataflow

    def _reaching_definitions(
        self,
        cfg_graph: ControlFlowGraph,
        instruction_nodes: dict[str, _InstructionNodes],
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        all_defs: dict[str, set[str]] = {}
        def_name: dict[str, str] = {}
        block_names: dict[str, set[str]] = {block.block_id: set() for block in cfg_graph.blocks}

        # Collect the full definition universe first: KILL sets must include
        # definitions that occur in later blocks, not only those seen so far.
        for block in cfg_graph.blocks:
            for instruction in block.statements:
                record = instruction_nodes[instruction.instruction_id]
                for occurrence, node_id in record.defs:
                    def_name[node_id] = occurrence.name
                    all_defs.setdefault(occurrence.name, set()).add(node_id)
                    block_names[block.block_id].add(occurrence.name)

        gen: dict[str, set[str]] = {}
        kill: dict[str, set[str]] = {}
        for block in cfg_graph.blocks:
            block_gen: set[str] = set()
            for instruction in block.statements:
                record = instruction_nodes[instruction.instruction_id]
                for occurrence, node_id in record.defs:
                    block_gen = {
                        existing
                        for existing in block_gen
                        if def_name.get(existing) != occurrence.name
                    }
                    block_gen.add(node_id)
            gen[block.block_id] = block_gen
            block_kill: set[str] = set()
            for name in block_names[block.block_id]:
                block_kill.update(all_defs.get(name, set()))
            kill[block.block_id] = block_kill

        in_sets = {block.block_id: set() for block in cfg_graph.blocks}
        out_sets = {block.block_id: set() for block in cfg_graph.blocks}
        changed = True
        while changed:
            changed = False
            for block in cfg_graph.blocks:
                predecessors = list(cfg_graph.graph.predecessors(block.block_id))
                incoming: set[str] = set()
                for predecessor in predecessors:
                    incoming.update(out_sets[predecessor])
                new_out = (incoming - kill[block.block_id]) | gen[block.block_id]
                if incoming != in_sets[block.block_id] or new_out != out_sets[block.block_id]:
                    in_sets[block.block_id] = incoming
                    out_sets[block.block_id] = new_out
                    changed = True
        self._def_names = def_name
        return in_sets, out_sets

    def _connect_def_use(
        self,
        cfg_graph: ControlFlowGraph,
        instruction_nodes: dict[str, _InstructionNodes],
        block_in: dict[str, set[str]],
    ) -> None:
        for block in cfg_graph.blocks:
            current = set(block_in[block.block_id])
            for instruction in block.statements:
                record = instruction_nodes[instruction.instruction_id]
                for occurrence, use_id in record.uses:
                    matches = {
                        definition
                        for definition in current
                        if self._def_names.get(definition) == occurrence.name
                    }
                    for definition in sorted(matches):
                        self._add_edge(
                            definition,
                            use_id,
                            DFGEdgeKind.DEF_USE,
                            occurrence.name,
                            occurrence.span,
                        )
                for occurrence, definition_id in record.defs:
                    current = {
                        definition
                        for definition in current
                        if self._def_names.get(definition) != occurrence.name
                    }
                    current.add(definition_id)

    def _connect_calls(
        self,
        cfg_graph: ControlFlowGraph,
        instruction_nodes: dict[str, _InstructionNodes],
    ) -> None:
        for block in cfg_graph.blocks:
            for instruction in block.statements:
                record = instruction_nodes[instruction.instruction_id]
                if not record.calls:
                    continue
                outer_calls = [
                    call
                    for call, _node_id in record.calls
                    if not any(
                        other is not call and _contains(other.span, call.span)
                        for other, _other_id in record.calls
                    )
                ]
                for occurrence, use_id in record.uses:
                    if occurrence.category is VariableCategory.CALLEE:
                        candidates = [
                            (call, call_id)
                            for call, call_id in record.calls
                            if call.callee_span is not None
                            and _contains(call.callee_span, occurrence.span)
                        ]
                        if candidates:
                            _call, call_id = min(
                                candidates, key=lambda item: item[0].span.byte_length
                            )
                            self._add_edge(
                                use_id,
                                call_id,
                                DFGEdgeKind.CALLEE,
                                occurrence.name,
                                occurrence.span,
                            )
                    if occurrence.category is VariableCategory.CALL_ARGUMENT:
                        candidates = [
                            (call, call_id, argument)
                            for call, call_id in record.calls
                            for argument in call.argument_spans
                            if _contains(argument, occurrence.span)
                        ]
                        if candidates:
                            _call, call_id, _argument = min(
                                candidates, key=lambda item: item[2].byte_length
                            )
                            self._add_edge(
                                use_id,
                                call_id,
                                DFGEdgeKind.ARGUMENT,
                                occurrence.name,
                                occurrence.span,
                            )

                if (
                    len(outer_calls) == 1
                    and record.defs
                    and instruction.kind
                    in {
                        InstructionKind.ASSIGNMENT,
                        InstructionKind.AUGMENTED_ASSIGNMENT,
                        InstructionKind.DECLARATION,
                    }
                ):
                    outer_call = outer_calls[0]
                    call_id = next(node_id for call, node_id in record.calls if call is outer_call)
                    for occurrence, definition_id in record.defs:
                        self._add_edge(
                            call_id,
                            definition_id,
                            DFGEdgeKind.CALL_RESULT,
                            occurrence.name,
                            occurrence.span,
                        )

    def _connect_returns(
        self,
        cfg_graph: ControlFlowGraph,
        instruction_nodes: dict[str, _InstructionNodes],
        exit_id: str,
    ) -> None:
        for block in cfg_graph.blocks:
            for instruction in block.statements:
                record = instruction_nodes[instruction.instruction_id]
                if record.return_node is not None:
                    for occurrence, use_id in record.uses:
                        self._add_edge(
                            use_id,
                            record.return_node,
                            DFGEdgeKind.RETURN_VALUE,
                            occurrence.name,
                            occurrence.span,
                        )
                    for _call, call_id in record.calls:
                        self._add_edge(
                            call_id,
                            record.return_node,
                            DFGEdgeKind.RETURN_VALUE,
                            None,
                            self._nodes[call_id].span,
                        )
                    self._add_edge(
                        record.return_node,
                        exit_id,
                        DFGEdgeKind.RETURNS_TO,
                        None,
                        self._nodes[record.return_node].span,
                    )
                if record.raise_node is not None:
                    for occurrence, use_id in record.uses:
                        self._add_edge(
                            use_id,
                            record.raise_node,
                            DFGEdgeKind.RAISE_VALUE,
                            occurrence.name,
                            occurrence.span,
                        )
                    for _call, call_id in record.calls:
                        self._add_edge(
                            call_id,
                            record.raise_node,
                            DFGEdgeKind.RAISE_VALUE,
                            None,
                            self._nodes[call_id].span,
                        )
                    self._add_edge(
                        record.raise_node,
                        exit_id,
                        DFGEdgeKind.RAISES_TO,
                        None,
                        self._nodes[record.raise_node].span,
                    )

    def _resolve_closures(
        self,
        cfg_graph: ControlFlowGraph,
        instruction_nodes: dict[str, _InstructionNodes],
    ) -> None:
        local_names = {
            occurrence.name
            for record in instruction_nodes.values()
            for occurrence, _node_id in record.defs
        }
        scope_start = (
            cfg_graph.function.span.start.byte_offset if cfg_graph.function is not None else 0
        )
        parent = self._parent_scope.get(cfg_graph.scope_id)
        for record in instruction_nodes.values():
            for occurrence, use_id in record.uses:
                if occurrence.name in local_names:
                    continue
                definition = self._find_outer_definition(parent, occurrence.name, scope_start)
                if definition is not None:
                    self._add_edge(
                        definition.node_id,
                        use_id,
                        DFGEdgeKind.CLOSURE,
                        occurrence.name,
                        occurrence.span,
                    )

    def _find_outer_definition(
        self,
        scope_id: str | None,
        name: str,
        before: int,
    ) -> DFGNode | None:
        while scope_id is not None:
            candidates = [
                node
                for node in self._defs_by_scope.get(scope_id, {}).get(name, [])
                if node.span.start.byte_offset < before
            ]
            if candidates:
                return max(candidates, key=lambda node: node.span.start.byte_offset)
            scope_id = self._parent_scope.get(scope_id)
        return None

    def _finalize_resolution(
        self,
        cfg_graph: ControlFlowGraph,
        instruction_nodes: dict[str, _InstructionNodes],
    ) -> None:
        incoming = {
            edge.target
            for edge in self._edges
            if edge.kind in {DFGEdgeKind.DEF_USE, DFGEdgeKind.CLOSURE}
        }
        for record in instruction_nodes.values():
            for _occurrence, use_id in record.uses:
                node = self._nodes[use_id]
                resolved = use_id in incoming
                if node.resolved != resolved:
                    self._nodes[use_id] = replace(node, resolved=resolved)
        _ = cfg_graph

    def _register_scope_defs(self, scope_id: str) -> None:
        definitions: dict[str, list[DFGNode]] = {}
        for node_id in self._node_order:
            node = self._nodes[node_id]
            if (
                node.scope_id == scope_id
                and node.name is not None
                and node.kind in {DFGNodeKind.DEFINITION, DFGNodeKind.PARAMETER}
            ):
                definitions.setdefault(node.name, []).append(node)
        self._defs_by_scope[scope_id] = definitions
        if self.cfg.module.scope_id == scope_id:
            self._scope_start[scope_id] = 0

    # --------------------------------------------------------------- helpers

    def _add_node(self, node: DFGNode) -> None:
        if node.node_id in self._nodes:
            return
        self._nodes[node.node_id] = node
        self._node_order.append(node.node_id)

    def _add_edge(
        self,
        source: str,
        target: str,
        kind: DFGEdgeKind,
        variable: str | None,
        span: SourceSpan,
    ) -> None:
        key = (source, target, kind)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self._edges.append(
            DFGEdge(
                source=source,
                target=target,
                kind=kind,
                variable=variable,
                span=span,
            )
        )


def build_dfg(
    source: ParsedSource | str,
    *,
    cfg: ControlFlowAnalysis | None = None,
    path: str | Path | None = None,
    language: SupportedLanguage | str | None = None,
    language_id: str | None = None,
) -> DataFlowAnalysis:
    """Build module and function-level DFGs for Python or JavaScript source."""
    if cfg is None:
        parsed = _ensure_parsed(
            source,
            path=path,
            language=language,
            language_id=language_id,
        )
        cfg = build_cfg(parsed)
    else:
        parsed = cfg.parsed
    return _DFGBuilder(parsed, cfg).build()


def _contains(outer: SourceSpan, inner: SourceSpan) -> bool:
    return (
        outer.start.byte_offset <= inner.start.byte_offset
        and outer.end.byte_offset >= inner.end.byte_offset
    )


build_data_flow_graph = build_dfg
analyze_data_flow = build_dfg
