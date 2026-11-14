"""Control-flow graph construction for Python and JavaScript.

The CFG is built in two stages. First, tree-sitter statements are lowered to
straight-line instructions with explicit branch, loop, exception, return, break,
and continue edges. Second, leaders are computed and instructions are collapsed
into basic blocks. Function bodies are analysed as separate graphs; the module
graph treats declarations as opaque instructions.

Approximations are documented in ``docs/program-analysis.md`` and
``security-engine/LIMITATIONS.md``. In particular, exception edges are attached
to a structured try dispatch rather than to every potentially raising
instruction, and returns inside ``try``/``finally`` are not routed through the
finalizer.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
from tree_sitter import Node

from craftsec.parsing.functions import extract_functions
from craftsec.parsing.models import FunctionSymbol, SourceSpan, SupportedLanguage
from craftsec.parsing.parser import ParsedSource, parse_source
from craftsec.program_analysis.models import (
    BasicBlock,
    CallSite,
    CFGEdge,
    CFGEdgeKind,
    CFGNodeKind,
    FunctionScopeInfo,
    Instruction,
    InstructionKind,
    VariableCategory,
    VariableOccurrence,
    span_to_dict,
)
from craftsec.program_analysis.variables import (
    ExpressionAnalysis,
    VariableExtractor,
    _parameters_node,
)

_FUNCTION_NODE_TYPES = {
    SupportedLanguage.PYTHON: frozenset({"function_definition", "lambda"}),
    SupportedLanguage.JAVASCRIPT: frozenset(
        {
            "arrow_function",
            "function_declaration",
            "function_expression",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
        }
    ),
}
_PYTHON_CLASS_TYPES = frozenset({"class_definition"})
_JAVASCRIPT_CLASS_TYPES = frozenset({"class", "class_declaration"})
_BLOCK_TYPES = frozenset({"block", "statement_block", "switch_body"})
_PYTHON_ASSIGNMENT_STATEMENTS = frozenset(
    {"assignment", "augmented_assignment", "named_expression"}
)
_JAVASCRIPT_ASSIGNMENT_STATEMENTS = frozenset(
    {"assignment_expression", "augmented_assignment_expression", "update_expression"}
)
_COMMENT_AND_EXTRA_TYPES = frozenset({"comment"})


@dataclass(slots=True)
class _FlowPoint:
    node: Instruction
    edge_kind: CFGEdgeKind | None = None
    label: str | None = None


@dataclass(frozen=True, slots=True)
class ControlFlowGraph:
    """A basic-block CFG for one module or function."""

    parsed: ParsedSource = field(compare=False, repr=False)
    scope_id: str
    scope_name: str
    function: FunctionSymbol | None
    graph: nx.DiGraph = field(compare=False, repr=False)
    entry_id: str
    exit_id: str
    blocks: tuple[BasicBlock, ...]
    edges: tuple[CFGEdge, ...]

    @property
    def instructions(self) -> tuple[Instruction, ...]:
        return tuple(statement for block in self.blocks for statement in block.statements)

    @property
    def nodes(self) -> tuple[BasicBlock, ...]:
        return self.blocks

    @property
    def parameters(self) -> tuple[Instruction, ...]:
        return tuple(
            instruction
            for instruction in self.instructions
            if instruction.kind is InstructionKind.PARAMETER
        )

    @property
    def calls(self) -> tuple[CallSite, ...]:
        return tuple(call for instruction in self.instructions for call in instruction.calls)

    def block(self, block_id: str) -> BasicBlock:
        for block in self.blocks:
            if block.block_id == block_id:
                return block
        raise KeyError(f"unknown CFG block: {block_id}")

    def successors(self, block: str | BasicBlock) -> tuple[BasicBlock, ...]:
        block_id = block.block_id if isinstance(block, BasicBlock) else block
        return tuple(self.block(target) for target in self.graph.successors(block_id))

    def predecessors(self, block: str | BasicBlock) -> tuple[BasicBlock, ...]:
        block_id = block.block_id if isinstance(block, BasicBlock) else block
        return tuple(self.block(source) for source in self.graph.predecessors(block_id))

    def reachable_blocks(self) -> frozenset[str]:
        return frozenset(nx.descendants(self.graph, self.entry_id)) | {self.entry_id}

    def edge_details(self, source: str, target: str) -> tuple[CFGEdge, ...]:
        return tuple(edge for edge in self.edges if edge.source == source and edge.target == target)

    def to_dict(self) -> dict[str, object]:
        return {
            "scope_id": self.scope_id,
            "scope_name": self.scope_name,
            "kind": "function" if self.function is not None else "module",
            "entry": self.entry_id,
            "exit": self.exit_id,
            "blocks": [block.to_dict() for block in self.blocks],
            "edges": [edge.to_dict() for edge in self.edges],
        }


@dataclass(frozen=True, slots=True)
class ControlFlowAnalysis:
    """Module and function-level CFGs for one parsed source file."""

    parsed: ParsedSource
    module: ControlFlowGraph
    functions: tuple[ControlFlowGraph, ...]
    scopes: tuple[FunctionScopeInfo, ...] = ()

    @property
    def function_graphs(self) -> tuple[ControlFlowGraph, ...]:
        return self.functions

    @property
    def function_cfgs(self) -> tuple[ControlFlowGraph, ...]:
        return self.functions

    @property
    def graph(self) -> nx.DiGraph:
        return self.module.graph

    @property
    def blocks(self) -> tuple[BasicBlock, ...]:
        return self.module.blocks

    @property
    def edges(self) -> tuple[CFGEdge, ...]:
        return self.module.edges

    @property
    def instructions(self) -> tuple[Instruction, ...]:
        return self.module.instructions

    @property
    def entry_id(self) -> str:
        return self.module.entry_id

    @property
    def exit_id(self) -> str:
        return self.module.exit_id

    def function_graph(self, name: str) -> ControlFlowGraph:
        for graph in self.functions:
            if name in {graph.scope_id, graph.scope_name}:
                return graph
            if graph.function is not None and name in {
                graph.function.name,
                graph.function.qualified_name,
            }:
                return graph
        raise KeyError(f"unknown function scope: {name}")

    # Common aliases used by callers and tests.
    graph_for = function_graph
    cfg_for = function_graph

    def to_dict(self) -> dict[str, object]:
        return {
            "module": self.module.to_dict(),
            "functions": [graph.to_dict() for graph in self.functions],
            "scopes": [scope.to_dict() for scope in self.scopes],
        }


class _CFGBuilder:
    def __init__(
        self,
        parsed: ParsedSource,
        *,
        scope_id: str,
        scope_name: str,
        function: FunctionSymbol | None,
        function_node: Node | None,
        body_node: Node,
    ) -> None:
        self.parsed = parsed
        self.scope_id = scope_id
        self.scope_name = scope_name
        self.function = function
        self.function_node = function_node
        self.body_node = body_node
        self.variables = VariableExtractor(parsed)
        self.nodes: list[Instruction] = []
        self._by_id: dict[str, Instruction] = {}
        self._order: dict[str, int] = {}
        self._edges: list[tuple[Instruction, Instruction, CFGEdgeKind, str | None]] = []
        self._counter = 0
        self._forced_leaders: set[str] = set()
        self._break_stack: list[list[_FlowPoint]] = []
        self._continue_stack: list[Instruction] = []
        self._exception_stack: list[list[Instruction]] = []

        start_span = parsed.span_for_node(function_node or body_node)
        end_span = parsed.span_for_node(body_node)
        self.entry = self._create(
            InstructionKind.PASS,
            SourceSpan(start_span.start, start_span.start),
            "",
            synthetic=True,
        )
        self._register(self.entry)
        self.exit = self._create(
            InstructionKind.PASS,
            SourceSpan(end_span.end, end_span.end),
            "",
            synthetic=True,
        )

    # ------------------------------------------------------------------ build

    def build(self) -> ControlFlowGraph:
        points = [_FlowPoint(self.entry)]

        if self.function_node is not None:
            parameter_analysis = self.variables.parameters(self.function_node)
            if parameter_analysis.definitions or parameter_analysis.uses:
                span = _combined_span(
                    [item.span for item in parameter_analysis.definitions]
                    + [item.span for item in parameter_analysis.uses]
                )
                parameter_instruction = self._add(
                    InstructionKind.PARAMETER,
                    span,
                    self.parsed.text_for_span(span),
                    definitions=tuple(parameter_analysis.definitions),
                    uses=tuple(parameter_analysis.uses),
                    calls=tuple(parameter_analysis.calls),
                )
                self._connect(points, parameter_instruction, CFGEdgeKind.NORMAL)
                points = [_FlowPoint(parameter_instruction)]

        body_marker = len(self.nodes)
        body_is_expression = (
            self.body_node.type not in _BLOCK_TYPES
            and self.body_node.type
            not in {
                "module",
                "program",
            }
        )
        if body_is_expression:
            exits = self._emit_implicit_return(self.body_node, points)
        else:
            exits = self._emit_body(self.body_node, points)

        for point in exits:
            self._connect([point], self.exit, CFGEdgeKind.NORMAL)

        if len(self.nodes) > body_marker:
            self._forced_leaders.add(self.nodes[body_marker].instruction_id)

        self._register(self.exit)
        return self._finish()

    # --------------------------------------------------------------- emission

    def _emit_body(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        if node.type in _BLOCK_TYPES or node.type in {"module", "program"}:
            return self._emit_statements(node.named_children, points)
        if node.type == "else_clause":
            body = node.child_by_field_name("body")
            return self._emit_body(body, points) if body is not None else points
        if node.type == "finally_clause":
            body = _clause_body(node)
            return self._emit_body(body, points) if body is not None else points
        return self._emit_statement(node, points)

    def _emit_statements(
        self,
        statements: Iterable[Node],
        points: list[_FlowPoint],
    ) -> list[_FlowPoint]:
        current = points
        for statement in statements:
            if statement.type in _COMMENT_AND_EXTRA_TYPES:
                continue
            current = self._emit_statement(statement, current)
        return current

    def _emit_statement(
        self,
        node: Node,
        points: list[_FlowPoint],
    ) -> list[_FlowPoint]:
        node_type = node.type

        if node_type in _COMMENT_AND_EXTRA_TYPES:
            return points

        if node_type == "decorated_definition":
            definition = next(
                (
                    child
                    for child in node.named_children
                    if child.type
                    in _FUNCTION_NODE_TYPES[self.parsed.language]
                    | (
                        _PYTHON_CLASS_TYPES
                        if self.parsed.language is SupportedLanguage.PYTHON
                        else _JAVASCRIPT_CLASS_TYPES
                    )
                ),
                None,
            )
            if definition is not None:
                return self._emit_declaration(definition, points, outer=node)
            return self._emit_simple(node, points, InstructionKind.STATEMENT)

        if node_type in _FUNCTION_NODE_TYPES[self.parsed.language]:
            return self._emit_declaration(node, points)
        if node_type in (
            _PYTHON_CLASS_TYPES
            if self.parsed.language is SupportedLanguage.PYTHON
            else _JAVASCRIPT_CLASS_TYPES
        ):
            return self._emit_declaration(node, points)

        if node_type == "if_statement":
            return self._emit_if(node, points)
        if node_type == "while_statement":
            return self._emit_while(node, points)
        if node_type == "do_statement":
            return self._emit_do_while(node, points)
        if node_type == "for_statement":
            return self._emit_for(node, points)
        if node_type == "for_in_statement":
            return self._emit_for_in(node, points)
        if node_type == "switch_statement":
            return self._emit_switch(node, points)
        if node_type == "match_statement":
            return self._emit_match(node, points)
        if node_type == "try_statement":
            return self._emit_try(node, points)
        if node_type == "with_statement":
            return self._emit_with(node, points)
        if node_type == "assert_statement":
            return self._emit_assert(node, points)
        if node_type == "return_statement":
            return self._emit_return(node, points)
        if node_type in {"raise_statement", "throw_statement"}:
            return self._emit_raise(node, points)
        if node_type == "break_statement":
            return self._emit_break(node, points)
        if node_type == "continue_statement":
            return self._emit_continue(node, points)
        if node_type in {"import_statement", "import_from_statement", "future_import_statement"}:
            return self._emit_import(node, points)
        if node_type in {"global_statement", "nonlocal_statement"}:
            return self._emit_simple(node, points, InstructionKind.DECLARATION)
        if node_type == "pass_statement":
            return self._emit_simple(node, points, InstructionKind.PASS)
        if node_type == "delete_statement":
            return self._emit_delete(node, points)
        if node_type in {"lexical_declaration", "variable_declaration"}:
            analysis = self.variables.declaration(node)
            return self._emit_analysis(node, points, InstructionKind.DECLARATION, analysis)
        if node_type == "export_statement":
            return self._emit_export(node, points)
        if node_type == "labeled_statement":
            body = node.child_by_field_name("body")
            if body is None and node.named_children:
                body = node.named_children[-1]
            return self._emit_statement(body, points) if body is not None else points
        if node_type == "expression_statement":
            return self._emit_expression_statement(node, points)
        if node_type == "empty_statement":
            return self._emit_simple(node, points, InstructionKind.PASS)
        if node_type == "statement_block":
            return self._emit_body(node, points)

        return self._emit_simple(node, points, InstructionKind.STATEMENT)

    # ---------------------------------------------------------- control nodes

    def _emit_if(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        if alternative is None:
            alternative = next(
                (child for child in node.named_children if child.type == "else_clause"),
                None,
            )

        condition_instruction = self._condition(node, condition)
        self._connect(points, condition_instruction, CFGEdgeKind.NORMAL)
        consequence_exits = self._emit_body(
            consequence,
            [_FlowPoint(condition_instruction, CFGEdgeKind.TRUE)],
        )
        if alternative is not None:
            alternative_exits = self._emit_body(
                alternative,
                [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)],
            )
        else:
            alternative_exits = [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)]
        return consequence_exits + alternative_exits

    def _emit_while(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        alternative = node.child_by_field_name("alternative")
        if alternative is None:
            alternative = next(
                (child for child in node.named_children if child.type == "else_clause"),
                None,
            )

        condition_instruction = self._condition(node, condition)
        self._connect(points, condition_instruction, CFGEdgeKind.NORMAL)

        self._break_stack.append([])
        self._continue_stack.append(condition_instruction)
        body_exits = self._emit_body(
            body,
            [_FlowPoint(condition_instruction, CFGEdgeKind.TRUE)],
        )
        self._connect(body_exits, condition_instruction, CFGEdgeKind.LOOP_BACK)
        self._continue_stack.pop()
        break_points = self._break_stack.pop()

        if alternative is not None:
            false_exits = self._emit_body(
                alternative,
                [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)],
            )
        else:
            false_exits = [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)]
        return false_exits + break_points

    def _emit_do_while(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        body = node.child_by_field_name("body")
        condition = node.child_by_field_name("condition")
        anchor = self._add(
            InstructionKind.LOOP,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            synthetic=True,
        )
        self._connect(points, anchor, CFGEdgeKind.NORMAL)
        condition_instruction = self._create(
            InstructionKind.CONDITION,
            self.parsed.span_for_node(condition) if condition is not None else anchor.span,
            self.parsed.text_for_node(condition) if condition is not None else "",
            definitions=tuple(
                self.variables.expression(condition).definitions if condition is not None else ()
            ),
            uses=tuple(self.variables.expression(condition).uses if condition is not None else ()),
            calls=tuple(
                self.variables.expression(condition).calls if condition is not None else ()
            ),
        )

        self._break_stack.append([])
        self._continue_stack.append(condition_instruction)
        body_exits = self._emit_body(body, [_FlowPoint(anchor)])
        self._continue_stack.pop()
        break_points = self._break_stack.pop()

        self._register(condition_instruction)
        self._connect(body_exits, condition_instruction, CFGEdgeKind.NORMAL)
        self._connect(
            [_FlowPoint(condition_instruction, CFGEdgeKind.TRUE)],
            anchor,
            CFGEdgeKind.LOOP_BACK,
        )
        return [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)] + break_points

    def _emit_for(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        if self.parsed.language is SupportedLanguage.PYTHON:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            body = node.child_by_field_name("body")
            alternative = node.child_by_field_name("alternative")
            if alternative is None:
                alternative = next(
                    (child for child in node.named_children if child.type == "else_clause"),
                    None,
                )

            iterable_analysis = (
                self.variables.expression(right) if right is not None else ExpressionAnalysis()
            )
            span = _header_span(self.parsed, node, body)
            iterable = self._add(
                InstructionKind.LOOP,
                span,
                self.parsed.text_for_span(span),
                definitions=tuple(iterable_analysis.definitions),
                uses=tuple(iterable_analysis.uses),
                calls=tuple(iterable_analysis.calls),
            )
            self._connect(points, iterable, CFGEdgeKind.NORMAL)
            target_analysis = (
                self.variables.targets(left, VariableCategory.LOOP_TARGET)
                if left is not None
                else ExpressionAnalysis()
            )
            target_span = self.parsed.span_for_node(left) if left is not None else span
            target = self._add(
                InstructionKind.LOOP_TARGET,
                target_span,
                self.parsed.text_for_node(left) if left is not None else "",
                definitions=tuple(target_analysis.definitions),
                uses=tuple(target_analysis.uses),
            )
            self._connect(
                [_FlowPoint(iterable, CFGEdgeKind.TRUE)],
                target,
                CFGEdgeKind.NORMAL,
            )

            self._break_stack.append([])
            self._continue_stack.append(iterable)
            body_exits = self._emit_body(body, [_FlowPoint(target)])
            self._connect(body_exits, iterable, CFGEdgeKind.LOOP_BACK)
            self._continue_stack.pop()
            break_points = self._break_stack.pop()

            if alternative is not None:
                false_exits = self._emit_body(
                    alternative,
                    [_FlowPoint(iterable, CFGEdgeKind.FALSE)],
                )
            else:
                false_exits = [_FlowPoint(iterable, CFGEdgeKind.FALSE)]
            return false_exits + break_points

        initializer = node.child_by_field_name("initializer")
        condition = _javascript_for_condition(node)
        increment = node.child_by_field_name("increment")
        body = node.child_by_field_name("body")
        current = points
        if initializer is not None and initializer.type not in {"empty_statement", ";"}:
            current = self._emit_statement(initializer, current)

        if condition is not None and condition.type != ";":
            condition_instruction = self._condition(node, condition)
        else:
            span = _header_span(self.parsed, node, body)
            condition_instruction = self._add(
                InstructionKind.LOOP,
                span,
                self.parsed.text_for_span(span),
            )
        self._connect(current, condition_instruction, CFGEdgeKind.NORMAL)

        update_instruction: Instruction | None = None
        if increment is not None and increment.type not in {"empty_statement", ";"}:
            update_analysis = self.variables.expression(increment)
            update_instruction = self._create(
                InstructionKind.LOOP_UPDATE,
                self.parsed.span_for_node(increment),
                self.parsed.text_for_node(increment),
                definitions=tuple(update_analysis.definitions),
                uses=tuple(update_analysis.uses),
                calls=tuple(update_analysis.calls),
            )

        self._break_stack.append([])
        self._continue_stack.append(update_instruction or condition_instruction)
        body_exits = self._emit_body(
            body,
            [_FlowPoint(condition_instruction, CFGEdgeKind.TRUE)],
        )
        self._continue_stack.pop()
        break_points = self._break_stack.pop()

        if update_instruction is not None:
            self._register(update_instruction)
            self._connect(body_exits, update_instruction, CFGEdgeKind.NORMAL)
            self._connect([update_instruction], condition_instruction, CFGEdgeKind.LOOP_BACK)
        else:
            self._connect(body_exits, condition_instruction, CFGEdgeKind.LOOP_BACK)

        return [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)] + break_points

    def _emit_for_in(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        body = node.child_by_field_name("body")
        iterable_analysis = (
            self.variables.expression(right) if right is not None else ExpressionAnalysis()
        )
        span = _header_span(self.parsed, node, body)
        iterable = self._add(
            InstructionKind.LOOP,
            span,
            self.parsed.text_for_span(span),
            definitions=tuple(iterable_analysis.definitions),
            uses=tuple(iterable_analysis.uses),
            calls=tuple(iterable_analysis.calls),
        )
        self._connect(points, iterable, CFGEdgeKind.NORMAL)
        target_analysis = (
            self.variables.targets(left, VariableCategory.LOOP_TARGET)
            if left is not None
            else ExpressionAnalysis()
        )
        target_span = self.parsed.span_for_node(left) if left is not None else span
        target = self._add(
            InstructionKind.LOOP_TARGET,
            target_span,
            self.parsed.text_for_node(left) if left is not None else "",
            definitions=tuple(target_analysis.definitions),
            uses=tuple(target_analysis.uses),
        )
        self._connect([_FlowPoint(iterable, CFGEdgeKind.TRUE)], target, CFGEdgeKind.NORMAL)

        self._break_stack.append([])
        self._continue_stack.append(iterable)
        body_exits = self._emit_body(body, [_FlowPoint(target)])
        self._connect(body_exits, iterable, CFGEdgeKind.LOOP_BACK)
        self._continue_stack.pop()
        break_points = self._break_stack.pop()
        return [_FlowPoint(iterable, CFGEdgeKind.FALSE)] + break_points

    def _emit_switch(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        value = node.child_by_field_name("value")
        body = node.child_by_field_name("body")
        value_analysis = (
            self.variables.expression(value) if value is not None else ExpressionAnalysis()
        )
        dispatch = self._add(
            InstructionKind.SWITCH,
            (
                self.parsed.span_for_node(value)
                if value is not None
                else self.parsed.span_for_node(node)
            ),
            self.parsed.text_for_node(value) if value is not None else "",
            definitions=tuple(value_analysis.definitions),
            uses=tuple(value_analysis.uses),
            calls=tuple(value_analysis.calls),
        )
        self._connect(points, dispatch, CFGEdgeKind.NORMAL)

        cases = [
            child
            for child in (body.named_children if body is not None else ())
            if child.type in {"switch_case", "switch_default"}
        ]
        anchors: list[tuple[Node, Instruction, bool]] = []
        for case in cases:
            is_default = case.type == "switch_default"
            test = None if is_default else case.child_by_field_name("value")
            test_analysis = (
                self.variables.expression(test) if test is not None else ExpressionAnalysis()
            )
            span = _header_span(self.parsed, case, None)
            anchor = self._add(
                InstructionKind.CASE,
                span,
                self.parsed.text_for_span(span),
                definitions=tuple(test_analysis.definitions),
                uses=tuple(test_analysis.uses),
                calls=tuple(test_analysis.calls),
            )
            anchors.append((case, anchor, is_default))
            self._connect(
                [dispatch],
                anchor,
                CFGEdgeKind.DEFAULT if is_default else CFGEdgeKind.CASE,
                self.parsed.text_for_node(test).strip() if test is not None else "default",
            )

        self._break_stack.append([])
        terminal_points: list[_FlowPoint] = []
        for index, (case, anchor, _is_default) in enumerate(anchors):
            body_nodes = _case_body_nodes(case)
            case_exits = self._emit_statements(body_nodes, [_FlowPoint(anchor)])
            if index + 1 < len(anchors):
                next_anchor = anchors[index + 1][1]
                self._connect(case_exits, next_anchor, CFGEdgeKind.FALLTHROUGH)
            else:
                terminal_points.extend(case_exits)
        break_points = self._break_stack.pop()
        if not any(is_default for _case, _anchor, is_default in anchors):
            terminal_points.append(_FlowPoint(dispatch, CFGEdgeKind.FALSE, "no_matching_case"))
        return terminal_points + break_points

    def _emit_match(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        subject = node.child_by_field_name("subject")
        body = node.child_by_field_name("body")
        subject_analysis = (
            self.variables.expression(subject) if subject is not None else ExpressionAnalysis()
        )
        dispatch = self._add(
            InstructionKind.MATCH,
            (
                self.parsed.span_for_node(subject)
                if subject is not None
                else self.parsed.span_for_node(node)
            ),
            self.parsed.text_for_node(subject) if subject is not None else "",
            definitions=tuple(subject_analysis.definitions),
            uses=tuple(subject_analysis.uses),
            calls=tuple(subject_analysis.calls),
        )
        self._connect(points, dispatch, CFGEdgeKind.NORMAL)

        cases = [
            child
            for child in (body.named_children if body is not None else ())
            if child.type == "case_clause"
        ]
        exits: list[_FlowPoint] = []
        has_wildcard = False
        for case in cases:
            pattern = next(
                (child for child in case.named_children if child.type == "case_pattern"),
                None,
            )
            guard = case.child_by_field_name("guard")
            consequence = case.child_by_field_name("consequence")
            pattern_text = self.parsed.text_for_node(pattern).strip() if pattern is not None else ""
            has_wildcard = has_wildcard or pattern_text == "_"
            target_analysis = (
                self.variables.case_targets(pattern)
                if pattern is not None
                else ExpressionAnalysis()
            )
            guard_analysis = (
                self.variables.expression(guard) if guard is not None else ExpressionAnalysis()
            )
            target_analysis.merge(guard_analysis)
            span = _header_span(self.parsed, case, consequence)
            anchor = self._add(
                InstructionKind.CASE,
                span,
                self.parsed.text_for_span(span),
                definitions=tuple(target_analysis.definitions),
                uses=tuple(target_analysis.uses),
                calls=tuple(target_analysis.calls),
            )
            self._connect(
                [dispatch],
                anchor,
                CFGEdgeKind.CASE,
                pattern_text or "case",
            )
            exits.extend(self._emit_body(consequence, [_FlowPoint(anchor)]))
        if not has_wildcard:
            exits.append(_FlowPoint(dispatch, CFGEdgeKind.FALSE, "no_matching_case"))
        return exits

    def _emit_try(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        body = node.child_by_field_name("body")
        handlers = [
            child
            for child in node.named_children
            if child.type in {"except_clause", "catch_clause"}
        ]
        alternative = next(
            (child for child in node.named_children if child.type == "else_clause"),
            None,
        )
        finalizer = node.child_by_field_name("finalizer")
        if finalizer is None:
            finalizer = next(
                (child for child in node.named_children if child.type == "finally_clause"),
                None,
            )

        dispatch = self._add(
            InstructionKind.TRY,
            _header_span(self.parsed, node, body),
            self.parsed.text_for_span(_header_span(self.parsed, node, body)),
        )
        self._connect(points, dispatch, CFGEdgeKind.NORMAL)

        anchors: list[tuple[Node, Instruction]] = []
        for handler in handlers:
            analysis = ExpressionAnalysis()
            if handler.type == "except_clause":
                value = handler.child_by_field_name("value")
                if value is not None and value.type == "as_pattern":
                    alias = value.child_by_field_name("alias")
                    if alias is not None:
                        analysis.merge(
                            self.variables.targets(alias, VariableCategory.EXCEPTION_TARGET)
                        )
            else:
                parameter = handler.child_by_field_name("parameter")
                if parameter is not None:
                    analysis.merge(
                        self.variables.targets(parameter, VariableCategory.EXCEPTION_TARGET)
                    )
            handler_body = _clause_body(handler)
            span = _header_span(self.parsed, handler, handler_body)
            anchor = self._add(
                InstructionKind.CASE,
                span,
                self.parsed.text_for_span(span),
                definitions=tuple(analysis.definitions),
                uses=tuple(analysis.uses),
            )
            anchors.append((handler, anchor))

        self._exception_stack.append([anchor for _handler, anchor in anchors])
        body_exits = self._emit_body(body, [_FlowPoint(dispatch)])
        self._exception_stack.pop()

        for handler, anchor in anchors:
            label = "exception"
            if handler.type == "except_clause":
                value = handler.child_by_field_name("value")
                if value is not None:
                    label = self.parsed.text_for_node(value).strip()
            self._connect([dispatch], anchor, CFGEdgeKind.EXCEPTION, label)

        exits: list[_FlowPoint] = []
        if alternative is not None:
            exits.extend(self._emit_body(alternative, body_exits))
        else:
            exits.extend(body_exits)

        for handler, anchor in anchors:
            exits.extend(self._emit_body(_clause_body(handler), [_FlowPoint(anchor)]))

        if finalizer is not None:
            finalizer_body = _clause_body(finalizer)
            exits = self._emit_body(finalizer_body, exits) if finalizer_body else exits
        return exits

    def _emit_with(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        body = node.child_by_field_name("body")
        with_clause = next(
            (child for child in node.named_children if child.type == "with_clause"),
            node,
        )
        items = [child for child in with_clause.named_children if child.type == "with_item"]
        current = points
        for item in items:
            value = item.child_by_field_name("value")
            alias_pattern = next(
                (child for child in item.named_children if child.type == "as_pattern"),
                None,
            )
            analysis = (
                self.variables.expression(value) if value is not None else ExpressionAnalysis()
            )
            if alias_pattern is not None:
                alias = alias_pattern.child_by_field_name("alias")
                if alias is not None:
                    analysis.merge(self.variables.targets(alias, VariableCategory.WITH_TARGET))
            span = self.parsed.span_for_node(item)
            instruction = self._add(
                InstructionKind.WITH,
                span,
                self.parsed.text_for_node(item),
                definitions=tuple(analysis.definitions),
                uses=tuple(analysis.uses),
                calls=tuple(analysis.calls),
            )
            self._connect(current, instruction, CFGEdgeKind.NORMAL)
            current = [_FlowPoint(instruction)]
        return self._emit_body(body, current)

    def _emit_assert(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        condition = node.named_children[0] if node.named_children else None
        condition_instruction = self._condition(node, condition)
        self._connect(points, condition_instruction, CFGEdgeKind.NORMAL)
        failure = self._add(
            InstructionKind.RAISE,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            synthetic=True,
        )
        self._connect(
            [_FlowPoint(condition_instruction, CFGEdgeKind.FALSE)],
            failure,
            CFGEdgeKind.NORMAL,
        )
        self._connect([failure], self.exit, CFGEdgeKind.RAISE)
        return [_FlowPoint(condition_instruction, CFGEdgeKind.TRUE)]

    def _emit_return(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        value = next(
            (child for child in node.named_children if child.type not in {"comment"}),
            None,
        )
        analysis = self.variables.expression(value) if value is not None else ExpressionAnalysis()
        instruction = self._add(
            InstructionKind.RETURN,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            definitions=tuple(analysis.definitions),
            uses=tuple(analysis.uses),
            calls=tuple(analysis.calls),
        )
        self._connect(points, instruction, CFGEdgeKind.NORMAL)
        self._connect([instruction], self.exit, CFGEdgeKind.RETURN)
        return []

    def _emit_implicit_return(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        analysis = self.variables.expression(node)
        instruction = self._add(
            InstructionKind.RETURN,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            definitions=tuple(analysis.definitions),
            uses=tuple(analysis.uses),
            calls=tuple(analysis.calls),
            synthetic=True,
        )
        self._connect(points, instruction, CFGEdgeKind.NORMAL)
        self._connect([instruction], self.exit, CFGEdgeKind.RETURN)
        return []

    def _emit_raise(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        value = next((child for child in node.named_children if child.type != "comment"), None)
        analysis = self.variables.expression(value) if value is not None else ExpressionAnalysis()
        instruction = self._add(
            InstructionKind.RAISE,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            definitions=tuple(analysis.definitions),
            uses=tuple(analysis.uses),
            calls=tuple(analysis.calls),
        )
        self._connect(points, instruction, CFGEdgeKind.NORMAL)
        if self._exception_stack and self._exception_stack[-1]:
            target = self._exception_stack[-1][0]
            self._connect([instruction], target, CFGEdgeKind.EXCEPTION)
        else:
            self._connect([instruction], self.exit, CFGEdgeKind.RAISE)
        return []

    def _emit_break(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        instruction = self._add(
            InstructionKind.BREAK,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
        )
        self._connect(points, instruction, CFGEdgeKind.NORMAL)
        if self._break_stack:
            self._break_stack[-1].append(_FlowPoint(instruction, CFGEdgeKind.BREAK))
        else:
            self._connect([instruction], self.exit, CFGEdgeKind.BREAK)
        return []

    def _emit_continue(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        instruction = self._add(
            InstructionKind.CONTINUE,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
        )
        self._connect(points, instruction, CFGEdgeKind.NORMAL)
        if self._continue_stack:
            self._connect([instruction], self._continue_stack[-1], CFGEdgeKind.CONTINUE)
        else:
            self._connect([instruction], self.exit, CFGEdgeKind.CONTINUE)
        return []

    # ------------------------------------------------------------- statements

    def _emit_declaration(
        self,
        node: Node,
        points: list[_FlowPoint],
        *,
        outer: Node | None = None,
    ) -> list[_FlowPoint]:
        is_class = node.type in _PYTHON_CLASS_TYPES | _JAVASCRIPT_CLASS_TYPES
        kind = InstructionKind.CLASS if is_class else InstructionKind.FUNCTION
        category = VariableCategory.CLASS_NAME if is_class else VariableCategory.FUNCTION_NAME
        name_node = node.child_by_field_name("name")
        if name_node is None:
            name_node = _inferred_declaration_name(node)
        definitions: list[VariableOccurrence] = []
        if name_node is not None:
            name = self.parsed.text_for_node(name_node).strip()
            if name:
                definitions.append(self.variables.definition(name_node, category, name=name))

        analysis = ExpressionAnalysis()
        for decorator_owner in (outer, node):
            if decorator_owner is None:
                continue
            for decorator in decorator_owner.named_children:
                if decorator.type == "decorator":
                    analysis.merge(self.variables.expression(decorator))
        for field_name in ("superclasses", "superclass", "bases", "interfaces"):
            value = node.child_by_field_name(field_name)
            if value is not None:
                analysis.merge(self.variables.expression(value))
        for child in node.named_children:
            if child.type in {"class_heritage", "extends_clause"}:
                analysis.merge(self.variables.expression(child))

        body = node.child_by_field_name("body")
        span = _header_span(self.parsed, outer or node, body)
        return self._emit_analysis(
            outer or node,
            points,
            kind,
            ExpressionAnalysis(
                definitions=definitions,
                uses=analysis.uses,
                calls=analysis.calls,
            ),
            span=span,
        )

    def _emit_import(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        analysis = self.variables.import_definitions(node)
        return self._emit_analysis(node, points, InstructionKind.IMPORT, analysis)

    def _emit_delete(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        target = next((child for child in node.named_children if child.type != "comment"), None)
        analysis = (
            self.variables.targets(target, VariableCategory.DELETE)
            if target is not None
            else ExpressionAnalysis()
        )
        return self._emit_analysis(node, points, InstructionKind.DELETE, analysis)

    def _emit_export(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        declaration = node.child_by_field_name("declaration")
        if declaration is not None:
            return self._emit_statement(declaration, points)
        current = points
        for child in node.named_children:
            if child.type in {"string", "comment", "export_clause"}:
                continue
            current = self._emit_statement(child, current)
        return current

    def _emit_expression_statement(self, node: Node, points: list[_FlowPoint]) -> list[_FlowPoint]:
        expression = next(
            (child for child in node.named_children if child.type != "comment"),
            None,
        )
        if expression is None:
            return self._emit_simple(node, points, InstructionKind.PASS)
        if expression.type == "assignment":
            return self._emit_analysis(
                node, points, InstructionKind.ASSIGNMENT, self.variables.assignment(expression)
            )
        if expression.type == "augmented_assignment":
            return self._emit_analysis(
                node,
                points,
                InstructionKind.AUGMENTED_ASSIGNMENT,
                self.variables.assignment(expression, augmented=True),
            )
        if expression.type == "named_expression":
            return self._emit_analysis(
                node, points, InstructionKind.ASSIGNMENT, self.variables.expression(expression)
            )
        if expression.type in _JAVASCRIPT_ASSIGNMENT_STATEMENTS:
            if expression.type == "augmented_assignment_expression":
                analysis = self.variables.assignment(expression, augmented=True)
            else:
                analysis = self.variables.expression(expression)
            kind = (
                InstructionKind.AUGMENTED_ASSIGNMENT
                if expression.type in {"augmented_assignment_expression", "update_expression"}
                else InstructionKind.ASSIGNMENT
            )
            return self._emit_analysis(node, points, kind, analysis)
        return self._emit_analysis(
            node, points, InstructionKind.STATEMENT, self.variables.expression(expression)
        )

    # --------------------------------------------------------------- helpers

    def _condition(self, statement: Node, condition: Node | None) -> Instruction:
        analysis = (
            self.variables.expression(condition) if condition is not None else ExpressionAnalysis()
        )
        span = (
            self.parsed.span_for_node(condition)
            if condition is not None
            else _header_span(self.parsed, statement, None)
        )
        return self._add(
            InstructionKind.CONDITION,
            span,
            self.parsed.text_for_span(span),
            definitions=tuple(analysis.definitions),
            uses=tuple(analysis.uses),
            calls=tuple(analysis.calls),
        )

    def _emit_analysis(
        self,
        node: Node,
        points: list[_FlowPoint],
        kind: InstructionKind,
        analysis: ExpressionAnalysis,
        *,
        span: SourceSpan | None = None,
    ) -> list[_FlowPoint]:
        instruction_span = span or self.parsed.span_for_node(node)
        instruction = self._add(
            kind,
            instruction_span,
            self.parsed.text_for_span(instruction_span),
            definitions=tuple(analysis.definitions),
            uses=tuple(analysis.uses),
            calls=tuple(analysis.calls),
        )
        self._connect(points, instruction, CFGEdgeKind.NORMAL)
        return [_FlowPoint(instruction)]

    def _emit_simple(
        self, node: Node, points: list[_FlowPoint], kind: InstructionKind
    ) -> list[_FlowPoint]:
        analysis = self.variables.expression(node)
        return self._emit_analysis(node, points, kind, analysis)

    def _create(
        self,
        kind: InstructionKind,
        span: SourceSpan,
        text: str,
        *,
        definitions: tuple[VariableOccurrence, ...] = (),
        uses: tuple[VariableOccurrence, ...] = (),
        calls: tuple[CallSite, ...] = (),
        synthetic: bool = False,
    ) -> Instruction:
        instruction_id = f"{self.scope_id}:i{self._counter}"
        self._counter += 1
        return Instruction(
            instruction_id=instruction_id,
            kind=kind,
            span=span,
            text=text,
            definitions=definitions,
            uses=uses,
            calls=calls,
            synthetic=synthetic,
        )

    def _register(self, instruction: Instruction) -> Instruction:
        self.nodes.append(instruction)
        self._by_id[instruction.instruction_id] = instruction
        self._order[instruction.instruction_id] = len(self.nodes) - 1
        return instruction

    def _add(
        self,
        kind: InstructionKind,
        span: SourceSpan,
        text: str,
        *,
        definitions: tuple[VariableOccurrence, ...] = (),
        uses: tuple[VariableOccurrence, ...] = (),
        calls: tuple[CallSite, ...] = (),
        synthetic: bool = False,
    ) -> Instruction:
        return self._register(
            self._create(
                kind,
                span,
                text,
                definitions=definitions,
                uses=uses,
                calls=calls,
                synthetic=synthetic,
            )
        )

    def _connect(
        self,
        points: Iterable[_FlowPoint | Instruction],
        target: Instruction,
        default_kind: CFGEdgeKind,
        label: str | None = None,
    ) -> None:
        for point in points:
            if isinstance(point, Instruction):
                self._edges.append((point, target, default_kind, label))
                continue
            kind = point.edge_kind or default_kind
            edge_label = point.label if point.label is not None else label
            self._edges.append((point.node, target, kind, edge_label))

    # ----------------------------------------------------------- block graph

    def _finish(self) -> ControlFlowGraph:
        outgoing: dict[str, list[tuple[str, CFGEdgeKind]]] = {
            node.instruction_id: [] for node in self.nodes
        }
        incoming: dict[str, list[str]] = {node.instruction_id: [] for node in self.nodes}
        for source, target, kind, _label in self._edges:
            outgoing[source.instruction_id].append((target.instruction_id, kind))
            incoming[target.instruction_id].append(source.instruction_id)

        leaders: set[str] = {self.entry.instruction_id, self.exit.instruction_id}
        leaders.update(self._forced_leaders)
        for source, target, kind, _label in self._edges:
            if kind is not CFGEdgeKind.NORMAL:
                leaders.add(target.instruction_id)
            if len(outgoing[source.instruction_id]) != 1:
                leaders.add(target.instruction_id)
            if len(incoming[target.instruction_id]) != 1:
                leaders.add(target.instruction_id)
        for node in self.nodes:
            if (
                node.instruction_id != self.entry.instruction_id
                and not incoming[node.instruction_id]
            ):
                leaders.add(node.instruction_id)

        leader_nodes = sorted(
            (self._by_id[node_id] for node_id in leaders),
            key=lambda node: (node.span.start.byte_offset, self._order[node.instruction_id]),
        )

        groups: list[list[Instruction]] = []
        assigned: set[str] = set()
        for leader in leader_nodes:
            if leader.instruction_id in assigned:
                continue
            group = [leader]
            assigned.add(leader.instruction_id)
            current = leader
            while True:
                next_edges = outgoing[current.instruction_id]
                if len(next_edges) != 1:
                    break
                target_id, kind = next_edges[0]
                if kind is not CFGEdgeKind.NORMAL or target_id in leaders:
                    break
                if target_id in assigned:
                    break
                target = self._by_id[target_id]
                group.append(target)
                assigned.add(target_id)
                current = target
            groups.append(group)

        # Any instruction not reached by a leader is still represented rather
        # than silently dropped.
        for node in self.nodes:
            if node.instruction_id not in assigned:
                groups.append([node])
                assigned.add(node.instruction_id)

        groups.sort(
            key=lambda group: (
                group[0].span.start.byte_offset,
                self._order[group[0].instruction_id],
            )
        )

        block_of: dict[str, str] = {}
        blocks: list[BasicBlock] = []
        for index, group in enumerate(groups):
            block_id = f"{self.scope_id}:bb{index}"
            for node in group:
                block_of[node.instruction_id] = block_id
            real = [node for node in group if not node.synthetic]
            if real:
                span = _combined_span([node.span for node in real])
                text = self.parsed.text_for_span(span)
            else:
                start = min(node.span.start for node in group)
                end = max(node.span.end for node in group)
                span = SourceSpan(start, end)
                text = self.parsed.text_for_span(span) if span.byte_length else ""
            if self.entry.instruction_id in {node.instruction_id for node in group}:
                kind = CFGNodeKind.ENTRY
                label = "entry"
            elif self.exit.instruction_id in {node.instruction_id for node in group}:
                kind = CFGNodeKind.EXIT
                label = "exit"
            else:
                kind = CFGNodeKind.BASIC
                label = f"block-{index}"
            blocks.append(
                BasicBlock(
                    block_id=block_id,
                    kind=kind,
                    scope_id=self.scope_id,
                    span=span,
                    text=text,
                    statements=tuple(real),
                    label=label,
                )
            )

        graph = nx.DiGraph()
        for block in blocks:
            graph.add_node(
                block.block_id,
                kind=block.kind.value,
                label=block.label,
                scope_id=block.scope_id,
                span=block.span,
                span_dict=span_to_dict(block.span),
                text=block.text,
                block=block,
            )

        logical_edges: list[CFGEdge] = []
        aggregate: dict[tuple[str, str], list[tuple[CFGEdgeKind, str | None, Instruction]]] = {}
        for source, target, kind, label in self._edges:
            source_block = block_of.get(source.instruction_id)
            target_block = block_of.get(target.instruction_id)
            if source_block is None or target_block is None:
                continue
            if source_block == target_block and kind is CFGEdgeKind.NORMAL:
                continue
            logical_edges.append(
                CFGEdge(
                    source=source_block,
                    target=target_block,
                    kind=kind,
                    label=label,
                    span=source.span,
                    source_instruction_id=source.instruction_id,
                    target_instruction_id=target.instruction_id,
                )
            )
            aggregate.setdefault((source_block, target_block), []).append((kind, label, source))

        for (source_block, target_block), details in aggregate.items():
            kinds = tuple(dict.fromkeys(kind.value for kind, _label, _node in details))
            labels = tuple(
                dict.fromkeys(label for _kind, label, _node in details if label is not None)
            )
            graph.add_edge(
                source_block,
                target_block,
                kind=details[0][0].value,
                label=labels[0] if labels else None,
                kinds=kinds,
                labels=labels,
                count=len(details),
                span=details[0][2].span,
                span_dict=span_to_dict(details[0][2].span),
            )

        return ControlFlowGraph(
            parsed=self.parsed,
            scope_id=self.scope_id,
            scope_name=self.scope_name,
            function=self.function,
            graph=graph,
            entry_id=block_of[self.entry.instruction_id],
            exit_id=block_of[self.exit.instruction_id],
            blocks=tuple(blocks),
            edges=tuple(logical_edges),
        )


def build_cfg(
    source: ParsedSource | str,
    *,
    path: str | Path | None = None,
    language: SupportedLanguage | str | None = None,
    language_id: str | None = None,
) -> ControlFlowAnalysis:
    """Build module and function-level CFGs for Python or JavaScript source."""
    parsed = _ensure_parsed(
        source,
        path=path,
        language=language,
        language_id=language_id,
    )
    module = _build_module(parsed)
    function_graphs, scopes = _build_function_graphs(parsed)
    return ControlFlowAnalysis(
        parsed=parsed,
        module=module,
        functions=function_graphs,
        scopes=scopes,
    )


def build_module_cfg(parsed: ParsedSource | str, **kwargs: object) -> ControlFlowGraph:
    """Build only the module-level CFG."""
    return build_cfg(parsed, **kwargs).module


def build_function_cfg(
    parsed: ParsedSource | str,
    name: str,
    **kwargs: object,
) -> ControlFlowGraph:
    """Build only the CFG for a named function or method."""
    return build_cfg(parsed, **kwargs).function_graph(name)


def _build_module(parsed: ParsedSource) -> ControlFlowGraph:
    builder = _CFGBuilder(
        parsed,
        scope_id="module",
        scope_name="<module>",
        function=None,
        function_node=None,
        body_node=parsed.root_node,
    )
    return builder.build()


def _build_function_graphs(
    parsed: ParsedSource,
) -> tuple[tuple[ControlFlowGraph, ...], tuple[FunctionScopeInfo, ...]]:
    symbols = extract_functions(parsed)
    nodes = _collect_function_nodes(parsed)
    targets: list[tuple[FunctionSymbol, Node, int]] = []
    for index, (symbol, node) in enumerate(zip(symbols, nodes, strict=False)):
        targets.append((symbol, node, index))

    # Determine lexical parents from source-span containment. This is a purely
    # syntactic approximation; closures and dynamic rebinding are not resolved.
    parents: dict[int, int | None] = {}
    for index, (symbol, _node, _order) in enumerate(targets):
        best: int | None = None
        best_span = None
        for other_index, (other_symbol, _other_node, _other_order) in enumerate(targets):
            if other_index == index:
                continue
            container = other_symbol.span
            child = symbol.span
            if (
                container.start.byte_offset <= child.start.byte_offset
                and container.end.byte_offset >= child.end.byte_offset
                and (container.start.byte_offset, container.end.byte_offset)
                != (child.start.byte_offset, child.end.byte_offset)
            ):
                if best_span is None or (
                    container.end.byte_offset - container.start.byte_offset
                    < best_span.end.byte_offset - best_span.start.byte_offset
                ):
                    best = other_index
                    best_span = container
        parents[index] = best

    scope_ids = [f"fn{index}" for index in range(len(targets))]
    scopes: list[FunctionScopeInfo] = []
    for index, (symbol, _node, _order) in enumerate(targets):
        parent_index = parents[index]
        scopes.append(
            FunctionScopeInfo(
                scope_id=scope_ids[index],
                scope_name=symbol.qualified_name
                or symbol.name
                or f"<anonymous:{symbol.span.start.line + 1}>",
                symbol=symbol,
                parent_scope_id=scope_ids[parent_index] if parent_index is not None else "module",
            )
        )

    graphs: list[ControlFlowGraph] = []
    for index, (symbol, node, _order) in enumerate(targets):
        body = node.child_by_field_name("body")
        if body is None:
            for child in node.named_children:
                if child.type in {"block", "statement_block"}:
                    body = child
                    break
        if body is None:
            # A lambda/arrow can have an expression body, but a malformed tree
            # may not expose it. Fall back to the function node itself.
            body = node
        builder = _CFGBuilder(
            parsed,
            scope_id=scope_ids[index],
            scope_name=scopes[index].scope_name,
            function=symbol,
            function_node=node,
            body_node=body,
        )
        graphs.append(builder.build())
    return tuple(graphs), tuple(scopes)


def _collect_function_nodes(parsed: ParsedSource) -> list[Node]:
    function_types = _FUNCTION_NODE_TYPES[parsed.language]
    found: list[Node] = []
    stack = [parsed.root_node]
    while stack:
        node = stack.pop()
        if node.type in function_types:
            found.append(node)
        stack.extend(reversed(node.children))
    return found


def _javascript_for_condition(node: Node) -> Node | None:
    for index, child in enumerate(node.children):
        field_name = node.field_name_for_child(index)
        if field_name == "condition" and child.type != ";":
            return child
    return None


def _clause_body(node: Node) -> Node | None:
    body = node.child_by_field_name("body")
    if body is not None:
        return body
    for child in reversed(node.named_children):
        if child.type in _BLOCK_TYPES or child.type.endswith("_statement"):
            return child
    return None


def _case_body_nodes(node: Node) -> list[Node]:
    bodies = [
        child
        for index, child in enumerate(node.children)
        if node.field_name_for_child(index) == "body" and child.type not in _COMMENT_AND_EXTRA_TYPES
    ]
    if bodies:
        return bodies
    named = [child for child in node.named_children if child.type != "comment"]
    return named[1:] if node.type == "switch_case" else named[1:]


def _header_span(parsed: ParsedSource, node: Node, body: Node | None) -> SourceSpan:
    if body is not None and body.start_byte >= node.start_byte:
        end = max(node.start_byte, body.start_byte)
        return parsed.span_from_normalized_bytes(node.start_byte, end)
    return parsed.span_for_node(node)


def _combined_span(spans: list[SourceSpan]) -> SourceSpan:
    if not spans:
        raise ValueError("at least one span is required")
    first = min(spans, key=lambda span: span.start.byte_offset)
    last = max(spans, key=lambda span: span.end.byte_offset)
    return SourceSpan(first.start, last.end)


def _inferred_declaration_name(node: Node) -> Node | None:
    name = node.child_by_field_name("name")
    if name is not None:
        return name
    ancestor = node.parent
    while ancestor is not None:
        if ancestor.type == "variable_declarator":
            return ancestor.child_by_field_name("name")
        if ancestor.type in {
            "program",
            "statement_block",
            "export_statement",
        }:
            break
        ancestor = ancestor.parent
    return None


def _ensure_parsed(
    source: ParsedSource | str,
    *,
    path: str | Path | None,
    language: SupportedLanguage | str | None,
    language_id: str | None,
) -> ParsedSource:
    if isinstance(source, ParsedSource):
        return source
    return parse_source(
        source,
        path=path,
        language=language,
        language_id=language_id,
    )


# Backwards-friendly aliases for callers that prefer descriptive names.
build_control_flow_graph = build_cfg
analyze_control_flow = build_cfg


def _parameters_node_for_cfg(function_node: Node, language: SupportedLanguage) -> Node | None:
    """Exposed for tests and future helpers without duplicating grammar logic."""
    return _parameters_node(function_node, language)
