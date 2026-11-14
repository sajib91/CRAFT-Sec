"""Shared models for control-flow and data-flow analysis.

The graph builders in this package keep source spans on every instruction,
basic block, graph node, and edge. Spans use the same coordinate systems as
:mod:`craftsec.parsing`: absolute UTF-8 byte offsets, Python character offsets,
zero-based lines, UTF-8 byte columns, and UTF-16 columns for editors/LSP.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from craftsec.parsing.models import FunctionKind, FunctionSymbol, SourceSpan


class CFGNodeKind(StrEnum):
    """The role of a node in a control-flow graph."""

    ENTRY = "entry"
    BASIC = "basic"
    EXIT = "exit"


class CFGEdgeKind(StrEnum):
    """Why control can move from one basic block to another."""

    NORMAL = "normal"
    TRUE = "true"
    FALSE = "false"
    LOOP_BACK = "loop_back"
    BREAK = "break"
    CONTINUE = "continue"
    RETURN = "return"
    RAISE = "raise"
    EXCEPTION = "exception"
    CASE = "case"
    DEFAULT = "default"
    FALLTHROUGH = "fallthrough"


class InstructionKind(StrEnum):
    """The syntactic category of one CFG instruction."""

    STATEMENT = "statement"
    ASSIGNMENT = "assignment"
    AUGMENTED_ASSIGNMENT = "augmented_assignment"
    DECLARATION = "declaration"
    PARAMETER = "parameter"
    CONDITION = "condition"
    LOOP = "loop"
    LOOP_TARGET = "loop_target"
    LOOP_UPDATE = "loop_update"
    SWITCH = "switch"
    CASE = "case"
    TRY = "try"
    WITH = "with"
    RETURN = "return"
    RAISE = "raise"
    BREAK = "break"
    CONTINUE = "continue"
    IMPORT = "import"
    FUNCTION = "function"
    CLASS = "class"
    PASS = "pass"
    DELETE = "delete"
    MATCH = "match"


class VariableRole(StrEnum):
    """Whether an occurrence defines or reads a name."""

    DEFINITION = "definition"
    USE = "use"


class VariableCategory(StrEnum):
    """The syntactic reason a variable occurrence was recorded."""

    USE = "use"
    ASSIGNMENT = "assignment"
    AUGMENTED_ASSIGNMENT = "augmented_assignment"
    PARAMETER = "parameter"
    LOOP_TARGET = "loop_target"
    IMPORT = "import"
    WITH_TARGET = "with_target"
    EXCEPTION_TARGET = "exception_target"
    FUNCTION_NAME = "function_name"
    CLASS_NAME = "class_name"
    UPDATE = "update"
    DELETE = "delete"
    CALLEE = "callee"
    CALL_ARGUMENT = "call_argument"
    COMPREHENSION = "comprehension"
    CASE_TARGET = "case_target"


class DFGNodeKind(StrEnum):
    """The role of a node in a data-flow graph."""

    MODULE_ENTRY = "module_entry"
    FUNCTION_ENTRY = "function_entry"
    MODULE_EXIT = "module_exit"
    FUNCTION_EXIT = "function_exit"
    PARAMETER = "parameter"
    DEFINITION = "definition"
    USE = "use"
    CALL = "call"
    RETURN = "return"
    RAISE = "raise"


class DFGEdgeKind(StrEnum):
    """The relationship represented by a data-flow edge."""

    DEF_USE = "def_use"
    CLOSURE = "closure"
    PARAMETER_BINDING = "parameter_binding"
    CALLEE = "callee"
    ARGUMENT = "argument"
    CALL_RESULT = "call_result"
    RETURN_VALUE = "return_value"
    RETURNS_TO = "returns_to"
    RAISE_VALUE = "raise_value"
    RAISES_TO = "raises_to"


@dataclass(frozen=True, slots=True)
class VariableOccurrence:
    """One definition or use of a variable name."""

    name: str
    span: SourceSpan
    text: str
    role: VariableRole
    category: VariableCategory

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "role": self.role.value,
            "category": self.category.value,
            "span": span_to_dict(self.span),
            "text": self.text,
        }


@dataclass(frozen=True, slots=True)
class CallSite:
    """A call expression found inside one instruction.

    Calls are recorded syntactically. Resolving a callee to a function body is
    outside the scope of the intraprocedural analysis.
    """

    call_id: str
    callee: str | None
    span: SourceSpan
    callee_span: SourceSpan | None
    argument_spans: tuple[SourceSpan, ...]
    is_method: bool
    is_constructor: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "call_id": self.call_id,
            "callee": self.callee,
            "span": span_to_dict(self.span),
            "callee_span": span_to_dict(self.callee_span) if self.callee_span else None,
            "argument_spans": [span_to_dict(span) for span in self.argument_spans],
            "is_method": self.is_method,
            "is_constructor": self.is_constructor,
        }


@dataclass(frozen=True, slots=True)
class Instruction:
    """One CFG instruction with its variable occurrences and call sites."""

    instruction_id: str
    kind: InstructionKind
    span: SourceSpan
    text: str
    definitions: tuple[VariableOccurrence, ...] = ()
    uses: tuple[VariableOccurrence, ...] = ()
    calls: tuple[CallSite, ...] = ()
    synthetic: bool = False

    @property
    def is_terminator(self) -> bool:
        return self.kind in {
            InstructionKind.RETURN,
            InstructionKind.RAISE,
            InstructionKind.BREAK,
            InstructionKind.CONTINUE,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "instruction_id": self.instruction_id,
            "kind": self.kind.value,
            "span": span_to_dict(self.span),
            "text": self.text,
            "definitions": [item.to_dict() for item in self.definitions],
            "uses": [item.to_dict() for item in self.uses],
            "calls": [call.to_dict() for call in self.calls],
            "synthetic": self.synthetic,
        }


@dataclass(frozen=True, slots=True)
class BasicBlock:
    """A maximal straight-line sequence of CFG instructions."""

    block_id: str
    kind: CFGNodeKind
    scope_id: str
    span: SourceSpan
    text: str
    statements: tuple[Instruction, ...] = ()
    label: str = ""

    @property
    def terminator(self) -> Instruction | None:
        if self.statements and self.statements[-1].is_terminator:
            return self.statements[-1]
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "block_id": self.block_id,
            "kind": self.kind.value,
            "scope_id": self.scope_id,
            "span": span_to_dict(self.span),
            "text": self.text,
            "label": self.label,
            "statements": [statement.to_dict() for statement in self.statements],
        }


@dataclass(frozen=True, slots=True)
class CFGEdge:
    """One logical control-flow edge between two basic blocks."""

    source: str
    target: str
    kind: CFGEdgeKind
    label: str | None
    span: SourceSpan
    source_instruction_id: str
    target_instruction_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "label": self.label,
            "span": span_to_dict(self.span),
            "source_instruction_id": self.source_instruction_id,
            "target_instruction_id": self.target_instruction_id,
        }


@dataclass(frozen=True, slots=True)
class DFGNode:
    """One data-flow graph node.

    ``name`` is the variable name for parameter, definition, and use nodes, the
    callee text for call nodes, and ``None`` for entry, exit, and literal return
    nodes.
    """

    node_id: str
    kind: DFGNodeKind
    span: SourceSpan
    text: str
    scope_id: str
    block_id: str | None = None
    instruction_id: str | None = None
    name: str | None = None
    category: VariableCategory | None = None
    role: VariableRole | None = None
    call_id: str | None = None
    resolved: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "span": span_to_dict(self.span),
            "text": self.text,
            "scope_id": self.scope_id,
            "block_id": self.block_id,
            "instruction_id": self.instruction_id,
            "name": self.name,
            "category": self.category.value if self.category else None,
            "role": self.role.value if self.role else None,
            "call_id": self.call_id,
            "resolved": self.resolved,
        }


@dataclass(frozen=True, slots=True)
class DFGEdge:
    """One data-flow relationship between two DFG nodes."""

    source: str
    target: str
    kind: DFGEdgeKind
    variable: str | None
    span: SourceSpan

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "variable": self.variable,
            "span": span_to_dict(self.span),
        }


@dataclass(frozen=True, slots=True)
class FunctionScopeInfo:
    """Metadata for one function-level CFG/DFG."""

    scope_id: str
    scope_name: str
    symbol: FunctionSymbol
    parent_scope_id: str | None = None

    @property
    def qualified_name(self) -> str | None:
        return self.symbol.qualified_name

    @property
    def kind(self) -> FunctionKind:
        return self.symbol.kind

    def to_dict(self) -> dict[str, object]:
        return {
            "scope_id": self.scope_id,
            "scope_name": self.scope_name,
            "qualified_name": self.qualified_name,
            "kind": self.kind.value,
            "parent_scope_id": self.parent_scope_id,
            "span": span_to_dict(self.symbol.span),
            "parameters": list(self.symbol.parameter_names),
        }


def span_to_dict(span: SourceSpan) -> dict[str, object]:
    """Serialize a source span without losing either coordinate system."""
    return {
        "start": {
            "byte_offset": span.start.byte_offset,
            "char_offset": span.start.char_offset,
            "line": span.start.line,
            "column": span.start.column,
            "character": span.start.character,
        },
        "end": {
            "byte_offset": span.end.byte_offset,
            "char_offset": span.end.char_offset,
            "line": span.end.line,
            "column": span.end.column,
            "character": span.end.character,
        },
        "lsp": span.as_lsp_range(),
    }
