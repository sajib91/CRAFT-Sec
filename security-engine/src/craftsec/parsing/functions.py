"""Function and method extraction for Python and JavaScript."""

from __future__ import annotations

from tree_sitter import Node

from craftsec.parsing.models import FunctionKind, FunctionSymbol, SourceSpan, SupportedLanguage
from craftsec.parsing.parser import ParsedSource

ScopeEntry = tuple[str, str]

_PYTHON_FUNCTION_TYPES = frozenset({"function_definition", "lambda"})
_JAVASCRIPT_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_PYTHON_CLASS_TYPES = frozenset({"class_definition"})
_JAVASCRIPT_CLASS_TYPES = frozenset({"class", "class_declaration"})
_PARAMETER_SEPARATORS = frozenset({"keyword_separator", "positional_separator", "comment"})
_JS_STOP_TYPES = _JAVASCRIPT_FUNCTION_TYPES | _JAVASCRIPT_CLASS_TYPES
_PY_STOP_TYPES = _PYTHON_FUNCTION_TYPES | _PYTHON_CLASS_TYPES


def extract_functions(parsed: ParsedSource) -> tuple[FunctionSymbol, ...]:
    """Extract function-like symbols in source order.

    Syntax errors do not hide recovered functions. Anonymous arrow functions,
    function expressions, and lambdas are included with ``name=None`` unless a
    surrounding assignment or property provides a stable name.
    """
    functions: list[FunctionSymbol] = []
    stack: list[tuple[Node, tuple[ScopeEntry, ...], Node | None]] = [(parsed.root_node, (), None)]

    while stack:
        node, scope, parent = stack.pop()

        if node.is_named and _is_class_node(node, parsed.language):
            name, _ = _class_name(parsed, node)
            next_scope = scope + (("class", name),) if name else scope
            _push_children(stack, node, next_scope, node)
            continue

        kind = _function_kind(node, parsed.language, scope)
        if kind is not None:
            symbol = _build_symbol(parsed, node, scope, parent, kind)
            if symbol is not None:
                functions.append(symbol)
                if symbol.name:
                    next_scope = scope + (("function", symbol.name),)
                else:
                    next_scope = scope
            else:
                next_scope = scope
            _push_children(stack, node, next_scope, node)
            continue

        _push_children(stack, node, scope, node)

    return tuple(functions)


def _push_children(
    stack: list[tuple[Node, tuple[ScopeEntry, ...], Node | None]],
    node: Node,
    scope: tuple[ScopeEntry, ...],
    parent: Node,
) -> None:
    for child in reversed(node.children):
        stack.append((child, scope, parent))


def _is_class_node(node: Node, language: SupportedLanguage) -> bool:
    types = _PYTHON_CLASS_TYPES if language is SupportedLanguage.PYTHON else _JAVASCRIPT_CLASS_TYPES
    return node.type in types


def _function_kind(
    node: Node,
    language: SupportedLanguage,
    scope: tuple[ScopeEntry, ...],
) -> FunctionKind | None:
    if not node.is_named:
        return None
    if language is SupportedLanguage.PYTHON:
        if node.type == "lambda":
            return FunctionKind.LAMBDA
        if node.type == "function_definition":
            if scope and scope[-1][0] == "class":
                return FunctionKind.METHOD
            return FunctionKind.FUNCTION
        return None

    if node.type == "method_definition":
        return FunctionKind.METHOD
    if node.type == "arrow_function":
        return FunctionKind.ARROW
    if node.type in _JAVASCRIPT_FUNCTION_TYPES:
        return FunctionKind.FUNCTION
    return None


def _build_symbol(
    parsed: ParsedSource,
    node: Node,
    scope: tuple[ScopeEntry, ...],
    parent: Node | None,
    kind: FunctionKind,
) -> FunctionSymbol | None:
    name, name_span = _symbol_name(parsed, node, parent, kind)
    span_node = parent if parent is not None and parent.type == "decorated_definition" else node
    parameters, parameter_names = _parameters(parsed, node)
    container_name = _container_name(parsed, node, scope, kind)
    qualified_parts = [entry_name for entry_kind, entry_name in scope if entry_name]
    if name and (not qualified_parts or qualified_parts[-1] != name):
        qualified_parts.append(name)
    qualified_name = ".".join(qualified_parts) if qualified_parts else None

    return FunctionSymbol(
        name=name,
        qualified_name=qualified_name,
        kind=kind,
        span=parsed.span_for_node(span_node),
        name_span=name_span,
        parameters=parameters,
        parameter_names=parameter_names,
        is_async=_is_async(node),
        is_generator=_is_generator(parsed, node),
        is_method=kind is FunctionKind.METHOD,
        container_name=container_name,
    )


def _symbol_name(
    parsed: ParsedSource,
    node: Node,
    parent: Node | None,
    kind: FunctionKind,
) -> tuple[str | None, SourceSpan | None]:
    if kind is FunctionKind.LAMBDA:
        name_node = _lambda_assignment_name(node, parent)
        if name_node is None:
            return None, None
        return parsed.text_for_node(name_node), parsed.span_for_node(name_node)

    name_node = node.child_by_field_name("name")
    if name_node is None:
        name_node = _inferred_javascript_name(node)
    if name_node is None:
        return None, None
    text = parsed.text_for_node(name_node).strip()
    if not text:
        return None, None
    return text, parsed.span_for_node(name_node)


def _lambda_assignment_name(node: Node, parent: Node | None) -> Node | None:
    if parent is None:
        return None
    if parent.type == "assignment":
        right = parent.child_by_field_name("right")
        left = parent.child_by_field_name("left")
        if right is not None and left is not None and _same_node(right, node):
            return left
    return None


def _inferred_javascript_name(node: Node) -> Node | None:
    ancestor = node.parent
    while ancestor is not None:
        if ancestor.type == "variable_declarator":
            return ancestor.child_by_field_name("name")
        if ancestor.type == "pair":
            return ancestor.child_by_field_name("key")
        if ancestor.type == "assignment_expression":
            return ancestor.child_by_field_name("left")
        if ancestor.type in {
            "statement_block",
            "class_body",
            "program",
            "export_statement",
            "return_statement",
        }:
            break
        ancestor = ancestor.parent
    return None


def _class_name(parsed: ParsedSource, node: Node) -> tuple[str | None, Node | None]:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        name_node = _inferred_javascript_name(node)
    if name_node is None:
        return None, None
    text = parsed.text_for_node(name_node).strip()
    if not text:
        return None, None
    return text, name_node


def _container_name(
    parsed: ParsedSource,
    node: Node,
    scope: tuple[ScopeEntry, ...],
    kind: FunctionKind,
) -> str | None:
    if kind is not FunctionKind.METHOD:
        return None
    for entry_kind, entry_name in reversed(scope):
        if entry_kind == "class":
            return entry_name
    if parsed.language is SupportedLanguage.JAVASCRIPT:
        container = _inferred_javascript_name(node)
        if container is not None:
            return parsed.text_for_node(container).strip() or None
    return None


def _parameters(parsed: ParsedSource, node: Node) -> tuple[tuple[str, ...], tuple[str, ...]]:
    parameters_node = node.child_by_field_name("parameters")
    if parameters_node is None:
        parameters_node = node.child_by_field_name("parameter")
    if parameters_node is None:
        for child in node.children:
            if child.type in {"formal_parameters", "lambda_parameters", "parameters"}:
                parameters_node = child
                break
    if parameters_node is None:
        return (), ()

    if parameters_node.type == "identifier":
        text = parsed.text_for_node(parameters_node).strip()
        return (text,) if text else (), (text,) if text else ()

    declarations: list[str] = []
    names: list[str] = []
    for child in parameters_node.named_children:
        if child.type in _PARAMETER_SEPARATORS:
            continue
        text = parsed.text_for_node(child).strip()
        if not text:
            continue
        declarations.append(text)
        names.extend(_bound_names(parsed, child))
    return tuple(declarations), tuple(dict.fromkeys(names))


def _bound_names(parsed: ParsedSource, node: Node) -> list[str]:
    if parsed.language is SupportedLanguage.PYTHON:
        return _python_bound_names(parsed, node)
    return _javascript_bound_names(parsed, node)


def _python_bound_names(parsed: ParsedSource, node: Node) -> list[str]:
    if node.type == "identifier":
        return [parsed.text_for_node(node)]

    if node.type in {"typed_parameter", "typed_default_parameter"}:
        for child in node.children:
            if child.type == "type":
                continue
            if child.type in {
                "identifier",
                "default_parameter",
                "dictionary_splat_pattern",
                "list_splat_pattern",
                "tuple_pattern",
            }:
                return _python_bound_names(parsed, child)
        return []

    if node.type == "default_parameter":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return _python_bound_names(parsed, name_node)
        return []

    if node.type in {"list_splat_pattern", "dictionary_splat_pattern"}:
        for child in node.named_children:
            if child.type == "identifier":
                return [parsed.text_for_node(child)]
        return []

    if node.type in {"tuple_pattern", "list_pattern"}:
        names: list[str] = []
        for child in node.named_children:
            names.extend(_python_bound_names(parsed, child))
        return names

    return []


def _javascript_bound_names(parsed: ParsedSource, node: Node) -> list[str]:
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [parsed.text_for_node(node)]

    if node.type == "assignment_pattern":
        left = node.child_by_field_name("left")
        if left is None and node.named_children:
            left = node.named_children[0]
        return _javascript_bound_names(parsed, left) if left is not None else []

    if node.type == "rest_pattern":
        names: list[str] = []
        for child in node.named_children:
            names.extend(_javascript_bound_names(parsed, child))
        return names

    if node.type == "pair_pattern":
        value = node.child_by_field_name("value")
        if value is None and len(node.named_children) >= 2:
            value = node.named_children[1]
        return _javascript_bound_names(parsed, value) if value is not None else []

    if node.type in {"array_pattern", "object_pattern", "object_assignment_pattern"}:
        names: list[str] = []
        for child in node.named_children:
            names.extend(_javascript_bound_names(parsed, child))
        return names

    return []


def _is_async(node: Node) -> bool:
    return any(child.type == "async" for child in node.children)


def _is_generator(parsed: ParsedSource, node: Node) -> bool:
    if node.type.startswith("generator_"):
        return True
    if any(child.type == "*" for child in node.children):
        return True
    stop_types = _PY_STOP_TYPES if parsed.language is SupportedLanguage.PYTHON else _JS_STOP_TYPES
    stack = list(node.children)
    while stack:
        child = stack.pop()
        if child.type in stop_types:
            continue
        if child.type in {"yield", "yield_from", "yield_expression"}:
            return True
        stack.extend(child.children)
    return False


def _same_node(left: Node, right: Node) -> bool:
    return left.id == right.id
