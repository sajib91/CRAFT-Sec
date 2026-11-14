"""Variable occurrence and call-site extraction from tree-sitter nodes.

This module deliberately works on syntax, not on a language server. It records
the occurrences needed for an intraprocedural DFG and avoids inventing bindings
for attributes, object properties, type annotations, or unresolved globals.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from craftsec.parsing.models import SourceSpan, SupportedLanguage
from craftsec.parsing.parser import ParsedSource
from craftsec.program_analysis.models import (
    CallSite,
    VariableCategory,
    VariableOccurrence,
    VariableRole,
)

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
_FUNCTION_TYPES = _PYTHON_FUNCTION_TYPES | _JAVASCRIPT_FUNCTION_TYPES
_CLASS_TYPES = _PYTHON_CLASS_TYPES | _JAVASCRIPT_CLASS_TYPES
_COMPREHENSION_TYPES = frozenset(
    {
        "dictionary_comprehension",
        "generator_expression",
        "list_comprehension",
        "set_comprehension",
    }
)
_PYTHON_ASSIGNMENT_TYPES = frozenset({"assignment", "named_expression"})
_JAVASCRIPT_ASSIGNMENT_TYPES = frozenset(
    {"assignment_expression", "augmented_assignment_expression"}
)
_PYTHON_SKIP_TYPES = frozenset(
    {
        "comment",
        "type",
        "type_parameter",
        "type_parameter_list",
        "type_parameters",
    }
)
_PARAMETER_SEPARATORS = frozenset({"keyword_separator", "positional_separator", "comment"})
_PYTHON_PARAMETER_CONTAINERS = frozenset({"parameters", "lambda_parameters"})
_JAVASCRIPT_PARAMETER_CONTAINERS = frozenset({"formal_parameters"})


@dataclass(slots=True)
class ExpressionAnalysis:
    """Definitions, uses, and calls found in one expression or statement."""

    definitions: list[VariableOccurrence] = field(default_factory=list)
    uses: list[VariableOccurrence] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)

    def merge(self, other: ExpressionAnalysis) -> None:
        self.definitions.extend(other.definitions)
        self.uses.extend(other.uses)
        self.calls.extend(other.calls)


class VariableExtractor:
    """Extract source-accurate variable occurrences for one parsed file."""

    def __init__(self, parsed: ParsedSource) -> None:
        self.parsed = parsed
        self.language = parsed.language

    # ------------------------------------------------------------------ public

    def expression(
        self,
        node: Node,
        *,
        category: VariableCategory = VariableCategory.USE,
    ) -> ExpressionAnalysis:
        result = ExpressionAnalysis()
        self._walk(node, result, category)
        return result

    def assignment(self, node: Node, *, augmented: bool = False) -> ExpressionAnalysis:
        result = ExpressionAnalysis()
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None:
            category = (
                VariableCategory.AUGMENTED_ASSIGNMENT if augmented else VariableCategory.ASSIGNMENT
            )
            self._collect_targets(left, category, result)
            if augmented:
                self._walk(left, result, VariableCategory.AUGMENTED_ASSIGNMENT)
        if right is not None:
            self._walk(right, result, VariableCategory.USE)
        return result

    def targets(
        self,
        node: Node,
        category: VariableCategory,
    ) -> ExpressionAnalysis:
        """Collect binding targets, including destructuring patterns."""
        result = ExpressionAnalysis()
        self._collect_targets(node, category, result)
        return result

    def declaration(self, node: Node) -> ExpressionAnalysis:
        """Extract variable declarators from a JS lexical/variable declaration."""
        result = ExpressionAnalysis()
        for declarator in _find_nodes(node, "variable_declarator"):
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is not None:
                self._collect_targets(name, VariableCategory.ASSIGNMENT, result)
            if value is not None:
                self._walk(value, result, VariableCategory.USE)
        return result

    def parameters(self, function_node: Node) -> ExpressionAnalysis:
        """Return parameter definitions plus default-value uses.

        Defaults are evaluated by the host language at function-definition time
        in the enclosing scope. For a self-contained function graph they are
        attached to the parameter instruction, which is an approximation noted
        in the package documentation.
        """
        result = ExpressionAnalysis()
        parameters = _parameters_node(function_node, self.language)
        if parameters is None:
            return result
        if parameters.type == "identifier":
            self._collect_targets(parameters, VariableCategory.PARAMETER, result)
            return result
        for child in parameters.named_children:
            if child.type in _PARAMETER_SEPARATORS:
                continue
            self._collect_targets(child, VariableCategory.PARAMETER, result)
            self._collect_default_uses(child, result)
        return result

    def import_definitions(self, node: Node) -> ExpressionAnalysis:
        result = ExpressionAnalysis()
        if self.language is SupportedLanguage.PYTHON:
            self._python_imports(node, result)
        else:
            self._javascript_imports(node, result)
        return result

    def case_targets(self, node: Node) -> ExpressionAnalysis:
        """Extract capture bindings from a Python ``match`` case pattern."""
        result = ExpressionAnalysis()
        self._case_pattern_targets(node, result, value_pattern=False)
        return result

    def definition(
        self,
        node: Node,
        category: VariableCategory,
        *,
        name: str | None = None,
    ) -> VariableOccurrence:
        text = name if name is not None else self.parsed.text_for_node(node).strip()
        return VariableOccurrence(
            name=text,
            span=self.parsed.span_for_node(node),
            text=self.parsed.text_for_node(node),
            role=VariableRole.DEFINITION,
            category=category,
        )

    # -------------------------------------------------------------- expression

    def _walk(
        self,
        node: Node,
        result: ExpressionAnalysis,
        category: VariableCategory,
    ) -> None:
        node_type = node.type

        if node_type in _PYTHON_SKIP_TYPES or node_type == "comment":
            return
        if node_type in _FUNCTION_TYPES or node_type in _CLASS_TYPES:
            return
        if node_type in _COMPREHENSION_TYPES:
            self._comprehension(node, result)
            return
        if node_type in {"call", "call_expression", "new_expression"}:
            self._call(node, result)
            return
        if node_type == "attribute":
            object_node = node.child_by_field_name("object")
            if object_node is not None:
                self._walk(object_node, result, category)
            return
        if node_type == "member_expression":
            object_node = node.child_by_field_name("object")
            property_node = node.child_by_field_name("property")
            if object_node is not None:
                self._walk(object_node, result, category)
            if property_node is not None and property_node.type not in {
                "property_identifier",
                "private_property_identifier",
            }:
                self._walk(property_node, result, category)
            return
        if node_type == "subscript":
            value = node.child_by_field_name("value")
            subscript = node.child_by_field_name("subscript")
            if value is not None:
                self._walk(value, result, category)
            if subscript is not None:
                self._walk(subscript, result, category)
            return
        if node_type == "subscript_expression":
            object_node = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            if object_node is not None:
                self._walk(object_node, result, category)
            if index is not None:
                self._walk(index, result, category)
            return
        if node_type == "keyword_argument":
            value = node.child_by_field_name("value")
            if value is not None:
                self._walk(value, result, category)
            return
        if node_type == "pair":
            key = node.child_by_field_name("key")
            value = node.child_by_field_name("value")
            if self.language is SupportedLanguage.PYTHON:
                if key is not None:
                    self._walk(key, result, category)
            elif key is not None and key.type not in {
                "property_identifier",
                "private_property_identifier",
                "string",
            }:
                self._walk(key, result, category)
            if value is not None:
                self._walk(value, result, category)
            return
        if node_type in {"identifier", "shorthand_property_identifier"}:
            if self.language is SupportedLanguage.JAVASCRIPT and node_type == "property_identifier":
                return
            self._add_use(node, result, category)
            return
        if node_type == "property_identifier":
            return
        if node_type in _PYTHON_ASSIGNMENT_TYPES - {"named_expression"}:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None:
                self._collect_targets(left, VariableCategory.ASSIGNMENT, result)
            if right is not None:
                self._walk(right, result, VariableCategory.USE)
            return
        if node_type == "named_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None:
                self._collect_targets(left, VariableCategory.ASSIGNMENT, result)
            if right is not None:
                self._walk(right, result, VariableCategory.USE)
            return
        if node_type in _JAVASCRIPT_ASSIGNMENT_TYPES:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None:
                augmented = node_type == "augmented_assignment_expression"
                self._collect_targets(
                    left,
                    VariableCategory.AUGMENTED_ASSIGNMENT
                    if augmented
                    else VariableCategory.ASSIGNMENT,
                    result,
                )
                if augmented:
                    self._walk(left, result, VariableCategory.AUGMENTED_ASSIGNMENT)
            if right is not None:
                self._walk(right, result, VariableCategory.USE)
            return
        if node_type == "update_expression":
            argument = node.child_by_field_name("argument")
            if argument is None and node.named_children:
                argument = node.named_children[0]
            if argument is not None:
                self._collect_targets(argument, VariableCategory.UPDATE, result)
                self._walk(argument, result, VariableCategory.UPDATE)
            return
        if node_type == "augmented_assignment":
            # Reached when an augmented assignment appears inside an expression.
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None:
                self._collect_targets(left, VariableCategory.AUGMENTED_ASSIGNMENT, result)
                self._walk(left, result, VariableCategory.AUGMENTED_ASSIGNMENT)
            if right is not None:
                self._walk(right, result, VariableCategory.USE)
            return

        for child in node.named_children:
            self._walk(child, result, category)

    def _call(self, node: Node, result: ExpressionAnalysis) -> None:
        callee_field = "constructor" if node.type == "new_expression" else "function"
        callee = node.child_by_field_name(callee_field)
        arguments = node.child_by_field_name("arguments")
        argument_nodes = list(arguments.named_children) if arguments is not None else []
        callee_text = self.parsed.text_for_node(callee).strip() if callee is not None else None
        is_method = callee is not None and callee.type in {"attribute", "member_expression"}
        call = CallSite(
            call_id=f"call@{node.start_byte}",
            callee=callee_text or None,
            span=self.parsed.span_for_node(node),
            callee_span=self.parsed.span_for_node(callee) if callee is not None else None,
            argument_spans=tuple(
                self.parsed.span_for_node(argument) for argument in argument_nodes
            ),
            is_method=is_method,
            is_constructor=node.type == "new_expression",
        )
        result.calls.append(call)
        if callee is not None:
            self._walk(callee, result, VariableCategory.CALLEE)
        for argument in argument_nodes:
            self._walk(argument, result, VariableCategory.CALL_ARGUMENT)

    def _comprehension(self, node: Node, result: ExpressionAnalysis) -> None:
        for child in node.named_children:
            if child.type == "for_in_clause":
                left = child.child_by_field_name("left")
                right = child.child_by_field_name("right")
                if right is not None:
                    self._walk(right, result, VariableCategory.USE)
                if left is not None:
                    self._collect_targets(left, VariableCategory.COMPREHENSION, result)
            elif child.type == "if_clause":
                for condition in child.named_children:
                    self._walk(condition, result, VariableCategory.USE)
            else:
                self._walk(child, result, VariableCategory.USE)

    def _add_use(
        self,
        node: Node,
        result: ExpressionAnalysis,
        category: VariableCategory,
    ) -> None:
        text = self.parsed.text_for_node(node)
        if not text or text == "_":
            return
        result.uses.append(
            VariableOccurrence(
                name=text,
                span=self.parsed.span_for_node(node),
                text=text,
                role=VariableRole.USE,
                category=category,
            )
        )

    # ----------------------------------------------------------------- targets

    def _collect_targets(
        self,
        node: Node,
        category: VariableCategory,
        result: ExpressionAnalysis,
    ) -> None:
        node_type = node.type

        if node_type == "identifier":
            text = self.parsed.text_for_node(node)
            if text:
                result.definitions.append(
                    VariableOccurrence(
                        name=text,
                        span=self.parsed.span_for_node(node),
                        text=text,
                        role=VariableRole.DEFINITION,
                        category=category,
                    )
                )
            return

        if node_type in {
            "shorthand_property_identifier_pattern",
            "shorthand_property_identifier",
        }:
            text = self.parsed.text_for_node(node)
            if text:
                result.definitions.append(
                    VariableOccurrence(
                        name=text,
                        span=self.parsed.span_for_node(node),
                        text=text,
                        role=VariableRole.DEFINITION,
                        category=category,
                    )
                )
            return

        if node_type in {"attribute", "subscript", "member_expression", "subscript_expression"}:
            # Assigning to a member or index mutates an existing object; it does
            # not bind a new local name.
            self._walk(node, result, category)
            return

        if node_type in {
            "pattern_list",
            "tuple_pattern",
            "list_pattern",
            "list_splat_pattern",
            "dictionary_splat_pattern",
            "object_pattern",
            "array_pattern",
            "rest_pattern",
            "as_pattern_target",
            "parenthesized_expression",
        }:
            for child in node.named_children:
                self._collect_targets(child, category, result)
            return

        if node_type in {"as_pattern", "pair_pattern"}:
            target = node.child_by_field_name("alias")
            if target is None:
                target = node.child_by_field_name("value")
            if target is not None:
                self._collect_targets(target, category, result)
            return

        if node_type in {"assignment_pattern", "object_assignment_pattern"}:
            target = node.child_by_field_name("left")
            if target is None and node.named_children:
                target = node.named_children[0]
            if target is not None:
                self._collect_targets(target, category, result)
            return

        if node_type in {"default_parameter", "typed_default_parameter"}:
            target = node.child_by_field_name("name")
            if target is not None:
                self._collect_targets(target, category, result)
            return

        if node_type in {"typed_parameter", "type"}:
            for child in node.named_children:
                if child.type == "type":
                    continue
                if child.type in {
                    "identifier",
                    "default_parameter",
                    "dictionary_splat_pattern",
                    "list_splat_pattern",
                    "tuple_pattern",
                }:
                    self._collect_targets(child, category, result)
            return

        if node_type == "dotted_name":
            if category is VariableCategory.CASE_TARGET and node.named_children:
                self._collect_targets(node.named_children[-1], category, result)
                return
            for child in node.named_children:
                self._collect_targets(child, category, result)
            return

        if node_type == "case_pattern":
            for child in node.named_children:
                self._collect_targets(child, category, result)
            return

    def _collect_default_uses(self, node: Node, result: ExpressionAnalysis) -> None:
        if node.type in {"default_parameter", "typed_default_parameter"}:
            value = node.child_by_field_name("value")
            if value is not None:
                self._walk(value, result, VariableCategory.USE)
        elif node.type == "assignment_pattern":
            right = node.child_by_field_name("right")
            if right is not None:
                self._walk(right, result, VariableCategory.USE)
        for child in node.named_children:
            if child.type in {"type", "identifier", "property_identifier"}:
                continue
            self._collect_default_uses(child, result)

    def _case_pattern_targets(
        self,
        node: Node,
        result: ExpressionAnalysis,
        *,
        value_pattern: bool,
    ) -> None:
        node_type = node.type
        if node_type in {"case_pattern", "union_pattern"}:
            for child in node.named_children:
                self._case_pattern_targets(child, result, value_pattern=value_pattern)
            return
        if node_type == "dotted_name":
            text = self.parsed.text_for_node(node)
            if not value_pattern and text not in {"_", "True", "False", "None"}:
                last = node.named_children[-1] if node.named_children else node
                result.definitions.append(self.definition(last, VariableCategory.CASE_TARGET))
            return
        if node_type == "as_pattern":
            for child in node.named_children:
                if child.type == "identifier":
                    result.definitions.append(self.definition(child, VariableCategory.CASE_TARGET))
                else:
                    # The class/value side is a use pattern, not a capture.
                    self._case_pattern_targets(child, result, value_pattern=True)
            return
        if node_type in {"splat_pattern", "dict_pattern"}:
            for child in node.named_children:
                if child.type == "identifier":
                    result.definitions.append(self.definition(child, VariableCategory.CASE_TARGET))
                elif child.type in {"case_pattern", "dotted_name"}:
                    self._case_pattern_targets(child, result, value_pattern=value_pattern)
            return
        if node_type == "class_pattern":
            children = list(node.named_children)
            for index, child in enumerate(children):
                if index == 0 and child.type == "dotted_name":
                    continue
                self._case_pattern_targets(child, result, value_pattern=False)
            return
        for child in node.named_children:
            self._case_pattern_targets(child, result, value_pattern=value_pattern)

    # ----------------------------------------------------------------- imports

    def _python_imports(self, node: Node, result: ExpressionAnalysis) -> None:
        if node.type == "import_statement":
            for child in node.named_children:
                self._python_import_name(child, result)
            return

        module_name = node.child_by_field_name("module_name")
        for index, child in enumerate(node.named_children):
            if child is module_name or child.type == "relative_import":
                continue
            if child.type == "wildcard_import":
                continue
            if index == 0 and child is module_name:
                continue
            self._python_import_name(child, result)

    def _python_import_name(self, node: Node, result: ExpressionAnalysis) -> None:
        if node.type == "aliased_import":
            alias = node.child_by_field_name("alias")
            name = node.child_by_field_name("name")
            target = alias if alias is not None else name
            if target is not None:
                result.definitions.append(
                    self.definition(
                        target,
                        VariableCategory.IMPORT,
                        name=self.parsed.text_for_node(target).strip(),
                    )
                )
            return
        if node.type == "dotted_name":
            first = node.named_children[0] if node.named_children else node
            result.definitions.append(
                self.definition(
                    first,
                    VariableCategory.IMPORT,
                    name=self.parsed.text_for_node(first).strip(),
                )
            )

    def _javascript_imports(self, node: Node, result: ExpressionAnalysis) -> None:
        for clause in _find_nodes(node, "import_clause"):
            for child in clause.named_children:
                if child.type == "identifier":
                    result.definitions.append(self.definition(child, VariableCategory.IMPORT))
                elif child.type == "namespace_import":
                    identifiers = [
                        item for item in child.named_children if item.type == "identifier"
                    ]
                    if identifiers:
                        result.definitions.append(
                            self.definition(identifiers[-1], VariableCategory.IMPORT)
                        )
                elif child.type == "named_imports":
                    for specifier in child.named_children:
                        if specifier.type != "import_specifier":
                            continue
                        alias = specifier.child_by_field_name("alias")
                        imported = specifier.child_by_field_name("name")
                        target = alias if alias is not None else imported
                        if target is not None:
                            result.definitions.append(
                                self.definition(target, VariableCategory.IMPORT)
                            )


def _parameters_node(function_node: Node, language: SupportedLanguage) -> Node | None:
    node = function_node.child_by_field_name("parameters")
    if node is None:
        node = function_node.child_by_field_name("parameter")
    if node is not None:
        return node
    containers = (
        _PYTHON_PARAMETER_CONTAINERS
        if language is SupportedLanguage.PYTHON
        else _JAVASCRIPT_PARAMETER_CONTAINERS
    )
    for child in function_node.named_children:
        if child.type in containers or child.type == "identifier":
            return child
    return None


def _find_nodes(node: Node, node_type: str) -> list[Node]:
    found: list[Node] = []
    stack = list(node.named_children)
    while stack:
        child = stack.pop(0)
        if child.type == node_type:
            found.append(child)
        stack[0:0] = list(child.named_children)
    return found


def span_text(parsed: ParsedSource, span: SourceSpan) -> str:
    """Return the exact original source slice for a span."""
    return parsed.text_for_span(span)
