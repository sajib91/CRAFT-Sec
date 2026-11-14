"""Terminal tree-sitter tokenization with exact original spans."""

from __future__ import annotations

from craftsec.parsing.models import Token
from craftsec.parsing.parser import ParsedSource


def tokenize_source(parsed: ParsedSource) -> tuple[Token, ...]:
    """Tokenize a parsed source into terminal syntactic tokens.

    Whitespace is not a tree-sitter token and is therefore omitted. Comments,
    punctuation, keywords, identifiers, and literals retain their exact source
    span and text. Zero-length missing nodes are reported as parse diagnostics
    rather than emitted as tokens.
    """
    tokens: list[Token] = []
    stack = [parsed.root_node]
    while stack:
        node = stack.pop()
        if node.children:
            stack.extend(reversed(node.children))
            continue
        if node.end_byte <= node.start_byte:
            continue
        span = parsed.span_for_node(node)
        tokens.append(
            Token(
                kind=node.type,
                text=parsed.text_for_span(span),
                span=span,
                named=node.is_named,
                is_comment="comment" in node.type,
                is_error=node.is_error or node.is_missing,
            )
        )
    return tuple(tokens)
