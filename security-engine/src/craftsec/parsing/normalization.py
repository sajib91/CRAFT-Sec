"""Canonical source normalization with a lossless source map.

Normalization removes a leading UTF-8 BOM and canonicalizes CRLF/CR line endings
to LF. It never changes indentation, identifiers, punctuation, or any other
source character. The returned source map translates every normalized byte
boundary back to the original file so tree-sitter spans remain exact.
"""

from __future__ import annotations

from craftsec.parsing.models import LineEnding, NormalizedSource, SourceMap


def normalize_source(text: str) -> NormalizedSource:
    """Return canonical text plus a normalized-to-original byte map."""
    if not isinstance(text, str):
        raise TypeError("source text must be a string")

    had_bom = text.startswith("\ufeff")
    start_index = 1 if had_bom else 0
    bom_bytes = len("\ufeff".encode("utf-8")) if had_bom else 0

    parts: list[bytes] = []
    offsets: list[int] = [bom_bytes]
    original_byte = bom_bytes
    index = start_index

    while index < len(text):
        character = text[index]
        if character == "\r":
            if index + 1 < len(text) and text[index + 1] == "\n":
                original_length = 2
                index += 2
            else:
                original_length = 1
                index += 1
            parts.append(b"\n")
            original_byte += original_length
            offsets.append(original_byte)
            continue

        encoded = character.encode("utf-8")
        parts.append(encoded)
        for byte_index in range(1, len(encoded) + 1):
            offsets.append(original_byte + byte_index)
        original_byte += len(encoded)
        index += 1

    normalized_bytes = b"".join(parts)
    original_size = len(text.encode("utf-8"))
    source_map = SourceMap(
        offsets=tuple(offsets),
        original_size=original_size,
        normalized_size=len(normalized_bytes),
    )
    return NormalizedSource(
        original_text=text,
        text=normalized_bytes.decode("utf-8"),
        source_map=source_map,
        had_bom=had_bom,
        line_ending=_detect_line_ending(text),
    )


def _detect_line_ending(text: str) -> LineEnding:
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    cr = text.count("\r") - crlf
    if crlf and (lf or cr):
        return "mixed"
    if crlf:
        return "crlf"
    if cr:
        return "cr"
    if lf:
        return "lf"
    return "none"
