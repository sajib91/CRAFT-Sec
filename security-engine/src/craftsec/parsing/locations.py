"""Exact conversion between byte, character, line, and LSP positions."""

from __future__ import annotations

from bisect import bisect_right

from craftsec.parsing.models import SourcePoint, SourceSpan


class LineIndex:
    """A reusable index over one immutable source string."""

    __slots__ = (
        "text",
        "encoded",
        "_byte_line_starts",
        "_char_line_starts",
        "_display_prefix_bytes",
        "_display_prefix_chars",
    )

    def __init__(
        self,
        text: str,
        *,
        display_prefix_bytes: int = 0,
        display_prefix_chars: int = 0,
    ) -> None:
        self.text = text
        self.encoded = text.encode("utf-8")
        self._byte_line_starts = _byte_line_starts(self.encoded)
        self._char_line_starts = _char_line_starts(text)
        self._display_prefix_bytes = display_prefix_bytes
        self._display_prefix_chars = display_prefix_chars

    @property
    def line_count(self) -> int:
        """Number of physical lines; empty text counts as zero."""
        if not self.text:
            return 0
        return self.text.count("\n") + (0 if self.text.endswith("\n") else 1)

    def point_from_byte(self, byte_offset: int) -> SourcePoint:
        """Convert an original UTF-8 byte offset to an exact source point."""
        if not 0 <= byte_offset <= len(self.encoded):
            raise ValueError("byte offset is outside the source")

        line = max(0, bisect_right(self._byte_line_starts, byte_offset) - 1)
        line_byte_start = self._byte_line_starts[line]
        line_char_start = self._char_line_starts[line]
        prefix_bytes = self.encoded[line_byte_start:byte_offset]
        prefix = prefix_bytes.decode("utf-8", errors="ignore")
        display_column = byte_offset - line_byte_start
        display_character = _utf16_width(prefix)
        if line == 0:
            display_column = max(0, display_column - self._display_prefix_bytes)
            display_character = max(0, display_character - self._display_prefix_chars)
        return SourcePoint(
            byte_offset=byte_offset,
            char_offset=line_char_start + len(prefix),
            line=line,
            column=display_column,
            character=display_character,
        )

    def point_from_char(self, char_offset: int) -> SourcePoint:
        """Convert a Python character offset to an exact source point."""
        if not 0 <= char_offset <= len(self.text):
            raise ValueError("character offset is outside the source")

        line = max(0, bisect_right(self._char_line_starts, char_offset) - 1)
        line_char_start = self._char_line_starts[line]
        line_byte_start = self._byte_line_starts[line]
        prefix = self.text[line_char_start:char_offset]
        prefix_bytes = prefix.encode("utf-8")
        display_column = len(prefix_bytes)
        display_character = _utf16_width(prefix)
        if line == 0:
            display_column = max(0, display_column - self._display_prefix_bytes)
            display_character = max(0, display_character - self._display_prefix_chars)
        return SourcePoint(
            byte_offset=line_byte_start + len(prefix_bytes),
            char_offset=char_offset,
            line=line,
            column=display_column,
            character=display_character,
        )

    def span_from_bytes(self, start_byte: int, end_byte: int) -> SourceSpan:
        """Build a span from original UTF-8 byte offsets."""
        if end_byte < start_byte:
            raise ValueError("span end must not precede start")
        return SourceSpan(
            start=self.point_from_byte(start_byte),
            end=self.point_from_byte(end_byte),
        )

    def span_from_chars(self, start_char: int, end_char: int) -> SourceSpan:
        """Build a span from Python character offsets."""
        if end_char < start_char:
            raise ValueError("span end must not precede start")
        return SourceSpan(
            start=self.point_from_char(start_char),
            end=self.point_from_char(end_char),
        )


def _byte_line_starts(encoded: bytes) -> list[int]:
    starts = [0]
    for index, byte in enumerate(encoded):
        if byte == 0x0A:
            starts.append(index + 1)
    return starts


def _char_line_starts(text: str) -> list[int]:
    starts = [0]
    for index, character in enumerate(text):
        if character == "\n":
            starts.append(index + 1)
    return starts


def _utf16_width(text: str) -> int:
    """Count UTF-16 code units, treating astral characters as surrogate pairs."""
    return sum(2 if ord(character) > 0xFFFF else 1 for character in text)
