"""Language detection and tree-sitter grammar registration.

Python and JavaScript are supported in this phase. Detection prefers an explicit
VS Code language identifier, then the file extension, then a shebang, and only
then a conservative content heuristic for extensionless files.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from functools import cache
from pathlib import Path

import tree_sitter_javascript
import tree_sitter_python
from tree_sitter import Language

from craftsec.parsing.models import DetectionSource, LanguageDetection, SupportedLanguage

_LANGUAGE_BY_SUFFIX: Mapping[str, SupportedLanguage] = {
    ".py": SupportedLanguage.PYTHON,
    ".pyi": SupportedLanguage.PYTHON,
    ".pyw": SupportedLanguage.PYTHON,
    ".js": SupportedLanguage.JAVASCRIPT,
    ".jsx": SupportedLanguage.JAVASCRIPT,
    ".mjs": SupportedLanguage.JAVASCRIPT,
    ".cjs": SupportedLanguage.JAVASCRIPT,
}

_LANGUAGE_BY_ID: Mapping[str, SupportedLanguage] = {
    "py": SupportedLanguage.PYTHON,
    "python": SupportedLanguage.PYTHON,
    "python3": SupportedLanguage.PYTHON,
    "js": SupportedLanguage.JAVASCRIPT,
    "javascript": SupportedLanguage.JAVASCRIPT,
    "javascriptreact": SupportedLanguage.JAVASCRIPT,
    "jsx": SupportedLanguage.JAVASCRIPT,
    "node": SupportedLanguage.JAVASCRIPT,
    "nodejs": SupportedLanguage.JAVASCRIPT,
}

_PYTHON_SHEBANG = re.compile(r"^#!.*\bpython(?:\d+(?:\.\d+)*)?\b", re.IGNORECASE)
_JAVASCRIPT_SHEBANG = re.compile(r"^#!.*\bnode(?:js)?\b", re.IGNORECASE)

_PYTHON_CONTENT = (
    re.compile(
        r"^\s*(?:from\s+[\w.]+\s+import\s+|import\s+[\w.]+|def\s+\w+\s*\(|class\s+\w+)",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:async\s+def|if\s+__name__\s*==\s*['\"]__main__['\"])",
        re.MULTILINE,
    ),
)
_JAVASCRIPT_CONTENT = (
    re.compile(
        r"^\s*(?:const|let|var)\s+[\w$]+\s*=|"
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+[\w$]*\s*\(|"
        r"^\s*(?:export\s+)?class\s+[\w$]+|"
        r"^\s*import\s+.+\s+from\s+['\"]",
        re.MULTILINE,
    ),
    re.compile(r"=>|console\.log\s*\("),
)


class UnsupportedLanguageError(ValueError):
    """Raised when a source file cannot be mapped to a supported language."""

    def __init__(
        self,
        *,
        path: str | Path | None = None,
        language_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        target = detail or "the source language is not supported"
        if path is not None:
            target = f"{target} for {Path(path)}"
        elif language_id:
            target = f"{target} for language id {language_id!r}"
        super().__init__(f"{target}. Supported languages: JavaScript, Python.")
        self.path = str(path) if path is not None else None
        self.language_id = language_id


@cache
def tree_sitter_language(language: SupportedLanguage) -> Language:
    """Return the cached tree-sitter grammar for a supported language."""
    if language is SupportedLanguage.PYTHON:
        return Language(tree_sitter_python.language())
    if language is SupportedLanguage.JAVASCRIPT:
        return Language(tree_sitter_javascript.language())
    raise UnsupportedLanguageError(detail=f"no grammar for {language!r}")


def detect_language(
    *,
    path: str | Path | None = None,
    text: str | None = None,
    language_id: str | None = None,
) -> LanguageDetection:
    """Detect Python or JavaScript from an editor id, path, or source text.

    An explicit ``language_id`` is authoritative. This lets the extension pass
    the editor's language even when the file is unsaved or has an unusual name.
    """
    if language_id is not None:
        normalized = language_id.strip().lower()
        language = _LANGUAGE_BY_ID.get(normalized)
        if language is None:
            return LanguageDetection(
                language=None,
                source=DetectionSource.EXPLICIT,
                detail=f"unsupported language id {language_id!r}",
            )
        return LanguageDetection(
            language=language,
            source=DetectionSource.EXPLICIT,
            detail=language_id,
        )

    if path is not None:
        suffix = Path(path).suffix.lower()
        language = _LANGUAGE_BY_SUFFIX.get(suffix)
        if language is not None:
            return LanguageDetection(
                language=language,
                source=DetectionSource.EXTENSION,
                detail=suffix,
            )
        if suffix:
            return LanguageDetection(
                language=None,
                source=DetectionSource.UNKNOWN,
                detail=f"unsupported source extension {suffix!r}",
            )

    if text is not None:
        first_line = text.splitlines()[0] if text.splitlines() else ""
        if _PYTHON_SHEBANG.search(first_line):
            return LanguageDetection(
                language=SupportedLanguage.PYTHON,
                source=DetectionSource.SHEBANG,
                detail="python shebang",
            )
        if _JAVASCRIPT_SHEBANG.search(first_line):
            return LanguageDetection(
                language=SupportedLanguage.JAVASCRIPT,
                source=DetectionSource.SHEBANG,
                detail="node shebang",
            )
        content_language = _detect_from_content(text)
        if content_language is not None:
            return LanguageDetection(
                language=content_language,
                source=DetectionSource.CONTENT,
                detail="syntax-pattern heuristic",
            )

    return LanguageDetection(
        language=None,
        source=DetectionSource.UNKNOWN,
        detail="no supported extension, language id, shebang, or syntax pattern",
    )


def require_language(
    detection: LanguageDetection, *, path: str | Path | None = None
) -> SupportedLanguage:
    """Return a detected language or raise a typed error."""
    if detection.language is None:
        raise UnsupportedLanguageError(path=path, detail=detection.detail)
    return detection.language


def _detect_from_content(text: str) -> SupportedLanguage | None:
    """Use conservative line-level evidence for extensionless source files."""
    sample = text[:8192]
    if not sample.strip():
        return None

    python_score = sum(len(pattern.findall(sample)) for pattern in _PYTHON_CONTENT)
    javascript_score = sum(len(pattern.findall(sample)) for pattern in _JAVASCRIPT_CONTENT)

    if python_score and not javascript_score:
        return SupportedLanguage.PYTHON
    if javascript_score and not python_score:
        return SupportedLanguage.JAVASCRIPT
    return None
