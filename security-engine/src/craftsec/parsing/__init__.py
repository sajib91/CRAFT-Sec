"""Source-code preprocessing for CRAFT-Sec.

Python and JavaScript are supported. The package provides language detection,
lossless normalization, tree-sitter tokenization, exact source spans, function
extraction, syntax-aware chunking, and repository metadata extraction. Syntax
errors are reported as diagnostics and never converted into a silent success.
"""

from craftsec.parsing.chunking import chunk_source
from craftsec.parsing.functions import extract_functions
from craftsec.parsing.languages import (
    UnsupportedLanguageError,
    detect_language,
    require_language,
    tree_sitter_language,
)
from craftsec.parsing.metadata import (
    RepositoryFileMetadata,
    RepositoryMetadata,
    SkippedFile,
    extract_repository_metadata,
)
from craftsec.parsing.models import (
    ChunkKind,
    CodeChunk,
    DetectionSource,
    FunctionKind,
    FunctionSymbol,
    LanguageDetection,
    LineEnding,
    NormalizedSource,
    ParseDiagnostic,
    SourceMap,
    SourcePoint,
    SourceSpan,
    SupportedLanguage,
    Token,
)
from craftsec.parsing.normalization import normalize_source
from craftsec.parsing.parser import ParsedSource, parse_source
from craftsec.parsing.preprocess import PreprocessedSource, preprocess_file, preprocess_source
from craftsec.parsing.tokens import tokenize_source

__all__ = [
    "ChunkKind",
    "CodeChunk",
    "DetectionSource",
    "FunctionKind",
    "FunctionSymbol",
    "LanguageDetection",
    "LineEnding",
    "NormalizedSource",
    "ParseDiagnostic",
    "ParsedSource",
    "PreprocessedSource",
    "RepositoryFileMetadata",
    "RepositoryMetadata",
    "SkippedFile",
    "SourceMap",
    "SourcePoint",
    "SourceSpan",
    "SupportedLanguage",
    "Token",
    "UnsupportedLanguageError",
    "chunk_source",
    "detect_language",
    "extract_functions",
    "extract_repository_metadata",
    "normalize_source",
    "parse_source",
    "preprocess_file",
    "preprocess_source",
    "require_language",
    "tokenize_source",
    "tree_sitter_language",
]
