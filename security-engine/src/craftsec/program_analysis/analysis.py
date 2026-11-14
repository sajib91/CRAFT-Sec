"""High-level program-analysis entry points."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from craftsec.parsing.models import SupportedLanguage
from craftsec.parsing.parser import ParsedSource, parse_source
from craftsec.program_analysis.cfg import (
    ControlFlowAnalysis,
    ControlFlowGraph,
    build_cfg,
)
from craftsec.program_analysis.dfg import DataFlowAnalysis, DataFlowGraph, build_dfg


@dataclass(frozen=True, slots=True)
class ProgramAnalysis:
    """CFG and DFG products for one source file."""

    parsed: ParsedSource
    cfg: ControlFlowAnalysis
    dfg: DataFlowAnalysis

    @property
    def module_cfg(self) -> ControlFlowGraph:
        return self.cfg.module

    @property
    def module_dfg(self) -> DataFlowGraph:
        return self.dfg.module

    @property
    def functions(self) -> tuple[ControlFlowGraph, ...]:
        return self.cfg.functions

    def function_cfg(self, name: str) -> ControlFlowGraph:
        return self.cfg.function_graph(name)

    def function_dfg(self, name: str) -> DataFlowGraph:
        return self.dfg.function_graph(name)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.parsed.path,
            "language": self.parsed.language.value,
            "cfg": self.cfg.to_dict(),
            "dfg": self.dfg.to_dict(),
        }


def analyze_source(
    source: str,
    *,
    path: str | Path | None = None,
    language: SupportedLanguage | str | None = None,
    language_id: str | None = None,
) -> ProgramAnalysis:
    """Parse source and build its CFG and DFG."""
    parsed = parse_source(
        source,
        path=path,
        language=language,
        language_id=language_id,
    )
    return _analyze_parsed(parsed)


def analyze_file(
    path: str | Path,
    *,
    language_id: str | None = None,
) -> ProgramAnalysis:
    """Read a UTF-8 source file and build its CFG and DFG.

    Callers handling untrusted paths must apply the workspace containment layer
    in :mod:`craftsec.core.paths` before invoking this helper.
    """
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    return analyze_source(text, path=file_path, language_id=language_id)


def analyze_parsed(parsed: ParsedSource) -> ProgramAnalysis:
    """Build CFG and DFG products for an already parsed source."""
    return _analyze_parsed(parsed)


def _analyze_parsed(parsed: ParsedSource) -> ProgramAnalysis:
    cfg = build_cfg(parsed)
    dfg = build_dfg(parsed, cfg=cfg)
    return ProgramAnalysis(parsed=parsed, cfg=cfg, dfg=dfg)
