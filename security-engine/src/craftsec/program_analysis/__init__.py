"""Program analysis for CRAFT-Sec.

This package currently provides intraprocedural control-flow graphs (CFGs) and
data-flow graphs (DFGs) for Python and JavaScript. Both analyses preserve exact
source spans and are built on NetworkX graphs.

The implementation is deliberately syntactic. Call targets, dynamic dispatch,
interprocedural return flow, and type information are not resolved. Unsupported
or approximated language constructs are listed in ``docs/program-analysis.md``
and tracked by the ``LIM-PA-*`` limitation identifiers.
"""

from craftsec.program_analysis.analysis import (
    ProgramAnalysis,
    analyze_file,
    analyze_parsed,
    analyze_source,
)
from craftsec.program_analysis.cfg import (
    ControlFlowAnalysis,
    ControlFlowGraph,
    analyze_control_flow,
    build_cfg,
    build_control_flow_graph,
    build_function_cfg,
    build_module_cfg,
)
from craftsec.program_analysis.dfg import (
    DataFlowAnalysis,
    DataFlowGraph,
    analyze_data_flow,
    build_data_flow_graph,
    build_dfg,
)
from craftsec.program_analysis.models import (
    BasicBlock,
    CallSite,
    CFGEdge,
    CFGEdgeKind,
    CFGNodeKind,
    DFGEdge,
    DFGEdgeKind,
    DFGNode,
    DFGNodeKind,
    FunctionScopeInfo,
    Instruction,
    InstructionKind,
    VariableCategory,
    VariableOccurrence,
    VariableRole,
    span_to_dict,
)

__all__ = [
    "BasicBlock",
    "CFGEdge",
    "CFGEdgeKind",
    "CFGNodeKind",
    "CallSite",
    "ControlFlowAnalysis",
    "ControlFlowGraph",
    "DFGEdge",
    "DFGEdgeKind",
    "DFGNode",
    "DFGNodeKind",
    "DataFlowAnalysis",
    "DataFlowGraph",
    "FunctionScopeInfo",
    "Instruction",
    "InstructionKind",
    "ProgramAnalysis",
    "VariableCategory",
    "VariableOccurrence",
    "VariableRole",
    "analyze_control_flow",
    "analyze_data_flow",
    "analyze_file",
    "analyze_parsed",
    "analyze_source",
    "build_cfg",
    "build_control_flow_graph",
    "build_data_flow_graph",
    "build_dfg",
    "build_function_cfg",
    "build_module_cfg",
    "span_to_dict",
]
