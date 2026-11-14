# Program analysis: CFG and DFG

The Python package `craftsec.program_analysis` provides standalone
intraprocedural control-flow graphs (CFGs) and data-flow graphs (DFGs) for the
Python and JavaScript source that `craftsec.parsing` accepts. It is a library
layer: no API route, workspace scan, detector, or VS Code command invokes it yet.

The analysis is deliberately syntactic. It preserves exact source locations for
every instruction, basic block, graph node, and graph edge, and it is built on
[NetworkX](https://networkx.org/) `DiGraph` objects. It does not resolve calls,
types, aliases, or runtime values. Known approximations are listed under
[Limitations](#limitations) and tracked by `LIM-PA-*` identifiers.

## Quick start

```python
from craftsec.program_analysis import analyze_source

source = """def classify(value):
    result = value + 1
    if result > 10:
        result = 0
    return result
"""

analysis = analyze_source(source, path="example.py")

module_cfg = analysis.module_cfg
function_cfg = analysis.function_cfg("classify")
function_dfg = analysis.function_dfg("classify")

print([block.text for block in function_cfg.blocks])
print([(node.name, node.kind.value) for node in function_dfg.nodes])
```

`analyze_file(path)` reads a UTF-8 file, and `analyze_parsed(parsed)` accepts an
existing `craftsec.parsing.ParsedSource`. Callers handling untrusted paths must
apply the workspace containment layer in `craftsec.core.paths` first.

Lower-level entry points:

| Function | Product |
|---|---|
| `build_cfg(source, *, path, language, language_id)` | `ControlFlowAnalysis` for a module and all functions |
| `build_module_cfg(...)` | Module-level `ControlFlowGraph` only |
| `build_function_cfg(source, name, ...)` | Named function or method `ControlFlowGraph` |
| `build_dfg(source, *, cfg=None, ...)` | `DataFlowAnalysis`; reuses a supplied CFG when provided |
| `build_control_flow_graph`, `analyze_control_flow` | Aliases of `build_cfg` |
| `build_data_flow_graph`, `analyze_data_flow` | Aliases of `build_dfg` |

The dependency on NetworkX is direct (`networkx>=3.2,<4`), not transitive.

## Graph model

### Scopes

A module and every function-like symbol (function, method, arrow function,
lambda, generator) receive independent CFGs and DFGs. The module graph treats a
function or class declaration as one opaque instruction whose span covers the
header and whose definition is the declared name. The function body is analysed
only in that function's graph.

`ControlFlowAnalysis.scopes` records each `FunctionScopeInfo`: scope ID, source
name, qualified name, function kind, parameter names, and lexical parent. Parent
links are inferred from source-span containment. Top-level functions have
`parent_scope_id == "module"`.

### CFG nodes and edges

`ControlFlowGraph.blocks` contains `BasicBlock` objects. Each block has a stable
ID, `entry`/`basic`/`exit` kind, exact `SourceSpan`, exact source text, and a
tuple of `Instruction` objects. Entry and exit blocks are synthetic and normally
have empty statement tuples and zero-width spans.

`ControlFlowGraph.edges` retains every logical edge between blocks, including
parallel edges. `ControlFlowGraph.graph` is a NetworkX `DiGraph` that aggregates
parallel block edges. Aggregated attributes include:

- `kind`: the first logical edge kind;
- `kinds`: all distinct logical kinds in insertion order;
- `label` / `labels`: branch labels such as `ValueError as exc` or `default`;
- `count`: the number of logical edges;
- `span` and `span_dict`: source span of the originating instruction.

Use `edge_details(source, target)` to recover the logical `CFGEdge` objects.
`successors`, `predecessors`, `reachable_blocks`, `block`, `parameters`, and
`calls` provide convenience accessors.

Edge kinds:

| Kind | Meaning |
|---|---|
| `normal` | Fallthrough or unconditional structured flow |
| `true` / `false` | Conditional branch outcomes |
| `loop_back` | Back edge to a loop header |
| `break` / `continue` | Loop exit and next-iteration jumps |
| `return` / `raise` | Transfer to the synthetic function exit |
| `exception` | Structured transfer from a `try` dispatch to a handler |
| `case` / `default` | `switch` / `match` dispatch |
| `fallthrough` | JavaScript `switch` fallthrough |

Instruction kinds distinguish assignments, declarations, parameters,
conditions, loops, loop targets and updates, switches, cases, tries, with-items,
returns, raises, breaks, continues, imports, functions, classes, deletes, and
matches. Each instruction records its own definitions, uses, and call sites.

### DFG nodes and edges

`DataFlowGraph.nodes` contains entry/exit nodes, parameter nodes, definition
nodes, use nodes, call nodes, return nodes, and raise nodes. Definition and use
nodes have a variable name, category, role, exact span, and `resolved` flag.
Call nodes retain the callee text and call-site ID.

`DataFlowGraph.edges` describes:

| Kind | Meaning |
|---|---|
| `def_use` | A definition reaches a use and the use resolves to it |
| `closure` | A lexically enclosing definition reaches a nested-function use |
| `parameter_binding` | Function entry binds a parameter |
| `callee` | A use is the callee expression of a call |
| `argument` | A use occurs inside an argument expression |
| `call_result` | A syntactic call result flows to an assigned definition |
| `return_value` | A use or call contributes to a returned value |
| `returns_to` / `raises_to` | Return/raise node reaches the synthetic exit |
| `raise_value` | A use or call contributes to a raised value |

`DataFlowGraph.graph` is the NetworkX representation. `definitions_for`,
`uses_for`, `dependencies`, `unresolved_uses`, `incoming_edges`,
`outgoing_edges`, `variables`, and `summary` support queries. `dependencies`
covers value-carrying edges but excludes structural entry/exit and
parameter-binding edges.

## Control-flow semantics

The CFG is built in two stages: tree-sitter statements are lowered to
instructions with explicit logical edges, then leaders are computed and
instructions are collapsed into maximal straight-line basic blocks. Blocks are
ordered by source position. Instructions not reachable from entry are still
represented as blocks rather than silently dropped.

Supported structured constructs include:

- Python: assignments (including annotated, augmented, walrus, and
  destructuring targets), `if`/`elif`/`else`, `while`/`else`, `for`/`else`,
  `break`, `continue`, `try`/`except`/`else`/`finally`, `with`, `assert`,
  `return`, `raise`, `import`, `from ... import`, function/class declarations,
  lambdas, `match`, `del`, and `pass`.
- JavaScript: lexical/variable declarations, assignment/augmented/update
  expressions, `if`/`else`, C-style `for`, `for...in`, `for...of`,
  `while`, `do...while`, `switch`/`case`/`default`, `try`/`catch`/`finally`,
  `throw`, `return`, `break`, `continue`, function/arrow/method/generator
  declarations, classes, exports, and labeled statements (the label itself is
  ignored and the labeled body is lowered).

Branches use `true`/`false` edges. Python loop `else` blocks are reachable only
from the loop's false edge. JavaScript `switch` cases fall through in source
order unless a terminator (`break`, `return`, `throw`, or `continue`) cuts the
path. A `switch` without a default receives a synthetic `no_matching_case` false
edge; Python `match` does the same unless a `case _` wildcard is present.

Function `return` statements connect to the function exit with a `return` edge.
The module graph also uses a `return` edge when a module-level statement is
lowered as a terminator. `assert` lowers to a condition plus a synthetic raise
path. `with` items are instructions, but context-manager enter/exit and
suppression semantics are not modeled.

## Data-flow semantics

The DFG runs reaching-definitions analysis over the basic blocks of one scope:

1. Collect every definition of every variable in the scope.
2. Compute each block's `GEN` and `KILL` sets.
3. Solve the standard forward data-flow equations to a fixed point over the
   block graph, including loop back edges and branch merges.
4. Walk each block in order. A use receives a `def_use` edge from every
   definition currently reaching it; a new definition then kills older
   definitions of the same name.

This produces real branch-merge and loop-carried dependencies. A reassignment
kills earlier definitions for later uses. An augmented assignment both reads
and defines the same name, so the pre-assignment definition reaches its use and
the new definition reaches later uses.

Additional relationships are added after reaching definitions:

- Function parameters are definitions bound from the function entry.
- Calls record callee and argument edges. If an assignment/declaration has one
  syntactically outer call, the call node receives a `call_result` edge to the
  assigned definition.
- Explicit return and raise statements connect their value uses and calls to a
  return/raise node, which connects to the scope exit.
- Nested-function uses that are not locally defined are resolved to the nearest
  earlier definition in an enclosing lexical scope and marked as `closure`.
- Uses with no incoming definition or closure edge remain in the graph with
  `resolved=False`. No definition is invented for builtins, globals, imports
  from unknown modules, or unresolved names.

The analysis is per scope. A module DFG contains module-level definitions and
uses only; function bodies appear only in their own DFG. A nested function's
closure edge may point to a definition node in an outer scope, but there is no
argument-to-parameter or return-to-caller propagation.

## Source locations

Every instruction, basic block, CFG node/edge, DFG node/edge, variable
occurrence, and call site carries an exact `craftsec.parsing.SourceSpan`.
Spans refer to the original source text, not the normalized parse buffer:

- `byte_offset` is an absolute UTF-8 byte offset into the original source.
- `char_offset` is an absolute Python character offset into the original source.
- `line` is zero-based.
- `column` is a zero-based UTF-8 byte column for tree-sitter.
- `character` is a zero-based UTF-16 code-unit column for VS Code/LSP.

BOM removal and CRLF/CR normalization in the parsing layer are mapped back, so
slicing `parsed.text` with `span.start.char_offset:span.end.char_offset`
returns exactly the recorded text. `span_to_dict` and every `to_dict` method
serialize both coordinate systems plus an LSP range; the serialized products are
JSON-safe.

Synthetic entry/exit locations are zero-width. A block span runs from its first
to last real instruction; synthetic-only blocks are empty. A synthetic lowering
anchor (for example, the `do...while` anchor) has a source span but is not
counted when the block's text span is computed.

## Tests

Graph correctness tests live in:

- `tests/unit/test_program_analysis_cfg.py` — basic blocks, branches, loops,
  break/continue, try/except/else/finally, `match`, functions and nested scopes,
  JavaScript switch fallthrough and loops, empty/dead code, exact BOM/CRLF/
  UTF-8/UTF-16 locations, and builder aliases.
- `tests/unit/test_program_analysis_dfg.py` — branch merges, reassignment kills,
  loop-carried definitions, augmented assignments, parameters, calls and
  arguments, call results, returns and raises, closures, module opacity,
  unresolved uses, JavaScript scope isolation, invariants, and determinism.
- `tests/unit/test_program_analysis_api.py` — high-level API parity, file
  loading, aliases, NetworkX/JSON serialization, syntax-error tolerance, and
  missing-scope errors.

Run them with:

```bash
cd security-engine
../.venv/bin/python -m pytest tests/unit/test_program_analysis_*.py
```

## Limitations

The implementation is a syntactic, intraprocedural approximation. It is not a
sound or complete program analysis and must not be used to claim that a path is
impossible or that a value always has a particular origin.

| ID | Limitation |
|---|---|
| `LIM-PA-01` | **Intraprocedural only.** Calls are syntactic sites, not resolved targets. There is no call graph, recursion handling, argument-to-parameter binding, return-to-caller flow, or interprocedural taint. |
| `LIM-PA-02` | **Structured exception approximation.** Exception edges originate at a `try` dispatch, not at every potentially raising instruction. Handler type matching is not evaluated, a `raise` inside a `try` routes to the first handler, and returns/raises inside `try`/`finally` bypass the finalizer. |
| `LIM-PA-03` | **Syntactic scopes and closures.** Closures resolve to the nearest earlier definition in an enclosing scope. `global`/`nonlocal`, named JavaScript function expressions, dynamic scoping, `eval`, reflection, and monkeypatching are not modeled. |
| `LIM-PA-04` | **No value, type, alias, or mutation tracking.** Attribute/subscript flow is reduced to base-name uses. Mutating a container or object does not create a new definition. Points-to, field sensitivity, string evaluation, and runtime type information are absent. |
| `LIM-PA-05` | **Construct approximations.** Comprehensions do not get loop CFGs. Generators and async functions are treated as ordinary functions and `yield`/`await` scheduling is ignored. Python `match` has no fallthrough and only a literal `_` pattern is treated as exhaustive. JavaScript labels are not modeled as break/continue targets, and JSX is treated as opaque expression syntax. TypeScript/TSX are unsupported by the parsing layer. |
| `LIM-PA-06` | **Syntactic partial graphs.** Tree-sitter recovery can produce incomplete or misleading instructions, functions, and edges for invalid source. Dead code is represented as unreachable blocks. Path feasibility, constant conditions, and implicit/exception flows are not evaluated. |
| `LIM-PA-07` | **Location caveats.** Spans are exact for parsed nodes, but synthetic entry/exit blocks are zero-width and block text spans exclude synthetic lowering anchors. Consumers must retain the original source for slicing. |
| `LIM-PA-08` | **Scale and determinism scope.** Graphs are rebuilt from scratch with no incremental or cross-file index. Output order is deterministic for a fixed parser/grammar version, but it is structural determinism, not a claim of semantic stability across grammar upgrades or language changes. |

See also [`../security-engine/LIMITATIONS.md`](../security-engine/LIMITATIONS.md)
and the authoritative register in
[`research-alignment.md`](research-alignment.md#12-limitations-register).
