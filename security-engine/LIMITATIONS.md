# Security Engine Limitations

The HTTP API, file/workspace inspection, shared contract validation, standalone
Python/JavaScript source preprocessing, and intraprocedural CFG/DFG construction
are implemented. No detector, model, SAE, counterfactual, steering, repair, or
verification component is implemented as of this phase. This file tracks
component-specific limitations as each module is built.

The authoritative limitation register is maintained in
[docs/research-alignment.md](../docs/research-alignment.md#12-limitations-register).
Every research component must reference the relevant `LIM-*` identifiers here
before its capability is exposed.

## Current status

- File and workspace scans inspect real files and report hashes, sizes, languages,
  and discovered source URIs.
- A standalone preprocessing library detects, normalizes, parses, tokenizes,
  extracts functions from, chunks, and summarizes Python and JavaScript files.
  It is not connected to the API, workspace scans, or the VS Code extension.
- A standalone program-analysis library builds intraprocedural control-flow and
  data-flow graphs for Python and JavaScript. It is not connected to the API,
  workspace scans, or the VS Code extension.
- Shared JSON Schema contracts and fixtures are validated by both runtimes, but the
  HTTP API still returns interim operation envelopes and does not generate or
  validate runtime responses from those schemas.
- No static analyzer adapter (Semgrep, Bandit, CodeQL, Joern) is connected.
- No evidence-fusion detector exists; scan findings are always empty with an
  explicit `analysisAvailable: false`.
- No SAE artifact has been registered or validated.
- No model activations have been captured.
- No counterfactual effect has been computed.
- No steering run has been performed.
- No repair has been proposed, applied, or verified.
- No benchmark or evaluation result exists.
- The VS Code extension connects to this server over the versioned HTTP API and
  performs health checks, file scans, selection detection requests, and workspace
  scans. It does not start or supervise the server. Research analysis stages still
  report explicit `unavailable` results.

## Parsing limitations

- Supported languages are Python (`.py`, `.pyi`, `.pyw`) and JavaScript (`.js`,
  `.jsx`, `.mjs`, `.cjs`). TypeScript, TSX, and other source formats are reported
  as `unsupported_language` by repository metadata and are never content-guessed
  when the extension is known and unsupported.
- Detection prefers an explicit editor language ID, then a supported extension,
  then a shebang, and finally a conservative content heuristic for extensionless
  files. Ambiguous content remains undetected.
- Normalization removes a leading BOM and converts CRLF/CR to LF. Original text is
  retained, and every span maps back to original byte offsets. `column` is a UTF-8
  byte column for tree-sitter; `character` is a UTF-16 column for VS Code/LSP.
- Tree-sitter error recovery is best effort. Invalid files are returned with
  diagnostics instead of raising, but recovered tokens, functions, and chunks may
  be incomplete or misleading. Consumers must inspect `has_syntax_errors` or
  `parse_ok` and must not claim full coverage.
- Function extraction covers declarations, expressions, arrows, methods, lambdas,
  async functions, and generators. Decorators are included in a symbol's span but
  are not exposed as separate metadata. Dynamic assignment, alias resolution, JSX
  component semantics, and type information are not modeled.
- Chunking uses top-level syntax boundaries and a character limit, not dependency
  analysis or model-tokenizer boundaries. Oversized single lines are split at
  character boundaries, so a part can end mid-token.
- Repository metadata uses a fixed ignored-directory set rather than full
  `.gitignore` semantics and skips symlinks. Oversized, binary, invalid-UTF-8,
  unsupported, and unreadable files are reported in `skipped_files` rather than
  silently dropped.
- There is no persisted index, incremental reparse, cross-file symbol table, import
  resolution, or call graph. The parsing API is currently library-only.

## Program-analysis limitations

The analysis is intraprocedural and syntactic. It preserves exact spans and
produces deterministic NetworkX graphs, but it is not sound or complete.

- `LIM-PA-01` — Calls are syntactic sites, not resolved targets. There is no call
  graph, recursion handling, argument-to-parameter binding, return-to-caller flow,
  or interprocedural taint.
- `LIM-PA-02` — Exception edges originate at a `try` dispatch, not at every
  potentially raising instruction. Handler type matching is not evaluated, a
  `raise` inside a `try` routes to the first handler, and returns/raises inside
  `try`/`finally` bypass the finalizer.
- `LIM-PA-03` — Closures resolve to the nearest earlier definition in an enclosing
  scope. `global`/`nonlocal`, named JavaScript function expressions, dynamic
  scoping, `eval`, reflection, and monkeypatching are not modeled.
- `LIM-PA-04` — There is no value, type, alias, or mutation tracking.
  Attribute/subscript flow is reduced to base-name uses; mutating a container or
  object does not create a new definition. Points-to, field sensitivity, string
  evaluation, and runtime type information are absent.
- `LIM-PA-05` — Comprehensions do not get loop CFGs. Generators and async functions
  are treated as ordinary functions; `yield` and `await` scheduling are ignored.
  Python `match` has no fallthrough and only a literal `_` pattern is treated as
  exhaustive. JavaScript labels are not modeled as break/continue targets, JSX is
  opaque expression syntax, and TypeScript/TSX are unsupported by the parsing
  layer.
- `LIM-PA-06` — Tree-sitter recovery can produce incomplete or misleading
  instructions, functions, and edges for invalid source. Dead code is represented
  as unreachable blocks. Path feasibility, constant conditions, and implicit or
  exception flows are not evaluated.
- `LIM-PA-07` — Spans are exact for parsed nodes, but synthetic entry/exit blocks
  are zero-width and block text spans exclude synthetic lowering anchors.
  Consumers must retain the original source for slicing.
- `LIM-PA-08` — Graphs are rebuilt from scratch with no incremental or cross-file
  index. Output order is structurally deterministic for a fixed parser/grammar
  version, not semantically stable across grammar upgrades or language changes.

## API limitations

- All analysis endpoints return `200` with `partial` operation status and explicit
  `unavailable` stages. Their result objects contain no findings, scores, features,
  effects, patches, or verdicts.
- Verification returns `verdict: "not_run"` because no verifier or adequate
  sandbox exists.
- Scans return an empty `findings` array. This is not a clean bill of health.
- The API is synchronous. There is no job queue, SSE stream, cancellation
  endpoint, or persisted analysis record.
- Workspace scans discover files but do not invoke the parsing library or analyze
  them. Scan responses contain no tokens, functions, chunks, or parsing
  diagnostics.
- Workspace roots must be inside `CRAFTSEC_WORKSPACE_ROOTS`, which defaults to the
  process working directory. Requested roots and files are resolved; escaping
  symlinks are rejected.
- Binary and non-UTF-8 files are rejected. Files over `CRAFTSEC_MAX_FILE_BYTES`
  and workspaces over `CRAFTSEC_MAX_WORKSPACE_FILES` are rejected rather than
  silently truncated.
- Bearer auth is optional and configured at process launch. There is no user
  account system, token rotation, or multi-user authorization.
- The root index, `/docs`, `/redoc`, and `/openapi.json` are not protected by the
  bearer middleware. Run the server on loopback or a trusted network.
- CORS is disabled by default and accepts only an exact origin allowlist. No
  wildcard is permitted.
- There is no Host-header allowlist, DNS-rebinding defense, or rate limiter beyond
  request-size limits. Do not expose the server directly to an untrusted network.
- Request bodies are size-checked while streaming, but FastAPI still buffers each
  accepted JSON body in memory.
- Logs are structured JSON and exclude request bodies and source text, but no
  separate audit store exists.
- No shared-schema runtime model generation or runtime response validation is
  implemented yet; the contract test suites validate schemas and fixtures
  independently in each runtime.

## Non-negotiable constraints

- Missing capabilities are reported as unavailable and are never simulated.
- Heuristic scores are not probabilities.
- Counterfactual effects are model-internal interventions, not real-world causal effects.
- Execution-based verification requires an adequate sandbox.
- Repairs require explicit user approval before application; the engine never
  writes user source.
