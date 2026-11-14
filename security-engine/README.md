# CRAFT-Sec Security Engine

Local FastAPI research engine for vulnerability evidence, SAE feature extraction, counterfactual analysis, activation steering, repository-aware repair, and independent verification.

## Status

**HTTP API, source preprocessing, and program analysis implemented; research
stages unavailable.** The versioned FastAPI transport, typed request/response
schemas, structured errors, logging, auth, CORS, request limits, workspace
containment, and real file/workspace inspection exist. A standalone tree-sitter
preprocessing library detects, parses, tokenizes, chunks, and summarizes Python and
JavaScript source. A second standalone library builds intraprocedural control-flow
and data-flow graphs with exact source spans and NetworkX. No analyzer adapter,
detector, model runtime, SAE loader, counterfactual engine, steering controller,
repair generator, or adequate verification sandbox is implemented. Those stages
return explicit `unavailable` statuses; no results are invented.

Implemented and tested:

- `src/craftsec/api/` — app factory, `/api/v1` routes, Pydantic schemas,
  request-ID/access-log middleware, optional bearer auth, streaming body limits,
  and RFC 9457 problem-detail handlers.
- `src/craftsec/core/` — settings, typed errors, logging, path containment,
  pipeline primitives, and the operation orchestrator.
- `src/craftsec/parsing/` — Python/JavaScript detection, BOM and line-ending
  normalization with a lossless source map, exact UTF-8/UTF-16 spans,
  tokenization, function/method/lambda extraction, AST-aware chunking,
  repository metadata, and recoverable syntax-error diagnostics.
- `src/craftsec/program_analysis/` — module/function CFGs with basic blocks,
  branches, loops, exceptions, returns, and break/continue; reaching-definition
  DFGs with def-use, parameter, call, return, raise, and closure edges; exact
  spans and NetworkX `DiGraph` products.
- `src/craftsec/main.py` — Uvicorn entry point with configurable host and port.
- File scans — allowlisted-root validation, path/symlink containment, UTF-8 and
  size checks, SHA-256 computation, and language detection.
- Workspace scans — symlink-safe source discovery with ignored generated
  directories and a configurable file-count limit. Discovery does not invoke the
  parsing library yet.
- 253 tests under `tests/`, covering every endpoint, validation, problem details,
  auth, CORS, request/file/workspace limits, path containment, pipeline status
  semantics, settings, OpenAPI paths, shared contracts, source preprocessing, and
  CFG/DFG graph correctness.
- [API documentation](../docs/api.md), [program-analysis documentation](../docs/program-analysis.md),
  and generated OpenAPI at `/openapi.json`, `/docs`, and `/redoc`.

All analysis endpoints currently return `analysisAvailable: false` with explicit
stage reason codes. Health reports every operation capability as `false`. The
preprocessing and program-analysis libraries are not connected to a scan route or
stage, so scan responses still contain no tokens, functions, chunks, syntax
diagnostics, CFGs, or DFGs.

## API

From `security-engine/`:

```bash
../.venv/bin/python -m craftsec
# or
../.venv/bin/craftsec
```

Defaults: `127.0.0.1:8765`, 2 MB request body, 1 MB file, 50,000 workspace files,
no CORS origins, and workspace roots set to the process working directory. Set
`CRAFTSEC_API_TOKEN` to require `Authorization: Bearer <token>` on `/api/*`
requests. See [../docs/api.md](../docs/api.md) and [../.env.example](../.env.example).

## Layout

```text
src/craftsec/
  api/                FastAPI app, routes, schemas, middleware
  artifacts/          content-addressed artifact store
  contracts/          generated Pydantic models from shared JSON Schema
  core/               errors, logging, paths, pipelines, orchestrator, settings
  counterfactual/     single, pairwise, higher-order analysis
  db/                 SQLite models and repositories
  detection/          evidence fusion and findings
  evaluation/         metrics and statistical evaluation
  experiments/        run manifests and export
  explain/            evidence graph
  features/           SAE feature extraction and aggregation
  ingestion/          project snapshots
  models/             HF runtime and activation hooks
  observability/      logging, redaction, audit
  parsing/            tree-sitter detection, tokenization, symbols, chunks, metadata
  program_analysis/   intraprocedural CFG/DFG construction with NetworkX
  repair/             context assembly and patch generation
  sae/                artifact registry, loader, encode/decode
  sandbox/            isolated execution backends
  static/             Semgrep, Bandit, CodeQL, Joern adapters
  steering/           activation steering and evaluation
  verification/       independent security/functional verification
```

## Local setup

From the repository root, the verified path is:

```bash
npm run setup -- --cpu --with-analyzers
npm run doctor
npm test
```

`--cpu` installs CPU-only PyTorch. `--with-analyzers` adds Semgrep and Bandit; omit it for a lighter environment. No model weights are downloaded.

For a manual environment:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
```

On Windows use `py -3.11 -m venv .venv` and `.\.venv\Scripts\Activate.ps1`. See [../docs/development-setup.md](../docs/development-setup.md) for the full macOS and Windows instructions.

## Tests

```bash
npm test
```

or directly:

```bash
cd security-engine
../.venv/bin/python -m pytest
```

The suite exercises the HTTP API, backend primitives, shared contract schemas, the
standalone preprocessing library, and the standalone program-analysis library. It
does not exercise vulnerability detection, SAE features, counterfactuals,
steering, repair, or execution verification because those capabilities are not
implemented. Because parsing and graph construction are not wired into the scan
pipeline, scan responses do not include preprocessing or graph products.

## Build

```bash
npm run build
```

This produces `security-engine/dist/craftsec_engine-0.1.0-py3-none-any.whl` and a development VSIX. It does not download models.

## Limitations

See [LIMITATIONS.md](LIMITATIONS.md), [../docs/api.md](../docs/api.md), and the
authoritative register in [../docs/research-alignment.md](../docs/research-alignment.md).
