# CRAFT-Sec Security Engine

Local FastAPI research engine for vulnerability evidence, SAE feature extraction, counterfactual analysis, activation steering, repository-aware repair, and independent verification.

## Status

**HTTP API implemented; research stages unavailable.** The versioned FastAPI
transport, typed request/response schemas, structured errors, logging, auth,
CORS, request limits, workspace containment, and real file/workspace inspection
exist. No analyzer adapter, detector, model runtime, SAE loader, counterfactual
engine, steering controller, repair generator, or adequate verification sandbox
is implemented. Those stages return explicit `unavailable` statuses; no results
are invented.

Implemented and tested:

- `src/craftsec/api/` — app factory, `/api/v1` routes, Pydantic schemas,
  request-ID/access-log middleware, optional bearer auth, streaming body limits,
  and RFC 9457 problem-detail handlers.
- `src/craftsec/core/` — settings, typed errors, logging, path containment,
  pipeline primitives, and the operation orchestrator.
- `src/craftsec/main.py` — Uvicorn entry point with configurable host and port.
- File scans — allowlisted-root validation, path/symlink containment, UTF-8 and
  size checks, SHA-256 computation, and language detection.
- Workspace scans — symlink-safe source discovery with ignored generated
  directories and a configurable file-count limit.
- 88 tests under `tests/`, covering every endpoint, validation, problem details,
  auth, CORS, request/file/workspace limits, path containment, pipeline status
  semantics, settings, and OpenAPI paths.
- [API documentation](../docs/api.md) and generated OpenAPI at `/openapi.json`,
  `/docs`, and `/redoc`.

All analysis endpoints currently return `analysisAvailable: false` with explicit
stage reason codes. Health reports every operation capability as `false`.

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
  parsing/            tree-sitter parsing and symbols
  program_analysis/   repository-level call graph/taint analysis
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

The suite exercises the HTTP API and backend primitives. It does not exercise
detection, SAE features, counterfactuals, steering, repair, or execution
verification because those capabilities are not implemented.

## Build

```bash
npm run build
```

This produces `security-engine/dist/craftsec_engine-0.1.0-py3-none-any.whl` and a development VSIX. It does not download models.

## Limitations

See [LIMITATIONS.md](LIMITATIONS.md), [../docs/api.md](../docs/api.md), and the
authoritative register in [../docs/research-alignment.md](../docs/research-alignment.md).
