# CRAFT-Sec Security Engine

Local FastAPI research engine for vulnerability evidence, SAE feature extraction, counterfactual analysis, activation steering, repository-aware repair, and independent verification.

## Status

**Scaffold only.** The Python package tree, dependency manifest, migration location, and typed environment settings exist. There is no runnable API server, analyzer adapter, model runtime, SAE loader, counterfactual engine, steering controller, repair generator, or verifier yet. No results are claimed.

Implemented and tested:

- `src/craftsec/core/settings.py` — Pydantic settings, environment/file loading, validation, directory creation, and Hugging Face token redaction.
- 7 settings unit tests under `tests/unit/`.

## Layout

```text
src/craftsec/
  api/                HTTP transport and route adapters
  artifacts/          content-addressed artifact store
  contracts/          generated Pydantic models from shared JSON Schema
  core/               errors, auth, paths, cancellation, jobs, settings
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

The current suite covers environment settings only. It does not exercise analysis functionality because none exists yet.

## Build

```bash
npm run build
```

This produces `security-engine/dist/craftsec_engine-0.1.0-py3-none-any.whl` and a development VSIX. It does not download models.

## Limitations

See [LIMITATIONS.md](LIMITATIONS.md) and the authoritative register in [../docs/research-alignment.md](../docs/research-alignment.md).
