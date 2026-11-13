# CRAFT-Sec

**Counterfactual Risk Analysis and Feature-aware Steering for Secure Code Generation.**

CRAFT-Sec is a local-first research system for explainable vulnerability detection, SAE-based feature analysis, counterfactual multi-feature interaction analysis, interaction-aware activation steering, repository-aware repair, and independent security/functional verification. It is delivered as a JavaScript VS Code extension backed by a Python/FastAPI security engine.

## Status

**Phase 1: repository scaffold, development environment, VS Code extension shell, security dashboard, diagnostics layer, versioned FastAPI engine API, and live local HTTP transport.** The extension shell and backend-result diagnostics are implemented. The Python engine exposes a tested `/api/v1` HTTP API, performs real allowlisted file and workspace inspection (including caller-supplied unsaved editor text), and reports every unimplemented research stage as `unavailable`. The extension connects to an already-running backend for health checks, file scans, selection detection requests, and workspace scans; it does not start the engine. It does **not** yet implement vulnerability detection, SAE extraction, counterfactuals, steering, repair, or verification; those responses contain no fabricated findings, scores, features, effects, patches, or verdicts. No empirical results, benchmarks, or model performance are claimed.

## Research integrity

- SAE features are only produced from a genuine, compatible SAE artifact and a white-box model with accessible activations. Missing capabilities are reported as unavailable, never simulated.
- Heuristic risk scores are not probabilities. Calibrated scores require a fitted calibrator and a held-out labelled dataset.
- Counterfactual effects describe model-internal interventions, not real-world causal effects.
- Activation steering is limited to compatible models with accessible internal activations.
- Repairs are applied only after explicit user approval; the Python engine never writes user source.
- Execution-based verification requires an isolated sandbox. If no adequate sandbox exists, verification is marked `not_run`.
- No fabricated datasets, citations, metrics, or experimental results are permitted.
- Every research component must ship tests and documented limitations before its capability is enabled.

See [docs/research-alignment.md](docs/research-alignment.md) for the binding claim taxonomy and acceptance gates.

## Monorepo map

| Path | Purpose |
|------|---------|
| `vscode-extension/` | JavaScript VS Code extension, webviews, backend HTTP client, patch approval |
| `security-engine/` | Python/FastAPI engine: ingestion, parsing, analyzers, model/SAE, detection, counterfactuals, steering, repair, verification |
| `shared/` | JSON Schemas, generated contract artifacts, and contract fixtures |
| `research/` | Experiment configs, evaluation protocols, dataset cards, and research records |
| `benchmarks/` | Benchmark harness, task definitions, configs, and non-committed results |
| `docs/` | Architecture, research alignment, ADRs |
| `scripts/` | Development and validation tooling |

Core research modules under `security-engine/src/craftsec/`:

- `sae/` and `features/` — genuine SAE feature extraction.
- `counterfactual/` — single-feature, pairwise, and higher-order interactions.
- `steering/` — interaction-aware activation steering.
- `detection/` and `explain/` — evidence fusion and explainable findings.
- `repair/` — repository-aware patch proposals.
- `verification/` — independent security and functional checks.
- `parsing/`, `static/`, and `program_analysis/` — program analysis.
- `evaluation/` — metrics and statistical evaluation helpers.

## Requirements

- Python 3.11–3.14 (3.11.14 verified)
- Node.js 22.13+ or 24+ (24 LTS recommended; Node 23 is unsupported)
- VS Code 1.90+
- Optional: Semgrep, Bandit, Docker/Podman, CodeQL, Joern
- Optional: CUDA/MPS hardware for future model/SAE workflows; CPU-only development is supported

The engine server is runnable. From the repository root after setup:

```bash
cd security-engine
../.venv/bin/python -m craftsec
```

It binds `127.0.0.1:8765` by default and serves OpenAPI at `/openapi.json` and `/docs`. See [docs/api.md](docs/api.md) for endpoints, limits, auth, and response contracts.

## Development setup

Verified macOS command (see [docs/development-setup.md](docs/development-setup.md) for Windows PowerShell and manual steps):

```bash
npm run setup -- --python python3.11 --cpu --with-analyzers
npm run doctor
npm run check
```

`--python` is optional; setup selects a supported interpreter automatically. `--cpu` installs CPU-only PyTorch. `--with-analyzers` installs optional Semgrep and Bandit. Setup does not download models, datasets, or SAE artifacts.

## Quick validation

```bash
npm run structure:check
```

This verifies that the scaffold matches the approved architecture layout. After setup, `npm run check` runs structure, lint, formatting, and tests. The current tests cover the versioned HTTP API, validation and problem details, auth/CORS/limits, path containment, pipeline semantics, environment settings, command registration and validation, backend URL/timeout/privacy configuration, HTTP transport and response validation, the extension manifest, the dashboard model/HTML/panel/client, the sidebar launcher, and an Extension Host run against a live backend that verifies health, unsaved-buffer scanning, consent-gated source sharing, workspace/selection scans, and the dashboard. No analysis functionality is implemented; analysis endpoints return explicit `unavailable` stages.

## Documentation

- [Development setup](docs/development-setup.md)
- [HTTP API](docs/api.md)
- [Architecture](docs/architecture.md)
- [Research alignment and integrity contract](docs/research-alignment.md)
- [Architecture decision records](docs/adr/README.md)

## Data policy

Datasets, model weights, SAE artifacts, experiment outputs, and benchmark results are not committed to this repository. Dataset cards and configuration files may be committed; data and results remain local or externally hosted under their own licenses.

## License

No license has been selected yet. Do not redistribute this repository until a license is added.
