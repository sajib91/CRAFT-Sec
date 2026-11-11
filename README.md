# CRAFT-Sec

**Counterfactual Risk Analysis and Feature-aware Steering for Secure Code Generation.**

CRAFT-Sec is a local-first research system for explainable vulnerability detection, SAE-based feature analysis, counterfactual multi-feature interaction analysis, interaction-aware activation steering, repository-aware repair, and independent security/functional verification. It is delivered as a JavaScript VS Code extension backed by a Python/FastAPI security engine.

## Status

**Phase 1: repository scaffold, development environment, VS Code extension shell, and command layer.** This repository currently contains the approved architecture, directory structure, package manifests, development toolchain, placeholder documentation, and a runnable extension shell. The environment settings layer, extension activation, and modular command registration against a security-engine service interface are implemented with tests. It does **not** yet implement vulnerability detection, SAE extraction, counterfactuals, steering, repair, or verification. No results, benchmarks, or model performance are claimed.

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
| `vscode-extension/` | JavaScript VS Code extension, webviews, backend lifecycle, patch approval |
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

The engine has no runnable server yet. Dependencies are installed for later phases; installing them does not make the application functional.

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

This verifies that the scaffold matches the approved architecture layout. After setup, `npm run check` runs structure, lint, formatting, and tests. The current tests cover environment settings, command registration and validation, the extension manifest and sidebar, and an Extension Host activation run; no analysis functionality is implemented.

## Documentation

- [Development setup](docs/development-setup.md)
- [Architecture](docs/architecture.md)
- [Research alignment and integrity contract](docs/research-alignment.md)
- [Architecture decision records](docs/adr/README.md)

## Data policy

Datasets, model weights, SAE artifacts, experiment outputs, and benchmark results are not committed to this repository. Dataset cards and configuration files may be committed; data and results remain local or externally hosted under their own licenses.

## License

No license has been selected yet. Do not redistribute this repository until a license is added.
