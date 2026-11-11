# Development Setup

**Status:** The macOS path was executed and verified on 2026-11-10. The Windows commands are derived from upstream installers and published wheel metadata; they were **not executed on this macOS host**. Claims below distinguish verified behavior from expected behavior.

This repository is a scaffold. Setup installs the toolchain and the VS Code extension shell can run in an Extension Development Host, but there is no FastAPI server, analyzer adapter, model runtime, SAE loader, counterfactual engine, steering controller, repair generator, or verifier yet. No model weights, datasets, SAE artifacts, or benchmark results are downloaded or produced.

## 1. Supported toolchain

| Component | Required | Verified on this host |
|---|---|---|
| Python | `>=3.11,<3.15` | 3.11.14 |
| Node.js | 22.13+ or 24+ (24 LTS recommended) | 25.9.0 |
| npm | Bundled with Node | 11.13.0 |
| VS Code | 1.90+ | 1.143.1; Extension Host launched |
| OS | macOS or Windows | macOS 26.3.1, arm64 |
| Docker | Optional, for future sandbox verification | 29.2.1 detected |
| Semgrep | Optional | 1.185.0 |
| Bandit | Optional | 1.9.4 |

Node 23 is intentionally excluded because ESLint 10 and `@vscode/vsce` 4 do not support it. `.nvmrc` pins Node 24 for nvm users. `.python-version` pins Python 3.11 as the most thoroughly verified interpreter.

Python 3.12–3.14 satisfy the declared range and have compatible wheels for PyTorch, Semgrep, and tree-sitter, but only Python 3.11.14 was exercised end-to-end in this verification run. Python 3.14.0 is installed on the host but was not used for the project virtual environment.

## 2. What setup does

`npm run setup` performs all of the following:

1. Finds a supported Python 3.11–3.14 interpreter.
2. Creates `.venv/` at the repository root (not inside `security-engine/`).
3. Upgrades `pip`, `setuptools`, and `wheel`.
4. Installs the CPU-only PyTorch wheel when `--cpu` is passed.
5. Installs `security-engine` in editable mode with the selected extras.
6. Runs `npm install` for the root workspace.
7. Creates `.env` from `.env.example` if `.env` does not already exist.

It does **not**:

- download Hugging Face models, tokenizers, datasets, or SAE artifacts;
- start the Python engine or the VS Code extension;
- install CodeQL or Joern;
- modify user source files;
- run analysis, counterfactual, steering, repair, or verification code.

Semgrep and Bandit are optional. Without `--with-analyzers`, setup skips them; their adapters will not exist until later phases regardless.

## 3. macOS quick start (verified)

Install Node 22.13+ or 24+ from [nodejs.org](https://nodejs.org/), or use nvm. The repository `.nvmrc` selects Node 24. Install Python 3.11–3.14 from [python.org](https://www.python.org/downloads/) or Homebrew, for example:

```bash
brew install python@3.11
python3.11 --version
```

From the repository root:

```bash
cd /path/to/CRAFT-Sec
npm run setup -- --python python3.11 --cpu --with-analyzers
npm run doctor
npm test
```

The `--python` argument is optional. Without it, `scripts/dev.js` selects the first supported interpreter from `python3.12`, `python3.11`, `python3`, then `python` (and `py -3` on Windows). Use `--python` when multiple interpreters exist and you want a specific one.

The exact command verified on this host was:

```bash
npm run setup -- --python python3.11 --cpu --with-analyzers
```

Result: Python 3.11.14 environment created, CPU-only PyTorch 2.15.0 installed, Semgrep 1.185.0 and Bandit 1.9.4 installed, npm workspace installed, `.env` created, and no model downloads performed. The CPU wheel reports `torch.version.cuda is None`.

## 4. Windows quick start (PowerShell; not executed here)

Install the prerequisites:

- **Node.js:** install Node 22.13+ or 24 LTS from [nodejs.org](https://nodejs.org/). Confirm with `node --version`.
- **Python:** install Python 3.11–3.14 from [python.org](https://www.python.org/downloads/). Select **Add python.exe to PATH** during installation. Confirm the available launchers with `py -0p`.
- **VS Code:** install 1.90 or newer.

If PowerShell blocks npm scripts such as `npm.ps1`, allow locally created scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

From the repository root:

```powershell
cd C:\path\to\CRAFT-Sec
npm run setup -- --cpu --with-analyzers
npm run doctor
npm test
```

If the Python launcher selects an unsupported interpreter, point the setup at a specific executable:

```powershell
$env:CRAFTSEC_PYTHON = "C:\Users\<you>\AppData\Local\Programs\Python\Python312\python.exe"
npm run setup -- --cpu --with-analyzers
```

To run Python tools manually, activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
python --version
```

Published Windows wheels were checked for the critical native packages:

- `torch-2.15.0+cpu-cp311-cp311-win_amd64.whl` is present on the PyTorch CPU index.
- Semgrep 1.185.0 publishes a `win_amd64` wheel.
- `tree-sitter-python`, `tree-sitter-javascript`, and `tree-sitter-typescript` publish Windows wheels.

Native Semgrep installation on Windows has not been executed here. If it fails, either omit `--with-analyzers` and use the engine without analyzer CLIs, or run the engine inside WSL2. Bandit is pure Python and is expected to work on Windows.

## 5. Manual setup (optional)

The setup script is the recommended path because it handles interpreter selection and CPU PyTorch. The equivalent manual commands are below.

### macOS / Linux

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
cd ..
npm install
cp .env.example .env
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
cd ..
npm install
Copy-Item .env.example .env
```

Do not run both the setup script and the manual commands against the same environment unless you intend to reinstall. The setup script reuses an existing `.venv` and leaves an existing `.env` unchanged.

## 6. Dependency profiles

| Goal | Command | Verification status |
|---|---|---|
| Full local development with CPU PyTorch and analyzer CLIs | `npm run setup -- --cpu --with-analyzers` | Executed and verified with Python 3.11 on macOS |
| Core + dev + ML, no Semgrep/Bandit | `npm run setup -- --cpu` | Same path minus the analyzer extra; not separately executed |
| Static-only engine, no PyTorch/Transformers | `npm run setup -- --static-only` | Not separately executed |
| Python environment only, skip npm | `npm run setup -- --cpu --skip-node` | Not separately executed |

The Python extras are declared in `security-engine/pyproject.toml`:

- Core: FastAPI, Uvicorn, Pydantic, SQLAlchemy, Alembic, NumPy, Pandas, tree-sitter and grammars, JSON Schema.
- `ml`: PyTorch, Transformers, safetensors.
- `analyzers`: Semgrep, Bandit.
- `dev`: pytest, pytest-cov, pytest-timeout, Ruff, import-linter, datamodel-code-generator, build.

## 7. Environment variables

Setup copies `.env.example` to `.env`. Never commit `.env`. The template sets CPU development as the default.

| Variable | Default in template | Purpose |
|---|---|---|
| `CRAFTSEC_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `CRAFTSEC_DATA_DIR` | `./.craftsec-data` | Local data directory |
| `CRAFTSEC_LOG_DIR` | `./.craftsec-data/logs` | Local log directory |
| `CRAFTSEC_DEVICE` | `cpu` | `cpu`, `auto`, `cuda`, or `mps`; `auto` detects hardware |
| `CRAFTSEC_GPU_CONCURRENCY` | `1` | Integer from 1 to 8 |
| `CRAFTSEC_MODEL_ID` | commented out | Hugging Face model identifier, only when a workflow needs it |
| `CRAFTSEC_MODEL_REVISION` | commented out | Immutable model revision, preferably a commit SHA |
| `CRAFTSEC_HF_TOKEN` or `HF_TOKEN` | commented out | Optional gated-model token; redacted from serialized settings |
| `CRAFTSEC_SAE_MANIFEST` | commented out | Registered, compatible SAE manifest path |
| `CRAFTSEC_SANDBOX_BACKEND` | `docker` | `docker`, `process`, or `none`; no sandbox backend is implemented yet |
| `CRAFTSEC_SANDBOX_TIMEOUT_SECONDS` | `900` | Sandbox timeout |
| `CRAFTSEC_SEMGREP_PATH` | `semgrep` | Semgrep executable or command |
| `CRAFTSEC_BANDIT_PATH` | `bandit` | Bandit executable or command |

Relative paths are resolved from the process working directory. Run engine commands from the repository root unless a later component documents otherwise.

The settings layer is implemented and tested in `security-engine/src/craftsec/core/settings.py`. It validates environment values, creates data/log directories on request, and removes the Hugging Face token from `Settings.redacted()`. The tests do not download models or call external services.

## 8. Daily commands

Run these from the repository root after setup.

| Command | What it does | Verified |
|---|---|---|
| `npm run doctor` | Prints Node, npm, venv Python, installed packages, optional analyzers, Docker, and `.env` status; performs no downloads | Yes |
| `npm run structure:check` | Validates required directories/files, package markers, JavaScript entry point, and absence of TypeScript | Yes |
| `npm run lint` | Runs Ruff on `security-engine/src` and `security-engine/tests`, then ESLint on `vscode-extension` | Yes |
| `npm run format` | Writes Ruff and Prettier formatting | Yes |
| `npm run format:check` | Checks formatting without writing | Yes |
| `npm test` | Runs pytest and VS Code extension unit tests | Yes |
| `npm run build` | Builds the Python wheel and packages a development VSIX | Yes |
| `npm run check` | Runs structure, lint, format check, and tests | Yes |
| `npm run extension:test` | Runs only extension unit tests | Yes (via the same command path) |
| `npm run extension:lint` | Runs only extension ESLint | Yes (via the same command path) |
| `npm run extension:test:integration` | Launches a real VS Code Extension Host and validates activation, commands, views, and settings | Yes; VS Code 1.143.1 on macOS |

Direct Python commands, after activation:

```bash
cd security-engine
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
```

## 9. VS Code extension development

The extension is JavaScript, not TypeScript. Its entry point is `vscode-extension/src/extension.js`.

The manifest contributes:

- **Activity Bar container:** `craftsec`, titled **CRAFT-Sec**, using `media/activitybar.svg`.
- **Sidebar webview:** `craftsec.sidebar`, titled **Security Dashboard**, rendered by `src/webviews/sidebarView.js` with a strict script-free CSP and local CSS.
- **Settings:** `craftsec.backend.pythonPath`, `craftsec.backend.autoStart`, `craftsec.logging.level`, and `craftsec.ui.showStatusBarItem`.
- **Extension icon:** `media/icon.png`, a 128×128 PNG placeholder. The publisher is the explicit placeholder `your-publisher-id`; replace it before publishing.

All commands use the **CRAFT-Sec** category:

| Command | Scope | Service method |
|---|---|---|
| `craftsec.showStatus` | None | — |
| `craftsec.showLogs` | None | — |
| `craftsec.scanCurrentFile` | Saved file in a workspace folder | `scanFile` |
| `craftsec.scanSelection` | Saved file with a non-empty selection | `scanSelection` |
| `craftsec.scanWorkspace` | One or more workspace folders | `scanWorkspace` |
| `craftsec.explainVulnerability` | Saved file in a workspace folder | `explainVulnerability` |
| `craftsec.analyzeSecurityFeatures` | Saved file in a workspace folder | `analyzeSecurityFeatures` |
| `craftsec.counterfactualAnalysis` | Saved file with a non-empty selection | `counterfactualAnalysis` |
| `craftsec.generateSecureCode` | Saved file in a workspace folder | `generateSecureCode` |
| `craftsec.repairVulnerability` | Saved file in a workspace folder | `repairVulnerability` |
| `craftsec.verifyRepair` | One or more workspace folders | `verifyRepair` |
| `craftsec.openSecurityDashboard` | None | — |

The extension activates on startup, its commands, and when the sidebar view is opened. Activation creates the output channel, status bar item, security-engine service, command registry, settings listeners, and sidebar provider. Deactivation records the transition; VS Code disposes the registered subscriptions, including the single command registry that owns all 12 registrations. No Python process is started and no analysis runs.

Engine-backed commands validate the editor and workspace before calling the injected `SecurityEngineService`. Validation failures and service failures are logged and shown as error messages with a **Show Logs** action; cancelled commands are logged without an error dialog. Commands show a cancellable progress notification but never a success notification. The current `UnavailableSecurityEngineService` rejects every call with `E_ENGINE_UNAVAILABLE`, so no result is fabricated.

Use the **Run CRAFT-Sec Extension** launch configuration in `.vscode/launch.json` to start an Extension Development Host with `vscode-extension/` as the development path. The equivalent automated check is:

```bash
npm run extension:test:integration
```

This uses a locally installed VS Code when found (`CRAFTSEC_VSCODE_EXECUTABLE` overrides it), otherwise it downloads stable VS Code into the gitignored `.vscode-test/` directory. The suite activates the extension, verifies all registered commands, the activity bar container, sidebar view, and configuration defaults, and executes the dashboard command.

The launch configuration itself was not clicked on this host, but the same development-extension path was loaded by the Extension Host integration test.

## 10. Build and packaging

```bash
npm run build
```

Outputs:

- Python wheel: `security-engine/dist/craftsec_engine-0.1.0-py3-none-any.whl`
- VSIX: `vscode-extension/craft-sec-0.1.0.vsix`

The VSIX packaging command uses `--no-dependencies` because npm workspaces hoist dependencies to the repository root, and `vsce` otherwise treats the entire repository (including `.venv`) as extension content. The packaged VSIX currently contains 36 files and about 26.7 KB. It does **not** include the declared `ajv` runtime dependency; no current code requires `ajv`, but a bundling step (for example, esbuild) must be added before contract validation is implemented or the extension is published.

The VSIX is a development artifact. It has no repository URL or license yet, so packaging uses `--allow-missing-repository` and `--skip-license`. Do not publish it until those decisions are made.

## 11. Verification record

Verified on macOS 26.3.1 arm64; environment verification on 2026-11-10, command-layer verification on 2026-11-11:

| Check | Result |
|---|---|
| `npm run setup -- --python python3.11 --cpu --with-analyzers` | Succeeded; reused/created `.venv`; no model downloads |
| `npm run structure:check` | 45 required directories and 72 required files present; no TypeScript sources |
| `npm run doctor` | Python 3.11.14; Node 25.9.0; npm 11.13.0; all declared Python packages present; Semgrep 1.185.0; Bandit 1.9.4; Docker 29.2.1 |
| CPU-only PyTorch | `torch 2.15.0`, `torch.version.cuda is None` |
| Tree-sitter grammars | Python, JavaScript, and TypeScript modules imported successfully |
| `npm run lint` | Ruff passed; ESLint passed |
| `npm run format:check` | 30 Python files formatted; all matched JS/JSON files formatted |
| `npm test` | 7 pytest tests passed; 34 Node unit tests passed |
| `npm run extension:test:integration` | Extension Host activated the extension; all 12 commands, activity bar container, sidebar webview, settings, and dashboard execution verified; VS Code 1.143.1 |
| `npm run check` | Structure, lint, format check, and both test suites passed |
| `npm run build` | Python wheel built; 36-file, 26.7 KB VSIX packaged |
| `npm audit --omit=dev` | 0 production vulnerabilities |
| `npm audit` | 4 moderate `minimatch` advisories in development tooling only |
| Windows wheel availability | Torch CPU `win_amd64`, Semgrep `win_amd64`, and tree-sitter Windows wheels present in metadata; not executed |

The `minimatch` advisories affect ESLint and `@vscode/vsce` development dependencies. They are not shipped in the VSIX because packaging uses `--no-dependencies`. Revisit them when upstream releases compatible fixed versions; do not force a downgrade to ESLint 9 or vsce 3 to silence the audit.

## 12. Troubleshooting

**`npm` scripts are blocked in PowerShell.** Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then open a new terminal.

**Python is missing or unsupported.** Run `py -0p` on Windows or `command -v python3.11 python3.12 python3.13 python3.14` on macOS. Set `CRAFTSEC_PYTHON` to the executable, or pass `--python <path>` to setup.

**Node is too old.** Run `node --version`. Install Node 24 LTS if the version is below 22.13 or is Node 23.

**`npm run lint` says the virtual environment is missing.** Run `npm run setup` first. The lint and test commands use `.venv`, not the system Python.

**Semgrep is slow or missing from `PATH`.** Setup installs it into `.venv`. Doctor checks the venv binary directly, but your shell may not have it on `PATH`. On macOS use `.venv/bin/semgrep --version`; on Windows use `.\.venv\Scripts\semgrep.exe --version`. The first Semgrep invocation can take longer than later runs.

**Docker is missing.** Setup, lint, and unit tests still work. Execution-based verification is not implemented and is reported as unavailable until an adequate sandbox exists.

**The VSIX is unexpectedly huge.** Do not remove `--no-dependencies` from the packaging script until the extension is bundled. Without it, npm workspace hoisting causes `vsce` to include the entire repository.

**A model download is requested.** Setup and doctor do not download models. Any later workflow that needs a model must request it explicitly and record the model ID and immutable revision.

## 13. Known limitations

- Windows setup commands were not executed on this macOS host.
- The VS Code **Run CRAFT-Sec Extension** launch configuration was not clicked manually; an equivalent Extension Host run passed through `@vscode/test-electron`.
- The extension is a shell only. It does not start the Python backend or implement detection, SAE extraction, counterfactuals, steering, repair, or verification.
- All engine-backed commands are wired to `UnavailableSecurityEngineService`. Invoking them shows progress and then reports `E_ENGINE_UNAVAILABLE`; no analysis result, probability, or causal claim is produced.
- Command behavior is covered by unit tests with fake VS Code and service objects. The Extension Host test verifies registration and dashboard execution; it does not invoke engine-backed commands against a real backend.
- No FastAPI server, analyzer adapter, model runtime, SAE loader, feature extractor, counterfactual engine, steering controller, repair generator, or verifier exists yet.
- Python 3.12–3.14 were not exercised end-to-end.
- Native Semgrep on Windows was not exercised.
- The development VSIX does not bundle `ajv` or other runtime dependencies.
- The extension icon and activity bar icon are placeholders, and the publisher ID is a placeholder.
- The repository has no license and no repository URL, so it is not publishable.
- No model weights, SAE artifacts, datasets, benchmarks, or research results are included.
