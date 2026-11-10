# Scripts

Development and validation tooling for the CRAFT-Sec monorepo.

## Current

| Script | Purpose |
|---|---|
| `dev.py` | Cross-platform task runner: setup, doctor, structure check, lint, format, test, build, check |
| `dev.js` | Finds a supported Python 3.11–3.14 interpreter and forwards npm arguments to `dev.py` |
| `check_structure.py` | Validates required directories/files, package markers, the JavaScript extension entry point, and the absence of TypeScript |

Use the npm wrappers from the repository root:

```bash
npm run setup -- --cpu --with-analyzers
npm run doctor
npm run structure:check
npm run lint
npm run format:check
npm test
npm run build
npm run check
```

`npm run setup` installs dependencies and creates `.env`; it does not download models or start the engine. `npm run check` runs structure, lint, format check, and tests.

Direct invocation is also supported after setup:

```bash
.venv/bin/python scripts/dev.py doctor
```

On Windows use `.\.venv\Scripts\python scripts\dev.py doctor`.

## Rules

- Scripts must use environment variables for secrets and never print tokens.
- Scripts must fail with actionable messages.
- Setup must not download models, datasets, or SAE artifacts.
- Packaging must not include `.env`, model weights, datasets, or the project virtual environment.
- The VSIX build currently uses `--no-dependencies` because npm workspaces hoist dependencies to the repository root; add a bundling step before runtime dependencies are required.

## Planned (later phases)

- `generate_contracts.py` — JSON Schema → Pydantic + Ajv generation.
- `check_schema_drift.py` — fail CI when generated contracts differ.
- `export_experiment.py` — reproducibility bundle export.
- `bundle_extension.js` — bundle extension runtime dependencies before packaging.
