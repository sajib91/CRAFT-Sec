# CRAFT-Sec VS Code Extension

JavaScript VS Code client for the CRAFT-Sec security engine.

## Status

**Scaffold only.** The extension registers a status command and does not start the Python backend or perform analysis. Detection, SAE features, counterfactuals, steering, repair, and verification are not implemented.

## Development

Set up the repository once from the root:

```bash
npm run setup -- --cpu --with-analyzers
```

Then use the root commands:

```bash
npm run extension:lint
npm run extension:test
npm run build
```

The unit tests validate the extension manifest, entry point, and the no-TypeScript constraint. They do not exercise analysis functionality because none exists yet.

Open the repository root in VS Code and use the **Run CRAFT-Sec Extension** launch configuration in `.vscode/launch.json` to start an Extension Development Host.

## Packaging note

The VSIX build uses `vsce package --no-dependencies` because npm workspaces hoist dependencies to the repository root; without this flag, `vsce` would package the entire repository. The current extension does not require `ajv` at runtime, but a bundling step must be added before runtime dependencies are used or the extension is published. The VSIX also lacks a repository URL and license, so it is a development artifact only.

## Layout

| Path | Purpose |
|------|---------|
| `extension.js` | Activation entry point (currently a status placeholder) |
| `src/backend/` | Engine spawn, handshake, health, restart |
| `src/api/` | Authenticated client, SSE, schema validation |
| `src/jobs/` | Job lifecycle and progress routing |
| `src/commands/` | Commands and capability guards |
| `src/views/` | Findings tree, jobs tree, status bar |
| `src/webviews/` | Feature explorer, counterfactual matrix, steering lab, repair review |
| `src/workspace/` | Snapshots, patch approval, diagnostics |
| `src/logging/` | Output channel and redaction |
| `src/security/` | Webview CSP and path containment |
| `media/` | HTML/CSS/vanilla JS assets |
| `test/` | Unit, integration, and fixture tests |

See `docs/architecture.md` in the repository for the full design.
