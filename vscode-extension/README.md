# CRAFT-Sec VS Code Extension

JavaScript VS Code client for the CRAFT-Sec security framework.

## Status

**Extension shell only.** The extension activates, registers its commands, settings, output channel, status bar item, activity bar container, and sidebar webview. Every analysis command is connected to the `SecurityEngineService` interface, but the current `UnavailableSecurityEngineService` reports that the local engine is unavailable. It does **not** start the Python backend or perform analysis. Detection, SAE features, counterfactuals, steering, repair, and verification are not implemented.

No analysis results, probabilities, or causal claims are produced by this extension. Commands show cancellable progress while they wait and then report the engine error; they never show a placeholder success message.

## Manifest contributions

| Contribution | Identifier | Purpose |
|---|---|---|
| Activity bar container | `craftsec` | CRAFT-Sec entry in the Activity Bar |
| Sidebar webview | `craftsec.sidebar` | Scaffold status and planned-capability view |
| Command | `craftsec.showStatus` | Report the real extension and engine status |
| Command | `craftsec.showLogs` | Open the CRAFT-Sec output channel |
| Command | `craftsec.scanCurrentFile` | Scan the active saved file |
| Command | `craftsec.scanSelection` | Scan the selected code |
| Command | `craftsec.scanWorkspace` | Scan all open workspace folders |
| Command | `craftsec.explainVulnerability` | Explain the vulnerability in context |
| Command | `craftsec.analyzeSecurityFeatures` | Analyze security-relevant features |
| Command | `craftsec.counterfactualAnalysis` | Compare a selected code region with counterfactual variants |
| Command | `craftsec.generateSecureCode` | Generate secure code from editor context |
| Command | `craftsec.repairVulnerability` | Generate a repair proposal |
| Command | `craftsec.verifyRepair` | Verify a repair at workspace scope |
| Command | `craftsec.openSecurityDashboard` | Reveal the CRAFT-Sec Activity Bar container |

All commands use the `CRAFT-Sec` category. The extension activates on startup, on any of its commands, and when the sidebar view is opened.

## Command validation and service wiring

- File, selection, analysis, generation, and repair commands require a saved `file:` editor inside an open workspace folder.
- `scanSelection` and `counterfactualAnalysis` also require a non-empty selection.
- `scanWorkspace` and `verifyRepair` require at least one workspace folder; `verifyRepair` does not require an editor.
- Validation failures are logged as warnings and shown as error messages with a **Show Logs** action.
- Engine calls run under `window.withProgress` with a cancellable notification. Cancellation is logged and produces no error dialog.
- Every engine-backed command calls its declared `SecurityEngineService` method. Because the service is unavailable, the call rejects with `E_ENGINE_UNAVAILABLE` and the command reports the error instead of inventing a result.
- A single `CommandRegistry` owns all 12 registrations and is disposed with the extension.

The publisher is set to the explicit placeholder `your-publisher-id`. Replace it with the real Marketplace publisher ID before publishing; no publisher identity is claimed by this repository.

## Settings

| Setting | Default | Behavior |
|---|---|---|
| `craftsec.backend.pythonPath` | empty | Reserved for the future backend manager; the scaffold does not start an engine |
| `craftsec.backend.autoStart` | `false` | Reserved; enabling it logs a warning because no engine exists |
| `craftsec.logging.level` | `info` | Filters messages written to the CRAFT-Sec output channel |
| `craftsec.ui.showStatusBarItem` | `true` | Shows or hides the CRAFT-Sec status bar item |

## Development

Set up the repository once from the root:

```bash
npm run setup -- --cpu --with-analyzers
```

Then use the root commands:

```bash
npm run extension:lint
npm run extension:test
npm run extension:test:integration
npm run build
```

The unit tests validate the manifest, command definitions, command registration and disposal, editor/workspace validation, progress and error behavior, the unavailable service contract, shared command/view identifiers, icon dimensions, CSP behavior, and the no-TypeScript constraint. The integration test launches a real VS Code Extension Host with `@vscode/test-electron`, activates the extension, checks all registered commands, the activity bar container, sidebar view, and settings defaults, and executes the dashboard command. Tests never download models or call a security engine.

## Extension Development Host

1. Open the repository root in VS Code.
2. Install the recommended extensions from `.vscode/extensions.json` if prompted.
3. Open **Run and Debug** and select **Run CRAFT-Sec Extension** from `.vscode/launch.json`.
4. Press F5. The Extension Development Host loads `vscode-extension/` as the development extension.
5. Open the CRAFT-Sec shield in the Activity Bar or run a `CRAFT-Sec:` command from the Command Palette.

To run the integration test, use `npm run extension:test:integration`. It prefers a locally installed VS Code (`CRAFTSEC_VSCODE_EXECUTABLE` overrides the path) and otherwise lets `@vscode/test-electron` download a stable build into `.vscode-test/`, which is gitignored.

## Packaging note

The VSIX build uses `vsce package --no-dependencies` because npm workspaces hoist dependencies to the repository root; without this flag, `vsce` would package the entire repository. The current extension does not require `ajv` at runtime, but a bundling step must be added before runtime dependencies are used or the extension is published. The VSIX also lacks a repository URL and license, so it is a development artifact only.

## Layout

| Path | Purpose |
|------|---------|
| `src/extension.js` | Activation entry point and disposable registration |
| `src/config.js` | Typed settings access and change subscription |
| `src/constants.js` | Command, container, and view IDs shared with tests |
| `src/commands/index.js` | Registers all commands and returns one composite disposable |
| `src/commands/definitions.js` | Canonical feature-command metadata and service mapping |
| `src/commands/registry.js` | Duplicate-safe registration and composite disposal |
| `src/commands/validation.js` | Editor, workspace, file, and selection validation; request builders |
| `src/commands/runEngineCommand.js` | Cancellable progress, cancellation, and error reporting |
| `src/commands/registerEngineCommand.js` | Binds a command definition to a service method |
| `src/commands/scanCommands.js` | Scan Current File, Scan Selection, Scan Workspace |
| `src/commands/analysisCommands.js` | Explain, security features, counterfactual analysis |
| `src/commands/repairCommands.js` | Generate secure code, repair, verify |
| `src/commands/dashboardCommand.js` | Open security dashboard |
| `src/commands/utilityCommands.js` | Show status and show logs |
| `src/api/securityEngineService.js` | Service contract and unavailable implementation |
| `src/logging/output.js` | Log output channel and level filtering |
| `src/views/statusBar.js` | Status bar item and visibility setting |
| `src/webviews/sidebarView.js` | Webview view provider and strict CSP setup |
| `src/webviews/sidebarHtml.js` | Static, script-free sidebar HTML |
| `src/backend/` | Engine spawn, handshake, health, restart (future) |
| `src/api/` | Security-engine service contract; authenticated client, SSE, schema validation (future) |
| `src/jobs/` | Job lifecycle and progress routing (future) |
| `src/workspace/` | Snapshots, patch approval, diagnostics (future) |
| `src/security/` | Webview CSP and path containment helpers (future) |
| `media/` | Icon, activity bar SVG, sidebar CSS |
| `test/` | Unit, integration, and fixture tests |

See `docs/architecture.md` in the repository for the full design.
