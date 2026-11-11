# CRAFT-Sec VS Code Extension

JavaScript VS Code client for the CRAFT-Sec security framework.

## Status

**Extension shell with a security dashboard.** The extension activates, registers its commands, settings, output channel, status bar item, Activity Bar container, sidebar launcher, and an editor-area **CRAFT-Sec Security Dashboard** panel. The dashboard provides 11 navigable sections and renders only the state supplied by the extension host. Every analysis command is connected to the `SecurityEngineService` interface, but the current `UnavailableSecurityEngineService` reports that the local engine is unavailable. It does **not** start the Python backend or perform analysis. Detection, SAE features, counterfactuals, steering, repair, and verification are not implemented.

No analysis results, probabilities, or causal claims are produced by this extension. The dashboard starts empty. An explicitly labeled demo preview can populate illustrative overview, finding, CWE, and scan-history values; it deliberately leaves SAE features, interactions, steering, explanations, repairs, verification checks, and reports empty. Commands show cancellable progress while they wait and then report the engine error; they never show a placeholder success message.

## Manifest contributions

| Contribution | Identifier | Purpose |
|---|---|---|
| Activity bar container | `craftsec` | CRAFT-Sec entry in the Activity Bar |
| Sidebar webview | `craftsec.sidebar` | Activity Bar launcher for the editor-area dashboard |
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
| Command | `craftsec.openSecurityDashboard` | Open or reveal the CRAFT-Sec Security Dashboard panel |

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

## Security dashboard

`craftsec.openSecurityDashboard` opens (or reveals) a singleton editor-area webview panel titled **CRAFT-Sec Security Dashboard**. The Activity Bar sidebar is a launcher that sends one message, `openDashboard`.

The dashboard has 11 sections: Overview, Security Scan, Vulnerabilities, SAE Features, Feature Interactions, Security Steering, Explanations, Automated Repair, Verification, Research Reports, and Settings. Overview shows total findings, severity counts, vulnerability and CWE distributions, verification status, and recent scan history.

- **Empty by default.** Counts are `null` and lists are empty until a real scan result is supplied. The dashboard never estimates missing values.
- **Explicit demo preview.** The **Load demo preview** button requests a separately labeled data mode with 18 illustrative findings, matching severity and CWE totals, and scan history. It does not simulate SAE activations, feature interactions, steering, explanations, repairs, verification checks, or reports.
- **Backend-ready state.** The panel controller calls an injected `getState(dataMode)` function. `live` currently falls back to the empty state because no backend exists; this is deliberate.
- **Restricted execution.** Dashboard action buttons can execute only the nine engine-backed commands in the controller's allowlist, with no arguments. The dashboard cannot execute arbitrary VS Code commands, write files, apply patches, or start a backend.
- **Validation.** Inbound messages are checked for shape and value. Unknown or malformed messages are logged and ignored. Engine command failures produce an error notice, never a success notice.
- **Webview security.** The shell uses a per-render nonce, a restrictive CSP (`default-src 'none'`, no network or inline execution), local resource roots, escaped embedded JSON, and DOM text APIs for dynamic content. The sidebar launcher has its own nonce CSP and can only post `openDashboard`.
- **Accessibility and theming.** Navigation uses an accessible vertical tablist with keyboard support, tables have captions and scoped headers, status changes use a live region, and styling uses VS Code theme tokens with reduced-motion and forced-colors handling.
- **Read-only settings.** Settings are displayed read-only; **Open VS Code Settings** and **Show logs** delegate to VS Code.

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

The unit suite (67 tests) validates the manifest, command definitions and registration, editor/workspace validation, progress and error behavior, the unavailable service contract, shared identifiers, icon dimensions, the dashboard model and demo data, webview CSP/message handling, dashboard HTML and client-source constraints, the sidebar launcher, and the no-TypeScript constraint. The integration test launches a real VS Code Extension Host with `@vscode/test-electron`, activates the extension, checks all registered commands, the Activity Bar container, sidebar view, and settings defaults, opens the dashboard, and verifies that a second invocation reuses the same panel tab. Tests never download models or call a security engine.

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
| `src/commands/dashboardCommand.js` | Open or reveal the dashboard panel |
| `src/commands/utilityCommands.js` | Show status and show logs |
| `src/api/securityEngineService.js` | Service contract and unavailable implementation |
| `src/logging/output.js` | Log output channel and level filtering |
| `src/views/statusBar.js` | Status bar item and visibility setting |
| `src/webviews/sidebarView.js` | Activity Bar launcher provider and `openDashboard` validation |
| `src/webviews/sidebarHtml.js` | Nonce-CSP launcher markup |
| `src/webviews/dashboardPanel.js` | Singleton panel controller, message validation, and command allowlist |
| `src/webviews/dashboardModel.js` | 11-section navigation, actions, empty state, and labeled demo state |
| `src/webviews/dashboardHtml.js` | Accessible dashboard shell with nonce CSP and embedded state |
| `src/webviews/csp.js` | Nonce and Content Security Policy construction |
| `src/webviews/html.js` | Attribute/text escaping and safe inline JSON serialization |
| `src/backend/` | Engine spawn, handshake, health, restart (future) |
| `src/api/` | Security-engine service contract; authenticated client, SSE, schema validation (future) |
| `src/jobs/` | Job lifecycle and progress routing (future) |
| `src/workspace/` | Snapshots, patch approval, diagnostics (future) |
| `src/security/` | Shared webview and path containment helpers (future) |
| `media/` | Icons, dashboard CSS/JS, and sidebar launcher CSS/JS |
| `test/` | Unit and Extension Host integration tests |

See `docs/architecture.md` in the repository for the full design.
