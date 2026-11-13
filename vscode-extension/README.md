# CRAFT-Sec VS Code Extension

JavaScript VS Code client for the CRAFT-Sec security framework.

## Status

**Extension shell with a live local-backend transport and diagnostics pipeline.** The extension activates, registers its commands, settings, output channel, status bar item, Activity Bar container, sidebar launcher, an editor-area **CRAFT-Sec Security Dashboard** panel, and native VS Code vulnerability diagnostics with hover explanations and repair Quick Fixes. The dashboard provides 11 navigable sections and renders only the state supplied by the extension host. Every analysis command is connected to a `SecurityEngineService` backed by the versioned FastAPI engine. Health checks, file scans, selection detection requests, and workspace scans reach the real backend; detection, SAE features, counterfactuals, steering, repair generation, and verification remain unimplemented and return explicit `unavailable` stages. The extension does **not** start the Python backend.

No analysis results, probabilities, or causal claims are produced by this extension. The dashboard starts empty. An explicitly labeled demo preview can populate illustrative overview, finding, CWE, and scan-history values; it deliberately leaves SAE features, interactions, steering, explanations, repairs, verification checks, and reports empty. Commands show cancellable progress while they contact the backend and report transport or validation errors; they never show a placeholder success message. Diagnostics, hover content, and repair Quick Fixes are generated only from validated backend scan results. An empty findings list with `analysisAvailable: false` is reported as unavailable analysis, never as a clean scan.

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
- `scanWorkspace` requires at least one local file-system workspace folder. `verifyRepair` requires an active saved editor because the backend verification contract extends the file context.
- Validation failures are logged as warnings and shown as error messages with a **Show Logs** action.
- Engine calls run under `window.withProgress` with a cancellable notification. Cancellation is logged and produces no error dialog.
- Every engine-backed command calls its declared `SecurityEngineService` method. Transport failures, timeouts, problem details, and schema mismatches are reported instead of inventing a result.
- Successful scan results are validated and published as diagnostics; failed or cancelled scans never alter the Problems panel.
- `craftsec.repairVulnerability` accepts an optional finding context from a diagnostic Quick Fix while retaining its no-argument Command Palette and dashboard behavior. A finding for another file is rejected before the engine call.
- A single `CommandRegistry` owns all 12 registrations and is disposed with the extension.

## Backend transport and privacy

- `craftsec.backend.url` points at an already-running backend. Only an HTTP(S) origin is accepted; credentials, paths, queries, and fragments are rejected.
- The client calls `GET /api/v1/health`, `POST /api/v1/scan/file`, `POST /api/v1/scan/workspace`, and the analysis routes under `/api/v1`. Timeouts abort the request and are reported to the user.
- An optional bearer token is read from the extension host environment (`CRAFTSEC_API_TOKEN`, with `CRAFTSEC_ENGINE_TOKEN` as a legacy alias). Tokens are never stored in settings or logs.
- File and selection requests include the current editor buffer as `sourceText` and the selected code as `selectedText` only when `craftsec.privacy.sendSourceText` is enabled. The commands are always explicitly user-invoked. Disabling the setting sends only paths and ranges; the backend then reads the saved file from disk.
- Workspace scans send folder name, path, and file-URI metadata only, never file contents.
- Health checks send no source code.
- Every response is validated before use. The backend's `partial`/`unavailable` statuses and `analysisAvailable: false` are preserved; they are never converted into a clean scan.

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

## Vulnerability diagnostics

The scan commands feed successful backend results into a native VS Code `DiagnosticCollection`. No finding is hardcoded in the extension: an empty backend result produces no diagnostics, and the extension is empty at activation.

- **Required result contract.** A scan result is either a findings array or `{ findings: [...], scope?: { uris: [...] } }`. Each finding requires `id`, `message`, `severity`, and a `location` with a `file:` URI and a zero-based `range`; `cwe`, `ruleId`, `evidence`, `explanation`, `sourceReferences`, and `repair` are optional.
- **Severity mapping.** `critical` and `high` become errors, `medium` becomes a warning, `low` becomes information, and `info` becomes a hint. Severity is taken from the backend, never inferred from the message.
- **Problems panel.** The diagnostic uses the backend range, the concise backend message, source `CRAFT-Sec`, and the CWE identifier as clickable diagnostic code when supplied. Related information carries backend evidence and source references.
- **Hover explanations.** Hovering a finding shows its message, severity, CWE, rule ID, backend explanation, evidence, source references, and repair eligibility. Missing explanation, sources, or repair metadata are stated explicitly rather than filled in.
- **Repair Quick Fix.** A Quick Fix appears only when the backend sets `repair.eligible` to `true`. It invokes the existing `craftsec.repairVulnerability` command with the finding ID, document URI, range, CWE, and rule ID. The extension does not edit code or generate a patch itself.
- **Validation and containment.** Malformed findings are rejected and logged; a malformed result envelope is rejected without clearing existing diagnostics. Findings outside an open workspace folder and non-`file:` URIs are never published. `scope.uris` or the scanned document URI clears stale diagnostics for the covered files.
- **No detector findings yet.** Scans reach the real backend, but the detector and evidence stages are unimplemented, so responses contain `analysisAvailable: false` and no findings. The extension reports that state explicitly and does not populate diagnostics from a simulated analysis. Providers are tested with backend-shaped fixtures.

## Settings

| Setting | Default | Behavior |
|---|---|---|
| `craftsec.backend.url` | `http://127.0.0.1:8765` | Base URL of the already-running FastAPI backend; must be an HTTP(S) origin |
| `craftsec.backend.requestTimeoutMs` | `30000` | Timeout for scan and analysis requests |
| `craftsec.backend.healthTimeoutMs` | `3000` | Timeout for backend health checks |
| `craftsec.privacy.sendSourceText` | `true` | Send the current buffer and selection with explicitly user-invoked file/selection requests |
| `craftsec.backend.pythonPath` | empty | Reserved for a future backend process manager; the extension does not start an engine |
| `craftsec.backend.autoStart` | `false` | Reserved; enabling it logs a warning because no engine is started |
| `craftsec.logging.level` | `info` | Filters messages written to the CRAFT-Sec output channel |
| `craftsec.ui.showStatusBarItem` | `true` | Shows or hides the CRAFT-Sec status bar item |

The backend must be started separately, for example from `security-engine/`:

```bash
../.venv/bin/python -m craftsec --host 127.0.0.1 --port 8765
```

Set `CRAFTSEC_WORKSPACE_ROOTS` to the folders the backend may inspect. Set the
same `CRAFTSEC_API_TOKEN` in the extension host environment when backend bearer
authentication is enabled.

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

The unit suite (167 tests) validates the manifest, command definitions and registration, editor/workspace validation, progress and error behavior, the unavailable and HTTP service contracts, backend URL/timeout/privacy configuration, request mapping and consent omission, API transport failures and cancellation, response schema validation, workspace metadata limits, shared identifiers, icon dimensions, the dashboard model and demo data, webview CSP/message handling, dashboard HTML and client-source constraints, the sidebar launcher, the backend finding contract, diagnostic publication and clearing, severity/CWE mapping, workspace containment, hover content and escaping, repair Quick Fix eligibility and arguments, provider registration/disposal, and the no-TypeScript constraint. The integration test launches a real VS Code Extension Host with `@vscode/test-electron`, starts the Python backend against a disposable workspace, points the extension at that backend, checks health and unreachable-backend handling, scans an unsaved buffer and verifies the returned SHA-256 matches the buffer rather than the disk copy, disables source sharing and verifies the backend falls back to the saved file, scans the workspace and a selection, verifies that unavailable analysis never publishes findings, and opens the singleton dashboard tab. Tests never download models.

## Extension Development Host

1. Open the repository root in VS Code.
2. Install the recommended extensions from `.vscode/extensions.json` if prompted.
3. Open **Run and Debug** and select **Run CRAFT-Sec Extension** from `.vscode/launch.json`.
4. Press F5. The Extension Development Host loads `vscode-extension/` as the development extension.
5. Open the CRAFT-Sec shield in the Activity Bar or run a `CRAFT-Sec:` command from the Command Palette.

To run the integration test, use `npm run extension:test:integration`. It prefers a locally installed VS Code (`CRAFTSEC_VSCODE_EXECUTABLE` overrides the path) and otherwise lets `@vscode/test-electron` download a stable build into `.vscode-test/`, which is gitignored.

## Packaging note

The VSIX build uses `vsce package --no-dependencies` because npm workspaces hoist dependencies to the repository root; without this flag, `vsce` would package the entire repository. The current VSIX contains 50 files and about 74.6 KB, including the dashboard, launcher, and diagnostics modules. The current extension does not require `ajv` at runtime, but a bundling step must be added before runtime dependencies are used or the extension is published. The VSIX also lacks a repository URL and license, so it is a development artifact only.

## Layout

| Path | Purpose |
|------|---------|
| `src/extension.js` | Activation entry point and disposable registration |
| `src/config.js` | Typed settings access and change subscription |
| `src/constants.js` | Command, container, and view IDs shared with tests |
| `src/commands/index.js` | Registers all commands and returns one composite disposable |
| `src/commands/definitions.js` | Canonical feature-command metadata and service mapping |
| `src/commands/registry.js` | Duplicate-safe registration and composite disposal |
| `src/commands/validation.js` | Re-exports the workspace validation and request builders |
| `src/commands/runEngineCommand.js` | Cancellable progress, cancellation, and error reporting |
| `src/commands/registerEngineCommand.js` | Binds a command definition to a service method |
| `src/commands/scanCommands.js` | Scan Current File, Scan Selection, Scan Workspace |
| `src/commands/analysisCommands.js` | Explain, security features, counterfactual analysis |
| `src/commands/repairCommands.js` | Generate secure code, repair, verify |
| `src/commands/dashboardCommand.js` | Open or reveal the dashboard panel |
| `src/commands/utilityCommands.js` | Show status and show logs |
| `src/api/securityEngineService.js` | Service contract, HTTP implementation, request mapping, unavailable fallback |
| `src/api/apiClient.js` | Fetch transport, timeouts, cancellation, problem details, bounded responses |
| `src/api/configurationService.js` | Backend URL/timeout validation, environment token, source-sharing setting |
| `src/api/securityResultService.js` | Health, envelope, scan, detection, and analysis response validation |
| `src/workspace/workspaceService.js` | Editor/workspace request builders, source consent, workspace metadata limits |
| `src/diagnostics/findingModel.js` | Backend finding validation, severity/CWE mapping, and range helpers |
| `src/diagnostics/diagnosticController.js` | DiagnosticCollection, finding store, scope clearing, and Problems panel publication |
| `src/diagnostics/hoverProvider.js` | Hover explanations built only from backend finding fields |
| `src/diagnostics/codeActionProvider.js` | Repair Quick Fixes for backend-eligible findings |
| `src/diagnostics/index.js` | Diagnostic provider registration and disposal |
| `src/security/paths.js` | Workspace containment checks for backend-supplied paths |
| `src/logging/output.js` | Log output channel and level filtering |
| `src/views/statusBar.js` | Status bar item and visibility setting |
| `src/webviews/sidebarView.js` | Activity Bar launcher provider and `openDashboard` validation |
| `src/webviews/sidebarHtml.js` | Nonce-CSP launcher markup |
| `src/webviews/dashboardPanel.js` | Singleton panel controller, message validation, and command allowlist |
| `src/webviews/dashboardModel.js` | 11-section navigation, actions, empty state, and labeled demo state |
| `src/webviews/dashboardHtml.js` | Accessible dashboard shell with nonce CSP and embedded state |
| `src/webviews/csp.js` | Nonce and Content Security Policy construction |
| `src/webviews/html.js` | Attribute/text escaping and safe inline JSON serialization |
| `src/backend/` | Engine process manager and handshake (future; the extension connects to an already-running backend) |
| `src/jobs/` | Job lifecycle and progress routing (future) |
| `src/workspace/` | Request builders now; snapshots and patch approval (future) |
| `src/security/` | Workspace path containment; shared webview helpers (future) |
| `media/` | Icons, dashboard CSS/JS, and sidebar launcher CSS/JS |
| `test/` | Unit and Extension Host integration tests |

See `docs/architecture.md` in the repository for the full design.
