'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const vscode = require('vscode');
const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');
const { DASHBOARD_TITLE } = require('../../src/webviews/dashboardPanel');
const { DIAGNOSTIC_SOURCE } = require('../../src/diagnostics/findingModel');

async function waitForTab(label, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const tabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs);
    const tab = tabs.find((entry) => entry.label === label);
    if (tab) {
      return tab;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return undefined;
}

/**
 * @param {string} text
 * @returns {string}
 */
function sha256(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function craftsecDiagnostics() {
  return vscode.languages
    .getDiagnostics()
    .flatMap(([uri, diagnostics]) =>
      diagnostics
        .filter((diagnostic) => diagnostic.source === DIAGNOSTIC_SOURCE)
        .map((diagnostic) => ({ uri, diagnostic }))
    );
}

async function assertBackendHealth(api, backendUrl) {
  const health = await api.checkBackendHealth();
  assert.ok(health, `the extension must reach the backend at ${backendUrl}`);
  assert.equal(health.status, 'ok');
  assert.equal(health.apiVersion, 'v1');
  assert.equal(typeof health.capabilities, 'object');

  const direct = await api.service.health({});
  assert.equal(direct.service, health.service);
  assert.equal(direct.version, health.version);
}

async function run() {
  const manifest = require('../../package.json');
  const extensionId = `${manifest.publisher}.${manifest.name}`;
  const extension = vscode.extensions.getExtension(extensionId);

  assert.ok(extension, `extension ${extensionId} must be discoverable`);
  const api = await extension.activate();
  assert.equal(extension.isActive, true, 'extension must activate');
  assert.ok(api, 'activation must expose the backend service and health check');
  assert.equal(typeof api.checkBackendHealth, 'function');
  assert.equal(typeof api.service.health, 'function');
  assert.equal(typeof api.configurationService.get, 'function');

  const backendUrl = process.env.CRAFTSEC_E2E_BACKEND_URL;
  const workspacePath = process.env.CRAFTSEC_E2E_WORKSPACE;
  const sourcePath = process.env.CRAFTSEC_E2E_FILE;
  const diskSha256 = process.env.CRAFTSEC_E2E_DISK_SHA256;
  assert.ok(backendUrl, 'CRAFTSEC_E2E_BACKEND_URL must be provided by runTest.js');
  assert.ok(workspacePath, 'CRAFTSEC_E2E_WORKSPACE must be provided by runTest.js');
  assert.ok(sourcePath, 'CRAFTSEC_E2E_FILE must be provided by runTest.js');
  assert.ok(diskSha256, 'CRAFTSEC_E2E_DISK_SHA256 must be provided by runTest.js');

  const configuration = vscode.workspace.getConfiguration('craftsec');
  await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Workspace);
  await configuration.update('privacy.sendSourceText', true, vscode.ConfigurationTarget.Workspace);

  await assertBackendHealth(api, backendUrl);

  const commands = await vscode.commands.getCommands(true);
  for (const command of Object.values(COMMANDS)) {
    assert.ok(commands.includes(command), `${command} must be registered`);
  }

  assert.equal(
    craftsecDiagnostics().length,
    0,
    'activation must not publish hardcoded CRAFT-Sec diagnostics'
  );

  // End-to-end file scan: the unsaved editor buffer must be what the backend
  // hashes, not the stale saved copy on disk.
  const document = await vscode.workspace.openTextDocument(sourcePath);
  const editor = await vscode.window.showTextDocument(document, { preview: false });
  assert.equal(editor.document.isDirty, false);

  const inserted = '# E2E unsaved marker\n';
  assert.equal(
    await editor.edit((builder) => builder.insert(new vscode.Position(0, 0), inserted)),
    true
  );
  assert.equal(editor.document.isDirty, true);
  const unsavedText = editor.document.getText();
  assert.notEqual(unsavedText, undefined);
  assert.notEqual(sha256(unsavedText), diskSha256);

  const scan = await vscode.commands.executeCommand(COMMANDS.scanCurrentFile);
  assert.ok(scan, 'the file scan must return a validated backend response');
  assert.equal(scan.operation, 'scan_file');
  assert.equal(scan.apiVersion, 'v1');
  assert.equal(scan.analysisAvailable, false, 'analysis is not implemented and must say so');
  assert.deepEqual(scan.findings, [], 'no finding may be fabricated when analysis is unavailable');
  assert.equal(scan.filesScanned, 1);
  assert.equal(
    scan.file.path,
    fs.realpathSync(sourcePath),
    'the backend must report the resolved path of the scanned file'
  );
  assert.ok(scan.file.uri.startsWith('file:'), 'the scanned file must be a file URI');
  assert.equal(
    scan.file.sha256,
    sha256(unsavedText),
    'the backend must hash the unsaved editor buffer, not the disk copy'
  );
  assert.notEqual(scan.file.sha256, diskSha256);
  assert.equal(
    craftsecDiagnostics().length,
    0,
    'an unavailable analysis must not publish diagnostics'
  );

  // With source sharing disabled the backend must fall back to the saved file.
  await configuration.update('privacy.sendSourceText', false, vscode.ConfigurationTarget.Workspace);
  assert.equal(
    await editor.edit((builder) =>
      builder.insert(new vscode.Position(0, 0), '# E2E consent disabled\n')
    ),
    true
  );
  assert.notEqual(sha256(editor.document.getText()), diskSha256);

  const withoutConsent = await vscode.commands.executeCommand(COMMANDS.scanCurrentFile);
  assert.ok(withoutConsent);
  assert.equal(
    withoutConsent.file.sha256,
    diskSha256,
    'without consent the backend must inspect the saved file only'
  );

  await configuration.update('privacy.sendSourceText', true, vscode.ConfigurationTarget.Workspace);

  // Workspace scans are metadata-only and still report unavailable analysis.
  const workspaceScan = await vscode.commands.executeCommand(COMMANDS.scanWorkspace);
  assert.ok(workspaceScan);
  assert.equal(workspaceScan.operation, 'scan_workspace');
  assert.ok(workspaceScan.filesScanned >= 1);
  assert.equal(workspaceScan.analysisAvailable, false);
  assert.deepEqual(workspaceScan.findings, []);
  assert.ok(
    workspaceScan.scope.uris.every((uri) => uri.startsWith('file:')),
    'workspace scope must contain only file URIs'
  );

  // A selection scan exercises the detection transport and keeps the backend's
  // explicit unavailable state intact.
  editor.selection = new vscode.Selection(0, 0, 0, 10);
  const selectionScan = await vscode.commands.executeCommand(COMMANDS.scanSelection);
  assert.ok(selectionScan);
  assert.equal(selectionScan.operation, 'detection_analyze');
  assert.equal(selectionScan.analysisAvailable, false);
  assert.deepEqual(selectionScan.findings, []);
  assert.deepEqual(selectionScan.scope.uris, [document.uri.toString()]);

  // An unreachable backend must be reported as unavailable, never as a clean
  // analysis. Port 1 on loopback refuses connections immediately.
  await configuration.update(
    'backend.url',
    'http://127.0.0.1:1',
    vscode.ConfigurationTarget.Workspace
  );
  assert.equal(await api.checkBackendHealth(), undefined);
  await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Workspace);
  await assertBackendHealth(api, backendUrl);

  const contributes = extension.packageJSON.contributes;
  const container = contributes.viewsContainers.activitybar.find(
    (entry) => entry.id === CONTAINER_ID
  );
  assert.ok(container, 'activity bar container must be contributed');

  const sidebar = contributes.views[CONTAINER_ID].find((view) => view.id === VIEW_ID);
  assert.ok(sidebar, 'sidebar webview must be contributed');
  assert.equal(sidebar.type, 'webview');

  assert.equal(configuration.get('logging.level'), 'info');
  assert.equal(configuration.get('ui.showStatusBarItem'), true);

  await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
  const dashboardTab = await waitForTab(DASHBOARD_TITLE);
  assert.ok(dashboardTab, 'the dashboard panel must open in an editor tab');

  await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
  const dashboardTabs = vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .filter((entry) => entry.label === DASHBOARD_TITLE);
  assert.equal(dashboardTabs.length, 1, 'the dashboard panel must be a singleton');

  console.log('CRAFT-Sec Extension Host checks passed.');
}

module.exports = { run };
