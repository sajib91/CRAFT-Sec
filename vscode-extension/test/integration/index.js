'use strict';

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

async function run() {
  const manifest = require('../../package.json');
  const extensionId = `${manifest.publisher}.${manifest.name}`;
  const extension = vscode.extensions.getExtension(extensionId);

  assert.ok(extension, `extension ${extensionId} must be discoverable`);
  await extension.activate();
  assert.equal(extension.isActive, true, 'extension must activate');

  const commands = await vscode.commands.getCommands(true);
  for (const command of Object.values(COMMANDS)) {
    assert.ok(commands.includes(command), `${command} must be registered`);
  }

  const fabricatedDiagnostics = vscode.languages
    .getDiagnostics()
    .filter(([, diagnostics]) =>
      diagnostics.some((diagnostic) => diagnostic.source === DIAGNOSTIC_SOURCE)
    );
  assert.equal(
    fabricatedDiagnostics.length,
    0,
    'activation must not publish hardcoded CRAFT-Sec diagnostics'
  );

  const contributes = extension.packageJSON.contributes;
  const container = contributes.viewsContainers.activitybar.find(
    (entry) => entry.id === CONTAINER_ID
  );
  assert.ok(container, 'activity bar container must be contributed');

  const sidebar = contributes.views[CONTAINER_ID].find((view) => view.id === VIEW_ID);
  assert.ok(sidebar, 'sidebar webview must be contributed');
  assert.equal(sidebar.type, 'webview');

  const configuration = vscode.workspace.getConfiguration('craftsec');
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
