'use strict';

const assert = require('node:assert/strict');
const vscode = require('vscode');
const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');

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
  console.log('CRAFT-Sec Extension Host checks passed.');
}

module.exports = { run };
