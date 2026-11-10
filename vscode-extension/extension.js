'use strict';

const vscode = require('vscode');

/**
 * Minimal Phase 1 activation stub.
 *
 * This does not start the Python engine or perform analysis. It exists so the
 * extension manifest is valid and the scaffold can be loaded by VS Code.
 *
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.text = '$(shield) CRAFT-Sec';
  statusItem.tooltip = 'CRAFT-Sec scaffold: analysis engine not implemented';
  statusItem.command = 'craftsec.showStatus';
  statusItem.show();

  const showStatus = vscode.commands.registerCommand('craftsec.showStatus', () => {
    vscode.window.showInformationMessage(
      'CRAFT-Sec scaffold. Detection, SAE analysis, counterfactuals, steering, repair, and verification are not implemented yet.'
    );
  });

  context.subscriptions.push(statusItem, showStatus);
}

function deactivate() {}

module.exports = { activate, deactivate };
