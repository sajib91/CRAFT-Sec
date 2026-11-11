'use strict';

const vscode = require('vscode');

const SECTION = 'craftsec';

/**
 * @typedef {Object} ExtensionSettings
 * @property {string} pythonPath
 * @property {boolean} autoStart
 * @property {string} logLevel
 * @property {boolean} showStatusBarItem
 */

/** @returns {vscode.WorkspaceConfiguration} */
function getConfiguration() {
  return vscode.workspace.getConfiguration(SECTION);
}

/** @returns {ExtensionSettings} */
function readSettings() {
  const configuration = getConfiguration();
  return {
    pythonPath: configuration.get('backend.pythonPath', ''),
    autoStart: configuration.get('backend.autoStart', false),
    logLevel: configuration.get('logging.level', 'info'),
    showStatusBarItem: configuration.get('ui.showStatusBarItem', true)
  };
}

/**
 * Subscribe to CRAFT-Sec configuration changes.
 *
 * @param {(event: vscode.ConfigurationChangeEvent, settings: ExtensionSettings) => void} listener
 * @returns {vscode.Disposable}
 */
function onSettingsChanged(listener) {
  return vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration(SECTION)) {
      listener(event, readSettings());
    }
  });
}

module.exports = { SECTION, getConfiguration, readSettings, onSettingsChanged };
