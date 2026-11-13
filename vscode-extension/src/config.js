'use strict';

const vscode = require('vscode');

const {
  SECTION,
  DEFAULT_BACKEND_URL,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEALTH_TIMEOUT_MS
} = require('./api/configurationService');

/**
 * @typedef {Object} ExtensionSettings
 * @property {string} pythonPath
 * @property {boolean} autoStart
 * @property {string} backendUrl
 * @property {number} requestTimeoutMs
 * @property {number} healthTimeoutMs
 * @property {boolean} sendSourceText
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
    backendUrl: configuration.get('backend.url', DEFAULT_BACKEND_URL),
    requestTimeoutMs: configuration.get('backend.requestTimeoutMs', DEFAULT_REQUEST_TIMEOUT_MS),
    healthTimeoutMs: configuration.get('backend.healthTimeoutMs', DEFAULT_HEALTH_TIMEOUT_MS),
    sendSourceText: configuration.get('privacy.sendSourceText', true),
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
