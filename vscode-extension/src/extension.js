'use strict';

const vscode = require('vscode');
const { createSecurityEngineService } = require('./api/securityEngineService');
const { createLogger } = require('./logging/output');
const { createStatusBar } = require('./views/statusBar');
const { registerCommands } = require('./commands');
const { registerSidebarView } = require('./webviews/sidebarView');
const { onSettingsChanged, readSettings } = require('./config');

/** @type {import('./logging/output').Logger | undefined} */
let logger;

/**
 * Activate the CRAFT-Sec extension.
 *
 * This starts no Python process and performs no analysis. It creates the
 * security-engine service, registers commands against that interface,
 * registers the sidebar and status bar, and wires settings changes.
 *
 * @param {import('vscode').ExtensionContext} context
 */
function activate(context) {
  logger = createLogger();
  logger.info('Activating CRAFT-Sec Security Framework.');
  logger.info('The local security engine is not available in this build.');

  const statusBar = createStatusBar();
  const service = createSecurityEngineService();
  const commandRegistry = registerCommands({ vscode, service, logger });
  const sidebarRegistration = registerSidebarView(context, logger);

  const settingsSubscription = onSettingsChanged((event) => {
    if (event.affectsConfiguration('craftsec.logging.level')) {
      logger.applySettings();
    }
    if (event.affectsConfiguration('craftsec.ui.showStatusBarItem')) {
      statusBar.applySettings();
    }
    logger.debug('CRAFT-Sec settings updated.');
  });

  context.subscriptions.push(
    logger,
    statusBar,
    sidebarRegistration,
    settingsSubscription,
    commandRegistry
  );

  if (readSettings().autoStart) {
    logger.warn(
      'craftsec.backend.autoStart is enabled, but the security engine is not implemented in this build.'
    );
  }

  logger.info('CRAFT-Sec activated.');
}

/**
 * VS Code disposes the registered subscriptions after this hook. The logger is
 * only used to record the transition.
 */
function deactivate() {
  if (logger) {
    logger.info('CRAFT-Sec deactivated.');
    logger = undefined;
  }
}

module.exports = { activate, deactivate };
