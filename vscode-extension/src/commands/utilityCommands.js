'use strict';

const { COMMANDS } = require('../constants');

const UTILITY_COMMANDS = Object.freeze([COMMANDS.showStatus, COMMANDS.showLogs]);

/**
 * @param {object} health
 * @returns {string}
 */
function describeHealth(health) {
  if (!health || health.status !== 'ok') {
    return 'The CRAFT-Sec backend responded, but its health state is unknown.';
  }
  return (
    `CRAFT-Sec backend v${health.version} is reachable (API ${health.apiVersion}). ` +
    'All declared analysis capabilities currently report unavailable, so no findings, ' +
    'scores, or security conclusions are produced.'
  );
}

/**
 * Register the status and log commands.
 *
 * The status command checks the real backend and reports an error when it
 * cannot be reached. It never claims that an analysis succeeded.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerUtilityCommands({ vscode, service, logger, registry }) {
  registry.register(COMMANDS.showStatus, async () => {
    let health;
    try {
      health = await service.health({});
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn(`Backend health check failed: ${message}`);
      const action = await vscode.window.showErrorMessage(
        `CRAFT-Sec: ${message}`,
        'Show Logs',
        'Open Settings'
      );
      if (action === 'Show Logs') {
        logger.show();
      } else if (action === 'Open Settings') {
        await vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'craftsec.backend.url'
        );
      }
      return;
    }

    const action = await vscode.window.showInformationMessage(
      describeHealth(health),
      'Open Security Dashboard',
      'Show Logs'
    );

    if (action === 'Open Security Dashboard') {
      await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
    } else if (action === 'Show Logs') {
      logger.show();
    }
  });

  registry.register(COMMANDS.showLogs, () => {
    logger.show();
  });
}

module.exports = { registerUtilityCommands, describeHealth, UTILITY_COMMANDS };
