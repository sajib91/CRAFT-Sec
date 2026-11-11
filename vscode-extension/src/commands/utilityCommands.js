'use strict';

const { COMMANDS } = require('../constants');

const STATUS_MESSAGE =
  'CRAFT-Sec Security Framework is active. The local security engine is not available in this ' +
  'build, so no analysis, repair, or verification results can be produced.';

const UTILITY_COMMANDS = Object.freeze([COMMANDS.showStatus, COMMANDS.showLogs]);

/**
 * Register the status and log commands.
 *
 * The status message reports the real state of the extension; it never claims
 * that an analysis succeeded.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerUtilityCommands({ vscode, logger, registry }) {
  registry.register(COMMANDS.showStatus, async () => {
    const action = await vscode.window.showInformationMessage(
      STATUS_MESSAGE,
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

module.exports = { registerUtilityCommands, STATUS_MESSAGE, UTILITY_COMMANDS };
