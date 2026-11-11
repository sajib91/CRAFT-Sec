'use strict';

const { COMMANDS, CONTAINER_ID } = require('../constants');
const { getCommandDefinition } = require('./definitions');

const REVEAL_CONTAINER_COMMAND = `workbench.view.extension.${CONTAINER_ID}`;

/**
 * Register the dashboard command.
 *
 * Revealing the Activity Bar container is the dashboard action; no analysis
 * runs and no result notification is shown.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerDashboardCommand({ vscode, logger, registry }) {
  const definition = getCommandDefinition(COMMANDS.openSecurityDashboard);

  registry.register(definition.id, async () => {
    try {
      await vscode.commands.executeCommand(REVEAL_CONTAINER_COMMAND);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error(`${definition.title} failed: ${message}`, error);

      const action = await vscode.window.showErrorMessage(
        'CRAFT-Sec: Unable to open the Security Dashboard.',
        'Show Logs'
      );
      if (action === 'Show Logs') {
        logger.show();
      }
    }
  });
}

module.exports = { registerDashboardCommand, REVEAL_CONTAINER_COMMAND };
