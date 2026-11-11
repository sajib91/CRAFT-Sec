'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');

/**
 * Register the dashboard command.
 *
 * The command opens the editor-area dashboard panel. It does not run analysis
 * and never reports a scan result.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   dashboard: import('../webviews/dashboardPanel').DashboardPanelController
 * }} context
 */
function registerDashboardCommand({ vscode, logger, registry, dashboard }) {
  const definition = getCommandDefinition(COMMANDS.openSecurityDashboard);

  registry.register(definition.id, async () => {
    try {
      dashboard.open();
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

module.exports = { registerDashboardCommand };
