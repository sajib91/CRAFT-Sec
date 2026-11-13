'use strict';

const vscode = require('vscode');
const { createSecurityEngineService } = require('./api/securityEngineService');
const { createConfigurationService, isLoopbackBackendUrl } = require('./api/configurationService');
const { createLogger } = require('./logging/output');
const { createStatusBar } = require('./views/statusBar');
const { registerCommands } = require('./commands');
const { registerSidebarView } = require('./webviews/sidebarView');
const { DashboardPanelController } = require('./webviews/dashboardPanel');
const { buildDashboardState } = require('./webviews/dashboardModel');
const { registerDiagnostics } = require('./diagnostics');
const { onSettingsChanged, readSettings } = require('./config');

/** @type {import('./logging/output').Logger | undefined} */
let logger;

/**
 * Activate the CRAFT-Sec extension.
 *
 * This starts no Python process and performs no analysis. It connects to an
 * already-running backend, checks its health without sending source code, and
 * creates the dashboard, command registry, sidebar launcher, and status bar.
 *
 * @param {import('vscode').ExtensionContext} context
 */
function activate(context) {
  logger = createLogger();
  logger.info('Activating CRAFT-Sec Security Framework.');

  const statusBar = createStatusBar();
  const configurationService = createConfigurationService({ vscode });
  const service = createSecurityEngineService({ configurationService, logger });

  /**
   * Check liveness without sending source. The result only controls status
   * text; analysis availability is reported by each backend operation.
   *
   * @returns {Promise<object | undefined>}
   */
  async function checkBackendHealth() {
    statusBar.setBackendStatus('checking');
    try {
      const health = await service.health({});
      const detail =
        `CRAFT-Sec backend v${health.version} reachable. ` +
        'Analysis stages are reported individually by the backend.';
      statusBar.setBackendStatus('reachable', detail);
      logger.info(
        `CRAFT-Sec backend v${health.version} reachable at the configured URL ` +
          `(API ${health.apiVersion}).`
      );
      const settings = readSettings();
      if (!isLoopbackBackendUrl(settings.backendUrl)) {
        logger.warn(
          'craftsec.backend.url points outside loopback. Source text is sent only for explicit ' +
            'user-invoked commands and only when craftsec.privacy.sendSourceText is enabled.'
        );
      }
      return health;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      statusBar.setBackendStatus('unavailable', message);
      logger.warn(`CRAFT-Sec backend health check failed: ${message}`);
      return undefined;
    }
  }

  const diagnostics = registerDiagnostics({ vscode, logger });
  const dashboard = new DashboardPanelController({
    vscode,
    extensionUri: context.extensionUri,
    logger,
    getState: (dataMode) =>
      buildDashboardState({
        dataMode,
        settings: readSettings()
      })
  });
  const commandRegistry = registerCommands({
    vscode,
    service,
    logger,
    dashboard,
    diagnostics: diagnostics.controller
  });
  const sidebarRegistration = registerSidebarView(context, logger);

  const settingsSubscription = onSettingsChanged((event) => {
    if (event.affectsConfiguration('craftsec.logging.level')) {
      logger.applySettings();
    }
    if (event.affectsConfiguration('craftsec.ui.showStatusBarItem')) {
      statusBar.applySettings();
    }
    if (event.affectsConfiguration('craftsec')) {
      dashboard.refresh();
    }
    if (
      event.affectsConfiguration('craftsec.backend.url') ||
      event.affectsConfiguration('craftsec.backend.requestTimeoutMs') ||
      event.affectsConfiguration('craftsec.backend.healthTimeoutMs')
    ) {
      void checkBackendHealth();
    }
    logger.debug('CRAFT-Sec settings updated.');
  });

  context.subscriptions.push(
    logger,
    statusBar,
    dashboard,
    diagnostics,
    sidebarRegistration,
    settingsSubscription,
    commandRegistry
  );

  if (readSettings().autoStart) {
    logger.warn(
      'craftsec.backend.autoStart is reserved for a future process manager. The extension ' +
        'connects to an already-running backend and does not start one.'
    );
  }

  void checkBackendHealth();
  logger.info('CRAFT-Sec activated.');

  return { service, configurationService, checkBackendHealth };
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
