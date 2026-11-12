'use strict';

const { COMMAND_DEFINITIONS } = require('./definitions');
const { CommandRegistry } = require('./registry');
const { registerScanCommands } = require('./scanCommands');
const { registerAnalysisCommands } = require('./analysisCommands');
const { registerRepairCommands } = require('./repairCommands');
const { registerDashboardCommand } = require('./dashboardCommand');
const { registerUtilityCommands, UTILITY_COMMANDS } = require('./utilityCommands');

/**
 * Registration order is deliberate: feature commands first, then the dashboard
 * and utility commands. A single registry owns every disposable.
 */
const COMMAND_REGISTRARS = Object.freeze([
  registerScanCommands,
  registerAnalysisCommands,
  registerRepairCommands,
  registerDashboardCommand,
  registerUtilityCommands
]);

/**
 * @returns {Set<string>}
 */
function expectedCommandIds() {
  return new Set([...COMMAND_DEFINITIONS.map((definition) => definition.id), ...UTILITY_COMMANDS]);
}

/**
 * Activation must never leave a partially registered command set. This check
 * also catches a definition that was added without a registrar.
 *
 * @param {CommandRegistry} registry
 */
function assertCompleteRegistry(registry) {
  const expected = expectedCommandIds();
  const actual = new Set(registry.ids());

  const missing = [...expected].filter((commandId) => !actual.has(commandId));
  if (missing.length > 0) {
    throw new Error(`CRAFT-Sec commands were not registered: ${missing.join(', ')}`);
  }

  const unexpected = [...actual].filter((commandId) => !expected.has(commandId));
  if (unexpected.length > 0) {
    throw new Error(`CRAFT-Sec registered undeclared commands: ${unexpected.join(', ')}`);
  }
}

/**
 * Register every CRAFT-Sec command.
 *
 * Dependencies are injected so unit tests can register commands against fake
 * VS Code and service objects without importing the VS Code runtime.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   dashboard: import('../webviews/dashboardPanel').DashboardPanelController,
 *   diagnostics: import('../diagnostics/diagnosticController').DiagnosticController
 * }} dependencies
 * @returns {CommandRegistry} One disposable that owns every registration.
 */
function registerCommands({ vscode, service, logger, dashboard, diagnostics }) {
  if (!vscode) {
    throw new TypeError('registerCommands requires a vscode API object.');
  }
  if (!service) {
    throw new TypeError('registerCommands requires a SecurityEngineService.');
  }
  if (!logger) {
    throw new TypeError('registerCommands requires a logger.');
  }
  if (!dashboard || typeof dashboard.open !== 'function') {
    throw new TypeError('registerCommands requires a dashboard controller.');
  }
  if (!diagnostics || typeof diagnostics.publishScanResult !== 'function') {
    throw new TypeError('registerCommands requires a diagnostics controller.');
  }

  const registry = new CommandRegistry(vscode, logger);
  const context = { vscode, service, logger, dashboard, diagnostics, registry };

  try {
    for (const register of COMMAND_REGISTRARS) {
      register(context);
    }
    assertCompleteRegistry(registry);
  } catch (error) {
    registry.dispose();
    throw error;
  }

  logger.debug(`Registered ${registry.size} CRAFT-Sec commands.`);
  return registry;
}

module.exports = { registerCommands, assertCompleteRegistry, expectedCommandIds };
