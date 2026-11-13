'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const {
  requireActiveEditor,
  requireSelection,
  requireWorkspace,
  createEditorRequest,
  createWorkspaceRequest
} = require('./validation');

/**
 * Surface an explicit unavailable analysis without treating empty findings as
 * a clean scan. The backend status and stages remain the source of truth.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger
 * }} dependencies
 * @param {string} label
 * @param {unknown} result
 */
function reportScanAvailability({ vscode, logger }, label, result) {
  if (!result || typeof result !== 'object' || result.analysisAvailable !== false) {
    return;
  }
  const message =
    `CRAFT-Sec: ${label} reached the backend, but analysis is unavailable. ` +
    'No findings or security conclusion were produced.';
  logger.warn(message);
  void vscode.window.showWarningMessage(message);
}

/**
 * Register the three scanning commands.
 *
 * File and selection scans require a saved editor; workspace scans require at
 * least one open workspace folder.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   diagnostics: import('../diagnostics/diagnosticController').DiagnosticController
 * }} context
 */
function registerScanCommands(context) {
  const { vscode, diagnostics } = context;

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.scanCurrentFile),
    () => createEditorRequest(vscode, requireActiveEditor(vscode)),
    {
      onResult: (result, request) => {
        diagnostics.publishScanResult(result, { scopeUris: [request.documentUri] });
        reportScanAvailability(context, 'current-file scan', result);
      }
    }
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.scanSelection),
    () => {
      const editor = requireActiveEditor(vscode);
      requireSelection(editor);
      return createEditorRequest(vscode, editor);
    },
    {
      onResult: (result, request) => {
        diagnostics.publishScanResult(result, { scopeUris: [request.documentUri] });
        reportScanAvailability(context, 'selection scan', result);
      }
    }
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.scanWorkspace),
    () => {
      requireWorkspace(vscode);
      return createWorkspaceRequest(vscode);
    },
    {
      onResult: (result) => {
        diagnostics.publishScanResult(result);
        reportScanAvailability(context, 'workspace scan', result);
      }
    }
  );
}

module.exports = { registerScanCommands, reportScanAvailability };
