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
      onResult: (result, request) =>
        diagnostics.publishScanResult(result, { scopeUris: [request.documentUri] })
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
      onResult: (result, request) =>
        diagnostics.publishScanResult(result, { scopeUris: [request.documentUri] })
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
      onResult: (result) => diagnostics.publishScanResult(result)
    }
  );
}

module.exports = { registerScanCommands };
