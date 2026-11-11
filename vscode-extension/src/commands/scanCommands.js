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
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerScanCommands(context) {
  const { vscode } = context;

  registerEngineCommand(context, getCommandDefinition(COMMANDS.scanCurrentFile), () =>
    createEditorRequest(vscode, requireActiveEditor(vscode))
  );

  registerEngineCommand(context, getCommandDefinition(COMMANDS.scanSelection), () => {
    const editor = requireActiveEditor(vscode);
    requireSelection(editor);
    return createEditorRequest(vscode, editor);
  });

  registerEngineCommand(context, getCommandDefinition(COMMANDS.scanWorkspace), () => {
    requireWorkspace(vscode);
    return createWorkspaceRequest(vscode);
  });
}

module.exports = { registerScanCommands };
