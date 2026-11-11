'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const {
  requireActiveEditor,
  createEditorRequest,
  createVerificationRequest
} = require('./validation');

/**
 * Register the generation, repair, and verification commands.
 *
 * Generation and repair use the active saved editor as context. Verification
 * works at workspace scope and does not require an editor.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerRepairCommands(context) {
  const { vscode } = context;

  registerEngineCommand(context, getCommandDefinition(COMMANDS.generateSecureCode), () =>
    createEditorRequest(vscode, requireActiveEditor(vscode))
  );

  registerEngineCommand(context, getCommandDefinition(COMMANDS.repairVulnerability), () =>
    createEditorRequest(vscode, requireActiveEditor(vscode))
  );

  registerEngineCommand(context, getCommandDefinition(COMMANDS.verifyRepair), () =>
    createVerificationRequest(vscode)
  );
}

module.exports = { registerRepairCommands };
