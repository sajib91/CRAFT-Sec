'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const { requireActiveEditor, requireSelection, createEditorRequest } = require('./validation');

/**
 * Register the explanation, security-feature, and counterfactual commands.
 *
 * Explanation and feature analysis can operate on a saved file and include a
 * selection when one exists. Counterfactual analysis requires an explicit
 * selection so the engine can compare a concrete code region.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerAnalysisCommands(context) {
  const { vscode } = context;

  registerEngineCommand(context, getCommandDefinition(COMMANDS.explainVulnerability), () =>
    createEditorRequest(vscode, requireActiveEditor(vscode))
  );

  registerEngineCommand(context, getCommandDefinition(COMMANDS.analyzeSecurityFeatures), () =>
    createEditorRequest(vscode, requireActiveEditor(vscode))
  );

  registerEngineCommand(context, getCommandDefinition(COMMANDS.counterfactualAnalysis), () => {
    const editor = requireActiveEditor(vscode);
    requireSelection(editor);
    return createEditorRequest(vscode, editor);
  });
}

module.exports = { registerAnalysisCommands };
