'use strict';

const { COMMANDS } = require('../constants');

/**
 * Canonical feature command definitions. package.json and the command
 * registry must both match this list; tests enforce the drift check.
 */
const COMMAND_DEFINITIONS = Object.freeze([
  Object.freeze({
    id: COMMANDS.scanCurrentFile,
    title: 'Scan Current File',
    progressTitle: 'CRAFT-Sec: Scanning current file',
    serviceMethod: 'scanFile'
  }),
  Object.freeze({
    id: COMMANDS.scanSelection,
    title: 'Scan Selection',
    progressTitle: 'CRAFT-Sec: Scanning selection',
    serviceMethod: 'scanSelection'
  }),
  Object.freeze({
    id: COMMANDS.scanWorkspace,
    title: 'Scan Workspace',
    progressTitle: 'CRAFT-Sec: Scanning workspace',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.explainVulnerability,
    title: 'Explain Vulnerability',
    progressTitle: 'CRAFT-Sec: Explaining vulnerability',
    serviceMethod: 'explainVulnerability'
  }),
  Object.freeze({
    id: COMMANDS.analyzeSecurityFeatures,
    title: 'Analyze Security Features',
    progressTitle: 'CRAFT-Sec: Analyzing security features',
    serviceMethod: 'analyzeSecurityFeatures'
  }),
  Object.freeze({
    id: COMMANDS.counterfactualAnalysis,
    title: 'Counterfactual Analysis',
    progressTitle: 'CRAFT-Sec: Running counterfactual analysis',
    serviceMethod: 'counterfactualAnalysis'
  }),
  Object.freeze({
    id: COMMANDS.generateSecureCode,
    title: 'Generate Secure Code',
    progressTitle: 'CRAFT-Sec: Generating secure code',
    serviceMethod: 'generateSecureCode'
  }),
  Object.freeze({
    id: COMMANDS.repairVulnerability,
    title: 'Repair Vulnerability',
    progressTitle: 'CRAFT-Sec: Generating repair proposal',
    serviceMethod: 'repairVulnerability'
  }),
  Object.freeze({
    id: COMMANDS.verifyRepair,
    title: 'Verify Repair',
    progressTitle: 'CRAFT-Sec: Verifying repair',
    serviceMethod: 'verifyRepair'
  }),
  Object.freeze({
    id: COMMANDS.openSecurityDashboard,
    title: 'Open Security Dashboard',
    progressTitle: 'CRAFT-Sec: Opening security dashboard',
    serviceMethod: null
  })
]);

const DEFINITIONS_BY_ID = new Map(
  COMMAND_DEFINITIONS.map((definition) => [definition.id, definition])
);

/**
 * @param {string} commandId
 * @returns {typeof COMMAND_DEFINITIONS[number]}
 */
function getCommandDefinition(commandId) {
  const definition = DEFINITIONS_BY_ID.get(commandId);
  if (!definition) {
    throw new Error(`No command definition registered for ${commandId}`);
  }
  return definition;
}

module.exports = { COMMAND_DEFINITIONS, getCommandDefinition };
