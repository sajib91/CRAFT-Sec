'use strict';

/** Shared identifiers that must stay in sync with package.json. */
const CONTAINER_ID = 'craftsec';
const VIEW_ID = 'craftsec.sidebar';
const COMMANDS = Object.freeze({
  showStatus: 'craftsec.showStatus',
  showLogs: 'craftsec.showLogs',
  scanCurrentFile: 'craftsec.scanCurrentFile',
  scanSelection: 'craftsec.scanSelection',
  scanWorkspace: 'craftsec.scanWorkspace',
  explainVulnerability: 'craftsec.explainVulnerability',
  analyzeSecurityFeatures: 'craftsec.analyzeSecurityFeatures',
  counterfactualAnalysis: 'craftsec.counterfactualAnalysis',
  generateSecureCode: 'craftsec.generateSecureCode',
  repairVulnerability: 'craftsec.repairVulnerability',
  verifyRepair: 'craftsec.verifyRepair',
  openSecurityDashboard: 'craftsec.openSecurityDashboard'
});

module.exports = { CONTAINER_ID, VIEW_ID, COMMANDS };
