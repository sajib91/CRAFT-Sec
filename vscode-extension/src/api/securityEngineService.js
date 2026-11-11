'use strict';

/**
 * Service contract used by all engine-backed commands.
 *
 * A future authenticated HTTP client implements these methods; the current
 * implementation reports that the engine is unavailable. No command may
 * fabricate a result when a method fails or is unavailable.
 *
 * @typedef {Object} EngineRequestContext
 * @property {import('vscode').CancellationToken} token
 * @property {import('vscode').Progress<{ message?: string }>} progress
 *
 * @typedef {Object} SecurityEngineService
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} scanFile
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} scanSelection
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} scanWorkspace
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} explainVulnerability
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} analyzeSecurityFeatures
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} counterfactualAnalysis
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} generateSecureCode
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} repairVulnerability
 * @property {(request: object, context: EngineRequestContext) => Promise<object>} verifyRepair
 */

class SecurityEngineUnavailableError extends Error {
  /** @param {string} operation */
  constructor(operation) {
    super(
      `The local CRAFT-Sec security engine is not available yet, so ${operation} cannot run. ` +
        'No result was produced.'
    );
    this.name = 'SecurityEngineUnavailableError';
    this.code = 'E_ENGINE_UNAVAILABLE';
  }
}

/**
 * Explicit unavailable implementation. Every method fails instead of
 * returning a simulated analysis result.
 *
 * @implements {SecurityEngineService}
 */
class UnavailableSecurityEngineService {
  /** @returns {Promise<never>} */
  async scanFile() {
    throw new SecurityEngineUnavailableError('current-file scanning');
  }

  /** @returns {Promise<never>} */
  async scanSelection() {
    throw new SecurityEngineUnavailableError('selection scanning');
  }

  /** @returns {Promise<never>} */
  async scanWorkspace() {
    throw new SecurityEngineUnavailableError('workspace scanning');
  }

  /** @returns {Promise<never>} */
  async explainVulnerability() {
    throw new SecurityEngineUnavailableError('vulnerability explanation');
  }

  /** @returns {Promise<never>} */
  async analyzeSecurityFeatures() {
    throw new SecurityEngineUnavailableError('security feature analysis');
  }

  /** @returns {Promise<never>} */
  async counterfactualAnalysis() {
    throw new SecurityEngineUnavailableError('counterfactual analysis');
  }

  /** @returns {Promise<never>} */
  async generateSecureCode() {
    throw new SecurityEngineUnavailableError('secure code generation');
  }

  /** @returns {Promise<never>} */
  async repairVulnerability() {
    throw new SecurityEngineUnavailableError('vulnerability repair');
  }

  /** @returns {Promise<never>} */
  async verifyRepair() {
    throw new SecurityEngineUnavailableError('repair verification');
  }
}

/** @returns {SecurityEngineService} */
function createSecurityEngineService() {
  return new UnavailableSecurityEngineService();
}

module.exports = {
  SecurityEngineUnavailableError,
  UnavailableSecurityEngineService,
  createSecurityEngineService
};
