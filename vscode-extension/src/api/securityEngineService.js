'use strict';

/**
 * Security-engine service contract and implementations.
 *
 * `HttpSecurityEngineService` talks to the local FastAPI backend through
 * `ApiClient` and validates every response before returning it. The explicit
 * unavailable implementation remains available for tests and for a caller
 * that has no VS Code configuration object.
 *
 * No command may fabricate a result when a method fails or is unavailable.
 */

const path = require('node:path');
const { pathToFileURL } = require('node:url');

const { createApiClient } = require('./apiClient');
const { createConfigurationService } = require('./configurationService');
const {
  validateAnalysisResponse,
  validateDetectionResponse,
  validateHealthResponse,
  validateScanResponse
} = require('./securityResultService');

const MAX_WORKSPACE_FOLDERS = 50;

/**
 * @typedef {Object} EngineRequestContext
 * @property {import('vscode').CancellationToken} token
 * @property {import('vscode').Progress<{ message?: string }>} progress
 *
 * @typedef {Object} SecurityEngineService
 * @property {(context?: Partial<EngineRequestContext>) => Promise<object>} health
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

class SecurityEngineRequestError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   */
  constructor(message, code) {
    super(message);
    this.name = 'SecurityEngineRequestError';
    this.code = code;
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
  async health() {
    throw new SecurityEngineUnavailableError('backend health checking');
  }

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

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {string}
 */
function requireRequestString(value, field) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new SecurityEngineRequestError(
      `The engine request is missing ${field}. Run the command from an open, saved workspace file.`,
      'E_INVALID_REQUEST'
    );
  }
  return value;
}

/**
 * @param {object} request
 * @returns {string | undefined}
 */
function findFindingId(request) {
  if (typeof request.findingId === 'string' && request.findingId.trim().length > 0) {
    return request.findingId.trim();
  }
  if (isPlainObject(request.finding)) {
    if (typeof request.finding.id === 'string' && request.finding.id.trim().length > 0) {
      return request.finding.id.trim();
    }
    if (
      typeof request.finding.findingId === 'string' &&
      request.finding.findingId.trim().length > 0
    ) {
      return request.finding.findingId.trim();
    }
  }
  return undefined;
}

/**
 * @param {object} request
 * @param {string} filePath
 * @returns {string}
 */
function resolveDocumentUri(request, filePath) {
  const value =
    typeof request.documentUri === 'string' && request.documentUri.length > 0
      ? request.documentUri
      : pathToFileURL(filePath).toString();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new SecurityEngineRequestError(
      'The active document URI is invalid.',
      'E_INVALID_REQUEST'
    );
  }
  if (parsed.protocol !== 'file:') {
    throw new SecurityEngineRequestError(
      'The active document is not a local file.',
      'E_INVALID_REQUEST'
    );
  }
  return value;
}

/**
 * Build the common file context sent to the backend. Unknown fields are never
 * forwarded. Source text and selected text are included only when the current
 * configuration explicitly permits source sharing.
 *
 * @param {object} request
 * @param {{
 *   sendSourceText: boolean
 * }} configuration
 * @returns {Record<string, unknown>}
 */
function buildFileRequestBody(request, configuration) {
  if (!isPlainObject(request)) {
    throw new SecurityEngineRequestError(
      'The engine request must be an object.',
      'E_INVALID_REQUEST'
    );
  }
  const workspaceRoot = requireRequestString(
    request.workspaceFolder ?? request.workspaceRoot,
    'workspaceFolder'
  );
  const filePath = requireRequestString(request.filePath, 'filePath');

  /** @type {Record<string, unknown>} */
  const body = {
    workspaceRoot,
    filePath
  };

  if (typeof request.workspaceFolderName === 'string') {
    body.workspaceFolderName = request.workspaceFolderName;
  }
  if (typeof request.documentUri === 'string') {
    body.documentUri = request.documentUri;
  }
  if (typeof request.languageId === 'string') {
    body.languageId = request.languageId;
  }
  if (Number.isInteger(request.documentVersion) && request.documentVersion >= 0) {
    body.documentVersion = request.documentVersion;
  }
  if (request.selection !== undefined && request.selection !== null) {
    if (!isPlainObject(request.selection)) {
      throw new SecurityEngineRequestError(
        'The engine request contains an invalid selection.',
        'E_INVALID_REQUEST'
      );
    }
    body.selection = request.selection;
  }

  if (configuration.sendSourceText) {
    if (typeof request.selectedText === 'string') {
      body.selectedText = request.selectedText;
    }
    if (typeof request.sourceText === 'string') {
      body.sourceText = request.sourceText;
    }
  }

  return body;
}

/**
 * @param {object} request
 * @returns {object}
 */
function buildRepairFinding(request) {
  if (!isPlainObject(request.finding)) {
    throw new SecurityEngineRequestError(
      'Repair generation requires a backend finding. Open a CRAFT-Sec finding and run the ' +
        'command from its Quick Fix.',
      'E_FINDING_REQUIRED'
    );
  }
  const findingId = findFindingId(request);
  if (!findingId) {
    throw new SecurityEngineRequestError(
      'Repair generation requires a finding identifier.',
      'E_FINDING_REQUIRED'
    );
  }
  if (!isPlainObject(request.finding.range)) {
    throw new SecurityEngineRequestError(
      'Repair generation requires the finding range.',
      'E_FINDING_RANGE_REQUIRED'
    );
  }

  /** @type {Record<string, unknown>} */
  const finding = {
    findingId,
    range: request.finding.range
  };
  if (typeof request.finding.documentUri === 'string') {
    finding.documentUri = request.finding.documentUri;
  }
  if (typeof request.finding.cwe === 'string') {
    finding.cwe = request.finding.cwe;
  }
  if (typeof request.finding.ruleId === 'string') {
    finding.ruleId = request.finding.ruleId;
  }
  return finding;
}

/**
 * @param {object} request
 * @returns {Array<object>}
 */
function buildInterventions(request) {
  if (!Array.isArray(request.interventions) || request.interventions.length === 0) {
    throw new SecurityEngineRequestError(
      'Counterfactual analysis requires at least one explicit intervention. The extension ' +
        'does not invent interventions or feature indices.',
      'E_INTERVENTIONS_REQUIRED'
    );
  }
  return request.interventions;
}

/**
 * HTTP-backed implementation of the service contract.
 *
 * @implements {SecurityEngineService}
 */
class HttpSecurityEngineService {
  /**
   * @param {{
   *   configuration: { get: () => object },
   *   logger?: import('../logging/output').Logger,
   *   apiClientFactory?: (configuration: object) => import('./apiClient').ApiClient
   * }} dependencies
   */
  constructor({ configuration, logger, apiClientFactory }) {
    if (!configuration || typeof configuration.get !== 'function') {
      throw new TypeError('HttpSecurityEngineService requires a configuration service.');
    }
    this.configuration = configuration;
    this.logger = logger;
    this.apiClientFactory =
      typeof apiClientFactory === 'function' ? apiClientFactory : createApiClient;
  }

  /**
   * @returns {{ configuration: object, client: import('./apiClient').ApiClient }}
   */
  createClient() {
    const configuration = this.configuration.get();
    return {
      configuration,
      client: this.apiClientFactory(configuration)
    };
  }

  /**
   * Check backend liveness and capability flags. This performs no scan and
   * sends no source code.
   *
   * @param {Partial<EngineRequestContext>} [context]
   * @returns {Promise<object>}
   */
  async health(context = {}) {
    const { client, configuration } = this.createClient();
    this.logger?.debug(`Checking CRAFT-Sec backend at ${configuration.baseUrl}.`);
    const { data } = await client.health(context?.token);
    const health = validateHealthResponse(data);
    this.logger?.debug(
      `CRAFT-Sec backend ${health.version} responded with apiVersion ${health.apiVersion}.`
    );
    return health;
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async scanFile(request, context = {}) {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    this.logger?.debug('Sending POST /api/v1/scan/file.');
    const { data } = await client.post('/scan/file', body, context?.token);
    return validateScanResponse(data, { kind: 'file' });
  }

  /**
   * Selection scans use the detection endpoint so the backend receives the
   * selected range and, with consent, the selected code plus current buffer.
   *
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async scanSelection(request, context = {}) {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    if (!body.selection) {
      throw new SecurityEngineRequestError(
        'Selection scanning requires a non-empty selection.',
        'E_SELECTION_REQUIRED'
      );
    }
    const documentUri = resolveDocumentUri(request, /** @type {string} */ (body.filePath));
    this.logger?.debug('Sending POST /api/v1/detection/analyze for a selection.');
    const { data } = await client.post('/detection/analyze', body, context?.token);
    return validateDetectionResponse(data, { documentUri });
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async scanWorkspace(request, context = {}) {
    const { client } = this.createClient();
    const folders = Array.isArray(request.workspaceFolders) ? request.workspaceFolders : [];
    if (folders.length === 0) {
      throw new SecurityEngineRequestError(
        'Workspace scanning requires at least one local workspace folder.',
        'E_WORKSPACE_REQUIRED'
      );
    }
    if (folders.length > MAX_WORKSPACE_FOLDERS) {
      throw new SecurityEngineRequestError(
        `Workspace scanning accepts at most ${MAX_WORKSPACE_FOLDERS} folders.`,
        'E_TOO_MANY_WORKSPACE_FOLDERS'
      );
    }

    const seen = new Set();
    const workspaceFolders = [];
    for (const folder of folders) {
      if (!isPlainObject(folder)) {
        throw new SecurityEngineRequestError(
          'Workspace metadata contains an invalid folder entry.',
          'E_INVALID_WORKSPACE'
        );
      }
      const folderPath = requireRequestString(folder.path, 'workspaceFolders[].path');
      if (!path.isAbsolute(folderPath)) {
        throw new SecurityEngineRequestError(
          `Workspace folder path must be absolute: ${folderPath}`,
          'E_INVALID_WORKSPACE'
        );
      }
      if (seen.has(folderPath)) {
        continue;
      }
      seen.add(folderPath);
      const entry = {
        name: requireRequestString(folder.name, 'workspaceFolders[].name'),
        path: folderPath
      };
      if (typeof folder.uri === 'string') {
        try {
          if (new URL(folder.uri).protocol !== 'file:') {
            throw new Error('not a file URI');
          }
        } catch {
          throw new SecurityEngineRequestError(
            `Workspace folder URI must use the file: scheme: ${folder.uri}`,
            'E_INVALID_WORKSPACE'
          );
        }
        entry.uri = folder.uri;
      }
      workspaceFolders.push(entry);
    }

    this.logger?.debug(
      `Sending POST /api/v1/scan/workspace for ${workspaceFolders.length} folder(s).`
    );
    const { data } = await client.post('/scan/workspace', { workspaceFolders }, context?.token);
    return validateScanResponse(data, { kind: 'workspace' });
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async explainVulnerability(request, context = {}) {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    const findingId = findFindingId(request);
    if (!findingId) {
      throw new SecurityEngineRequestError(
        'Vulnerability explanation requires a backend finding identifier. Open a CRAFT-Sec ' +
          'finding and run the command from its context.',
        'E_FINDING_REQUIRED'
      );
    }
    body.findingId = findingId;
    if (typeof request.includeFeatureEvidence === 'boolean') {
      body.includeFeatureEvidence = request.includeFeatureEvidence;
    }
    const { data } = await client.post('/explanation/analyze', body, context?.token);
    return validateAnalysisResponse(data, { operation: 'explanation_analyze' });
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async analyzeSecurityFeatures(request, context = {}) {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    for (const field of ['saeArtifactId', 'hookPoint', 'aggregation']) {
      if (typeof request[field] === 'string') {
        body[field] = request[field];
      }
    }
    if (Number.isInteger(request.layer) && request.layer >= 0) {
      body.layer = request.layer;
    }
    const { data } = await client.post('/features/extract', body, context?.token);
    return validateAnalysisResponse(data, { operation: 'features_extract' });
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async counterfactualAnalysis(request, context = {}) {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    const findingId = findFindingId(request);
    if (!findingId) {
      throw new SecurityEngineRequestError(
        'Counterfactual analysis requires a backend finding identifier.',
        'E_FINDING_REQUIRED'
      );
    }
    body.findingId = findingId;
    body.interventions = buildInterventions(request);
    if (Number.isInteger(request.budget)) {
      body.budget = request.budget;
    }
    if (Number.isInteger(request.seed)) {
      body.seed = request.seed;
    }
    const { data } = await client.post('/counterfactual/analyze', body, context?.token);
    return validateAnalysisResponse(data, { operation: 'counterfactual_analyze' });
  }

  /**
   * Secure-code generation currently maps to the repair proposal endpoint. It
   * requires a backend finding; the extension never invents one.
   *
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async generateSecureCode(request, context = {}) {
    return this.generateRepair(request, context, 'Secure code generation');
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async repairVulnerability(request, context = {}) {
    return this.generateRepair(request, context, 'Repair generation');
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @param {string} operationLabel
   * @returns {Promise<object>}
   */
  async generateRepair(request, context = {}, operationLabel = 'Repair generation') {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    body.finding = buildRepairFinding(request);
    if (typeof request.snapshotHash === 'string') {
      body.snapshotHash = request.snapshotHash;
    }
    this.logger?.debug(`${operationLabel}: sending POST /api/v1/repair/generate.`);
    const { data } = await client.post('/repair/generate', body, context?.token);
    return validateAnalysisResponse(data, { operation: 'repair_generate' });
  }

  /**
   * @param {object} request
   * @param {EngineRequestContext} context
   * @returns {Promise<object>}
   */
  async verifyRepair(request, context = {}) {
    const { client, configuration } = this.createClient();
    const body = buildFileRequestBody(request, configuration);
    const hasRepairId = typeof request.repairId === 'string' && request.repairId.trim().length > 0;
    const hasPatch = typeof request.patch === 'string' && request.patch.length > 0;
    if (!hasRepairId && !hasPatch) {
      throw new SecurityEngineRequestError(
        'Verification requires an approved repair ID or patch. The extension does not invent ' +
          'a repair target.',
        'E_REPAIR_TARGET_REQUIRED'
      );
    }
    if (hasRepairId) {
      body.repairId = request.repairId.trim();
    }
    if (hasPatch) {
      body.patch = request.patch;
    }
    if (request.profile === 'static_only' || request.profile === 'sandbox') {
      body.profile = request.profile;
    }
    if (typeof request.runExecution === 'boolean') {
      body.runExecution = request.runExecution;
    }
    const { data } = await client.post('/verification/run', body, context?.token);
    return validateAnalysisResponse(data, { operation: 'verification_run' });
  }
}

/**
 * Create the extension's service.
 *
 * Without a VS Code object or explicit configuration service, return the
 * explicit unavailable implementation. The extension always supplies one.
 *
 * @param {{
 *   vscode?: import('vscode'),
 *   configurationService?: { get: () => object },
 *   configuration?: { get: () => object },
 *   logger?: import('../logging/output').Logger,
 *   apiClientFactory?: (configuration: object) => import('./apiClient').ApiClient,
 *   environment?: NodeJS.ProcessEnv
 * }} [options]
 * @returns {SecurityEngineService}
 */
function createSecurityEngineService(options = {}) {
  const configuration =
    options.configurationService ??
    options.configuration ??
    (options.vscode
      ? createConfigurationService({
          vscode: options.vscode,
          environment: options.environment
        })
      : undefined);

  if (!configuration) {
    return new UnavailableSecurityEngineService();
  }

  return new HttpSecurityEngineService({
    configuration,
    logger: options.logger,
    apiClientFactory: options.apiClientFactory
  });
}

module.exports = {
  SecurityEngineUnavailableError,
  SecurityEngineRequestError,
  UnavailableSecurityEngineService,
  HttpSecurityEngineService,
  buildFileRequestBody,
  buildRepairFinding,
  findFindingId,
  createSecurityEngineService
};
