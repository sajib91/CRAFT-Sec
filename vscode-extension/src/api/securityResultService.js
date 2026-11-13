'use strict';

/**
 * Validation for CRAFT-Sec HTTP response contracts.
 *
 * The backend reports unimplemented capabilities as `unavailable`. These
 * validators preserve that distinction: they never turn an unavailable stage
 * or `analysisAvailable: false` into an empty successful analysis.
 */

const OPERATION_STATUSES = Object.freeze(['completed', 'partial', 'unavailable', 'failed']);
const STAGE_STATUSES = Object.freeze(['ok', 'partial', 'skipped', 'unavailable', 'failed']);
const CAPABILITY_KEYS = Object.freeze([
  'scan_file',
  'scan_workspace',
  'detection_analyze',
  'explanation_analyze',
  'features_extract',
  'counterfactual_analyze',
  'prevention_steer',
  'repair_generate',
  'verification_run'
]);

class SecurityResultValidationError extends Error {
  /**
   * @param {string} message
   * @param {string} [path]
   */
  constructor(message, path) {
    super(message);
    this.name = 'SecurityResultValidationError';
    this.code = 'E_INVALID_RESPONSE';
    this.path = path;
  }
}

/** @param {unknown} value */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {Record<string, any>}
 */
function requireObject(value, path) {
  if (!isPlainObject(value)) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be an object.`,
      path
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @param {{ allowEmpty?: boolean }} [options]
 * @returns {string}
 */
function requireString(value, path, options = {}) {
  if (typeof value !== 'string') {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be a string.`,
      path
    );
  }
  if (!options.allowEmpty && value.trim().length === 0) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must not be empty.`,
      path
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {boolean}
 */
function requireBoolean(value, path) {
  if (typeof value !== 'boolean') {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be a boolean.`,
      path
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {number}
 */
function requireNonNegativeInteger(value, path) {
  if (!Number.isInteger(value) || value < 0) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be a non-negative integer.`,
      path
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {unknown[]}
 */
function requireArray(value, path) {
  if (!Array.isArray(value)) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be an array.`,
      path
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {string[]}
 */
function requireStringArray(value, path) {
  return requireArray(value, path).map((entry, index) => requireString(entry, `${path}[${index}]`));
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {string}
 */
function requireFileUri(value, path) {
  const text = requireString(value, path);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be an absolute file URI.`,
      path
    );
  }
  if (parsed.protocol !== 'file:') {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must use the file: scheme.`,
      path
    );
  }
  return text;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {string}
 */
function requireSha256(value, path) {
  const text = requireString(value, path);
  if (!/^[a-f0-9]{64}$/.test(text)) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path} must be a lowercase SHA-256 digest.`,
      path
    );
  }
  return text;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {Record<string, any>}
 */
function requireObjectOrNull(value, path) {
  if (value === null) {
    return value;
  }
  return requireObject(value, path);
}

/**
 * Validate the health response and its explicit capability map.
 *
 * @param {unknown} value
 * @returns {{
 *   service: string,
 *   status: 'ok',
 *   version: string,
 *   apiVersion: string,
 *   timestamp: string,
 *   uptimeSeconds: number,
 *   capabilities: Record<string, boolean>,
 *   sandboxBackend: string
 * }}
 */
function validateHealthResponse(value) {
  const health = requireObject(value, 'health');
  requireString(health.service, 'health.service');
  if (health.status !== 'ok') {
    throw new SecurityResultValidationError(
      'The backend response is invalid: health.status must be "ok".',
      'health.status'
    );
  }
  requireString(health.version, 'health.version');
  if (health.apiVersion !== 'v1') {
    throw new SecurityResultValidationError(
      'The backend API version is not supported. Expected health.apiVersion "v1".',
      'health.apiVersion'
    );
  }
  const timestamp = requireString(health.timestamp, 'health.timestamp');
  if (Number.isNaN(Date.parse(timestamp))) {
    throw new SecurityResultValidationError(
      'The backend response is invalid: health.timestamp must be an ISO timestamp.',
      'health.timestamp'
    );
  }
  if (
    typeof health.uptimeSeconds !== 'number' ||
    !Number.isFinite(health.uptimeSeconds) ||
    health.uptimeSeconds < 0
  ) {
    throw new SecurityResultValidationError(
      'The backend response is invalid: health.uptimeSeconds must be a non-negative number.',
      'health.uptimeSeconds'
    );
  }

  const capabilities = requireObject(health.capabilities, 'health.capabilities');
  for (const key of CAPABILITY_KEYS) {
    if (!(key in capabilities)) {
      throw new SecurityResultValidationError(
        `The backend response is invalid: health.capabilities.${key} is missing.`,
        `health.capabilities.${key}`
      );
    }
    requireBoolean(capabilities[key], `health.capabilities.${key}`);
  }
  requireString(health.sandboxBackend, 'health.sandboxBackend');

  return {
    service: health.service,
    status: 'ok',
    version: health.version,
    apiVersion: health.apiVersion,
    timestamp,
    uptimeSeconds: health.uptimeSeconds,
    capabilities: { ...capabilities },
    sandboxBackend: health.sandboxBackend
  };
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {void}
 */
function validateStage(value, path) {
  const stage = requireObject(value, path);
  requireString(stage.stage, `${path}.stage`);
  if (!STAGE_STATUSES.includes(stage.status)) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: ${path}.status must be one of ${STAGE_STATUSES.join(
        ', '
      )}.`,
      `${path}.status`
    );
  }
  if (stage.reasonCode !== null && stage.reasonCode !== undefined) {
    requireString(stage.reasonCode, `${path}.reasonCode`);
  }
  if (stage.detail !== null && stage.detail !== undefined) {
    requireString(stage.detail, `${path}.detail`, { allowEmpty: true });
  }
  requireStringArray(stage.warnings, `${path}.warnings`);
  requireObject(stage.data, `${path}.data`);
}

/**
 * @param {unknown} value
 * @param {string} [expectedOperation]
 * @returns {Record<string, any>}
 */
function validateOperationEnvelope(value, expectedOperation) {
  const envelope = requireObject(value, 'response');
  requireString(envelope.operation, 'response.operation');
  if (expectedOperation && envelope.operation !== expectedOperation) {
    throw new SecurityResultValidationError(
      `The backend response is for "${envelope.operation}", not the expected ` +
        `"${expectedOperation}".`,
      'response.operation'
    );
  }
  if (!OPERATION_STATUSES.includes(envelope.status)) {
    throw new SecurityResultValidationError(
      `The backend response is invalid: response.status must be one of ${OPERATION_STATUSES.join(
        ', '
      )}.`,
      'response.status'
    );
  }
  if (envelope.apiVersion !== 'v1') {
    throw new SecurityResultValidationError(
      'The backend API version is not supported. Expected response.apiVersion "v1".',
      'response.apiVersion'
    );
  }
  requireString(envelope.requestId, 'response.requestId');

  const stages = requireArray(envelope.stages, 'response.stages');
  if (stages.length === 0) {
    throw new SecurityResultValidationError(
      'The backend response is invalid: response.stages must not be empty.',
      'response.stages'
    );
  }
  const stageNames = new Set();
  stages.forEach((stage, index) => {
    validateStage(stage, `response.stages[${index}]`);
    if (stageNames.has(stage.stage)) {
      throw new SecurityResultValidationError(
        `The backend response is invalid: duplicate stage "${stage.stage}".`,
        `response.stages[${index}].stage`
      );
    }
    stageNames.add(stage.stage);
  });

  requireStringArray(envelope.warnings, 'response.warnings');
  if (envelope.result !== null && envelope.result !== undefined) {
    requireObject(envelope.result, 'response.result');
  }
  return envelope;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {void}
 */
function validateScanScope(value, path) {
  const scope = requireObject(value, path);
  const uris = requireArray(scope.uris, `${path}.uris`);
  uris.forEach((uri, index) => requireFileUri(uri, `${path}.uris[${index}]`));
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {void}
 */
function validateFileInfo(value, path) {
  const file = requireObject(value, path);
  requireString(file.path, `${path}.path`);
  requireFileUri(file.uri, `${path}.uri`);
  requireNonNegativeInteger(file.size, `${path}.size`);
  requireSha256(file.sha256, `${path}.sha256`);
  if (file.languageId !== null && file.languageId !== undefined) {
    requireString(file.languageId, `${path}.languageId`);
  }
}

/**
 * Validate a file or workspace scan response.
 *
 * @param {unknown} value
 * @param {{ kind?: 'file' | 'workspace' }} [options]
 * @returns {Record<string, any>}
 */
function validateScanResponse(value, options = {}) {
  const kind = options.kind ?? 'file';
  const operation = kind === 'workspace' ? 'scan_workspace' : 'scan_file';
  const response = validateOperationEnvelope(value, operation);

  requireArray(response.findings, 'response.findings');
  requireNonNegativeInteger(response.filesScanned, 'response.filesScanned');
  requireBoolean(response.analysisAvailable, 'response.analysisAvailable');
  validateScanScope(response.scope, 'response.scope');
  if (kind === 'file') {
    validateFileInfo(response.file, 'response.file');
  }
  return response;
}

/**
 * Validate a detection response and flatten its findings into the scan shape
 * consumed by the diagnostics controller. The original envelope and result are
 * preserved; no finding is synthesized when detection is unavailable.
 *
 * @param {unknown} value
 * @param {{ documentUri: string }} options
 * @returns {Record<string, any>}
 */
function validateDetectionResponse(value, { documentUri }) {
  const response = validateOperationEnvelope(value, 'detection_analyze');
  const result = requireObject(response.result, 'response.result');
  requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
  requireArray(result.findings, 'response.result.findings');
  requireStringArray(result.evidenceSources, 'response.result.evidenceSources');
  if (
    result.scoreKind !== null &&
    result.scoreKind !== undefined &&
    !['heuristic', 'model_logit', 'calibrated'].includes(result.scoreKind)
  ) {
    throw new SecurityResultValidationError(
      'The backend response is invalid: response.result.scoreKind is not recognized.',
      'response.result.scoreKind'
    );
  }

  const scopeUri = requireFileUri(documentUri, 'request.documentUri');
  return {
    ...response,
    findings: result.findings,
    scope: { uris: [scopeUri] },
    analysisAvailable: result.analysisAvailable
  };
}

/**
 * @param {Record<string, any>} result
 * @returns {void}
 */
function validateDetectionResult(result) {
  requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
  requireArray(result.findings, 'response.result.findings');
  requireStringArray(result.evidenceSources, 'response.result.evidenceSources');
}

/**
 * Validate operation-specific results. Each check is deliberately limited to
 * fields this client consumes; absent capability results stay null/empty.
 *
 * @param {Record<string, any>} result
 * @param {string} operation
 * @returns {void}
 */
function validateOperationResult(result, operation) {
  switch (operation) {
    case 'explanation_analyze':
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
      if (result.findingId !== null && result.findingId !== undefined) {
        requireString(result.findingId, 'response.result.findingId');
      }
      requireObjectOrNull(result.graph, 'response.result.graph');
      requireStringArray(result.claimKinds, 'response.result.claimKinds');
      requireStringArray(result.limitations, 'response.result.limitations');
      return;
    case 'features_extract':
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
      if (result.saeArtifactId !== null && result.saeArtifactId !== undefined) {
        requireString(result.saeArtifactId, 'response.result.saeArtifactId');
      }
      requireArray(result.features, 'response.result.features');
      if (result.coverage !== null && result.coverage !== undefined) {
        if (
          typeof result.coverage !== 'number' ||
          !Number.isFinite(result.coverage) ||
          result.coverage < 0 ||
          result.coverage > 1
        ) {
          throw new SecurityResultValidationError(
            'The backend response is invalid: response.result.coverage must be between 0 and 1.',
            'response.result.coverage'
          );
        }
      }
      if (result.aggregation !== null && result.aggregation !== undefined) {
        requireString(result.aggregation, 'response.result.aggregation');
      }
      return;
    case 'counterfactual_analyze':
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
      if (result.scope !== 'model_intervention') {
        throw new SecurityResultValidationError(
          'The backend response is invalid: counterfactual scope must be "model_intervention".',
          'response.result.scope'
        );
      }
      requireArray(result.effects, 'response.result.effects');
      requireObjectOrNull(result.validity, 'response.result.validity');
      requireNonNegativeInteger(result.budget, 'response.result.budget');
      return;
    case 'prevention_steer':
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
      requireObjectOrNull(result.plan, 'response.result.plan');
      requireStringArray(result.guardrails, 'response.result.guardrails');
      requireObjectOrNull(result.evaluation, 'response.result.evaluation');
      requireStringArray(result.limitations, 'response.result.limitations');
      return;
    case 'repair_generate':
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
      if (result.patch !== null && result.patch !== undefined) {
        requireString(result.patch, 'response.result.patch', { allowEmpty: true });
      }
      requireStringArray(result.touchedFiles, 'response.result.touchedFiles');
      requireStringArray(result.rationale, 'response.result.rationale');
      requireStringArray(result.riskNotes, 'response.result.riskNotes');
      if (result.requiresApproval !== true) {
        throw new SecurityResultValidationError(
          'The backend response is invalid: a repair proposal must require approval.',
          'response.result.requiresApproval'
        );
      }
      requireObject(result.metadata, 'response.result.metadata');
      return;
    case 'verification_run':
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
      if (!['passed', 'failed', 'inconclusive', 'not_run'].includes(result.verdict)) {
        throw new SecurityResultValidationError(
          'The backend response is invalid: response.result.verdict is not recognized.',
          'response.result.verdict'
        );
      }
      requireArray(result.checks, 'response.result.checks');
      requireString(result.sandboxBackend, 'response.result.sandboxBackend');
      requireStringArray(result.limitations, 'response.result.limitations');
      return;
    default:
      requireBoolean(result.analysisAvailable, 'response.result.analysisAvailable');
  }
}

/**
 * @param {unknown} value
 * @param {{ operation: string }} options
 * @returns {Record<string, any>}
 */
function validateAnalysisResponse(value, { operation }) {
  const response = validateOperationEnvelope(value, operation);
  const result = requireObject(response.result, 'response.result');
  validateOperationResult(result, operation);
  return response;
}

/**
 * Human-readable summary for a validated scan response. Used for logging only;
 * callers must still inspect the structured status.
 *
 * @param {Record<string, any>} response
 * @returns {string}
 */
function describeScanAvailability(response) {
  if (response.analysisAvailable === true) {
    return 'The backend reported that the scan analysis stage ran.';
  }
  return (
    'The backend reported that analysis is unavailable. No findings or security conclusion ' +
    'were produced; an empty findings list is not a clean result.'
  );
}

module.exports = {
  OPERATION_STATUSES,
  STAGE_STATUSES,
  CAPABILITY_KEYS,
  SecurityResultValidationError,
  validateHealthResponse,
  validateOperationEnvelope,
  validateScanResponse,
  validateDetectionResponse,
  validateDetectionResult,
  validateOperationResult,
  validateAnalysisResponse,
  describeScanAvailability
};
