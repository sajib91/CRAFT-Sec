'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  SecurityResultValidationError,
  validateHealthResponse,
  validateOperationEnvelope,
  validateScanResponse,
  validateDetectionResponse,
  validateAnalysisResponse,
  describeScanAvailability
} = require('../../src/api/securityResultService');

const FILE_URI = 'file:///workspace/src/app.js';
const SHA = 'b'.repeat(64);

function healthPayload(overrides = {}) {
  return {
    service: 'craftsec-engine',
    status: 'ok',
    version: '0.1.0',
    apiVersion: 'v1',
    timestamp: '2026-11-13T00:00:00Z',
    uptimeSeconds: 0.5,
    capabilities: {
      scan_file: true,
      scan_workspace: true,
      detection_analyze: false,
      explanation_analyze: false,
      features_extract: false,
      counterfactual_analyze: false,
      prevention_steer: false,
      repair_generate: false,
      verification_run: false
    },
    sandboxBackend: 'none',
    ...overrides
  };
}

function stage(overrides = {}) {
  return {
    stage: 'file_snapshot',
    status: 'ok',
    reasonCode: null,
    detail: null,
    warnings: [],
    data: {},
    ...overrides
  };
}

function scanPayload(overrides = {}) {
  return {
    operation: 'scan_file',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-1',
    stages: [stage()],
    warnings: [],
    result: null,
    findings: [],
    filesScanned: 1,
    analysisAvailable: false,
    file: {
      path: '/workspace/src/app.js',
      uri: FILE_URI,
      size: 20,
      sha256: SHA,
      languageId: 'javascript'
    },
    scope: { uris: [FILE_URI] },
    ...overrides
  };
}

function detectionPayload(overrides = {}) {
  return {
    operation: 'detection_analyze',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-2',
    stages: [stage()],
    warnings: [],
    result: {
      analysisAvailable: false,
      findings: [],
      evidenceSources: [],
      scoreKind: null
    },
    ...overrides
  };
}

test('health validation accepts the documented response without adding fields', () => {
  const health = validateHealthResponse(healthPayload());

  assert.equal(health.status, 'ok');
  assert.equal(health.apiVersion, 'v1');
  assert.equal(health.capabilities.scan_file, true);
  assert.equal(health.capabilities.detection_analyze, false);
  assert.equal(health.sandboxBackend, 'none');
});

test('health validation rejects unsupported or incomplete responses', () => {
  for (const payload of [
    healthPayload({ status: 'degraded' }),
    healthPayload({ apiVersion: 'v2' }),
    healthPayload({ timestamp: 'not-a-date' }),
    healthPayload({ uptimeSeconds: -1 }),
    healthPayload({ capabilities: { scan_file: true } })
  ]) {
    assert.throws(() => validateHealthResponse(payload), SecurityResultValidationError);
  }
});

test('scan validation preserves partial status and unavailable analysis', () => {
  const result = validateScanResponse(scanPayload());

  assert.equal(result.operation, 'scan_file');
  assert.equal(result.status, 'partial');
  assert.equal(result.analysisAvailable, false);
  assert.deepEqual(result.findings, []);
  assert.equal(result.result, null);
  assert.equal(result.file.sha256, SHA);
});

test('scan validation rejects a different operation and malformed metadata', () => {
  assert.throws(
    () => validateScanResponse(scanPayload({ operation: 'scan_workspace' })),
    /not the expected/
  );
  assert.throws(() => validateScanResponse(scanPayload({ filesScanned: 1.5 })), /filesScanned/);
  assert.throws(() => validateScanResponse(scanPayload({ findings: {} })), /findings/);
  assert.throws(
    () => validateScanResponse(scanPayload({ scope: { uris: ['https://example.test'] } })),
    /file: scheme/
  );
  assert.throws(
    () =>
      validateScanResponse(
        scanPayload({ file: { path: '/x', uri: FILE_URI, size: 1, sha256: 'bad' } })
      ),
    /sha256/
  );
});

test('workspace scans do not require a file object', () => {
  const payload = scanPayload({
    operation: 'scan_workspace',
    stages: [stage({ stage: 'workspace_discovery', status: 'partial' })],
    file: undefined
  });

  const result = validateScanResponse(payload, { kind: 'workspace' });

  assert.equal(result.operation, 'scan_workspace');
  assert.equal(result.filesScanned, 1);
});

test('operation envelopes require unique, well-formed stages', () => {
  assert.throws(() => validateOperationEnvelope(scanPayload({ stages: [] })), /must not be empty/);
  assert.throws(
    () =>
      validateOperationEnvelope(
        scanPayload({
          stages: [stage(), stage()]
        })
      ),
    /duplicate stage/
  );
  assert.throws(
    () => validateOperationEnvelope(scanPayload({ stages: [stage({ status: 'unknown' })] })),
    /status must be one of/
  );
});

test('detection validation flattens findings and scopes them to the document', () => {
  const finding = {
    id: 'finding-1',
    message: 'Input reaches a shell command.',
    severity: 'critical',
    location: {
      uri: FILE_URI,
      range: {
        start: { line: 0, character: 0 },
        end: { line: 0, character: 10 }
      }
    }
  };
  const payload = detectionPayload({
    status: 'completed',
    result: {
      analysisAvailable: true,
      findings: [finding],
      evidenceSources: ['semgrep'],
      scoreKind: 'heuristic'
    }
  });

  const result = validateDetectionResponse(payload, { documentUri: FILE_URI });

  assert.equal(result.operation, 'detection_analyze');
  assert.equal(result.analysisAvailable, true);
  assert.deepEqual(result.findings, [finding]);
  assert.deepEqual(result.scope, { uris: [FILE_URI] });
  assert.deepEqual(result.result.findings, [finding]);
});

test('detection validation never converts unavailable analysis into a clean scan', () => {
  const result = validateDetectionResponse(detectionPayload(), { documentUri: FILE_URI });

  assert.equal(result.analysisAvailable, false);
  assert.deepEqual(result.findings, []);
  assert.match(describeScanAvailability(result), /not a clean result/);
});

test('detection validation rejects unknown score kinds and non-file document URIs', () => {
  assert.throws(
    () =>
      validateDetectionResponse(
        detectionPayload({
          result: {
            analysisAvailable: false,
            findings: [],
            evidenceSources: [],
            scoreKind: 'vibes'
          }
        }),
        { documentUri: FILE_URI }
      ),
    /scoreKind/
  );
  assert.throws(
    () => validateDetectionResponse(detectionPayload(), { documentUri: 'https://example.test' }),
    /file: scheme/
  );
});

test('repair analysis requires an approval gate', () => {
  const payload = {
    operation: 'repair_generate',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-3',
    stages: [stage()],
    warnings: [],
    result: {
      analysisAvailable: false,
      patch: null,
      touchedFiles: [],
      rationale: [],
      riskNotes: [],
      requiresApproval: true,
      metadata: {}
    }
  };

  assert.equal(
    validateAnalysisResponse(payload, { operation: 'repair_generate' }).result.requiresApproval,
    true
  );
  assert.throws(
    () =>
      validateAnalysisResponse(
        {
          ...payload,
          result: { ...payload.result, requiresApproval: false }
        },
        { operation: 'repair_generate' }
      ),
    /must require approval/
  );
});

test('verification analysis accepts only declared verdicts', () => {
  function payload(verdict) {
    return {
      operation: 'verification_run',
      status: 'partial',
      apiVersion: 'v1',
      requestId: 'req-4',
      stages: [stage()],
      warnings: [],
      result: {
        analysisAvailable: false,
        verdict,
        checks: [],
        sandboxBackend: 'none',
        limitations: []
      }
    };
  }

  assert.equal(
    validateAnalysisResponse(payload('not_run'), { operation: 'verification_run' }).result.verdict,
    'not_run'
  );
  assert.throws(
    () => validateAnalysisResponse(payload('probably'), { operation: 'verification_run' }),
    /verdict/
  );
});

test('counterfactual analysis requires the model-intervention scope', () => {
  function payload(scope) {
    return {
      operation: 'counterfactual_analyze',
      status: 'partial',
      apiVersion: 'v1',
      requestId: 'req-5',
      stages: [stage()],
      warnings: [],
      result: {
        analysisAvailable: false,
        scope,
        effects: [],
        validity: null,
        budget: 0
      }
    };
  }

  assert.equal(
    validateAnalysisResponse(payload('model_intervention'), {
      operation: 'counterfactual_analyze'
    }).result.scope,
    'model_intervention'
  );
  assert.throws(
    () =>
      validateAnalysisResponse(payload('static_estimate'), {
        operation: 'counterfactual_analyze'
      }),
    /model_intervention/
  );
});

test('analysis responses without a result are rejected', () => {
  assert.throws(
    () =>
      validateAnalysisResponse(
        {
          operation: 'features_extract',
          status: 'unavailable',
          apiVersion: 'v1',
          requestId: 'req-6',
          stages: [stage()],
          warnings: [],
          result: null
        },
        { operation: 'features_extract' }
      ),
    /result must be an object/
  );
});
