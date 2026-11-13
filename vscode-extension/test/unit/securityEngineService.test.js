'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  SecurityEngineUnavailableError,
  SecurityEngineRequestError,
  UnavailableSecurityEngineService,
  HttpSecurityEngineService,
  buildFileRequestBody,
  createSecurityEngineService
} = require('../../src/api/securityEngineService');
const { RequestTimeoutError } = require('../../src/api/apiClient');

const ENGINE_METHODS = Object.freeze([
  'scanFile',
  'scanSelection',
  'scanWorkspace',
  'explainVulnerability',
  'analyzeSecurityFeatures',
  'counterfactualAnalysis',
  'generateSecureCode',
  'repairVulnerability',
  'verifyRepair'
]);

const ALL_METHODS = Object.freeze(['health', ...ENGINE_METHODS]);

const SHA = 'a'.repeat(64);
const FILE_URI = 'file:///workspace/src/app.js';

function healthPayload(overrides = {}) {
  return {
    service: 'craftsec-engine',
    status: 'ok',
    version: '0.1.0',
    apiVersion: 'v1',
    timestamp: '2026-11-13T00:00:00Z',
    uptimeSeconds: 1.5,
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
    sandboxBackend: 'docker',
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

function fileInfo(overrides = {}) {
  return {
    path: '/workspace/src/app.js',
    uri: FILE_URI,
    size: 16,
    sha256: SHA,
    languageId: 'javascript',
    ...overrides
  };
}

function scanPayload(overrides = {}) {
  return {
    operation: 'scan_file',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-scan',
    stages: [stage()],
    warnings: [],
    result: null,
    findings: [],
    filesScanned: 1,
    analysisAvailable: false,
    file: fileInfo(),
    scope: { uris: [FILE_URI] },
    ...overrides
  };
}

function workspacePayload(overrides = {}) {
  return {
    operation: 'scan_workspace',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-workspace',
    stages: [stage({ stage: 'workspace_discovery' })],
    warnings: [],
    result: null,
    findings: [],
    filesScanned: 2,
    analysisAvailable: false,
    scope: { uris: [FILE_URI] },
    ...overrides
  };
}

function detectionPayload(overrides = {}) {
  return {
    operation: 'detection_analyze',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-detection',
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

function repairPayload(overrides = {}) {
  return {
    operation: 'repair_generate',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-repair',
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
    },
    ...overrides
  };
}

/**
 * @param {unknown} responseData
 */
function createFakeApiClient(responseData) {
  const calls = [];
  return {
    calls,
    async health(token) {
      calls.push({ method: 'GET', path: '/health', token });
      return { data: responseData, status: 200, requestId: 'req-health' };
    },
    async post(path, body, token) {
      calls.push({ method: 'POST', path, body, token });
      return { data: responseData, status: 200, requestId: 'req-post' };
    }
  };
}

function createConfiguration(overrides = {}) {
  const configuration = {
    baseUrl: 'http://127.0.0.1:8765',
    requestTimeoutMs: 30_000,
    healthTimeoutMs: 3_000,
    sendSourceText: true,
    token: '',
    ...overrides
  };
  return { get: () => configuration };
}

function createService(responseData, configurationOverrides) {
  const client = createFakeApiClient(responseData);
  const configuration = createConfiguration(configurationOverrides);
  const service = new HttpSecurityEngineService({
    configuration,
    apiClientFactory(received) {
      assert.equal(received, configuration.get());
      return client;
    }
  });
  return { service, client };
}

function editorRequest(overrides = {}) {
  return {
    workspaceFolder: '/workspace',
    workspaceFolderName: 'workspace',
    filePath: '/workspace/src/app.js',
    documentUri: FILE_URI,
    languageId: 'javascript',
    documentVersion: 2,
    selection: {
      start: { line: 0, character: 0 },
      end: { line: 1, character: 10 }
    },
    selectedText: 'const x = 1;',
    sourceText: 'const x = 1;\nconsole.log(x);\n',
    ...overrides
  };
}

test('factory returns the unavailable service implementation without configuration', () => {
  const service = createSecurityEngineService();
  assert.ok(service instanceof UnavailableSecurityEngineService);
  for (const method of ALL_METHODS) {
    assert.equal(typeof service[method], 'function', `${method} must exist`);
  }
});

test('every unavailable service method rejects with a typed unavailable error', async () => {
  const service = createSecurityEngineService();
  const context = { token: {}, progress: { report() {} } };

  for (const method of ALL_METHODS) {
    await assert.rejects(
      () => service[method]({}, context),
      (error) => {
        assert.ok(error instanceof SecurityEngineUnavailableError, `${method} error type`);
        assert.equal(error.name, 'SecurityEngineUnavailableError');
        assert.equal(error.code, 'E_ENGINE_UNAVAILABLE');
        assert.match(error.message, /security engine is not available yet/);
        assert.match(error.message, /No result was produced/);
        return true;
      },
      `${method} must not resolve with a simulated result`
    );
  }
});

test('factory creates the HTTP service when a configuration service is supplied', () => {
  const service = createSecurityEngineService({
    configurationService: createConfiguration()
  });
  assert.ok(service instanceof HttpSecurityEngineService);
});

test('health performs a GET without source text and validates capabilities', async () => {
  const { service, client } = createService(healthPayload());
  const token = { isCancellationRequested: false };

  const health = await service.health({ token });

  assert.deepEqual(client.calls, [{ method: 'GET', path: '/health', token }]);
  assert.equal(health.status, 'ok');
  assert.equal(health.apiVersion, 'v1');
  assert.equal(health.capabilities.detection_analyze, false);
  assert.equal(health.sandboxBackend, 'docker');
});

test('health rejects a malformed backend response', async () => {
  const { service } = createService(healthPayload({ status: 'degraded' }));

  await assert.rejects(() => service.health({}), /health\.status/);
});

test('scanFile maps the file context and validated scan response', async () => {
  const { service, client } = createService(scanPayload());
  const token = { isCancellationRequested: false };

  const result = await service.scanFile(editorRequest(), { token });

  assert.equal(client.calls.length, 1);
  const [call] = client.calls;
  assert.equal(call.method, 'POST');
  assert.equal(call.path, '/scan/file');
  assert.equal(call.token, token);
  assert.deepEqual(call.body, {
    workspaceRoot: '/workspace',
    filePath: '/workspace/src/app.js',
    workspaceFolderName: 'workspace',
    documentUri: FILE_URI,
    languageId: 'javascript',
    documentVersion: 2,
    selection: {
      start: { line: 0, character: 0 },
      end: { line: 1, character: 10 }
    },
    selectedText: 'const x = 1;',
    sourceText: 'const x = 1;\nconsole.log(x);\n'
  });
  assert.equal(result.operation, 'scan_file');
  assert.equal(result.analysisAvailable, false);
  assert.deepEqual(result.findings, []);
});

test('scanFile omits source and selected text when source sharing is disabled', async () => {
  const { service, client } = createService(scanPayload(), { sendSourceText: false });

  await service.scanFile(editorRequest(), {});

  const [call] = client.calls;
  assert.equal('sourceText' in call.body, false);
  assert.equal('selectedText' in call.body, false);
  assert.equal(call.body.selection.start.line, 0);
});

test('scanFile never forwards unknown request fields', async () => {
  const { service, client } = createService(scanPayload());

  await service.scanFile(editorRequest({ arbitrary: 'value', token: 'secret' }), {});

  const [call] = client.calls;
  assert.equal('arbitrary' in call.body, false);
  assert.equal('token' in call.body, false);
});

test('scanSelection posts to detection and flattens validated findings', async () => {
  const finding = {
    id: 'finding-1',
    message: 'Unsanitized input reaches a query.',
    severity: 'high',
    cwe: 'CWE-89',
    location: {
      uri: FILE_URI,
      range: {
        start: { line: 0, character: 0 },
        end: { line: 1, character: 10 }
      }
    }
  };
  const payload = detectionPayload({
    result: {
      analysisAvailable: true,
      findings: [finding],
      evidenceSources: ['semgrep'],
      scoreKind: 'heuristic'
    }
  });
  const { service, client } = createService(payload);

  const result = await service.scanSelection(editorRequest(), {});

  assert.equal(client.calls[0].path, '/detection/analyze');
  assert.equal(result.operation, 'detection_analyze');
  assert.equal(result.analysisAvailable, true);
  assert.deepEqual(result.findings, [finding]);
  assert.deepEqual(result.scope, { uris: [FILE_URI] });
});

test('scanSelection requires a non-empty selection', async () => {
  const { service, client } = createService(detectionPayload());

  await assert.rejects(
    () => service.scanSelection(editorRequest({ selection: undefined }), {}),
    (error) => {
      assert.ok(error instanceof SecurityEngineRequestError);
      assert.equal(error.code, 'E_SELECTION_REQUIRED');
      return true;
    }
  );
  assert.equal(client.calls.length, 0);
});

test('scanWorkspace sends folder metadata only and validates the response', async () => {
  const { service, client } = createService(workspacePayload());
  const request = {
    workspaceFolders: [
      { name: 'workspace', path: '/workspace', uri: 'file:///workspace' },
      { name: 'duplicate', path: '/workspace', uri: 'file:///workspace' }
    ]
  };

  const result = await service.scanWorkspace(request, {});

  assert.equal(client.calls[0].path, '/scan/workspace');
  assert.deepEqual(client.calls[0].body, {
    workspaceFolders: [{ name: 'workspace', path: '/workspace', uri: 'file:///workspace' }]
  });
  assert.equal('sourceText' in client.calls[0].body, false);
  assert.equal(result.operation, 'scan_workspace');
});

test('scanWorkspace rejects relative paths and non-file URIs before sending', async () => {
  const { service, client } = createService(workspacePayload());

  await assert.rejects(
    () => service.scanWorkspace({ workspaceFolders: [{ name: 'x', path: 'relative' }] }, {}),
    /absolute/
  );
  await assert.rejects(
    () =>
      service.scanWorkspace(
        { workspaceFolders: [{ name: 'x', path: '/tmp', uri: 'https://example.test' }] },
        {}
      ),
    /file: scheme/
  );
  assert.equal(client.calls.length, 0);
});

test('invalid scan responses are rejected instead of being published', async () => {
  const { service } = createService(scanPayload({ filesScanned: -1 }));

  await assert.rejects(() => service.scanFile(editorRequest(), {}), /filesScanned/);
});

test('transport errors from the API client propagate unchanged', async () => {
  const configuration = createConfiguration();
  const failure = new RequestTimeoutError('http://127.0.0.1:8765', 25);
  const service = new HttpSecurityEngineService({
    configuration,
    apiClientFactory() {
      return {
        async health() {
          throw failure;
        },
        async post() {
          throw failure;
        }
      };
    }
  });

  await assert.rejects(
    () => service.scanFile(editorRequest(), {}),
    (error) => error === failure
  );
});

test('repair generation requires a backend finding and range', async () => {
  const { service, client } = createService(repairPayload());

  await assert.rejects(
    () => service.repairVulnerability(editorRequest(), {}),
    (error) => {
      assert.ok(error instanceof SecurityEngineRequestError);
      assert.equal(error.code, 'E_FINDING_REQUIRED');
      return true;
    }
  );
  assert.equal(client.calls.length, 0);
});

test('repair generation maps a finding and validated proposal', async () => {
  const { service, client } = createService(repairPayload());
  const request = editorRequest({
    finding: {
      findingId: 'finding-1',
      documentUri: FILE_URI,
      range: {
        start: { line: 0, character: 0 },
        end: { line: 1, character: 10 }
      },
      cwe: 'CWE-89',
      ruleId: 'sql-injection'
    }
  });

  const result = await service.repairVulnerability(request, {});

  assert.equal(client.calls[0].path, '/repair/generate');
  assert.deepEqual(client.calls[0].body.finding, {
    findingId: 'finding-1',
    documentUri: FILE_URI,
    range: {
      start: { line: 0, character: 0 },
      end: { line: 1, character: 10 }
    },
    cwe: 'CWE-89',
    ruleId: 'sql-injection'
  });
  assert.equal(client.calls[0].body.sourceText, request.sourceText);
  assert.equal(result.result.requiresApproval, true);
});

test('verification requires an explicit repair target', async () => {
  const { service, client } = createService({
    operation: 'verification_run',
    status: 'partial',
    apiVersion: 'v1',
    requestId: 'req-verify',
    stages: [stage()],
    warnings: [],
    result: {
      analysisAvailable: false,
      verdict: 'not_run',
      checks: [],
      sandboxBackend: 'docker',
      limitations: []
    }
  });

  await assert.rejects(
    () => service.verifyRepair(editorRequest(), {}),
    (error) => {
      assert.equal(error.code, 'E_REPAIR_TARGET_REQUIRED');
      return true;
    }
  );
  assert.equal(client.calls.length, 0);
});

test('buildFileRequestBody rejects incomplete contexts', () => {
  assert.throws(
    () => buildFileRequestBody({ filePath: '/workspace/a.js' }, { sendSourceText: true }),
    /workspaceFolder/
  );
  assert.throws(
    () => buildFileRequestBody({ workspaceFolder: '/workspace' }, { sendSourceText: true }),
    /filePath/
  );
  assert.throws(() => buildFileRequestBody(null, { sendSourceText: true }), /must be an object/);
});
