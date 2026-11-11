'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  SecurityEngineUnavailableError,
  UnavailableSecurityEngineService,
  createSecurityEngineService
} = require('../../src/api/securityEngineService');

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

test('factory returns the unavailable service implementation', () => {
  const service = createSecurityEngineService();
  assert.ok(service instanceof UnavailableSecurityEngineService);
  for (const method of ENGINE_METHODS) {
    assert.equal(typeof service[method], 'function', `${method} must exist`);
  }
});

test('every service method rejects with a typed unavailable error', async () => {
  const service = createSecurityEngineService();
  const context = { token: {}, progress: { report() {} } };

  for (const method of ENGINE_METHODS) {
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

test('unavailable errors identify the operation without fabricating details', async () => {
  const service = createSecurityEngineService();

  await assert.rejects(service.scanFile({}, {}), (error) => {
    assert.match(error.message, /current-file scanning/);
    assert.doesNotMatch(error.message, /probability|causal|verified/i);
    return true;
  });

  await assert.rejects(service.verifyRepair({}, {}), (error) => {
    assert.match(error.message, /repair verification/);
    return true;
  });
});
