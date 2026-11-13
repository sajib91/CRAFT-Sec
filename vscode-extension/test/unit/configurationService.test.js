'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_BACKEND_URL,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEALTH_TIMEOUT_MS,
  ConfigurationError,
  normalizeBackendUrl,
  normalizeTimeout,
  normalizeApiConfiguration,
  getEnvironmentToken,
  createConfigurationService,
  isLoopbackBackendUrl
} = require('../../src/api/configurationService');

test('backend URLs accept HTTP and HTTPS origins', () => {
  assert.equal(normalizeBackendUrl('http://127.0.0.1:8765'), 'http://127.0.0.1:8765');
  assert.equal(normalizeBackendUrl(' https://engine.example.test '), 'https://engine.example.test');
  assert.equal(normalizeBackendUrl('http://127.0.0.1:8765/'), 'http://127.0.0.1:8765');
});

test('backend URLs reject ambiguous or non-HTTP values', () => {
  for (const value of [
    '',
    '   ',
    'not a URL',
    'ftp://127.0.0.1:8765',
    'http://user:secret@127.0.0.1:8765',
    'http://127.0.0.1:8765/?token=value',
    'http://127.0.0.1:8765/#fragment',
    'http://127.0.0.1:8765/api/v1',
    'http://'
  ]) {
    assert.throws(
      () => normalizeBackendUrl(value),
      (error) => {
        assert.ok(error instanceof ConfigurationError, `${value} error type`);
        assert.equal(error.code, 'E_INVALID_BACKEND_URL');
        return true;
      },
      `${value} must be rejected`
    );
  }
});

test('timeouts are rounded, clamped, and fall back for invalid values', () => {
  assert.equal(normalizeTimeout(undefined, 100, 10, 1000), 100);
  assert.equal(normalizeTimeout('250.6', 100, 10, 1000), 251);
  assert.equal(normalizeTimeout(1, 100, 10, 1000), 10);
  assert.equal(normalizeTimeout(5000, 100, 10, 1000), 1000);
  assert.equal(normalizeTimeout('not-a-number', 100, 10, 1000), 100);
  assert.equal(normalizeTimeout(Number.NaN, 100, 10, 1000), 100);
});

test('API configuration applies defaults, consent, and token normalization', () => {
  const configuration = normalizeApiConfiguration({ token: '  secret  ' });

  assert.equal(configuration.baseUrl, DEFAULT_BACKEND_URL);
  assert.equal(configuration.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS);
  assert.equal(configuration.healthTimeoutMs, DEFAULT_HEALTH_TIMEOUT_MS);
  assert.equal(configuration.sendSourceText, true);
  assert.equal(configuration.token, 'secret');
  assert.equal(Object.isFrozen(configuration), true);

  assert.equal(normalizeApiConfiguration({ sendSourceText: false }).sendSourceText, false);
  assert.equal(normalizeApiConfiguration({ sendSourceText: null }).sendSourceText, true);
});

test('the token is read only from the extension host environment', () => {
  assert.equal(getEnvironmentToken({}), '');
  assert.equal(getEnvironmentToken({ CRAFTSEC_API_TOKEN: ' primary ' }), 'primary');
  assert.equal(getEnvironmentToken({ CRAFTSEC_ENGINE_TOKEN: 'legacy' }), 'legacy');
  assert.equal(
    getEnvironmentToken({ CRAFTSEC_API_TOKEN: 'primary', CRAFTSEC_ENGINE_TOKEN: 'legacy' }),
    'primary'
  );
});

test('loopback detection covers localhost and IPv4 loopback only', () => {
  assert.equal(isLoopbackBackendUrl('http://127.0.0.1:8765'), true);
  assert.equal(isLoopbackBackendUrl('http://localhost:8765'), true);
  assert.equal(isLoopbackBackendUrl('http://[::1]:8765'), true);
  assert.equal(isLoopbackBackendUrl('https://engine.example.test'), false);
  assert.equal(isLoopbackBackendUrl('not a URL'), false);
});

test('the configuration service reads VS Code settings per call', () => {
  const settings = {
    'backend.url': 'http://127.0.0.1:9000',
    'backend.requestTimeoutMs': 12_000,
    'backend.healthTimeoutMs': 2_000,
    'privacy.sendSourceText': false
  };
  /** @type {Array<string | undefined>} */
  const sections = [];
  const vscode = {
    workspace: {
      getConfiguration(section) {
        sections.push(section);
        return {
          get(key, fallback) {
            return settings[key] ?? fallback;
          }
        };
      }
    }
  };

  const service = createConfigurationService({
    vscode,
    environment: { CRAFTSEC_API_TOKEN: 'token-value' }
  });

  const first = service.get();
  assert.equal(first.baseUrl, 'http://127.0.0.1:9000');
  assert.equal(first.requestTimeoutMs, 12_000);
  assert.equal(first.healthTimeoutMs, 2_000);
  assert.equal(first.sendSourceText, false);
  assert.equal(first.token, 'token-value');

  settings['backend.url'] = 'http://127.0.0.1:9100';
  assert.equal(service.get().baseUrl, 'http://127.0.0.1:9100');
  assert.deepEqual(sections, ['craftsec', 'craftsec']);
});

test('the configuration service requires the VS Code workspace API', () => {
  assert.throws(() => createConfigurationService({}), /VS Code workspace API/);
  assert.throws(() => createConfigurationService({ vscode: {} }), /VS Code workspace API/);
});
