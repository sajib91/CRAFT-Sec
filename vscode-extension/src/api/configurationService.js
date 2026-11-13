'use strict';

/**
 * Backend configuration for the HTTP client.
 *
 * This module deliberately has no `vscode` import so URL and timeout rules can
 * be unit tested with plain Node. The extension supplies a VS Code
 * configuration object when it creates a service.
 */

const SECTION = 'craftsec';
const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8765';
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_HEALTH_TIMEOUT_MS = 3_000;
const MIN_REQUEST_TIMEOUT_MS = 1_000;
const MAX_REQUEST_TIMEOUT_MS = 300_000;
const MIN_HEALTH_TIMEOUT_MS = 500;
const MAX_HEALTH_TIMEOUT_MS = 60_000;

class ConfigurationError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'E_INVALID_CONFIGURATION') {
    super(message);
    this.name = 'ConfigurationError';
    this.code = code;
  }
}

/**
 * Validate and normalize the configured backend base URL.
 *
 * Only an HTTP(S) origin is accepted. Credentials, query strings, fragments,
 * and path prefixes are rejected so source data cannot be redirected through
 * an ambiguous URL. The client always appends the versioned API path itself.
 *
 * @param {unknown} value
 * @returns {string}
 */
function normalizeBackendUrl(value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ConfigurationError(
      'craftsec.backend.url must be a non-empty HTTP or HTTPS URL.',
      'E_INVALID_BACKEND_URL'
    );
  }

  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new ConfigurationError(
      `craftsec.backend.url is not a valid URL: ${value}`,
      'E_INVALID_BACKEND_URL'
    );
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ConfigurationError(
      'craftsec.backend.url must use the http: or https: scheme.',
      'E_INVALID_BACKEND_URL'
    );
  }
  if (!parsed.hostname) {
    throw new ConfigurationError(
      'craftsec.backend.url must include a host name.',
      'E_INVALID_BACKEND_URL'
    );
  }
  if (parsed.username || parsed.password) {
    throw new ConfigurationError(
      'craftsec.backend.url must not contain credentials. Configure authentication separately.',
      'E_INVALID_BACKEND_URL'
    );
  }
  if (parsed.search || parsed.hash) {
    throw new ConfigurationError(
      'craftsec.backend.url must not contain a query string or fragment.',
      'E_INVALID_BACKEND_URL'
    );
  }
  if (parsed.pathname !== '' && parsed.pathname !== '/') {
    throw new ConfigurationError(
      'craftsec.backend.url must not contain a path. The extension appends /api/v1 itself.',
      'E_INVALID_BACKEND_URL'
    );
  }

  return `${parsed.protocol}//${parsed.host}`;
}

/**
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} minimum
 * @param {number} maximum
 * @returns {number}
 */
function normalizeTimeout(value, fallback, minimum, maximum) {
  const number =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim().length > 0
        ? Number(value)
        : Number.NaN;
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(maximum, Math.max(minimum, Math.round(number)));
}

/**
 * @param {string | undefined} value
 * @returns {string}
 */
function normalizeToken(value) {
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Read an optional bearer token from the extension host environment.
 *
 * Tokens are never written to settings, logs, or API responses. The backend
 * documents `CRAFTSEC_API_TOKEN`; the legacy engine alias is accepted too.
 *
 * @param {NodeJS.ProcessEnv} [environment]
 * @returns {string}
 */
function getEnvironmentToken(environment = process.env) {
  return normalizeToken(environment?.CRAFTSEC_API_TOKEN ?? environment?.CRAFTSEC_ENGINE_TOKEN);
}

/**
 * @typedef {Object} ApiConfiguration
 * @property {string} baseUrl
 * @property {number} requestTimeoutMs
 * @property {number} healthTimeoutMs
 * @property {boolean} sendSourceText
 * @property {string} token
 */

/**
 * @param {{
 *   baseUrl?: unknown,
 *   requestTimeoutMs?: unknown,
 *   healthTimeoutMs?: unknown,
 *   sendSourceText?: unknown,
 *   token?: unknown
 * }} [raw]
 * @returns {ApiConfiguration}
 */
function normalizeApiConfiguration(raw = {}) {
  return Object.freeze({
    baseUrl: normalizeBackendUrl(raw.baseUrl ?? DEFAULT_BACKEND_URL),
    requestTimeoutMs: normalizeTimeout(
      raw.requestTimeoutMs,
      DEFAULT_REQUEST_TIMEOUT_MS,
      MIN_REQUEST_TIMEOUT_MS,
      MAX_REQUEST_TIMEOUT_MS
    ),
    healthTimeoutMs: normalizeTimeout(
      raw.healthTimeoutMs,
      DEFAULT_HEALTH_TIMEOUT_MS,
      MIN_HEALTH_TIMEOUT_MS,
      MAX_HEALTH_TIMEOUT_MS
    ),
    sendSourceText: raw.sendSourceText !== false,
    token: normalizeToken(raw.token)
  });
}

/**
 * Read the raw API settings from a VS Code WorkspaceConfiguration.
 *
 * @param {import('vscode').WorkspaceConfiguration} configuration
 * @param {NodeJS.ProcessEnv} [environment]
 * @returns {Record<string, unknown>}
 */
function readRawApiConfiguration(configuration, environment = process.env) {
  return {
    baseUrl: configuration.get('backend.url', DEFAULT_BACKEND_URL),
    requestTimeoutMs: configuration.get('backend.requestTimeoutMs', DEFAULT_REQUEST_TIMEOUT_MS),
    healthTimeoutMs: configuration.get('backend.healthTimeoutMs', DEFAULT_HEALTH_TIMEOUT_MS),
    sendSourceText: configuration.get('privacy.sendSourceText', true),
    token: getEnvironmentToken(environment)
  };
}

/**
 * Create the configuration service consumed by the HTTP security engine.
 *
 * `get()` is evaluated per request so changes to the backend URL, timeouts, or
 * source-sharing setting take effect without reloading the extension.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   environment?: NodeJS.ProcessEnv
 * }} dependencies
 */
function createConfigurationService({ vscode, environment = process.env }) {
  if (!vscode || !vscode.workspace || typeof vscode.workspace.getConfiguration !== 'function') {
    throw new TypeError('createConfigurationService requires the VS Code workspace API.');
  }

  return Object.freeze({
    /** @returns {ApiConfiguration} */
    get() {
      return normalizeApiConfiguration(
        readRawApiConfiguration(vscode.workspace.getConfiguration(SECTION), environment)
      );
    },
    /** @returns {Record<string, unknown>} */
    getRaw() {
      return readRawApiConfiguration(vscode.workspace.getConfiguration(SECTION), environment);
    }
  });
}

/**
 * @param {string} baseUrl
 * @returns {boolean}
 */
function isLoopbackBackendUrl(baseUrl) {
  try {
    const hostname = new URL(baseUrl).hostname.toLowerCase();
    return (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname === '::1'
    );
  } catch {
    return false;
  }
}

module.exports = {
  SECTION,
  DEFAULT_BACKEND_URL,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEALTH_TIMEOUT_MS,
  MIN_REQUEST_TIMEOUT_MS,
  MAX_REQUEST_TIMEOUT_MS,
  MIN_HEALTH_TIMEOUT_MS,
  MAX_HEALTH_TIMEOUT_MS,
  ConfigurationError,
  normalizeBackendUrl,
  normalizeTimeout,
  normalizeApiConfiguration,
  readRawApiConfiguration,
  getEnvironmentToken,
  createConfigurationService,
  isLoopbackBackendUrl
};
