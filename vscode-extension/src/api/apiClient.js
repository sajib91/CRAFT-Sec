'use strict';

/**
 * Minimal HTTP client for the local CRAFT-Sec FastAPI service.
 *
 * The client deliberately uses the platform `fetch` rather than adding a
 * runtime npm dependency: the VSIX is packaged with `--no-dependencies`.
 * It performs no retries, never logs request bodies or tokens, and maps every
 * transport failure to a typed error that a command can show to the user.
 */

const API_PREFIX = '/api/v1';
const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

class ApiClientError extends Error {
  /**
   * @param {string} message
   * @param {{
   *   code?: string,
   *   status?: number,
   *   requestId?: string,
   *   details?: unknown,
   *   retryable?: boolean,
   *   cause?: unknown
   * }} [options]
   */
  constructor(message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'ApiClientError';
    this.code = options.code ?? 'E_API';
    this.status = options.status;
    this.requestId = options.requestId;
    this.details = options.details;
    this.retryable = options.retryable === true;
  }
}

class BackendUnavailableError extends ApiClientError {
  /**
   * @param {string} baseUrl
   * @param {unknown} [cause]
   */
  constructor(baseUrl, cause) {
    super(
      `Cannot reach the CRAFT-Sec backend at ${baseUrl}. Start the local security engine and ` +
        'verify the craftsec.backend.url setting. No analysis was performed.',
      { code: 'E_BACKEND_UNAVAILABLE', retryable: true, cause }
    );
    this.name = 'BackendUnavailableError';
    this.baseUrl = baseUrl;
  }
}

class RequestTimeoutError extends ApiClientError {
  /**
   * @param {string} baseUrl
   * @param {number} timeoutMs
   */
  constructor(baseUrl, timeoutMs) {
    super(
      `The CRAFT-Sec backend at ${baseUrl} did not respond within ${timeoutMs} ms. ` +
        'No analysis was performed.',
      { code: 'E_REQUEST_TIMEOUT', retryable: true }
    );
    this.name = 'RequestTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

class RequestCancelledError extends ApiClientError {
  constructor() {
    super('The CRAFT-Sec request was cancelled. No analysis was performed.', {
      code: 'E_CANCELLED'
    });
    this.name = 'AbortError';
  }
}

class ApiHttpError extends ApiClientError {
  /**
   * @param {number} status
   * @param {string} statusText
   * @param {string} [requestId]
   */
  constructor(status, statusText, requestId) {
    super(
      `The CRAFT-Sec backend rejected the request with HTTP ${status}${
        statusText ? ` ${statusText}` : ''
      }.${requestId ? ` Request ID: ${requestId}.` : ''}`,
      { code: 'E_HTTP', status, requestId, retryable: status >= 500 }
    );
    this.name = 'ApiHttpError';
  }
}

class ApiProblemError extends ApiClientError {
  /**
   * @param {Record<string, any>} problem
   * @param {number} fallbackStatus
   * @param {string | undefined} requestId
   */
  constructor(problem, fallbackStatus, requestId) {
    const status = Number.isInteger(problem.status) ? problem.status : fallbackStatus;
    const resolvedRequestId =
      typeof problem.requestId === 'string' && problem.requestId.length > 0
        ? problem.requestId
        : requestId;
    super(formatProblemMessage(problem, status, resolvedRequestId), {
      code: typeof problem.code === 'string' ? problem.code : 'E_PROBLEM',
      status,
      requestId: resolvedRequestId,
      details: problem.details,
      retryable: problem.retryable === true
    });
    this.name = 'ApiProblemError';
    this.title = typeof problem.title === 'string' ? problem.title : 'Request failed';
    this.type = typeof problem.type === 'string' ? problem.type : undefined;
    this.problem = problem;
  }
}

class ApiResponseError extends ApiClientError {
  /**
   * @param {string} message
   * @param {string} [requestId]
   */
  constructor(message, requestId) {
    super(message, { code: 'E_INVALID_RESPONSE', requestId });
    this.name = 'ApiResponseError';
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
 * @param {Record<string, any>} problem
 * @param {number} status
 * @param {string | undefined} requestId
 * @returns {string}
 */
function formatProblemMessage(problem, status, requestId) {
  const detail =
    typeof problem.detail === 'string' && problem.detail.trim().length > 0
      ? problem.detail.trim()
      : typeof problem.title === 'string' && problem.title.trim().length > 0
        ? problem.title.trim()
        : `The CRAFT-Sec backend rejected the request with HTTP ${status}.`;
  const parts = [detail];
  if (typeof problem.code === 'string' && problem.code.length > 0) {
    parts.push(`(${problem.code})`);
  }

  const errors = isPlainObject(problem.details) ? problem.details.errors : undefined;
  if (Array.isArray(errors) && errors.length > 0) {
    const summary = errors
      .slice(0, 3)
      .map((error) => {
        if (!isPlainObject(error)) {
          return undefined;
        }
        const location = Array.isArray(error.location) ? error.location.join('.') : 'request';
        const message = typeof error.message === 'string' ? error.message : 'is invalid';
        return `${location}: ${message}`;
      })
      .filter(Boolean)
      .join('; ');
    if (summary.length > 0) {
      parts.push(`Details: ${summary}.`);
    }
  }

  if (status === 401) {
    parts.push(
      'If the backend was started with CRAFTSEC_API_TOKEN, set the same value in the ' +
        'extension host environment.'
    );
  }
  if (requestId) {
    parts.push(`Request ID: ${requestId}.`);
  }
  return parts.join(' ');
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isProblemDetail(value) {
  return (
    isPlainObject(value) &&
    (typeof value.title === 'string' || typeof value.detail === 'string') &&
    (typeof value.code === 'string' || Number.isInteger(value.status))
  );
}

class ApiClient {
  /**
   * @param {{
   *   baseUrl: string,
   *   requestTimeoutMs?: number,
   *   healthTimeoutMs?: number,
   *   token?: string,
   *   fetchImpl?: typeof fetch,
   *   maxResponseBytes?: number,
   *   userAgent?: string
   * }} options
   */
  constructor({
    baseUrl,
    requestTimeoutMs = 30_000,
    healthTimeoutMs = 3_000,
    token = '',
    fetchImpl,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    userAgent = 'craftsec-vscode/0.1.0'
  }) {
    if (typeof fetchImpl !== 'function') {
      if (typeof globalThis.fetch !== 'function') {
        throw new TypeError('The current runtime does not provide fetch().');
      }
      fetchImpl = globalThis.fetch.bind(globalThis);
    }
    if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs <= 0) {
      throw new TypeError('requestTimeoutMs must be a positive integer.');
    }
    if (!Number.isInteger(healthTimeoutMs) || healthTimeoutMs <= 0) {
      throw new TypeError('healthTimeoutMs must be a positive integer.');
    }

    this.baseUrl = String(baseUrl).replace(/\/+$/, '');
    this.requestTimeoutMs = requestTimeoutMs;
    this.healthTimeoutMs = healthTimeoutMs;
    this.token = typeof token === 'string' ? token.trim() : '';
    this.fetchImpl = fetchImpl;
    this.maxResponseBytes = maxResponseBytes;
    this.userAgent = userAgent;
  }

  /**
   * @param {import('vscode').CancellationToken | undefined} token
   * @param {number} timeoutMs
   * @returns {Promise<{ data: unknown, requestId?: string, status: number }>}
   */
  async health(token) {
    return this.request(`${API_PREFIX}/health`, {
      method: 'GET',
      timeoutMs: this.healthTimeoutMs,
      token
    });
  }

  /**
   * @param {string} path
   * @param {object} body
   * @param {import('vscode').CancellationToken | undefined} token
   * @returns {Promise<{ data: unknown, requestId?: string, status: number }>}
   */
  async post(path, body, token) {
    return this.request(`${API_PREFIX}${path}`, {
      method: 'POST',
      body,
      timeoutMs: this.requestTimeoutMs,
      token
    });
  }

  /**
   * @param {string} path
   * @param {{
   *   method: 'GET' | 'POST',
   *   body?: object,
   *   timeoutMs: number,
   *   token?: import('vscode').CancellationToken
   * }} options
   * @returns {Promise<{ data: unknown, requestId?: string, status: number }>}
   */
  async request(path, { method, body, timeoutMs, token }) {
    if (typeof path !== 'string' || !path.startsWith(`${API_PREFIX}/`)) {
      throw new TypeError(`API path must start with ${API_PREFIX}/: ${path}`);
    }

    const url = new URL(path, `${this.baseUrl}/`).toString();
    const controller = new AbortController();
    let timedOut = false;
    let cancelled = false;
    let cancellationSubscription;

    if (token?.isCancellationRequested) {
      cancelled = true;
      controller.abort();
    } else if (typeof token?.onCancellationRequested === 'function') {
      cancellationSubscription = token.onCancellationRequested(() => {
        cancelled = true;
        controller.abort();
      });
    }

    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    const headers = {
      Accept: 'application/json',
      'User-Agent': this.userAgent
    };
    if (method === 'POST') {
      headers['Content-Type'] = 'application/json';
    }
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    /** @type {RequestInit} */
    const init = {
      method,
      headers,
      signal: controller.signal
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    let response;
    try {
      if (cancelled) {
        throw new RequestCancelledError();
      }
      response = await this.fetchImpl(url, init);
    } catch (error) {
      if (error instanceof ApiClientError) {
        throw error;
      }
      if (timedOut) {
        throw new RequestTimeoutError(this.baseUrl, timeoutMs);
      }
      if (cancelled || controller.signal.aborted) {
        throw new RequestCancelledError();
      }
      throw new BackendUnavailableError(this.baseUrl, error);
    } finally {
      clearTimeout(timer);
      cancellationSubscription?.dispose?.();
    }

    const responseText = await response.text();
    if (responseText.length > this.maxResponseBytes) {
      throw new ApiResponseError(
        `The CRAFT-Sec backend response exceeded ${this.maxResponseBytes} bytes.`,
        response.headers?.get?.('x-request-id') ?? undefined
      );
    }

    let data;
    if (responseText.trim().length > 0) {
      try {
        data = JSON.parse(responseText);
      } catch {
        if (!response.ok) {
          throw new ApiHttpError(
            response.status,
            response.statusText,
            response.headers?.get?.('x-request-id') ?? undefined
          );
        }
        throw new ApiResponseError(
          'The CRAFT-Sec backend returned a response that is not valid JSON.',
          response.headers?.get?.('x-request-id') ?? undefined
        );
      }
    }

    const headerRequestId = response.headers?.get?.('x-request-id') ?? undefined;
    const bodyRequestId =
      isPlainObject(data) && typeof data.requestId === 'string' ? data.requestId : undefined;
    const requestId = headerRequestId ?? bodyRequestId;

    if (!response.ok) {
      if (isProblemDetail(data)) {
        throw new ApiProblemError(data, response.status, requestId);
      }
      throw new ApiHttpError(response.status, response.statusText, requestId);
    }

    if (data === undefined) {
      throw new ApiResponseError(
        'The CRAFT-Sec backend returned an empty response body.',
        requestId
      );
    }

    return { data, requestId, status: response.status };
  }
}

/**
 * @param {ConstructorParameters<typeof ApiClient>[0]} options
 * @returns {ApiClient}
 */
function createApiClient(options) {
  return new ApiClient(options);
}

module.exports = {
  API_PREFIX,
  ApiClient,
  ApiClientError,
  BackendUnavailableError,
  RequestTimeoutError,
  RequestCancelledError,
  ApiHttpError,
  ApiProblemError,
  ApiResponseError,
  createApiClient
};
