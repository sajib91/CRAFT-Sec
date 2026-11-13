'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  ApiClient,
  ApiHttpError,
  ApiProblemError,
  ApiResponseError,
  BackendUnavailableError,
  RequestCancelledError,
  RequestTimeoutError
} = require('../../src/api/apiClient');

const BASE_URL = 'http://127.0.0.1:8765';

/**
 * @param {unknown} data
 * @param {{ status?: number, statusText?: string, headers?: Record<string, string> }} [options]
 */
function jsonResponse(data, options = {}) {
  const status = options.status ?? 200;
  const headers = options.headers ?? {};
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: options.statusText ?? '',
    headers: {
      get(name) {
        return headers[name.toLowerCase()] ?? null;
      }
    },
    async text() {
      return typeof data === 'string' ? data : JSON.stringify(data);
    }
  };
}

function createClient(fetchImpl, options = {}) {
  return new ApiClient({ baseUrl: BASE_URL, fetchImpl, ...options });
}

test('health sends an unauthenticated GET to the versioned endpoint', async () => {
  const requests = [];
  const client = createClient(async (url, init) => {
    requests.push({ url, init });
    return jsonResponse({ status: 'ok' });
  });

  const result = await client.health();

  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, `${BASE_URL}/api/v1/health`);
  assert.equal(requests[0].init.method, 'GET');
  assert.equal(requests[0].init.body, undefined);
  assert.equal(requests[0].init.headers.Accept, 'application/json');
  assert.equal('Authorization' in requests[0].init.headers, false);
  assert.equal(result.status, 200);
});

test('post sends JSON and a bearer token when configured', async () => {
  const requests = [];
  const client = createClient(
    async (url, init) => {
      requests.push({ url, init });
      return jsonResponse({ ok: true });
    },
    { token: '  secret-token  ' }
  );

  await client.post('/scan/file', { filePath: '/workspace/a.js' }, undefined);

  assert.equal(requests[0].url, `${BASE_URL}/api/v1/scan/file`);
  assert.equal(requests[0].init.method, 'POST');
  assert.equal(requests[0].init.headers['Content-Type'], 'application/json');
  assert.equal(requests[0].init.headers.Authorization, 'Bearer secret-token');
  assert.deepEqual(JSON.parse(requests[0].init.body), { filePath: '/workspace/a.js' });
});

test('problem details become a typed error with code, details, and request ID', async () => {
  const problem = {
    type: 'https://craftsec.local/problems/validation',
    title: 'Request validation failed',
    status: 422,
    code: 'E_VALIDATION',
    detail: 'The request is invalid.',
    instance: '/api/v1/scan/file',
    retryable: false,
    requestId: 'req-problem',
    details: {
      errors: [{ location: ['body', 'filePath'], message: 'Field required' }]
    }
  };
  const client = createClient(async () =>
    jsonResponse(problem, {
      status: 422,
      statusText: 'Unprocessable Entity',
      headers: { 'x-request-id': 'req-header' }
    })
  );

  await assert.rejects(
    () => client.post('/scan/file', {}),
    (error) => {
      assert.ok(error instanceof ApiProblemError);
      assert.equal(error.code, 'E_VALIDATION');
      assert.equal(error.status, 422);
      assert.equal(error.requestId, 'req-problem');
      assert.equal(error.retryable, false);
      assert.match(error.message, /The request is invalid\./);
      assert.match(error.message, /body\.filePath: Field required/);
      return true;
    }
  );
});

test('a non-JSON error body becomes a generic HTTP error', async () => {
  const client = createClient(async () =>
    jsonResponse('<html>bad gateway</html>', {
      status: 502,
      statusText: 'Bad Gateway',
      headers: { 'x-request-id': 'req-http' }
    })
  );

  await assert.rejects(
    () => client.post('/scan/file', {}),
    (error) => {
      assert.ok(error instanceof ApiHttpError);
      assert.equal(error.code, 'E_HTTP');
      assert.equal(error.status, 502);
      assert.equal(error.retryable, true);
      assert.equal(error.requestId, 'req-http');
      return true;
    }
  );
});

test('an empty successful response is rejected', async () => {
  const client = createClient(async () => jsonResponse(''));

  await assert.rejects(
    () => client.post('/scan/file', {}),
    (error) => {
      assert.ok(error instanceof ApiResponseError);
      assert.equal(error.code, 'E_INVALID_RESPONSE');
      assert.match(error.message, /empty response/);
      return true;
    }
  );
});

test('a malformed successful response is rejected', async () => {
  const client = createClient(async () => jsonResponse('{'));

  await assert.rejects(
    () => client.post('/scan/file', {}),
    (error) => {
      assert.ok(error instanceof ApiResponseError);
      assert.match(error.message, /not valid JSON/);
      return true;
    }
  );
});

test('responses larger than the configured limit are rejected', async () => {
  const client = createClient(async () => jsonResponse({ payload: 'x'.repeat(64) }), {
    maxResponseBytes: 16
  });

  await assert.rejects(
    () => client.post('/scan/file', {}),
    (error) => {
      assert.ok(error instanceof ApiResponseError);
      assert.match(error.message, /exceeded 16 bytes/);
      return true;
    }
  );
});

test('network failures become an unavailable-backend error', async () => {
  const client = createClient(async () => {
    throw new TypeError('fetch failed');
  });

  await assert.rejects(
    () => client.health(),
    (error) => {
      assert.ok(error instanceof BackendUnavailableError);
      assert.equal(error.code, 'E_BACKEND_UNAVAILABLE');
      assert.equal(error.baseUrl, BASE_URL);
      assert.match(error.message, /No analysis was performed/);
      return true;
    }
  );
});

test('a request that exceeds its timeout is aborted and reported', async () => {
  const client = createClient(
    (url, init) =>
      new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
      }),
    { healthTimeoutMs: 20 }
  );

  await assert.rejects(
    () => client.health(),
    (error) => {
      assert.ok(error instanceof RequestTimeoutError);
      assert.equal(error.code, 'E_REQUEST_TIMEOUT');
      assert.equal(error.timeoutMs, 20);
      assert.match(error.message, /did not respond within 20 ms/);
      return true;
    }
  );
});

test('a cancellation token aborts the request and reports cancellation', async () => {
  let cancel;
  let disposed = false;
  const token = {
    isCancellationRequested: false,
    onCancellationRequested(callback) {
      cancel = callback;
      return {
        dispose() {
          disposed = true;
        }
      };
    }
  };
  const client = createClient(
    (url, init) =>
      new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
        cancel();
      })
  );

  await assert.rejects(
    () => client.post('/scan/file', {}, token),
    (error) => {
      assert.ok(error instanceof RequestCancelledError);
      assert.equal(error.name, 'AbortError');
      assert.equal(error.code, 'E_CANCELLED');
      assert.match(error.message, /cancelled/);
      return true;
    }
  );
  assert.equal(disposed, true);
});

test('a pre-cancelled token never performs a network request', async () => {
  let calls = 0;
  const client = createClient(async () => {
    calls += 1;
    return jsonResponse({ status: 'ok' });
  });

  await assert.rejects(
    () => client.health({ isCancellationRequested: true }),
    (error) => {
      assert.ok(error instanceof RequestCancelledError);
      return true;
    }
  );
  assert.equal(calls, 0);
});

test('paths outside the versioned API prefix are rejected', async () => {
  const client = createClient(async () => jsonResponse({}));

  await assert.rejects(() => client.request('/health', { method: 'GET', timeoutMs: 10 }), {
    name: 'TypeError'
  });
});
