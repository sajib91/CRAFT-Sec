'use strict';

const crypto = require('node:crypto');

/**
 * Create a per-render nonce for webview scripts.
 *
 * @returns {string}
 */
function createNonce() {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * Build a restrictive Content Security Policy for a webview.
 *
 * Executable scripts require the per-render nonce. Styles are limited to
 * resources served by the webview itself. Network, media, frames, workers,
 * forms, and inline script/style are disabled.
 *
 * @param {{ cspSource: string, nonce: string }} options
 * @returns {string}
 */
function buildContentSecurityPolicy({ cspSource, nonce }) {
  if (typeof cspSource !== 'string' || cspSource.length === 0) {
    throw new TypeError('A webview cspSource is required.');
  }
  if (typeof nonce !== 'string' || nonce.length < 16) {
    throw new TypeError('A sufficiently long webview script nonce is required.');
  }

  return [
    "default-src 'none'",
    `style-src ${cspSource}`,
    `script-src 'nonce-${nonce}'`,
    "connect-src 'none'",
    "img-src 'none'",
    "font-src 'none'",
    "media-src 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "worker-src 'none'",
    "base-uri 'none'",
    "form-action 'none'"
  ].join('; ');
}

module.exports = { createNonce, buildContentSecurityPolicy };
