'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { createSidebarHtml, escapeAttribute } = require('../../src/webviews/sidebarHtml');

const NONCE = 'sidebar-nonce-0123456789';

function createHtml(options = {}) {
  return createSidebarHtml({
    cspSource: 'vscode-webview://test',
    styleUri: 'vscode-webview://test/media/sidebar.css',
    scriptUri: 'vscode-webview://test/media/sidebar.js',
    nonce: NONCE,
    ...options
  });
}

test('sidebar launcher uses a strict nonce CSP', () => {
  const html = createHtml();

  assert.match(html, /default-src &#39;none&#39;/);
  assert.match(html, /style-src vscode-webview:\/\/test/);
  assert.match(html, new RegExp(`script-src &#39;nonce-${NONCE}&#39;`));
  assert.match(html, /connect-src &#39;none&#39;/);
  assert.match(html, /img-src &#39;none&#39;/);
  assert.ok(!html.includes('unsafe-inline'));
  assert.ok(!html.includes('unsafe-eval'));
  assert.ok(!/https?:\/\//.test(html), 'sidebar must not reference remote origins');
});

test('sidebar launcher renders local assets and the dashboard action', () => {
  const html = createHtml();

  assert.match(html, /href="vscode-webview:\/\/test\/media\/sidebar.css"/);
  assert.match(
    html,
    new RegExp(
      `<script nonce="${NONCE}" src="vscode-webview://test/media/sidebar.js" defer><\\/script>`
    )
  );
  assert.match(html, /Open Security Dashboard/);
  assert.match(html, /Engine status/);
  assert.match(html, /Not connected/);
  assert.match(html, /No analysis results are produced in this build/);
  assert.match(html, /<noscript>/);
});

test('sidebar launcher requires a nonce', () => {
  assert.throws(() => createHtml({ nonce: 'short' }), /nonce/);
});

test('sidebar script only posts the openDashboard message', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../../media/sidebar.js'), 'utf8');

  assert.match(source, /postMessage\(\{ type: 'openDashboard' \}\)/);
  assert.ok(!source.includes('innerHTML'));
  assert.ok(!source.includes('executeCommand'));
  assert.ok(!source.includes('fetch('));
});

test('attribute escaping prevents markup injection', () => {
  assert.equal(escapeAttribute(`a"b<c>d&e`), 'a&quot;b&lt;c&gt;d&amp;e');
  assert.equal(escapeAttribute(`a'b`), 'a&#39;b');
});
