'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSidebarHtml, escapeAttribute } = require('../../src/webviews/sidebarHtml');

test('sidebar HTML uses a strict script-free CSP', () => {
  const html = createSidebarHtml({
    cspSource: 'vscode-webview://test',
    styleUri: 'vscode-webview://test/media/sidebar.css'
  });

  assert.match(html, /default-src 'none'/);
  assert.match(html, /style-src vscode-webview:\/\/test/);
  assert.ok(!html.includes('<script'), 'sidebar must not load scripts');
  assert.ok(!html.includes('unsafe-inline'), 'sidebar must not allow inline styles');
});

test('sidebar HTML renders local styles and scaffold status', () => {
  const html = createSidebarHtml({
    cspSource: 'vscode-webview://test',
    styleUri: 'vscode-webview://test/media/sidebar.css'
  });

  assert.match(html, /href="vscode-webview:\/\/test\/media\/sidebar.css"/);
  assert.match(html, /Engine status/);
  assert.match(html, /Not connected/);
  assert.match(html, /No analysis results are produced in this build/);
});

test('attribute escaping prevents markup injection', () => {
  assert.equal(escapeAttribute(`a"b<c>d&e`), 'a&quot;b&lt;c&gt;d&amp;e');
});
