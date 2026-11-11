'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createDashboardHtml, buildNavigation } = require('../../src/webviews/dashboardHtml');
const {
  createEmptyDashboardState,
  DASHBOARD_SECTIONS
} = require('../../src/webviews/dashboardModel');
const { escapeAttribute, serializeStateForScript } = require('../../src/webviews/html');

const NONCE = 'test-nonce-0123456789';

function createHtml(options = {}) {
  const state = options.state ?? createEmptyDashboardState({ generatedAt: '2026-11-11T12:00:00Z' });
  return createDashboardHtml({
    cspSource: 'vscode-webview://test',
    styleUri: 'vscode-webview://test/media/dashboard.css',
    scriptUri: 'vscode-webview://test/media/dashboard.js',
    nonce: NONCE,
    state
  });
}

test('dashboard shell uses a restrictive nonce CSP with no network or inline execution', () => {
  const html = createHtml();

  assert.match(html, /default-src &#39;none&#39;/);
  assert.match(html, new RegExp(`script-src &#39;nonce-${NONCE}&#39;`));
  assert.match(html, /style-src vscode-webview:\/\/test/);
  assert.match(html, /connect-src &#39;none&#39;/);
  assert.match(html, /img-src &#39;none&#39;/);
  assert.match(html, /object-src &#39;none&#39;/);
  assert.match(html, /frame-src &#39;none&#39;/);
  assert.match(html, /worker-src &#39;none&#39;/);
  assert.match(html, /form-action &#39;none&#39;/);
  assert.ok(!html.includes('unsafe-inline'));
  assert.ok(!html.includes('unsafe-eval'));
  assert.ok(!/https?:\/\//.test(html), 'dashboard must not reference remote origins');
});

test('dashboard shell loads the local stylesheet and nonce-authorized script', () => {
  const html = createHtml();

  assert.match(html, /href="vscode-webview:\/\/test\/media\/dashboard.css"/);
  assert.match(
    html,
    new RegExp(
      `<script nonce="${NONCE}" src="vscode-webview://test/media/dashboard.js" defer><\/script>`
    )
  );
  assert.match(
    html,
    new RegExp(`<script type="application/json" id="dashboard-state" nonce="${NONCE}">`)
  );
  assert.ok(html.includes('Skip to dashboard content'));
  assert.ok(html.includes('CRAFT-Sec Security Dashboard'));
});

test('dashboard shell renders all eleven accessible navigation tabs', () => {
  const html = createHtml();

  assert.match(html, /role="tablist"/);
  assert.match(html, /aria-orientation="vertical"/);
  assert.equal((html.match(/role="tab"/g) ?? []).length, 11);
  assert.equal((html.match(/aria-selected="true"/g) ?? []).length, 1);

  for (const section of DASHBOARD_SECTIONS) {
    assert.ok(html.includes(`id="tab-${section.id}"`), `${section.id} tab must exist`);
    assert.ok(html.includes(`data-section="${section.id}"`), `${section.id} data attribute`);
    assert.ok(html.includes(`>${section.label}<`) || html.includes(section.label), section.label);
  }

  assert.ok(!html.includes('role="tab" aria-selected="false" tabindex="0"'));
});

test('initial state is serialized safely inside the JSON script', () => {
  const state = createEmptyDashboardState({
    generatedAt: '2026-11-11T12:00:00Z',
    settings: {
      pythonPath: '"><script>alert("x")</script>&',
      autoStart: false,
      logLevel: 'info',
      showStatusBarItem: true
    }
  });
  const html = createHtml({ state });
  const match = html.match(
    /<script type="application\/json" id="dashboard-state" nonce="[^"]+">([\s\S]*?)<\/script>/
  );

  assert.ok(match, 'dashboard state script must exist');
  const serialized = match[1];
  assert.ok(serialized.includes('\\u003cscript\\u003e'));
  assert.ok(serialized.includes('\\u0026'));
  assert.ok(!serialized.includes('<script>'));
  assert.equal(JSON.parse(serialized).settings.pythonPath, state.settings.pythonPath);
});

test('navigation builder escapes labels and keeps one selected tab', () => {
  const html = buildNavigation();

  assert.equal((html.match(/role="tab"/g) ?? []).length, 11);
  assert.equal((html.match(/aria-selected="true"/g) ?? []).length, 1);
  assert.ok(html.includes('Overview'));
  assert.ok(html.includes('SAE Features'));
});

test('HTML helpers escape attributes and inline JSON payloads', () => {
  assert.equal(escapeAttribute(`a"b'c<d>e&f`), 'a&quot;b&#39;c&lt;d&gt;e&amp;f');

  const payload = serializeStateForScript({
    value: `<script>&\u2028\u2029`,
    nested: { quote: `"'` }
  });
  assert.ok(payload.includes('\\u003cscript\\u003e'));
  assert.ok(payload.includes('\\u0026'));
  assert.ok(payload.includes('\\u2028'));
  assert.ok(payload.includes('\\u2029'));
  assert.deepEqual(JSON.parse(payload).value, `<script>&\u2028\u2029`);
});

test('dashboard HTML requires a script nonce', () => {
  assert.throws(
    () =>
      createDashboardHtml({
        cspSource: 'vscode-webview://test',
        styleUri: 'vscode-webview://test/media/dashboard.css',
        scriptUri: 'vscode-webview://test/media/dashboard.js',
        nonce: 'short',
        state: createEmptyDashboardState()
      }),
    /nonce/
  );
});
