'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname, '../../media/dashboard.js'), 'utf8');

test('dashboard client avoids unsafe rendering and network APIs', () => {
  assert.ok(!/\.innerHTML\s*=/.test(source), 'dynamic innerHTML is forbidden');
  assert.ok(!source.includes('outerHTML'));
  assert.ok(!source.includes('insertAdjacentHTML'));
  assert.ok(!source.includes('document.write'));
  assert.ok(!source.includes('eval('));
  assert.ok(!source.includes('new Function'));
  assert.ok(!source.includes('fetch('));
  assert.ok(!source.includes('XMLHttpRequest'));
  assert.ok(!/https?:\/\//.test(source), 'dashboard client must not reference remote origins');
  assert.ok(!source.includes('.style.'), 'client must not set inline styles');
});

test('dashboard client renders all eleven dashboard sections', () => {
  for (const sectionId of [
    'overview',
    'scan',
    'vulnerabilities',
    'saeFeatures',
    'featureInteractions',
    'securitySteering',
    'explanations',
    'automatedRepair',
    'verification',
    'researchReports',
    'settings'
  ]) {
    assert.ok(source.includes(`'${sectionId}'`), `${sectionId} must be handled`);
  }

  assert.ok(source.includes("sendMessage({ type: 'ready' })"));
  assert.ok(source.includes("type: 'refresh'"));
  assert.ok(source.includes("type: 'setDemoMode'"));
  assert.ok(source.includes("type: 'executeCommand'"));
  assert.ok(source.includes("type: 'openSettings'"));
  assert.ok(source.includes("type: 'showLogs'"));
});

test('dashboard client labels demo and unavailability states honestly', () => {
  assert.match(source, /Demo data/);
  assert.match(source, /not real-world causal claims/i);
  assert.match(source, /Not run is not a pass/i);
  assert.match(source, /No activation values are inferred/i);
  assert.match(source, /No patch has been applied/i);
  assert.match(source, /not probabilities/i);
});

test('dashboard client validates commands before posting them', () => {
  assert.ok(source.includes('safeCommandPattern'));
  assert.ok(source.includes('/^craftsec\\.[A-Za-z][A-Za-z0-9]*$/'));
  assert.ok(source.includes('command: action.command'));
});
