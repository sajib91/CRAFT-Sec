'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { COMMANDS } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const {
  DASHBOARD_SCHEMA_VERSION,
  DASHBOARD_SECTIONS,
  DASHBOARD_ACTIONS,
  DEMO_NOTICE,
  ENGINE_UNAVAILABLE,
  buildDashboardState,
  createEmptyDashboardState,
  createDemoDashboardState,
  normalizeEngine,
  normalizeSettings
} = require('../../src/webviews/dashboardModel');

const SECTION_IDS = [
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
];

test('dashboard sections are canonical and complete', () => {
  assert.deepEqual(
    DASHBOARD_SECTIONS.map((section) => section.id),
    SECTION_IDS
  );
  assert.equal(new Set(SECTION_IDS).size, 11);
  for (const section of DASHBOARD_SECTIONS) {
    assert.equal(typeof section.label, 'string');
    assert.ok(section.label.length > 1);
    assert.equal(typeof section.description, 'string');
    assert.ok(section.description.length > 0);
  }
});

test('dashboard actions only reference engine-backed commands', () => {
  const engineCommands = new Set(
    COMMAND_DEFINITIONS.filter((definition) => definition.serviceMethod).map(
      (definition) => definition.id
    )
  );

  assert.ok(DASHBOARD_ACTIONS.length > 0);
  assert.equal(
    new Set(DASHBOARD_ACTIONS.map((action) => action.id)).size,
    DASHBOARD_ACTIONS.length
  );

  for (const action of DASHBOARD_ACTIONS) {
    assert.ok(engineCommands.has(action.command), `${action.command} must be engine-backed`);
    assert.ok(SECTION_IDS.includes(action.section));
    assert.equal(typeof action.title, 'string');
    assert.equal(typeof action.description, 'string');
    assert.equal(typeof action.meta, 'string');
  }

  const commands = DASHBOARD_ACTIONS.map((action) => action.command);
  assert.ok(commands.includes(COMMANDS.scanCurrentFile));
  assert.ok(commands.includes(COMMANDS.scanWorkspace));
  assert.ok(commands.includes(COMMANDS.verifyRepair));
});

test('empty dashboard state reports unknowns as null, never zero', () => {
  const state = createEmptyDashboardState({ generatedAt: '2026-11-11T12:00:00.000Z' });

  assert.equal(state.schemaVersion, DASHBOARD_SCHEMA_VERSION);
  assert.equal(state.dataMode, 'empty');
  assert.equal(state.demoNotice, '');
  assert.equal(state.generatedAt, '2026-11-11T12:00:00.000Z');
  assert.equal(state.sections, DASHBOARD_SECTIONS);
  assert.equal(state.actions, DASHBOARD_ACTIONS);
  assert.equal(state.summary.totalFindings, null);
  assert.deepEqual(state.summary.severity, {
    critical: null,
    high: null,
    medium: null,
    low: null
  });
  assert.equal(state.summary.lastScanAt, null);
  assert.equal(state.summary.workspaceName, null);
  assert.deepEqual(state.vulnerabilityDistribution, []);
  assert.deepEqual(state.cweDistribution, []);
  assert.deepEqual(state.scanHistory, []);
  assert.deepEqual(state.vulnerabilities, []);
  assert.deepEqual(state.explanations, []);
  assert.deepEqual(state.repairs, []);
  assert.deepEqual(state.reports, []);
  assert.equal(state.sae.available, false);
  assert.deepEqual(state.sae.features, []);
  assert.equal(state.featureInteractions.available, false);
  assert.deepEqual(state.featureInteractions.items, []);
  assert.equal(state.steering.available, false);
  assert.deepEqual(state.steering.controls, []);
  assert.equal(state.verification.status, 'not-run');
  assert.equal(state.verification.label, 'Not run');
  assert.deepEqual(state.verification.checks, []);
  assert.equal(state.verification.executionSandbox.available, false);
  assert.deepEqual(state.engine, ENGINE_UNAVAILABLE);
});

test('demo dashboard state is explicitly labelled and internally consistent', () => {
  const state = createDemoDashboardState({ generatedAt: '2026-11-11T12:00:00.000Z' });

  assert.equal(state.dataMode, 'demo');
  assert.equal(state.demoNotice, DEMO_NOTICE);
  assert.match(state.demoNotice, /Demo data/);
  assert.match(state.demoNotice, /not produced by a scan/i);
  assert.equal(state.summary.totalFindings, 18);
  assert.equal(state.vulnerabilities.length, 18);
  assert.equal(
    state.summary.severity.critical +
      state.summary.severity.high +
      state.summary.severity.medium +
      state.summary.severity.low,
    state.summary.totalFindings
  );

  for (const severity of ['critical', 'high', 'medium', 'low']) {
    assert.equal(
      state.vulnerabilities.filter((finding) => finding.severity === severity).length,
      state.summary.severity[severity]
    );
  }

  assert.equal(
    state.vulnerabilityDistribution.reduce((sum, item) => sum + item.count, 0),
    state.summary.totalFindings
  );
  assert.equal(
    state.cweDistribution.reduce((sum, item) => sum + item.count, 0),
    state.summary.totalFindings
  );

  for (const item of state.cweDistribution) {
    assert.equal(
      state.vulnerabilities.filter((finding) => finding.cwe === item.cwe).length,
      item.count,
      `${item.cwe} count must match the demo findings`
    );
  }

  assert.equal(state.scanHistory.length, 3);
  assert.ok(state.scanHistory.every((scan) => typeof scan.startedAt === 'string'));
});

test('demo mode does not simulate SAE, interaction, steering, repair, or verification results', () => {
  const state = createDemoDashboardState({ generatedAt: '2026-11-11T12:00:00.000Z' });

  assert.equal(state.sae.available, false);
  assert.deepEqual(state.sae.features, []);
  assert.equal(state.featureInteractions.available, false);
  assert.deepEqual(state.featureInteractions.items, []);
  assert.equal(state.steering.available, false);
  assert.deepEqual(state.steering.controls, []);
  assert.deepEqual(state.explanations, []);
  assert.deepEqual(state.repairs, []);
  assert.deepEqual(state.reports, []);
  assert.equal(state.verification.status, 'not-run');
  assert.deepEqual(state.verification.checks, []);
  assert.equal(state.verification.executionSandbox.available, false);
  assert.match(state.verification.summary, /Demo preview only/);
});

test('buildDashboardState selects the requested data mode', () => {
  const generatedAt = '2026-11-11T12:00:00.000Z';
  const empty = buildDashboardState({ dataMode: 'empty', generatedAt });
  const demo = buildDashboardState({ dataMode: 'demo', generatedAt });
  const fallback = buildDashboardState({ dataMode: 'live', generatedAt });

  assert.equal(empty.dataMode, 'empty');
  assert.equal(demo.dataMode, 'demo');
  assert.equal(fallback.dataMode, 'empty', 'live data must not be invented');
});

test('settings and engine normalization reject unsupported values', () => {
  assert.deepEqual(normalizeSettings(), {
    pythonPath: '',
    autoStart: false,
    logLevel: 'info',
    showStatusBarItem: true
  });
  assert.deepEqual(
    normalizeSettings({
      pythonPath: '/usr/bin/python3',
      autoStart: true,
      logLevel: 'trace',
      showStatusBarItem: false
    }),
    {
      pythonPath: '/usr/bin/python3',
      autoStart: true,
      logLevel: 'trace',
      showStatusBarItem: false
    }
  );
  assert.equal(normalizeSettings({ logLevel: 'verbose' }).logLevel, 'info');
  assert.equal(normalizeSettings({ showStatusBarItem: null }).showStatusBarItem, true);

  assert.deepEqual(normalizeEngine({ status: 'ready', label: 'Ready', detail: 'OK' }), {
    status: 'ready',
    label: 'Ready',
    detail: 'OK'
  });
  assert.deepEqual(normalizeEngine(), ENGINE_UNAVAILABLE);
});

test('state options inject settings without changing other sections', () => {
  const state = createEmptyDashboardState({
    settings: {
      pythonPath: '/custom/python',
      autoStart: true,
      logLevel: 'warn',
      showStatusBarItem: false
    },
    engine: { status: 'ready', label: 'Engine ready', detail: 'Capabilities loaded.' }
  });

  assert.equal(state.settings.pythonPath, '/custom/python');
  assert.equal(state.settings.autoStart, true);
  assert.equal(state.settings.logLevel, 'warn');
  assert.equal(state.settings.showStatusBarItem, false);
  assert.equal(state.engine.status, 'ready');
  assert.deepEqual(state.vulnerabilities, []);
});
