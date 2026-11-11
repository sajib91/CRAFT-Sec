'use strict';

const { COMMANDS } = require('../constants');

const DASHBOARD_SCHEMA_VERSION = 1;

/**
 * Canonical dashboard navigation. The webview shell, client renderer, and
 * tests all use this list so section labels cannot drift.
 */
const DASHBOARD_SECTIONS = Object.freeze([
  Object.freeze({
    id: 'overview',
    label: 'Overview',
    icon: 'overview',
    description: 'Security posture, findings, verification, and recent activity.'
  }),
  Object.freeze({
    id: 'scan',
    label: 'Security Scan',
    icon: 'scan',
    description: 'Start a scan and review scan history.'
  }),
  Object.freeze({
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    icon: 'vulnerabilities',
    description: 'Findings by severity, CWE, location, and status.'
  }),
  Object.freeze({
    id: 'saeFeatures',
    label: 'SAE Features',
    icon: 'features',
    description: 'Features measured from a genuine SAE and white-box model.'
  }),
  Object.freeze({
    id: 'featureInteractions',
    label: 'Feature Interactions',
    icon: 'interactions',
    description: 'Counterfactual feature comparisons and their evidence.'
  }),
  Object.freeze({
    id: 'securitySteering',
    label: 'Security Steering',
    icon: 'steering',
    description: 'Capability-gated activation steering controls.'
  }),
  Object.freeze({
    id: 'explanations',
    label: 'Explanations',
    icon: 'explanations',
    description: 'Evidence-backed explanations for reported findings.'
  }),
  Object.freeze({
    id: 'automatedRepair',
    label: 'Automated Repair',
    icon: 'repair',
    description: 'Reviewable repair proposals; source is never modified silently.'
  }),
  Object.freeze({
    id: 'verification',
    label: 'Verification',
    icon: 'verification',
    description: 'Static, functional, and isolated execution verification.'
  }),
  Object.freeze({
    id: 'researchReports',
    label: 'Research Reports',
    icon: 'reports',
    description: 'Reports generated from recorded runs with full provenance.'
  }),
  Object.freeze({
    id: 'settings',
    label: 'Settings',
    icon: 'settings',
    description: 'Extension settings and dashboard data mode.'
  })
]);

const DEMO_NOTICE =
  'Demo data: illustrative interface values only. Not produced by a scan or security engine. ' +
  'SAE activations, feature effects, and verification results are not simulated.';

/**
 * Commands the dashboard may request. Only engine-backed commands are listed;
 * the panel controller independently rejects anything outside its allowlist.
 */
const DASHBOARD_ACTIONS = Object.freeze([
  Object.freeze({
    id: 'scan-current-file',
    section: 'scan',
    command: COMMANDS.scanCurrentFile,
    title: 'Scan current file',
    description: 'Analyze the saved active editor for security-relevant evidence.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'scan-selection',
    section: 'scan',
    command: COMMANDS.scanSelection,
    title: 'Scan selection',
    description: 'Analyze the selected region of the active saved editor.',
    meta: 'Requires a non-empty selection'
  }),
  Object.freeze({
    id: 'scan-workspace',
    section: 'scan',
    command: COMMANDS.scanWorkspace,
    title: 'Scan workspace',
    description: 'Analyze every open workspace folder.',
    meta: 'Requires an open workspace'
  }),
  Object.freeze({
    id: 'analyze-security-features',
    section: 'saeFeatures',
    command: COMMANDS.analyzeSecurityFeatures,
    title: 'Analyze security features',
    description: 'Extract features from a compatible model and genuine SAE artifact.',
    meta: 'Requires model and SAE access'
  }),
  Object.freeze({
    id: 'counterfactual-analysis',
    section: 'featureInteractions',
    command: COMMANDS.counterfactualAnalysis,
    title: 'Run counterfactual analysis',
    description: 'Compare the selected region with defined model interventions.',
    meta: 'Requires measured features'
  }),
  Object.freeze({
    id: 'explain-vulnerability',
    section: 'explanations',
    command: COMMANDS.explainVulnerability,
    title: 'Explain vulnerability',
    description: 'Build an evidence graph around a reported finding.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'generate-secure-code',
    section: 'automatedRepair',
    command: COMMANDS.generateSecureCode,
    title: 'Generate secure code',
    description: 'Ask the engine for a secure alternative to the current context.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'propose-repair',
    section: 'automatedRepair',
    command: COMMANDS.repairVulnerability,
    title: 'Propose repair',
    description: 'Generate a reviewable patch proposal; no source is modified automatically.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'verify-repair',
    section: 'verification',
    command: COMMANDS.verifyRepair,
    title: 'Verify repair',
    description: 'Run independent security and functional verification on an approved patch.',
    meta: 'Requires an open workspace'
  })
]);

const ENGINE_UNAVAILABLE = Object.freeze({
  status: 'unavailable',
  label: 'Security engine unavailable',
  detail:
    'The local CRAFT-Sec security engine is not running in this build. No scanning, SAE analysis, ' +
    'counterfactual analysis, repair, or verification result is available.'
});

const DEFAULT_SETTINGS = Object.freeze({
  pythonPath: '',
  autoStart: false,
  logLevel: 'info',
  showStatusBarItem: true
});

const LOG_LEVELS = Object.freeze(['trace', 'debug', 'info', 'warn', 'error', 'off']);

/**
 * @param {Partial<typeof DEFAULT_SETTINGS>} [settings]
 */
function normalizeSettings(settings = {}) {
  return {
    pythonPath: typeof settings.pythonPath === 'string' ? settings.pythonPath : '',
    autoStart: Boolean(settings.autoStart),
    logLevel: LOG_LEVELS.includes(settings.logLevel) ? settings.logLevel : 'info',
    showStatusBarItem: settings.showStatusBarItem !== false
  };
}

/**
 * @param {{ status?: string, label?: string, detail?: string }} [engine]
 */
function normalizeEngine(engine = ENGINE_UNAVAILABLE) {
  return {
    status: typeof engine.status === 'string' ? engine.status : 'unavailable',
    label: typeof engine.label === 'string' ? engine.label : ENGINE_UNAVAILABLE.label,
    detail: typeof engine.detail === 'string' ? engine.detail : ENGINE_UNAVAILABLE.detail
  };
}

/** @returns {object} */
function unavailableSaeState() {
  return {
    available: false,
    statusLabel: 'Unavailable',
    message:
      'SAE features require a compatible SAE artifact and a white-box model with accessible ' +
      'activations. No activation values are simulated or inferred.',
    provenance: null,
    features: []
  };
}

/** @returns {object} */
function unavailableInteractionState() {
  return {
    available: false,
    statusLabel: 'Unavailable',
    message:
      'Feature interactions require measured activations and a counterfactual run. Estimated ' +
      'effects are not real-world causal claims.',
    items: []
  };
}

/** @returns {object} */
function unavailableSteeringState() {
  return {
    available: false,
    statusLabel: 'Unavailable',
    message:
      'Activation steering requires a compatible white-box model, accessible activations, and a ' +
      'steering-capable SAE. No steering is performed in this build.',
    controls: []
  };
}

/** @returns {object} */
function executionSandboxState() {
  return {
    available: false,
    label: 'Execution sandbox unavailable',
    detail:
      'Execution-based verification requires an isolated sandbox with workspace containment, a ' +
      'scrubbed environment, resource limits, and process-group termination. None is configured.'
  };
}

/** @returns {object} */
function notRunVerificationState() {
  return {
    status: 'not-run',
    label: 'Not run',
    summary: 'No verification has been run for this workspace.',
    checks: [],
    lastRunAt: null,
    executionSandbox: executionSandboxState()
  };
}

/**
 * @param {{
 *   settings?: Partial<typeof DEFAULT_SETTINGS>,
 *   engine?: { status?: string, label?: string, detail?: string },
 *   generatedAt?: string
 * }} [options]
 */
function createEmptyDashboardState(options = {}) {
  return {
    schemaVersion: DASHBOARD_SCHEMA_VERSION,
    dataMode: 'empty',
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    demoNotice: '',
    sections: DASHBOARD_SECTIONS,
    actions: DASHBOARD_ACTIONS,
    engine: normalizeEngine(options.engine),
    summary: {
      totalFindings: null,
      severity: { critical: null, high: null, medium: null, low: null },
      lastScanAt: null,
      workspaceName: null
    },
    vulnerabilityDistribution: [],
    cweDistribution: [],
    scanHistory: [],
    vulnerabilities: [],
    sae: unavailableSaeState(),
    featureInteractions: unavailableInteractionState(),
    steering: unavailableSteeringState(),
    explanations: [],
    repairs: [],
    verification: notRunVerificationState(),
    reports: [],
    settings: normalizeSettings(options.settings)
  };
}

const DEMO_VULNERABILITIES = Object.freeze([
  {
    id: 'DEMO-001',
    title: 'SQL injection in user lookup',
    summary: 'A request parameter is concatenated into a SQL query.',
    severity: 'critical',
    cwe: 'CWE-89',
    file: 'src/auth/session.ts',
    line: 84,
    status: 'open'
  },
  {
    id: 'DEMO-002',
    title: 'SQL injection in report filter',
    summary: 'A report filter reaches a query without parameterization.',
    severity: 'critical',
    cwe: 'CWE-89',
    file: 'src/api/reports.py',
    line: 142,
    status: 'open'
  },
  {
    id: 'DEMO-003',
    title: 'Reflected XSS in search results',
    summary: 'The search term is written into HTML without escaping.',
    severity: 'high',
    cwe: 'CWE-79',
    file: 'src/web/search.js',
    line: 57,
    status: 'triaged'
  },
  {
    id: 'DEMO-004',
    title: 'Stored XSS in comment rendering',
    summary: 'Comment bodies are inserted as raw markup.',
    severity: 'high',
    cwe: 'CWE-79',
    file: 'src/web/comments.jsx',
    line: 121,
    status: 'open'
  },
  {
    id: 'DEMO-005',
    title: 'Path traversal in file download',
    summary: 'A user-supplied filename is joined to a storage root without containment.',
    severity: 'high',
    cwe: 'CWE-22',
    file: 'src/files/download.py',
    line: 63,
    status: 'in-review'
  },
  {
    id: 'DEMO-006',
    title: 'Hardcoded vendor API token',
    summary: 'A credential-like literal is committed in an integration module.',
    severity: 'high',
    cwe: 'CWE-798',
    file: 'src/integrations/vendor.py',
    line: 19,
    status: 'open'
  },
  {
    id: 'DEMO-007',
    title: 'SQL concatenation in admin query',
    summary: 'An admin filter is built with string formatting.',
    severity: 'medium',
    cwe: 'CWE-89',
    file: 'src/admin/queries.py',
    line: 88,
    status: 'triaged'
  },
  {
    id: 'DEMO-008',
    title: 'XSS in profile biography',
    summary: 'A profile field is rendered into a template without escaping.',
    severity: 'medium',
    cwe: 'CWE-79',
    file: 'src/web/profile.js',
    line: 73,
    status: 'open'
  },
  {
    id: 'DEMO-009',
    title: 'Path traversal in template loader',
    summary: 'Template names are resolved without a containment check.',
    severity: 'medium',
    cwe: 'CWE-22',
    file: 'src/templates/loader.py',
    line: 41,
    status: 'in-review'
  },
  {
    id: 'DEMO-010',
    title: 'Hardcoded database password',
    summary: 'A database password literal is used as a fallback.',
    severity: 'medium',
    cwe: 'CWE-798',
    file: 'src/db/config.py',
    line: 27,
    status: 'open'
  },
  {
    id: 'DEMO-011',
    title: 'Unsafe YAML deserialization',
    summary: 'Untrusted YAML is loaded with a permissive loader.',
    severity: 'medium',
    cwe: 'CWE-502',
    file: 'src/jobs/serializer.py',
    line: 112,
    status: 'triaged'
  },
  {
    id: 'DEMO-012',
    title: 'XML external entity expansion',
    summary: 'The XML parser enables external entities.',
    severity: 'medium',
    cwe: 'CWE-611',
    file: 'src/importers/xml_reader.py',
    line: 36,
    status: 'open'
  },
  {
    id: 'DEMO-013',
    title: 'Second SQL filter in metrics endpoint',
    summary: 'A metrics dimension is concatenated into a query.',
    severity: 'medium',
    cwe: 'CWE-89',
    file: 'src/metrics/query.py',
    line: 95,
    status: 'open'
  },
  {
    id: 'DEMO-014',
    title: 'SQL string assembled in migration helper',
    summary: 'A migration helper concatenates a table name.',
    severity: 'low',
    cwe: 'CWE-89',
    file: 'src/db/migrate.py',
    line: 54,
    status: 'triaged'
  },
  {
    id: 'DEMO-015',
    title: 'Unescaped error message in HTML',
    summary: 'An error detail is rendered into a status banner.',
    severity: 'low',
    cwe: 'CWE-79',
    file: 'src/web/errors.js',
    line: 31,
    status: 'open'
  },
  {
    id: 'DEMO-016',
    title: 'Path join without containment check',
    summary: 'A local asset path is joined without normalization.',
    severity: 'low',
    cwe: 'CWE-22',
    file: 'src/assets/paths.py',
    line: 22,
    status: 'in-review'
  },
  {
    id: 'DEMO-017',
    title: 'Committed test credential',
    summary: 'A fixture contains a credential-like literal.',
    severity: 'low',
    cwe: 'CWE-798',
    file: 'tests/fixtures/auth.py',
    line: 14,
    status: 'triaged'
  },
  {
    id: 'DEMO-018',
    title: 'Insecure deserialization fallback',
    summary: 'A cache fallback uses a permissive deserializer.',
    severity: 'low',
    cwe: 'CWE-502',
    file: 'src/cache/fallback.py',
    line: 67,
    status: 'open'
  }
]);

/**
 * @param {{
 *   settings?: Partial<typeof DEFAULT_SETTINGS>,
 *   engine?: { status?: string, label?: string, detail?: string },
 *   generatedAt?: string
 * }} [options]
 */
function createDemoDashboardState(options = {}) {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const baseTime = new Date(generatedAt).getTime();
  const hoursAgo = (hours) => new Date(baseTime - hours * 60 * 60 * 1000).toISOString();

  const empty = createEmptyDashboardState({ ...options, generatedAt });

  return {
    ...empty,
    dataMode: 'demo',
    demoNotice: DEMO_NOTICE,
    summary: {
      totalFindings: 18,
      severity: { critical: 2, high: 4, medium: 7, low: 5 },
      lastScanAt: hoursAgo(2),
      workspaceName: 'demo-workspace'
    },
    vulnerabilityDistribution: [
      { key: 'critical', label: 'Critical', count: 2 },
      { key: 'high', label: 'High', count: 4 },
      { key: 'medium', label: 'Medium', count: 7 },
      { key: 'low', label: 'Low', count: 5 }
    ],
    cweDistribution: [
      { cwe: 'CWE-89', label: 'SQL Injection', count: 5 },
      { cwe: 'CWE-79', label: 'Cross-site Scripting', count: 4 },
      { cwe: 'CWE-22', label: 'Path Traversal', count: 3 },
      { cwe: 'CWE-798', label: 'Hardcoded Credentials', count: 3 },
      { cwe: 'CWE-502', label: 'Unsafe Deserialization', count: 2 },
      { cwe: 'CWE-611', label: 'XML External Entity', count: 1 }
    ],
    scanHistory: [
      {
        id: 'DEMO-SCAN-3',
        startedAt: hoursAgo(2),
        scope: 'Workspace',
        status: 'completed',
        findings: 18,
        durationMs: 42000
      },
      {
        id: 'DEMO-SCAN-2',
        startedAt: hoursAgo(26),
        scope: 'Selection: src/auth/session.ts',
        status: 'completed',
        findings: 3,
        durationMs: 1800
      },
      {
        id: 'DEMO-SCAN-1',
        startedAt: hoursAgo(72),
        scope: 'Current file: src/api/reports.py',
        status: 'partial',
        findings: 2,
        durationMs: 950
      }
    ],
    vulnerabilities: DEMO_VULNERABILITIES.map((finding) => ({ ...finding })),
    sae: unavailableSaeState(),
    featureInteractions: unavailableInteractionState(),
    steering: unavailableSteeringState(),
    explanations: [],
    repairs: [],
    verification: {
      ...notRunVerificationState(),
      summary: 'Demo preview only. No verification checks were executed.'
    },
    reports: []
  };
}

/**
 * @param {{
 *   dataMode?: 'empty' | 'demo' | 'live',
 *   settings?: Partial<typeof DEFAULT_SETTINGS>,
 *   engine?: { status?: string, label?: string, detail?: string },
 *   generatedAt?: string
 * }} [options]
 */
function buildDashboardState(options = {}) {
  const { dataMode = 'empty' } = options;
  if (dataMode === 'demo') {
    return createDemoDashboardState(options);
  }
  return createEmptyDashboardState(options);
}

module.exports = {
  DASHBOARD_SCHEMA_VERSION,
  DASHBOARD_SECTIONS,
  DASHBOARD_ACTIONS,
  DEMO_NOTICE,
  ENGINE_UNAVAILABLE,
  DEFAULT_SETTINGS,
  LOG_LEVELS,
  normalizeSettings,
  normalizeEngine,
  createEmptyDashboardState,
  createDemoDashboardState,
  buildDashboardState
};
