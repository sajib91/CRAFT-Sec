'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DiagnosticController,
  DIAGNOSTIC_COLLECTION_NAME
} = require('../../src/diagnostics/diagnosticController');
const { createFinding, createRawFinding, createFakeVscode } = require('./diagnosticsFake');

function createHarness(options = {}) {
  const fake = createFakeVscode(options);
  const controller = new DiagnosticController({
    vscode: fake.vscode,
    logger: fake.logger,
    isWithinWorkspace: options.isWithinWorkspace
  });
  return { ...fake, controller };
}

test('publishes backend findings as diagnostics with CWE, evidence, and sources', () => {
  const harness = createHarness();
  const result = harness.controller.publishScanResult({
    findings: [createRawFinding()]
  });

  assert.equal(result.published, 1);
  assert.deepEqual(result.files, ['file:///workspace/src/app.js']);
  assert.deepEqual(result.rejected, []);

  const collection = harness.collections[0];
  assert.equal(collection.name, DIAGNOSTIC_COLLECTION_NAME);
  assert.equal(collection.setCalls.length, 1);

  const uri = 'file:///workspace/src/app.js';
  const [diagnostic] = collection.entries.get(uri);
  assert.equal(diagnostic.message, 'User input reaches a SQL query.');
  assert.equal(diagnostic.severity, 0, 'high severity must map to Error');
  assert.equal(diagnostic.source, 'CRAFT-Sec');
  assert.equal(diagnostic.code.value, 'CWE-89');
  assert.equal(diagnostic.code.target.toString(), 'https://cwe.mitre.org/data/definitions/89.html');
  assert.deepEqual(diagnostic.range.start, { line: 4, character: 2 });
  assert.deepEqual(diagnostic.range.end, { line: 4, character: 42 });

  assert.equal(diagnostic.relatedInformation.length, 2);
  assert.match(diagnostic.relatedInformation[0].message, /^Evidence: db\.query/);
  assert.match(diagnostic.relatedInformation[1].message, /^Source: CWE-89/);
  assert.equal(
    diagnostic.relatedInformation[1].message,
    'Source: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)'
  );

  const [finding] = harness.controller.getFindingsForUri(uri);
  assert.equal(finding.id, 'finding-1');
  assert.equal(harness.controller.getDiagnosticsForUri(uri)[0], diagnostic);
  assert.equal(harness.controller.getDiagnosticForFinding(finding), diagnostic);
  assert.equal(harness.controller.findAt(uri, { line: 4, character: 10 }).length, 1);
  assert.equal(harness.controller.findAt(uri, { line: 4, character: 50 }).length, 0);

  const info = harness.logger.entries.find((entry) => entry.level === 'info');
  assert.match(info.message, /Published 1 CRAFT-Sec finding/);

  harness.controller.dispose();
});

test('source references outside the workspace are not clickable', () => {
  const harness = createHarness();
  harness.controller.publishScanResult({
    findings: [
      createRawFinding({
        sourceReferences: [
          {
            label: 'Local sink',
            uri: 'file:///tmp/outside.js',
            range: {
              start: { line: 1, character: 0 },
              end: { line: 1, character: 4 }
            }
          },
          {
            label: 'Helper',
            uri: 'file:///workspace/src/helper.js',
            range: {
              start: { line: 2, character: 1 },
              end: { line: 2, character: 5 }
            }
          }
        ]
      })
    ]
  });

  const [diagnostic] = harness.collections[0].entries.get('file:///workspace/src/app.js');
  assert.equal(diagnostic.relatedInformation.length, 3);

  const outside = diagnostic.relatedInformation[1];
  assert.equal(outside.location.uri.toString(), 'file:///workspace/src/app.js');
  assert.deepEqual(outside.location.range.start, { line: 4, character: 2 });
  assert.equal(outside.message, 'Source: Local sink (file:///tmp/outside.js)');

  const inside = diagnostic.relatedInformation[2];
  assert.equal(inside.location.uri.toString(), 'file:///workspace/src/helper.js');
  assert.deepEqual(inside.location.range.start, { line: 2, character: 1 });
  assert.equal(inside.message, 'Source: Helper');

  harness.controller.dispose();
});

test('maps every backend severity to a VS Code diagnostic severity', () => {
  const harness = createHarness();
  const severities = ['critical', 'high', 'medium', 'low', 'info'];

  harness.controller.publishScanResult({
    findings: severities.map((severity, index) =>
      createRawFinding({
        id: `finding-${severity}`,
        severity,
        location: {
          uri: 'file:///workspace/src/app.js',
          range: {
            start: { line: index, character: 0 },
            end: { line: index, character: 10 }
          }
        }
      })
    )
  });

  const diagnostics = harness.collections[0].entries.get('file:///workspace/src/app.js');
  assert.deepEqual(
    diagnostics.map((diagnostic) => diagnostic.severity),
    [0, 0, 1, 2, 3]
  );

  harness.controller.dispose();
});

test('empty results clear diagnostics for the scan scope', () => {
  const harness = createHarness();
  const uri = 'file:///workspace/src/app.js';

  harness.controller.publishScanResult({ findings: [createRawFinding()] }, { scopeUris: [uri] });
  assert.ok(harness.collections[0].entries.has(uri));

  const result = harness.controller.publishScanResult({ findings: [] }, { scopeUris: [uri] });

  assert.equal(result.published, 0);
  assert.equal(harness.collections[0].entries.has(uri), false);
  assert.equal(harness.collections[0].deleteCalls.length, 1);
  assert.deepEqual(harness.controller.getFindingsForUri(uri), []);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'debug' && /No CRAFT-Sec findings/.test(entry.message)
    )
  );

  harness.controller.dispose();
});

test('a result-level scope clears stale files without touching unrelated diagnostics', () => {
  const harness = createHarness();
  const first = 'file:///workspace/src/app.js';
  const second = 'file:///workspace/src/other.js';

  harness.controller.publishScanResult({
    findings: [
      createRawFinding(),
      createRawFinding({
        id: 'finding-2',
        location: {
          uri: second,
          range: {
            start: { line: 1, character: 0 },
            end: { line: 1, character: 8 }
          }
        }
      })
    ]
  });

  harness.controller.publishScanResult({
    findings: [],
    scope: { uris: [first] }
  });

  assert.equal(harness.controller.getFindingsForUri(first).length, 0);
  assert.equal(harness.controller.getFindingsForUri(second).length, 1);

  harness.controller.dispose();
});

test('findings outside the workspace are rejected and never published', () => {
  const harness = createHarness();
  const result = harness.controller.publishScanResult({
    findings: [
      createRawFinding({
        location: {
          uri: 'file:///tmp/outside.js',
          range: {
            start: { line: 0, character: 0 },
            end: { line: 0, character: 5 }
          }
        }
      })
    ]
  });

  assert.equal(result.published, 0);
  assert.equal(result.rejected.length, 1);
  assert.equal(result.rejected[0].code, 'E_OUTSIDE_WORKSPACE');
  assert.equal(harness.collections[0].setCalls.length, 0);
  assert.deepEqual(harness.controller.getFindingsForUri('file:///tmp/outside.js'), []);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'warn' && /outside the workspace/.test(entry.message)
    )
  );

  harness.controller.dispose();
});

test('malformed findings are discarded while valid findings are published', () => {
  const harness = createHarness();
  const result = harness.controller.publishScanResult({
    findings: [createRawFinding(), createRawFinding({ id: 'broken', severity: undefined })]
  });

  assert.equal(result.published, 1);
  assert.equal(result.rejected.length, 1);
  assert.match(result.rejected[0].reason, /severity must be a string/);
  assert.ok(
    harness.logger.entries.some(
      (entry) =>
        entry.level === 'warn' && /Discarded 1 invalid CRAFT-Sec finding/.test(entry.message)
    )
  );

  harness.controller.dispose();
});

test('a malformed result envelope leaves existing diagnostics intact', () => {
  const harness = createHarness();
  const uri = 'file:///workspace/src/app.js';

  harness.controller.publishScanResult({ findings: [createRawFinding()] });
  assert.throws(() => harness.controller.publishScanResult({}), /findings array/);
  assert.equal(harness.controller.getFindingsForUri(uri).length, 1);
  assert.equal(harness.controller.getDiagnosticsForUri(uri).length, 1);

  harness.controller.dispose();
});

test('clearUri, clearAll, and dispose release published diagnostics', () => {
  const harness = createHarness();
  const uri = 'file:///workspace/src/app.js';

  harness.controller.publishScanResult({ findings: [createRawFinding()] });
  harness.controller.clearUri(uri);
  assert.deepEqual(harness.controller.getFindingsForUri(uri), []);
  assert.equal(harness.collections[0].entries.size, 0);

  harness.controller.publishScanResult({ findings: [createRawFinding()] });
  harness.controller.clearAll();
  assert.equal(harness.collections[0].entries.size, 0);
  assert.equal(harness.collections[0].cleared, true);

  harness.controller.publishScanResult({ findings: [createRawFinding()] });
  harness.controller.dispose();
  assert.equal(harness.collections[0].disposed, true);
  assert.equal(harness.controller.entries.size, 0);

  harness.controller.dispose();
  assert.throws(() => harness.controller.publishScanResult({ findings: [] }), /has been disposed/);
});

test('a finding can be located by identifier for Quick Fix diagnostics', () => {
  const harness = createHarness();
  const finding = createFinding();
  harness.controller.publishScanResult({ findings: [createRawFinding()] });

  const stored = harness.controller.getFindingsForUri(finding.documentUri)[0];
  const diagnostic = harness.controller.getDiagnosticForFinding(stored);

  assert.ok(diagnostic);
  assert.equal(harness.controller.getDiagnosticForFinding({ ...stored, id: 'unknown' }), undefined);

  harness.controller.dispose();
});
