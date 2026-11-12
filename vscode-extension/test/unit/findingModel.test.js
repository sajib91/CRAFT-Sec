'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  FindingValidationError,
  normalizeScanResult,
  normalizeFinding,
  severityToKind,
  severityLabel,
  cweUrl,
  findingContainsPosition,
  rangesIntersect
} = require('../../src/diagnostics/findingModel');
const { isPathWithinRoot, isFileUriWithinFolders } = require('../../src/security/paths');
const { createRawFinding, createWorkspaceFolder } = require('./diagnosticsFake');

test('valid backend results normalize without adding fields', () => {
  const result = normalizeScanResult({
    findings: [createRawFinding()],
    scope: { uris: ['file:///workspace/src/app.js'] }
  });

  assert.deepEqual(result.rejected, []);
  assert.deepEqual(result.scopeUris, ['file:///workspace/src/app.js']);
  assert.equal(result.findings.length, 1);

  const [finding] = result.findings;
  assert.equal(finding.id, 'finding-1');
  assert.equal(finding.message, 'User input reaches a SQL query.');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.severityKind, 'error');
  assert.equal(finding.cwe, 'CWE-89');
  assert.equal(finding.ruleId, 'js/sql-injection');
  assert.equal(finding.documentUri, 'file:///workspace/src/app.js');
  assert.deepEqual(finding.range, {
    start: { line: 4, character: 2 },
    end: { line: 4, character: 42 }
  });
  assert.equal(finding.repairEligible, true);
  assert.equal(finding.repair.description, 'Use a parameterized query.');
});

test('a bare findings array is accepted but has no scan scope', () => {
  const result = normalizeScanResult([createRawFinding()]);

  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.scopeUris, []);
});

test('severity mapping and labels are deterministic', () => {
  assert.equal(severityToKind('critical'), 'error');
  assert.equal(severityToKind('high'), 'error');
  assert.equal(severityToKind('medium'), 'warning');
  assert.equal(severityToKind('low'), 'information');
  assert.equal(severityToKind('info'), 'hint');
  assert.equal(severityLabel('medium'), 'Medium');
});

test('CWE identifiers are validated, normalized, and linked', () => {
  const finding = normalizeFinding(createRawFinding({ cwe: 'cwe-79' }));

  assert.equal(finding.cwe, 'CWE-79');
  assert.equal(cweUrl(finding.cwe), 'https://cwe.mitre.org/data/definitions/79.html');
  assert.throws(() => normalizeFinding(createRawFinding({ cwe: '79' })), /CWE-<number>/);
  assert.throws(() => normalizeFinding(createRawFinding({ cwe: 'CWE-0' })), /positive CWE/);
});

test('repair eligibility is never inferred', () => {
  const withoutRepair = normalizeFinding(createRawFinding({ repair: undefined }));
  assert.equal(withoutRepair.repairEligible, false);
  assert.equal(withoutRepair.repair, undefined);

  const explicitlyIneligible = normalizeFinding(
    createRawFinding({ repair: { eligible: false, description: 'Manual review required.' } })
  );
  assert.equal(explicitlyIneligible.repairEligible, false);
  assert.equal(explicitlyIneligible.repair.description, 'Manual review required.');

  assert.throws(
    () => normalizeFinding(createRawFinding({ repair: { eligible: 'yes' } })),
    /repair\.eligible must be a boolean/
  );
});

test('malformed findings are rejected without suppressing valid findings', () => {
  const result = normalizeScanResult({
    findings: [
      createRawFinding(),
      createRawFinding({ id: 'missing-message', message: '' }),
      createRawFinding({ id: 'bad-severity', severity: 'severe' }),
      createRawFinding({
        id: 'bad-uri',
        location: { uri: 'https://example.com/a.js', range: createRawFinding().location.range }
      }),
      createRawFinding({
        id: 'bad-range',
        location: {
          uri: 'file:///workspace/src/app.js',
          range: {
            start: { line: 5, character: 0 },
            end: { line: 3, character: 0 }
          }
        }
      }),
      createRawFinding({
        id: 'bad-reference',
        sourceReferences: [{ label: 'Docs', url: 'javascript:alert(1)' }]
      })
    ]
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, 'finding-1');
  assert.equal(result.rejected.length, 5);
  assert.ok(result.rejected.every((entry) => typeof entry.reason === 'string'));
});

test('duplicate finding identifiers are rejected', () => {
  const result = normalizeScanResult({
    findings: [createRawFinding(), createRawFinding()]
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.rejected.length, 1);
  assert.match(result.rejected[0].reason, /Duplicate finding id/);
});

test('a malformed result envelope or scope is rejected as a whole', () => {
  assert.throws(
    () => normalizeScanResult(null),
    (error) => error instanceof FindingValidationError && error.code === 'E_INVALID_SCAN_RESULT'
  );
  assert.throws(
    () => normalizeScanResult({ findings: [], scope: { uris: 'file:///workspace/a.js' } }),
    (error) => error instanceof FindingValidationError && error.code === 'E_INVALID_SCOPE'
  );
});

test('positions and ranges support hover and code-action intersections', () => {
  const finding = normalizeFinding(createRawFinding());

  assert.equal(findingContainsPosition(finding, { line: 4, character: 2 }), true);
  assert.equal(findingContainsPosition(finding, { line: 4, character: 41 }), true);
  assert.equal(findingContainsPosition(finding, { line: 4, character: 42 }), false);
  assert.equal(findingContainsPosition(finding, { line: 3, character: 10 }), false);

  assert.equal(
    rangesIntersect(finding.range, {
      start: { line: 4, character: 20 },
      end: { line: 4, character: 30 }
    }),
    true
  );
  assert.equal(
    rangesIntersect(finding.range, {
      start: { line: 5, character: 0 },
      end: { line: 5, character: 10 }
    }),
    false
  );
});

test('workspace path containment rejects siblings and traversal', () => {
  assert.equal(isPathWithinRoot('/workspace/src/app.js', '/workspace'), true);
  assert.equal(isPathWithinRoot('/workspace', '/workspace'), true);
  assert.equal(isPathWithinRoot('/workspace-other/app.js', '/workspace'), false);
  assert.equal(isPathWithinRoot('/workspace/../etc/passwd', '/workspace'), false);
  assert.equal(isPathWithinRoot('', '/workspace'), false);

  const folder = createWorkspaceFolder('/workspace');
  assert.equal(
    isFileUriWithinFolders({ scheme: 'file', fsPath: '/workspace/src/app.js' }, [folder]),
    true
  );
  assert.equal(isFileUriWithinFolders({ scheme: 'file', fsPath: '/tmp/app.js' }, [folder]), false);
  assert.equal(
    isFileUriWithinFolders({ scheme: 'untitled', fsPath: '/workspace/a' }, [folder]),
    false
  );
});
