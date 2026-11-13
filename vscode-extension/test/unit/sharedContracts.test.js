'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Ajv2020 = require('ajv/dist/2020');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const SCHEMA_DIR = path.join(REPO_ROOT, 'shared', 'schemas');
const FIXTURE_DIR = path.join(REPO_ROOT, 'shared', 'fixtures', 'contracts');
const MANIFEST = readJson(path.join(SCHEMA_DIR, 'manifest.json'));

const EXPECTED_CONTRACTS = new Set([
  'ScanRequest',
  'ScanResult',
  'VulnerabilityFinding',
  'FeatureExtractionResult',
  'CounterfactualResult',
  'SteeringResult',
  'ExplanationResult',
  'RepairCandidate',
  'VerificationResult',
  'ExperimentMetadata'
]);

const FINDING_REQUIRED_FIELDS = [
  'findingId',
  'filePath',
  'location',
  'cwe',
  'severity',
  'evidenceSources',
  'riskScore',
  'explanation',
  'suggestedRemediation',
  'provenance'
];

/**
 * @param {string} filePath
 * @returns {any}
 */
function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function loadSchemas() {
  /** @type {Map<string, any>} */
  const byFile = new Map();
  /** @type {any[]} */
  const schemas = [];
  for (const name of fs.readdirSync(SCHEMA_DIR).sort()) {
    if (!name.endsWith('.json') || name === 'manifest.json') {
      continue;
    }
    const schema = readJson(path.join(SCHEMA_DIR, name));
    byFile.set(name, schema);
    schemas.push(schema);
  }
  return { byFile, schemas };
}

const { byFile, schemas } = loadSchemas();
const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const schema of schemas) {
  ajv.addSchema(schema);
}

/**
 * @param {string} contract
 * @returns {import('ajv').ValidateFunction}
 */
function validatorFor(contract) {
  const entry = MANIFEST.schemas[contract];
  assert.ok(entry, `${contract} must be declared in the manifest`);
  const schema = byFile.get(entry.schema);
  assert.ok(schema, `${contract} schema ${entry.schema} must exist`);
  const validate = ajv.getSchema(schema.$id);
  assert.ok(validate, `${contract} validator must compile`);
  return validate;
}

/**
 * @param {string} relativePath
 * @returns {any}
 */
function loadFixture(relativePath) {
  return readJson(path.join(FIXTURE_DIR, relativePath));
}

/**
 * @param {import('ajv').ErrorObject[] | null | undefined} errors
 * @returns {string}
 */
function errorSummary(errors) {
  return (errors ?? [])
    .map((error) => `${error.instancePath || '<root>'}: ${error.keyword}: ${error.message}`)
    .join('\n');
}

for (const [contract, entry] of Object.entries(MANIFEST.schemas)) {
  for (const fixture of entry.validFixtures) {
    test(`valid ${contract} fixture: ${fixture}`, () => {
      const validate = validatorFor(contract);
      const payload = loadFixture(`valid/${fixture}`);
      assert.equal(validate(payload), true, errorSummary(validate.errors));
    });
  }
}

for (const testCase of MANIFEST.invalidFixtures) {
  test(`invalid fixture is rejected: ${path.basename(testCase.fixture)}`, () => {
    const validate = validatorFor(testCase.schema);
    const payload = loadFixture(testCase.fixture);
    assert.equal(
      validate(payload),
      false,
      `${testCase.fixture} unexpectedly validated (${testCase.reason})`
    );
    const keywords = new Set((validate.errors ?? []).map((error) => error.keyword));
    assert.ok(
      keywords.has(testCase.keyword),
      `${testCase.fixture} failed for ${[...keywords].sort().join(', ')}, not ${testCase.keyword}: ` +
        errorSummary(validate.errors)
    );
  });
}

test('every schema is valid Draft 2020-12 with a versioned $id', () => {
  for (const schema of schemas) {
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.ok(schema.$id.startsWith('https://craftsec.local/schemas/v1/'));
    assert.equal(ajv.validateSchema(schema, true), true);
  }
});

test('payload schemas reject unknown fields', () => {
  for (const [name, schema] of byFile) {
    if (name === 'common.json') {
      continue;
    }
    assert.equal(schema.additionalProperties, false, `${name} must be closed`);
  }
});

test('manifest contract version matches the version file', () => {
  const version = fs.readFileSync(path.join(SCHEMA_DIR, 'VERSION'), 'utf8').trim();
  assert.equal(MANIFEST.contractVersion, version);
  assert.equal(MANIFEST.jsonSchemaDialect, 'https://json-schema.org/draft/2020-12/schema');
});

test('manifest declares the requested contracts', () => {
  assert.deepEqual(new Set(Object.keys(MANIFEST.schemas)), EXPECTED_CONTRACTS);
});

test('manifest references every schema and fixture', () => {
  const referencedSchemas = new Set(Object.values(MANIFEST.schemas).map((entry) => entry.schema));
  const actualSchemas = new Set([...byFile.keys()].filter((name) => name !== 'common.json'));
  assert.deepEqual(referencedSchemas, actualSchemas);

  const referencedValid = new Set(
    Object.values(MANIFEST.schemas).flatMap((entry) => entry.validFixtures)
  );
  const actualValid = new Set(
    fs.readdirSync(path.join(FIXTURE_DIR, 'valid')).filter((name) => name.endsWith('.json'))
  );
  assert.deepEqual(referencedValid, actualValid);

  const referencedInvalid = new Set(MANIFEST.invalidFixtures.map((entry) => entry.fixture));
  const actualInvalid = new Set(
    fs
      .readdirSync(path.join(FIXTURE_DIR, 'invalid'))
      .filter((name) => name.endsWith('.json'))
      .map((name) => `invalid/${name}`)
  );
  assert.deepEqual(referencedInvalid, actualInvalid);
});

for (const field of FINDING_REQUIRED_FIELDS) {
  test(`VulnerabilityFinding requires ${field}`, () => {
    const finding = structuredClone(loadFixture('valid/vulnerability-finding-heuristic.json'));
    delete finding[field];
    assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
  });
}

for (const field of ['line', 'column']) {
  test(`VulnerabilityFinding location requires ${field}`, () => {
    const finding = structuredClone(loadFixture('valid/vulnerability-finding-heuristic.json'));
    delete finding.location.start[field];
    assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
  });
}

for (const field of ['value', 'kind', 'interpretation']) {
  test(`VulnerabilityFinding riskScore requires ${field}`, () => {
    const finding = structuredClone(loadFixture('valid/vulnerability-finding-heuristic.json'));
    delete finding.riskScore[field];
    assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
  });
}

test('a heuristic score rejects a calibrated probability interpretation', () => {
  const finding = structuredClone(loadFixture('valid/vulnerability-finding-heuristic.json'));
  finding.riskScore.interpretation = 'calibrated_probability';
  assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
});

test('a heuristic score rejects calibrator evidence', () => {
  const finding = structuredClone(loadFixture('valid/vulnerability-finding-heuristic.json'));
  const calibrated = loadFixture('valid/vulnerability-finding-calibrated.json');
  finding.riskScore.calibrator = calibrated.riskScore.calibrator;
  assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
});

test('a calibrated score requires a calibrator', () => {
  const finding = structuredClone(loadFixture('valid/vulnerability-finding-calibrated.json'));
  delete finding.riskScore.calibrator;
  assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
});

test('calibrated probabilities are bounded to the unit interval', () => {
  const finding = structuredClone(loadFixture('valid/vulnerability-finding-calibrated.json'));
  finding.riskScore.value = 1.2;
  assert.equal(validatorFor('VulnerabilityFinding')(finding), false);
});

test('a model logit is never labelled as a probability', () => {
  const finding = structuredClone(loadFixture('valid/vulnerability-finding-heuristic.json'));
  finding.riskScore = {
    value: 2.4,
    kind: 'model_logit',
    interpretation: 'model_score_not_calibrated'
  };
  const validate = validatorFor('VulnerabilityFinding');
  assert.equal(validate(finding), true);

  finding.riskScore.interpretation = 'calibrated_probability';
  assert.equal(validate(finding), false);
});

test('an unavailable scan with empty findings remains valid', () => {
  const result = structuredClone(loadFixture('valid/scan-result.json'));
  result.analysisAvailable = false;
  result.status = 'partial';
  result.findings = [];
  assert.equal(validatorFor('ScanResult')(result), true);
});
