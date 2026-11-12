'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { COMMANDS } = require('../../src/constants');
const {
  FindingHoverProvider,
  buildHoverMarkdown,
  escapeMarkdown
} = require('../../src/diagnostics/hoverProvider');
const {
  FindingCodeActionProvider,
  buildRepairArgument
} = require('../../src/diagnostics/codeActionProvider');
const { registerDiagnostics } = require('../../src/diagnostics');
const { createFinding, createFakeVscode, createUri } = require('./diagnosticsFake');

function createStore(findings, diagnostics = new Map()) {
  return {
    getFindingsForUri(uri) {
      const key = typeof uri === 'string' ? uri : uri.toString();
      return findings.filter((finding) => finding.documentUri === key);
    },
    getDiagnosticForFinding(finding) {
      return diagnostics.get(finding);
    }
  };
}

function createHoverProvider(findings) {
  const fake = createFakeVscode();
  return {
    ...fake,
    provider: new FindingHoverProvider({ vscode: fake.vscode, findings: createStore(findings) })
  };
}

function createCodeActionProvider(findings, diagnostics) {
  const fake = createFakeVscode();
  return {
    ...fake,
    provider: new FindingCodeActionProvider({
      vscode: fake.vscode,
      findings: createStore(findings, diagnostics)
    })
  };
}

test('hover explains a finding with severity, CWE, evidence, sources, and repair state', () => {
  const finding = createFinding();
  const { provider } = createHoverProvider([finding]);

  const hover = provider.provideHover(
    { uri: createUri(finding.documentUri) },
    { line: 4, character: 10 }
  );

  assert.ok(hover);
  assert.equal(hover.contents.isTrusted, false);
  assert.ok(hover.contents.value.includes('CRAFT-Sec: User input reaches a SQL query\\.'));
  assert.match(hover.contents.value, /\*\*Severity:\*\* High/);
  assert.match(
    hover.contents.value,
    /\[CWE-89\]\(https:\/\/cwe\.mitre\.org\/data\/definitions\/89\.html\)/
  );
  assert.match(hover.contents.value, /\*\*Explanation\*\*/);
  assert.match(hover.contents.value, /request parameter is concatenated/);
  assert.match(hover.contents.value, /\*\*Evidence\*\*/);
  assert.match(hover.contents.value, /SELECT \* FROM users/);
  assert.match(hover.contents.value, /\*\*Sources\*\*/);
  assert.match(hover.contents.value, /<https:\/\/cwe\.mitre\.org\/data\/definitions\/89\.html>/);
  assert.match(hover.contents.value, /Available from the CRAFT-Sec Quick Fix menu/);
  assert.ok(hover.contents.value.includes('Use a parameterized query\\.'));
  assert.deepEqual(hover.range.start, { line: 4, character: 2 });
  assert.deepEqual(hover.range.end, { line: 4, character: 42 });
});

test('hover is absent outside a finding range or on another document', () => {
  const finding = createFinding();
  const { provider } = createHoverProvider([finding]);

  assert.equal(
    provider.provideHover({ uri: createUri(finding.documentUri) }, { line: 9, character: 0 }),
    undefined
  );
  assert.equal(
    provider.provideHover(
      { uri: createUri('file:///workspace/src/other.js') },
      { line: 4, character: 10 }
    ),
    undefined
  );
  assert.equal(provider.provideHover(undefined, undefined), undefined);
});

test('hover reports missing explanation, sources, and repair metadata without inventing them', () => {
  const finding = createFinding({
    explanation: undefined,
    sourceReferences: [],
    repair: undefined
  });
  const { provider } = createHoverProvider([finding]);

  const hover = provider.provideHover(
    { uri: createUri(finding.documentUri) },
    { line: 4, character: 10 }
  );

  assert.match(hover.contents.value, /No explanation was provided by the backend\./);
  assert.match(hover.contents.value, /No source references were provided by the backend\./);
  assert.match(hover.contents.value, /did not provide repair metadata/);
});

test('hover shows explicit repair ineligibility from the backend', () => {
  const finding = createFinding({
    repair: { eligible: false, description: 'Manual review is required.' }
  });
  const { provider } = createHoverProvider([finding]);

  const hover = provider.provideHover(
    { uri: createUri(finding.documentUri) },
    { line: 4, character: 10 }
  );

  assert.match(hover.contents.value, /Not eligible for automated repair\./);
  assert.ok(hover.contents.value.includes('Manual review is required\\.'));
});

test('hover escapes backend Markdown and combines overlapping findings', () => {
  const first = createFinding({
    message: '*SQL* injection',
    explanation: '<script>alert(1)</script>'
  });
  const second = createFinding({
    id: 'finding-2',
    location: {
      uri: first.documentUri,
      range: {
        start: { line: 4, character: 2 },
        end: { line: 6, character: 10 }
      }
    }
  });
  const { provider } = createHoverProvider([first, second]);

  const hover = provider.provideHover(
    { uri: createUri(first.documentUri) },
    { line: 4, character: 10 }
  );

  assert.match(hover.contents.value, /\\\*SQL\\\* injection/);
  assert.ok(hover.contents.value.includes('\\<script\\>alert\\(1\\)\\</script\\>'));
  assert.match(hover.contents.value, /\n\n---\n\n/);
  assert.deepEqual(hover.range.start, { line: 4, character: 2 });
  assert.deepEqual(hover.range.end, { line: 6, character: 10 });
  assert.equal(escapeMarkdown('a_b'), 'a\\_b');
  assert.match(buildHoverMarkdown([first]), /CRAFT-Sec/);
});

test('a repair Quick Fix is offered only for explicitly eligible findings', () => {
  const finding = createFinding();
  const diagnostic = { source: 'CRAFT-Sec' };
  const { provider } = createCodeActionProvider([finding], new Map([[finding, diagnostic]]));

  const actions = provider.provideCodeActions(
    { uri: createUri(finding.documentUri) },
    {
      start: { line: 4, character: 20 },
      end: { line: 4, character: 30 }
    }
  );

  assert.equal(actions.length, 1);
  const [action] = actions;
  assert.equal(action.title, 'CRAFT-Sec: Repair CWE-89');
  assert.equal(action.kind, 'quickfix');
  assert.equal(action.command.command, COMMANDS.repairVulnerability);
  assert.equal(action.command.title, action.title);
  assert.deepEqual(action.diagnostics, [diagnostic]);
  assert.deepEqual(action.command.arguments, [
    {
      findingId: 'finding-1',
      documentUri: finding.documentUri,
      range: {
        start: { line: 4, character: 2 },
        end: { line: 4, character: 42 }
      },
      cwe: 'CWE-89',
      ruleId: 'js/sql-injection'
    }
  ]);
  assert.deepEqual(buildRepairArgument(finding), action.command.arguments[0]);
});

test('ineligible findings and ranges outside a finding produce no code actions', () => {
  const ineligible = createFinding({ repair: { eligible: false } });
  const { provider } = createCodeActionProvider([ineligible]);

  assert.deepEqual(
    provider.provideCodeActions(
      { uri: createUri(ineligible.documentUri) },
      { start: { line: 4, character: 0 }, end: { line: 4, character: 10 } }
    ),
    []
  );

  const eligible = createFinding();
  const second = createCodeActionProvider([eligible]);
  assert.deepEqual(
    second.provider.provideCodeActions(
      { uri: createUri(eligible.documentUri) },
      { start: { line: 20, character: 0 }, end: { line: 21, character: 0 } }
    ),
    []
  );
  assert.deepEqual(second.provider.provideCodeActions(undefined, undefined), []);
});

test('registerDiagnostics registers one collection, hover provider, and Quick Fix provider', () => {
  const fake = createFakeVscode();
  const feature = registerDiagnostics({ vscode: fake.vscode, logger: fake.logger });

  assert.equal(fake.collections.length, 1);
  assert.equal(fake.collections[0].name, 'craftsec');
  assert.equal(fake.registry.registrations.length, 2);

  const hover = fake.registry.registrations.find((entry) => entry.kind === 'hover');
  assert.deepEqual(hover.selector, { scheme: 'file' });
  assert.ok(hover.provider instanceof FindingHoverProvider);

  const codeAction = fake.registry.registrations.find((entry) => entry.kind === 'codeAction');
  assert.deepEqual(codeAction.selector, { scheme: 'file' });
  assert.deepEqual(codeAction.metadata, { providedCodeActionKinds: ['quickfix'] });
  assert.ok(codeAction.provider instanceof FindingCodeActionProvider);
  assert.ok(feature.controller instanceof Object);

  feature.dispose();
  assert.equal(fake.collections[0].disposed, true);
  assert.ok(fake.registry.registrations.every((entry) => entry.disposed));

  feature.dispose();
});

test('provider and registration factories reject incomplete VS Code APIs', () => {
  assert.throws(
    () => new FindingHoverProvider({ vscode: {}, findings: createStore([]) }),
    /hover APIs/
  );
  assert.throws(
    () => new FindingCodeActionProvider({ vscode: {}, findings: createStore([]) }),
    /CodeAction APIs/
  );
  assert.throws(
    () => registerDiagnostics({ vscode: {}, logger: { debug() {} } }),
    /language provider APIs/
  );
});
