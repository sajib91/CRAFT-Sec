'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  MAX_WORKSPACE_FOLDERS,
  CommandValidationError,
  requireWorkspace,
  findWorkspaceFolder,
  requireActiveEditor,
  requireSelection,
  readSendSourceText,
  createEditorRequest,
  normalizeRepairFindingArgument,
  createRepairRequest,
  createWorkspaceRequest,
  createVerificationRequest
} = require('../../src/workspace/workspaceService');

function createUri(fsPath, scheme = 'file') {
  return {
    scheme,
    fsPath,
    toString() {
      return `${scheme}://${fsPath}`;
    }
  };
}

function createWorkspaceFolder(fsPath = '/workspace', name = 'workspace') {
  return { name, index: 0, uri: createUri(fsPath) };
}

function createSelection(overrides = {}) {
  return {
    isEmpty: false,
    start: { line: 2, character: 0 },
    end: { line: 4, character: 8 },
    ...overrides
  };
}

function createEditor(overrides = {}) {
  const {
    fsPath = '/workspace/src/app.js',
    scheme = 'file',
    languageId = 'javascript',
    version = 7,
    text = 'const value = 1;\nconsole.log(value);\n',
    selectedText = 'console.log(value);',
    selection = createSelection()
  } = overrides;

  return {
    document: {
      uri: createUri(fsPath, scheme),
      languageId,
      version,
      getText(range) {
        return range === undefined ? text : selectedText;
      }
    },
    selection
  };
}

function createVscode(options = {}) {
  const folders = options.workspaceFolders ?? [];
  return {
    workspace: {
      workspaceFolders: folders,
      getConfiguration(section) {
        assert.equal(section, 'craftsec');
        return {
          get(key, fallback) {
            if (key === 'privacy.sendSourceText' && options.sendSourceText !== undefined) {
              return options.sendSourceText;
            }
            return fallback;
          }
        };
      },
      getWorkspaceFolder(uri) {
        if (options.getWorkspaceFolder) {
          return options.getWorkspaceFolder(uri);
        }
        return folders.find(
          (folder) =>
            uri.fsPath === folder.uri.fsPath || uri.fsPath.startsWith(`${folder.uri.fsPath}/`)
        );
      }
    },
    window: {
      activeTextEditor: options.editor
    }
  };
}

test('editor requests include workspace metadata and consented source text', () => {
  const vscode = createVscode({
    workspaceFolders: [createWorkspaceFolder()],
    editor: createEditor()
  });

  const request = createEditorRequest(vscode, vscode.window.activeTextEditor);

  assert.deepEqual(request, {
    workspaceFolder: '/workspace',
    workspaceFolderName: 'workspace',
    filePath: '/workspace/src/app.js',
    documentUri: 'file:///workspace/src/app.js',
    languageId: 'javascript',
    documentVersion: 7,
    selection: {
      start: { line: 2, character: 0 },
      end: { line: 4, character: 8 }
    },
    selectedText: 'console.log(value);',
    sourceText: 'const value = 1;\nconsole.log(value);\n'
  });
});

test('source and selected text are omitted when sharing is disabled', () => {
  const vscode = createVscode({
    workspaceFolders: [createWorkspaceFolder()],
    editor: createEditor(),
    sendSourceText: false
  });

  const request = createEditorRequest(vscode, vscode.window.activeTextEditor);

  assert.equal('sourceText' in request, false);
  assert.equal('selectedText' in request, false);
  assert.equal(request.selection.start.line, 2);
  assert.equal(new Set(Object.keys(request)).has('filePath'), true);
});

test('an explicit includeSourceText option overrides the setting', () => {
  const vscode = createVscode({
    workspaceFolders: [createWorkspaceFolder()],
    editor: createEditor(),
    sendSourceText: false
  });

  const request = createEditorRequest(vscode, vscode.window.activeTextEditor, {
    includeSourceText: true
  });

  assert.equal(request.sourceText, 'const value = 1;\nconsole.log(value);\n');
  assert.equal(request.selectedText, 'console.log(value);');
});

test('an editor without an active selection omits selection fields', () => {
  const vscode = createVscode({
    workspaceFolders: [createWorkspaceFolder()],
    editor: createEditor({ selection: createSelection({ isEmpty: true }) })
  });

  const request = createEditorRequest(vscode, vscode.window.activeTextEditor);

  assert.equal('selection' in request, false);
  assert.equal('selectedText' in request, false);
  assert.equal(request.sourceText.length > 0, true);
});

test('readSendSourceText defaults to enabled and fails closed on error', () => {
  assert.equal(readSendSourceText({}), true);
  assert.equal(readSendSourceText(createVscode()), true);
  assert.equal(readSendSourceText(createVscode({ sendSourceText: false })), false);
  assert.equal(
    readSendSourceText({
      workspace: {
        getConfiguration() {
          throw new Error('configuration unavailable');
        }
      }
    }),
    false
  );
});

test('editor and selection preconditions produce typed validation errors', () => {
  assert.throws(
    () => requireWorkspace(createVscode()),
    (error) => {
      assert.ok(error instanceof CommandValidationError);
      assert.equal(error.code, 'E_NO_WORKSPACE');
      return true;
    }
  );
  assert.throws(
    () => requireActiveEditor(createVscode()),
    (error) => {
      assert.equal(error.code, 'E_NO_EDITOR');
      return true;
    }
  );
  assert.throws(
    () => requireActiveEditor(createVscode({ editor: createEditor({ scheme: 'untitled' }) })),
    (error) => {
      assert.equal(error.code, 'E_UNSAVED_FILE');
      return true;
    }
  );
  assert.throws(
    () => requireSelection(createEditor({ selection: createSelection({ isEmpty: true }) })),
    (error) => {
      assert.equal(error.code, 'E_NO_SELECTION');
      return true;
    }
  );
});

test('findWorkspaceFolder rejects files outside every open folder', () => {
  const vscode = createVscode({ workspaceFolders: [createWorkspaceFolder('/workspace')] });

  assert.throws(
    () => findWorkspaceFolder(vscode, createUri('/outside/app.js')),
    (error) => {
      assert.equal(error.code, 'E_FILE_OUTSIDE_WORKSPACE');
      return true;
    }
  );
});

test('workspace requests contain only folder metadata and deduplicate paths', () => {
  const vscode = createVscode({
    workspaceFolders: [
      createWorkspaceFolder('/workspace', 'workspace'),
      createWorkspaceFolder('/workspace', 'duplicate'),
      createWorkspaceFolder('/other', 'other')
    ]
  });

  assert.deepEqual(createWorkspaceRequest(vscode), {
    workspaceFolders: [
      { name: 'workspace', path: '/workspace', uri: 'file:///workspace' },
      { name: 'other', path: '/other', uri: 'file:///other' }
    ]
  });
});

test('workspace requests reject virtual folders and excessive folder counts', () => {
  assert.throws(
    () =>
      createWorkspaceRequest(
        createVscode({
          workspaceFolders: [{ name: 'remote', uri: createUri('/remote', 'vscode-remote') }]
        })
      ),
    (error) => {
      assert.equal(error.code, 'E_UNSUPPORTED_WORKSPACE');
      return true;
    }
  );

  const tooMany = Array.from({ length: MAX_WORKSPACE_FOLDERS + 1 }, (_, index) =>
    createWorkspaceFolder(`/workspace-${index}`, `workspace-${index}`)
  );
  assert.throws(
    () => createWorkspaceRequest(createVscode({ workspaceFolders: tooMany })),
    (error) => {
      assert.equal(error.code, 'E_TOO_MANY_WORKSPACE_FOLDERS');
      return true;
    }
  );
});

test('repair finding arguments are validated and normalized', () => {
  const finding = normalizeRepairFindingArgument({
    findingId: ' finding-1 ',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 2, character: 4 }
    },
    cwe: 'cwe-89',
    ruleId: 'sql-injection'
  });

  assert.deepEqual(finding, {
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 2, character: 4 }
    },
    cwe: 'CWE-89',
    ruleId: 'sql-injection'
  });
  assert.equal(normalizeRepairFindingArgument(undefined), undefined);

  for (const value of [
    'not-an-object',
    [],
    { findingId: '', documentUri: 'file:///workspace/src/app.js', range: finding.range },
    { findingId: 'x', documentUri: 'https://example.test', range: finding.range },
    { findingId: 'x', documentUri: 'file:///workspace/src/app.js', range: { start: {} } }
  ]) {
    assert.throws(
      () => normalizeRepairFindingArgument(value),
      (error) => {
        assert.ok(error instanceof CommandValidationError);
        assert.equal(error.code, 'E_INVALID_FINDING_CONTEXT');
        return true;
      }
    );
  }
});

test('repair requests require the finding to belong to the active document', () => {
  const vscode = createVscode({
    workspaceFolders: [createWorkspaceFolder()],
    editor: createEditor()
  });
  const range = {
    start: { line: 0, character: 0 },
    end: { line: 1, character: 1 }
  };

  const matching = createRepairRequest(vscode, {
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/app.js',
    range
  });
  assert.equal(matching.finding.findingId, 'finding-1');

  assert.throws(
    () =>
      createRepairRequest(vscode, {
        findingId: 'finding-1',
        documentUri: 'file:///workspace/src/other.js',
        range
      }),
    (error) => {
      assert.equal(error.code, 'E_FINDING_DOCUMENT_MISMATCH');
      return true;
    }
  );
});

test('verification requests use the active saved editor', () => {
  const vscode = createVscode({
    workspaceFolders: [createWorkspaceFolder()],
    editor: createEditor()
  });

  const request = createVerificationRequest(vscode);

  assert.equal(request.filePath, '/workspace/src/app.js');
  assert.equal(request.workspaceFolder, '/workspace');
  assert.equal(request.sourceText.length > 0, true);
  assert.throws(() => createVerificationRequest(createVscode()), /Open a text editor/);
});
