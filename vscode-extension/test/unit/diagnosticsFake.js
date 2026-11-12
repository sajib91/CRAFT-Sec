'use strict';

const { normalizeFinding } = require('../../src/diagnostics/findingModel');
const { isPathWithinRoot } = require('../../src/security/paths');

function createUri(uriString) {
  const parsed = new URL(uriString);
  return {
    scheme: parsed.protocol.slice(0, -1),
    path: parsed.pathname,
    fsPath: decodeURIComponent(parsed.pathname),
    toString() {
      return uriString;
    }
  };
}

function createWorkspaceFolder(fsPath = '/workspace', name = 'workspace') {
  const uriText = fsPath.startsWith('file:') ? fsPath : `file://${fsPath}`;
  return { name, index: 0, uri: createUri(uriText) };
}

function createFakeLogger() {
  const entries = [];
  const logger = {
    entries,
    shown: false,
    trace(message) {
      entries.push({ level: 'trace', message });
    },
    debug(message) {
      entries.push({ level: 'debug', message });
    },
    info(message) {
      entries.push({ level: 'info', message });
    },
    warn(message) {
      entries.push({ level: 'warn', message });
    },
    error(message, error) {
      entries.push({ level: 'error', message, error });
    },
    show() {
      logger.shown = true;
    },
    applySettings() {},
    dispose() {}
  };
  return logger;
}

class FakeRange {
  constructor(startLine, startCharacter, endLine, endCharacter) {
    this.start = { line: startLine, character: startCharacter };
    this.end = { line: endLine, character: endCharacter };
  }
}

class FakeDiagnostic {
  constructor(range, message, severity) {
    this.range = range;
    this.message = message;
    this.severity = severity;
    this.source = undefined;
    this.code = undefined;
    this.relatedInformation = undefined;
  }
}

class FakeLocation {
  constructor(uri, range) {
    this.uri = uri;
    this.range = range;
  }
}

class FakeDiagnosticRelatedInformation {
  constructor(location, message) {
    this.location = location;
    this.message = message;
  }
}

class FakeMarkdownString {
  constructor(value) {
    this.value = value;
    this.isTrusted = true;
  }
}

class FakeHover {
  constructor(contents, range) {
    this.contents = contents;
    this.range = range;
  }
}

class FakeCodeAction {
  constructor(title, kind) {
    this.title = title;
    this.kind = kind;
    this.command = undefined;
    this.diagnostics = undefined;
    this.isPreferred = false;
  }
}

class FakeDiagnosticCollection {
  constructor(name) {
    this.name = name;
    this.entries = new Map();
    this.setCalls = [];
    this.deleteCalls = [];
    this.cleared = false;
    this.disposed = false;
  }

  set(uri, diagnostics) {
    this.setCalls.push({ uri, diagnostics });
    this.entries.set(uri.toString(), diagnostics);
  }

  delete(uri) {
    this.deleteCalls.push(uri);
    this.entries.delete(uri.toString());
  }

  clear() {
    this.cleared = true;
    this.entries.clear();
  }

  dispose() {
    this.disposed = true;
    this.entries.clear();
  }
}

function createFakeRegistry() {
  const registrations = [];
  return {
    registrations,
    register(kind, selector, provider, metadata) {
      const registration = {
        kind,
        selector,
        provider,
        metadata,
        disposed: false,
        dispose() {
          registration.disposed = true;
        }
      };
      registrations.push(registration);
      return registration;
    }
  };
}

function createFakeVscode(options = {}) {
  const workspaceFolders = options.workspaceFolders ?? [createWorkspaceFolder('/workspace')];
  const collections = [];
  const registry = createFakeRegistry();

  const vscode = {
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    CodeActionKind: { QuickFix: 'quickfix' },
    Range: FakeRange,
    Diagnostic: FakeDiagnostic,
    Location: FakeLocation,
    DiagnosticRelatedInformation: FakeDiagnosticRelatedInformation,
    MarkdownString: FakeMarkdownString,
    Hover: FakeHover,
    CodeAction: FakeCodeAction,
    Uri: {
      parse(uriString) {
        return createUri(uriString);
      }
    },
    workspace: {
      workspaceFolders,
      getWorkspaceFolder(uri) {
        return workspaceFolders.find(
          (folder) => uri.scheme === 'file' && isPathWithinRoot(uri.fsPath, folder.uri.fsPath)
        );
      }
    },
    languages: {
      createDiagnosticCollection(name) {
        const collection = new FakeDiagnosticCollection(name);
        collections.push(collection);
        return collection;
      },
      registerHoverProvider(selector, provider) {
        return registry.register('hover', selector, provider);
      },
      registerCodeActionsProvider(selector, provider, metadata) {
        return registry.register('codeAction', selector, provider, metadata);
      }
    }
  };

  return { vscode, collections, registry, logger: createFakeLogger() };
}

function createRawFinding(overrides = {}) {
  return {
    id: 'finding-1',
    message: 'User input reaches a SQL query.',
    severity: 'high',
    cwe: 'CWE-89',
    ruleId: 'js/sql-injection',
    location: {
      uri: 'file:///workspace/src/app.js',
      range: {
        start: { line: 4, character: 2 },
        end: { line: 4, character: 42 }
      }
    },
    evidence: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
    explanation: 'The request parameter is concatenated into a SQL statement.',
    sourceReferences: [
      {
        label: 'CWE-89',
        url: 'https://cwe.mitre.org/data/definitions/89.html'
      }
    ],
    repair: {
      eligible: true,
      description: 'Use a parameterized query.'
    },
    ...overrides
  };
}

function createFinding(overrides = {}) {
  return normalizeFinding(createRawFinding(overrides));
}

module.exports = {
  createUri,
  createWorkspaceFolder,
  createFakeLogger,
  createFakeVscode,
  createRawFinding,
  createFinding
};
