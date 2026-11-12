'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { COMMANDS } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const { registerCommands, expectedCommandIds } = require('../../src/commands');
const { CommandRegistry } = require('../../src/commands/registry');

const ENGINE_METHODS = Object.freeze([
  'scanFile',
  'scanSelection',
  'scanWorkspace',
  'explainVulnerability',
  'analyzeSecurityFeatures',
  'counterfactualAnalysis',
  'generateSecureCode',
  'repairVulnerability',
  'verifyRepair'
]);

/**
 * @param {string} fsPath
 * @param {string} [scheme]
 */
function createUri(fsPath, scheme = 'file') {
  return {
    scheme,
    fsPath,
    toString() {
      return `${scheme}://${fsPath}`;
    }
  };
}

/**
 * @param {string} [fsPath]
 * @param {string} [name]
 */
function createWorkspaceFolder(fsPath = '/workspace', name = 'workspace') {
  return { name, index: 0, uri: createUri(fsPath) };
}

/**
 * @param {{
 *   empty?: boolean,
 *   start?: { line: number, character: number },
 *   end?: { line: number, character: number }
 * }} [options]
 */
function createSelection(options = {}) {
  return {
    isEmpty: options.empty ?? false,
    start: options.start ?? { line: 1, character: 0 },
    end: options.end ?? { line: 3, character: 2 }
  };
}

/**
 * @param {{
 *   fsPath?: string,
 *   scheme?: string,
 *   languageId?: string,
 *   version?: number,
 *   text?: string,
 *   selection?: object
 * }} [options]
 */
function createEditor(options = {}) {
  const {
    fsPath = '/workspace/src/app.js',
    scheme = 'file',
    languageId = 'javascript',
    version = 4,
    text = 'const value = 1;',
    selection = createSelection()
  } = options;
  const uri = createUri(fsPath, scheme);

  return {
    document: {
      uri,
      languageId,
      version,
      getText() {
        return text;
      }
    },
    selection
  };
}

/**
 * @param {{
 *   activeTextEditor?: object,
 *   workspaceFolders?: object[],
 *   cancellationRequested?: boolean,
 *   informationMessageResult?: string,
 *   errorMessageResult?: string,
 *   executeCommandError?: Error,
 *   executeCommandResult?: unknown,
 *   getWorkspaceFolder?: (uri: object) => object | undefined
 * }} [options]
 */
function createFakeVscode(options = {}) {
  const handlers = new Map();
  const registrations = [];
  const progressReports = [];
  const progressOptions = [];
  const informationMessages = [];
  const errorMessages = [];
  const executedCommands = [];
  const workspaceFolders = options.workspaceFolders ?? [];
  let activeTextEditor = options.activeTextEditor;

  const vscode = {
    ProgressLocation: { Notification: 15 },
    commands: {
      registerCommand(commandId, handler) {
        if (handlers.has(commandId)) {
          throw new Error(`Command already registered: ${commandId}`);
        }
        handlers.set(commandId, handler);

        const registration = {
          commandId,
          disposed: false,
          dispose() {
            registration.disposed = true;
            handlers.delete(commandId);
          }
        };
        registrations.push(registration);
        return registration;
      },
      async executeCommand(command, ...args) {
        executedCommands.push({ command, args });
        if (options.executeCommandError) {
          throw options.executeCommandError;
        }
        return options.executeCommandResult;
      }
    },
    window: {
      get activeTextEditor() {
        return activeTextEditor;
      },
      async showInformationMessage(message, ...actions) {
        informationMessages.push({ message, actions });
        return options.informationMessageResult;
      },
      async showErrorMessage(message, ...actions) {
        errorMessages.push({ message, actions });
        return options.errorMessageResult;
      },
      async withProgress(configuration, task) {
        progressOptions.push(configuration);
        const progress = {
          report(value) {
            progressReports.push(value);
          }
        };
        const token = {
          isCancellationRequested: Boolean(options.cancellationRequested),
          onCancellationRequested() {
            return { dispose() {} };
          }
        };
        return task(progress, token);
      }
    },
    workspace: {
      workspaceFolders,
      getWorkspaceFolder(uri) {
        if (options.getWorkspaceFolder) {
          return options.getWorkspaceFolder(uri);
        }
        return workspaceFolders.find(
          (folder) =>
            uri.fsPath === folder.uri.fsPath || uri.fsPath.startsWith(`${folder.uri.fsPath}/`)
        );
      }
    }
  };

  return {
    vscode,
    handlers,
    registrations,
    progressReports,
    progressOptions,
    informationMessages,
    errorMessages,
    executedCommands,
    setActiveTextEditor(editor) {
      activeTextEditor = editor;
    }
  };
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

/**
 * @param {Record<string, (request: object, context: object) => Promise<unknown>>} [overrides]
 */
function createFakeService(overrides = {}) {
  const calls = [];
  const service = {};

  for (const method of ENGINE_METHODS) {
    service[method] = async (request, context) => {
      calls.push({ method, request, context });
      if (overrides[method]) {
        return overrides[method](request, context);
      }
      return { method, request };
    };
  }

  return { service, calls };
}

function createFakeDashboard(options = {}) {
  const openCalls = [];
  return {
    openCalls,
    dashboard: {
      open() {
        openCalls.push({});
        if (options.openError) {
          throw options.openError;
        }
        return { revealed: false };
      }
    }
  };
}

function createFakeDiagnostics() {
  const publications = [];
  return {
    publications,
    publishScanResult(result, options) {
      publications.push({ result, options });
      return { published: 0, files: [], rejected: [] };
    }
  };
}

function createHarness(options = {}) {
  const fake = createFakeVscode(options);
  const logger = createFakeLogger();
  const { service, calls } = createFakeService(options.serviceOverrides);
  const { dashboard, openCalls } = createFakeDashboard(options);
  const { publications, ...diagnostics } = createFakeDiagnostics();
  const registry = registerCommands({
    vscode: fake.vscode,
    service,
    logger,
    dashboard,
    diagnostics
  });
  return {
    ...fake,
    logger,
    service,
    calls,
    dashboard,
    openCalls,
    diagnostics,
    publications,
    registry
  };
}

test('registerCommands registers every declared command exactly once', () => {
  const harness = createHarness();
  const expected = [...expectedCommandIds()].sort();

  assert.equal(harness.registry.size, 12);
  assert.deepEqual(harness.registry.ids().sort(), expected);
  assert.deepEqual([...harness.handlers.keys()].sort(), expected);
  assert.equal(harness.registrations.length, 12);

  harness.registry.dispose();
});

test('disposing the registry releases every registration and is idempotent', () => {
  const harness = createHarness();
  const registrations = [...harness.registrations];

  harness.registry.dispose();

  assert.equal(harness.handlers.size, 0);
  assert.equal(harness.registry.size, 0);
  assert.ok(registrations.every((registration) => registration.disposed));

  harness.registry.dispose();
  assert.throws(
    () => harness.registry.register('craftsec.lateCommand', () => {}),
    /Cannot register command after disposal/
  );
});

test('the registry refuses duplicate command IDs', () => {
  const fake = createFakeVscode();
  const registry = new CommandRegistry(fake.vscode, createFakeLogger());

  registry.register('craftsec.testCommand', () => {});
  assert.throws(
    () => registry.register('craftsec.testCommand', () => {}),
    /Command is already registered/
  );

  registry.dispose();
});

test('editor commands reject a missing editor without calling the engine', async () => {
  const harness = createHarness({ activeTextEditor: undefined });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(result, undefined);
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Open a text editor/);
  assert.deepEqual(harness.errorMessages[0].actions, ['Show Logs']);
  assert.equal(harness.informationMessages.length, 0, 'no success message may be shown');
  assert.equal(harness.logger.entries.at(-1).level, 'warn');

  harness.registry.dispose();
});

test('unsaved or virtual documents are rejected before analysis', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor({ scheme: 'untitled', fsPath: '/workspace/Untitled-1' }),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Save the active file/);

  harness.registry.dispose();
});

test('files outside the workspace are rejected before analysis', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor({ fsPath: '/outside/app.js' }),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /not inside an open workspace folder/);

  harness.registry.dispose();
});

test('workspace commands require an open workspace', async () => {
  const harness = createHarness({ workspaceFolders: [] });

  await harness.handlers.get(COMMANDS.scanWorkspace)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Open a folder or workspace/);

  harness.registry.dispose();
});

test('selection commands require a non-empty selection', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor({ selection: createSelection({ empty: true }) }),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.scanSelection)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Select code/);

  harness.registry.dispose();
});

test('scan current file passes saved editor context and cancellable progress', async () => {
  const workspaceFolder = createWorkspaceFolder('/workspace');
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [workspaceFolder]
  });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 1);
  const [{ method, request, context }] = harness.calls;
  assert.equal(method, 'scanFile');
  assert.equal(request.workspaceFolder, '/workspace');
  assert.equal(request.workspaceFolderName, 'workspace');
  assert.equal(request.filePath, '/workspace/src/app.js');
  assert.equal(request.languageId, 'javascript');
  assert.equal(request.documentVersion, 4);
  assert.deepEqual(request.selection, {
    start: { line: 1, character: 0 },
    end: { line: 3, character: 2 }
  });
  assert.equal(request.selectedText, 'const value = 1;');
  assert.equal(typeof context.token.isCancellationRequested, 'boolean');

  assert.equal(harness.progressOptions[0].location, 15);
  assert.equal(harness.progressOptions[0].cancellable, true);
  assert.equal(harness.progressOptions[0].title, 'CRAFT-Sec: Scanning current file');
  assert.deepEqual(harness.progressReports, [
    { message: 'Waiting for the local security engine.' }
  ]);

  assert.deepEqual(result, { method: 'scanFile', request });
  assert.equal(harness.informationMessages.length, 0, 'no success message may be shown');
  assert.equal(harness.errorMessages.length, 0);

  harness.registry.dispose();
});

test('every engine-backed command invokes its declared service method', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });
  const engineDefinitions = COMMAND_DEFINITIONS.filter((definition) => definition.serviceMethod);

  for (const definition of engineDefinitions) {
    await harness.handlers.get(definition.id)();
  }

  assert.deepEqual(
    harness.calls.map((call) => call.method),
    engineDefinitions.map((definition) => definition.serviceMethod)
  );
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);

  harness.registry.dispose();
});

test('service failures show an error with a log action and never a success notice', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    errorMessageResult: 'Show Logs',
    serviceOverrides: {
      scanFile: async () => {
        throw new Error('engine connection failed');
      }
    }
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /engine connection failed/);
  assert.deepEqual(harness.errorMessages[0].actions, ['Show Logs']);
  assert.equal(harness.informationMessages.length, 0);
  assert.equal(harness.logger.shown, true);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'error'));

  harness.registry.dispose();
});

test('pre-cancelled commands report cancellation without an error notification', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    cancellationRequested: true
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'info' && /cancelled/.test(entry.message)
    )
  );

  harness.registry.dispose();
});

test('a scan cancelled during the engine call publishes no diagnostics', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile(request, context) {
        context.token.isCancellationRequested = true;
        return { findings: [] };
      }
    }
  });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(result, undefined);
  assert.equal(harness.calls.length, 1);
  assert.equal(harness.publications.length, 0);
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'info' && /cancelled/.test(entry.message)
    )
  );

  harness.registry.dispose();
});

test('open security dashboard opens the dashboard panel', async () => {
  const harness = createHarness();

  const result = await harness.handlers.get(COMMANDS.openSecurityDashboard)();

  assert.equal(result, undefined);
  assert.equal(harness.openCalls.length, 1);
  assert.deepEqual(harness.executedCommands, []);
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);

  harness.registry.dispose();
});

test('dashboard failures are logged and reported', async () => {
  const harness = createHarness({
    openError: new Error('view unavailable'),
    errorMessageResult: 'Show Logs'
  });

  await harness.handlers.get(COMMANDS.openSecurityDashboard)();

  assert.equal(harness.openCalls.length, 1);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Unable to open the Security Dashboard/);
  assert.equal(harness.logger.shown, true);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'error'));

  harness.registry.dispose();
});

test('show status reports the unavailable engine and never claims success', async () => {
  const harness = createHarness({ informationMessageResult: 'Open Security Dashboard' });

  await harness.handlers.get(COMMANDS.showStatus)();

  assert.equal(harness.informationMessages.length, 1);
  assert.match(harness.informationMessages[0].message, /not available/);
  assert.doesNotMatch(harness.informationMessages[0].message, /success/i);
  assert.deepEqual(harness.informationMessages[0].actions, [
    'Open Security Dashboard',
    'Show Logs'
  ]);
  assert.deepEqual(harness.executedCommands, [
    { command: COMMANDS.openSecurityDashboard, args: [] }
  ]);

  harness.registry.dispose();
});

test('show logs opens the CRAFT-Sec output channel', async () => {
  const harness = createHarness();

  await harness.handlers.get(COMMANDS.showLogs)();

  assert.equal(harness.logger.shown, true);

  harness.registry.dispose();
});

test('scan results are published to diagnostics with the scanned file scope', async () => {
  const backendResult = { findings: [] };
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile: async () => backendResult
    }
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.publications.length, 1);
  assert.equal(harness.publications[0].result, backendResult);
  assert.deepEqual(harness.publications[0].options, {
    scopeUris: ['file:///workspace/src/app.js']
  });

  harness.registry.dispose();
});

test('workspace scans publish diagnostics without inventing a file scope', async () => {
  const backendResult = { findings: [], scope: { uris: ['file:///workspace/src/app.js'] } };
  const harness = createHarness({
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanWorkspace: async () => backendResult
    }
  });

  await harness.handlers.get(COMMANDS.scanWorkspace)();

  assert.equal(harness.publications.length, 1);
  assert.equal(harness.publications[0].result, backendResult);
  assert.equal(harness.publications[0].options, undefined);

  harness.registry.dispose();
});

test('analysis commands do not publish diagnostics', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.explainVulnerability)();
  await harness.handlers.get(COMMANDS.analyzeSecurityFeatures)();

  assert.equal(harness.publications.length, 0);

  harness.registry.dispose();
});

test('failed scans never publish diagnostics', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile: async () => {
        throw new Error('engine connection failed');
      }
    }
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.publications.length, 0);
  assert.equal(harness.errorMessages.length, 1);

  harness.registry.dispose();
});

test('a repair Quick Fix sends finding context with the editor request', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });
  const finding = {
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 4, character: 2 },
      end: { line: 4, character: 42 }
    },
    cwe: 'CWE-89',
    ruleId: 'js/sql-injection'
  };

  await harness.handlers.get(COMMANDS.repairVulnerability)(finding);

  assert.equal(harness.calls.length, 1);
  assert.equal(harness.calls[0].method, 'repairVulnerability');
  assert.deepEqual(harness.calls[0].request.finding, finding);
  assert.equal(harness.calls[0].request.filePath, '/workspace/src/app.js');
  assert.equal(harness.errorMessages.length, 0);

  harness.registry.dispose();
});

test('a repair Quick Fix for another file is rejected before the engine call', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.repairVulnerability)({
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/other.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 0, character: 5 }
    }
  });

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Open the file that contains this finding/);

  harness.registry.dispose();
});

test('malformed repair finding context is rejected before the engine call', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.repairVulnerability)({
    findingId: '',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 0, character: 5 }
    }
  });

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Invalid repair finding context/);

  harness.registry.dispose();
});

test('registration fails atomically when the diagnostics controller is missing', () => {
  const fake = createFakeVscode();
  const { service } = createFakeService();
  const { dashboard } = createFakeDashboard();

  assert.throws(
    () =>
      registerCommands({
        vscode: fake.vscode,
        service,
        logger: createFakeLogger(),
        dashboard
      }),
    /diagnostics controller/
  );
  assert.equal(fake.handlers.size, 0);
  assert.equal(fake.registrations.length, 0);
});

test('registration fails atomically when the service contract is incomplete', () => {
  const fake = createFakeVscode();
  const { service } = createFakeService();
  const { dashboard } = createFakeDashboard();
  delete service.verifyRepair;

  assert.throws(
    () =>
      registerCommands({
        vscode: fake.vscode,
        service,
        logger: createFakeLogger(),
        dashboard,
        diagnostics: createFakeDiagnostics()
      }),
    /SecurityEngineService\.verifyRepair/
  );
  assert.equal(fake.handlers.size, 0);
  assert.ok(fake.registrations.every((registration) => registration.disposed));
});

test('registration fails atomically when the dashboard controller is missing', () => {
  const fake = createFakeVscode();
  const { service } = createFakeService();

  assert.throws(
    () => registerCommands({ vscode: fake.vscode, service, logger: createFakeLogger() }),
    /dashboard controller/
  );
  assert.equal(fake.handlers.size, 0);
  assert.equal(fake.registrations.length, 0);
});
