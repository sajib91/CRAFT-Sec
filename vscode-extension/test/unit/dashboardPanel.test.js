'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { COMMANDS } = require('../../src/constants');
const {
  DashboardPanelController,
  DASHBOARD_TITLE,
  DASHBOARD_VIEW_TYPE,
  EXECUTABLE_COMMANDS
} = require('../../src/webviews/dashboardPanel');

function createUri(path) {
  return {
    path,
    scheme: 'file',
    toString() {
      return `file://${path}`;
    }
  };
}

function createFakeVscode(options = {}) {
  const createdPanels = [];
  const executedCommands = [];

  const vscode = {
    ViewColumn: { One: 1 },
    Uri: {
      joinPath(base, ...parts) {
        const separator = base.path.endsWith('/') ? '' : '/';
        return createUri(`${base.path}${separator}${parts.join('/')}`);
      }
    },
    window: {
      createWebviewPanel(viewType, title, column, panelOptions) {
        const panel = createFakePanel({ options: panelOptions, viewType, title, column });
        createdPanels.push(panel);
        return panel;
      }
    },
    commands: {
      async executeCommand(command, ...args) {
        executedCommands.push({ command, args });
        const error = options.commandErrors?.get(command);
        if (error) {
          throw error;
        }
        return undefined;
      }
    }
  };

  return { vscode, createdPanels, executedCommands };
}

function createFakePanel({ options, viewType, title, column }) {
  const messageHandlers = new Set();
  const disposeHandlers = new Set();
  const postedMessages = [];
  const revealCalls = [];

  const panel = {
    viewType,
    title,
    viewColumn: column,
    options,
    iconPath: undefined,
    disposed: false,
    postedMessages,
    revealCalls,
    webview: {
      cspSource: 'vscode-webview://test',
      html: '',
      options,
      asWebviewUri(uri) {
        return {
          toString() {
            return `vscode-webview://test${uri.path}`;
          }
        };
      },
      onDidReceiveMessage(handler) {
        messageHandlers.add(handler);
        return {
          dispose() {
            messageHandlers.delete(handler);
          }
        };
      },
      async postMessage(message) {
        postedMessages.push(message);
        return true;
      }
    },
    reveal(viewColumn) {
      revealCalls.push(viewColumn);
      return this;
    },
    onDidDispose(handler) {
      disposeHandlers.add(handler);
      return {
        dispose() {
          disposeHandlers.delete(handler);
        }
      };
    },
    dispose() {
      if (this.disposed) {
        return;
      }
      this.disposed = true;
      for (const handler of [...disposeHandlers]) {
        handler();
      }
      disposeHandlers.clear();
    },
    async send(message) {
      for (const handler of [...messageHandlers]) {
        await handler(message);
      }
    },
    messageHandlerCount() {
      return messageHandlers.size;
    }
  };

  return panel;
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

function createHarness(options = {}) {
  const fake = createFakeVscode(options);
  const logger = createFakeLogger();
  const stateCalls = [];
  const controller = new DashboardPanelController({
    vscode: fake.vscode,
    extensionUri: createUri('/extension'),
    logger,
    getState(dataMode) {
      stateCalls.push(dataMode);
      return {
        dataMode,
        generatedAt: '2026-11-11T12:00:00.000Z',
        request: stateCalls.length
      };
    }
  });

  return { ...fake, logger, stateCalls, controller };
}

test('dashboard panel opens once with local-resource and script options', () => {
  const harness = createHarness();

  const panel = harness.controller.open();

  assert.equal(harness.createdPanels.length, 1);
  assert.equal(panel, harness.createdPanels[0]);
  assert.equal(panel.viewType, DASHBOARD_VIEW_TYPE);
  assert.equal(panel.title, DASHBOARD_TITLE);
  assert.equal(panel.webview.options.enableScripts, true);
  assert.equal(panel.webview.options.retainContextWhenHidden, true);
  assert.equal(panel.webview.options.localResourceRoots.length, 1);
  assert.equal(panel.webview.options.localResourceRoots[0].path, '/extension/media');
  assert.equal(panel.iconPath.path, '/extension/media/icon.png');
  assert.match(panel.webview.html, /default-src &#39;none&#39;/);
  assert.match(panel.webview.html, /Loading dashboard/);
  assert.ok(!panel.webview.html.includes('unsafe-inline'));
  assert.deepEqual(harness.stateCalls, ['empty']);
  assert.equal(panel.messageHandlerCount(), 1);

  harness.controller.dispose();
});

test('opening an existing dashboard reveals the same panel', () => {
  const harness = createHarness();
  const first = harness.controller.open();

  const second = harness.controller.open();

  assert.equal(second, first);
  assert.equal(harness.createdPanels.length, 1);
  assert.deepEqual(first.revealCalls, [1]);
  assert.deepEqual(harness.stateCalls, ['empty']);

  harness.controller.dispose();
});

test('ready and refresh messages post the current state', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'ready' });
  await panel.send({ type: 'refresh' });

  assert.deepEqual(harness.stateCalls, ['empty', 'empty']);
  assert.deepEqual(panel.postedMessages, [
    {
      type: 'state',
      state: { dataMode: 'empty', generatedAt: '2026-11-11T12:00:00.000Z', request: 1 }
    },
    {
      type: 'state',
      state: { dataMode: 'empty', generatedAt: '2026-11-11T12:00:00.000Z', request: 2 }
    }
  ]);

  harness.controller.dispose();
});

test('demo mode toggling validates input and rebuilds state', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'setDemoMode', enabled: true });
  assert.deepEqual(harness.stateCalls, ['empty', 'demo']);
  assert.equal(panel.postedMessages.at(-1).state.dataMode, 'demo');

  await panel.send({ type: 'setDemoMode', enabled: false });
  assert.deepEqual(harness.stateCalls, ['empty', 'demo', 'empty']);
  assert.equal(panel.postedMessages.at(-1).state.dataMode, 'empty');

  await panel.send({ type: 'setDemoMode', enabled: 'yes' });
  assert.deepEqual(harness.stateCalls, ['empty', 'demo', 'empty']);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'warn'));

  harness.controller.dispose();
});

test('dashboard commands are restricted to the engine command allowlist', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'executeCommand', command: COMMANDS.scanWorkspace });
  assert.deepEqual(harness.executedCommands, [{ command: COMMANDS.scanWorkspace, args: [] }]);
  assert.ok(EXECUTABLE_COMMANDS.has(COMMANDS.scanWorkspace));
  assert.ok(!EXECUTABLE_COMMANDS.has(COMMANDS.openSecurityDashboard));
  assert.ok(EXECUTABLE_COMMANDS.has(COMMANDS.verifyRepair));

  await panel.send({ type: 'executeCommand', command: COMMANDS.openSecurityDashboard });
  await panel.send({ type: 'executeCommand', command: 'workbench.action.terminal.new' });
  await panel.send({ type: 'executeCommand', command: 42 });
  await panel.send({ type: 'executeCommand', command: COMMANDS.scanWorkspace, args: ['extra'] });

  assert.deepEqual(harness.executedCommands, [
    { command: COMMANDS.scanWorkspace, args: [] },
    { command: COMMANDS.scanWorkspace, args: [] }
  ]);

  harness.controller.dispose();
});

test('dashboard opens CRAFT-Sec settings and the output channel', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'openSettings' });
  await panel.send({ type: 'showLogs' });

  assert.deepEqual(harness.executedCommands, [
    { command: 'workbench.action.openSettings', args: ['craftsec'] }
  ]);
  assert.equal(harness.logger.shown, true);

  harness.controller.dispose();
});

test('command failures produce an error notice without inventing success', async () => {
  const harness = createHarness({
    commandErrors: new Map([[COMMANDS.scanWorkspace, new Error('engine unavailable')]])
  });
  const panel = harness.controller.open();

  await panel.send({ type: 'executeCommand', command: COMMANDS.scanWorkspace });

  assert.equal(panel.postedMessages.length, 1);
  assert.equal(panel.postedMessages[0].type, 'notice');
  assert.equal(panel.postedMessages[0].level, 'error');
  assert.match(panel.postedMessages[0].message, /Unable to run/);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'error'));
  assert.ok(!panel.postedMessages.some((message) => /success/i.test(String(message.message))));

  harness.controller.dispose();
});

test('settings failures produce an error notice', async () => {
  const harness = createHarness({
    commandErrors: new Map([['workbench.action.openSettings', new Error('settings unavailable')]])
  });
  const panel = harness.controller.open();

  await panel.send({ type: 'openSettings' });

  assert.equal(panel.postedMessages.length, 1);
  assert.equal(panel.postedMessages[0].level, 'error');
  assert.match(panel.postedMessages[0].message, /Unable to open VS Code settings/);

  harness.controller.dispose();
});

test('unknown and malformed messages are ignored', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send(null);
  await panel.send('ready');
  await panel.send({ type: 'notARealMessage' });
  await panel.send({ type: 'state', state: {} });

  assert.deepEqual(panel.postedMessages, []);
  assert.equal(harness.executedCommands.length, 0);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'debug' && /unknown dashboard message/.test(entry.message)
    )
  );

  harness.controller.dispose();
});

test('disposing the dashboard releases listeners and allows a fresh panel', () => {
  const harness = createHarness();
  const first = harness.controller.open();

  assert.equal(first.messageHandlerCount(), 1);
  harness.controller.dispose();
  assert.equal(first.disposed, true);
  assert.equal(first.messageHandlerCount(), 0);
  assert.equal(harness.controller.panel, undefined);

  const second = harness.controller.open();
  assert.notEqual(second, first);
  assert.equal(harness.createdPanels.length, 2);

  harness.controller.dispose();
});

test('a panel closed by VS Code clears controller state', () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  panel.dispose();

  assert.equal(harness.controller.panel, undefined);
  assert.equal(harness.controller.state, undefined);
  assert.equal(panel.messageHandlerCount(), 0);

  harness.controller.dispose();
});
