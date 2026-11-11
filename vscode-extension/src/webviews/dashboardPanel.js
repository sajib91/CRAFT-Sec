'use strict';

const { COMMAND_DEFINITIONS } = require('../commands/definitions');
const { createNonce } = require('./csp');
const { createDashboardHtml } = require('./dashboardHtml');
const { createEmptyDashboardState } = require('./dashboardModel');

const DASHBOARD_VIEW_TYPE = 'craftsec.dashboard';
const DASHBOARD_TITLE = 'CRAFT-Sec Security Dashboard';
const SETTINGS_QUERY = 'craftsec';

/**
 * Only engine-backed commands may be triggered from the dashboard. The panel
 * never accepts arbitrary command IDs or command arguments from the webview.
 */
const EXECUTABLE_COMMANDS = Object.freeze(
  new Set(
    COMMAND_DEFINITIONS.filter((definition) => definition.serviceMethod).map(
      (definition) => definition.id
    )
  )
);

class DashboardPanelController {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   extensionUri: import('vscode').Uri,
   *   logger: import('../logging/output').Logger,
   *   getState?: (dataMode: 'empty' | 'demo') => object
   * }} options
   */
  constructor({ vscode, extensionUri, logger, getState }) {
    if (!vscode) {
      throw new TypeError('DashboardPanelController requires a vscode API object.');
    }
    if (!extensionUri) {
      throw new TypeError('DashboardPanelController requires an extension URI.');
    }
    if (!logger) {
      throw new TypeError('DashboardPanelController requires a logger.');
    }

    this.vscode = vscode;
    this.extensionUri = extensionUri;
    this.logger = logger;
    this.getState = getState ?? (() => createEmptyDashboardState());
    this.dataMode = 'empty';
    /** @type {import('vscode').WebviewPanel | undefined} */
    this.panel = undefined;
    /** @type {object | undefined} */
    this.state = undefined;
    /** @type {import('vscode').Disposable[]} */
    this.disposables = [];
  }

  /**
   * Open the dashboard, or reveal the existing panel.
   *
   * @returns {import('vscode').WebviewPanel}
   */
  open() {
    if (this.panel) {
      this.panel.reveal(this.panel.viewColumn ?? this.vscode.ViewColumn.One);
      return this.panel;
    }

    const mediaRoot = this.vscode.Uri.joinPath(this.extensionUri, 'media');
    const panel = this.vscode.window.createWebviewPanel(
      DASHBOARD_VIEW_TYPE,
      DASHBOARD_TITLE,
      this.vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [mediaRoot]
      }
    );

    this.panel = panel;
    panel.iconPath = this.vscode.Uri.joinPath(this.extensionUri, 'media', 'icon.png');

    this.state = this.getState(this.dataMode);
    panel.webview.html = this.buildHtml(panel.webview, mediaRoot, this.state);

    this.disposables = [
      panel.webview.onDidReceiveMessage((message) => this.handleMessage(message)),
      panel.onDidDispose(() => this.handleDispose(panel))
    ];

    this.logger.info('Opened the CRAFT-Sec security dashboard.');
    return panel;
  }

  /**
   * @param {import('vscode').Webview} webview
   * @param {import('vscode').Uri} mediaRoot
   * @param {object} state
   * @returns {string}
   */
  buildHtml(webview, mediaRoot, state) {
    const nonce = createNonce();
    const styleUri = webview.asWebviewUri(this.vscode.Uri.joinPath(mediaRoot, 'dashboard.css'));
    const scriptUri = webview.asWebviewUri(this.vscode.Uri.joinPath(mediaRoot, 'dashboard.js'));

    return createDashboardHtml({
      cspSource: webview.cspSource,
      styleUri: styleUri.toString(),
      scriptUri: scriptUri.toString(),
      nonce,
      state
    });
  }

  /**
   * @param {unknown} message
   */
  async handleMessage(message) {
    if (!message || typeof message !== 'object') {
      return;
    }

    switch (message.type) {
      case 'ready':
        this.postState();
        break;
      case 'refresh':
        this.refresh();
        break;
      case 'setDemoMode':
        if (typeof message.enabled !== 'boolean') {
          this.logger.warn('Ignored a malformed dashboard data-mode request.');
          return;
        }
        this.setDataMode(message.enabled ? 'demo' : 'empty');
        break;
      case 'executeCommand':
        await this.executeDashboardCommand(message.command);
        break;
      case 'openSettings':
        await this.openSettings();
        break;
      case 'showLogs':
        this.logger.show();
        break;
      default:
        this.logger.debug('Ignored an unknown dashboard message.');
    }
  }

  /**
   * @param {'empty' | 'demo'} dataMode
   */
  setDataMode(dataMode) {
    this.dataMode = dataMode === 'demo' ? 'demo' : 'empty';
    if (!this.panel) {
      return;
    }
    this.state = this.getState(this.dataMode);
    this.postState();
    this.logger.debug(`Dashboard data mode: ${this.dataMode}.`);
  }

  refresh() {
    if (!this.panel) {
      return;
    }
    this.state = this.getState(this.dataMode);
    this.postState();
    this.logger.debug('Refreshed the CRAFT-Sec security dashboard.');
  }

  postState() {
    if (!this.panel || !this.state) {
      return;
    }
    this.panel.webview.postMessage({ type: 'state', state: this.state });
  }

  /**
   * @param {unknown} command
   */
  async executeDashboardCommand(command) {
    if (typeof command !== 'string' || !EXECUTABLE_COMMANDS.has(command)) {
      this.logger.warn(`Ignored a dashboard request for a disallowed command: ${String(command)}`);
      return;
    }

    try {
      await this.vscode.commands.executeCommand(command);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to start dashboard command ${command}: ${message}`, error);
      this.postNotice('error', `Unable to run the requested command. See CRAFT-Sec logs.`);
    }
  }

  async openSettings() {
    try {
      await this.vscode.commands.executeCommand('workbench.action.openSettings', SETTINGS_QUERY);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Unable to open CRAFT-Sec settings: ${message}`, error);
      this.postNotice('error', 'Unable to open VS Code settings. See CRAFT-Sec logs.');
    }
  }

  /**
   * @param {'info' | 'warning' | 'error'} level
   * @param {string} message
   */
  postNotice(level, message) {
    if (!this.panel) {
      return;
    }
    this.panel.webview.postMessage({ type: 'notice', level, message });
  }

  /**
   * @param {import('vscode').WebviewPanel} panel
   */
  handleDispose(panel) {
    if (this.panel !== panel) {
      return;
    }
    this.panel = undefined;
    this.state = undefined;
    this.disposeListeners();
    this.logger.debug('Closed the CRAFT-Sec security dashboard.');
  }

  disposeListeners() {
    const disposables = this.disposables;
    this.disposables = [];
    for (const disposable of disposables) {
      try {
        disposable.dispose();
      } catch (error) {
        this.logger.error('Failed to dispose a dashboard listener.', error);
      }
    }
  }

  dispose() {
    const panel = this.panel;
    this.panel = undefined;
    this.state = undefined;
    this.disposeListeners();
    if (panel) {
      panel.dispose();
    }
  }
}

module.exports = {
  DashboardPanelController,
  DASHBOARD_VIEW_TYPE,
  DASHBOARD_TITLE,
  EXECUTABLE_COMMANDS,
  SETTINGS_QUERY
};
