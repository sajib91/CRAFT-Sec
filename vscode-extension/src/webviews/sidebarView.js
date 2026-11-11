'use strict';

const vscode = require('vscode');
const { VIEW_ID } = require('../constants');
const { createSidebarHtml } = require('./sidebarHtml');

class SidebarViewProvider {
  /**
   * @param {vscode.Uri} extensionUri
   * @param {import('../logging/output').Logger} logger
   */
  constructor(extensionUri, logger) {
    this.extensionUri = extensionUri;
    this.logger = logger;
  }

  /**
   * @param {vscode.WebviewView} webviewView
   */
  resolveWebviewView(webviewView) {
    const mediaRoot = vscode.Uri.joinPath(this.extensionUri, 'media');
    webviewView.webview.options = {
      enableScripts: false,
      localResourceRoots: [mediaRoot]
    };

    const styleUri = webviewView.webview.asWebviewUri(
      vscode.Uri.joinPath(mediaRoot, 'sidebar.css')
    );
    webviewView.webview.html = createSidebarHtml({
      cspSource: webviewView.webview.cspSource,
      styleUri: styleUri.toString()
    });

    this.logger.debug('Resolved the CRAFT-Sec sidebar webview.');
  }
}

/**
 * @param {vscode.ExtensionContext} context
 * @param {import('../logging/output').Logger} logger
 * @returns {vscode.Disposable}
 */
function registerSidebarView(context, logger) {
  const provider = new SidebarViewProvider(context.extensionUri, logger);
  return vscode.window.registerWebviewViewProvider(VIEW_ID, provider, {
    webviewOptions: { retainContextWhenHidden: false }
  });
}

module.exports = { SidebarViewProvider, registerSidebarView };
