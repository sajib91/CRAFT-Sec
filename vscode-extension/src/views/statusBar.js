'use strict';

const vscode = require('vscode');
const { readSettings } = require('../config');
const { COMMANDS } = require('../constants');

class StatusBar {
  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.name = 'CRAFT-Sec';
    this.item.text = '$(shield) CRAFT-Sec';
    this.item.tooltip = 'CRAFT-Sec Security Framework. Click to check backend status.';
    this.item.command = COMMANDS.showStatus;
    this.applySettings();
  }

  /**
   * Reflect the last known backend health without claiming analysis exists.
   *
   * @param {'checking' | 'reachable' | 'unavailable'} state
   * @param {string} [detail]
   */
  setBackendStatus(state, detail) {
    if (state === 'checking') {
      this.item.text = '$(sync~spin) CRAFT-Sec';
      this.item.tooltip = 'Checking the CRAFT-Sec backend connection.';
    } else if (state === 'reachable') {
      this.item.text = '$(shield) CRAFT-Sec';
      this.item.tooltip =
        detail ??
        'CRAFT-Sec backend reachable. Detection and AI analysis stages remain unavailable.';
    } else {
      this.item.text = '$(shield) CRAFT-Sec';
      this.item.tooltip =
        detail ?? 'CRAFT-Sec backend unavailable. Click for status and troubleshooting.';
    }
  }

  applySettings() {
    const { showStatusBarItem } = readSettings();
    if (showStatusBarItem) {
      this.item.show();
    } else {
      this.item.hide();
    }
  }

  dispose() {
    this.item.dispose();
  }
}

/** @returns {StatusBar} */
function createStatusBar() {
  return new StatusBar();
}

module.exports = { StatusBar, createStatusBar };
