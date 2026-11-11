'use strict';

const vscode = require('vscode');
const { readSettings } = require('../config');
const { COMMANDS } = require('../constants');

class StatusBar {
  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.name = 'CRAFT-Sec';
    this.item.text = '$(shield) CRAFT-Sec';
    this.item.tooltip = 'CRAFT-Sec Security Framework (scaffold). Click for status.';
    this.item.command = COMMANDS.showStatus;
    this.applySettings();
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
