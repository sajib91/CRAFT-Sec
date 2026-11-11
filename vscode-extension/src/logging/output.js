'use strict';

const vscode = require('vscode');
const { readSettings } = require('../config');

/** @type {Record<string, number>} */
const LOG_LEVELS = Object.freeze({
  trace: vscode.LogLevel.Trace,
  debug: vscode.LogLevel.Debug,
  info: vscode.LogLevel.Info,
  warn: vscode.LogLevel.Warning,
  error: vscode.LogLevel.Error,
  off: vscode.LogLevel.Off
});

/**
 * Thin wrapper around a VS Code LogOutputChannel.
 *
 * The channel never receives secrets: callers must redact values before
 * logging. Environment settings are read by the caller, not this module.
 */
class Logger {
  /** @param {string} name */
  constructor(name) {
    this.channel = vscode.window.createOutputChannel(name, { log: true });
    /** @type {number} */
    this.minimumLevel = vscode.LogLevel.Info;
    this.applySettings();
  }

  applySettings() {
    const { logLevel } = readSettings();
    this.minimumLevel = LOG_LEVELS[logLevel] ?? vscode.LogLevel.Info;
  }

  /**
   * VS Code controls the output channel's effective level; this wrapper
   * applies the extension setting as an additional, stricter filter.
   *
   * @param {number} level
   * @returns {boolean}
   */
  shouldLog(level) {
    return this.minimumLevel !== vscode.LogLevel.Off && level >= this.minimumLevel;
  }

  /** @param {string} message */
  trace(message) {
    if (this.shouldLog(vscode.LogLevel.Trace)) {
      this.channel.trace(message);
    }
  }

  /** @param {string} message */
  debug(message) {
    if (this.shouldLog(vscode.LogLevel.Debug)) {
      this.channel.debug(message);
    }
  }

  /** @param {string} message */
  info(message) {
    if (this.shouldLog(vscode.LogLevel.Info)) {
      this.channel.info(message);
    }
  }

  /** @param {string} message */
  warn(message) {
    if (this.shouldLog(vscode.LogLevel.Warning)) {
      this.channel.warn(message);
    }
  }

  /**
   * @param {string | Error} message
   * @param {...unknown} args
   */
  error(message, ...args) {
    if (this.shouldLog(vscode.LogLevel.Error)) {
      this.channel.error(message, ...args);
    }
  }

  show() {
    this.channel.show(true);
  }

  dispose() {
    this.channel.dispose();
  }
}

/** @returns {Logger} */
function createLogger() {
  return new Logger('CRAFT-Sec');
}

module.exports = { LOG_LEVELS, Logger, createLogger };
