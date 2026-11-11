'use strict';

/**
 * Composite command registry. A single disposable owns every command
 * registration so activation and deactivation cannot leak handlers.
 */
class CommandRegistry {
  /**
   * @param {import('vscode')} vscode
   * @param {import('../logging/output').Logger} logger
   */
  constructor(vscode, logger) {
    this.vscode = vscode;
    this.logger = logger;
    /** @type {Map<string, import('vscode').Disposable>} */
    this.registrations = new Map();
    this.disposed = false;
  }

  /**
   * @param {string} commandId
   * @param {(...args: unknown[]) => unknown} handler
   * @returns {import('vscode').Disposable}
   */
  register(commandId, handler) {
    if (this.disposed) {
      throw new Error(`Cannot register command after disposal: ${commandId}`);
    }
    if (typeof handler !== 'function') {
      throw new TypeError(`Command handler must be a function: ${commandId}`);
    }
    if (this.registrations.has(commandId)) {
      throw new Error(`Command is already registered: ${commandId}`);
    }

    const disposable = this.vscode.commands.registerCommand(commandId, handler);
    this.registrations.set(commandId, disposable);
    return disposable;
  }

  /** @param {string} commandId */
  has(commandId) {
    return this.registrations.has(commandId);
  }

  /** @returns {string[]} */
  ids() {
    return [...this.registrations.keys()];
  }

  get size() {
    return this.registrations.size;
  }

  dispose() {
    if (this.disposed) {
      return;
    }
    this.disposed = true;

    const registrations = [...this.registrations.values()].reverse();
    this.registrations.clear();
    for (const disposable of registrations) {
      try {
        disposable.dispose();
      } catch (error) {
        this.logger?.error?.('Failed to dispose a CRAFT-Sec command registration.', error);
      }
    }
  }
}

module.exports = { CommandRegistry };
