'use strict';

const { runEngineCommand } = require('./runEngineCommand');

/**
 * Bind one command definition to a service method.
 *
 * The service method is captured at registration time so a broken service
 * fails during activation instead of after the user starts a command.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 * @param {{ id: string, title: string, progressTitle: string, serviceMethod: string | null }} definition
 * @param {(...args: unknown[]) => object | Promise<object>} prepare
 * @param {{ onResult?: (result: unknown, request: object) => void | Promise<void> }} [options]
 * @returns {import('vscode').Disposable}
 */
function registerEngineCommand(context, definition, prepare, options = {}) {
  const { vscode, service, logger, registry } = context;
  const { serviceMethod } = definition;

  if (!serviceMethod) {
    throw new Error(`Command ${definition.id} does not declare a service method.`);
  }
  const method = service?.[serviceMethod];
  if (typeof method !== 'function') {
    throw new TypeError(
      `SecurityEngineService.${serviceMethod} is required by ${definition.id} but is not implemented.`
    );
  }

  return registry.register(definition.id, (...args) =>
    runEngineCommand(
      { vscode, logger },
      {
        definition,
        prepare: () => prepare(...args),
        invoke: (request, engineContext) => method.call(service, request, engineContext),
        onResult: options.onResult
      }
    )
  );
}

module.exports = { registerEngineCommand };
