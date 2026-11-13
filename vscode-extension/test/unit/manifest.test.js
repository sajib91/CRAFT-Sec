'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const { expectedCommandIds } = require('../../src/commands');

const extensionRoot = path.resolve(__dirname, '..', '..');
const manifestPath = path.join(extensionRoot, 'package.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

test('identity fields match the approved extension identity', () => {
  assert.equal(manifest.name, 'craft-sec');
  assert.equal(manifest.displayName, 'CRAFT-Sec Security Framework');
  assert.equal(typeof manifest.description, 'string');
  assert.ok(manifest.description.length > 0);
  assert.equal(manifest.publisher, 'your-publisher-id');
  assert.equal(manifest.version, '0.1.0');
});

test('manifest entry point exists and is JavaScript', () => {
  assert.equal(manifest.main, './src/extension.js');
  assert.ok(manifest.main.endsWith('.js'), 'main must be a JavaScript file');
  assert.ok(fs.existsSync(path.join(extensionRoot, manifest.main)));
});

test('manifest targets the selected VS Code API baseline', () => {
  assert.equal(manifest.engines.vscode, '^1.90.0');
  assert.deepEqual(manifest.categories, ['Linters', 'Machine Learning', 'Other']);
});

test('activation events cover startup, commands, and the sidebar view', () => {
  const events = manifest.activationEvents ?? [];
  assert.ok(events.includes('onStartupFinished'));
  assert.ok(events.includes(`onView:${VIEW_ID}`));
  for (const command of Object.values(COMMANDS)) {
    assert.ok(events.includes(`onCommand:${command}`));
  }
});

test('commands are registered with a category and match shared IDs', () => {
  const commands = manifest.contributes?.commands ?? [];
  assert.deepEqual(commands.map((entry) => entry.command).sort(), [...expectedCommandIds()].sort());
  for (const entry of commands) {
    assert.equal(entry.category, 'CRAFT-Sec');
    assert.equal(typeof entry.title, 'string');
  }
});

test('command definitions are unique and match manifest titles and activation events', () => {
  assert.equal(COMMAND_DEFINITIONS.length, 10, 'ten feature commands must be defined');

  const definitionIds = COMMAND_DEFINITIONS.map((definition) => definition.id);
  assert.equal(new Set(definitionIds).size, definitionIds.length, 'definition IDs must be unique');

  const contributions = new Map(
    (manifest.contributes?.commands ?? []).map((entry) => [entry.command, entry])
  );
  const activationEvents = manifest.activationEvents ?? [];

  for (const definition of COMMAND_DEFINITIONS) {
    const contribution = contributions.get(definition.id);
    assert.ok(contribution, `${definition.id} must be contributed`);
    assert.equal(contribution.title, definition.title);
    assert.equal(contribution.category, 'CRAFT-Sec');
    assert.ok(
      activationEvents.includes(`onCommand:${definition.id}`),
      `${definition.id} must activate the extension`
    );
    assert.equal(typeof definition.progressTitle, 'string');
    assert.ok(definition.progressTitle.length > 0);
  }
});

test('every feature command except the dashboard declares a service method', () => {
  for (const definition of COMMAND_DEFINITIONS) {
    if (definition.id === COMMANDS.openSecurityDashboard) {
      assert.equal(definition.serviceMethod, null);
    } else {
      assert.equal(
        typeof definition.serviceMethod,
        'string',
        `${definition.id} must map to a service method`
      );
    }
  }
});

test('activity bar container and sidebar webview are contributed', () => {
  const containers = manifest.contributes?.viewsContainers?.activitybar ?? [];
  const container = containers.find((entry) => entry.id === CONTAINER_ID);
  assert.ok(container, 'activity bar container must exist');
  assert.equal(container.icon, 'media/activitybar.svg');
  assert.ok(fs.existsSync(path.join(extensionRoot, container.icon)));

  const views = manifest.contributes?.views?.[CONTAINER_ID] ?? [];
  const sidebar = views.find((entry) => entry.id === VIEW_ID);
  assert.ok(sidebar, 'sidebar view must exist');
  assert.equal(sidebar.type, 'webview');
});

test('configuration settings are declared', () => {
  const properties = manifest.contributes?.configuration?.properties ?? {};
  for (const key of [
    'craftsec.backend.url',
    'craftsec.backend.requestTimeoutMs',
    'craftsec.backend.healthTimeoutMs',
    'craftsec.privacy.sendSourceText',
    'craftsec.backend.pythonPath',
    'craftsec.backend.autoStart',
    'craftsec.logging.level',
    'craftsec.ui.showStatusBarItem'
  ]) {
    assert.ok(properties[key], `${key} must be declared`);
  }
  assert.deepEqual(properties['craftsec.logging.level'].enum, [
    'trace',
    'debug',
    'info',
    'warn',
    'error',
    'off'
  ]);
  assert.equal(properties['craftsec.backend.url'].default, 'http://127.0.0.1:8765');
  assert.equal(properties['craftsec.backend.requestTimeoutMs'].default, 30000);
  assert.equal(properties['craftsec.backend.healthTimeoutMs'].default, 3000);
  assert.equal(properties['craftsec.privacy.sendSourceText'].default, true);
});

test('extension icon is a valid 128x128 PNG', () => {
  assert.equal(manifest.icon, 'media/icon.png');
  const iconPath = path.join(extensionRoot, manifest.icon);
  assert.ok(fs.existsSync(iconPath));
  const png = fs.readFileSync(iconPath);
  assert.equal(png.toString('ascii', 1, 4), 'PNG');
  assert.equal(png.readUInt32BE(16), 128);
  assert.equal(png.readUInt32BE(20), 128);
});

test('no TypeScript sources are present', () => {
  const stack = [extensionRoot];
  const ignored = new Set(['node_modules', '.git', '.vscode-test']);

  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (ignored.has(entry.name)) {
        continue;
      }
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else {
        assert.ok(
          !entry.name.endsWith('.ts') && !entry.name.endsWith('.tsx'),
          `TypeScript file found: ${fullPath}`
        );
      }
    }
  }
});
