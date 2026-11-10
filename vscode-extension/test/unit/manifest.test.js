'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const extensionRoot = path.resolve(__dirname, '..', '..');
const manifestPath = path.join(extensionRoot, 'package.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

test('manifest entry point exists and is JavaScript', () => {
  assert.equal(typeof manifest.main, 'string');
  assert.ok(manifest.main.endsWith('.js'), 'main must be a JavaScript file');
  assert.ok(fs.existsSync(path.join(extensionRoot, manifest.main)));
});

test('extension contributes the scaffold status command', () => {
  const commands = manifest.contributes?.commands ?? [];
  assert.ok(commands.some((entry) => entry.command === 'craftsec.showStatus'));
});

test('no TypeScript sources are present', () => {
  const stack = [extensionRoot];
  const ignored = new Set(['node_modules', '.git']);

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
