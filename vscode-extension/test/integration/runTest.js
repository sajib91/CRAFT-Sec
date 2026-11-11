'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { runTests } = require('@vscode/test-electron');

const extensionDevelopmentPath = path.resolve(__dirname, '..', '..');
const extensionTestsPath = path.join(__dirname, 'index.js');

/**
 * Prefer a locally installed VS Code. When none is found, let
 * @vscode/test-electron download a stable build into .vscode-test/.
 *
 * @returns {string | undefined}
 */
function findLocalVSCode() {
  if (process.env.CRAFTSEC_VSCODE_EXECUTABLE) {
    return process.env.CRAFTSEC_VSCODE_EXECUTABLE;
  }

  const candidates = [];
  if (process.platform === 'darwin') {
    candidates.push(
      '/Applications/Visual Studio Code.app/Contents/MacOS/Code',
      '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
      path.join(
        process.env.HOME ?? '',
        'Applications',
        'Visual Studio Code.app',
        'Contents',
        'MacOS',
        'Code'
      ),
      path.join(
        process.env.HOME ?? '',
        'Applications',
        'Visual Studio Code.app',
        'Contents',
        'MacOS',
        'Electron'
      )
    );
  } else if (process.platform === 'win32') {
    if (process.env.LOCALAPPDATA) {
      candidates.push(
        path.join(process.env.LOCALAPPDATA, 'Programs', 'Microsoft VS Code', 'Code.exe')
      );
    }
    if (process.env.ProgramFiles) {
      candidates.push(path.join(process.env.ProgramFiles, 'Microsoft VS Code', 'Code.exe'));
    }
  }

  return candidates.find((candidate) => fs.existsSync(candidate));
}

async function main() {
  const vscodeExecutablePath = findLocalVSCode();
  console.log(
    vscodeExecutablePath
      ? `Using local VS Code: ${vscodeExecutablePath}`
      : 'No local VS Code found; @vscode/test-electron will download a stable build.'
  );

  const options = {
    extensionDevelopmentPath,
    extensionTestsPath,
    launchArgs: ['--disable-extensions']
  };
  if (vscodeExecutablePath) {
    options.vscodeExecutablePath = vscodeExecutablePath;
  }

  const exitCode = await runTests(options);
  if (exitCode !== 0) {
    process.exit(exitCode);
  }
}

main().catch((error) => {
  console.error('CRAFT-Sec Extension Host test failed:', error);
  process.exit(1);
});
