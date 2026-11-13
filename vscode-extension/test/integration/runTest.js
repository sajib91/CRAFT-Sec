'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { runTests } = require('@vscode/test-electron');

const extensionDevelopmentPath = path.resolve(__dirname, '..', '..');
const extensionTestsPath = path.join(__dirname, 'index.js');
const repositoryRoot = path.resolve(extensionDevelopmentPath, '..');
const engineRoot = path.join(repositoryRoot, 'security-engine');

const DISK_SOURCE = 'def add(a, b):\n    return a + b\n';

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

/**
 * @returns {string}
 */
function resolvePython() {
  if (process.env.CRAFTSEC_PYTHON) {
    return process.env.CRAFTSEC_PYTHON;
  }
  const candidate =
    process.platform === 'win32'
      ? path.join(repositoryRoot, '.venv', 'Scripts', 'python.exe')
      : path.join(repositoryRoot, '.venv', 'bin', 'python');
  if (fs.existsSync(candidate)) {
    return candidate;
  }
  return process.platform === 'win32' ? 'python' : 'python3';
}

/**
 * @returns {Promise<number>}
 */
function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : undefined;
      server.close((error) => {
        if (error) {
          reject(error);
        } else if (!port) {
          reject(new Error('Could not allocate a loopback port for the backend.'));
        } else {
          resolve(port);
        }
      });
    });
  });
}

/** @param {number} ms */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * @param {import('node:child_process').ChildProcess} child
 * @param {number} timeoutMs
 * @returns {Promise<boolean>}
 */
function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) {
      resolve(true);
      return;
    }
    const timer = setTimeout(() => resolve(false), timeoutMs);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

/**
 * @param {import('node:child_process').ChildProcess} child
 */
async function stopBackend(child) {
  if (!child || child.exitCode !== null) {
    return;
  }
  child.kill('SIGTERM');
  if (!(await waitForExit(child, 5_000))) {
    child.kill('SIGKILL');
    await waitForExit(child, 2_000);
  }
}

/**
 * @param {string} backendUrl
 * @param {import('node:child_process').ChildProcess} child
 * @param {() => string} readLogs
 * @param {number} [timeoutMs]
 */
async function waitForBackend(backendUrl, child, readLogs, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;

  while (Date.now() < deadline) {
    if (!child.pid) {
      throw new Error(`The CRAFT-Sec backend process could not be started.\n${readLogs()}`);
    }
    if (child.exitCode !== null) {
      throw new Error(
        `The CRAFT-Sec backend exited with code ${child.exitCode} before becoming ready.\n` +
          readLogs()
      );
    }
    try {
      const response = await fetch(`${backendUrl}/api/v1/health`, {
        signal: AbortSignal.timeout(1_000)
      });
      if (response.ok) {
        const body = await response.json();
        if (body.status === 'ok') {
          return body;
        }
      }
    } catch (error) {
      lastError = error;
    }
    await delay(150);
  }

  throw new Error(
    `The CRAFT-Sec backend did not become ready at ${backendUrl} within ${timeoutMs} ms. ` +
      `Last error: ${lastError instanceof Error ? lastError.message : String(lastError)}\n` +
      readLogs()
  );
}

async function main() {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'craftsec-e2e-'));
  const workspacePath = path.join(temporaryRoot, 'workspace');
  const userDataDir = path.join(temporaryRoot, 'user-data');
  const extensionsDir = path.join(temporaryRoot, 'extensions');
  const dataDir = path.join(temporaryRoot, 'data');
  const logDir = path.join(temporaryRoot, 'logs');
  for (const directory of [workspacePath, userDataDir, extensionsDir, dataDir, logDir]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  const sourcePath = path.join(workspacePath, 'app.py');
  fs.writeFileSync(sourcePath, DISK_SOURCE, 'utf8');

  /** @type {import('node:child_process').ChildProcess | undefined} */
  let backend;
  const logLines = [];
  const record = (chunk) => {
    for (const line of chunk.toString().split(/\r?\n/)) {
      if (line.length > 0) {
        logLines.push(line);
      }
    }
    while (logLines.length > 200) {
      logLines.shift();
    }
  };
  const readLogs = () =>
    logLines.length > 0 ? `Backend output:\n${logLines.join('\n')}` : 'No backend output captured.';

  try {
    const port = await findFreePort();
    const backendUrl = `http://127.0.0.1:${port}`;
    const python = resolvePython();
    const backendEnvironment = { ...process.env };
    delete backendEnvironment.CRAFTSEC_API_TOKEN;
    delete backendEnvironment.CRAFTSEC_ENGINE_TOKEN;
    backendEnvironment.CRAFTSEC_WORKSPACE_ROOTS = workspacePath;
    backendEnvironment.CRAFTSEC_LOG_LEVEL = 'ERROR';
    backendEnvironment.CRAFTSEC_DATA_DIR = dataDir;
    backendEnvironment.CRAFTSEC_LOG_DIR = logDir;

    console.log(`Starting CRAFT-Sec backend with ${python} on ${backendUrl}.`);
    backend = spawn(python, ['-m', 'craftsec', '--host', '127.0.0.1', '--port', String(port)], {
      cwd: engineRoot,
      env: backendEnvironment,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    backend.stdout?.on('data', record);
    backend.stderr?.on('data', record);
    backend.once('error', (error) => record(`spawn error: ${error.message}`));

    const health = await waitForBackend(backendUrl, backend, readLogs);
    console.log(`CRAFT-Sec backend ready (version ${health.version}, API ${health.apiVersion}).`);

    const vscodeExecutablePath = findLocalVSCode();
    console.log(
      vscodeExecutablePath
        ? `Using local VS Code: ${vscodeExecutablePath}`
        : 'No local VS Code found; @vscode/test-electron will download a stable build.'
    );

    const options = {
      extensionDevelopmentPath,
      extensionTestsPath,
      launchArgs: [
        workspacePath,
        '--disable-extensions',
        `--user-data-dir=${userDataDir}`,
        `--extensions-dir=${extensionsDir}`,
        '--new-window'
      ],
      extensionTestsEnv: {
        CRAFTSEC_E2E_BACKEND_URL: backendUrl,
        CRAFTSEC_E2E_WORKSPACE: workspacePath,
        CRAFTSEC_E2E_FILE: sourcePath,
        CRAFTSEC_E2E_DISK_SHA256: crypto
          .createHash('sha256')
          .update(Buffer.from(DISK_SOURCE, 'utf8'))
          .digest('hex'),
        // Never inherit a developer token in either direction.
        CRAFTSEC_API_TOKEN: '',
        CRAFTSEC_ENGINE_TOKEN: ''
      }
    };
    if (vscodeExecutablePath) {
      options.vscodeExecutablePath = vscodeExecutablePath;
    }

    const exitCode = await runTests(options);
    if (exitCode !== 0) {
      process.exitCode = exitCode;
    }
  } finally {
    await stopBackend(backend);
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error('CRAFT-Sec Extension Host test failed:', error);
  process.exitCode = 1;
});
