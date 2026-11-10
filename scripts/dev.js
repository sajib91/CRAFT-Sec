'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const script = path.join(__dirname, 'dev.py');
const minVersion = [3, 11];
const maxVersionExclusive = [3, 15];

function pythonVersion(command, prefix) {
  const result = spawnSync(
    command,
    [...prefix, '-c', "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
    { encoding: 'utf8' }
  );
  if (result.status !== 0 || !result.stdout) {
    return null;
  }
  return result.stdout.trim().split('.').map((part) => Number.parseInt(part, 10));
}

function isSupported(version) {
  if (!version || version.length !== 2 || version.some(Number.isNaN)) {
    return false;
  }
  const [major, minor] = version;
  const afterMin = major > minVersion[0] || (major === minVersion[0] && minor >= minVersion[1]);
  const beforeMax =
    major < maxVersionExclusive[0] ||
    (major === maxVersionExclusive[0] && minor < maxVersionExclusive[1]);
  return afterMin && beforeMax;
}

const candidates = [];
if (process.env.CRAFTSEC_PYTHON) {
  candidates.push({ command: process.env.CRAFTSEC_PYTHON, prefix: [] });
}
if (process.platform === 'win32') {
  candidates.push({ command: 'py', prefix: ['-3'] });
}
candidates.push(
  { command: 'python3.12', prefix: [] },
  { command: 'python3.11', prefix: [] },
  { command: 'python3', prefix: [] },
  { command: 'python', prefix: [] }
);

const selected = candidates.find(({ command, prefix }) =>
  isSupported(pythonVersion(command, prefix))
);

if (!selected) {
  console.error(
    'Error: Python 3.11–3.14 is required. Install one from https://www.python.org/downloads/ ' +
      'or set CRAFTSEC_PYTHON to its executable.'
  );
  process.exit(1);
}

const result = spawnSync(
  selected.command,
  [...selected.prefix, script, ...process.argv.slice(2)],
  { stdio: 'inherit' }
);

if (result.error) {
  console.error(`Error: failed to start Python: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
