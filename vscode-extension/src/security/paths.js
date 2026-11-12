'use strict';

const path = require('node:path');

/**
 * Return true when `filePath` is the root itself or a descendant of `rootPath`.
 * The check is lexical; callers that need symlink realpath checks must add them.
 *
 * @param {unknown} filePath
 * @param {unknown} rootPath
 * @returns {boolean}
 */
function isPathWithinRoot(filePath, rootPath) {
  if (typeof filePath !== 'string' || typeof rootPath !== 'string') {
    return false;
  }
  if (filePath.length === 0 || rootPath.length === 0) {
    return false;
  }

  const resolvedRoot = path.resolve(rootPath);
  const resolvedFile = path.resolve(filePath);
  const relative = path.relative(resolvedRoot, resolvedFile);

  return (
    relative === '' ||
    (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

/**
 * Return true when a file URI is inside one of the supplied workspace folders.
 * Non-file URIs are never accepted.
 *
 * @param {{ scheme?: string, fsPath?: string } | undefined} uri
 * @param {ReadonlyArray<{ uri?: { scheme?: string, fsPath?: string } }>} folders
 * @returns {boolean}
 */
function isFileUriWithinFolders(uri, folders) {
  if (!uri || uri.scheme !== 'file' || typeof uri.fsPath !== 'string') {
    return false;
  }
  return folders.some(
    (folder) =>
      folder?.uri?.scheme === 'file' &&
      typeof folder.uri.fsPath === 'string' &&
      isPathWithinRoot(uri.fsPath, folder.uri.fsPath)
  );
}

module.exports = { isPathWithinRoot, isFileUriWithinFolders };
