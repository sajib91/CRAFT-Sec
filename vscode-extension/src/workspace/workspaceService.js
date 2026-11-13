'use strict';

/**
 * Safe construction of workspace and editor requests for the CRAFT-Sec API.
 *
 * Source text is included only when the user-invoked command's configuration
 * permits it. Workspace scans send folder metadata only, never file contents.
 */

const path = require('node:path');

const {
  FindingValidationError,
  normalizeFileUri,
  normalizeRange,
  normalizeCwe
} = require('../diagnostics/findingModel');
const { SECTION } = require('../api/configurationService');

const MAX_WORKSPACE_FOLDERS = 50;

class CommandValidationError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   */
  constructor(message, code) {
    super(message);
    this.name = 'CommandValidationError';
    this.code = code;
  }
}

/**
 * @param {import('vscode')} vscode
 * @returns {readonly import('vscode').WorkspaceFolder[]}
 */
function requireWorkspace(vscode) {
  const folders = vscode.workspace?.workspaceFolders ?? [];
  if (folders.length === 0) {
    throw new CommandValidationError(
      'Open a folder or workspace before running this command.',
      'E_NO_WORKSPACE'
    );
  }
  return folders;
}

/**
 * @param {import('vscode')} vscode
 * @param {import('vscode').Uri} uri
 * @returns {import('vscode').WorkspaceFolder}
 */
function findWorkspaceFolder(vscode, uri) {
  requireWorkspace(vscode);
  const folder =
    typeof vscode.workspace.getWorkspaceFolder === 'function'
      ? vscode.workspace.getWorkspaceFolder(uri)
      : undefined;
  if (!folder) {
    throw new CommandValidationError(
      'The active file is not inside an open workspace folder.',
      'E_FILE_OUTSIDE_WORKSPACE'
    );
  }
  return folder;
}

/**
 * @param {import('vscode')} vscode
 * @returns {import('vscode').TextEditor}
 */
function requireActiveEditor(vscode) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    throw new CommandValidationError(
      'Open a text editor before running this command.',
      'E_NO_EDITOR'
    );
  }
  if (!editor.document || editor.document.uri.scheme !== 'file') {
    throw new CommandValidationError(
      'Save the active file to disk before running this command.',
      'E_UNSAVED_FILE'
    );
  }
  return editor;
}

/**
 * @param {import('vscode').TextEditor} editor
 * @returns {import('vscode').Selection}
 */
function requireSelection(editor) {
  if (!editor.selection || editor.selection.isEmpty) {
    throw new CommandValidationError(
      'Select code in the active editor before running this command.',
      'E_NO_SELECTION'
    );
  }
  return editor.selection;
}

/**
 * @param {import('vscode').Selection} selection
 */
function serializeSelection(selection) {
  return {
    start: { line: selection.start.line, character: selection.start.character },
    end: { line: selection.end.line, character: selection.end.character }
  };
}

/**
 * Read the explicit source-sharing setting. If the fake or host does not
 * expose configuration, the manifest default (enabled) applies.
 *
 * @param {import('vscode')} vscode
 * @returns {boolean}
 */
function readSendSourceText(vscode) {
  try {
    const configuration = vscode.workspace?.getConfiguration?.(SECTION);
    if (!configuration || typeof configuration.get !== 'function') {
      return true;
    }
    return configuration.get('privacy.sendSourceText', true) !== false;
  } catch {
    return false;
  }
}

/**
 * Build the request shared by editor-scoped commands. Source text and selected
 * text are included only with explicit source-sharing consent; selecting code
 * and invoking a scan command is itself user-triggered.
 *
 * @param {import('vscode')} vscode
 * @param {import('vscode').TextEditor} editor
 * @param {{ includeSourceText?: boolean }} [options]
 * @returns {object}
 */
function createEditorRequest(vscode, editor, options = {}) {
  const folder = findWorkspaceFolder(vscode, editor.document.uri);
  const hasSelection = Boolean(editor.selection) && !editor.selection.isEmpty;
  const selection = hasSelection ? serializeSelection(editor.selection) : undefined;
  const includeSourceText = options.includeSourceText ?? readSendSourceText(vscode);
  const sourceText = includeSourceText ? editor.document.getText() : undefined;
  const selectedText =
    includeSourceText && hasSelection ? editor.document.getText(editor.selection) : undefined;

  return {
    workspaceFolder: folder.uri.fsPath,
    workspaceFolderName: folder.name,
    filePath: editor.document.uri.fsPath,
    documentUri: editor.document.uri.toString(),
    languageId: editor.document.languageId,
    documentVersion: editor.document.version,
    ...(selection === undefined ? {} : { selection }),
    ...(selectedText === undefined ? {} : { selectedText }),
    ...(sourceText === undefined ? {} : { sourceText })
  };
}

/**
 * Validate the finding context attached to a repair Quick Fix. Absence of a
 * finding context is valid because the command is also callable from the
 * Command Palette and dashboard.
 *
 * @param {unknown} value
 * @returns {{
 *   findingId: string,
 *   documentUri: string,
 *   range: ReturnType<typeof normalizeRange>,
 *   cwe?: string,
 *   ruleId?: string
 * } | undefined}
 */
function normalizeRepairFindingArgument(value) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new CommandValidationError(
      'Invalid repair finding context: expected an object.',
      'E_INVALID_FINDING_CONTEXT'
    );
  }

  try {
    if (typeof value.findingId !== 'string' || value.findingId.trim().length === 0) {
      throw new FindingValidationError('findingId must be a non-empty string.');
    }

    const finding = {
      findingId: value.findingId.trim(),
      documentUri: normalizeFileUri(value.documentUri, 'documentUri'),
      range: normalizeRange(value.range, 'range')
    };
    if (value.cwe !== undefined && value.cwe !== null) {
      finding.cwe = normalizeCwe(value.cwe);
    }
    if (value.ruleId !== undefined && value.ruleId !== null) {
      if (typeof value.ruleId !== 'string' || value.ruleId.trim().length === 0) {
        throw new FindingValidationError('ruleId must be a non-empty string.');
      }
      finding.ruleId = value.ruleId.trim();
    }
    return finding;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CommandValidationError(
      `Invalid repair finding context: ${message}`,
      'E_INVALID_FINDING_CONTEXT'
    );
  }
}

/**
 * Build a repair request for either the active editor or a specific finding
 * supplied by a Quick Fix. The finding must belong to the active document so
 * a repair request cannot silently target a different file.
 *
 * @param {import('vscode')} vscode
 * @param {unknown} [findingArgument]
 * @returns {object}
 */
function createRepairRequest(vscode, findingArgument) {
  const request = createEditorRequest(vscode, requireActiveEditor(vscode));
  const finding = normalizeRepairFindingArgument(findingArgument);
  if (!finding) {
    return request;
  }
  if (finding.documentUri !== request.documentUri) {
    throw new CommandValidationError(
      'Open the file that contains this finding before requesting a repair.',
      'E_FINDING_DOCUMENT_MISMATCH'
    );
  }
  return { ...request, finding };
}

/**
 * Build safe workspace metadata. Only local file folders are accepted, and no
 * document content or file list is sent. Duplicate paths are collapsed.
 *
 * @param {import('vscode')} vscode
 * @returns {{ workspaceFolders: Array<{ name: string, path: string, uri: string }> }}
 */
function createWorkspaceRequest(vscode) {
  const folders = requireWorkspace(vscode);
  const seen = new Set();
  /** @type {Array<{ name: string, path: string, uri: string }>} */
  const workspaceFolders = [];

  for (const folder of folders) {
    if (!folder?.uri || folder.uri.scheme !== 'file') {
      throw new CommandValidationError(
        'Workspace scans require local file-system folders.',
        'E_UNSUPPORTED_WORKSPACE'
      );
    }
    const fsPath = folder.uri.fsPath;
    if (typeof fsPath !== 'string' || fsPath.length === 0 || !path.isAbsolute(fsPath)) {
      throw new CommandValidationError(
        'A workspace folder does not have a valid absolute path.',
        'E_INVALID_WORKSPACE_PATH'
      );
    }
    if (seen.has(fsPath)) {
      continue;
    }
    seen.add(fsPath);
    workspaceFolders.push({
      name:
        typeof folder.name === 'string' && folder.name.length > 0
          ? folder.name
          : path.basename(fsPath),
      path: fsPath,
      uri: folder.uri.toString()
    });
  }

  if (workspaceFolders.length === 0) {
    throw new CommandValidationError(
      'Open at least one local workspace folder before running this command.',
      'E_NO_WORKSPACE'
    );
  }
  if (workspaceFolders.length > MAX_WORKSPACE_FOLDERS) {
    throw new CommandValidationError(
      `The backend accepts at most ${MAX_WORKSPACE_FOLDERS} workspace folders.`,
      'E_TOO_MANY_WORKSPACE_FOLDERS'
    );
  }

  return { workspaceFolders };
}

/**
 * Verification endpoints require a file context. Use the active saved editor;
 * a workspace-only request cannot satisfy the backend contract.
 *
 * @param {import('vscode')} vscode
 * @returns {object}
 */
function createVerificationRequest(vscode) {
  return createEditorRequest(vscode, requireActiveEditor(vscode));
}

module.exports = {
  MAX_WORKSPACE_FOLDERS,
  CommandValidationError,
  requireWorkspace,
  findWorkspaceFolder,
  requireActiveEditor,
  requireSelection,
  serializeSelection,
  readSendSourceText,
  createEditorRequest,
  normalizeRepairFindingArgument,
  createRepairRequest,
  createWorkspaceRequest,
  createVerificationRequest
};
