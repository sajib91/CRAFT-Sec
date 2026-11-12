'use strict';

const {
  FindingValidationError,
  normalizeFileUri,
  normalizeRange,
  normalizeCwe
} = require('../diagnostics/findingModel');

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
  const folders = vscode.workspace.workspaceFolders ?? [];
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
 * Build the request shared by editor-scoped commands. The request contains
 * locations and selection metadata; it does not invent analysis results.
 *
 * @param {import('vscode')} vscode
 * @param {import('vscode').TextEditor} editor
 */
function createEditorRequest(vscode, editor) {
  const folder = findWorkspaceFolder(vscode, editor.document.uri);
  const hasSelection = Boolean(editor.selection) && !editor.selection.isEmpty;
  const selection = hasSelection ? serializeSelection(editor.selection) : undefined;

  return {
    workspaceFolder: folder.uri.fsPath,
    workspaceFolderName: folder.name,
    filePath: editor.document.uri.fsPath,
    documentUri: editor.document.uri.toString(),
    languageId: editor.document.languageId,
    documentVersion: editor.document.version,
    selection,
    selectedText: hasSelection ? editor.document.getText(editor.selection) : undefined
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
 * @param {import('vscode')} vscode
 */
function createWorkspaceRequest(vscode) {
  const folders = requireWorkspace(vscode);
  return {
    workspaceFolders: folders.map((folder) => ({
      name: folder.name,
      path: folder.uri.fsPath,
      uri: folder.uri.toString()
    }))
  };
}

/**
 * Verification works at workspace scope and includes the active file when it
 * belongs to an open folder. No editor is required.
 *
 * @param {import('vscode')} vscode
 */
function createVerificationRequest(vscode) {
  const request = createWorkspaceRequest(vscode);
  const editor = vscode.window.activeTextEditor;
  if (!editor || !editor.document || editor.document.uri.scheme !== 'file') {
    return request;
  }

  const folder =
    typeof vscode.workspace.getWorkspaceFolder === 'function'
      ? vscode.workspace.getWorkspaceFolder(editor.document.uri)
      : undefined;
  if (!folder) {
    return request;
  }

  return {
    ...request,
    workspaceFolder: folder.uri.fsPath,
    workspaceFolderName: folder.name,
    filePath: editor.document.uri.fsPath,
    documentUri: editor.document.uri.toString(),
    languageId: editor.document.languageId,
    documentVersion: editor.document.version
  };
}

module.exports = {
  CommandValidationError,
  requireWorkspace,
  findWorkspaceFolder,
  requireActiveEditor,
  requireSelection,
  serializeSelection,
  createEditorRequest,
  normalizeRepairFindingArgument,
  createRepairRequest,
  createWorkspaceRequest,
  createVerificationRequest
};
