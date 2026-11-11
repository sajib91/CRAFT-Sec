'use strict';

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
  createWorkspaceRequest,
  createVerificationRequest
};
