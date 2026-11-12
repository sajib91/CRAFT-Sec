'use strict';

const { COMMANDS } = require('../constants');
const { rangesIntersect } = require('./findingModel');

/**
 * Serializable finding context passed to the repair command. The engine request
 * still includes the saved editor context; this object identifies the exact
 * finding the user selected without inventing any repair content.
 *
 * @param {object} finding
 * @returns {object}
 */
function buildRepairArgument(finding) {
  return {
    findingId: finding.id,
    documentUri: finding.documentUri,
    range: {
      start: { line: finding.range.start.line, character: finding.range.start.character },
      end: { line: finding.range.end.line, character: finding.range.end.character }
    },
    ...(finding.cwe ? { cwe: finding.cwe } : {}),
    ...(finding.ruleId ? { ruleId: finding.ruleId } : {})
  };
}

/**
 * Offer a Quick Fix only for findings the backend explicitly marked as
 * repair-eligible. The action invokes the existing repair command with the
 * finding context; it never edits source code itself.
 */
class FindingCodeActionProvider {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   findings: {
   *     getFindingsForUri: (uri: string | import('vscode').Uri) => object[],
   *     getDiagnosticForFinding?: (finding: object) => import('vscode').Diagnostic | undefined
   *   }
   * }} dependencies
   */
  constructor({ vscode, findings }) {
    if (!vscode || typeof vscode.CodeAction !== 'function' || !vscode.CodeActionKind?.QuickFix) {
      throw new TypeError('FindingCodeActionProvider requires the VS Code CodeAction APIs.');
    }
    if (!findings || typeof findings.getFindingsForUri !== 'function') {
      throw new TypeError('FindingCodeActionProvider requires a finding store.');
    }
    this.vscode = vscode;
    this.findings = findings;
  }

  /**
   * @param {import('vscode').TextDocument} document
   * @param {import('vscode').Range} range
   * @returns {import('vscode').CodeAction[]}
   */
  provideCodeActions(document, range) {
    const uri = document?.uri?.toString?.();
    if (!uri || !range) {
      return [];
    }

    return this.findings
      .getFindingsForUri(uri)
      .filter((finding) => finding.repairEligible && rangesIntersect(finding.range, range))
      .map((finding) => this.createRepairAction(finding));
  }

  /**
   * @param {object} finding
   * @returns {import('vscode').CodeAction}
   */
  createRepairAction(finding) {
    const label = finding.cwe ?? finding.ruleId ?? finding.id;
    const title = `CRAFT-Sec: Repair ${label}`;
    const action = new this.vscode.CodeAction(title, this.vscode.CodeActionKind.QuickFix);
    action.command = {
      command: COMMANDS.repairVulnerability,
      title,
      arguments: [buildRepairArgument(finding)]
    };

    const diagnostic = this.findings.getDiagnosticForFinding?.(finding);
    if (diagnostic) {
      action.diagnostics = [diagnostic];
    }

    return action;
  }
}

module.exports = { FindingCodeActionProvider, buildRepairArgument };
