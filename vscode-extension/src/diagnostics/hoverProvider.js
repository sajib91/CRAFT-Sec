'use strict';

const {
  findingContainsPosition,
  comparePositions,
  severityLabel,
  cweUrl
} = require('./findingModel');

/**
 * Escape text that will be rendered as Markdown. The backend supplies all
 * explanation text; escaping keeps it from becoming active Markdown or HTML.
 *
 * @param {string} value
 * @returns {string}
 */
function escapeMarkdown(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/([`*_{}\[\]()#+\-.!|<>])/g, '\\$1');
}

/**
 * @param {string} value
 * @returns {string}
 */
function inlineCode(value) {
  const text = String(value).replace(/\r?\n/g, ' ');
  const runs = text.match(/`+/g) ?? [];
  const longest = runs.reduce((max, run) => Math.max(max, run.length), 0);
  const fence = '`'.repeat(longest + 1);
  return `${fence}${text}${fence}`;
}

/**
 * @param {string} value
 * @returns {string}
 */
function fencedCode(value) {
  const runs = String(value).match(/`+/g) ?? [];
  const longest = runs.reduce((max, run) => Math.max(max, run.length), 0);
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}text\n${value}\n${fence}`;
}

/**
 * @param {object} finding
 * @returns {string}
 */
function buildFindingSection(finding) {
  const lines = [`**CRAFT-Sec: ${escapeMarkdown(finding.message)}**`, ''];

  const metadata = [`**Severity:** ${severityLabel(finding.severity)}`];
  if (finding.cwe) {
    metadata.push(`**CWE:** [${finding.cwe}](${cweUrl(finding.cwe)})`);
  }
  if (finding.ruleId) {
    metadata.push(`**Rule:** ${inlineCode(finding.ruleId)}`);
  }
  lines.push(metadata.join(' · '), '');

  lines.push('**Explanation**', '');
  lines.push(
    finding.explanation
      ? escapeMarkdown(finding.explanation)
      : '_No explanation was provided by the backend._',
    ''
  );

  if (finding.evidence) {
    lines.push('**Evidence**', '', fencedCode(finding.evidence), '');
  }

  lines.push('**Sources**', '');
  if (finding.sourceReferences.length > 0) {
    for (const reference of finding.sourceReferences) {
      const label = escapeMarkdown(reference.label);
      if (reference.url) {
        lines.push(`- ${label} — <${reference.url}>`);
      } else if (reference.uri) {
        lines.push(`- ${label} — ${inlineCode(reference.uri)}`);
      } else {
        lines.push(`- ${label}`);
      }
    }
  } else {
    lines.push('_No source references were provided by the backend._');
  }
  lines.push('');

  if (finding.repairEligible) {
    const description = finding.repair?.description
      ? ` ${escapeMarkdown(finding.repair.description)}`
      : '';
    lines.push(`**Repair:** Available from the CRAFT-Sec Quick Fix menu.${description}`);
  } else if (finding.repair) {
    const description = finding.repair.description
      ? ` ${escapeMarkdown(finding.repair.description)}`
      : '';
    lines.push(`**Repair:** Not eligible for automated repair.${description}`);
  } else {
    lines.push('**Repair:** The backend did not provide repair metadata.');
  }

  return lines.join('\n').trimEnd();
}

/**
 * @param {object[]} findings
 * @returns {string}
 */
function buildHoverMarkdown(findings) {
  return findings.map(buildFindingSection).join('\n\n---\n\n');
}

/**
 * @param {object[]} findings
 * @returns {{ start: { line: number, character: number }, end: { line: number, character: number } }}
 */
function unionRange(findings) {
  let start = findings[0].range.start;
  let end = findings[0].range.end;
  for (const finding of findings.slice(1)) {
    if (comparePositions(finding.range.start, start) < 0) {
      start = finding.range.start;
    }
    if (comparePositions(finding.range.end, end) > 0) {
      end = finding.range.end;
    }
  }
  return { start, end };
}

/**
 * Hover provider for backend findings. It reads only the controller's finding
 * store; it never computes a vulnerability or explanation locally.
 */
class FindingHoverProvider {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   findings: { getFindingsForUri: (uri: string | import('vscode').Uri) => object[] }
   * }} dependencies
   */
  constructor({ vscode, findings }) {
    if (
      !vscode ||
      typeof vscode.MarkdownString !== 'function' ||
      typeof vscode.Hover !== 'function'
    ) {
      throw new TypeError('FindingHoverProvider requires the VS Code hover APIs.');
    }
    if (!findings || typeof findings.getFindingsForUri !== 'function') {
      throw new TypeError('FindingHoverProvider requires a finding store.');
    }
    this.vscode = vscode;
    this.findings = findings;
  }

  /**
   * @param {import('vscode').TextDocument} document
   * @param {import('vscode').Position} position
   * @returns {import('vscode').Hover | undefined}
   */
  provideHover(document, position) {
    const uri = document?.uri?.toString?.();
    if (!uri || !position) {
      return undefined;
    }

    const matching = this.findings
      .getFindingsForUri(uri)
      .filter((finding) => findingContainsPosition(finding, position));
    if (matching.length === 0) {
      return undefined;
    }

    const markdown = new this.vscode.MarkdownString(buildHoverMarkdown(matching));
    markdown.isTrusted = false;
    const range = unionRange(matching);
    return new this.vscode.Hover(
      markdown,
      new this.vscode.Range(
        range.start.line,
        range.start.character,
        range.end.line,
        range.end.character
      )
    );
  }
}

module.exports = {
  FindingHoverProvider,
  buildHoverMarkdown,
  buildFindingSection,
  escapeMarkdown,
  inlineCode,
  unionRange
};
