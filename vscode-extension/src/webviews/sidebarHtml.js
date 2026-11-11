'use strict';

const { buildContentSecurityPolicy } = require('./csp');
const { escapeAttribute } = require('./html');

/**
 * Build the sidebar webview. The sidebar is a small launcher for the full
 * editor-area dashboard. Its only script posts a single allowlisted message.
 *
 * @param {{
 *   cspSource: string,
 *   styleUri: string,
 *   scriptUri: string,
 *   nonce: string
 * }} options
 * @returns {string}
 */
function createSidebarHtml({ cspSource, styleUri, scriptUri, nonce }) {
  const csp = escapeAttribute(buildContentSecurityPolicy({ cspSource, nonce }));
  const stylesheet = escapeAttribute(styleUri);
  const script = escapeAttribute(scriptUri);
  const scriptNonce = escapeAttribute(nonce);

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Content-Security-Policy" content="${csp}" />
    <link rel="stylesheet" href="${stylesheet}" />
    <title>CRAFT-Sec</title>
  </head>
  <body>
    <main>
      <header class="hero">
        <div class="brand-row">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2.6 4.6 5.5v5.8c0 4.4 3.1 8.4 7.4 9.9 4.3-1.5 7.4-5.5 7.4-9.9V5.5L12 2.6Z" />
              <path d="m8.7 11.8 2.2 2.2 4.4-4.4" />
            </svg>
          </span>
          <span class="badge">VS Code</span>
        </div>
        <h1>CRAFT-Sec</h1>
        <p class="subtitle">Security Framework</p>
        <p class="hero-copy">
          Explainable vulnerability analysis, SAE feature inspection, counterfactual analysis,
          repair proposals, and verification.
        </p>
        <button type="button" class="primary-button" id="open-dashboard">
          Open Security Dashboard
        </button>
      </header>

      <section class="card" aria-labelledby="engine-heading">
        <h2 id="engine-heading">Engine status</h2>
        <p class="status">
          <span class="status-dot" aria-hidden="true"></span>
          <span>Not connected</span>
        </p>
        <p>
          The local security engine is not implemented in this build. The dashboard reports
          unavailable capabilities explicitly and does not simulate results.
        </p>
      </section>

      <section class="card" aria-labelledby="dashboard-heading">
        <h2 id="dashboard-heading">Dashboard sections</h2>
        <ul class="section-list">
          <li>Overview and severity totals</li>
          <li>Security scan history</li>
          <li>Vulnerabilities and CWE distribution</li>
          <li>SAE features and interactions</li>
          <li>Steering, explanations, and repair</li>
          <li>Verification and research reports</li>
        </ul>
        <p class="local-note">Opens in the editor area. All analysis stays local.</p>
      </section>

      <p class="notice">
        No analysis results are produced in this build. Heuristic scores are not probabilities,
        and counterfactual effects are not real-world causal claims.
      </p>

      <noscript>
        <p class="noscript-warning">
          The sidebar launcher requires its nonce-authorized local script. Open the dashboard from
          the Command Palette with “CRAFT-Sec: Open Security Dashboard”.
        </p>
      </noscript>
    </main>

    <script nonce="${scriptNonce}" src="${script}" defer></script>
  </body>
</html>
`;
}

module.exports = { createSidebarHtml, escapeAttribute };
