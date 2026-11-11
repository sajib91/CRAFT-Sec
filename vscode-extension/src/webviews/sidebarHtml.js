'use strict';

/**
 * Escape a value inserted into an HTML attribute.
 *
 * @param {string} value
 * @returns {string}
 */
function escapeAttribute(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

/**
 * Build the static sidebar webview. The view uses a strict CSP and no scripts,
 * so it can only render local styles and static scaffold status.
 *
 * @param {{ cspSource: string, styleUri: string }} options
 * @returns {string}
 */
function createSidebarHtml({ cspSource, styleUri }) {
  const csp = escapeAttribute(`default-src 'none'; style-src ${cspSource}; img-src ${cspSource};`);
  const stylesheet = escapeAttribute(styleUri);

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
        <span class="badge">Scaffold</span>
        <h1>CRAFT-Sec</h1>
        <p class="subtitle">Security Framework</p>
      </header>

      <section class="card" aria-labelledby="engine-heading">
        <h2 id="engine-heading">Engine status</h2>
        <p class="status"><span class="status-dot" aria-hidden="true"></span>Not connected</p>
        <p>
          The local Python security engine is not implemented yet. This view will host
          findings, jobs, evidence, and review actions once the engine is available.
        </p>
      </section>

      <section class="card" aria-labelledby="capabilities-heading">
        <h2 id="capabilities-heading">Planned capabilities</h2>
        <ul>
          <li>Static analysis evidence</li>
          <li>SAE feature inspection</li>
          <li>Counterfactual analysis</li>
          <li>Interaction-aware steering</li>
          <li>Repository-aware repair</li>
          <li>Independent verification</li>
        </ul>
      </section>

      <p class="notice">
        No analysis results are produced in this build. Heuristic scores are not
        probabilities, and counterfactual effects are not real-world causal claims.
      </p>
    </main>
  </body>
</html>
`;
}

module.exports = { createSidebarHtml, escapeAttribute };
