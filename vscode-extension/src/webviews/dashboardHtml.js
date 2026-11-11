'use strict';

const { DASHBOARD_SECTIONS } = require('./dashboardModel');
const { buildContentSecurityPolicy } = require('./csp');
const { escapeAttribute, serializeStateForScript } = require('./html');

const NAV_ICONS = Object.freeze({
  overview:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
  scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/><path d="M8 10.5h5M10.5 8v5"/></svg>',
  vulnerabilities:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2.8 4.5 5.7v5.7c0 4.4 3.1 8.4 7.5 9.8 4.4-1.4 7.5-5.4 7.5-9.8V5.7L12 2.8Z"/><path d="M12 8v4.5"/><path d="M12 16h.01"/></svg>',
  features:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h10M18 18h2"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="18" r="2"/></svg>',
  interactions:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="m8.2 10.8 7.6-3.6M8.2 13.2l7.6 3.6"/></svg>',
  steering:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="m15.8 8.2-2.1 5.5-5.5 2.1 2.1-5.5 5.5-2.1Z"/></svg>',
  explanations:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 5.5h16v10H9l-5 4v-14Z"/><path d="M8 9h8M8 12h5"/></svg>',
  repair:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.5 6.5a4.5 4.5 0 0 0-5.8 5.8L3.5 17.5 6.5 20.5l5.2-5.2a4.5 4.5 0 0 0 5.8-5.8l-2.8 2.8-2.5-2.5 2.3-3.3Z"/></svg>',
  verification:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8 12 2.7 2.7L16 9"/></svg>',
  reports:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v5h4M9 12h6M9 16h6"/></svg>',
  settings:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4v-.2a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/></svg>'
});

/**
 * @param {string} sectionId
 * @returns {string}
 */
function navIcon(sectionId) {
  return NAV_ICONS[sectionId] ?? NAV_ICONS.overview;
}

/**
 * @returns {string}
 */
function buildNavigation() {
  return DASHBOARD_SECTIONS.map((section, index) => {
    const selected = index === 0;
    return `<li role="presentation">
              <button
                type="button"
                class="nav-item${selected ? ' is-active' : ''}"
                id="tab-${escapeAttribute(section.id)}"
                role="tab"
                aria-selected="${selected}"
                aria-controls="dashboard-content"
                tabindex="${selected ? '0' : '-1'}"
                data-section="${escapeAttribute(section.id)}"
              >
                <span class="nav-icon" aria-hidden="true">${navIcon(section.id)}</span>
                <span class="nav-label">${escapeAttribute(section.label)}</span>
                <span class="nav-count" data-nav-count="${escapeAttribute(section.id)}" hidden></span>
              </button>
            </li>`;
  }).join('\n');
}

/**
 * Build the dashboard webview document.
 *
 * The initial state is embedded as non-executable JSON. The external script
 * carries the per-render nonce required by the CSP; no inline executable code
 * is used.
 *
 * @param {{
 *   cspSource: string,
 *   styleUri: string,
 *   scriptUri: string,
 *   nonce: string,
 *   state: object
 * }} options
 * @returns {string}
 */
function createDashboardHtml({ cspSource, styleUri, scriptUri, nonce, state }) {
  const csp = escapeAttribute(buildContentSecurityPolicy({ cspSource, nonce }));
  const stylesheet = escapeAttribute(styleUri);
  const script = escapeAttribute(scriptUri);
  const scriptNonce = escapeAttribute(nonce);
  const stateJson = serializeStateForScript(state);

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Content-Security-Policy" content="${csp}" />
    <link rel="stylesheet" href="${stylesheet}" />
    <title>CRAFT-Sec Security Dashboard</title>
  </head>
  <body>
    <a class="skip-link" href="#dashboard-content">Skip to dashboard content</a>

    <div class="app-shell">
      <aside class="sidebar" aria-label="CRAFT-Sec navigation">
        <div class="brand">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2.6 4.6 5.5v5.8c0 4.4 3.1 8.4 7.4 9.9 4.3-1.5 7.4-5.5 7.4-9.9V5.5L12 2.6Z"/>
              <path d="m8.7 11.8 2.2 2.2 4.4-4.4"/>
            </svg>
          </span>
          <span class="brand-copy">
            <span class="brand-name">CRAFT-Sec</span>
            <span class="brand-subtitle">Security Framework</span>
          </span>
        </div>

        <nav class="nav" aria-label="Dashboard sections">
          <ul id="dashboard-tabs" role="tablist" aria-orientation="vertical">
${buildNavigation()}
          </ul>
        </nav>

        <div class="sidebar-footer">
          <div class="engine-pill" id="engine-pill">
            <span class="engine-dot" aria-hidden="true"></span>
            <span id="engine-pill-label">Engine unavailable</span>
          </div>
          <p class="sidebar-note">Local-first analysis. No cloud calls.</p>
        </div>
      </aside>

      <div class="workspace">
        <header class="topbar">
          <div class="topbar-heading">
            <p class="eyebrow">CRAFT-Sec Security Framework</p>
            <div class="title-row">
              <h1>Security Dashboard</h1>
              <span class="badge badge--neutral" id="data-mode-badge">No scan data</span>
            </div>
            <p class="topbar-subtitle">
              Explainable vulnerability analysis, feature inspection, repair, and verification.
            </p>
          </div>

          <div class="topbar-actions">
            <span class="last-updated">Updated <time id="last-updated">—</time></span>
            <button type="button" class="button button--secondary" id="refresh-button">
              Refresh
            </button>
            <button type="button" class="button button--secondary" id="demo-button">
              Load demo preview
            </button>
            <button type="button" class="button button--ghost" id="logs-button">
              Show logs
            </button>
          </div>
        </header>

        <div class="banner-slot" id="dashboard-banner" role="status" aria-live="polite"></div>

        <main
          class="content"
          id="dashboard-content"
          role="tabpanel"
          aria-labelledby="tab-overview"
          tabindex="0"
        >
          <div class="boot-state">Loading dashboard…</div>
        </main>

        <noscript>
          <p class="noscript-warning">
            CRAFT-Sec dashboard scripts are disabled. The dashboard cannot render without its
            nonce-authorized local script.
          </p>
        </noscript>
      </div>
    </div>

    <script type="application/json" id="dashboard-state" nonce="${scriptNonce}">${stateJson}</script>
    <script nonce="${scriptNonce}" src="${script}" defer></script>
  </body>
</html>
`;
}

module.exports = { createDashboardHtml, buildNavigation, NAV_ICONS };
