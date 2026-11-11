'use strict';

/**
 * Sidebar launcher script.
 *
 * The sidebar can only request that the extension open the full dashboard.
 * It cannot execute commands, read analysis data, or write source files.
 */
(function sidebar() {
  const vscode = acquireVsCodeApi();
  const openButton = document.getElementById('open-dashboard');

  if (!openButton) {
    return;
  }

  openButton.addEventListener('click', () => {
    vscode.postMessage({ type: 'openDashboard' });
  });
})();
