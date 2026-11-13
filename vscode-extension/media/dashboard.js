'use strict';

/**
 * CRAFT-Sec dashboard renderer.
 *
 * This file is loaded inside the dashboard webview. It renders the state sent
 * by the extension host and never invents analysis data, probabilities, SAE
 * activations, or causal effects. All dynamic text is written with textContent
 * or DOM properties; dynamic innerHTML is not used.
 */
(function dashboard() {
  const vscode = acquireVsCodeApi();

  const sectionIds = [
    'overview',
    'scan',
    'vulnerabilities',
    'saeFeatures',
    'featureInteractions',
    'securitySteering',
    'explanations',
    'automatedRepair',
    'verification',
    'researchReports',
    'settings'
  ];

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const severityLabels = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low'
  };
  const severityTones = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low'
  };
  const badgeTones = new Set([
    'neutral',
    'critical',
    'high',
    'medium',
    'low',
    'success',
    'warning',
    'danger',
    'info'
  ]);
  const safeCommandPattern = /^craftsec\.[A-Za-z][A-Za-z0-9]*$/;
  const demoFallbackNotice =
    'Demo data is shown for interface preview only. It was not produced by a scan or security ' +
    'engine, and no SAE, interaction, explanation, repair, or verification result is simulated.';

  const content = document.getElementById('dashboard-content');
  const bannerSlot = document.getElementById('dashboard-banner');
  const navList = document.getElementById('dashboard-tabs');
  const navButtons = navList ? Array.from(navList.querySelectorAll('.nav-item[data-section]')) : [];
  const dataModeBadge = document.getElementById('data-mode-badge');
  const lastUpdated = document.getElementById('last-updated');
  const refreshButton = document.getElementById('refresh-button');
  const demoButton = document.getElementById('demo-button');
  const logsButton = document.getElementById('logs-button');
  const enginePill = document.getElementById('engine-pill');
  const enginePillLabel = document.getElementById('engine-pill-label');

  const navSections = navButtons
    .map((button) => {
      const id = button.dataset.section;
      const labelNode = button.querySelector('.nav-label');
      const label = labelNode ? labelNode.textContent.trim() : id;
      return id ? { id, label } : null;
    })
    .filter(Boolean);

  let state = null;
  let activeSection = navSections[0] ? navSections[0].id : sectionIds[0];
  let transientNotice = null;
  let vulnerabilityFilter = { severity: 'all', cwe: 'all' };

  const restored = readRememberedState();
  if (restored && navSections.some((section) => section.id === restored.activeSection)) {
    activeSection = restored.activeSection;
  }

  bindChrome();
  bindMessageChannel();

  const initialRawState = readInitialState();
  if (initialRawState) {
    state = normalizeState(initialRawState);
    render();
  } else {
    renderBootError();
  }

  sendMessage({ type: 'ready' });

  // ---------------------------------------------------------------------
  // State and messaging
  // ---------------------------------------------------------------------

  function sendMessage(message) {
    try {
      vscode.postMessage(message);
    } catch (error) {
      console.error('CRAFT-Sec dashboard could not contact the extension host.', error);
      transientNotice = {
        level: 'error',
        message: 'The dashboard could not contact VS Code. See the CRAFT-Sec output channel.'
      };
      renderBanners();
    }
  }

  function bindMessageChannel() {
    window.addEventListener('message', (event) => {
      const message = event.data;
      if (!isRecord(message) || typeof message.type !== 'string') {
        return;
      }

      if (message.type === 'state') {
        state = normalizeState(message.state);
        if (
          vulnerabilityFilter.severity !== 'all' &&
          !severityOrder.includes(vulnerabilityFilter.severity)
        ) {
          vulnerabilityFilter.severity = 'all';
        }
        render();
        return;
      }

      if (message.type === 'notice') {
        const level =
          message.level === 'error' || message.level === 'warning' ? message.level : 'info';
        if (typeof message.message === 'string' && message.message.length > 0) {
          transientNotice = { level, message: message.message };
          renderBanners();
        }
      }
    });
  }

  function bindChrome() {
    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        sendMessage({ type: 'refresh' });
      });
    }

    if (demoButton) {
      demoButton.addEventListener('click', () => {
        const enabled = !state || state.dataMode !== 'demo';
        sendMessage({ type: 'setDemoMode', enabled });
      });
    }

    if (logsButton) {
      logsButton.addEventListener('click', () => {
        sendMessage({ type: 'showLogs' });
      });
    }

    if (!navList) {
      return;
    }

    navList.addEventListener('click', (event) => {
      const button = closestNavButton(event.target);
      if (button) {
        event.preventDefault();
        activateSection(button.dataset.section, false);
      }
    });

    navList.addEventListener('keydown', (event) => {
      const button = closestNavButton(event.target);
      if (!button) {
        return;
      }

      const currentIndex = navButtons.indexOf(button);
      let nextIndex;

      switch (event.key) {
        case 'ArrowDown':
        case 'ArrowRight':
          nextIndex = (currentIndex + 1) % navButtons.length;
          break;
        case 'ArrowUp':
        case 'ArrowLeft':
          nextIndex = (currentIndex - 1 + navButtons.length) % navButtons.length;
          break;
        case 'Home':
          nextIndex = 0;
          break;
        case 'End':
          nextIndex = navButtons.length - 1;
          break;
        default:
          return;
      }

      event.preventDefault();
      const nextButton = navButtons[nextIndex];
      activateSection(nextButton.dataset.section, true);
    });
  }

  function closestNavButton(target) {
    if (!(target instanceof Element)) {
      return null;
    }
    const button = target.closest('.nav-item[data-section]');
    return button && navButtons.includes(button) ? button : null;
  }

  function activateSection(sectionId, moveFocus) {
    if (typeof sectionId !== 'string' || !navSections.some((item) => item.id === sectionId)) {
      return;
    }

    activeSection = sectionId;
    updateNavigation();

    const activeButton = navButtons.find((button) => button.dataset.section === sectionId);
    if (moveFocus && activeButton) {
      activeButton.focus();
    }

    renderActiveSection();
    rememberState({ activeSection });
  }

  function rememberState(value) {
    try {
      vscode.setState(value);
    } catch (error) {
      console.error('CRAFT-Sec dashboard could not persist its view state.', error);
    }
  }

  function readRememberedState() {
    try {
      const value = vscode.getState();
      return isRecord(value) ? value : null;
    } catch (error) {
      console.error('CRAFT-Sec dashboard could not restore its view state.', error);
      return null;
    }
  }

  function readInitialState() {
    const node = document.getElementById('dashboard-state');
    if (!node) {
      return null;
    }
    try {
      return JSON.parse(node.textContent || '{}');
    } catch (error) {
      console.error('CRAFT-Sec dashboard state could not be parsed.', error);
      return null;
    }
  }

  function normalizeState(raw) {
    const source = isRecord(raw) ? raw : {};
    const summary = isRecord(source.summary) ? source.summary : {};
    const severity = isRecord(summary.severity) ? summary.severity : {};
    const demoNotice =
      typeof source.demoNotice === 'string' && source.demoNotice.length > 0
        ? source.demoNotice
        : '';

    return {
      schemaVersion: numberOrNull(source.schemaVersion),
      dataMode:
        source.dataMode === 'demo' || source.dataMode === 'live' ? source.dataMode : 'empty',
      generatedAt: stringOrNull(source.generatedAt),
      demoNotice,
      sections: arrayOfRecords(source.sections),
      actions: arrayOfRecords(source.actions),
      engine: isRecord(source.engine) ? source.engine : {},
      summary: {
        totalFindings: numberOrNull(summary.totalFindings),
        severity: {
          critical: numberOrNull(severity.critical),
          high: numberOrNull(severity.high),
          medium: numberOrNull(severity.medium),
          low: numberOrNull(severity.low)
        },
        lastScanAt: stringOrNull(summary.lastScanAt),
        workspaceName: stringOrNull(summary.workspaceName)
      },
      vulnerabilityDistribution: arrayOfRecords(source.vulnerabilityDistribution),
      cweDistribution: arrayOfRecords(source.cweDistribution),
      scanHistory: arrayOfRecords(source.scanHistory),
      vulnerabilities: arrayOfRecords(source.vulnerabilities),
      sae: isRecord(source.sae) ? source.sae : {},
      featureInteractions: isRecord(source.featureInteractions) ? source.featureInteractions : {},
      steering: isRecord(source.steering) ? source.steering : {},
      explanations: arrayOfRecords(source.explanations),
      repairs: arrayOfRecords(source.repairs),
      verification: isRecord(source.verification) ? source.verification : {},
      reports: arrayOfRecords(source.reports),
      settings: isRecord(source.settings) ? source.settings : {}
    };
  }

  // ---------------------------------------------------------------------
  // Main rendering
  // ---------------------------------------------------------------------

  function render() {
    if (!state) {
      renderBootError();
      return;
    }

    updateChrome();
    updateNavigation();
    renderBanners();
    renderActiveSection();
  }

  function renderBootError() {
    if (dataModeBadge) {
      dataModeBadge.textContent = 'State unavailable';
      dataModeBadge.className = 'badge badge--warning';
    }
    if (demoButton) {
      demoButton.disabled = true;
    }
    if (!content) {
      return;
    }
    clearNode(content);
    content.appendChild(
      emptyState(
        '!',
        'Dashboard state unavailable',
        'The webview could not read the initial dashboard state. Refresh the dashboard. If the ' +
          'problem persists, open the CRAFT-Sec output channel.'
      )
    );
  }

  function updateChrome() {
    if (!state) {
      return;
    }

    if (dataModeBadge) {
      if (state.dataMode === 'demo') {
        dataModeBadge.textContent = 'Demo data';
        dataModeBadge.className = 'badge badge--warning';
      } else if (state.dataMode === 'live') {
        dataModeBadge.textContent = 'Live data';
        dataModeBadge.className = 'badge badge--info';
      } else {
        dataModeBadge.textContent = 'No scan data';
        dataModeBadge.className = 'badge badge--neutral';
      }
    }

    if (lastUpdated) {
      const generatedAt = state.generatedAt;
      if (generatedAt) {
        lastUpdated.dateTime = generatedAt;
        lastUpdated.textContent = formatDateTime(generatedAt);
      } else {
        lastUpdated.removeAttribute('datetime');
        lastUpdated.textContent = '—';
      }
    }

    if (demoButton) {
      const demo = state.dataMode === 'demo';
      demoButton.hidden = state.dataMode === 'live';
      demoButton.disabled = false;
      demoButton.textContent = demo ? 'Clear demo data' : 'Load demo preview';
      demoButton.setAttribute('aria-pressed', demo ? 'true' : 'false');
    }

    const engine = isRecord(state.engine) ? state.engine : {};
    const engineLabel =
      typeof engine.label === 'string' && engine.label.length > 0
        ? engine.label
        : 'Engine status unavailable';

    if (enginePill) {
      enginePill.classList.toggle('is-ready', isEngineReady(engine.status));
      enginePill.classList.toggle('is-error', engine.status === 'unavailable');
      enginePill.title = typeof engine.detail === 'string' ? engine.detail : engineLabel;
    }
    if (enginePillLabel) {
      enginePillLabel.textContent = engineLabel;
    }

    updateNavCounts();
  }

  function updateNavigation() {
    if (navButtons.length === 0) {
      return;
    }

    for (const button of navButtons) {
      const selected = button.dataset.section === activeSection;
      button.classList.toggle('is-active', selected);
      button.setAttribute('aria-selected', selected ? 'true' : 'false');
      button.tabIndex = selected ? 0 : -1;
    }

    if (content) {
      content.setAttribute('aria-labelledby', `tab-${activeSection}`);
    }
  }

  function updateNavCounts() {
    if (!state) {
      return;
    }

    const saeFeatures =
      state.sae && state.sae.available === true && Array.isArray(state.sae.features)
        ? state.sae.features.length
        : null;
    const interactions =
      state.featureInteractions &&
      state.featureInteractions.available === true &&
      Array.isArray(state.featureInteractions.items)
        ? state.featureInteractions.items.length
        : null;
    const counts = {
      vulnerabilities: state.summary.totalFindings,
      saeFeatures,
      featureInteractions: interactions,
      explanations: state.explanations.length > 0 ? state.explanations.length : null,
      automatedRepair: state.repairs.length > 0 ? state.repairs.length : null,
      researchReports: state.reports.length > 0 ? state.reports.length : null
    };

    for (const element of document.querySelectorAll('[data-nav-count]')) {
      const section = element.dataset.navCount;
      const count = counts[section];
      if (typeof count === 'number' && Number.isFinite(count)) {
        element.hidden = false;
        element.textContent = formatNumber(count);
      } else {
        element.hidden = true;
        element.textContent = '';
      }
    }
  }

  function renderBanners() {
    if (!bannerSlot) {
      return;
    }

    clearNode(bannerSlot);

    if (state && state.dataMode === 'demo') {
      bannerSlot.appendChild(
        banner('warning', 'Demo data preview', state.demoNotice || demoFallbackNotice, false)
      );
    }

    if (transientNotice) {
      bannerSlot.appendChild(
        banner(
          transientNotice.level,
          transientNotice.level === 'error'
            ? 'Error'
            : transientNotice.level === 'warning'
              ? 'Warning'
              : 'Notice',
          transientNotice.message,
          true
        )
      );
    }
  }

  function renderActiveSection() {
    if (!content || !state) {
      return;
    }

    clearNode(content);
    content.setAttribute('aria-busy', 'false');

    let section;
    switch (activeSection) {
      case 'scan':
        section = renderScanSection();
        break;
      case 'vulnerabilities':
        section = renderVulnerabilitiesSection();
        break;
      case 'saeFeatures':
        section = renderSaeSection();
        break;
      case 'featureInteractions':
        section = renderInteractionsSection();
        break;
      case 'securitySteering':
        section = renderSteeringSection();
        break;
      case 'explanations':
        section = renderExplanationsSection();
        break;
      case 'automatedRepair':
        section = renderRepairSection();
        break;
      case 'verification':
        section = renderVerificationSection();
        break;
      case 'researchReports':
        section = renderReportsSection();
        break;
      case 'settings':
        section = renderSettingsSection();
        break;
      default:
        section = renderOverviewSection();
    }

    content.appendChild(section);
  }

  // ---------------------------------------------------------------------
  // Sections
  // ---------------------------------------------------------------------

  function renderOverviewSection() {
    const section = sectionContainer('overview', [
      internalButton('View vulnerabilities', 'vulnerabilities'),
      internalButton('Start a scan', 'scan')
    ]);

    const engineMessage = engineUnavailableCallout();
    if (engineMessage) {
      section.appendChild(engineMessage);
    }

    const summary = state.summary;
    const total = summary.totalFindings;
    const hasData = typeof total === 'number' && Number.isFinite(total);
    const dataNote =
      state.dataMode === 'demo'
        ? 'Illustrative demo value'
        : hasData
          ? 'Latest completed scan'
          : 'No scan data';

    const kpis = el('div', 'kpi-grid');
    kpis.appendChild(kpi('Total findings', total, dataNote));
    for (const severity of severityOrder) {
      const count = summary.severity[severity];
      const note =
        typeof count === 'number' && hasData && total > 0
          ? `${formatPercent(count, total)} of findings`
          : dataNote;
      kpis.appendChild(kpi(severityLabels[severity], count, note, severityTones[severity]));
    }
    section.appendChild(kpis);

    const distributionGrid = el('div', 'split-grid');
    distributionGrid.appendChild(
      card(
        'Vulnerability distribution',
        'Findings by severity in the current data set.',
        distributionList(state.vulnerabilityDistribution, true)
      )
    );
    distributionGrid.appendChild(
      card(
        'CWE distribution',
        'Findings grouped by Common Weakness Enumeration.',
        distributionList(state.cweDistribution, false)
      )
    );
    section.appendChild(distributionGrid);

    const statusGrid = el('div', 'split-grid');
    statusGrid.appendChild(renderVerificationSummaryCard());
    statusGrid.appendChild(
      card('Recent scan history', 'The most recent recorded scan runs.', scanHistoryContent(5))
    );
    section.appendChild(statusGrid);

    return section;
  }

  function renderScanSection() {
    const section = sectionContainer('scan');
    const engineMessage = engineUnavailableCallout();
    if (engineMessage) {
      section.appendChild(engineMessage);
    }

    const actions = actionGrid('scan');
    if (actions) {
      section.appendChild(
        card(
          'Run a security scan',
          'Commands run through the VS Code command layer and require a saved editor or workspace.',
          actions
        )
      );
    }

    section.appendChild(
      card(
        'Scan history',
        'Recorded scan runs and their outcomes. No scan is started by opening this section.',
        scanHistoryContent()
      )
    );

    return section;
  }

  function renderVulnerabilitiesSection() {
    const section = sectionContainer('vulnerabilities', [
      internalButton('Go to Security Scan', 'scan')
    ]);

    if (state.vulnerabilities.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No findings available',
          'No vulnerability findings have been recorded for this workspace. Run a scan once the ' +
            'security engine is connected. No findings are inferred by the dashboard.'
        )
      );
      return section;
    }

    const findings = [...state.vulnerabilities].sort(compareFindings);
    const cwes = [
      ...new Set(findings.map((finding) => stringOrNull(finding.cwe)).filter(Boolean))
    ].sort();
    if (vulnerabilityFilter.cwe !== 'all' && !cwes.includes(vulnerabilityFilter.cwe)) {
      vulnerabilityFilter.cwe = 'all';
    }

    const toolbar = el('div', 'table-toolbar');
    const filters = el('div', 'filter-row');
    filters.appendChild(
      filterGroup(
        'Severity',
        [
          { value: 'all', label: 'All' },
          ...severityOrder.map((severity) => ({
            value: severity,
            label: severityLabels[severity]
          }))
        ],
        vulnerabilityFilter.severity,
        (value) => {
          vulnerabilityFilter.severity = value;
          applyVulnerabilityFilters();
        }
      )
    );

    if (cwes.length > 0) {
      const cweGroup = el('div', 'filter-group');
      const label = el('label', 'filter-label', 'CWE');
      const select = el('select', 'select-control');
      select.id = 'cwe-filter';
      label.htmlFor = select.id;
      select.appendChild(option('all', 'All CWEs'));
      for (const cwe of cwes) {
        select.appendChild(option(cwe, cwe));
      }
      select.value = vulnerabilityFilter.cwe;
      select.addEventListener('change', () => {
        vulnerabilityFilter.cwe = select.value;
        applyVulnerabilityFilters();
      });
      cweGroup.appendChild(label);
      cweGroup.appendChild(select);
      filters.appendChild(cweGroup);
    }

    toolbar.appendChild(filters);
    const visibleCount = el('p', 'toolbar-meta');
    toolbar.appendChild(visibleCount);
    section.appendChild(toolbar);

    const table = createTable({
      caption: 'Vulnerability findings',
      columns: [
        { label: 'ID' },
        { label: 'Finding' },
        { label: 'Severity' },
        { label: 'CWE' },
        { label: 'Location' },
        { label: 'Status' }
      ],
      rows: findings.map((finding) => {
        const row = [
          el('span', 'mono', textOrDash(finding.id)),
          stackedCell(textOrDash(finding.title), stringOrNull(finding.summary)),
          severityBadge(finding.severity),
          el('span', 'mono', textOrDash(finding.cwe)),
          locationCell(finding.file, finding.line),
          statusBadge(finding.status)
        ];
        return row;
      })
    });

    const bodyRows = Array.from(table.tbody.querySelectorAll('tr'));
    bodyRows.forEach((row, index) => {
      const finding = findings[index];
      row.dataset.severity = typeof finding.severity === 'string' ? finding.severity : '';
      row.dataset.cwe = typeof finding.cwe === 'string' ? finding.cwe : '';
    });

    section.appendChild(
      card(
        'Findings',
        'Sorted by severity. Filters apply only to the data already loaded.',
        table.element
      )
    );

    const noMatches = emptyState(
      '—',
      'No findings match these filters',
      'Change the severity or CWE filter to show other findings.'
    );
    noMatches.hidden = true;
    section.appendChild(noMatches);

    function applyVulnerabilityFilters() {
      let shown = 0;
      bodyRows.forEach((row) => {
        const severityMatch =
          vulnerabilityFilter.severity === 'all' ||
          row.dataset.severity === vulnerabilityFilter.severity;
        const cweMatch =
          vulnerabilityFilter.cwe === 'all' || row.dataset.cwe === vulnerabilityFilter.cwe;
        const matches = severityMatch && cweMatch;
        row.hidden = !matches;
        if (matches) {
          shown += 1;
        }
      });

      visibleCount.textContent = `Showing ${formatNumber(shown)} of ${formatNumber(
        findings.length
      )} findings`;
      noMatches.hidden = shown !== 0;

      for (const chip of filters.querySelectorAll('.filter-chip')) {
        const active = chip.dataset.filterValue === vulnerabilityFilter.severity;
        chip.classList.toggle('is-active', active);
        chip.setAttribute('aria-pressed', active ? 'true' : 'false');
      }
      if (cwes.length > 0) {
        const select = filters.querySelector('#cwe-filter');
        if (select) {
          select.value = vulnerabilityFilter.cwe;
        }
      }
    }

    applyVulnerabilityFilters();
    return section;
  }

  function renderSaeSection() {
    const section = sectionContainer('saeFeatures');
    const actions = actionGrid('saeFeatures');
    if (actions) {
      section.appendChild(actions);
    }

    const sae = isRecord(state.sae) ? state.sae : {};
    if (sae.available !== true) {
      section.appendChild(
        callout(
          'SAE features unavailable',
          typeof sae.message === 'string' && sae.message.length > 0
            ? sae.message
            : 'No compatible SAE artifact and model activation source are registered.',
          'warning'
        )
      );
      section.appendChild(
        requirementsCard('Capabilities required for SAE features', [
          'A registered, compatible SAE artifact with a verified checksum.',
          'A white-box model whose internal activations are accessible at the declared hook point.',
          'Token-to-source alignment coverage reported by the backend.',
          'A recorded feature run tied to the model revision, SAE hash, and source snapshot.'
        ])
      );
      return section;
    }

    const features = Array.isArray(sae.features) ? arrayOfRecords(sae.features) : [];
    if (features.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No feature run has been recorded',
          'The SAE capability is available, but no feature extraction run has produced data for ' +
            'this workspace. No activation values are inferred.'
        )
      );
    } else {
      section.appendChild(
        card(
          'Measured features',
          'Activation statistics come from the recorded SAE run. Values are not probabilities.',
          createTable({
            caption: 'Measured SAE features',
            columns: [
              { label: 'Feature' },
              { label: 'Label' },
              { label: 'Max activation', numeric: true },
              { label: 'Mean activation', numeric: true },
              { label: 'Count', numeric: true },
              { label: 'Layer', numeric: true }
            ],
            rows: features.map((feature) => [
              el('span', 'mono', textOrDash(feature.index)),
              stackedCell(
                textOrDash(feature.label),
                stringOrNull(feature.labelSource) ? `Label source: ${feature.labelSource}` : null
              ),
              formatDecimal(feature.maxActivation),
              formatDecimal(feature.meanActivation),
              formatNumber(feature.count),
              textOrDash(feature.layer)
            ])
          }).element
        )
      );
    }

    section.appendChild(renderProvenanceCard(sae.provenance, 'SAE run provenance'));
    return section;
  }

  function renderInteractionsSection() {
    const section = sectionContainer('featureInteractions');
    const actions = actionGrid('featureInteractions');
    if (actions) {
      section.appendChild(actions);
    }

    section.appendChild(
      callout(
        'Model-intervention scope',
        'Counterfactual effects describe model behaviour under the named intervention. They are ' +
          'not real-world causal claims and must not be presented as probabilities.',
        'info'
      )
    );

    const interactions = isRecord(state.featureInteractions) ? state.featureInteractions : {};
    if (interactions.available !== true) {
      section.appendChild(
        callout(
          'Feature interactions unavailable',
          typeof interactions.message === 'string' && interactions.message.length > 0
            ? interactions.message
            : 'No measured activations or counterfactual run are available.',
          'warning'
        )
      );
      return section;
    }

    const items = Array.isArray(interactions.items) ? arrayOfRecords(interactions.items) : [];
    if (items.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No interaction results',
          'No counterfactual comparison has been recorded for this workspace. Effects are not ' +
            'estimated by the dashboard.'
        )
      );
      return section;
    }

    section.appendChild(
      card(
        'Counterfactual comparisons',
        'Effects are reported with their validity and evidence method.',
        createTable({
          caption: 'Feature interaction results',
          columns: [
            { label: 'Features' },
            { label: 'Effect' },
            { label: 'Interval' },
            { label: 'Validity' },
            { label: 'Method' }
          ],
          rows: items.map((item) => [
            describeFeaturePair(item),
            stackedCell(
              formatSignedNumber(item.effect),
              stringOrNull(item.effectKind) ? `Kind: ${item.effectKind}` : null
            ),
            formatInterval(item.interval ?? item.ci),
            validityBadge(item.valid),
            textOrDash(item.method)
          ])
        }).element
      )
    );

    return section;
  }

  function renderSteeringSection() {
    const section = sectionContainer('securitySteering');
    const steering = isRecord(state.steering) ? state.steering : {};

    if (steering.available !== true) {
      section.appendChild(
        callout(
          'Activation steering unavailable',
          typeof steering.message === 'string' && steering.message.length > 0
            ? steering.message
            : 'No compatible white-box model, activation access, and steering-capable SAE are ' +
                'available.',
          'warning'
        )
      );
      section.appendChild(
        requirementsCard('Capabilities required for steering', [
          'A white-box model with accessible internal activations.',
          'A compatible SAE with decoder directions at the steering hook point.',
          'Counterfactual interaction results that define the steering plan.',
          'A paired security and functional evaluation harness.',
          'Explicit user opt-in before any steering run begins.'
        ])
      );
      return section;
    }

    const controls = Array.isArray(steering.controls) ? arrayOfRecords(steering.controls) : [];
    if (controls.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No steering controls',
          'The steering capability is available, but no plan or control has been recorded. No ' +
            'activation steering is performed by the dashboard.'
        )
      );
      return section;
    }

    const list = el('ul', 'check-list');
    for (const control of controls) {
      const item = el('li');
      const copy = el('div', 'check-list__copy');
      copy.appendChild(el('span', null, textOrDash(control.label)));
      if (typeof control.detail === 'string' && control.detail.length > 0) {
        copy.appendChild(el('span', 'check-list__detail', control.detail));
      }
      item.appendChild(copy);
      item.appendChild(controlBadge(control));
      list.appendChild(item);
    }

    section.appendChild(
      card(
        'Steering controls',
        'Controls remain capability-gated and require explicit opt-in.',
        list
      )
    );

    return section;
  }

  function renderExplanationsSection() {
    const section = sectionContainer('explanations');
    const actions = actionGrid('explanations');
    if (actions) {
      section.appendChild(actions);
    }

    section.appendChild(
      callout(
        'Evidence-backed explanations only',
        'Every explanation must state its claim kind and evidence. An explanation without a claim ' +
          'kind is shown as unlabelled, not as a probability.',
        'info'
      )
    );

    if (state.explanations.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No explanations available',
          'No explanation graph has been recorded. Explanations cannot precede the evidence they ' +
            'explain.'
        )
      );
      return section;
    }

    for (const explanation of state.explanations) {
      const title = textOrDash(explanation.title);
      const claimKind = stringOrNull(explanation.claimKind);
      const header = el('div', 'card__header');
      const copy = el('div');
      copy.appendChild(el('h3', 'card__title', title));
      if (typeof explanation.summary === 'string' && explanation.summary.length > 0) {
        copy.appendChild(el('p', 'card__description', explanation.summary));
      }
      header.appendChild(copy);
      header.appendChild(
        claimKind ? badge(`Claim: ${claimKind}`, 'info') : badge('Unlabelled claim', 'warning')
      );

      const body = el('div', 'card__body');
      body.appendChild(
        el(
          'p',
          'text-muted',
          claimKind
            ? 'Claim kind is reported by the engine. Interpret it according to the documented ' +
                'score semantics.'
            : 'No claim kind was provided. This result must not be described as a probability or ' +
                'as a validated security conclusion.'
        )
      );
      body.appendChild(renderEvidenceList(explanation.evidence));

      if (Array.isArray(explanation.limitations) && explanation.limitations.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Limitations'));
        body.appendChild(renderStringList(explanation.limitations, 'policy-list'));
      }

      if (isRecord(explanation.provenance)) {
        body.appendChild(el('h4', 'subheading', 'Provenance'));
        body.appendChild(renderProvenance(explanation.provenance));
      }

      const article = el('article', 'card');
      article.appendChild(header);
      article.appendChild(body);
      section.appendChild(article);
    }

    return section;
  }

  function renderRepairSection() {
    const section = sectionContainer('automatedRepair');
    const actions = actionGrid('automatedRepair');
    if (actions) {
      section.appendChild(actions);
    }

    section.appendChild(
      callout(
        'Source files are never modified silently',
        'Repair proposals are reviewable artifacts. Applying a patch requires an explicit diff ' +
          'review, base-hash revalidation, and user approval in VS Code. This dashboard does not ' +
          'apply patches.',
        'info'
      )
    );

    if (state.repairs.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No repair proposals',
          'No patch proposal has been generated for this workspace. Repairs are not synthesized ' +
            'by the dashboard.'
        )
      );
      return section;
    }

    for (const repair of state.repairs) {
      const header = el('div', 'card__header');
      const copy = el('div');
      copy.appendChild(el('h3', 'card__title', textOrDash(repair.title ?? repair.id)));
      if (typeof repair.summary === 'string' && repair.summary.length > 0) {
        copy.appendChild(el('p', 'card__description', repair.summary));
      }
      header.appendChild(copy);
      header.appendChild(statusBadge(repair.status));

      const body = el('div', 'card__body');
      body.appendChild(
        definitionList(
          [
            ['Finding', repair.findingId],
            ['Base snapshot', repair.baseSnapshotId],
            ['Generator', repair.generator],
            ['Status', repair.status]
          ],
          'No repair metadata was provided.'
        )
      );

      const files = Array.isArray(repair.files) ? arrayOfRecords(repair.files) : [];
      if (files.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Files in this proposal'));
        const list = el('ul', 'file-list');
        for (const file of files) {
          const item = el('li');
          item.appendChild(el('span', 'mono', textOrDash(file.path)));
          const delta = formatFileDelta(file.additions, file.deletions);
          if (delta) {
            item.appendChild(el('span', 'file-list__delta', delta));
          }
          list.appendChild(item);
        }
        body.appendChild(list);
      }

      if (typeof repair.rationale === 'string' && repair.rationale.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Rationale'));
        body.appendChild(el('p', 'text-muted', repair.rationale));
      }

      if (Array.isArray(repair.riskNotes) && repair.riskNotes.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Risk notes'));
        body.appendChild(renderStringList(repair.riskNotes, 'policy-list'));
      }

      body.appendChild(
        el(
          'p',
          'setting-note',
          'No patch has been applied. Patch review and approval are handled outside this dashboard.'
        )
      );

      const article = el('article', 'card');
      article.appendChild(header);
      article.appendChild(body);
      section.appendChild(article);
    }

    return section;
  }

  function renderVerificationSection() {
    const section = sectionContainer('verification');
    const actions = actionGrid('verification');
    if (actions) {
      section.appendChild(actions);
    }

    const verification = isRecord(state.verification) ? state.verification : {};
    const checks = Array.isArray(verification.checks) ? arrayOfRecords(verification.checks) : [];
    const status = stringOrNull(verification.status) || 'not-run';
    const statusLabel = stringOrNull(verification.label) || humanize(status);

    const kpis = el('div', 'kpi-grid');
    kpis.appendChild(
      kpi(
        'Verification status',
        statusLabel,
        'Never treated as a pass by default',
        verificationTone(status),
        true
      )
    );
    kpis.appendChild(
      kpi(
        'Checks recorded',
        checks.length,
        checks.length === 0 ? 'No checks' : 'From the latest run',
        'neutral'
      )
    );
    kpis.appendChild(
      kpi(
        'Last verification',
        verification.lastRunAt ? formatDateTime(verification.lastRunAt) : null,
        verification.lastRunAt ? 'Recorded timestamp' : 'Not run',
        'neutral',
        true
      )
    );
    section.appendChild(kpis);

    if (typeof verification.summary === 'string' && verification.summary.length > 0) {
      section.appendChild(callout('Verification summary', verification.summary, 'info'));
    }

    const sandbox = isRecord(verification.executionSandbox) ? verification.executionSandbox : {};
    section.appendChild(
      callout(
        sandbox.available === true
          ? stringOrNull(sandbox.label) || 'Execution sandbox available'
          : stringOrNull(sandbox.label) || 'Execution sandbox unavailable',
        typeof sandbox.detail === 'string' && sandbox.detail.length > 0
          ? sandbox.detail
          : sandbox.available === true
            ? 'Execution-based checks may run only inside the configured sandbox.'
            : 'Execution-based verification is not attempted without an adequate isolated sandbox.',
        sandbox.available === true ? 'success' : 'warning'
      )
    );

    section.appendChild(
      card(
        'Verification checks',
        'Static, functional, and execution checks reported by the engine.',
        checks.length === 0
          ? emptyState(
              '—',
              'No verification checks recorded',
              'Not run is not a pass. Verification requires an approved repair and an available ' +
                'verification profile.'
            )
          : renderCheckList(checks)
      )
    );

    return section;
  }

  function renderReportsSection() {
    const section = sectionContainer('researchReports');

    if (state.reports.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No research reports',
          'No report has been generated for this workspace. Reports must come from recorded runs ' +
            'with model, SAE, analyzer, and configuration provenance.'
        )
      );
      return section;
    }

    section.appendChild(
      card(
        'Generated reports',
        'Reports are listed with their provenance references. This dashboard does not export or ' +
          'fabricate report content.',
        createTable({
          caption: 'Research reports',
          columns: [
            { label: 'Report' },
            { label: 'Generated' },
            { label: 'Scope' },
            { label: 'Format' },
            { label: 'Artifact' }
          ],
          rows: state.reports.map((report) => [
            stackedCell(textOrDash(report.title), stringOrNull(report.id)),
            formatDateTime(report.generatedAt),
            textOrDash(report.scope),
            textOrDash(report.format),
            el('span', 'mono', textOrDash(report.artifactId))
          ])
        }).element
      )
    );

    return section;
  }

  function renderSettingsSection() {
    const section = sectionContainer('settings');

    const buttons = el('div', 'inline-actions');
    buttons.appendChild(
      actionButton('Open VS Code Settings', () => {
        sendMessage({ type: 'openSettings' });
      })
    );
    buttons.appendChild(
      actionButton(
        'Show logs',
        () => {
          sendMessage({ type: 'showLogs' });
        },
        'button button--secondary'
      )
    );

    const settingsCard = card(
      'Extension settings',
      'Read-only values reported by the extension. Change settings in VS Code.',
      (() => {
        const list = el('dl', 'settings-list');
        const settings = state.settings;
        addSettingsRow(list, 'Python path', settingText(settings.pythonPath, 'Automatic'));
        addSettingsRow(list, 'Auto-start engine', settings.autoStart ? 'Enabled' : 'Disabled');
        addSettingsRow(list, 'Log level', settingText(settings.logLevel, 'info'));
        addSettingsRow(
          list,
          'Show status bar item',
          settings.showStatusBarItem === false ? 'Hidden' : 'Shown'
        );
        addSettingsRow(list, 'Dashboard data mode', dataModeBadgeText(state.dataMode));
        addSettingsRow(list, 'Workspace', settingText(state.summary.workspaceName, 'No workspace'));
        addSettingsRow(
          list,
          'Dashboard schema',
          state.schemaVersion === null ? 'Not reported' : String(state.schemaVersion)
        );
        return list;
      })()
    );
    settingsCard.body.appendChild(buttons);
    section.appendChild(settingsCard);

    const engine = isRecord(state.engine) ? state.engine : {};
    section.appendChild(
      card(
        'Engine',
        'The dashboard reflects the engine state reported by the extension host.',
        definitionList(
          [
            ['Status', engine.status],
            ['Label', engine.label],
            ['Detail', engine.detail]
          ],
          'No engine metadata was provided.'
        )
      )
    );

    section.appendChild(
      card(
        'Security and privacy',
        'Dashboard constraints enforced by the extension and webview.',
        renderStringList(
          [
            'Content Security Policy denies network, media, frames, workers, and inline executable code.',
            'Scripts are local files authorized by a per-render nonce.',
            'All dynamic text is rendered with DOM text nodes; the client does not use dynamic innerHTML.',
            'The dashboard is local-first and makes no cloud requests.',
            'The dashboard cannot write source files. Repair application is outside this panel.'
          ],
          'policy-list'
        )
      )
    );

    return section;
  }

  // ---------------------------------------------------------------------
  // Overview cards and shared content
  // ---------------------------------------------------------------------

  function renderVerificationSummaryCard() {
    const verification = isRecord(state.verification) ? state.verification : {};
    const status = stringOrNull(verification.status) || 'not-run';
    const body = el('div', 'stack');

    const statusRow = el('div', 'status-row');
    statusRow.appendChild(statusBadge(verification.status));
    statusRow.appendChild(
      el(
        'span',
        'text-muted',
        verification.lastRunAt
          ? `Last run ${formatDateTime(verification.lastRunAt)}`
          : 'No verification run recorded'
      )
    );
    body.appendChild(statusRow);

    if (typeof verification.summary === 'string' && verification.summary.length > 0) {
      body.appendChild(el('p', 'text-muted', verification.summary));
    }

    const checks = Array.isArray(verification.checks) ? arrayOfRecords(verification.checks) : [];
    if (checks.length > 0) {
      const summary = { passed: 0, failed: 0, other: 0 };
      for (const check of checks) {
        const checkStatus = stringOrNull(check.status);
        if (checkStatus === 'passed') {
          summary.passed += 1;
        } else if (checkStatus === 'failed') {
          summary.failed += 1;
        } else {
          summary.other += 1;
        }
      }
      body.appendChild(
        el(
          'p',
          'text-muted',
          `${formatNumber(summary.passed)} passed · ${formatNumber(
            summary.failed
          )} failed · ${formatNumber(summary.other)} other`
        )
      );
    }

    const sandbox = isRecord(verification.executionSandbox) ? verification.executionSandbox : {};
    body.appendChild(
      callout(
        sandbox.available === true
          ? 'Execution sandbox available'
          : 'Execution sandbox unavailable',
        typeof sandbox.detail === 'string' && sandbox.detail.length > 0
          ? sandbox.detail
          : 'Execution checks depend on a configured isolated sandbox.',
        sandbox.available === true ? 'success' : 'warning'
      )
    );

    body.appendChild(internalButton('Open Verification', 'verification', 'button button--ghost'));

    return card('Verification status', `Current verdict: ${humanize(status)}`, body);
  }

  function scanHistoryContent(limit) {
    const history = state.scanHistory.filter((entry) => isRecord(entry));
    const visible = typeof limit === 'number' ? history.slice(0, limit) : history;

    if (visible.length === 0) {
      return emptyState(
        '—',
        'No scan history',
        'No scan run has been recorded. Starting this dashboard does not start a scan.'
      );
    }

    return createTable({
      caption: 'Recent scan history',
      columns: [
        { label: 'Started' },
        { label: 'Scope' },
        { label: 'Status' },
        { label: 'Findings', numeric: true },
        { label: 'Duration', numeric: true }
      ],
      rows: visible.map((entry) => [
        formatDateTime(entry.startedAt),
        stackedCell(textOrDash(entry.scope), stringOrNull(entry.id)),
        statusBadge(entry.status),
        formatNumber(entry.findings),
        formatDuration(entry.durationMs)
      ])
    }).element;
  }

  function distributionList(items, severityColors) {
    const entries = arrayOfRecords(items).filter(
      (item) => typeof item.count === 'number' && Number.isFinite(item.count)
    );
    if (entries.length === 0) {
      return emptyState(
        '—',
        'No distribution data',
        'No scan result supplies this distribution. The dashboard does not estimate or infer values.'
      );
    }

    const maxCount = Math.max(...entries.map((item) => item.count), 1);
    const list = el('div', 'distribution-list');

    for (const item of entries) {
      const row = el('div', 'distribution-row');
      const meta = el('div', 'distribution-row__meta');
      const labelText = [stringOrNull(item.cwe), stringOrNull(item.label)]
        .filter(Boolean)
        .join(' · ');
      meta.appendChild(el('span', 'distribution-row__label', textOrDash(labelText || item.key)));
      meta.appendChild(el('span', 'distribution-row__count', formatNumber(item.count)));
      row.appendChild(meta);

      const progress = el('progress', `bar${severityBarClass(item, severityColors)}`);
      progress.max = maxCount;
      progress.value = item.count;
      progress.setAttribute(
        'aria-label',
        `${labelText || textOrDash(item.key)}: ${formatNumber(item.count)}`
      );
      row.appendChild(progress);
      list.appendChild(row);
    }

    return list;
  }

  function severityBarClass(item, severityColors) {
    if (!severityColors) {
      return ' bar--accent';
    }
    const key = typeof item.key === 'string' ? item.key : '';
    return severityTones[key] ? ` bar--${severityTones[key]}` : ' bar--accent';
  }

  function renderCheckList(checks) {
    const list = el('ul', 'check-list');
    for (const check of checks) {
      const item = el('li');
      const copy = el('div', 'check-list__copy');
      copy.appendChild(el('span', null, textOrDash(check.label ?? check.id)));
      if (typeof check.detail === 'string' && check.detail.length > 0) {
        copy.appendChild(el('span', 'check-list__detail', check.detail));
      }
      item.appendChild(copy);
      item.appendChild(statusBadge(check.status));
      list.appendChild(item);
    }
    return list;
  }

  function renderEvidenceList(evidence) {
    if (!Array.isArray(evidence) || evidence.length === 0) {
      return el('p', 'text-muted', 'No evidence entries were provided with this result.');
    }

    const list = el('ul', 'evidence-list');
    for (const entry of evidence) {
      const item = el('li');
      if (isRecord(entry)) {
        item.appendChild(el('span', 'evidence-list__label', textOrDash(entry.label ?? entry.kind)));
        const detail = stringOrNull(entry.detail ?? entry.summary);
        if (detail) {
          item.appendChild(el('span', 'evidence-list__detail', detail));
        }
      } else if (typeof entry === 'string') {
        item.textContent = entry;
      } else {
        item.textContent = 'Unsupported evidence entry';
      }
      list.appendChild(item);
    }
    return list;
  }

  function renderStringList(values, className) {
    const list = el('ul', className);
    for (const value of values) {
      if (typeof value === 'string' && value.length > 0) {
        list.appendChild(el('li', null, value));
      }
    }
    return list;
  }

  function renderProvenanceCard(provenance, title) {
    return card(
      title,
      'Provenance must identify the producer, input, and artifact for the recorded result.',
      renderProvenance(isRecord(provenance) ? provenance : {})
    );
  }

  function renderProvenance(provenance) {
    return definitionList([
      ['Producer', provenance.producer],
      ['Artifact', provenance.artifactId ?? provenance.artifact],
      ['Model', provenance.modelId ?? provenance.model],
      ['Revision', provenance.modelRevision ?? provenance.revision],
      ['SAE artifact', provenance.saeArtifactId],
      ['Layer', provenance.layer],
      ['Hook point', provenance.hookPoint],
      ['SHA-256', provenance.sha256],
      ['Created', provenance.createdAt ? formatDateTime(provenance.createdAt) : null]
    ]);
  }

  function definitionList(entries, emptyMessage = 'No provenance record was provided.') {
    const pairs = entries.filter((pair) => isDisplayValue(pair[1]));

    if (pairs.length === 0) {
      return el('p', 'text-muted', emptyMessage);
    }

    const list = el('dl', 'provenance');
    for (const [label, value] of pairs) {
      list.appendChild(el('dt', null, label));
      list.appendChild(el('dd', null, String(value)));
    }
    return list;
  }

  function requirementsCard(title, requirements) {
    return card(
      title,
      'These capabilities are required before this section can produce results.',
      renderStringList(requirements, 'requirement-list')
    );
  }

  function engineUnavailableCallout() {
    const engine = isRecord(state.engine) ? state.engine : {};
    if (engine.status === 'ready') {
      return null;
    }
    const detail =
      typeof engine.detail === 'string' && engine.detail.length > 0
        ? engine.detail
        : 'The local security engine is not reachable. No result is produced.';
    const title =
      typeof engine.label === 'string' && engine.label.length > 0
        ? engine.label
        : 'Analysis capabilities unavailable';
    return callout(title, detail, 'warning');
  }

  function actionGrid(sectionId) {
    const actions = state.actions.filter(
      (action) =>
        action.section === sectionId &&
        typeof action.command === 'string' &&
        safeCommandPattern.test(action.command) &&
        typeof action.title === 'string' &&
        action.title.length > 0
    );

    if (actions.length === 0) {
      return null;
    }

    const grid = el('div', 'action-grid');
    for (const action of actions) {
      const button = el('button', 'action-card');
      button.type = 'button';
      button.appendChild(el('span', 'action-card__title', action.title));
      if (typeof action.description === 'string' && action.description.length > 0) {
        button.appendChild(el('span', 'action-card__description', action.description));
      }
      if (typeof action.meta === 'string' && action.meta.length > 0) {
        button.appendChild(el('span', 'action-card__meta', action.meta));
      }
      button.addEventListener('click', () => {
        sendMessage({ type: 'executeCommand', command: action.command });
      });
      grid.appendChild(button);
    }
    return grid;
  }

  // ---------------------------------------------------------------------
  // DOM helpers
  // ---------------------------------------------------------------------

  function sectionContainer(sectionId, actions) {
    const container = el('div', 'stack');
    container.appendChild(sectionHeading(sectionId, actions));
    return container;
  }

  function sectionHeading(sectionId, actions) {
    const meta = sectionMeta(sectionId);
    const heading = el('div', 'section-heading');
    const copy = el('div', 'section-heading__copy');
    copy.appendChild(el('p', 'section-kicker', 'CRAFT-Sec'));
    copy.appendChild(el('h2', null, meta.label));
    if (meta.description) {
      copy.appendChild(el('p', 'section-description', meta.description));
    }
    heading.appendChild(copy);

    if (Array.isArray(actions) && actions.length > 0) {
      const actionRow = el('div', 'section-actions');
      for (const action of actions) {
        if (action) {
          actionRow.appendChild(action);
        }
      }
      heading.appendChild(actionRow);
    }

    return heading;
  }

  function sectionMeta(sectionId) {
    const nav = navSections.find((section) => section.id === sectionId);
    const fromState = state.sections.find((section) => section.id === sectionId);
    return {
      label: nav ? nav.label : humanize(sectionId),
      description:
        fromState && typeof fromState.description === 'string' ? fromState.description : ''
    };
  }

  function card(title, description, body, options = {}) {
    const container = el('section', 'card');
    if (title) {
      const header = el('div', 'card__header');
      const copy = el('div');
      copy.appendChild(el('h3', 'card__title', title));
      if (description) {
        copy.appendChild(el('p', 'card__description', description));
      }
      header.appendChild(copy);
      container.appendChild(header);
    }

    const bodyNode = el('div', `card__body${options.flush ? ' card__body--flush' : ''}`);
    if (body) {
      if (isNode(body)) {
        bodyNode.appendChild(body);
      } else if (Array.isArray(body)) {
        for (const child of body) {
          if (child) {
            bodyNode.appendChild(child);
          }
        }
      }
    }
    container.appendChild(bodyNode);
    container.body = bodyNode;
    return container;
  }

  function kpi(label, value, note, tone = 'neutral', textValue = false) {
    const container = el('div', `kpi kpi--${badgeTones.has(tone) ? tone : 'neutral'}`);
    container.appendChild(el('span', 'kpi__label', label));
    const display = textValue
      ? textOrDash(value)
      : typeof value === 'number' && Number.isFinite(value)
        ? formatNumber(value)
        : '—';
    container.appendChild(el('span', `kpi__value${textValue ? ' kpi__value--text' : ''}`, display));
    if (note) {
      container.appendChild(el('span', 'kpi__note', note));
    }
    return container;
  }

  function callout(title, body, tone) {
    const className =
      tone === 'warning' || tone === 'danger' || tone === 'success'
        ? `callout callout--${tone}`
        : 'callout';
    const container = el('div', className);
    container.appendChild(el('p', 'callout__title', title));
    container.appendChild(el('p', 'callout__body', body));
    return container;
  }

  function emptyState(mark, title, body) {
    const container = el('div', 'empty-state');
    container.appendChild(el('span', 'empty-state__mark', mark));
    container.appendChild(el('h3', 'empty-state__title', title));
    container.appendChild(el('p', 'empty-state__body', body));
    return container;
  }

  function banner(level, title, message, dismissible) {
    const className =
      level === 'error'
        ? 'banner banner--error'
        : level === 'info'
          ? 'banner banner--info'
          : 'banner';
    const container = el('div', className);
    const copy = el('div', 'banner__copy');
    copy.appendChild(el('span', 'banner__title', title));
    copy.appendChild(el('span', null, message));
    container.appendChild(copy);

    if (dismissible) {
      const dismiss = el('button', 'banner__dismiss', 'Dismiss');
      dismiss.type = 'button';
      dismiss.addEventListener('click', () => {
        transientNotice = null;
        renderBanners();
      });
      container.appendChild(dismiss);
    }

    return container;
  }

  function createTable({ caption, columns, rows }) {
    const wrap = el('div', 'table-wrap');
    const table = el('table', 'data-table');
    table.appendChild(el('caption', null, caption));

    const thead = el('thead');
    const headerRow = el('tr');
    for (const column of columns) {
      const cell = el('th', column.numeric ? 'data-table__numeric' : null, column.label);
      cell.scope = 'col';
      headerRow.appendChild(cell);
    }
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = el('tbody');
    for (const row of rows) {
      const rowNode = el('tr');
      row.forEach((value, index) => {
        const column = columns[index] || {};
        const cell = el('td', column.numeric ? 'data-table__numeric' : null);
        if (isNode(value)) {
          cell.appendChild(value);
        } else {
          cell.textContent = isDisplayValue(value) ? String(value) : '—';
        }
        rowNode.appendChild(cell);
      });
      tbody.appendChild(rowNode);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    return { element: wrap, tbody };
  }

  function filterGroup(labelText, options, selected, onChange) {
    const group = el('div', 'filter-group');
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', `Filter by ${labelText.toLowerCase()}`);
    group.appendChild(el('span', 'filter-label', labelText));

    for (const optionEntry of options) {
      const active = optionEntry.value === selected;
      const chip = el('button', `filter-chip${active ? ' is-active' : ''}`, optionEntry.label);
      chip.type = 'button';
      chip.dataset.filterValue = optionEntry.value;
      chip.setAttribute('aria-pressed', active ? 'true' : 'false');
      chip.addEventListener('click', () => {
        onChange(optionEntry.value);
      });
      group.appendChild(chip);
    }

    return group;
  }

  function option(value, label) {
    const node = el('option', null, label);
    node.value = value;
    return node;
  }

  function addSettingsRow(list, label, value) {
    list.appendChild(el('dt', 'settings-row__label', label));
    list.appendChild(el('dd', 'settings-row__value', value));
  }

  function stackedCell(primary, secondary) {
    const container = el('span', 'stacked-cell');
    container.appendChild(el('span', 'finding-title', textOrDash(primary)));
    if (typeof secondary === 'string' && secondary.length > 0) {
      container.appendChild(el('span', 'finding-summary', secondary));
    }
    return container;
  }

  function locationCell(file, line) {
    if (typeof file !== 'string' || file.length === 0) {
      return el('span', 'location', '—');
    }
    const location = typeof line === 'number' && Number.isFinite(line) ? `${file}:${line}` : file;
    return el('span', 'location', location);
  }

  function describeFeaturePair(item) {
    const features = Array.isArray(item.features)
      ? item.features
      : [item.featureA, item.featureB].filter((value) => isDisplayValue(value));
    if (features.length === 0) {
      return el('span', 'text-muted', '—');
    }
    return el('span', null, features.map(describeFeature).join(' + '));
  }

  function describeFeature(feature) {
    if (isRecord(feature)) {
      return textOrDash(
        feature.label ?? feature.id ?? feature.index ?? feature.featureIndex,
        'Unlabelled feature'
      );
    }
    return textOrDash(feature);
  }

  function severityBadge(severity) {
    const key = typeof severity === 'string' ? severity.toLowerCase() : '';
    if (severityTones[key]) {
      return badge(severityLabels[key], severityTones[key]);
    }
    return badge(textOrDash(severity, 'Unknown'), 'neutral');
  }

  function statusBadge(status) {
    const key = typeof status === 'string' ? status : '';
    return badge(humanize(textOrDash(key, 'Unknown')), statusTone(key));
  }

  function validityBadge(valid) {
    if (valid === true) {
      return badge('Valid', 'success');
    }
    if (valid === false) {
      return badge('Not valid', 'danger');
    }
    if (typeof valid === 'string' && valid.length > 0) {
      return badge(humanize(valid), valid === 'valid' ? 'success' : 'warning');
    }
    return badge('Unverified', 'warning');
  }

  function controlBadge(control) {
    if (control.requiresOptIn === true) {
      return badge('Opt-in required', 'warning');
    }
    if (control.enabled === true || control.available === true) {
      return badge('Available', 'success');
    }
    return badge('Unavailable', 'neutral');
  }

  function badge(text, tone) {
    return el('span', `badge badge--${badgeTones.has(tone) ? tone : 'neutral'}`, text);
  }

  function internalButton(label, sectionId, className = 'button button--secondary') {
    return actionButton(label, () => activateSection(sectionId, false), className);
  }

  function actionButton(label, onClick, className = 'button') {
    const button = el('button', className, label);
    button.type = 'button';
    button.addEventListener('click', onClick);
    return button;
  }

  function statusTone(status) {
    const key = typeof status === 'string' ? status : '';
    if (key === 'completed' || key === 'passed' || key === 'resolved' || key === 'fixed') {
      return 'success';
    }
    if (key === 'failed' || key === 'error') {
      return 'danger';
    }
    if (
      key === 'partial' ||
      key === 'warning' ||
      key === 'open' ||
      key === 'cancelled' ||
      key === 'skipped' ||
      key === 'not-run'
    ) {
      return 'warning';
    }
    if (key === 'running' || key === 'triaged' || key === 'in-review') {
      return 'info';
    }
    return 'neutral';
  }

  function verificationTone(status) {
    if (status === 'passed') {
      return 'success';
    }
    if (status === 'failed') {
      return 'danger';
    }
    if (status === 'not-run' || status === 'skipped') {
      return 'neutral';
    }
    return 'warning';
  }

  function dataModeBadgeText(mode) {
    if (mode === 'demo') {
      return 'Demo data';
    }
    if (mode === 'live') {
      return 'Live data';
    }
    return 'No scan data';
  }

  function el(tagName, className, text) {
    const node = document.createElement(tagName);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function isNode(value) {
    return Boolean(value) && typeof value === 'object' && typeof value.nodeType === 'number';
  }

  function isRecord(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  function arrayOfRecords(value) {
    return Array.isArray(value) ? value.filter((entry) => isRecord(entry)) : [];
  }

  function numberOrNull(value) {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  }

  function stringOrNull(value) {
    return typeof value === 'string' && value.length > 0 ? value : null;
  }

  function isDisplayValue(value) {
    return (
      (typeof value === 'string' && value.length > 0) ||
      (typeof value === 'number' && Number.isFinite(value))
    );
  }

  function textOrDash(value, fallback = '—') {
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }
    return fallback;
  }

  function settingText(value, fallback) {
    return typeof value === 'string' && value.length > 0 ? value : fallback;
  }

  function isEngineReady(status) {
    return status === 'ready' || status === 'available' || status === 'connected';
  }

  function formatNumber(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return '—';
    }
    return new Intl.NumberFormat().format(value);
  }

  function formatPercent(value, total) {
    if (
      typeof value !== 'number' ||
      typeof total !== 'number' ||
      !Number.isFinite(value) ||
      !Number.isFinite(total) ||
      total <= 0
    ) {
      return '—';
    }
    return `${Math.round((value / total) * 100)}%`;
  }

  function formatSignedNumber(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return '—';
    }
    if (value === 0) {
      return '0';
    }
    return `${value > 0 ? '+' : ''}${formatDecimal(value)}`;
  }

  function formatDecimal(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return '—';
    }
    if (Number.isInteger(value)) {
      return formatNumber(value);
    }
    return String(Number(value.toPrecision(4)));
  }

  function formatInterval(interval) {
    if (Array.isArray(interval) && interval.length >= 2) {
      return `[${formatDecimal(interval[0])}, ${formatDecimal(interval[1])}]`;
    }
    if (
      isRecord(interval) &&
      typeof interval.low === 'number' &&
      typeof interval.high === 'number'
    ) {
      return `[${formatDecimal(interval.low)}, ${formatDecimal(interval.high)}]`;
    }
    return '—';
  }

  function formatDateTime(value) {
    if (typeof value !== 'string' || value.length === 0) {
      return '—';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return '—';
    }
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(date);
  }

  function formatDuration(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      return '—';
    }
    if (value < 1000) {
      return `${formatNumber(value)} ms`;
    }
    return `${formatDecimal(value / 1000)} s`;
  }

  function formatFileDelta(additions, deletions) {
    const hasAdditions = typeof additions === 'number' && Number.isFinite(additions);
    const hasDeletions = typeof deletions === 'number' && Number.isFinite(deletions);
    if (!hasAdditions && !hasDeletions) {
      return '';
    }
    return `+${hasAdditions ? formatNumber(additions) : '—'} / -${
      hasDeletions ? formatNumber(deletions) : '—'
    }`;
  }

  function humanize(value) {
    if (typeof value !== 'string' || value.length === 0) {
      return 'Unknown';
    }
    const words = value.replaceAll('_', '-').split('-').filter(Boolean);
    if (words.length === 0) {
      return 'Unknown';
    }
    return words
      .map((word) => {
        if (word.toLowerCase() === 'cwe') {
          return 'CWE';
        }
        if (word.toLowerCase() === 'sae') {
          return 'SAE';
        }
        return `${word.charAt(0).toUpperCase()}${word.slice(1)}`;
      })
      .join(' ');
  }

  function compareFindings(left, right) {
    const leftRank = severityOrder.indexOf(typeof left.severity === 'string' ? left.severity : '');
    const rightRank = severityOrder.indexOf(
      typeof right.severity === 'string' ? right.severity : ''
    );
    const leftValue = leftRank === -1 ? severityOrder.length : leftRank;
    const rightValue = rightRank === -1 ? severityOrder.length : rightRank;
    if (leftValue !== rightValue) {
      return leftValue - rightValue;
    }
    return String(left.id ?? '').localeCompare(String(right.id ?? ''));
  }
})();
