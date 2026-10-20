/*
 * reachable dashboard — no-build frontend.
 *
 * API contract (intentionally tolerant while the backend evolves):
 *   GET  /api/demo             -> AnalysisResponse
 *   POST /api/analyze          -> AnalysisResponse (JSON {path, include_tests, scan_subfolders})
 *   POST /api/analyze/upload   -> AnalysisResponse (multipart files + include_tests + scan_subfolders)
 *   GET  /api/results/:id      -> AnalysisResponse
 *   GET  /api/export/:id?format=html|markdown -> downloadable report
 *
 * AnalysisResponse accepts {id, project_path|path, created_at|timestamp,
 * results|alerts: Alert[], summary}. Alert fields are package|name,
 * version, severity, status, advisory_id|id, advisory_text|description,
 * reason|reason_code, confidence, symbol_source, evidence|chain, snippets,
 * graph, fixed_version. Unknown fields are preserved by normalization.
 */
(function () {
  'use strict';

  const state = {
    analysis: null,
    alerts: [],
    filtered: [],
    activeAlert: null,
    source: 'none',
    allSelectedFiles: [],
    selectedFiles: [],
    selectedFileCount: 0,
    selectedFolderCount: 0,
    unsupportedFiles: [],
    excludedNestedFiles: [],
    selectedFolderName: '',
    folderSelected: false,
    scanSubfolders: true,
    loading: false,
    lastFocus: null
  };

  const $ = (id) => document.getElementById(id);
  const els = {
    path: $('project-path'),
    folderInput: $('folder-input'),
    folderButton: $('folder-button'),
    folderStatus: $('folder-status'),
    includeTests: $('include-tests'),
    scanSubfolders: $('scan-subfolders'),
    demo: $('demo-button'),
    welcomeDemo: $('welcome-demo-button'),
    analyze: $('analyze-button'),
    analyzeLabel: $('analyze-label'),
    refresh: $('refresh-button'),
    results: $('results-section'),
    welcome: $('welcome-state'),
    message: $('global-message'),
    meta: $('analysis-meta'),
    summary: $('summary-panel'),
    search: $('alert-search'),
    status: $('status-filter'),
    severity: $('severity-filter'),
    sort: $('sort-filter'),
    clear: $('clear-filters'),
    emptyClear: $('empty-clear'),
    count: $('alert-count'),
    list: $('alert-list'),
    empty: $('empty-alerts'),
    emptyTitle: $('empty-alerts-title'),
    emptyCopy: $('empty-alerts-copy'),
    theme: $('theme-toggle'),
    drawer: $('detail-drawer'),
    backdrop: $('drawer-backdrop'),
    drawerContent: $('drawer-content'),
    drawerIndex: $('drawer-index'),
    closeDrawer: $('close-drawer'),
    toast: $('toast'),
    exportMd: $('export-markdown'),
    exportHtml: $('export-html')
  };

  const SUPPORTED_FILE_NAMES = new Set([
    'dockerfile',
    'pipfile',
    'pipfile.lock',
    'poetry.lock',
    'pyproject.toml',
    'requirements.txt',
    'requirements.lock',
    'setup.cfg',
    'setup.py',
    'tox.ini',
    'uv.lock',
    'osv_records.json',
    'osv.json',
    'pip-audit.json'
  ]);
  const SUPPORTED_FILE_EXTENSIONS = ['.py', '.pyi', '.toml', '.cfg', '.ini', '.json', '.yaml', '.yml', '.txt', '.lock'];

  function normalizeStatus(status) {
    const value = String(status || 'UNKNOWN').toUpperCase().replace(/ /g, '_');
    return ['REACHABLE', 'NOT_PROVEN_REACHABLE', 'UNKNOWN'].includes(value) ? value : 'UNKNOWN';
  }

  function normalizeAlert(item, index) {
    const alert = item || {};
    const status = normalizeStatus(alert.status || alert.classification);
    const evidence = alert.evidence || alert.chain || alert.call_chain || [];
    return {
      ...alert,
      id: alert.id || alert.advisory_id || `alert-${index}`,
      package: alert.package || alert.name || alert.ecosystem_package || 'unknown package',
      version: alert.version || alert.installed_version || '—',
      severity: String(alert.severity || 'unknown').toLowerCase(),
      status,
      advisory_id: alert.advisory_id || alert.id || '—',
      advisory_text: alert.advisory_text || alert.details || alert.description || alert.summary || 'No advisory description was provided.',
      reason: alert.reason || alert.explanation || alert.why || alert.message || defaultReason(status),
      reason_code: alert.reason_code || alert.reasonCode || 'UNKNOWN',
      confidence: alert.confidence || 'low',
      symbol_source: alert.symbol_source || alert.symbolSource || 'none',
      evidence: Array.isArray(evidence)
        ? evidence.map((hop) => typeof hop === 'string' ? { label: hop, symbol: hop } : { ...hop, label: hop.label || hop.file || hop.path || hop.detail || '' })
        : [],
      snippets: normalizeSnippets(alert.snippets || alert.code_snippets || alert.snippet),
      graph: normalizeGraph(alert.graph || alert.call_graph),
      fixed_version: alert.fixed_version || alert.fix_version || null
    };
  }

  function normalizeSnippets(raw) {
    const items = Array.isArray(raw) ? raw : raw ? [raw] : [];
    return items.map((item) => typeof item === 'string' ? { file: 'source', lines: [{ number: '', text: item }] } : item);
  }

  function normalizeGraph(raw) {
    if (!raw) return null;
    const nodes = Array.isArray(raw.nodes)
      ? raw.nodes.map((node, index) => typeof node === 'string'
        ? { id: String(index), label: node, type: index === raw.nodes.length - 1 ? 'library' : 'user' }
        : node)
      : [];
    const edges = Array.isArray(raw.edges || raw.links)
      ? (raw.edges || raw.links).map((edge) => ({
        ...edge,
        from: edge.from ?? edge.source,
        to: edge.to ?? edge.target,
        kind: edge.kind || edge.type || 'reachable'
      }))
      : [];
    return { ...raw, nodes, edges };
  }

  function defaultReason(status) {
    if (status === 'REACHABLE') return 'A complete call chain was found in the analyzed source.';
    if (status === 'NOT_PROVEN_REACHABLE') return 'No matching call path was found in the analyzed source.';
    return 'Static analysis could not establish a reliable call path.';
  }

  function normalizeResponse(payload, fallbackPath) {
    const source = payload?.data || payload?.result || payload || {};
    const raw = source.results || source.alerts || source.findings || [];
    const alerts = Array.isArray(raw) ? raw.map(normalizeAlert) : [];
    return {
      ...source,
      id: source.id || source.analysis_id || 'analysis',
      path: source.project_path || source.path || fallbackPath || 'Python project',
      created_at: source.created_at || source.timestamp || new Date().toISOString(),
      alerts,
      summary: source.summary || {}
    };
  }

  async function api(path, options = {}) {
    const headers = { Accept: 'application/json', ...(options.headers || {}) };
    if (options.body instanceof FormData) {
      delete headers['Content-Type'];
    } else if (!headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    const response = await fetch(path, { ...options, headers });
    const text = await response.text().catch(() => '');
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch (_) {
      /* Keep a useful plain-text error below. */
    }
    if (!response.ok) {
      const message = payload?.error?.message || payload?.detail || (typeof payload?.error === 'string' ? payload.error : '') || text || `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload || {};
  }

  async function loadDemo() {
    resetFolderSelection(false);
    els.path.value = '';
    renderFolderStatus();
    state.source = 'demo';
    setLoading(true, 'Loading the offline notebook…');
    try {
      state.analysis = normalizeResponse(await api('/api/demo'));
      finishLoad();
    } catch (error) {
      setLoading(false);
      showMessage(`The offline demo could not be loaded. ${error.message || 'Start the local reachable server and try again.'}`, 'error');
    }
  }

  async function analyze() {
    if (state.folderSelected) {
      if (!state.selectedFiles.length) {
        showMessage(folderEmptyMessage(), 'error');
        return;
      }
      return analyzeUpload();
    }
    const path = els.path.value.trim();
    if (!path) {
      showMessage('Add a project path, choose a folder, or load the offline demo to explore the dashboard.', 'error');
      els.path.focus();
      return;
    }
    return analyzePath(path);
  }

  async function analyzePath(path) {
    state.source = 'path';
    setLoading(true, 'Reading the project without running it…');
    try {
      state.analysis = normalizeResponse(await api('/api/analyze', {
        method: 'POST',
        body: JSON.stringify({
          path,
          include_tests: els.includeTests.checked,
          scan_subfolders: els.scanSubfolders.checked
        })
      }), path);
      finishLoad();
    } catch (error) {
      setLoading(false);
      showMessage(`Analysis could not be loaded. ${error.message || 'Check the project path and try again.'}`, 'error', true);
    }
  }

  async function analyzeUpload() {
    const formData = new FormData();
    state.selectedFiles.forEach((file) => formData.append('files', file, relativePath(file)));
    formData.append('include_tests', String(els.includeTests.checked));
    formData.append('scan_subfolders', String(els.scanSubfolders.checked));
    state.source = 'upload';
    setLoading(true, 'Uploading the selected folder for static analysis…');
    try {
      state.analysis = normalizeResponse(await api('/api/analyze/upload', {
        method: 'POST',
        body: formData
      }), state.selectedFolderName || 'Selected project');
      finishLoad();
    } catch (error) {
      setLoading(false);
      showMessage(`Folder analysis could not be loaded. ${error.message || 'Check the selected files and try again.'}`, 'error');
    }
  }

  function relativeParts(file) {
    const raw = String(file?.webkitRelativePath || file?.name || '').replace(/\\/g, '/');
    return raw
      .split('/')
      .filter(Boolean)
      .filter((part) => part !== '.' && part !== '..' && !/^[A-Za-z]:$/.test(part));
  }

  function relativePath(file) {
    return relativeParts(file).join('/');
  }

  function isSupportedFile(file) {
    const parts = relativeParts(file);
    const name = (parts[parts.length - 1] || '').toLowerCase();
    return SUPPORTED_FILE_NAMES.has(name) || SUPPORTED_FILE_EXTENSIONS.some((extension) => name.endsWith(extension));
  }

  function isRootLevelFile(file) {
    return relativeParts(file).length <= 2;
  }

  function safeFolderName(value) {
    const label = String(value || '').replace(/[\\/:]/g, ' ').replace(/\s+/g, ' ').trim();
    return label || 'Selected folder';
  }

  function folderRoots(files) {
    const roots = new Set();
    files.forEach((file) => {
      const parts = relativeParts(file);
      roots.add(safeFolderName(parts.length > 1 ? parts[0] : 'Selected folder'));
    });
    return roots;
  }

  function countLabel(count, singular, plural = `${singular}s`) {
    return `${count} ${count === 1 ? singular : plural}`;
  }

  function renderFolderStatus() {
    if (!state.folderSelected) {
      els.folderStatus.className = 'folder-status';
      els.folderStatus.textContent = 'No folder selected. Choose a folder to upload its Python source and project metadata.';
      return;
    }

    const ignored = state.unsupportedFiles.length;
    const excluded = state.excludedNestedFiles.length;
    const ready = state.selectedFiles.length;
    const classes = [ready ? 'has-files' : 'has-warning'];
    if (ignored || excluded) classes.push('has-warning');
    els.folderStatus.className = `folder-status ${classes.join(' ')}`;

    const scope = els.scanSubfolders.checked ? 'supported files' : 'supported root-level files';
    const readyText = ready ? `${countLabel(ready, 'supported file', 'supported files')} ready` : 'No supported files remain';
    const ignoredText = ignored ? ` · ${countLabel(ignored, 'unsupported file')} skipped` : '';
    const excludedText = excluded ? ` · ${countLabel(excluded, 'supported nested file')} excluded` : '';
    const scanText = els.scanSubfolders.checked ? 'Nested folders included' : 'Root level only';
    els.folderStatus.textContent = `${state.selectedFolderName} · ${countLabel(state.selectedFolderCount, 'folder')} selected · ${readyText} (${scope}) · ${countLabel(state.selectedFileCount, 'file')} found${ignoredText}${excludedText}. ${scanText}.`;
  }

  function folderEmptyMessage() {
    if (!state.folderSelected) return 'Choose a project folder before analyzing.';
    if (state.excludedNestedFiles.length) {
      return `No supported files are available at the root level. ${countLabel(state.excludedNestedFiles.length, 'supported nested file')} are excluded because Scan nested folders is off.`;
    }
    return 'This folder contains no supported Python or project metadata files. Unsupported files were skipped.';
  }

  function syncFolderMessage() {
    if (!state.folderSelected) return;
    if (!state.selectedFiles.length) {
      showMessage(folderEmptyMessage(), 'error');
      return;
    }
    if (state.excludedNestedFiles.length) {
      showMessage(`${countLabel(state.excludedNestedFiles.length, 'supported nested file')} excluded because Scan nested folders is off.`, 'notice');
      return;
    }
    if (state.unsupportedFiles.length) {
      showMessage(`${countLabel(state.unsupportedFiles.length, 'unsupported file')} will be skipped. The supported files are ready to analyze.`, 'notice');
      return;
    }
    hideMessage();
  }

  function updateAnalyzeButton() {
    const hasFolder = state.folderSelected;
    els.analyzeLabel.textContent = hasFolder ? 'Analyze folder' : 'Analyze project';
    els.analyze.setAttribute('aria-label', hasFolder ? 'Analyze selected folder' : 'Analyze typed project path');
  }

  function resetFolderSelection(updateStatus = true) {
    state.allSelectedFiles = [];
    state.selectedFiles = [];
    state.selectedFileCount = 0;
    state.selectedFolderCount = 0;
    state.unsupportedFiles = [];
    state.excludedNestedFiles = [];
    state.selectedFolderName = '';
    state.folderSelected = false;
    els.folderInput.value = '';
    if (updateStatus) renderFolderStatus();
    updateAnalyzeButton();
  }

  function recomputeFolderSelection() {
    if (!state.folderSelected) return;
    state.scanSubfolders = els.scanSubfolders.checked;
    const supportedFiles = state.allSelectedFiles.filter(isSupportedFile);
    state.unsupportedFiles = state.allSelectedFiles.filter((file) => !isSupportedFile(file));
    state.excludedNestedFiles = state.scanSubfolders ? [] : supportedFiles.filter((file) => !isRootLevelFile(file));
    state.selectedFiles = state.scanSubfolders ? supportedFiles : supportedFiles.filter(isRootLevelFile);
    renderFolderStatus();
    updateAnalyzeButton();
  }

  function handleFolderSelection() {
    const files = Array.from(els.folderInput.files || []);
    if (!files.length) {
      resetFolderSelection();
      showMessage('No files were selected. Choose a project folder before analyzing.', 'error');
      els.folderButton.focus();
      return;
    }

    const roots = folderRoots(files);
    state.allSelectedFiles = files;
    state.selectedFileCount = files.length;
    state.selectedFolderCount = roots.size || 1;
    state.selectedFolderName = roots.size === 1 ? [...roots][0] : `${roots.size} selected folders`;
    state.folderSelected = true;

    /* The path bar is a privacy-safe browser-relative label, never a local path. */
    els.path.value = state.selectedFolderName;
    recomputeFolderSelection();
    syncFolderMessage();
  }

  function handleScanPreferenceChange() {
    state.scanSubfolders = els.scanSubfolders.checked;
    if (state.folderSelected) {
      recomputeFolderSelection();
      syncFolderMessage();
    }
  }

  function handlePathInput() {
    if (!state.folderSelected) return;
    resetFolderSelection();
    if (!state.loading) hideMessage();
  }

  function finishLoad() {
    state.alerts = state.analysis.alerts;
    setLoading(false);
    els.welcome.hidden = true;
    els.results.hidden = false;
    hideMessage();
    els.meta.textContent = `${state.analysis.path} · ${formatTime(state.analysis.created_at)}`;
    restoreFilters();
    renderSummary();
    applyFilters(false);
    history.replaceState({}, '', updateUrl());
    els.results.scrollIntoView({ behavior: motionAllowed() ? 'smooth' : 'auto', block: 'start' });
  }

  function setLoading(value, text) {
    state.loading = value;
    els.analyze.disabled = value;
    els.demo.disabled = value;
    els.welcomeDemo.disabled = value;
    els.folderButton.disabled = value;
    els.folderInput.disabled = value;
    els.path.disabled = value;
    els.includeTests.disabled = value;
    els.scanSubfolders.disabled = value;
    if (value) showMessage(text, 'loading');
  }

  function showMessage(text, type, retry) {
    els.message.hidden = false;
    els.message.className = `global-message ${type || ''}`;
    els.message.textContent = text;
    if (retry) {
      const button = document.createElement('button');
      button.className = 'button button-quiet';
      button.textContent = 'Load demo';
      button.addEventListener('click', loadDemo);
      els.message.append(button);
    }
  }

  function hideMessage() {
    els.message.hidden = true;
    els.message.textContent = '';
  }

  function formatTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'just now' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }

  function counts() {
    return state.alerts.reduce((out, alert) => {
      out[alert.status] += 1;
      return out;
    }, { REACHABLE: 0, NOT_PROVEN_REACHABLE: 0, UNKNOWN: 0 });
  }

  function renderSummary() {
    const total = state.alerts.length;
    const count = counts();
    const percent = (number) => total ? `${(number / total) * 100}%` : '0%';
    els.summary.innerHTML = `<div class="summary-lead"><div class="summary-total">${total}</div><div class="summary-copy"><p class="mono-label">signals found</p><p><strong>${count.REACHABLE} reachable</strong>, ${count.NOT_PROVEN_REACHABLE} not proven reachable,<br>${count.UNKNOWN} unknown</p></div></div><div class="summary-bar-wrap"><div class="summary-bar" aria-label="${count.REACHABLE} reachable, ${count.NOT_PROVEN_REACHABLE} not proven reachable, ${count.UNKNOWN} unknown"><span class="bar-reachable" style="width:${percent(count.REACHABLE)}"></span><span class="bar-not-proven" style="width:${percent(count.NOT_PROVEN_REACHABLE)}"></span><span class="bar-unknown" style="width:${percent(count.UNKNOWN)}"></span></div><div class="summary-legend"><span class="legend-item"><i class="bar-reachable"></i><strong>${count.REACHABLE}</strong> reachable</span><span class="legend-item"><i class="bar-not-proven"></i><strong>${count.NOT_PROVEN_REACHABLE}</strong> not proven</span><span class="legend-item"><i class="bar-unknown"></i><strong>${count.UNKNOWN}</strong> unknown</span></div></div>`;
  }

  function applyFilters(updateHistory = true) {
    const query = els.search.value.trim().toLowerCase();
    const status = els.status.value;
    const severity = els.severity.value;
    state.filtered = state.alerts.filter((alert) => {
      const text = [alert.package, alert.advisory_id, alert.reason, alert.reason_code, alert.symbol_source, ...alert.evidence.map((item) => `${item.label || ''} ${item.symbol || ''}`)].join(' ').toLowerCase();
      return (!query || text.includes(query)) && (status === 'all' || alert.status === status) && (severity === 'all' || alert.severity === severity);
    });
    const order = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
    const sort = els.sort.value;
    state.filtered.sort((a, b) => sort === 'severity'
      ? (order[a.severity] - order[b.severity])
      : sort === 'status'
        ? a.status.localeCompare(b.status)
        : sort === 'package'
          ? a.package.localeCompare(b.package)
          : a.advisory_id.localeCompare(b.advisory_id));
    renderRows();
    if (updateHistory) history.replaceState({}, '', updateUrl());
  }

  function renderRows() {
    const noMatches = state.filtered.length === 0;
    const noAdvisories = state.alerts.length === 0;
    const noInventory = state.analysis?.advisory_source === 'none';
    els.count.textContent = `${state.filtered.length} of ${state.alerts.length}`;
    els.empty.hidden = !noMatches;
    if (noMatches) {
      els.emptyTitle.textContent = noAdvisories ? (noInventory ? 'No advisory inventory was provided' : 'No matching advisories found') : 'No alerts in this part of the notebook';
      els.emptyCopy.textContent = noAdvisories
        ? (noInventory ? 'Add osv_records.json or pip-audit.json to the project, or configure an offline OSV cache, then analyze again.' : 'The analyzer found no cached advisory that matches this project. You can still review the analysis summary above.')
        : 'Try widening your filters or searching for a different package.';
      els.emptyClear.hidden = noAdvisories;
    }
    els.list.innerHTML = state.filtered.map((alert) => `<tr><td><div class="dependency-cell"><span class="package-icon" aria-hidden="true">${escapeHtml(alert.package.slice(0, 2).toUpperCase())}</span><div><div class="package-name">${escapeHtml(alert.package)}</div><div class="package-version">${escapeHtml(alert.version)}</div></div></div></td><td><span class="severity severity-${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span></td><td><span class="status-badge ${statusClass(alert.status)}">${statusLabel(alert.status)}</span></td><td><span class="advisory-id">${escapeHtml(alert.advisory_id)}</span></td><td><button class="row-detail" type="button" data-alert-id="${escapeHtml(alert.id)}" aria-label="Open details for ${escapeHtml(alert.package)}">→</button></td></tr>`).join('');
    els.list.querySelectorAll('[data-alert-id]').forEach((button) => button.addEventListener('click', () => openDrawer(state.alerts.find((alert) => alert.id === button.dataset.alertId))));
  }

  function statusClass(status) {
    return status === 'REACHABLE' ? 'status-reachable' : status === 'NOT_PROVEN_REACHABLE' ? 'status-not-proven' : 'status-unknown';
  }

  function statusLabel(status) {
    return status === 'NOT_PROVEN_REACHABLE' ? 'not proven' : status.toLowerCase();
  }

  function updateUrl() {
    const params = new URLSearchParams();
    if (els.search.value) params.set('q', els.search.value);
    if (els.status.value !== 'all') params.set('status', els.status.value);
    if (els.severity.value !== 'all') params.set('severity', els.severity.value);
    if (els.sort.value !== 'severity') params.set('sort', els.sort.value);
    const query = params.toString();
    return query ? `${location.pathname}?${query}` : location.pathname;
  }

  function restoreFilters() {
    const params = new URLSearchParams(location.search);
    els.search.value = params.get('q') || '';
    els.status.value = params.get('status') || 'all';
    els.severity.value = params.get('severity') || 'all';
    els.sort.value = params.get('sort') || 'severity';
  }

  function clearFilters() {
    els.search.value = '';
    els.status.value = 'all';
    els.severity.value = 'all';
    els.sort.value = 'severity';
    applyFilters();
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
  }

  function openDrawer(alert) {
    if (!alert) return;
    state.activeAlert = alert;
    state.lastFocus = document.activeElement;
    els.drawerIndex.textContent = `${String(state.alerts.indexOf(alert) + 1).padStart(2, '0')} / ${alert.package}`;
    els.drawerContent.innerHTML = drawerMarkup(alert);
    renderCytoscape(alert);
    els.backdrop.hidden = false;
    els.drawer.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => els.drawer.classList.add('open'));
    setTimeout(() => els.drawer.focus(), 20);
  }

  function closeDrawer() {
    els.drawer.classList.remove('open');
    els.drawer.setAttribute('aria-hidden', 'true');
    setTimeout(() => {
      els.backdrop.hidden = true;
      if (state.lastFocus) state.lastFocus.focus();
      state.activeAlert = null;
    }, motionAllowed() ? 480 : 0);
  }

  function drawerMarkup(alert) {
    return `<h2 id="drawer-title">${escapeHtml(alert.package)}</h2><p class="drawer-advisory">${escapeHtml(alert.version)} · ${escapeHtml(alert.advisory_id)}</p><div class="drawer-status-row"><span class="status-badge ${statusClass(alert.status)}">${statusLabel(alert.status)}</span><span class="confidence">confidence <span>${escapeHtml(alert.confidence)}</span></span><span class="confidence">source <span>${escapeHtml(alert.symbol_source)}</span></span></div><div class="why-box"><p class="section-kicker">WHY THIS STATUS</p><p>${escapeHtml(alert.reason)}</p></div><p class="drawer-description">${escapeHtml(alert.advisory_text)}</p>${snippetMarkup(alert)}${graphMarkup(alert)}<div class="detail-section"><div class="detail-section-title"><p class="section-kicker">SUGGESTED FIX</p><span class="source-label">advisory metadata</span></div><p class="dynamic-note">Upgrade to <strong>${escapeHtml(alert.fixed_version || 'a patched release')}</strong>, then re-run the analysis. A version bump changes the dependency; it does not prove the project is safe.</p></div>`;
  }

  function snippetMarkup(alert) {
    if (!alert.snippets.length) return '';
    return `<div class="detail-section"><div class="detail-section-title"><p class="section-kicker">SOURCE EVIDENCE</p><span class="source-label">${escapeHtml(alert.snippets[0].file || 'source')}</span></div><div class="code-block">${(alert.snippets[0].lines || []).map((line) => `<div class="code-line ${Number(line.number) === Number(alert.snippets[0].highlight) ? 'highlight' : ''}"><span class="line-number">${line.number}</span><span>${escapeHtml(line.text)}</span></div>`).join('')}</div></div>`;
  }

  function renderCytoscape(alert) {
    const container = els.drawerContent.querySelector('.cy-graph');
    if (!container || !window.cytoscape) return;
    const chain = alert.evidence || [];
    const graph = alert.graph || {
      nodes: chain.map((hop, index) => ({ id: String(index), label: hop.symbol || hop.label || hop.file, type: index === chain.length - 1 ? 'library' : 'user' })),
      edges: chain.slice(1).map((hop, index) => ({ from: String(index), to: String(index + 1), kind: 'reachable' }))
    };
    const elements = [
      ...(graph.nodes || []).map((node) => ({ data: { id: String(node.id), label: String(node.label || node.id), type: node.type || 'user' } })),
      ...(graph.edges || []).map((edge) => ({ data: { id: `${edge.from}-${edge.to}`, source: String(edge.from || edge.source), target: String(edge.to || edge.target), kind: edge.kind || 'reachable' } }))
    ];
    try {
      window.cytoscape({
        container,
        elements,
        layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.1, padding: 18 },
        userZoomingEnabled: false,
        userPanningEnabled: false,
        style: [
          { selector: 'node', style: { 'background-color': '#168f89', label: 'data(label)', color: '#201914', 'font-size': 10, 'text-wrap': 'ellipsis', 'text-max-width': 90, 'text-valign': 'bottom', 'text-margin-y': 7, width: 18, height: 18 } },
          { selector: 'node[type = "library"]', style: { 'background-color': '#ff6b5b' } },
          { selector: 'edge', style: { 'curve-style': 'bezier', 'line-color': '#ff6b5b', 'target-arrow-color': '#ff6b5b', 'target-arrow-shape': 'triangle', width: 2 } },
          { selector: 'edge[kind = "dynamic"]', style: { 'line-style': 'dashed', 'line-color': '#168f89', 'target-arrow-color': '#168f89' } }
        ]
      });
      container.classList.add('has-cytoscape');
    } catch (_) {
      // The inline SVG below remains visible as an offline-safe fallback.
    }
  }

  function graphMarkup(alert) {
    const graph = alert.graph;
    const chain = alert.evidence;
    if (!graph && !chain.length) return '';
    const nodes = graph?.nodes || chain.map((hop, index) => ({ id: String(index), label: hop.symbol || hop.label, type: index === chain.length - 1 ? 'library' : 'user' }));
    const edges = graph?.edges || nodes.slice(1).map((node, index) => ({ from: nodes[index].id, to: node.id, kind: 'reachable' }));
    const width = 470;
    const step = Math.max(1, Math.floor((width - 45) / Math.max(nodes.length, 1)));
    const nodeSvg = nodes.map((node, index) => {
      const x = 18 + index * step;
      const label = String(node.label || '').slice(0, 17);
      return `<g class="graph-node ${node.type === 'library' ? 'library' : 'user'}"><rect x="${x}" y="78" width="${Math.min(125, step - 8)}" height="49" rx="4"></rect><text x="${x + 10}" y="101">${escapeHtml(label)}</text><text x="${x + 10}" y="118" opacity=".55">${node.type === 'library' ? 'library' : 'your code'}</text></g>`;
    }).join('');
    const edgeSvg = edges.map((edge) => {
      const from = nodes.findIndex((node) => node.id === edge.from);
      const to = nodes.findIndex((node) => node.id === edge.to);
      if (from < 0 || to < 0) return '';
      const x1 = 18 + from * step + Math.min(125, step - 8);
      const x2 = 18 + to * step;
      return `<path class="graph-edge ${edge.kind === 'dynamic' ? 'dynamic' : 'reachable'}" d="M${x1} 102 C${x1 + 12} 56, ${x2 - 12} 56, ${x2} 102" marker-end="url(#arrow)"></path>`;
    }).join('');
    return `<div class="detail-section"><div class="detail-section-title"><p class="section-kicker">CALL CHAIN</p><span class="source-label">static path view</span></div><div class="call-graph" role="img" aria-label="Call chain from your code to the dependency"><svg viewBox="0 0 ${width} 205" preserveAspectRatio="xMidYMid meet"><defs><marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="none" stroke="var(--coral)" stroke-width="1"></path></marker></defs>${edgeSvg}${nodeSvg}</svg></div><div class="graph-legend"><span><i></i> evidence path</span><span><i class="dashed"></i> dynamic gap</span></div></div>`;
  }

  function reportMarkdown() {
    const analysis = state.analysis;
    const count = counts();
    return `# reachable report\n\n**Project:** ${analysis.path}\n**Analyzed:** ${formatTime(analysis.created_at)}\n\n## Summary\n\n- ${state.alerts.length} alerts\n- ${count.REACHABLE} reachable\n- ${count.NOT_PROVEN_REACHABLE} not proven reachable\n- ${count.UNKNOWN} unknown\n\n> Not proven reachable is not the same as safe. It means static analysis did not find a path.\n\n## Alerts\n\n${state.alerts.map((alert) => `### ${alert.package} ${alert.version}\n\n- **Status:** ${statusLabel(alert.status)}\n- **Advisory:** ${alert.advisory_id}\n- **Severity:** ${alert.severity}\n- **Reason:** ${alert.reason}\n- **Confidence:** ${alert.confidence}\n- **Symbol source:** ${alert.symbol_source}`).join('\n\n')}`;
  }

  function reportHtml() {
    const analysis = state.analysis;
    return `<!doctype html><html><head><meta charset="utf-8"><title>reachable report · ${escapeHtml(analysis.path)}</title><style>body{max-width:800px;margin:50px auto;padding:0 22px;background:#f7efd9;color:#201914;font:15px Arial,sans-serif;line-height:1.6}h1,h2{font-family:Arial Black,Arial,sans-serif}article{padding:18px 22px;margin:16px 0;background:#fff9eb;border:3px solid #201914;box-shadow:5px 5px 0 #201914}small{color:#76685a}strong{color:#d84c43}</style></head><body><h1>reachable report</h1><p><small>${escapeHtml(analysis.path)} · ${escapeHtml(formatTime(analysis.created_at))}</small></p><h2>${state.alerts.length} alerts</h2>${state.alerts.map((alert) => `<article><h3>${escapeHtml(alert.package)} <small>${escapeHtml(alert.version)}</small></h3><p><strong>${escapeHtml(statusLabel(alert.status))}</strong> · ${escapeHtml(alert.advisory_id)} · ${escapeHtml(alert.severity)}</p><p>${escapeHtml(alert.reason)}</p></article>`).join('')}<p><small>Not proven reachable is not the same as safe. This report records static evidence only.</small></p></body></html>`;
  }

  function download(content, filename, type) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([content], { type }));
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    showToast(`Downloaded ${filename}`);
  }

  function showToast(text) {
    els.toast.textContent = text;
    els.toast.hidden = false;
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => {
      els.toast.hidden = true;
    }, 2800);
  }

  function motionAllowed() {
    return !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function applyTheme(theme) {
    const dark = theme === 'dark';
    document.body.classList.toggle('dark', dark);
    localStorage.setItem('reachable-theme', theme);
    els.theme.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} mode`);
    els.theme.setAttribute('aria-pressed', String(dark));
    document.querySelector('meta[name="theme-color"]').setAttribute('content', dark ? '#211b18' : '#f7efd9');
  }

  function focusableDrawerElements() {
    return [...els.drawer.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter((element) => !element.disabled);
  }

  function handleDocumentKeydown(event) {
    if (event.key === 'Escape' && !els.backdrop.hidden) {
      closeDrawer();
      return;
    }
    if (event.key === 'Tab' && !els.backdrop.hidden) {
      const focusable = focusableDrawerElements();
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
      return;
    }
    if (event.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
      event.preventDefault();
      if (!els.results.hidden) els.search.focus();
    }
  }

  function init() {
    const savedTheme = localStorage.getItem('reachable-theme');
    applyTheme(savedTheme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
    state.scanSubfolders = els.scanSubfolders.checked;
    els.demo.addEventListener('click', loadDemo);
    els.welcomeDemo.addEventListener('click', loadDemo);
    els.analyze.addEventListener('click', analyze);
    els.refresh.addEventListener('click', () => state.analysis?.path === 'fixtures/demo_app' ? loadDemo() : analyze());
    [els.search, els.status, els.severity, els.sort].forEach((element) => element.addEventListener(element === els.search ? 'input' : 'change', () => applyFilters()));
    els.clear.addEventListener('click', clearFilters);
    els.emptyClear.addEventListener('click', clearFilters);
    els.theme.addEventListener('click', () => applyTheme(document.body.classList.contains('dark') ? 'light' : 'dark'));
    els.scanSubfolders.addEventListener('change', handleScanPreferenceChange);
    els.closeDrawer.addEventListener('click', closeDrawer);
    els.backdrop.addEventListener('click', closeDrawer);
    els.exportMd.addEventListener('click', () => {
      if (state.analysis) download(reportMarkdown(), 'reachable-report.md', 'text/markdown');
    });
    els.exportHtml.addEventListener('click', () => {
      if (state.analysis) download(reportHtml(), 'reachable-report.html', 'text/html');
    });
    document.addEventListener('keydown', handleDocumentKeydown);
  }

  function bindFolderPicker() {
    els.folderButton.addEventListener('click', () => els.folderInput.click());
    els.folderInput.addEventListener('change', handleFolderSelection);
    els.path.addEventListener('input', handlePathInput);
    renderFolderStatus();
    updateAnalyzeButton();
  }

  init();
  bindFolderPicker();
  if (document.body.dataset.demo === 'true') loadDemo();
})();
