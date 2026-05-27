/**
 * SecuScan AI — Frontend controller
 * Uses window.__TAURI__ globals (withGlobalTauri: true in tauri.conf.json)
 */

// ─── Tauri bindings ────────────────────────────────────────────────────────────
const { invoke }  = window.__TAURI__.core;
const { listen }  = window.__TAURI__.event;
const { open }    = window.__TAURI__.dialog;
const { writeTextFile, BaseDirectory } = window.__TAURI__.fs;

// ─── State ────────────────────────────────────────────────────────────────────
let currentScan    = null;
let activeVulnId   = null;
let activeFilter   = 'all';
let searchQuery    = '';
let progressUnlisten = null;

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const scanZone        = $('scanZone');
const dropArea        = $('dropArea');
const scanProgress    = $('scanProgress');
const progressFill    = $('progressFill');
const progressCount   = $('progressCount');
const progressFile    = $('progressFile');
const statsRow        = $('statsRow');
const filterBar       = $('filterBar');
const resultsContainer = $('resultsContainer');
const vulnList        = $('vulnList');
const detailEmpty     = $('detailEmpty');
const detailContent   = $('detailContent');

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  try {
    const ver = await invoke('get_version');
    $('appVersion').textContent = `v${ver}`;
  } catch (_) {}

  await refreshKeyStatus();
  setupDragDrop();
  setupButtons();
  setupFilters();
  setupSettings();
}

// ─── Drag & Drop ──────────────────────────────────────────────────────────────
function setupDragDrop() {
  // Prevent browser default
  document.addEventListener('dragover', e => { e.preventDefault(); e.stopPropagation(); });
  document.addEventListener('drop', e => { e.preventDefault(); e.stopPropagation(); });

  dropArea.addEventListener('dragover', e => {
    e.preventDefault();
    dropArea.classList.add('drag-over');
  });
  dropArea.addEventListener('dragleave', () => dropArea.classList.remove('drag-over'));
  dropArea.addEventListener('drop', async e => {
    e.preventDefault();
    dropArea.classList.remove('drag-over');
    const items = [...(e.dataTransfer?.items || [])];
    const dir   = items.find(i => i.kind === 'file')?.getAsFile();
    if (dir) startScan(dir.path);
  });
}

function setupButtons() {
  $('btnPickFolder').addEventListener('click', async () => {
    const dir = await open({ directory: true, multiple: false, title: 'Select folder to scan' });
    if (dir) startScan(dir);
  });

  $('btnCancel').addEventListener('click', async () => {
    await invoke('cancel_scan');
    toast('Scan cancelled');
  });

  $('btnNewScan').addEventListener('click', resetToScanZone);

  $('btnSettings').addEventListener('click', () => {
    $('settingsModal').classList.remove('hidden');
  });

  $('btnExportJson').addEventListener('click', () => exportReport('json'));
  $('btnExportCsv').addEventListener('click', () => exportReport('csv'));
  $('btnExportMd').addEventListener('click', () => exportReport('md'));

  $('btnGetFix').addEventListener('click', requestAiFix);
  $('btnCopyPrompt').addEventListener('click', copyAiPrompt);
}

function setupFilters() {
  document.querySelectorAll('.pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      activeFilter = pill.dataset.filter;
      renderVulnList();
    });
  });

  $('searchInput').addEventListener('input', e => {
    searchQuery = e.target.value.toLowerCase();
    renderVulnList();
  });
}

// ─── Scan ─────────────────────────────────────────────────────────────────────
async function startScan(path) {
  showProgress();

  // Subscribe to progress events
  if (progressUnlisten) { progressUnlisten(); progressUnlisten = null; }
  progressUnlisten = await listen('scan:progress', e => updateProgress(e.payload));

  const config = getScanConfig();

  try {
    currentScan = await invoke('start_scan', { path, config });
    showResults();
  } catch (err) {
    toast(`Scan error: ${err}`, true);
    resetToScanZone();
  } finally {
    if (progressUnlisten) { progressUnlisten(); progressUnlisten = null; }
  }
}

function getScanConfig() {
  return {
    max_file_size_mb:  parseFloat($('settingMaxSize')?.value || '50'),
    skip_git_dirs:     $('settingSkipGit')?.checked ?? true,
    skip_node_modules: $('settingSkipNode')?.checked ?? true,
    scan_executables:  $('settingScanBin')?.checked ?? true,
    include_info:      false,
  };
}

function updateProgress(p) {
  const pct = p.total > 0 ? Math.round((p.scanned / p.total) * 100) : 0;
  progressFill.style.width   = `${pct}%`;
  progressCount.textContent  = `${p.scanned} / ${p.total}`;
  progressFile.textContent   = p.current_file || '';
}

// ─── Show / hide states ───────────────────────────────────────────────────────
function showProgress() {
  dropArea.classList.add('hidden');
  scanProgress.classList.remove('hidden');
  statsRow.classList.add('hidden');
  filterBar.classList.add('hidden');
  resultsContainer.classList.add('hidden');
}

function showResults() {
  scanProgress.classList.add('hidden');
  dropArea.classList.add('hidden');
  statsRow.classList.remove('hidden');
  filterBar.classList.remove('hidden');
  resultsContainer.classList.remove('hidden');

  const s = currentScan.stats;
  $('numCritical').textContent = s.critical;
  $('numHigh').textContent     = s.high;
  $('numMedium').textContent   = s.medium;
  $('numLow').textContent      = s.low;
  $('numInfo').textContent     = s.info;
  $('numFiles').textContent    = currentScan.scanned_files;

  renderVulnList();
}

function resetToScanZone() {
  currentScan = null; activeVulnId = null;
  dropArea.classList.remove('hidden');
  scanProgress.classList.add('hidden');
  statsRow.classList.add('hidden');
  filterBar.classList.add('hidden');
  resultsContainer.classList.add('hidden');
  progressFill.style.width = '0%';
  progressCount.textContent = '0 / 0';
  progressFile.textContent  = 'Initializing…';
  vulnList.innerHTML = '';
  showDetailEmpty();
}

// ─── Vuln list rendering ──────────────────────────────────────────────────────
function renderVulnList() {
  if (!currentScan) return;

  const vulns = currentScan.vulnerabilities.filter(v => {
    if (activeFilter !== 'all' && v.severity !== activeFilter) return false;
    if (searchQuery) {
      const hay = `${v.title} ${v.file_path} ${v.cwe_id || ''} ${v.description}`.toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  });

  vulnList.innerHTML = '';

  if (vulns.length === 0) {
    vulnList.innerHTML = `<div style="color:var(--text-muted);padding:20px;text-align:center;font-size:13px;">No findings match filters</div>`;
    return;
  }

  vulns.forEach(v => {
    const el = document.createElement('div');
    el.className = 'vuln-item';
    el.dataset.id  = v.id;
    el.dataset.sev = v.severity;

    const fileShort = v.file_path.split(/[\\/]/).slice(-2).join('/');
    const line      = v.line_number ? `:${v.line_number}` : '';

    el.innerHTML = `
      <div class="vuln-item-header">
        <span class="vuln-item-title">${escHtml(v.title)}</span>
        <span class="sev-badge ${v.severity}">${v.severity.toUpperCase()}</span>
      </div>
      <div class="vuln-item-file">${escHtml(fileShort)}${line}</div>
      <div class="vuln-item-meta">${v.cwe_id || ''}</div>
    `;

    el.addEventListener('click', () => selectVuln(v));
    vulnList.appendChild(el);
  });
}

// ─── Detail panel ─────────────────────────────────────────────────────────────
function selectVuln(v) {
  activeVulnId = v.id;

  // Update list selection
  document.querySelectorAll('.vuln-item').forEach(el => {
    el.classList.toggle('active', el.dataset.id === v.id);
  });

  // Populate detail
  const badge = $('detailSeverity');
  badge.textContent = v.severity.toUpperCase();
  badge.className   = `detail-badge sev-badge ${v.severity}`;

  $('detailTitle').textContent = v.title;
  $('detailFile').textContent  = v.file_path;
  $('detailLine').textContent  = v.line_number ? `Line ${v.line_number}` : '';
  $('detailCwe').textContent   = v.cwe_id || '';
  $('detailDesc').textContent  = v.description;
  $('detailSnippet').textContent = v.code_snippet || v.matched_pattern || '(no code context)';
  $('detailFix').textContent   = v.remediation;

  // Reset AI panel
  $('aiResult').classList.add('hidden');
  $('aiLoading').classList.add('hidden');

  showDetailContent();
}

function showDetailContent() {
  detailEmpty.classList.add('hidden');
  detailContent.classList.remove('hidden');
}
function showDetailEmpty() {
  detailContent.classList.add('hidden');
  detailEmpty.classList.remove('hidden');
}

// ─── AI Fix ───────────────────────────────────────────────────────────────────
async function requestAiFix() {
  if (!activeVulnId) return toast('Select a vulnerability first');

  const provider = $('aiProvider').value;
  $('aiResult').classList.add('hidden');
  $('aiLoading').classList.remove('hidden');
  $('btnGetFix').disabled = true;

  try {
    const result = await invoke('request_ai_fix', {
      req: { vulnerability_id: activeVulnId, provider }
    });

    $('aiExplanation').textContent = result.explanation;
    $('aiFixCode').textContent     = result.fixed_code || '(no code generated)';
    $('aiResult').classList.remove('hidden');
  } catch (err) {
    toast(`AI error: ${err}`, true);
  } finally {
    $('aiLoading').classList.add('hidden');
    $('btnGetFix').disabled = false;
  }
}

async function copyAiPrompt() {
  if (!activeVulnId) return toast('Select a vulnerability first');
  try {
    const prompt = await invoke('build_clipboard_prompt', { vulnId: activeVulnId });
    await navigator.clipboard.writeText(prompt);
    toast('Prompt copied to clipboard!');
  } catch (err) {
    toast(`Copy error: ${err}`, true);
  }
}

// ─── Export ───────────────────────────────────────────────────────────────────
async function exportReport(format) {
  if (!currentScan) return;

  try {
    let content, ext, mime;

    if (format === 'json') {
      content = await invoke('export_json');
      ext = 'json'; mime = 'application/json';
    } else if (format === 'csv') {
      content = await invoke('export_csv');
      ext = 'csv'; mime = 'text/csv';
    } else {
      content = await invoke('export_markdown');
      ext = 'md'; mime = 'text/markdown';
    }

    // Save via browser download API
    const blob = new Blob([content], { type: mime });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const date = new Date().toISOString().slice(0, 10);
    a.href     = url;
    a.download = `secuscan-report-${date}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Report exported as .${ext}`);
  } catch (err) {
    toast(`Export error: ${err}`, true);
  }
}

// ─── Settings ─────────────────────────────────────────────────────────────────
function setupSettings() {
  $('btnCloseSettings').addEventListener('click', () => {
    $('settingsModal').classList.add('hidden');
  });
  $('settingsModal').addEventListener('click', e => {
    if (e.target === $('settingsModal')) $('settingsModal').classList.add('hidden');
  });

  // Save / delete key buttons
  document.querySelectorAll('.btn-save-key[data-provider]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const provider = btn.dataset.provider;
      const input    = $(`key${capitalize(provider)}`);
      if (!input?.value.trim()) return toast('Enter a key first');
      try {
        await invoke('save_api_key', { provider, key: input.value.trim() });
        input.value = '';
        toast(`${capitalize(provider)} key saved`);
        await refreshKeyStatus();
      } catch (err) {
        toast(`Save error: ${err}`, true);
      }
    });
  });

  document.querySelectorAll('.btn-del-key').forEach(btn => {
    btn.addEventListener('click', async () => {
      const provider = btn.dataset.provider;
      try {
        await invoke('delete_api_key', { provider });
        toast(`${capitalize(provider)} key deleted`);
        await refreshKeyStatus();
      } catch (err) {
        toast(`Delete error: ${err}`, true);
      }
    });
  });

  $('btnSaveEndpoint').addEventListener('click', async () => {
    const ep = $('endpointAntigravity').value.trim();
    if (!ep) return toast('Enter endpoint URL');
    try {
      await invoke('save_antigravity_endpoint', { endpoint: ep });
      toast('Endpoint saved');
    } catch (err) {
      toast(`Error: ${err}`, true);
    }
  });
}

async function refreshKeyStatus() {
  try {
    const status = await invoke('get_key_status');
    for (const provider of ['claude', 'gemini', 'antigravity']) {
      const el = $(`status${capitalize(provider)}`);
      if (el) {
        el.textContent  = status[provider] ? '✓ Configured' : '✗ Not set';
        el.className    = `key-status ${status[provider] ? 'ok' : 'nok'}`;
      }
    }
    if (status.antigravity_endpoint) {
      $('endpointAntigravity').value = status.antigravity_endpoint;
    }
  } catch (_) {}
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $('toast');
  el.textContent = msg;
  el.style.borderColor = isError ? 'var(--critical)' : 'var(--border-glow)';
  el.style.color       = isError ? 'var(--critical)' : 'var(--text)';
  el.classList.remove('hidden');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3000);
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
