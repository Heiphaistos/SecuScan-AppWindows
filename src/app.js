/**
 * SecuScan AI — Frontend controller
 * Uses window.__TAURI__ globals (withGlobalTauri: true in tauri.conf.json)
 */

// ─── Tauri bindings ────────────────────────────────────────────────────────────
const { invoke }  = window.__TAURI__.core;
const { listen }  = window.__TAURI__.event;
const { open, save } = window.__TAURI__.dialog;
const { writeTextFile, BaseDirectory } = window.__TAURI__.fs;
// Plugins de mise a jour. `withGlobalTauri` les expose sous window.__TAURI__ ;
// ils sont absents en dehors d'un build Tauri, d'ou le garde-fou.
const updaterApi = window.__TAURI__.updater;

// ─── State ────────────────────────────────────────────────────────────────────
let currentScan      = null;
let activeVulnId     = null;
let activeFilter     = 'all';
let searchQuery      = '';
let hideLikelyFp     = false;
let progressUnlisten = null;
let scanStartTime    = null;
let timerInterval    = null;
let batchPatches     = [];     // FilePatch[] returned by batch_ai_fix
let batchUnlisten    = null;

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
  } catch (err) {
    console.error('[version] lecture impossible', err);
  }

  await refreshKeyStatus();
  setupDragDrop();
  setupButtons();
  setupFilters();
  setupSettings();

  // Verification silencieuse au demarrage : si le canal est injoignable,
  // l'utilisateur ne voit rien et continue de travailler.
  checkForUpdate(true);
}

// ─── Mise à jour automatique ──────────────────────────────────────────────────
// Meme mecanique que Nitrite : le plugin officiel de Tauri lit un manifeste
// signe sur secuscan-app.heiphaistos.org/maj/latest.json, telecharge
// l'installeur NSIS leger, le lance, et arrete l'application lui-meme en
// passant /R a NSIS pour qu'elle redemarre. Rien a relancer nous-memes.
async function checkForUpdate(silencieux = true) {
  if (!updaterApi) return false; // hors build Tauri : rien a remplacer

  const status = $('statusUpdate');
  if (!silencieux && status) status.textContent = 'Vérification…';

  try {
    const update = await updaterApi.check();
    if (!update) {
      if (!silencieux) {
        if (status) status.textContent = 'À jour';
        toast('SecuScan est à jour.');
      }
      return false;
    }

    if (status) status.textContent = `v${update.version} disponible`;
    const notes = update.body ? `

${update.body}` : '';
    const accepte = await window.__TAURI__.dialog.ask(
      `SecuScan ${update.version} est disponible (vous avez la ${update.currentVersion}).${notes}` +
      `

Voulez-vous la mettre à jour maintenant ? L'application redémarrera.`,
      { title: 'Une nouvelle version est sortie', kind: 'info' },
    );
    if (!accepte) return false;

    // Ne rend jamais la main : le plugin arrête l'application pour laisser
    // l'installeur remplacer les fichiers, puis NSIS la relance.
    await update.downloadAndInstall();
    return true;
  } catch (err) {
    // Canal injoignable, serveur en panne, signature refusée : l'utilisateur
    // continue de travailler avec la version qu'il a.
    console.error('[maj] vérification impossible', err);
    if (!silencieux) {
      if (status) status.textContent = 'Échec';
      toast(`Vérification impossible : ${err}`, true);
    }
    return false;
  }
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
    const dir = await open({ directory: true, multiple: false, title: 'Choisir le dossier à analyser' });
    if (dir) startScan(dir);
  });

  $('btnCancel').addEventListener('click', async () => {
    await invoke('cancel_scan');
    toast('Analyse annulée');
  });

  $('btnNewScan').addEventListener('click', resetToScanZone);

  $('btnSettings').addEventListener('click', () => {
    $('settingsModal').classList.remove('hidden');
  });

  $('btnExportJson').addEventListener('click', () => exportReport('json'));
  $('btnExportCsv').addEventListener('click', () => exportReport('csv'));
  $('btnExportMd').addEventListener('click', () => exportReport('md'));
  $('btnExportTxt').addEventListener('click', () => exportReport('txt'));
  $('btnExportHtml').addEventListener('click', () => exportReport('html'));
  $('btnExportPdf').addEventListener('click', () => exportReport('pdf'));

  $('btnGetFix').addEventListener('click', requestAiFix);
  $('btnCopyPrompt').addEventListener('click', copyAiPrompt);

  // Batch fix
  $('btnBatchFix').addEventListener('click', openBatchModal);
  $('btnCloseBatch').addEventListener('click', closeBatchModal);
  $('batchModal').addEventListener('click', e => { if (e.target === $('batchModal')) closeBatchModal(); });
  $('btnStartBatch').addEventListener('click', runBatchFix);
  $('btnApplyAll').addEventListener('click', applyAllPatches);
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

  $('hideLikelyFp').addEventListener('change', e => {
    hideLikelyFp = e.target.checked;
    renderVulnList();
  });
}

// ─── Timer ────────────────────────────────────────────────────────────────────
function startTimer() {
  scanStartTime = Date.now();
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
    const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
    const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
    const s = (elapsed % 60).toString().padStart(2, '0');
    $('elapsedTime').textContent = `${h}:${m}:${s}`;
  }, 500);
}

function stopTimer() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

// ─── Scan ─────────────────────────────────────────────────────────────────────
async function startScan(path) {
  showProgress();
  startTimer();

  // Subscribe to progress events
  if (progressUnlisten) { progressUnlisten(); progressUnlisten = null; }
  progressUnlisten = await listen('scan:progress', e => updateProgress(e.payload));

  const config = getScanConfig();

  try {
    currentScan = await invoke('start_scan', { path, config });
    stopTimer();
    showResults();
  } catch (err) {
    stopTimer();
    toast(`Erreur d'analyse : ${err}`, true);
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
  progressFill.style.width      = `${pct}%`;
  $('progressPct').textContent  = `${pct}%`;
  progressCount.textContent     = `${p.scanned} / ${p.total}`;
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

  renderAssessment(currentScan);
  renderVulnList();
}

function resetToScanZone() {
  currentScan = null; activeVulnId = null;
  stopTimer();
  dropArea.classList.remove('hidden');
  scanProgress.classList.add('hidden');
  statsRow.classList.add('hidden');
  filterBar.classList.add('hidden');
  resultsContainer.classList.add('hidden');
  $('assessPanel').classList.add('hidden');
  hideLikelyFp = false;
  $('hideLikelyFp').checked = false;
  progressFill.style.width     = '0%';
  $('progressPct').textContent = '0%';
  $('elapsedTime').textContent = '00:00:00';
  progressCount.textContent    = '0 / 0';
  progressFile.textContent  = 'Initialisation…';
  vulnList.innerHTML = '';
  showDetailEmpty();
}

// ─── Vuln list rendering ──────────────────────────────────────────────────────
function renderVulnList() {
  if (!currentScan) return;

  const vulns = currentScan.vulnerabilities.filter(v => {
    if (activeFilter !== 'all' && v.severity !== activeFilter) return false;
    if (hideLikelyFp && v.confidence < LIKELY_FP) return false;
    if (searchQuery) {
      const hay = `${v.title} ${v.file_path} ${v.cwe_id || ''} ${v.description}`.toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  });

  vulnList.innerHTML = '';

  if (vulns.length === 0) {
    vulnList.innerHTML = `<div style="color:var(--text-muted);padding:20px;text-align:center;font-size:13px;">Aucun résultat ne correspond aux filtres</div>`;
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
        <span class="sev-badge ${v.severity}">${sevLabel(v.severity)}</span>
      </div>
      <div class="vuln-item-file">${escHtml(fileShort)}${line}</div>
      <div class="vuln-item-meta">${escHtml(v.cwe_id || '')}</div>
    `;
    el.querySelector('.vuln-item-meta').appendChild(confidencePill(v));

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
  badge.textContent = sevLabel(v.severity);
  badge.className   = `detail-badge sev-badge ${v.severity}`;

  $('detailTitle').textContent = v.title;
  $('detailFile').textContent  = v.file_path;
  $('detailLine').textContent  = v.line_number ? `Ligne ${v.line_number}` : '';
  $('detailCwe').textContent   = v.cwe_id || '';
  $('detailDesc').textContent  = v.description;
  $('detailSnippet').textContent = v.code_snippet || v.matched_pattern || '(aucun extrait de code)';
  $('detailFix').textContent   = v.remediation;

  // Probabilité réel / faux positif, explications et calcul
  renderConfidence(v);

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
  if (!activeVulnId) return toast("Sélectionnez d'abord une vulnérabilité");

  const provider = $('aiProvider').value;
  $('aiResult').classList.add('hidden');
  $('aiLoading').classList.remove('hidden');
  $('btnGetFix').disabled = true;

  try {
    const result = await invoke('request_ai_fix', {
      req: { vulnerability_id: activeVulnId, provider }
    });

    $('aiExplanation').textContent = result.explanation;
    $('aiFixCode').textContent     = result.fixed_code || '(aucun code généré)';
    $('aiResult').classList.remove('hidden');
  } catch (err) {
    toast(`Erreur IA : ${err}`, true);
  } finally {
    $('aiLoading').classList.add('hidden');
    $('btnGetFix').disabled = false;
  }
}

async function copyAiPrompt() {
  if (!activeVulnId) return toast("Sélectionnez d'abord une vulnérabilité");
  try {
    const prompt = await invoke('build_clipboard_prompt', { vulnId: activeVulnId });
    await navigator.clipboard.writeText(prompt);
    toast('Prompt copié dans le presse-papiers');
  } catch (err) {
    toast(`Erreur de copie : ${err}`, true);
  }
}

// ─── Export ───────────────────────────────────────────────────────────────────
const EXPORT_META = {
  json: { cmd: 'export_json',     ext: 'json', label: 'JSON',     filter: 'Fichiers JSON'     },
  csv:  { cmd: 'export_csv',      ext: 'csv',  label: 'CSV',      filter: 'Fichiers CSV'      },
  md:   { cmd: 'export_markdown', ext: 'md',   label: 'Markdown', filter: 'Fichiers Markdown' },
  txt:  { cmd: 'export_txt',      ext: 'txt',  label: 'Texte',    filter: 'Fichiers texte'     },
  html: { cmd: 'export_html',     ext: 'html', label: 'HTML',     filter: 'Fichiers HTML'     },
  pdf:  { ext: 'pdf', label: 'PDF', filter: 'Fichiers PDF' },
};

async function exportReport(format) {
  if (!currentScan) return;
  const meta = EXPORT_META[format];
  if (!meta) return;

  try {
    const date     = new Date().toISOString().slice(0, 10);
    const filePath = await save({
      defaultPath: `secuscan-rapport-${date}.${meta.ext}`,
      filters: [{ name: meta.filter, extensions: [meta.ext] }],
    });
    if (!filePath) return; // user cancelled

    await invoke('save_report_to_file', { format, path: filePath });
    toast(`Rapport sauvegardé : ${filePath.split(/[\\/]/).pop()}`);
  } catch (err) {
    toast(`Erreur d'export : ${err}`, true);
  }
}

// ─── Settings ─────────────────────────────────────────────────────────────────
function setupSettings() {
  $('btnCheckUpdate').addEventListener('click', () => checkForUpdate(false));

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
      if (!input?.value.trim()) return toast("Saisissez d'abord une clé");
      try {
        await invoke('save_api_key', { provider, key: input.value.trim() });
        input.value = '';
        toast('Clé enregistrée');
        await refreshKeyStatus();
      } catch (err) {
        toast(`Erreur d'enregistrement : ${err}`, true);
      }
    });
  });

  document.querySelectorAll('.btn-del-key').forEach(btn => {
    btn.addEventListener('click', async () => {
      const provider = btn.dataset.provider;
      try {
        await invoke('delete_api_key', { provider });
        toast('Clé supprimée');
        await refreshKeyStatus();
      } catch (err) {
        toast(`Erreur de suppression : ${err}`, true);
      }
    });
  });

  $('settingFreeLookups').addEventListener('change', async e => {
    try {
      await invoke('set_intel_free_lookups', { enabled: e.target.checked });
      toast(e.target.checked ? 'Sources gratuites activées' : 'Sources gratuites coupées');
    } catch (err) {
      toast(`Erreur : ${err}`, true);
      await refreshKeyStatus();
    }
  });

  $('btnSaveEndpoint').addEventListener('click', async () => {
    const ep = $('endpointAntigravity').value.trim();
    if (!ep) return toast("Saisissez l'adresse du service");
    try {
      await invoke('save_antigravity_endpoint', { endpoint: ep });
      toast('Adresse enregistrée');
    } catch (err) {
      toast(`Erreur : ${err}`, true);
    }
  });
}

async function refreshKeyStatus() {
  try {
    const status = await invoke('get_key_status');
    for (const provider of ['claude', 'gemini', 'antigravity']) {
      const el = $(`status${capitalize(provider)}`);
      if (el) {
        el.textContent  = status[provider] ? '✓ Configurée' : '✗ Non configurée';
        el.className    = `key-status ${status[provider] ? 'ok' : 'nok'}`;
      }
    }
    if (status.antigravity_endpoint) {
      $('endpointAntigravity').value = status.antigravity_endpoint;
    }
    renderIntelKeyStatus(status);
  } catch (err) {
    console.error('[réglages] état des clés illisible', err);
  }
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Libellés français des gravités ; la valeur interne (critical, high...) ne change pas.
const SEV_LABELS = { critical: 'CRITIQUE', high: 'ÉLEVÉE', medium: 'MOYENNE', low: 'FAIBLE', info: 'INFO' };
function sevLabel(sev) {
  return SEV_LABELS[sev] || String(sev).toUpperCase();
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

// ─── Batch AI Fix ─────────────────────────────────────────────────────────────

function openBatchModal() {
  if (!currentScan || !currentScan.vulnerabilities.length) {
    return toast("Lancez d'abord une analyse", true);
  }
  // Reset state
  batchPatches = [];
  $('batchConfig').classList.remove('hidden');
  $('batchProgress').classList.add('hidden');
  $('batchResults').classList.add('hidden');
  $('batchFill').style.width = '0%';
  $('batchPct').textContent = '0%';
  $('batchCurrentFile').textContent = '';
  $('batchStatusLabel').textContent = 'Analyse en cours…';
  $('patchList').innerHTML = '';
  $('batchSummary').innerHTML = '';
  $('btnStartBatch').disabled = false;
  $('batchModal').classList.remove('hidden');
}

function closeBatchModal() {
  $('batchModal').classList.add('hidden');
  if (batchUnlisten) { batchUnlisten(); batchUnlisten = null; }
}

async function runBatchFix() {
  const provider = $('batchProvider').value;
  $('btnStartBatch').disabled = true;
  $('batchConfig').classList.add('hidden');
  $('batchProgress').classList.remove('hidden');
  $('batchResults').classList.add('hidden');

  // Subscribe to progress events
  if (batchUnlisten) { batchUnlisten(); batchUnlisten = null; }
  batchUnlisten = await listen('batch:progress', e => {
    const p = e.payload;
    const pct = p.total_files > 0 ? Math.round((p.file_idx / p.total_files) * 100) : 0;
    $('batchFill').style.width = pct + '%';
    $('batchPct').textContent  = pct + '%';
    $('batchCurrentFile').textContent = p.current_file;
    const isErr = p.status.startsWith('error');
    $('batchStatusLabel').textContent =
      isErr ? `⚠️ ${p.file_idx}/${p.total_files} — ${p.status.replace(/^error:\s*/, "erreur : ")}`
            : `Fichier ${p.file_idx} / ${p.total_files}`;
  });

  try {
    batchPatches = await invoke('batch_ai_fix', { provider });
    if (batchUnlisten) { batchUnlisten(); batchUnlisten = null; }
    $('batchProgress').classList.add('hidden');
    renderBatchResults();
  } catch (err) {
    if (batchUnlisten) { batchUnlisten(); batchUnlisten = null; }
    $('batchProgress').classList.add('hidden');
    $('batchConfig').classList.remove('hidden');
    $('btnStartBatch').disabled = false;
    toast('Erreur de correction groupée : ' + err, true);
  }
}

function renderBatchResults() {
  const list = $('patchList');
  list.innerHTML = '';

  if (!batchPatches.length) {
    list.innerHTML = '<p style="color:var(--text-muted);padding:12px">Aucun correctif généré.</p>';
  }

  batchPatches.forEach((patch, idx) => {
    const card = document.createElement('div');
    card.className = 'patch-card';

    const fileName = patch.file_path.split(/[\\/]/).slice(-2).join('/');
    const nVulns   = patch.vuln_ids.length;

    card.innerHTML = `
      <div class="patch-card-header">
        <span class="patch-filename">${escHtml(fileName)}</span>
        <span class="patch-vulns">${nVulns} vuln${nVulns > 1 ? 's' : ''} corrigée${nVulns > 1 ? 's' : ''}</span>
        ${patch.applied ? '<span class="patch-applied">✅ Appliqué</span>' : ''}
      </div>
      <p class="patch-summary">${escHtml(patch.summary)}</p>
      <div class="patch-actions">
        <button class="btn-secondary patch-btn-preview" data-idx="${idx}">👁 Voir les différences</button>
        ${!patch.applied ? `<button class="btn-ai patch-btn-apply" data-idx="${idx}">✅ Appliquer</button>` : ''}
      </div>
      <pre class="patch-diff hidden" id="diff-${idx}"></pre>
    `;

    card.querySelector('.patch-btn-preview').addEventListener('click', () => toggleDiff(idx, patch));
    const applyBtn = card.querySelector('.patch-btn-apply');
    if (applyBtn) applyBtn.addEventListener('click', () => applySinglePatch(idx));

    list.appendChild(card);
  });

  $('batchSummary').innerHTML =
    `<strong>${batchPatches.length}</strong> fichier(s) analysé(s) — cliquez sur un correctif pour voir les différences avant de l'appliquer.`;
  $('batchResults').classList.remove('hidden');
}

function toggleDiff(idx, patch) {
  const pre = document.getElementById('diff-' + idx);
  if (pre.classList.contains('hidden')) {
    // Generate simple unified diff view
    const origLines  = patch.original_content.split('\n');
    const patchLines = patch.patched_content.split('\n');
    let diffHtml = '';
    const maxLines = Math.max(origLines.length, patchLines.length);
    for (let i = 0; i < maxLines && i < 200; i++) {
      const o = origLines[i] ?? '';
      const p = patchLines[i] ?? '';
      if (o === p) {
        diffHtml += `<span class="diff-same"> ${escHtml(o)}\n</span>`;
      } else {
        if (o) diffHtml += `<span class="diff-del">-${escHtml(o)}\n</span>`;
        if (p) diffHtml += `<span class="diff-add">+${escHtml(p)}\n</span>`;
      }
    }
    pre.innerHTML = diffHtml || '(identique)';
    pre.classList.remove('hidden');
  } else {
    pre.classList.add('hidden');
  }
}

async function applySinglePatch(idx) {
  const patch = batchPatches[idx];
  if (!patch || patch.applied) return;
  try {
    await invoke('apply_patch', { filePath: patch.file_path, patchedContent: patch.patched_content });
    batchPatches[idx].applied = true;
    toast(`Correctif appliqué : ${patch.file_path.split(/[\\/]/).pop()}`);
    renderBatchResults();
  } catch (err) {
    toast("Erreur d'application du correctif : " + err, true);
  }
}

async function applyAllPatches() {
  let applied = 0;
  for (let i = 0; i < batchPatches.length; i++) {
    if (!batchPatches[i].applied) {
      try {
        await invoke('apply_patch', { filePath: batchPatches[i].file_path, patchedContent: batchPatches[i].patched_content });
        batchPatches[i].applied = true;
        applied++;
      } catch (err) {
        toast(`Erreur sur ${batchPatches[i].file_path.split(/[\\/]/).pop()}: ${err}`, true);
      }
    }
  }
  toast(`${applied} correctif(s) appliqué(s) sur le disque`);
  renderBatchResults();
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
