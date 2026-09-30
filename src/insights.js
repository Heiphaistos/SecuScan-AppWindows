/**
 * SecuScan AI — probabilité réel / faux positif, synthèse et réputation en ligne.
 * Toute donnée issue d'un fichier scanné passe par textContent (jamais innerHTML).
 */

// ─── Helpers ──────────────────────────────────────────────────────────────────
/** Crée un élément ; `text` via textContent, `style` en objet. */
function mk(tag, { cls, text, style, title } = {}, children = []) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (title) e.title = String(title);
  if (style) Object.assign(e.style, style);
  children.forEach(c => c && e.appendChild(c));
  return e;
}

/** Couleur d'une probabilité d'être un VRAI problème (identique au rapport). */
function realColor(p) {
  if (p < 15) return '#22c55e';
  if (p < 40) return '#eab308';
  if (p < 70) return '#f97316';
  return '#ef4444';
}

const INTEL_LABEL = {
  Malicious:     { label: 'MALVEILLANT',    color: '#ef4444' },
  Suspicious:    { label: 'SUSPECT',        color: '#eab308' },
  Clean:         { label: 'RIEN TROUVÉ',    color: '#22c55e' },
  KnownGood:     { label: 'LÉGITIME CONNU', color: '#22c55e' },
  NotFound:      { label: 'INCONNU',        color: '#64748b' },
  Error:         { label: 'INDISPONIBLE',   color: '#64748b' },
  NotConfigured: { label: 'NON CONFIGURÉ',  color: '#475569' },
};

/** Seuil sous lequel un résultat est un faux positif probable. */
const LIKELY_FP = 30;

// ─── Liste : pastille « % réel » ─────────────────────────────────────────────
function confidencePill(v) {
  return mk('span', {
    cls: 'pct-pill',
    text: `${v.confidence} % réel`,
    title: `${v.confidence_label} — ${v.false_positive} % de faux positif`,
    style: { color: realColor(v.confidence), borderColor: realColor(v.confidence) },
  });
}

// ─── Synthèse du scan + réputation en ligne ───────────────────────────────────
function renderAssessment(scan) {
  const panel = document.getElementById('assessPanel');
  const a = scan.assessment;
  if (!a) { panel.classList.add('hidden'); return; }

  const tile = (n, label, color) =>
    mk('div', { cls: 'tile', style: { borderTopColor: color } }, [
      mk('b', { text: n, style: { color } }),
      mk('span', { text: label }),
    ]);
  const tiles = document.getElementById('assessTiles');
  tiles.replaceChildren(
    tile(a.likely_real, 'probablement réel(s) ≥ 55 %', '#f97316'),
    tile(a.to_review, 'à vérifier 30–54 %', '#eab308'),
    tile(a.likely_false_positive, 'faux positif(s) probable(s) < 30 %', '#22c55e'),
    tile(`${a.malware_probability} %`, 'probabilité de code malveillant', realColor(a.malware_probability)),
  );
  document.getElementById('assessSummary').textContent = a.summary;
  document.getElementById('assessMethod').textContent = a.method;
  document.getElementById('fpFilterRow').classList.toggle('hidden', !a.likely_false_positive);

  renderReputation(scan.reputation || []);
  panel.classList.remove('hidden');
}

function renderReputation(reps) {
  const box = document.getElementById('repPanel');
  const list = document.getElementById('repList');
  if (!reps.length) { box.classList.add('hidden'); list.replaceChildren(); return; }
  document.getElementById('repTitle').textContent =
    `🌍 Réputation en ligne (${reps.length} fichier(s) vérifié(s))`;
  list.replaceChildren(...reps.map(fr => {
    const srcs = fr.sources.map(s => {
      const lab = INTEL_LABEL[s.status] || INTEL_LABEL.Error;
      return mk('span', {
        cls: 'rep-src',
        text: `${s.source} : ${lab.label}`,
        title: s.summary,
        style: { color: lab.color, borderColor: lab.color },
      });
    });
    return mk('div', { cls: 'rep-file' }, [
      mk('p', { cls: 'rep-path', text: fr.file_path }, [mk('span', { text: ` — ${fr.summary}` })]),
      mk('div', { cls: 'rep-srcs' }, srcs),
    ]);
  }));
  box.classList.remove('hidden');
}

// ─── Panneau de détail : pourcentages, explications, calcul ───────────────────
function renderConfidence(v) {
  const box = document.getElementById('detailConfidence');
  const color = realColor(v.confidence);

  const bar = mk('div', { cls: 'conf-bar' }, [
    mk('div', { style: { width: `${v.confidence}%`, background: color } }),
  ]);
  const label = mk('p', {
    cls: 'conf-label',
    text: `${v.confidence_label} — ${v.confidence} % de probabilité que ce soit un vrai problème, ${v.false_positive} % de faux positif`,
    style: { color },
  });

  const calc = mk('ul', { cls: 'calc' }, [
    mk('li', { text: `Probabilité de départ pour cette règle : ${v.base_confidence} %` }),
    ...(v.confidence_factors || []).map(f => {
      if (f.delta === 0) return mk('li', { text: f.label });
      return mk('li', {}, [
        mk('b', { text: `${f.delta > 0 ? '+' : ''}${f.delta}`, style: { color: f.delta < 0 ? '#22c55e' : '#ef4444' } }),
        document.createTextNode(` : ${f.label}`),
      ]);
    }),
    mk('li', { text: `Résultat : ${v.confidence} % réel → ${v.false_positive} % faux positif` }),
  ]);

  box.replaceChildren(
    bar, label,
    mk('div', { cls: 'detail-section' }, [mk('h4', { text: 'Ce que fait ce code' }), mk('p', { text: v.what_it_does })]),
    mk('div', { cls: 'why2' }, [
      mk('div', { cls: 'why bad' }, [mk('h4', { text: "Pourquoi c'est probablement un vrai problème" }), mk('p', { text: v.why_real })]),
      mk('div', { cls: 'why good' }, [mk('h4', { text: 'Pourquoi ça peut être un faux positif' }), mk('p', { text: v.why_false_positive })]),
    ]),
    mk('div', { cls: 'detail-section' }, [mk('h4', { text: 'Calcul du pourcentage' }), calc]),
  );
}

// ─── Réglages : clés des bases de réputation ──────────────────────────────────
const INTEL_KEYS = ['vt', 'metadefender', 'hybrid', 'opentip', 'otx', 'abusech'];

function renderIntelKeyStatus(status) {
  for (const k of INTEL_KEYS) {
    const el = document.getElementById(`status${k.charAt(0).toUpperCase()}${k.slice(1)}`);
    if (!el) continue;
    el.textContent = status[k] ? '✓ Configurée' : 'Non configurée';
    el.className = `key-status ${status[k] ? 'ok' : 'nok'}`;
  }
  const free = document.getElementById('settingFreeLookups');
  if (free) free.checked = status.intel_free_lookups !== false;
}
