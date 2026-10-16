// Build → Emulate (templates/emulate.html): recorded attack telemetry (archer.telemetry.web)
(function () {
  const $ = id => document.getElementById(id);
  const page = document.querySelector('.em-page');
  const signedIn = page.dataset.signedIn === 'true';
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const plural = (n, word) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;
  const json = async url => {
    const res = await fetch(url);
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || res.status);
    return r;
  };
  const PER_PAGE = 20;
  const EVTX_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>';
  const SOURCES = {
    splunk: { name: 'Splunk attack_data', img: '/static/images/siem/splunk.png' },
    otrf: { name: 'Security-Datasets (OTRF)', img: '/static/images/brands/otrf.png' },
    evtx: { name: 'EVTX-to-MITRE-Attack', svg: EVTX_ICON },
    guide: { name: 'Microsoft GUIDE', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/></svg>' },
    lab: { name: 'Your lab', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 3h6M10 3v6L4 19a2 2 0 0 0 2 3h12a2 2 0 0 0 2-3l-6-10V3"/></svg>' },
    macos: { name: 'macOS-ATTACK-DATASET', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/></svg>' },
  };
  const logo = (src, cls = 'em-logo') => {
    const s = SOURCES[src] || { name: src };
    const inner = s.img ? `<img src="${s.img}" alt="">` : (s.svg || esc(src));
    return `<span class="${cls} is-${esc(src)}" title="${esc(s.name)}">${inner}</span>`;
  };
  const STATUS = { seen: 'Seen', not_seen: 'Not seen', no_recordings: 'No recordings', no_indicators: 'No indicators', noisy: 'Noisy indicator' };
  const PLATFORM = { windows: 'Windows', linux: 'Linux', macos: 'macOS', esxi: 'ESXi', cloud: 'Cloud' };
  const COLLECTION = { native: 'native', sysmon: 'Sysmon', edr: 'EDR', osquery: 'osquery', cloud: 'cloud' };
  const STATUS_ORDER = ['seen', 'not_seen', 'no_indicators', 'no_recordings', 'no_values'];

  const state = {
    view: 'technique', siem: page.dataset.siem || 'secops', q: '', page: 1, open: new Set(),
    sel: { technique: new Set(), group: new Set(), source: new Set(), log: new Set(), collection: new Set(), platform: new Set(), defender: new Set(), seen: new Set() },
    collectionTouched: false,
  };
  // What a SIEM sees by default: SecOps gets the logs forwarded to it, and Sysmon is deployed far
  // less than native logging; with Defender XDR, Sysmon's recordings stand in for the MDE sensor,
  // which records the same process, file, network, registry and image-load activity itself
  const DEFAULT_COLLECTIONS = { secops: ['native', 'edr', 'osquery', 'cloud'], mde: ['native', 'sysmon', 'edr', 'osquery', 'cloud'] };
  const collectionsParam = () => `collections=${[...state.sel.collection].sort().join(',')}&platforms=${[...state.sel.platform].sort().join(',')}`;
  const data = { names: {}, techniques: null, sources: null, groups: [], checks: {}, groupTechs: {}, search: {}, details: {}, values: null };
  const siemKey = () => (state.siem === 'mde' ? 'mde' : 'udm');
  const siemName = () => (state.siem === 'mde' ? 'Defender XDR' : 'Google SecOps');
  const techName = tid => (data.names[tid] || {}).name || '';
  const anyIn = (list, set) => (list || []).some(v => set.has(v));

  // ---------- Recorded telemetry ----------
  let timer = null;
  function setCheck(cls, text, title = '') {
    $('em-check').className = `em-tile em-check ${cls}`;
    $('em-values').textContent = text;
    $('em-check').title = title;
  }

  async function status() {
    clearTimeout(timer);
    let r;
    try { r = await json('/api/telemetry/status'); } catch (e) { setCheck('is-error', 'Error', e.message); return; }
    data.values = r.values;
    $('em-datasets').textContent = r.datasets.toLocaleString();
    $('em-techniques').textContent = r.techniques.toLocaleString();
    const running = r.job.state === 'running';
    if (running) setCheck('is-starting', 'Starting…', 'Fetching what the sources have changed');
    else if (r.job.state === 'failed') setCheck('is-error', 'Error', r.job.error || '');
    else if (r.values) setCheck('is-ready', 'Ready', "Detections' indicators can be checked against the recordings");
    else setCheck('is-unavailable', 'Unavailable', "The recordings' field values aren't on this machine");
    const order = ['lab', 'splunk', 'otrf', 'evtx', 'macos'];
    $('em-sources').innerHTML = Object.entries(r.sources).sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0])).map(([k, s]) =>
      k === 'lab' && !s.datasets
        // Nothing recorded yet: docs/guide/20-recording-a-lab.md
        ? `<li class="is-missing">${logo(k, 'em-source-logo')}<div><strong>${esc(s.name)} <em class="nav-soon">Coming soon</em></strong>
            <span>No runs yet</span><small>Atomic Red Team on your own Windows, Linux and macOS VMs, with Defender for Endpoint's rows: see the user guide's <em>Recording a lab</em></small></div></li>`
        : `<li>${logo(k, 'em-source-logo')}
      <div>${s.url ? `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.name)}</a>` : `<strong>${esc(s.name)}</strong>`}
      <span>${esc((s.datasets || 0).toLocaleString())} recordings · ${esc(s.licence)} · built ${esc(s.built)}</span><small>${esc(s.note)}</small></div></li>`).join('');
    const hadGuide = data.guide;
    data.guide = !!r.guide;
    $('em-sources').insertAdjacentHTML('beforeend', r.guide
      ? `<li class="is-guide">${logo('guide', 'em-source-logo')}<div><a href="${esc(r.guide.url)}" target="_blank" rel="noopener">${esc(r.guide.name)}</a>
          <span>${r.guide.techniques.toLocaleString()} techniques Defender XDR alerts on · ${esc(r.guide.licence)} · built ${esc(r.guide.built)}</span>
          <small>${esc(r.guide.note)}. Alerts, not logs: shown with Defender XDR as the SIEM</small></div></li>`
      : `<li class="is-guide is-missing">${logo('guide', 'em-source-logo')}<div><a href="https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction" target="_blank" rel="noopener">Microsoft GUIDE</a>
          <span>Not loaded</span><small>Which techniques Defender XDR alerts on, and how often rightly. Download it from Kaggle, then <code>python -m archer.telemetry --guide &lt;zip&gt;</code></small></div></li>`);
    if (hadGuide !== data.guide) render();
    const btn = $('em-build');
    btn.hidden = page.dataset.admin !== 'true';
    btn.disabled = running;
    btn.textContent = r.values ? 'Update' : 'Download';
    $('em-state').textContent = running ? 'Downloading and summarising…' : r.job.state === 'done' ? 'Up to date' : '';
    const log = $('em-log');
    log.hidden = !r.log.length;
    log.textContent = r.log.map(l => l.msg).join('\n');
    log.scrollTop = log.scrollHeight;
    if (running) timer = setTimeout(status, 3000);
    else if (r.job.state === 'done' && btn.dataset.ran) { delete btn.dataset.ran; reload(); }
  }

  $('em-build').addEventListener('click', async () => {
    $('em-build').disabled = true;
    $('em-build').dataset.ran = '1';
    setCheck('is-starting', 'Starting…');
    await fetch('/api/telemetry/build', { method: 'POST' });
    status();
  });

  // ---------- Multiselect filters ----------
  const multis = {};
  const options = {
    technique: [], group: [], source: [], log: [], seen: Object.entries(STATUS).map(([v, l]) => ({ value: v, label: l })),
    collection: [['native', 'Native OS logs'], ['sysmon', 'Sysmon'], ['edr', 'EDR'], ['osquery', 'osquery'], ['cloud', 'Cloud and SaaS']].map(([v, l]) => ({ value: v, label: l })),
    defender: [['tp', 'Alerts, mostly true positives'], ['fp', 'Alerts, mostly not'], ['none', 'No alerts']].map(([v, l]) => ({ value: v, label: l })),
    platform: [['windows', 'Windows'], ['linux', 'Linux'], ['macos', 'macOS'], ['esxi', 'ESXi'], ['cloud', 'Cloud and SaaS']].map(([v, l]) => ({ value: v, label: l })),
  };

  document.querySelectorAll('.em-ms').forEach(el => {
    const key = el.dataset.key;
    el.innerHTML = `<button type="button" class="dropdown-styled em-ms-btn" aria-haspopup="listbox" aria-expanded="false">${esc(el.dataset.label)}</button>
      <div class="em-ms-panel" hidden>
        ${el.dataset.search ? `<input type="search" class="form-input em-ms-search" placeholder="${esc(el.dataset.search)}" aria-label="Search ${esc(el.dataset.label)}">` : ''}
        <div class="em-ms-list" role="listbox" aria-multiselectable="true"></div>
        <div class="em-ms-foot"><span class="em-ms-count"></span><button type="button" class="ui-pill em-ms-none">Clear</button></div>
      </div>`;
    const btn = el.querySelector('.em-ms-btn');
    const panel = el.querySelector('.em-ms-panel');
    const search = el.querySelector('.em-ms-search');
    const list = el.querySelector('.em-ms-list');
    const draw = () => {
      const q = (search ? search.value : '').trim().toLowerCase();
      const sel = state.sel[key];
      const all = options[key].filter(o => !q || o.value.toLowerCase().includes(q) || (o.label || '').toLowerCase().includes(q));
      // Picked first, then the rest; a long list draws its first 200 matches
      const shown = [...all.filter(o => sel.has(o.value)), ...all.filter(o => !sel.has(o.value))].slice(0, 200);
      list.innerHTML = shown.map(o => `<label class="em-ms-opt"><input type="checkbox" value="${esc(o.value)}"${sel.has(o.value) ? ' checked' : ''}>
        <span>${esc(o.label || o.value)}</span>${o.hint ? `<small>${esc(o.hint)}</small>` : ''}</label>`).join('')
        || '<p class="em-ms-empty">Nothing matches</p>';
      el.querySelector('.em-ms-count').textContent = all.length > 200 ? `First 200 of ${all.length.toLocaleString()}` : `${all.length.toLocaleString()} options`;
    };
    const label = () => {
      const n = state.sel[key].size;
      btn.textContent = n ? `${el.dataset.label} (${n})` : el.dataset.label;
      btn.classList.toggle('is-active', n > 0);
    };
    multis[key] = { draw, label, el };
    btn.addEventListener('click', () => {
      const open = panel.hidden;
      document.querySelectorAll('.em-ms-panel').forEach(p => { p.hidden = true; p.previousElementSibling.setAttribute('aria-expanded', 'false'); });
      panel.hidden = !open;
      btn.setAttribute('aria-expanded', String(open));
      if (open) { draw(); if (search) search.focus(); }
    });
    if (search) search.addEventListener('input', draw);
    list.addEventListener('change', e => {
      const v = e.target.value;
      if (e.target.checked) state.sel[key].add(v); else state.sel[key].delete(v);
      changed(key);
    });
    el.querySelector('.em-ms-none').addEventListener('click', () => { state.sel[key].clear(); draw(); changed(key); });
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('.em-ms')) document.querySelectorAll('.em-ms-panel').forEach(p => { p.hidden = true; p.previousElementSibling.setAttribute('aria-expanded', 'false'); });
  });

  function setOptions(key, list) {
    options[key] = list;
    multis[key].label();
  }

  function changed(key) {
    multis[key].label();
    state.page = 1;
    if (key === 'collection') state.collectionTouched = true;
    if (key === 'collection' || key === 'platform') { reload(); return; }
    render();
  }

  function defaultCollections() {
    state.sel.collection = new Set(DEFAULT_COLLECTIONS[state.siem] || DEFAULT_COLLECTIONS.secops);
    multis.collection.label();
  }

  function sourceOptions() {
    if (!data.sources) return;
    setOptions('source', data.sources[siemKey()].map(s => ({ value: s.name, label: s.name, hint: plural(s.techniques, 'technique') })));
    // A table picked for one SIEM isn't one for the other
    for (const v of [...state.sel.source]) if (!options.source.some(o => o.value === v)) state.sel.source.delete(v);
    multis.source.label();
  }

  // ---------- Views ----------
  let searchTimer = null;
  $('em-q').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.q = $('em-q').value.trim(); state.page = 1; render(); }, 350);
  });
  $('em-siem').value = state.siem;
  $('em-siem').addEventListener('change', () => {
    state.siem = $('em-siem').value;
    state.page = 1;
    if (!state.collectionTouched) { defaultCollections(); reload(); return; }
    sourceOptions();
    render();
  });
  $('em-view').addEventListener('change', () => { state.view = $('em-view').value; state.page = 1; render(); });
  $('em-clear').addEventListener('click', () => {
    Object.values(state.sel).forEach(s => s.clear());
    Object.values(multis).forEach(m => m.label());
    $('em-q').value = state.q = '';
    state.page = 1;
    state.collectionTouched = false;
    defaultCollections();
    reload();
  });
  $('em-filters-toggle').addEventListener('click', () => {
    const body = $('em-filters-body');
    body.hidden = !body.hidden;
    $('em-filters-toggle').textContent = body.hidden ? 'Expand' : 'Collapse';
  });
  $('em-prev').addEventListener('click', () => { state.page--; render(); scrollToCard(); });
  $('em-next').addEventListener('click', () => { state.page++; render(); scrollToCard(); });
  const scrollToCard = () => $('em-view-card').scrollIntoView({ block: 'start', behavior: 'smooth' });

  // The techniques the groups picked in Filters have detections for (null while loading)
  function groupTechniques() {
    if (!state.sel.group.size) return null;
    const out = new Set();
    let waiting = false;
    for (const g of state.sel.group) {
      if (!data.groupTechs[g]) {
        waiting = true;
        if (!data.groupTechs[g + '\u0000loading']) {
          data.groupTechs[g + '\u0000loading'] = true;
          json(`/api/telemetry/group-techniques?group=${encodeURIComponent(g)}`)
            .then(r => { data.groupTechs[g] = new Set(r.techniques); render(); })
            .catch(() => { data.groupTechs[g] = new Set(); render(); });
        }
        continue;
      }
      data.groupTechs[g].forEach(t => out.add(t));
    }
    return waiting ? undefined : out;
  }

  // Techniques whose recordings hold a value containing the search text (undefined while loading)
  function searched() {
    if (!state.q) return null;
    const hit = data.search[state.q];
    if (hit) return hit;
    if (hit === undefined) {
      data.search[state.q] = false;
      const q = state.q;
      json(`/api/telemetry/search?q=${encodeURIComponent(q)}`)
        .then(r => { data.search[q] = r.techniques; render(); })
        .catch(e => { data.search[q] = { error: e.message }; render(); });
    }
    return undefined;
  }

  function pageOf(rows) {
    const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
    state.page = Math.min(Math.max(1, state.page), pages);
    $('em-pager').hidden = pages <= 1;
    $('em-page').textContent = `Page ${state.page} of ${pages}`;
    $('em-prev').disabled = state.page <= 1;
    $('em-next').disabled = state.page >= pages;
    return rows.slice((state.page - 1) * PER_PAGE, state.page * PER_PAGE);
  }

  function shown(n, total, word) {
    $('em-shown').textContent = n === total ? plural(total, word) : `${n.toLocaleString()} of ${plural(total, word)}`;
  }

  function message(text) {
    $('em-results').innerHTML = `<p class="ms-note">${text}</p>`;
    $('em-pager').hidden = true;
    $('em-shown').textContent = '';
  }

  const chips = (list, max = 6) => {
    if (!list || !list.length) return '<small>–</small>';
    const more = list.length - max;
    return `<ul class="em-chips">${list.slice(0, max).map(v => `<li><code>${esc(v)}</code></li>`).join('')}${more > 0 ? `<li class="em-more" title="${esc(list.slice(max).join('\n'))}">+${more}</li>` : ''}</ul>`;
  };
  const techLink = tid => `<button type="button" class="em-tid" data-tid="${esc(tid)}">${esc(tid)}</button>`;

  function render() {
    const v = state.view;
    document.querySelectorAll('[data-for]').forEach(el => { el.hidden = !el.dataset.for.split(' ').includes(v); });
    if (!signedIn) multis.group.el.hidden = true;  // groups are your hunts
    if (state.siem !== 'mde' || !data.guide) multis.defender.el.hidden = true;  // GUIDE is Defender's alerting
    const active = Object.entries(state.sel).filter(([k, s]) => s.size && multis[k].el.dataset.for.split(' ').includes(v)).length + (state.q && v !== 'source' ? 1 : 0);
    $('em-filter-active').hidden = !active;
    $('em-filter-active').textContent = active ? `(${active} active)` : '';
    if (v === 'technique') renderTechniques();
    else if (v === 'group') renderGroups();
    else renderSources();
  }

  // By technique: every recorded technique, the logs most of its recordings hold, and their tables or event types
  // GUIDE: Defender XDR's own alerting on a technique, in 6,100+ organisations
  const defenderBand = d => (!d ? 'none' : d.tp_rate !== null && d.tp_rate >= 0.5 ? 'tp' : 'fp');
  const defenderCell = d => !d ? '<small>No alerts</small>'
    : `${d.alerts.toLocaleString()} alert${d.alerts === 1 ? '' : 's'}<br><small>${d.orgs.toLocaleString()} orgs${d.tp_rate !== null ? ` · ${Math.round(d.tp_rate * 100)}% true positive` : ''}${d.family ? ' · its parent\'s' : ''}</small>`;

  function renderTechniques() {
    $('em-view-note').innerHTML = `Every technique the labs recorded. <strong>Logs</strong> and <strong>${esc(siemName())}</strong> are what at least half its recordings hold, counting only the logs chosen under <strong>Collection</strong>.
      ${state.siem === 'mde' ? 'With Defender XDR, Sysmon\'s recordings stand in for the MDE sensor, which records the same activity without Sysmon installed.' : ''}
      A technique none of whose recordings hold those logs is marked. Select a row for each log and recording.`;
    if (!data.techniques) return message('Loading…');
    const groupT = groupTechniques();
    const hits = searched();
    const showDefender = state.siem === 'mde' && data.guide;
    if (groupT === undefined || hits === undefined) return message('Loading…');
    if (hits && hits.error) return message(esc(hits.error));
    const s = state.sel;
    const rows = data.techniques.filter(t => (!s.technique.size || s.technique.has(t.technique))
      && (!groupT || groupT.has(t.technique))
      && (!s.source.size || anyIn(t[siemKey()], s.source))
      && (!s.log.size || anyIn(t.logs, s.log))
      && (!s.platform.size || anyIn(t.platforms, s.platform))
      && (!showDefender || !s.defender.size || s.defender.has(defenderBand(t.defender)))
      && (!hits || hits[t.technique]));
    shown(rows.length, data.techniques.length, 'technique');
    if (!rows.length) return message('No recorded technique matches the filters.');
    const cols = showDefender ? 5 : 4;
    $('em-results').innerHTML = `<div class="ms-table-wrap"><table class="ms-table em-table em-rows">
      <thead><tr><th>Technique</th><th>Recordings</th><th>Logs</th><th>${esc(siemName())}</th>${showDefender ? '<th title="Microsoft GUIDE: Defender XDR alerts mapped to the technique, and how often customers graded them true positive">Defender XDR alerts</th>' : ''}</tr></thead>
      <tbody>${pageOf(rows).map(t => {
        const info = data.names[t.technique] || {};
        const open = state.open.has(t.technique);
        const gap = !t.visible;
        return `<tr class="em-row${open ? ' is-open' : ''}${gap ? ' is-gap' : ''}" data-tid="${esc(t.technique)}" tabindex="0" aria-expanded="${open}">
          <td><strong>${esc(t.technique)}</strong> ${esc(info.name || '')}${info.tactics ? `<br><small>${esc(info.tactics.join(', '))}</small>` : ''}
            ${hits ? `<br><small class="em-hit">Search found in: ${esc(hits[t.technique].join(', '))}</small>` : ''}</td>
          <td class="em-nowrap">${t.recordings}${t.visible !== t.recordings ? ` <small>· ${t.visible} in these logs</small>` : ''}
            <div class="em-logos">${Object.entries(t.sources).map(([k, n]) => `${logo(k)}<small>${n}</small>`).join('')}</div>
            <small>${esc(t.platforms.map(p => PLATFORM[p] || p).join(', '))}</small></td>
          ${gap ? '<td colspan="2"><span class="em-gap">No recording holds the chosen logs</span></td>' : `<td>${chips(t.logs, 4)}</td><td>${chips(t[siemKey()], 4)}</td>`}
          ${showDefender ? `<td>${defenderCell(t.defender)}</td>` : ''}</tr>
          ${open ? `<tr class="em-detail"><td colspan="${cols}">${detail(t.technique)}</td></tr>` : ''}`;
      }).join('')}</tbody></table></div>`;
  }

  function detail(tid) {
    const r = data.details[tid];
    if (!r) {
      if (r === undefined) {
        data.details[tid] = null;
        json(`/api/telemetry/technique/${encodeURIComponent(tid)}?${collectionsParam()}`).then(d => { data.details[tid] = d; render(); })
          .catch(e => { data.details[tid] = { error: e.message }; render(); });
      }
      return '<p class="ms-note">Loading…</p>';
    }
    if (r.error) return `<p class="ms-note">${esc(r.error)}</p>`;
    const key = siemKey();
    const g = r.defender;
    const guideNote = state.siem === 'mde' && data.guide ? (g
      ? `<p class="em-guide">${logo('guide')} <strong>Defender XDR</strong>${g.family ? ' (for its parent technique)' : ''}: ${g.alerts.toLocaleString()} alerts from ${g.detectors.toLocaleString()} detectors in ${g.orgs.toLocaleString()} organisations;
          graded ${g.grades.tp || 0} true, ${g.grades.bp || 0} benign and ${g.grades.fp || 0} false positive. Categories: ${esc(g.categories.join(', '))}. Evidence: ${esc(g.evidence.join(', '))}.</p>`
      : `<p class="em-guide">${logo('guide')} No Defender XDR alert in GUIDE maps to this technique: a custom detection is where coverage comes from.</p>`) : '';
    return `${guideNote}<table class="ms-table em-table em-sub">
        <thead><tr><th>Log</th><th>Recordings</th><th>Events</th><th>${esc(siemName())}</th></tr></thead>
        <tbody>${r.event_types.map(e => `<tr${e.common ? ' class="is-common" title="In 40% or more of a source\'s recordings, whatever the technique: lab background as much as the attack"' : ''}>
          <td>${esc(e.label)} <span class="em-coll is-${esc(e.collection)}">${esc(COLLECTION[e.collection] || e.collection)}</span>${e.common ? ' <span class="em-common">common</span>' : ''}</td><td>${e.recordings} of ${r.visible}</td>
          <td>${e.events.toLocaleString()}</td><td>${e[key] ? `<code>${esc(e[key])}</code>` : '–'}</td></tr>`).join('')}</tbody>
      </table>
      ${r.visible < r.recordings.length ? `<p class="ms-note">${r.recordings.length - r.visible} of ${plural(r.recordings.length, 'recording')} hold none of the chosen logs.</p>` : ''}
      <details class="em-recs"><summary>${plural(r.recordings.length, 'recording')}</summary><ul>${r.recordings.map(d => `<li${d.visible ? '' : ' class="is-gap"'}>
        ${logo(d.source)} <a href="${esc(d.url)}" target="_blank" rel="noopener">${esc(d.title)}</a>
        <span>${esc(d.techniques.join(', '))} · ${esc((d.platforms || []).map(p => PLATFORM[p] || p).join(', '))} · ${plural(d.events, 'event')}</span></li>`).join('')}</ul></details>`;
  }

  // By group: each detection's indicators against its technique's recordings
  function renderGroups() {
    $('em-view-note').innerHTML = `Your detections for ${esc(siemName())}, each indicator against its technique's recordings: <strong>seen</strong> means a recorded event of the attack contains it (and names the log),
      <strong>noisy</strong> means recordings of five or more other techniques contain it too. A cheap first look before testing against your own SIEM.`;
    if (!signedIn) return message('<a href="/login?next_url=/emulate">Log in</a> to check your detections.');
    if (data.values === false) return message("The recordings' field values aren't on this machine: an admin can fetch them with <strong>Download</strong> above.");
    let groups = [...state.sel.group];
    let note = '';
    if (!groups.length) {
      if (!data.groups.length) return message(data.groupsLoaded ? 'No hunts yet: hunt a group, then check its detections here.' : 'Loading…');
      groups = [data.groups[0].group];
      note = `<p class="em-summary">Your latest hunt, ${esc(groups[0])}. Pick others under <strong>Groups</strong> in Filters.</p>`;
    }
    const waiting = groups.filter(g => !data.checks[g]);
    waiting.forEach(g => {
      data.checks[g] = 'loading';
      json(`/api/telemetry/check?group=${encodeURIComponent(g)}`).then(r => { data.checks[g] = r; render(); })
        .catch(e => { data.checks[g] = { error: e.message, detections: [] }; render(); });
    });
    if (groups.some(g => data.checks[g] === 'loading')) return message(`Checking ${esc(groups.join(', '))}…`);
    const errors = groups.map(g => data.checks[g].error).filter(Boolean);
    const allowed = state.sel.collection;
    const platformsOf = Object.fromEntries((data.techniques || []).map(t => [t.technique, t.platforms]));
    // Hits only in logs left out under Collection don't count
    const all = groups.flatMap(g => data.checks[g].detections || []).filter(d => !d.siem || d.siem === state.siem).map(d => {
      if (!allowed.size || d.status !== 'seen') return d;
      const indicators = d.indicators.map(i => ({ ...i, seen: i.seen.filter(h => allowed.has(h.collection)) }));
      const hits = indicators.flatMap(i => i.seen);
      return { ...d, indicators, status: hits.length ? 'seen' : 'not_seen', events: [...new Set(hits.map(h => h.label))].sort() };
    });
    const s = state.sel;
    const q = state.q.toLowerCase();
    const rows = all.filter(d => (!s.technique.size || s.technique.has(d.technique))
      && (!s.source.size || anyIn(d[siemKey()], s.source))
      && (!s.log.size || anyIn(d.events, s.log))
      && (!s.platform.size || anyIn(platformsOf[d.technique], s.platform))
      && (!s.seen.size || s.seen.has(d.status) || (s.seen.has('noisy') && (d.indicators || []).some(i => i.noisy)))
      && (!q || (d.indicators || []).some(i => i.value.toLowerCase().includes(q))))
      .sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.technique.localeCompare(b.technique));
    shown(rows.length, all.length, 'detection');
    const c = rows.reduce((m, d) => ({ ...m, [d.status]: (m[d.status] || 0) + 1 }), {});
    const head = `${note}${errors.length ? `<p class="ms-note">${esc(errors.join('; '))}</p>` : ''}
      <p class="em-summary"><strong>${(c.seen || 0).toLocaleString()}</strong> with indicators seen in their technique's recordings, ${(c.not_seen || 0).toLocaleString()} not seen,
        ${(c.no_recordings || 0).toLocaleString()} with no recordings of their technique, ${(c.no_indicators || 0).toLocaleString()} without indicators to look for.</p>`;
    if (!rows.length) { message('No detection matches the filters.'); $('em-results').insertAdjacentHTML('afterbegin', head); return; }
    const many = groups.length > 1;
    $('em-results').innerHTML = `${head}<div class="ms-table-wrap"><table class="ms-table em-table">
      <thead><tr><th>Detection</th><th>Technique</th><th>Result</th><th>Indicators</th></tr></thead>
      <tbody>${pageOf(rows).map(d => `<tr class="is-${esc(d.status)}">
        <td>${esc(d.name)}<br><small>${many ? `${esc(d.group)} · ` : ''}${esc(d.file)}</small></td>
        <td>${techLink(d.technique)}<br><small>${plural(d.datasets, 'recording')}</small></td>
        <td><span class="em-status is-${esc(d.status)}">${STATUS[d.status] || esc(d.status)}</span>${d.events && d.events.length ? `<br><small>${esc(d.events.join(', '))}</small>` : ''}</td>
        <td>${(d.indicators || []).map(i => {
          const bySource = {};
          i.seen.forEach(h => { (bySource[h.source] = bySource[h.source] || new Set()).add(h.label.split(':')[0]); });
          return `<div class="em-ind" title="${esc(i.seen.map(h => `${h.label}, ${h.field}: ${h.example}`).join('\n'))}"><code>${esc(i.value)}</code>
            ${Object.entries(bySource).map(([src, labels]) => `<span class="em-tag is-seen">${logo(src, 'em-tag-logo')}seen: ${esc([...labels].join(', '))}</span>`).join('')}
            ${i.noisy ? `<span class="em-tag is-noisy">noisy: ${i.elsewhere} other</span>` : ''}</div>`;
        }).join('') || '<small>–</small>'}</td></tr>`).join('')}</tbody></table></div>`;
  }

  // By data source: each table or event type, the techniques it records and the logs it comes from
  function renderSources() {
    $('em-view-note').innerHTML = `How many techniques each ${state.siem === 'mde' ? 'Defender XDR table' : 'Google SecOps UDM event type'} records, counting it for a technique when at least half the technique's recordings hold it. Logs with no direct equivalent aren't counted.`;
    if (!data.sources) return message('Loading…');
    const groupT = groupTechniques();
    if (groupT === undefined) return message('Loading…');
    const s = state.sel;
    const all = data.sources[siemKey()];
    const platformsOf = Object.fromEntries((data.techniques || []).map(t => [t.technique, t.platforms]));
    const rows = all.filter(d => (!s.source.size || s.source.has(d.name))
      && (!s.technique.size || anyIn(d.technique_ids, s.technique))
      && (!s.log.size || anyIn(d.logs, s.log))
      && (!groupT || d.technique_ids.some(t => groupT.has(t)))
      && (!s.platform.size || d.technique_ids.some(t => anyIn(platformsOf[t], s.platform))));
    shown(rows.length, all.length, 'data source');
    if (!rows.length) return message('No data source matches the filters.');
    $('em-results').innerHTML = `<div class="ms-table-wrap"><table class="ms-table em-table">
      <thead><tr><th>${state.siem === 'mde' ? 'Table' : 'UDM event type'}</th><th>Techniques</th><th>From logs</th><th>Techniques it records</th></tr></thead>
      <tbody>${pageOf(rows).map(d => {
        const tids = groupT ? d.technique_ids.filter(t => groupT.has(t)) : s.technique.size ? d.technique_ids.filter(t => s.technique.has(t)) : d.technique_ids;
        return `<tr><td><code>${esc(d.name)}</code></td><td>${d.techniques}${tids.length !== d.techniques ? `<br><small>${tids.length} filtered</small>` : ''}</td>
          <td>${chips(d.logs, 4)}</td>
          <td class="em-tids">${tids.slice(0, 18).map(t => `<span title="${esc(techName(t))}">${techLink(t)}</span>`).join(' ')}${tids.length > 18 ? ` <small>+${tids.length - 18}</small>` : ''}</td></tr>`;
      }).join('')}</tbody></table></div>`;
  }

  // A technique link opens it in the technique view
  $('em-results').addEventListener('click', e => {
    const link = e.target.closest('.em-tid');
    if (link) {
      const tid = link.dataset.tid;
      state.sel.technique = new Set([tid]);
      multis.technique.label();
      state.open.add(tid);
      state.view = $('em-view').value = 'technique';
      state.page = 1;
      render();
      return;
    }
    const row = e.target.closest('tr.em-row');
    if (row && !e.target.closest('a')) toggle(row.dataset.tid);
  });
  $('em-results').addEventListener('keydown', e => {
    const row = e.target.closest('tr.em-row');
    if (row && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggle(row.dataset.tid); }
  });
  function toggle(tid) {
    if (state.open.has(tid)) state.open.delete(tid); else state.open.add(tid);
    render();
  }

  // ---------- Loading ----------
  let loading = 0;
  function reload() {
    data.details = {}; data.search = {};
    const mine = ++loading;
    const q = `?${collectionsParam()}`;
    data.techniques = data.sources = null;
    render();
    return Promise.all([
      json(`/api/telemetry/techniques${q}`).then(r => { if (mine === loading) data.techniques = r.techniques; }).catch(() => { data.techniques = []; }),
      json(`/api/telemetry/data-sources${q}`).then(r => { if (mine === loading) data.sources = r; }).catch(() => { data.sources = { mde: [], udm: [] }; }),
    ]).then(() => {
      if (mine !== loading) return;
      const logs = new Set();
      data.techniques.forEach(t => t.logs.forEach(l => logs.add(l)));
      setOptions('log', [...logs].sort().map(l => ({ value: l, label: l })));
      techniqueOptions();
      sourceOptions();
      render();
    });
  }

  function techniqueOptions() {
    if (!data.techniques) return;
    setOptions('technique', data.techniques.map(t => ({ value: t.technique, label: `${t.technique} ${techName(t.technique)}`, hint: plural(t.recordings, 'recording') })));
  }

  json('/api/attack/techniques').then(r => {
    r.techniques.forEach(t => { data.names[t.id] = { name: t.name, tactics: t.tactics }; });
    techniqueOptions();
    render();
  }).catch(() => {});

  if (signedIn) {
    json('/api/telemetry/groups').then(r => {
      data.groups = r.groups;
      setOptions('group', r.groups.map(g => ({ value: g.group, label: g.group })));
    }).catch(() => {}).finally(() => { data.groupsLoaded = true; render(); });
  } else {
    data.groupsLoaded = true;
  }

  // ?technique=T1003.001, ?group=APT29 or ?view=source open the page there
  const params = new URLSearchParams(location.search);
  if (params.get('technique')) { const t = params.get('technique').toUpperCase(); state.sel.technique.add(t); state.open.add(t); multis.technique.label(); }
  if (params.get('group')) { state.sel.group.add(params.get('group')); state.view = 'group'; multis.group.label(); }
  if (['technique', 'group', 'source'].includes(params.get('view'))) state.view = params.get('view');
  $('em-view').value = state.view;
  defaultCollections();
  render();
  status();
  reload();
})();
