// Build → Emulate → Lab (templates/emulate.html, archer/lab/web.py): the host, the machines
// you can create on it, and the ones that exist, with their lifecycle and provisioning.
(function () {
  const root = document.getElementById('lab');
  if (!root) return;
  const page = document.querySelector('.em-page');
  const isAdmin = page && page.dataset.admin === 'true';
  const signedIn = page && page.dataset.signedIn === 'true';
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const el = id => document.getElementById(id);
  const api = (path, opts) => fetch(path, opts).then(r => r.json());

  const modal = el('lab-modal'), modalBody = el('lab-modal-body'), modalTitle = el('lab-modal-title');
  function openModal(title, html) { modalTitle.textContent = title; modalBody.innerHTML = html; modal.hidden = false; }
  function closeModal() { modal.hidden = true; modalBody.innerHTML = ''; }
  el('lab-modal-close').addEventListener('click', closeModal);
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !modal.hidden) closeModal(); });

  function host(h) {
    const engines = h.engines.map(e => {
      let state, cls;
      if (!e.supported) { state = 'not on this host'; cls = 'is-na'; }
      else if (e.running) { state = `ready · ${esc(e.version)}`; cls = 'is-ready'; }
      else if (e.installed) { state = 'installed, not running'; cls = 'is-warn'; }
      else { state = 'not installed'; cls = 'is-missing'; }
      const install = e.install ? `<code class="lab-install">${esc(e.install)}</code>` : '';
      return `<li class="lab-engine ${cls}"><div><span class="lab-engine-name">${engineIcon(e.key)}<strong>${esc(e.name)}</strong></span> <span class="lab-engine-state">${state}</span>
        <div class="lab-engine-runs">${esc(e.runs)}</div></div>${install}</li>`;
    }).join('');
    // The engines are collapsed by default — you rarely need them once a platform is ready
    el('lab-host').innerHTML = `<div class="lab-host-head">This host: <strong>${esc(h.label)}</strong>
      <span class="lab-host-arch">${esc(h.os)} · ${esc(h.arch)}</span></div>
      <details class="lab-host-platforms">
        <summary>${esc(h.label)} supports the following platforms</summary>
        <ul class="lab-engines">${engines}</ul>
      </details>`;
  }

  const KIND = t => (t.kind === 'container' ? 'container' : 'VM');
  const ENGINE_NAME = { docker: 'Docker', tart: 'Tart', vmware: 'VMware', parallels: 'Parallels' };

  // One card per OS; each way of running it (Docker, Tart…) is a row with its own Create button
  function templateCards(tpls) {
    const byOs = new Map();
    tpls.forEach(t => { (byOs.get(t.os) || byOs.set(t.os, []).get(t.os)).push(t); });
    return [...byOs].map(([os, group]) => {
      const base = group[0].name.replace(/\s+(container|vm)$/i, '');
      return `<div class="lab-template"><div class="lab-template-top"><span class="lab-template-name">${osIcon(os)}<strong>${esc(base)}</strong></span></div>
        <div class="lab-variants">${group.map(variantRow).join('')}</div></div>`;
    }).join('');
  }

  function variantRow(t) {
    const badge = t.ready ? '<span class="lab-badge is-ready">Ready</span>'
      : `<span class="lab-badge is-off" title="${esc(t.reason)}">${esc(t.reason)}</span>`;
    const btn = isAdmin && t.ready ? `<button type="button" class="ui-pill lab-create" data-t="${esc(t.id)}">Create</button>` : '';
    return `<div class="lab-variant">
      <div class="lab-variant-head"><span class="lab-engine-name">${engineIcon(t.engine)}<strong>${esc(ENGINE_NAME[t.engine] || t.engine)} ${KIND(t)}</strong></span>${badge}</div>
      <p class="lab-variant-about">${esc(t.about)}</p>
      <p class="lab-template-records"><span>Records:</span> ${esc(t.records)}</p>${btn}</div>`;
  }

  const OS_ICON = { windows: 'windows.svg', macos: 'macos.png', linux: 'linux.png' };
  function osIcon(os) {
    const f = OS_ICON[os];
    if (!f) return '';
    return `<img class="lab-os-icon is-${esc(os)}" src="/static/images/os/${f}" alt="${esc(os)}" width="18" height="18">`;
  }

  // docker and tart are the engines Archer drives today; vmware/parallels are staged for if they're added
  const ENGINE_ICON = { docker: 'docker.png', tart: 'tart.png', vmware: 'vmware.svg', parallels: 'parallels.png' };
  function engineIcon(key) {
    const f = ENGINE_ICON[key];
    if (!f) return '';
    return `<img class="lab-engine-icon is-${esc(key)}" src="/static/images/os/${f}" alt="${esc(key)}" width="18" height="18">`;
  }

  function machineRow(m) {
    const dot = `<span class="lab-dot is-${m.state}" title="${esc(m.state)}"></span>`;
    const text = [m.engine, m.records && ('records ' + m.records)].filter(Boolean).map(esc).join(' · ');
    const meta = engineIcon(m.engine) + `<span>${text}</span>`;
    const steps = (m.provisioned || []).length ? `<span class="lab-prov">set up: ${m.provisioned.map(esc).join(', ')}</span>` : '';
    let actions = '';
    if (isAdmin) {
      const on = m.state === 'running';
      actions = `<div class="lab-actions">
        <button type="button" class="ui-pill lab-act" data-a="${on ? 'stop' : 'start'}">${on ? 'Stop' : 'Start'}</button>
        <button type="button" class="ui-pill lab-act" data-a="snapshot">Snapshot</button>
        <button type="button" class="ui-pill lab-act" data-a="revert">Revert</button>
        ${m.os ? '<button type="button" class="ui-pill lab-act" data-a="provision">Set up</button>' : ''}
        ${m.os ? '<button type="button" class="ui-pill lab-act" data-a="record">Record</button>' : ''}
        <button type="button" class="ui-pill" data-a="logs">Logs</button>
        <button type="button" class="ui-pill lab-danger" data-a="delete">Delete</button>
      </div>`;
    }
    return `<li class="lab-machine" data-engine="${esc(m.engine)}" data-name="${esc(m.name)}" data-os="${esc(m.os)}">
      <div class="lab-machine-head">${dot}${osIcon(m.os)}<strong>${esc(m.name)}</strong></div>
      <div class="lab-machine-meta">${meta}${m.detail ? ' · ' + esc(m.detail) : ''}</div>${steps}${actions}</li>`;
  }

  let timer = null;
  function pollJob() {
    api('/api/lab/job').then(({ job, log }) => {
      const box = el('lab-job');
      if (job.state === 'idle') { box.hidden = true; return; }
      box.hidden = false;
      el('lab-job-state').textContent = job.state === 'running' ? (job.what + '…')
        : job.state === 'error' ? ('Failed: ' + (job.error || '')) : (job.what + ' — done');
      el('lab-job-log').textContent = (log || []).join('\n');
      if (job.state === 'running') { if (!timer) timer = setInterval(pollJob, 1500); }
      else { clearInterval(timer); timer = null; refresh(); }
    });
  }

  let taken = new Set();  // every machine name on the host, for suggesting a clash-free new one
  function refresh() {
    api('/api/lab/overview').then(data => {
      host(data.host);
      taken = new Set(data.taken || []);
      const tpls = data.templates || [];
      el('lab-templates').innerHTML = templateCards(tpls);
      el('lab-templates-empty').hidden = tpls.length > 0;
      const ms = data.machines || [];
      el('lab-machines').innerHTML = ms.map(machineRow).join('');
      el('lab-machines-empty').hidden = ms.length > 0;
      if (data.job && data.job.state === 'running' && !timer) pollJob();
    });
  }

  function post(path, body) {
    return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(r => { if (r.error) alert(r.error + (r.detail ? '\n\n' + r.detail : '')); return r; });
  }

  // A free name that starts with "archer" and can't clash with a machine already on the host
  function suggestName(id) {
    const slug = id.replace(/-(vm|container)$/, '');
    for (let n = 1; ; n++) {
      const name = `archer-${slug}-${n}`;
      if (!taken.has(name)) return name;
    }
  }

  // Create
  root.addEventListener('click', e => {
    const c = e.target.closest('.lab-create');
    if (!c) return;
    const id = c.dataset.t;
    openModal('Create a machine', `<label class="lab-field">Name
      <input type="text" id="lab-name" value="${esc(suggestName(id))}" autocomplete="off"></label>
      <p class="lab-hint">Letters, digits, dot, dash or underscore.</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-name-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-name-go">Create</button></div>`);
    const go = () => {
      const name = el('lab-name').value.trim();
      if (!name) return;
      closeModal();
      post('/api/lab/create', { template: id, name }).then(r => { if (r.started) pollJob(); });
    };
    el('lab-name-go').addEventListener('click', go);
    el('lab-name-cancel').addEventListener('click', closeModal);
    el('lab-name').addEventListener('keydown', ev => { if (ev.key === 'Enter') go(); });
    el('lab-name').focus();
    el('lab-name').select();
  });

  // Machine actions
  el('lab-machines').addEventListener('click', e => {
    const btn = e.target.closest('[data-a]');
    if (!btn) return;
    const li = btn.closest('.lab-machine');
    const engine = li.dataset.engine, name = li.dataset.name, os = li.dataset.os;
    const act = btn.dataset.a;
    if (act === 'start' || act === 'stop') {
      post('/api/lab/action', { engine, name, action: act }).then(refresh);
    } else if (act === 'delete') {
      if (confirm(`Delete ${name}? This removes the machine and its snapshots for good.`))
        post('/api/lab/action', { engine, name, action: 'delete' }).then(refresh);
    } else if (act === 'snapshot') {
      snapshotDialog(engine, name);
    } else if (act === 'revert') {
      revertDialog(engine, name);
    } else if (act === 'provision') {
      provisionDialog(engine, name, os);
    } else if (act === 'record') {
      recordDialog(engine, name, os);
    } else if (act === 'logs') {
      api(`/api/lab/logs?engine=${encodeURIComponent(engine)}&name=${encodeURIComponent(name)}`)
        .then(r => openModal(`Logs — ${name}`, `<pre class="lab-logs">${esc(r.logs || r.error || 'No output')}</pre>`));
    }
  });

  function snapshotDialog(engine, name) {
    openModal(`Snapshot ${name}`, `<label class="lab-field">Snapshot name
      <input type="text" id="lab-snap" value="clean" autocomplete="off"></label>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-snap-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-snap-go">Snapshot</button></div>`);
    el('lab-snap-go').addEventListener('click', () => {
      const snap = el('lab-snap').value.trim(); if (!snap) return; closeModal();
      post('/api/lab/action', { engine, name, action: 'snapshot', snapshot: snap }).then(refresh);
    });
    el('lab-snap-cancel').addEventListener('click', closeModal);
  }

  function revertDialog(engine, name) {
    openModal(`Revert ${name}`, `<label class="lab-field">Snapshot to revert to
      <input type="text" id="lab-snap" value="clean" autocomplete="off"></label>
      <p class="lab-hint">Everything since that snapshot is discarded.</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-snap-cancel">Cancel</button>
      <button type="button" class="btn-primary lab-danger" id="lab-snap-go">Revert</button></div>`);
    el('lab-snap-go').addEventListener('click', () => {
      const snap = el('lab-snap').value.trim(); if (!snap) return; closeModal();
      post('/api/lab/action', { engine, name, action: 'revert', snapshot: snap }).then(r => { if (r.started) pollJob(); });
    });
    el('lab-snap-cancel').addEventListener('click', closeModal);
  }

  function provisionDialog(engine, name, os) {
    api(`/api/lab/provision-steps?os=${encodeURIComponent(os)}`).then(({ steps }) => {
      if (!steps || !steps.length) { openModal('Set up', '<p>No provisioning for this OS.</p>'); return; }
      const rows = steps.map(s => `<button type="button" class="ui-pill lab-step" data-step="${esc(s.step)}">${esc(s.label)}</button>`).join('');
      openModal(`Set up ${name}`, `<p class="lab-hint">Each step changes the machine. Snapshot it first.</p>
        <div class="lab-steps">${rows}</div>`);
      modalBody.querySelectorAll('.lab-step').forEach(b => b.addEventListener('click', () => {
        closeModal();
        post('/api/lab/provision', { engine, name, os, step: b.dataset.step }).then(r => { if (r.started) pollJob(); });
      }));
    });
  }

  function recordDialog(engine, name, os) {
    openModal(`Record on ${name}`, `
      <label class="lab-field">ATT&CK techniques
        <input type="text" id="lab-tech" placeholder="T1059.001, T1053.003" autocomplete="off"></label>
      <p class="lab-hint">Atomic Red Team runs these in the machine and Archer imports the logs as <strong>Your lab</strong>.
        The tests change the machine — snapshot it first and revert after.</p>
      <label class="lab-field">Revert to snapshot afterwards (optional)
        <input type="text" id="lab-revert" value="clean" autocomplete="off"></label>
      <div class="lab-preview" id="lab-preview" hidden></div>
      <label class="lab-confirm"><input type="checkbox" id="lab-snapped"> I've snapshotted this machine and it's disposable</label>
      <div class="lab-modal-actions">
        <button type="button" class="ui-pill" id="lab-rec-preview">Preview</button>
        <button type="button" class="btn-primary lab-danger" id="lab-rec-go" disabled>Run atomics</button>
      </div>`);
    const techEl = el('lab-tech'), snapped = el('lab-snapped'), go = el('lab-rec-go');
    const body = { engine, name, os };
    const sync = () => { go.disabled = !(snapped.checked && techEl.value.trim()); };
    snapped.addEventListener('change', sync);
    techEl.addEventListener('input', sync);
    el('lab-rec-preview').addEventListener('click', () => {
      post('/api/lab/record', { ...body, techniques: techEl.value, execute: false }).then(r => {
        if (!r || !r.plan) return;
        const warn = (r.warnings || []).length
          ? `<div class="lab-warn">Not ready: ${r.warnings.map(esc).join('; ')}</div>` : '';
        el('lab-preview').hidden = false;
        el('lab-preview').innerHTML = warn + '<ol class="lab-plan">' +
          r.plan.map(s => `<li>${esc(s)}</li>`).join('') + '</ol>';
      });
    });
    go.addEventListener('click', () => {
      const revert = el('lab-revert').value.trim();
      closeModal();
      post('/api/lab/record', { ...body, techniques: techEl.value, revert_to: revert, execute: true })
        .then(r => { if (r && r.started) pollJob(); });
    });
    techEl.focus();
  }

  if (!signedIn || !isAdmin) el('lab-guest').hidden = false;
  if (!signedIn) el('lab-guest').textContent = 'Log in as an admin to create and manage machines.';
  refresh();
})();
