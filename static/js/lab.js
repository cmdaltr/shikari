// Build → Emulate → Lab (templates/emulate.html, archer/lab/web.py): the host, the machines
// you can create on it, and the ones that exist, with their lifecycle and provisioning.
(function () {
  const root = document.getElementById('lab');
  if (!root) return;
  const page = document.querySelector('.em-page');
  const signedIn = page && page.dataset.signedIn === 'true';
  // Effective-role flags come from /overview (so a temporary elevation counts), not the page's
  // base-role dataset. They stay false until the first refresh answers.
  let canLab = false;   // operational analyst or admin — may use the lab
  let isAdmin = false;  // admin — may manage any machine
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
      // Show the engine's note when it's installed but not answering (e.g. UTM needs Automation access)
      const note = e.note && e.installed && !e.running ? `<p class="lab-engine-note">${esc(e.note)}</p>` : '';
      return `<li class="lab-engine ${cls}"><div><span class="lab-engine-name">${engineIcon(e.key)}<strong>${esc(e.name)}</strong></span> <span class="lab-engine-state">${state}</span>
        <div class="lab-engine-runs">${esc(e.blurb || e.runs)}</div>${note}</div>${install}</li>`;
    }).join('');
    // The engines are collapsed by default — you rarely need them once a platform is ready
    el('lab-host').innerHTML = `<div class="lab-host-head">This host: <strong>${esc(h.label)}</strong>
      <span class="lab-host-arch">${esc(h.os)} · ${esc(h.arch)}</span></div>
      <details class="lab-host-platforms">
        <summary>${esc(h.label)} supports the following platforms</summary>
        <ul class="lab-engines">${engines}</ul>
      </details>`;
  }

  const ENGINE_NAME = { docker: 'Docker', tart: 'Tart', vmware: 'VMware', parallels: 'Parallels' };

  // One card per OS; the way to run it (Docker, Tart…) is a Create button with that engine's logo
  function templateCards(tpls) {
    const byOs = new Map();
    tpls.forEach(t => { (byOs.get(t.os) || byOs.set(t.os, []).get(t.os)).push(t); });
    return [...byOs].map(([os, group]) => {
      const g0 = group[0];
      const row = canLab ? `<div class="lab-create-row">${group.map(createButton).join('')}</div>` : '';
      return `<div class="lab-template"><div class="lab-template-top"><span class="lab-template-name">${osIcon(os)}<strong>${esc(g0.os_name)}</strong></span></div>
        <p class="lab-template-about">${esc(g0.os_about)}</p>
        <p class="lab-template-records"><span>Records:</span> ${esc(g0.os_records)}</p>${row}</div>`;
    }).join('');
  }

  // UTM can't create a VM from an image, so instead of a Create button this card tells you how:
  // build it in UTM once, then it shows up under Your machines for Archer to drive.
  function utmCard(hostData) {
    const utm = (hostData.engines || []).find(e => e.key === 'utm');
    if (!utm || !utm.supported) return '';
    let body;
    if (utm.running) {
      const buttons = canLab ? `<div class="lab-create-row">
          <button type="button" class="ui-pill lab-win" data-win="clone">${engineIcon('utm')}<span>Clone existing</span></button>
          <button type="button" class="ui-pill lab-win" data-win="iso">${osIcon('windows')}<span>From ISO</span></button>
        </div>` : '';
      body = `<p class="lab-template-about">Two ways to a Windows machine: clone one you've already built, or build a new one from a Microsoft ISO (you make it in UTM once, then Archer manages it).</p>${buttons}`;
    } else {
      const note = utm.installed
        ? "Open UTM once and allow Archer's Automation access (System Settings → Privacy & Security → Automation). Then Windows machines can be cloned or built from an ISO here."
        : "Install UTM to run Windows 11 on ARM and other OSes QEMU supports.";
      const install = !utm.installed && utm.install ? `<p class="lab-template-records"><code class="lab-install">${esc(utm.install)}</code></p>` : '';
      body = `<p class="lab-template-about">${esc(note)}</p>${install}`;
    }
    return `<div class="lab-template lab-template-utm"><div class="lab-template-top"><span class="lab-template-name">${engineIcon('utm')}<strong>Windows &amp; others, via UTM</strong></span></div>${body}</div>`;
  }

  function createButton(t) {
    const label = ENGINE_NAME[t.engine] || t.engine;
    const title = t.ready ? `Create with ${label}` : t.reason;
    return `<button type="button" class="ui-pill lab-create" data-t="${esc(t.id)}" title="${esc(title)}"${t.ready ? '' : ' disabled'}>${engineIcon(t.engine)}<span>Create</span></button>`;
  }

  const OS_ICON = { windows: 'windows.svg', macos: 'macos.png', linux: 'linux.png' };
  function osIcon(os) {
    const f = OS_ICON[os];
    if (!f) return '';
    return `<img class="lab-os-icon is-${esc(os)}" src="/static/images/os/${f}" alt="${esc(os)}" width="18" height="18">`;
  }

  // docker, tart and utm are the engines Archer drives; vmware/parallels are staged for if they're added
  const ENGINE_ICON = { docker: 'docker.png', tart: 'tart.png', utm: 'utm.svg', vmware: 'vmware.svg', parallels: 'parallels.png' };
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
    if (m.manageable) {
      const on = m.state === 'running';
      // A UTM VM Archer didn't create needs its OS set before it can be set up or recorded on
      const needsOs = m.engine === 'utm' && !m.os;
      const setOs = needsOs ? '<button type="button" class="ui-pill lab-act" data-a="adopt">Set OS</button>' : '';
      actions = `<div class="lab-actions">
        <button type="button" class="ui-pill lab-act" data-a="${on ? 'stop' : 'start'}">${on ? 'Stop' : 'Start'}</button>
        <button type="button" class="ui-pill lab-act" data-a="snapshot">Snapshot</button>
        <button type="button" class="ui-pill lab-act" data-a="revert">Revert</button>
        ${m.engine === 'utm' ? '<button type="button" class="ui-pill lab-act" data-a="clone">Clone</button>' : ''}
        ${setOs}
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
  let lastMachines = [];  // the last machines listing, for the clone-from-create picker
  function refresh() {
    api('/api/lab/overview').then(data => {
      canLab = !!data.can_lab;
      isAdmin = !!data.is_admin;
      host(data.host);
      taken = new Set(data.taken || []);
      const tpls = data.templates || [];
      el('lab-templates').innerHTML = templateCards(tpls) + utmCard(data.host);
      el('lab-templates-empty').hidden = tpls.length > 0;
      const ms = data.machines || [];
      lastMachines = ms;
      el('lab-machines').innerHTML = ms.map(machineRow).join('');
      el('lab-machines-empty').hidden = ms.length > 0;
      const guest = el('lab-guest');
      guest.hidden = canLab;
      guest.textContent = signedIn
        ? 'You need the Operational analyst role to create and manage machines. Ask an admin to grant it.'
        : 'Log in as an Operational analyst or admin to create and manage machines.';
      el('lab-machines-empty').hidden = ms.length > 0 || !canLab;
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

  // Windows: clone an existing VM, or the guided from-ISO build
  root.addEventListener('click', e => {
    const b = e.target.closest('.lab-win');
    if (!b) return;
    if (b.dataset.win === 'clone') cloneFromCreate(); else isoDialog();
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
    } else if (act === 'clone') {
      cloneDialog(engine, name);
    } else if (act === 'adopt') {
      adoptDialog(engine, name);
    } else if (act === 'logs') {
      api(`/api/lab/logs?engine=${encodeURIComponent(engine)}&name=${encodeURIComponent(name)}`)
        .then(r => openModal(`Logs — ${name}`, `<pre class="lab-logs">${esc(r.logs || r.error || 'No output')}</pre>`));
    }
  });

  // A clash-free clone name from the source: archer-win11 -> archer-win11-2
  function suggestCloneName(src) {
    const stem = src.replace(/-\d+$/, '');
    for (let n = 2; ; n++) {
      const name = `${stem}-${n}`;
      if (!taken.has(name)) return name;
    }
  }

  function cloneDialog(engine, name) {
    openModal(`Clone ${name}`, `<label class="lab-field">New machine name
      <input type="text" id="lab-clone" value="${esc(suggestCloneName(name))}" autocomplete="off"></label>
      <p class="lab-hint">Copies the VM and its disk into a new machine — a few minutes. The clone inherits ${esc(name)}'s OS and set-up; snapshot it before recording.</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-clone-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-clone-go">Clone</button></div>`);
    const go = () => {
      const newName = el('lab-clone').value.trim();
      if (!newName) return;
      closeModal();
      post('/api/lab/clone', { engine, name, new_name: newName }).then(r => { if (r.started) pollJob(); });
    };
    el('lab-clone-go').addEventListener('click', go);
    el('lab-clone-cancel').addEventListener('click', closeModal);
    el('lab-clone').addEventListener('keydown', ev => { if (ev.key === 'Enter') go(); });
    el('lab-clone').focus();
    el('lab-clone').select();
  }

  // Clone from the create area: pick a source UTM VM, then clone it
  function cloneFromCreate() {
    const utmVms = lastMachines.filter(m => m.engine === 'utm');
    if (!utmVms.length) {
      openModal('Clone a Windows VM', `<p class="lab-hint">No UTM VM to clone yet. Build one from an ISO first (the From ISO button), then clone it here.</p>
        <div class="lab-modal-actions"><button type="button" class="btn-primary" id="lab-ok">OK</button></div>`);
      el('lab-ok').addEventListener('click', closeModal);
      return;
    }
    const opts = utmVms.map(m => `<option value="${esc(m.name)}">${esc(m.name)}${m.os ? ` (${esc(m.os)})` : ''}</option>`).join('');
    openModal('Clone a Windows VM', `<label class="lab-field">Clone from
      <select id="lab-src" class="dropdown-styled">${opts}</select></label>
      <label class="lab-field">New machine name
      <input type="text" id="lab-clone" autocomplete="off"></label>
      <p class="lab-hint">Copies the VM (instant on APFS until it diverges). The clone inherits the source's OS and set-up; snapshot it before recording.</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-clone-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-clone-go">Clone</button></div>`);
    const src = el('lab-src'), nameInput = el('lab-clone');
    const sync = () => { nameInput.value = suggestCloneName(src.value); };
    sync();
    src.addEventListener('change', sync);
    const go = () => {
      const newName = nameInput.value.trim();
      if (!newName) return;
      closeModal();
      post('/api/lab/clone', { engine: 'utm', name: src.value, new_name: newName }).then(r => { if (r.started) pollJob(); });
    };
    el('lab-clone-go').addEventListener('click', go);
    el('lab-clone-cancel').addEventListener('click', closeModal);
    nameInput.addEventListener('keydown', ev => { if (ev.key === 'Enter') go(); });
  }

  // Guided build from a Microsoft ISO — Archer verifies the ISO; you build the VM in UTM once
  function isoDialog() {
    openModal('Build a Windows VM from an ISO', `<ol class="lab-iso-steps">
      <li>Download the official <strong>Windows 11 Arm64</strong> ISO from
        <a href="https://www.microsoft.com/software-download/windows11arm64" target="_blank" rel="noopener">Microsoft</a> (~5 GB).</li>
      <li>Check it's the right installer:
        <label class="lab-field">Path to the .iso
          <input type="text" id="lab-iso-path" placeholder="~/Downloads/Win11_arm64.iso" autocomplete="off"></label>
        <div class="lab-iso-check"><button type="button" class="ui-pill" id="lab-iso-go">Verify ISO</button>
          <span id="lab-iso-result" class="lab-iso-result"></span></div></li>
      <li>In UTM: <strong>New Virtual Machine → Virtualize → Windows</strong>, pick that ISO, 4 GB RAM, name it without spaces (e.g. <code>archer-win11</code>), and install the <strong>UTM guest tools</strong> so Archer can run commands in it.</li>
      <li>It appears under Your machines. <strong>Set OS → Windows</strong>, then <strong>Set up</strong> and <strong>Record</strong>. For more Windows VMs after this, use <strong>Clone</strong> — no reinstall.</li>
    </ol>
    <div class="lab-modal-actions"><button type="button" class="btn-primary" id="lab-iso-close">Done</button></div>`);
    el('lab-iso-close').addEventListener('click', closeModal);
    el('lab-iso-go').addEventListener('click', () => {
      const path = el('lab-iso-path').value.trim();
      const out = el('lab-iso-result');
      if (!path) { out.textContent = 'Give the path first.'; out.className = 'lab-iso-result is-bad'; return; }
      out.textContent = 'Checking…'; out.className = 'lab-iso-result';
      post('/api/lab/verify-iso', { path }).then(r => {
        if (r && r.error) { out.textContent = r.error; out.className = 'lab-iso-result is-bad'; return; }
        out.textContent = r.detail || '';
        out.className = 'lab-iso-result ' + (r.ok_arm64 ? 'is-good' : 'is-bad');
      });
    });
  }

  function adoptDialog(engine, name) {
    openModal(`Set the OS for ${name}`, `<label class="lab-field">Operating system
      <select id="lab-os" class="dropdown-styled">
        <option value="windows">Windows</option>
        <option value="linux">Linux</option>
        <option value="macos">macOS</option>
      </select></label>
      <p class="lab-hint">So Archer knows how to turn on logging, install Atomic Red Team and record on it.</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-os-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-os-go">Save</button></div>`);
    el('lab-os-go').addEventListener('click', () => {
      closeModal();
      post('/api/lab/adopt', { engine, name, os: el('lab-os').value }).then(refresh);
    });
    el('lab-os-cancel').addEventListener('click', closeModal);
  }

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

  refresh();  // sets canLab/isAdmin and the guest notice from the server's effective-role check
})();
