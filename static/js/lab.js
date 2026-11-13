// Build → Emulate → Lab (templates/emulate.html, shikari/lab/web.py): the host, the machines
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

  const ENGINE_NAME = { docker: 'Docker', tart: 'Tart', hyperv: 'Hyper-V', libvirt: 'KVM', vmware: 'VMware', parallels: 'Parallels' };
  // Engines that drive VMs they didn't make: an unadopted one needs its OS set (machines.HAND_BUILT)
  const HAND_BUILT = ['utm', 'hyperv', 'libvirt'];
  // Shared engine descriptions, used by the Create buttons and the Info modal so they can't drift.
  const engineKind = t => (t.kind === 'container' ? 'container' : 'VM');
  const engineWhy = t => (t.kind === 'container'
    ? 'Light and fast to reset; shares the host kernel, so no Sysmon for Linux.'
    : 'A full VM with its own kernel — heavier, but records exactly like a real host (Sysmon for Linux too).');
  let templateInfo = {};  // card name -> { records, engines:[{label, why}] }, filled when cards render

  // One card per OS; the way to run it (Docker, Tart…) is a Create button with that engine's logo
  function templateCards(tpls) {
    // One card per distro (Linux) or OS — the backend's `group`, so Ubuntu and Rocky are separate.
    const byGroup = new Map();
    tpls.forEach(t => { const k = t.group || t.os; (byGroup.get(k) || byGroup.set(k, []).get(k)).push(t); });
    return [...byGroup].map(([, group]) => {
      const g0 = group[0];
      const row = canLab ? `<div class="lab-create-row">${group.map(createButton).join('')}</div>` : '';
      templateInfo[g0.os_name] = { records: g0.os_records,
        engines: group.map(t => ({ label: `${ENGINE_NAME[t.engine] || t.engine} ${engineKind(t)}`, why: engineWhy(t) })) };
      return `<div class="lab-template"><div class="lab-template-top"><span class="lab-template-name">${osIcon(g0.os, g0.os_name)}<strong>${esc(g0.os_name)}</strong></span>
        <button type="button" class="ui-pill lab-template-info" data-name="${esc(g0.os_name)}">${actIcon('info')}Info</button></div>
        <p class="lab-template-about">${esc(g0.os_about)}</p>${row}</div>`;
    }).join('');
  }

  // UTM can't create a VM from an image, so instead of a Create button this card tells you how:
  // build it in UTM once, then it shows up under Your machines for Shikari to drive.
  function utmCard(hostData) {
    const utm = (hostData.engines || []).find(e => e.key === 'utm');
    if (!utm || !utm.supported) return '';
    let body;
    if (utm.running) {
      const buttons = canLab ? `<div class="lab-create-row">
          <button type="button" class="ui-pill lab-win" data-win="clone">${engineIcon('utm')}<span>Clone existing</span></button>
          <button type="button" class="ui-pill lab-win" data-win="iso">${osIcon('windows')}<span>From ISO</span></button>
        </div>` : '';
      body = `<p class="lab-template-about">Two ways to a Windows machine: clone one you've already built, or build a new one from a Microsoft ISO (you make it in UTM once, then Shikari manages it).</p>${buttons}`;
    } else {
      const note = utm.installed
        ? "Open UTM once and allow Shikari's Automation access (System Settings → Privacy & Security → Automation). Then Windows machines can be cloned or built from an ISO here."
        : "Install UTM to run Windows 11 on ARM and other OSes QEMU supports.";
      const install = !utm.installed && utm.install ? `<p class="lab-template-records"><code class="lab-install">${esc(utm.install)}</code></p>` : '';
      body = `<p class="lab-template-about">${esc(note)}</p>${install}`;
    }
    templateInfo['Windows 11'] = {
      records: 'Security event log (process creation incl. command line), PowerShell Script Block Logging, Windows audit policy',
      engines: [{ label: 'UTM (QEMU)', why: 'Windows 11 on ARM, built once in the UTM app, then managed here — the only engine that runs Windows.' }] };
    return `<div class="lab-template lab-template-utm"><div class="lab-template-top"><span class="lab-template-name">${engineIcon('utm')}<strong>Windows &amp; others, via UTM</strong></span>
      <button type="button" class="ui-pill lab-template-info" data-name="Windows 11">${actIcon('info')}Info</button></div>${body}</div>`;
  }

  // Hyper-V (Windows host) and KVM (Linux host) build a VM from your own disk image or ISO — the
  // way to a Windows machine there, since Microsoft publish no image a template could pull.
  function vmHostCards(hostData) {
    return (hostData.engines || []).filter(e => (e.key === 'hyperv' || e.key === 'libvirt') && e.supported).map(e => {
      const label = e.key === 'hyperv' ? 'Hyper-V' : 'KVM';
      let body;
      if (e.running) {
        const buttons = canLab ? `<div class="lab-create-row">
            <button type="button" class="ui-pill lab-win" data-win="image" data-engine="${esc(e.key)}">${osIcon('windows')}<span>From disk or ISO</span></button>
          </div>` : '';
        body = `<p class="lab-template-about">Build a VM from a ${e.key === 'hyperv' ? 'VHDX, VHD' : 'qcow2'} or ISO on this host, or adopt one you built in ${e.key === 'hyperv' ? 'Hyper-V Manager' : 'virt-manager'} (an admin sees it under Your machines; Set OS claims it).</p>${buttons}`;
      } else {
        const note = e.installed ? (e.note || `${label} is installed but isn't answering.`) : `Install ${label} to run Windows and Linux VMs here.`;
        const install = !e.installed && e.install ? `<p class="lab-template-records"><code class="lab-install">${esc(e.install)}</code></p>` : '';
        body = `<p class="lab-template-about">${esc(note)}</p>${install}`;
      }
      templateInfo[`Windows (${label})`] = {
        records: 'Security event log (process creation incl. command line), PowerShell Script Block Logging, Windows audit policy',
        engines: [{ label: `${label} VM`, why: e.key === 'hyperv'
          ? 'Commands run in a Windows guest through PowerShell Direct (no network needed), as the login you give with Set OS; a Linux guest over SSH on the Default Switch.'
          : 'Commands run through the QEMU guest agent (qemu-guest-agent; virtio-win guest tools on Windows), so the guest needs no network or SSH.' }] };
      return `<div class="lab-template"><div class="lab-template-top"><span class="lab-template-name">${osIcon('windows')}<strong>Windows &amp; others, via ${esc(label)}</strong></span>
        <button type="button" class="ui-pill lab-template-info" data-name="${esc(`Windows (${label})`)}">${actIcon('info')}Info</button></div>${body}</div>`;
    }).join('');
  }

  function createButton(t) {
    const engine = ENGINE_NAME[t.engine] || t.engine, kind = engineKind(t);
    // Say what each engine gives you, so the Tart-vs-Docker choice is self-explanatory on hover.
    const title = t.ready ? `${engine} ${kind} — ${engineWhy(t)}` : t.reason;
    return `<button type="button" class="ui-pill lab-create" data-t="${esc(t.id)}" title="${esc(title)}"${t.ready ? '' : ' disabled'}>${engineIcon(t.engine)}<span>${esc(engine)} ${esc(kind)}</span></button>`;
  }

  // Tux for Linux generally; the Ubuntu mark only when the build is actually Ubuntu
  const OS_ICON = { windows: 'windows.svg', macos: 'macos.png', linux: 'tux.svg' };
  function osIcon(os, name = '') {
    let f = OS_ICON[os];
    // Linux carries the distro's own logo, read from the name/label (rky10/Rocky, ubu24/Ubuntu).
    if (os === 'linux') f = /rocky|rky/i.test(name) ? 'rocky.svg' : /ubuntu|ubu/i.test(name) ? 'ubuntu.png' : 'tux.svg';
    if (!f) return '';
    return `<img class="lab-os-icon is-${esc(os)}" src="/static/images/os/${f}" alt="${esc(os)}" width="18" height="18">`;
  }

  // docker, tart and utm are the engines Shikari drives; vmware/parallels are staged for if they're added
  const ENGINE_ICON = { docker: 'docker.png', tart: 'tart.png', utm: 'utm.svg', vmware: 'vmware.svg', parallels: 'parallels.png' };
  function engineIcon(key) {
    const f = ENGINE_ICON[key];
    if (!f) return '';
    return `<img class="lab-engine-icon is-${esc(key)}" src="/static/images/os/${f}" alt="${esc(key)}" width="18" height="18">`;
  }

  // A small leading glyph for each machine action, so the dense action row scans at a glance.
  const ACT_ICON = {
    start: '<path d="M5 4l7 4-7 4z" fill="currentColor" stroke="none"/>',
    stop: '<rect x="4.5" y="4.5" width="7" height="7" rx="1"/>',
    snapshot: '<rect x="2.5" y="5" width="11" height="8" rx="1.5"/><circle cx="8" cy="9" r="2.1"/><path d="M6 5l1-1.4h2L10 5"/>',
    revert: '<path d="M4.5 8a3.8 3.8 0 1 0 1.1-2.7"/><path d="M3.5 4.5V8H7"/>',
    clone: '<rect x="5.5" y="5.5" width="7" height="7" rx="1.2"/><path d="M3.5 10.5V4a.5.5 0 0 1 .5-.5h6"/>',
    adopt: '<path d="M8.5 3H4v4.5L9 12l4-4z"/><circle cx="6" cy="5.5" r=".8" fill="currentColor" stroke="none"/>',
    provision: '<path d="M8 3v5.5M5.5 7L8 9.5 10.5 7"/><path d="M4 12h8"/>',
    record: '<circle cx="8" cy="8" r="3.4" fill="currentColor" stroke="none"/>',
    enrol: '<circle cx="8" cy="8" r="5"/><circle cx="8" cy="8" r="1.5" fill="currentColor" stroke="none"/>',
    logs: '<path d="M4 5h8M4 8h8M4 11h5"/>',
    console: '<rect x="2.5" y="3.5" width="11" height="9" rx="1.2"/><path d="M5 6.5l1.8 1.5L5 9.5M8.5 10h3"/>',
    desktop: '<rect x="2.5" y="3" width="11" height="7.5" rx="1"/><path d="M6 13h4M8 10.5V13"/>',
    delete: '<path d="M4 5h8M6.5 5V3.9h3V5M5.5 5l.4 8h4.2l.4-8"/>',
    info: '<circle cx="8" cy="8" r="5.5"/><path d="M8 7.3v3.4"/><circle cx="8" cy="5.2" r=".7" fill="currentColor" stroke="none"/>',
  };
  const actIcon = a => (ACT_ICON[a] ? `<svg class="lab-act-ic" viewBox="0 0 16 16" aria-hidden="true">${ACT_ICON[a]}</svg>` : '');

  function machineRow(m) {
    const dot = `<span class="lab-dot is-${m.state}" title="${esc(m.state)}"></span>`;
    const steps = (m.provisioned || []).length ? `<span class="lab-prov">installed: ${m.provisioned.map(esc).join(', ')}</span>` : '';
    const on = m.state === 'running';
    // Icon-only quick controls in the card's top-right: Start (green) / Stop (red) toggle, and Delete (red).
    const qbtn = (a, title, cls) => `<button type="button" class="lab-q ${cls}" data-a="${a}" title="${title}" aria-label="${title}">${actIcon(a)}</button>`;
    const quick = m.manageable
      ? `<span class="lab-quick">${qbtn(on ? 'stop' : 'start', on ? 'Stop' : 'Start', on ? 'is-stop' : 'is-start')}${qbtn('delete', 'Delete', 'is-del')}</span>`
      : '';
    let actions = '';
    if (m.manageable) {
      // A UTM VM Shikari didn't create needs its OS set before it can be set up or recorded on
      const needsOs = HAND_BUILT.includes(m.engine) && !m.os;
      const act = (a, label, cls = 'lab-act') => `<button type="button" class="ui-pill ${cls}" data-a="${a}">${actIcon(a)}${label}</button>`;
      actions = `<div class="lab-actions">
        ${act('snapshot', 'Snapshot')}
        ${act('revert', 'Revert')}
        ${m.engine === 'utm' ? act('clone', 'Clone') : ''}
        ${needsOs ? act('adopt', 'Set OS') : ''}
        ${m.engine === 'hyperv' && m.os ? act('adopt', 'Guest login') : ''}
        ${m.os ? act('provision', 'Install tooling') : ''}
        ${m.os ? act('record', 'Record') : ''}
        ${m.os && on && !m.enrolled ? act('enrol', 'Enrol in CALDERA') : ''}
        ${act('logs', 'Logs')}
        ${on ? `<a class="ui-pill lab-act" href="/static/lab-console.html?engine=${encodeURIComponent(m.engine)}&name=${encodeURIComponent(m.name)}" target="_blank" rel="noopener" title="Open an interactive console in a new tab">${actIcon('console')}Console</a>` : ''}
        ${on ? `<a class="ui-pill lab-act" href="/static/lab-desktop.html?engine=${encodeURIComponent(m.engine)}&name=${encodeURIComponent(m.name)}" target="_blank" rel="noopener" title="Open the graphical desktop (VNC or SPICE) in a new tab${m.desktop ? ` — ${m.desktop_kind || 'vnc'}` : ' — endpoint not yet configured'}">${actIcon('desktop')}Desktop${m.desktop ? '' : ' *'}</a>` : ''}
      </div>`;
    }
    // Whether this machine is a live CALDERA agent — the same enrolled/not-enrolled cue the diagram
    // and `shikari caldera list` show. Only meaningful once the machine has an OS.
    const enrol = m.enrolled
      ? '<span class="lab-agent-badge is-on" title="Enrolled as a CALDERA agent"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="5.5"/><path d="M8 4.5V8l2.5 1.5"/></svg>agent</span>'
      : (m.os ? '<span class="lab-agent-badge" title="Not a CALDERA agent — use Enrol in CALDERA">not enrolled</span>' : '');
    return `<li class="lab-machine" data-engine="${esc(m.engine)}" data-name="${esc(m.name)}" data-os="${esc(m.os)}">
      <div class="lab-machine-head">${dot}${osIcon(m.os, m.name)}<strong>${esc(m.name)}</strong>${enrol}${quick}</div>
      ${steps}${actions}</li>`;
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
  let naming = {};        // the lab naming convention, from the backend (shared with the CLI)
  function refresh() {
    api('/api/lab/overview').then(data => {
      canLab = !!data.can_lab;
      isAdmin = !!data.is_admin;
      host(data.host);
      taken = new Set(data.taken || []);
      naming = data.naming || {};
      // Windows (the UTM card) leads, then macOS, then Linux/Ubuntu last
      const tpls = (data.templates || []).slice().sort((a, b) => (a.os === 'macos' ? 0 : 1) - (b.os === 'macos' ? 0 : 1));
      templateInfo = {};  // rebuilt by utmCard + templateCards below (keeps the Info modal in sync)
      el('lab-templates').innerHTML = utmCard(data.host) + vmHostCards(data.host) + templateCards(tpls);
      el('lab-templates-empty').hidden = tpls.length > 0;
      // Exclude Rivendell's own VMs, and order by OS: Windows, then macOS, then Linux.
      const osRank = { windows: 0, macos: 1, linux: 2 };
      const distroRank = n => /rocky|rky/i.test(n) ? 1 : 0;  // within Linux: Ubuntu (and others) above Rocky
      const ms = (data.machines || [])
        .filter(m => !/^rivendell-/i.test(m.name || ''))
        .sort((a, b) => (osRank[a.os] ?? 3) - (osRank[b.os] ?? 3)
          || (a.os === 'linux' ? distroRank(a.name) - distroRank(b.name) : 0)
          || (a.name || '').localeCompare(b.name || ''));
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

  // A clash-free name in the lab convention: shi-<OSVer> (shi-cal-<OSVer> is for CALDERA).
  // The OS tags come from the backend (data.naming), shared with the CLI, with a fallback.
  const OS_TAG_FALLBACK = { linux: 'ubu24', macos: 'mac15', windows: 'win11' };
  function suggestName(id) {
    const OS_TAG = naming.os_tag || OS_TAG_FALLBACK;
    const TPL_TAG = naming.template_tag || {};  // per-template tag, so Rocky reads rky10 not ubu24
    const os = id.startsWith('macos') ? 'macos' : id.startsWith('windows') ? 'windows' : 'linux';
    const base = `shi-${TPL_TAG[id] || OS_TAG[os] || id.replace(/-(vm|container)$/, '')}`;
    if (!taken.has(base)) return base;
    for (let n = 2; ; n++) if (!taken.has(`${base}-${n}`)) return `${base}-${n}`;
  }

  // Create
  root.addEventListener('click', e => {
    const info = e.target.closest('.lab-template-info');
    if (info) {
      const inf = templateInfo[info.dataset.name] || {};
      const engines = (inf.engines || []).length
        ? `<h4 class="lab-info-h">Engines</h4><ul class="lab-info-engines">${inf.engines.map(en => `<li><strong>${esc(en.label)}</strong> — ${esc(en.why)}</li>`).join('')}</ul>`
        : '';
      openModal(`${info.dataset.name} — info`,
        `<p class="lab-info-records"><strong>Records:</strong> ${esc(inf.records || '')}</p>${engines}`);
      return;
    }
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
    if (b.dataset.win === 'clone') cloneFromCreate();
    else if (b.dataset.win === 'image') imageDialog(b.dataset.engine);
    else isoDialog();
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
    } else if (act === 'enrol') {
      if (confirm(`Run a CALDERA sandcat agent on ${name}? It enrols as a live agent and beacons to your CALDERA server.`))
        post('/api/lab/caldera/enrol', { engine, name, os }).then(r => { if (r && !r.started && r.error) alert(r.error + (r.detail ? '\n\n' + r.detail : '')); pollJob(); });
    } else if (act === 'clone') {
      cloneDialog(engine, name);
    } else if (act === 'adopt') {
      adoptDialog(engine, name, os);
    } else if (act === 'logs') {
      api(`/api/lab/logs?engine=${encodeURIComponent(engine)}&name=${encodeURIComponent(name)}`)
        .then(r => openModal(`Logs — ${name}`, `<pre class="lab-logs">${esc(r.logs || r.error || 'No output')}</pre>`));
    }
  });

  // A clash-free clone name from the source: shi-win11 -> shi-win11-2
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

  // Guided build from a Microsoft ISO — Shikari verifies the ISO; you build the VM in UTM once
  function isoDialog() {
    openModal('Build a Windows VM from an ISO', `<ol class="lab-iso-steps">
      <li>Download the official <strong>Windows 11 Arm64</strong> ISO from
        <a href="https://www.microsoft.com/software-download/windows11arm64" target="_blank" rel="noopener">Microsoft</a> (~5 GB).</li>
      <li>Check it's the right installer:
        <label class="lab-field">Path to the .iso
          <input type="text" id="lab-iso-path" placeholder="~/Downloads/Win11_arm64.iso" autocomplete="off"></label>
        <div class="lab-iso-check"><button type="button" class="ui-pill" id="lab-iso-go">Verify ISO</button>
          <span id="lab-iso-result" class="lab-iso-result"></span></div></li>
      <li>In UTM: <strong>New Virtual Machine → Virtualize → Windows</strong>, pick that ISO, 4 GB RAM, name it without spaces (e.g. <code>shi-win11</code>), and install the <strong>UTM guest tools</strong> so Shikari can run commands in it.</li>
      <li>It appears under Your machines. <strong>Set OS → Windows</strong>, then <strong>Install tooling</strong> and <strong>Record</strong>. For more Windows VMs after this, use <strong>Clone</strong> — no reinstall.</li>
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

  // Hyper-V has no guest agent, so Set OS also takes the way in: the guest's own account for
  // PowerShell Direct (Windows), or the SSH user, key and address (Linux). Blank keeps what's stored.
  function accessFields(engine) {
    if (engine !== 'hyperv') return '';
    return `<div id="lab-access">
      <label class="lab-field">Guest user <input type="text" id="lab-acc-user" autocomplete="off" placeholder="Administrator / shikari"></label>
      <label class="lab-field lab-acc-win">Password <input type="password" id="lab-acc-pw" autocomplete="new-password"></label>
      <label class="lab-field lab-acc-lin">SSH key on this host <input type="text" id="lab-acc-key" autocomplete="off" placeholder="blank: Shikari's own key"></label>
      <label class="lab-field lab-acc-lin">Address <input type="text" id="lab-acc-host" autocomplete="off" placeholder="blank: ask Hyper-V"></label>
      <p class="lab-hint">PowerShell Direct runs commands in a Windows guest as this account (a local administrator); the password is kept encrypted. A Linux guest is reached over SSH.</p></div>`;
  }
  function accessValues() {
    const v = id => (el(id) ? el(id).value.trim() : '');
    return { user: v('lab-acc-user'), password: el('lab-acc-pw') ? el('lab-acc-pw').value : '', key: v('lab-acc-key'), host: v('lab-acc-host') };
  }
  function syncAccess(os) {
    document.querySelectorAll('.lab-acc-win').forEach(n => { n.hidden = os !== 'windows'; });
    document.querySelectorAll('.lab-acc-lin').forEach(n => { n.hidden = os !== 'linux'; });
  }

  function adoptDialog(engine, name, current) {
    openModal(`Set the OS for ${name}`, `<label class="lab-field">Operating system
      <select id="lab-os" class="dropdown-styled">
        <option value="windows">Windows</option>
        <option value="linux">Linux</option>
        ${engine === 'hyperv' || engine === 'libvirt' ? '' : '<option value="macos">macOS</option>'}
      </select></label>${accessFields(engine)}
      <p class="lab-hint">So Shikari knows how to turn on logging, install Atomic Red Team and record on it.</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-os-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-os-go">Save</button></div>`);
    if (current) el('lab-os').value = current;
    syncAccess(el('lab-os').value);
    el('lab-os').addEventListener('change', () => syncAccess(el('lab-os').value));
    el('lab-os-go').addEventListener('click', () => {
      const body = { engine, name, os: el('lab-os').value, ...accessValues() };
      closeModal();
      post('/api/lab/adopt', body).then(refresh);
    });
    el('lab-os-cancel').addEventListener('click', closeModal);
  }

  // A VM from your own disk or ISO (Hyper-V or KVM). From an ISO you install the OS yourself.
  function imageDialog(engine) {
    const hv = engine === 'hyperv';
    openModal(`New ${hv ? 'Hyper-V' : 'KVM'} VM from a disk or ISO`, `<label class="lab-field">Name
        <input type="text" id="lab-img-name" value="${esc(suggestName('windows-vm'))}" autocomplete="off"></label>
      <label class="lab-field">Disk image or ISO on this host
        <input type="text" id="lab-img-path" autocomplete="off" placeholder="${hv ? 'C:\\VMs\\win2022.vhdx or C:\\ISO\\Win11_x64.iso' : '/var/lib/libvirt/images/Win11_x64.iso or a .qcow2'}"></label>
      <label class="lab-field">Operating system
        <select id="lab-os" class="dropdown-styled"><option value="windows">Windows</option><option value="linux">Linux</option></select></label>
      ${hv ? accessFields('hyperv') : ''}
      <p class="lab-hint">${hv
        ? 'A VHDX or VHD becomes the read-only parent of a differencing disk, so one prepared image serves many machines. From an ISO, install over Hyper-V Manager\'s Connect.'
        : 'A qcow2 becomes the backing file of an overlay. From an ISO, install over Desktop, and add the virtio-win guest tools (Windows) or qemu-guest-agent (Linux) so Shikari can run commands.'}</p>
      <div class="lab-modal-actions"><button type="button" class="ui-pill" id="lab-img-cancel">Cancel</button>
      <button type="button" class="btn-primary" id="lab-img-go">Create</button></div>`);
    syncAccess(el('lab-os').value);
    el('lab-os').addEventListener('change', () => syncAccess(el('lab-os').value));
    el('lab-img-go').addEventListener('click', () => {
      const name = el('lab-img-name').value.trim(), image = el('lab-img-path').value.trim();
      if (!name || !image) return;
      const acc = accessValues();
      const body = { engine, name, image, os: el('lab-os').value, user: acc.user, password: acc.password };
      closeModal();
      post('/api/lab/create-from-image', body).then(r => { if (r.started) pollJob(); });
    });
    el('lab-img-cancel').addEventListener('click', closeModal);
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
      if (!steps || !steps.length) { openModal('Install tooling', '<p>No tooling to install for this OS.</p>'); return; }
      const rows = steps.map(s => `<button type="button" class="ui-pill lab-step" data-step="${esc(s.step)}">${esc(s.label)}</button>`).join('');
      openModal(`Install tooling on ${name}`, `<p class="lab-hint">Each step changes the machine. Snapshot it first.</p>
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
      <p class="lab-hint">Atomic Red Team runs these in the machine and Shikari imports the logs as <strong>Your lab</strong>.
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

  // A temporary elevation (or its expiry) changes can_lab/is_admin — re-pull the overview live.
  if (window.onRoleChange) window.onRoleChange(() => refresh());
})();
