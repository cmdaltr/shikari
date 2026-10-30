// Build → Emulate → Lab → CALDERA operations (templates/emulate.html, archer/lab/web.py /api/lab/caldera/*):
// plan an operation, run it, collect it, and the static check of detections and correlations against it.
// Shares the Lab's modal and job log; the server runs one lab job at a time, CALDERA's included.
(function () {
  const root = document.getElementById('caldera');
  if (!root) return;
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const el = id => document.getElementById(id);
  const api = (path, opts) => fetch(path, opts).then(r => r.json().then(j => ({ ok: r.ok, ...j })));
  const post = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const modal = el('lab-modal'), modalBody = el('lab-modal-body'), modalTitle = el('lab-modal-title');
  const open = (title, html) => { modalTitle.textContent = title; modalBody.innerHTML = html; modal.hidden = false; };
  const close = () => { modal.hidden = true; modalBody.innerHTML = ''; document.querySelector('.lab-modal-box')?.classList.remove('lab-modal-wide'); };
  let groups = [], timer = null;

  function poll() {
    api('/api/lab/job').then(({ job, log }) => {
      const box = el('lab-job');
      if (!job || job.state === 'idle') return;
      box.hidden = false;
      el('lab-job-state').textContent = job.state === 'running' ? (job.what + '…')
        : job.state === 'error' ? ('Failed: ' + (job.error || '')) : (job.what + ' — done');
      el('lab-job-log').textContent = (log || []).join('\n');
      if (job.state === 'running') { if (!timer) timer = setInterval(poll, 2000); }
      else { clearInterval(timer); timer = null; operations(); }
    });
  }

  function status() {
    api('/api/lab/caldera/status').then(r => {
      if (!r.ok) { root.hidden = true; return; }  // below the Operational analyst role: the Lab's notice says why
      root.hidden = false;
      groups = r.groups || [];
      const s = el('caldera-status');
      if (!r.configured) {
        s.innerHTML = `<span class="lab-badge is-off">Not configured</span>`;  // the buttons alongside say how
      } else if (r.error) {
        s.innerHTML = `<span class="lab-badge is-missed">Unreachable</span> ${esc(r.error)}${r.detail ? ' — ' + esc(r.detail) : ''}`;
      } else {
        s.innerHTML = `<span class="lab-badge is-ready">Connected</span> ${esc(r.url)} · ` +
          (groups.length ? groups.map(g => `${esc(g.group || '(no group)')}: ${g.agents} agent${g.agents === 1 ? '' : 's'} (${esc(g.platforms.join(', '))})`).join('; ')
            : 'no agents yet');
      }
      const ready = r.configured && !r.error;
      const canP = !!r.can_provision, isP = !!r.provisioned;
      el('caldera-actions').hidden = !ready;         // plan / collect once connected
      // Provisioning controls: Provision (red) → Re-provision (green) once a lab is up, plus De-provision.
      const pv = el('caldera-provision');
      pv.hidden = !canP;
      pv.textContent = isP ? 'Re-provision' : 'Provision';
      pv.classList.toggle('is-provisioned', isP);
      el('caldera-deprovision').hidden = !(canP && isP);
      el('caldera-steps').hidden = canP || ready;     // manual Deploy guide only for ineligible, unconfigured hosts
      el('caldera-prov').hidden = !(canP || !ready);
      operations();
    });
  }

  function operations() {
    api('/api/lab/caldera/operations').then(r => {
      const ops = (r && r.operations) || [], table = el('caldera-ops');
      table.hidden = !ops.length;
      table.querySelector('tbody').innerHTML = ops.map(o => `<tr>
        <td>${esc(o.name)}<br><small>${esc(o.operation_id)}</small></td><td>${esc(o.group)}</td>
        <td>${esc((o.hosts || []).join(', '))}</td><td>${o.steps}</td>
        <td>${o.captured ? '<span class="lab-badge is-ready">captured</span>' : '<small>commands only</small>'}</td>
        <td><small>${esc(o.collected)}</small></td>
        <td><button type="button" class="ui-pill" data-check="${esc(o.name)}">Check</button></td></tr>`).join('');
    });
  }

  function badge(st) {
    const cls = { fired: 'is-fired', matched: 'is-fired', half_fired: 'is-half', missed: 'is-missed', no_detections: 'is-off' }[st] || 'is-off';
    return `<span class="lab-badge ${cls}">${esc(st.replace('_', ' '))}</span>`;
  }

  function check(name) {
    const box = el('caldera-check');
    box.hidden = false;
    box.innerHTML = '<p class="lab-empty">Checking…</p>';
    api('/api/lab/caldera/check?name=' + encodeURIComponent(name)).then(r => {
      if (!r.ok) { box.innerHTML = `<p class="lab-warn">${esc(r.error || 'Check failed')}</p>`; return; }
      const s = r.summary, c = r.correlations || { correlations: [], summary: {} }, cs = c.summary;
      box.innerHTML = `<h4>${esc(r.operation)}: techniques <small>(matched against ${esc(r.evidence)})</small></h4>
        <p class="lab-hint">${s.matched} matched · ${s.missed} missed · ${s.no_detections} with no saved detection, of ${s.techniques}.
          An indicator appearing means the detection would plausibly have fired; the query's other conditions aren't run.</p>
        <table class="em-table"><thead><tr><th>Technique</th><th></th><th>Detections</th><th>Steps no detection matched</th></tr></thead><tbody>
        ${r.techniques.map(t => `<tr><td>${esc(t.technique_id)} ${esc(t.technique_name)}</td><td>${badge(t.status)}</td>
          <td>${t.detections.map(d => `${d.matched ? '✓' : '✗'} ${esc(d.name)} <small>${esc(d.file)}${d.hits.length ? ' — ' + d.hits.map(h => esc(h.value)).join(', ') : ''}</small>`).join('<br>') || '—'}</td>
          <td>${t.unmatched_commands.map(u => `<div class="lab-caldera-cmd">${esc(u.host)}: ${esc(u.command)}</div>`).join('') || '—'}</td></tr>`).join('')}
        </tbody></table>
        <h4>Correlations</h4>
        <p class="lab-hint">${cs.testable ? `${cs.fired} fired · ${cs.half_fired} half-fired · ${cs.missed} missed, of ${cs.testable} whose techniques all ran.
          Fired means every part matched on one host inside the correlation's window; the order is shown, not required.`
          : 'No saved correlation joins only techniques this operation ran.'}</p>
        ${cs.testable ? `<table class="em-table"><thead><tr><th>Correlation</th><th></th><th>Techniques</th><th>Host · span</th><th>Missing</th></tr></thead><tbody>
          ${c.correlations.map(x => `<tr><td>${esc(x.file)}<br><small>${esc(x.target)} · ${esc(x.vendor)}</small></td><td>${badge(x.status)}</td>
            <td>${esc((x.order.length ? x.order : x.techniques).join(' → '))}</td>
            <td>${x.host ? `${esc(x.host)} · ${x.span_seconds}s of ${x.window_seconds}s` : '—'}</td>
            <td>${esc(x.missing.join(', ')) || '—'}</td></tr>`).join('')}</tbody></table>` : ''}`;
    });
  }

  function machines() {
    return api('/api/lab/machines').then(r => (r && r.machines) || []).catch(() => []);
  }

  function planDialog() {
    machines().then(ms => {
      const withOs = ms.filter(m => m.os);
      open('Plan a CALDERA operation', `
        <label class="lab-field">Target
          <select id="cal-kind"><option value="technique">ATT&CK techniques</option><option value="group">Threat group</option><option value="cve">CVE</option></select></label>
        <label class="lab-field">Techniques, group or CVE
          <input type="text" id="cal-value" placeholder="T1057, T1053.005 — or a group name" autocomplete="off"></label>
        <label class="lab-field">Agent group
          <select id="cal-group">${groups.map(g => `<option value="${esc(g.group)}">${esc(g.group || '(no group)')} — ${g.agents} agent(s)</option>`).join('')}</select></label>
        <label class="lab-field">Capture the endpoint's logs afterwards (optional)
          <select id="cal-capture"><option value="">No — check against the commands only</option>
          <option value="caldera">Yes — via the agent, over CALDERA (any OS, no machine needed)</option>
          ${withOs.map(m => `<option value="${esc(m.engine)}|${esc(m.name)}|${esc(m.os)}">Via the lab machine ${esc(m.name)} (${esc(m.os)})</option>`).join('')}</select></label>
        <p class="lab-hint">Plan reads CALDERA's abilities and agents and changes nothing. Running creates the adversary and starts the operation on real agents.</p>
        <div class="lab-preview" id="cal-preview" hidden></div>
        <label class="lab-confirm"><input type="checkbox" id="cal-ok"> These agents are on disposable lab machines</label>
        <div class="lab-modal-actions">
          <button type="button" class="ui-pill" id="cal-preview-btn">Plan</button>
          <button type="button" class="btn-primary lab-danger" id="cal-go" disabled>Run operation</button>
        </div>`);
      const body = () => {
        const capv = el('cal-capture').value;
        const cap = capv.split('|');
        // "caldera" = capture over the agent's own C2 (no machine); otherwise engine|name|os of a lab machine
        const capture = capv === 'caldera' ? { engine: 'caldera' }
          : cap.length === 3 ? { engine: cap[0], name: cap[1], os: cap[2] } : null;
        return { kind: el('cal-kind').value, value: el('cal-value').value, group: el('cal-group').value, capture };
      };
      let planned = false;
      const sync = () => { el('cal-go').disabled = !(planned && el('cal-ok').checked); };
      el('cal-ok').addEventListener('change', sync);
      ['cal-kind', 'cal-value', 'cal-group'].forEach(id => el(id).addEventListener('input', () => { planned = false; sync(); }));
      el('cal-preview-btn').addEventListener('click', () => {
        post('/api/lab/caldera/operate', { ...body(), execute: false }).then(r => {
          const box = el('cal-preview');
          box.hidden = false;
          if (!r.ok) { box.innerHTML = `<div class="lab-warn">${esc(r.error)}${r.detail ? ': ' + esc(r.detail) : ''}</div>`; planned = false; sync(); return; }
          const warn = (r.warnings || []).length ? `<div class="lab-warn">${r.warnings.map(esc).join('; ')}</div>` : '';
          box.innerHTML = warn + '<ol class="lab-plan">' + r.plan.map(l => `<li>${esc(l)}</li>`).join('') + '</ol>';
          planned = (r.steps || []).length > 0 && (r.agents || []).length > 0;
          sync();
        });
      });
      el('cal-go').addEventListener('click', () => {
        const b = body();
        close();
        post('/api/lab/caldera/operate', { ...b, execute: true }).then(r => {
          if (!r.ok) { alert(r.error + (r.detail ? '\n\n' + r.detail : '')); return; }
          if (r.started) poll();
        });
      });
      el('cal-value').focus();
    });
  }

  // The rich Detonate flow: resolve a target, see which groups/VMs can run which techniques (OS
  // matched), then run on the chosen group(s), capturing over the agents' own C2.
  function osBadge(p) { return `<span class="det-os">${esc(p)}</span>`; }

  function renderMatrix(r) {
    const techs = (r.techniques || []).map(t =>
      `<span class="det-tech">${esc(t.id)} ${(t.platforms || []).map(osBadge).join('')}</span>`).join('') || '—';
    const groups = (r.groups || []).map(g => {
      const run = (g.runnable || []).length, total = run + (g.gaps || []).length;
      const vms = (g.vms || []).map(v => `${esc(v.host)} ${osBadge(v.platform)}`).join(', ') || 'no agents';
      const gaps = (g.gaps || []).length ? `<span class="det-gaps">no ability for ${g.gaps.map(esc).join(', ')}</span>` : '';
      return `<label class="det-grp${run ? '' : ' is-empty'}">
        <input type="checkbox" class="det-group" value="${esc(g.group)}"${run ? '' : ' disabled'}>
        <span class="det-grp-body"><strong>${esc(g.group || '(no group)')}</strong> — runs ${run} of ${total}
          <small>${vms}</small>${gaps}</span></label>`;
    }).join('') || '<p class="lab-hint">No agent groups — enrol an agent first.</p>';
    return `<div class="det-block"><span class="det-head">Techniques</span><div class="det-techs">${techs}</div></div>
      <div class="det-block"><span class="det-head">Run on</span>${groups}</div>`;
  }

  function detonateDialog() {
    open('Detonate — run on your agents', `
      <label class="lab-field">Target
        <select id="det-kind"><option value="technique">ATT&CK techniques</option><option value="group">Threat group</option><option value="cve">CVE</option></select></label>
      <label class="lab-field">Techniques, group or CVE
        <input type="text" id="det-value" placeholder="T1057, T1053.005 — or a group name" autocomplete="off"></label>
      <div class="lab-modal-actions" style="justify-content:flex-start"><button type="button" class="ui-pill" id="det-resolve">Resolve</button></div>
      <div id="det-matrix" hidden></div>
      <label class="lab-confirm" id="det-confirm-wrap" hidden><input type="checkbox" id="det-ok"> These agents are on disposable lab machines</label>
      <div class="lab-modal-actions"><button type="button" class="btn-primary lab-danger is-detonate" id="det-go" hidden disabled>Detonate</button></div>`);
    let resolved = false;
    const sync = () => {
      const anyGroup = !!document.querySelector('.det-group:checked');
      el('det-go').disabled = !(resolved && anyGroup && el('det-ok').checked);
    };
    el('det-ok').addEventListener('change', sync);
    ['det-kind', 'det-value'].forEach(id => el(id).addEventListener('input', () => { resolved = false; sync(); }));
    el('det-resolve').addEventListener('click', () => {
      const kind = el('det-kind').value, value = el('det-value').value.trim();
      if (!value) return;
      post('/api/lab/caldera/plan-matrix', { kind, value }).then(r => {
        const box = el('det-matrix'); box.hidden = false;
        if (!r.ok) { box.innerHTML = `<div class="lab-warn">${esc(r.error)}${r.detail ? ': ' + esc(r.detail) : ''}</div>`; resolved = false; sync(); return; }
        box.innerHTML = renderMatrix(r);
        el('det-confirm-wrap').hidden = false; el('det-go').hidden = false;
        resolved = (r.groups || []).some(g => (g.runnable || []).length);
        box.querySelectorAll('.det-group').forEach(c => c.addEventListener('change', sync));
        sync();
      });
    });
    el('det-go').addEventListener('click', () => {
      const groups = [...document.querySelectorAll('.det-group:checked')].map(c => c.value);
      if (!groups.length) return;
      if (!confirm(`This runs a real CALDERA operation on ${groups.length} group(s) — a live implant detonates and beacons over C2. Continue?`)) return;
      const kind = el('det-kind').value, value = el('det-value').value.trim();
      close();
      post('/api/lab/caldera/detonate', { kind, value, groups }).then(r => {
        if (!r.started) { alert((r.error || 'Could not start') + (r.detail ? '\n\n' + r.detail : '')); return; }
        poll();
      });
    });
    el('det-value').focus();
  }

  function collectDialog() {
    open('Collect a CALDERA operation', `
      <label class="lab-field">Operation id
        <input type="text" id="cal-op" placeholder="from CALDERA's operations list" autocomplete="off"></label>
      <p class="lab-hint">Pulls the commands each step ran, the host, times and output. Reads only.</p>
      <div class="lab-modal-actions"><button type="button" class="btn-primary" id="cal-collect-go">Collect</button></div>`);
    el('cal-collect-go').addEventListener('click', () => {
      const id = el('cal-op').value.trim();
      if (!id) return;
      close();
      post('/api/lab/caldera/collect', { operation_id: id }).then(r => {
        if (!r.ok) { alert(r.error + (r.detail ? '\n\n' + r.detail : '')); return; }
        if (r.started) poll();
      });
    });
  }

  function stepsDialog() {
    // Archer drives a CALDERA server you run; it never ships an implant. scripts/telemetry/caldera-lab.sh
    // does the whole disposable-lab setup, so the steps lead with it.
    open('Deploy CALDERA', `
      <p class="lab-hint">Archer drives a CALDERA server you run — it never ships an implant of its own. The repo's
        <code>scripts/telemetry/caldera-lab.sh</code> stands up a throwaway lab end to end; the steps below say what it does and the manual equivalent.</p>
      <ol class="lab-plan">
        <li><strong>A CALDERA server and red API key.</strong> <code>caldera-lab.sh up</code> builds a disposable CALDERA 5.2 server and enrols a couple of
          Linux agents (group <code>disposable</code>); <code>caldera-lab.sh config</code> prints its URL and key. Or point Archer at a CALDERA you already run.</li>
        <li><strong>Give Archer the key.</strong> Paste the server URL and red key in <a href="/profile?keytab=emulation#apikeys">Profile → API Keys → Emulation Tools</a> (encrypted per account).</li>
        <li><strong>An agent on a disposable VM, in a group.</strong> Linux agents come up with <code>up</code>; for Windows,
          <code>caldera-lab.sh win &lt;utm-vm&gt;</code> installs and runs sandcat on a UTM VM you've built (group <code>winlab</code>). Or deploy sandcat from CALDERA's own UI.</li>
        <li><strong>Run it here.</strong> Plan an operation, pick the group, run. Capturing “over the agent” reads each step's endpoint logs back over its own
          C2 — nothing installed, any OS — and the Check scores your saved detections and correlations against them.</li>
      </ol>
      <p class="lab-hint">⚠ A live operation detonates a real implant and beacons over C2 — only against disposable lab VMs.</p>`);
  }

  // ---- Provision: stand up a disposable CALDERA lab on this host (#30, Stage 1) ----

  const TASK_MARK = { pending: '○', running: '◐', waiting: '⏳', done: '✓', failed: '✗' };
  let provTimer = null;

  function renderTasks(tasks) {
    const box = el('prov-tasks');
    if (!box) { clearInterval(provTimer); provTimer = null; return; }  // modal closed
    box.innerHTML = (tasks || []).map(t => `<li class="lab-task is-${esc(t.state)}">
        <span class="lab-task-mark">${TASK_MARK[t.state] || '○'}</span>
        <span class="lab-task-body"><span class="lab-task-label">${esc(t.label)}</span>${t.detail ? ` <small>${esc(t.detail)}</small>` : ''}
          ${t.state === 'waiting' && t.action ? `<code class="lab-task-action">${esc(t.action)}</code>` : ''}</span>
      </li>`).join('');
  }

  function provPoll() {
    api('/api/lab/job').then(({ job, log }) => {
      if (!job || !el('prov-tasks')) { clearInterval(provTimer); provTimer = null; return; }
      renderTasks(job.tasks);
      const logBox = el('prov-log');
      if (logBox && (log || []).length) { logBox.hidden = false; logBox.textContent = log.join('\n'); logBox.scrollTop = logBox.scrollHeight; }
      if (job.state === 'running') { if (!provTimer) provTimer = setInterval(provPoll, 2000); return; }
      clearInterval(provTimer); provTimer = null;
      const done = job.state === 'done';
      const start = el('prov-start');
      if (start) { start.disabled = false; start.textContent = done ? 'Done' : 'Retry'; start.hidden = done; }
      const cb = el('prov-confirm');
      if (cb) { el('prov-confirm-wrap').hidden = false; cb.disabled = !done; }
      const res = el('prov-result');
      if (res && done) {
        const cfg = (job.tasks || []).find(t => t.id === 'configure');
        const url = cfg && cfg.detail;
        res.hidden = false;
        res.innerHTML = `<div class="prov-ok">✓ Lab ready</div>${url ? `<div class="prov-url">${esc(url)}</div>` : ''}<p class="lab-hint">Saved to your profile — the CALDERA card is now connected. Tick below, then Detonate to run techniques.</p>`;
      }
      if (!done && job.error && el('prov-tasks')) el('prov-tasks').insertAdjacentHTML('beforeend', `<li class="lab-warn">${esc(job.error)}</li>`);
      status();  // the panel may now be configured
    });
  }

  function startProvision() {
    const start = el('prov-start');
    start.disabled = true; start.textContent = 'Provisioning…';
    post('/api/lab/caldera/provision', {}).then(r => {
      if (!r.started) {
        renderTasks([]);
        el('prov-tasks').innerHTML = `<li class="lab-warn">${esc(r.error || 'Could not start')}${r.detail ? ': ' + esc(r.detail) : ''}</li>`;
        start.disabled = false; start.textContent = 'Start provisioning';
        return;
      }
      renderTasks(r.job && r.job.tasks);
      provPoll();
    });
  }

  function provisionDialog() {
    clearInterval(provTimer); provTimer = null;
    open('Provision CALDERA', `
      <div class="prov-grid">
        <div class="prov-col"><ol class="lab-tasks" id="prov-tasks"></ol><pre class="ms-log" id="prov-log" hidden></pre></div>
        <div class="prov-col prov-side">
          <p class="lab-hint">Installs OrbStack, builds and runs a disposable CALDERA server, enrols agents, and saves the server and key to your profile.
            Nothing detonates here. A step that needs you — a password, or OrbStack's first launch — shows what to do and carries on by itself once it's done (re-checked every 10 s).</p>
          <div class="prov-result" id="prov-result" hidden></div>
        </div>
      </div>
      <label class="lab-confirm" id="prov-confirm-wrap" hidden><input type="checkbox" id="prov-confirm" disabled> The lab is up — I'm ready to run operations</label>
      <div class="lab-modal-actions">
        <button type="button" class="ui-pill" id="prov-start">Start provisioning</button>
        <button type="button" class="btn-primary is-detonate" id="prov-detonate" hidden>Detonate…</button>
      </div>`);
    document.querySelector('.lab-modal-box')?.classList.add('lab-modal-wide');
    renderTasks([]);
    el('prov-start').addEventListener('click', startProvision);
    el('prov-confirm').addEventListener('change', () => { el('prov-detonate').hidden = !el('prov-confirm').checked; });
    el('prov-detonate').addEventListener('click', () => { close(); detonateDialog(); });
  }

  function deprovision() {
    if (!confirm('Tear down the CALDERA lab? This stops the server, deletes the agent VMs, and removes CALDERA from your profile.')) return;
    post('/api/lab/caldera/deprovision', {}).then(r => {
      if (!r.started) { alert((r.error || 'Could not start') + (r.detail ? '\n\n' + r.detail : '')); return; }
      poll();
    });
  }

  el('caldera-plan').addEventListener('click', planDialog);
  el('caldera-detonate').addEventListener('click', detonateDialog);
  el('caldera-collect').addEventListener('click', collectDialog);
  el('caldera-steps').addEventListener('click', stepsDialog);
  el('caldera-provision').addEventListener('click', provisionDialog);
  el('caldera-deprovision').addEventListener('click', deprovision);
  el('caldera-ops').addEventListener('click', e => { const b = e.target.closest('[data-check]'); if (b) check(b.dataset.check); });
  status();
  if (window.onRoleChange) window.onRoleChange(() => status());
})();
