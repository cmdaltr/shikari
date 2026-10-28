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
  const close = () => { modal.hidden = true; modalBody.innerHTML = ''; };
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
        s.innerHTML = `<span class="lab-badge is-off">Not configured</span> ${esc(r.detail || '')}`;
      } else if (r.error) {
        s.innerHTML = `<span class="lab-badge is-missed">Unreachable</span> ${esc(r.error)}${r.detail ? ' — ' + esc(r.detail) : ''}`;
      } else {
        s.innerHTML = `<span class="lab-badge is-ready">Connected</span> ${esc(r.url)} · ` +
          (groups.length ? groups.map(g => `${esc(g.group || '(no group)')}: ${g.agents} agent${g.agents === 1 ? '' : 's'} (${esc(g.platforms.join(', '))})`).join('; ')
            : 'no agents yet');
      }
      el('caldera-actions').hidden = !(r.configured && !r.error);
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
        <label class="lab-field">Capture logs afterwards from the lab machine the agent runs on (optional)
          <select id="cal-capture"><option value="">No — check against the commands only</option>
          ${withOs.map(m => `<option value="${esc(m.engine)}|${esc(m.name)}|${esc(m.os)}">${esc(m.name)} (${esc(m.os)})</option>`).join('')}</select></label>
        <p class="lab-hint">Plan reads CALDERA's abilities and agents and changes nothing. Running creates the adversary and starts the operation on real agents.</p>
        <div class="lab-preview" id="cal-preview" hidden></div>
        <label class="lab-confirm"><input type="checkbox" id="cal-ok"> These agents are on disposable lab machines</label>
        <div class="lab-modal-actions">
          <button type="button" class="ui-pill" id="cal-preview-btn">Plan</button>
          <button type="button" class="btn-primary lab-danger" id="cal-go" disabled>Run operation</button>
        </div>`);
      const body = () => {
        const cap = el('cal-capture').value.split('|');
        return { kind: el('cal-kind').value, value: el('cal-value').value, group: el('cal-group').value,
                 capture: cap.length === 3 ? { engine: cap[0], name: cap[1], os: cap[2] } : null };
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

  el('caldera-plan').addEventListener('click', planDialog);
  el('caldera-collect').addEventListener('click', collectDialog);
  el('caldera-ops').addEventListener('click', e => { const b = e.target.closest('[data-check]'); if (b) check(b.dataset.check); });
  status();
  if (window.onRoleChange) window.onRoleChange(() => status());
})();
