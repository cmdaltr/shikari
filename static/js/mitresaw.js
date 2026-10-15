// MITRESaw page (templates/mitresaw.html): the procedures CSV's state and rebuild, a search
// of its procedures, and MITRESaw's indicator exclusions (archer/mitre/web.py).
(function () {
  const $ = id => document.getElementById(id);
  const signedIn = document.querySelector('.ms-page').dataset.signedIn === 'true';
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const when = t => t ? new Date(t * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '–';
  let timer = null, page = 1, tacticsLoaded = false;

  async function json(url, opts) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  // ---------- OSINT repositories (what generation searches per technique) ----------
  const OSINT = [
    ['splunk', 'Splunk', 'splunk/security_content'],
    ['azure_sentinel', 'Sentinel', 'Azure/Azure-Sentinel'],
    ['elastic', 'Elastic', 'elastic/detection-rules'],
    ['mitre_car', 'MITRE CAR', 'mitre-attack/car'],
  ];
  async function osint() {
    const box = $('ms-osint'), overall = $('ms-osint-overall');
    let d;
    try { d = await json('/api/status/osint'); } catch (e) { box.innerHTML = `<p class="ms-note">Couldn't read the repositories' status: ${esc(e.message)}</p>`; return; }
    const repos = d.repos || {};
    const ready = OSINT.filter(([k]) => (repos[k] || {}).status === 'ready').length;
    const cloning = OSINT.some(([k]) => (repos[k] || {}).status === 'cloning');
    overall.textContent = cloning ? 'Updating…' : ready === OSINT.length ? 'All ready' : `${ready} of ${OSINT.length} ready`;
    overall.className = 'ms-osint-overall ' + (cloning ? 'is-busy' : ready === OSINT.length ? 'is-ok' : ready ? 'is-part' : 'is-bad');
    box.innerHTML = OSINT.map(([k, name, upstream]) => {
      const r = repos[k] || { status: 'missing' };
      const label = { ready: 'Ready', cloning: 'Updating…', failed: 'Failed', missing: 'Not cloned' }[r.status] || r.status;
      const detail = r.status === 'failed' && r.error ? esc(r.error) : r.updated ? `Last upstream commit ${esc(r.updated)}` : '';
      return `<div class="ms-osint-repo is-${esc(r.status)}">
        <div class="ms-osint-head"><strong>${esc(name)}</strong><span class="ms-osint-state">${esc(label)}</span></div>
        <a href="https://github.com/${upstream}" target="_blank" rel="noopener">${upstream}</a>
        <small>${detail}</small></div>`;
    }).join('');
    if (cloning) setTimeout(osint, 5000);
  }

  // ---------- Status and run ----------
  async function status() {
    clearTimeout(timer);
    let s;
    try { s = await json('/api/mitresaw/status'); } catch (e) { $('ms-state').textContent = `Couldn't read MITRESaw's state: ${e.message}`; return; }
    $('ms-version').textContent = s.meta.attack_version ? `v${s.meta.attack_version}` : '–';
    $('ms-groups').textContent = s.csv.groups.toLocaleString();
    $('ms-techniques').textContent = s.csv.techniques.toLocaleString();
    $('ms-rows').textContent = s.csv.rows.toLocaleString();
    $('ms-built').textContent = s.meta.built ? new Date(s.meta.built).toLocaleDateString(undefined, { dateStyle: 'medium' }) : when(s.csv.modified);
    $('ms-built').title = s.meta.mode ? `${s.meta.mode} run` : '';
    $('ms-dl-csv').hidden = !s.csv.exists;
    $('ms-dl-xlsx').hidden = !s.csv.xlsx;

    const check = $('ms-check');
    check.hidden = !s.check;
    if (s.check) {
      check.textContent = s.check.summary;
      check.className = `ms-check ${s.check.ok ? 'is-ok' : 'is-diff'}`;
    }

    const job = s.job, running = job.state === 'running';
    const busyElsewhere = s.busy && !running;
    let text = '';
    if (running) text = `${job.mode === 'full' ? 'Full rebuild' : 'Update'} running since ${when(job.started)}…`;
    else if (busyElsewhere) text = 'MITRESaw is rebuilding (started by Archer at startup or by a detection run).';
    else if (job.state === 'done') text = `Finished ${when(job.finished)}.`;
    else if (job.state === 'stopped') text = `Stopped ${when(job.finished)}; the next run carries on from the last finished batch.`;
    else if (job.state === 'failed') text = `Failed: ${job.error}`;
    else if (s.groups_resumable) text = `${s.groups_resumable} groups collected by an unfinished run; the next run carries on from them.`;
    if (!signedIn) text = (text ? text + ' ' : '') + 'Log in to rebuild.';
    $('ms-state').textContent = text;
    $('ms-update').disabled = $('ms-full').disabled = !signedIn || running || s.busy;
    $('ms-stop').hidden = !running;

    const log = $('ms-log');
    log.hidden = !s.log.length;
    if (s.log.length) {
      const atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
      log.innerHTML = s.log.map(l => {
        const cls = l.level === 'WARNING' ? 'is-warn' : (l.level === 'ERROR' ? 'is-err' : '');
        const t = new Date(l.t * 1000).toLocaleTimeString();
        return `<span class="${cls}">${esc(t)}  ${esc(l.msg)}</span>`;
      }).join('\n');
      if (atEnd) log.scrollTop = log.scrollHeight;
    }

    if (!tacticsLoaded && s.tactics.length) {
      tacticsLoaded = true;
      $('ms-tactic').insertAdjacentHTML('beforeend', s.tactics.map(t => `<option>${esc(t)}</option>`).join(''));
    }
    if (running || s.busy) timer = setTimeout(status, 3000);
    else if (job.state === 'done' && $('ms-rows-body').dataset.built !== String(s.csv.modified)) {
      $('ms-rows-body').dataset.built = String(s.csv.modified);
      search();
    }
  }

  async function start(full) {
    if (full && !confirm('Collect every group again? This takes about 30 minutes.')) return;
    try {
      await json('/api/mitresaw/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ full }) });
    } catch (e) { $('ms-state').textContent = e.message; }
    status();
  }

  $('ms-update').addEventListener('click', () => start(false));
  $('ms-full').addEventListener('click', () => start(true));
  $('ms-stop').addEventListener('click', async () => {
    try { await json('/api/mitresaw/stop', { method: 'POST' }); } catch (e) { $('ms-state').textContent = e.message; }
    status();
  });

  // ---------- Procedures ----------
  function via(a) {
    if (a === 'direct') return '<span class="ms-via">Group\'s own</span>';
    const [kind, name] = a.split(':');
    return kind === 'via_campaign'
      ? `<span class="ms-via is-campaign">Campaign: ${esc(name)}</span>`
      : `<span class="ms-via is-software">Software: ${esc(a.slice('via_software:'.length))}</span>`;
  }

  // ATT&CK's markdown links ([Name](url)) and code spans, as text
  const procedure = p => esc(p.replace(/^\[(Software|Campaign): [^\]]+\]\s*/, ''))
    .replace(/\[([^\]]+)\]\((https:\/\/attack\.mitre\.org[^)\s]*)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');

  function indicators(ind) {
    const keys = Object.keys(ind).filter(k => k !== 'software');
    if (!keys.length) return '<span class="ms-id">–</span>';
    return '<ul class="ms-ind">' + keys.map(k =>
      `<li><b>${esc(k)}</b>${ind[k].slice(0, 6).map(v => `<code>${esc(v)}</code>`).join(', ')}${ind[k].length > 6 ? ` +${ind[k].length - 6}` : ''}</li>`).join('') + '</ul>';
  }

  const techUrl = id => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
  const groupUrl = id => `https://attack.mitre.org/groups/${id}/`;

  async function search() {
    const params = new URLSearchParams({
      q: $('ms-q').value, group: $('ms-group').value, technique: $('ms-technique').value,
      tactic: $('ms-tactic').value, attribution: $('ms-attribution').value, page,
    });
    let d;
    try { d = await json(`/api/mitresaw/procedures?${params}`); } catch (e) { $('ms-count').textContent = e.message; return; }
    $('ms-count').textContent = d.total ? `${d.total.toLocaleString()} procedures` : 'No procedures match.';
    $('ms-rows-body').innerHTML = d.rows.map(r => `<tr>
      <td>${esc(r.group)}<span class="ms-id"><a href="${groupUrl(r.group_id)}" target="_blank" rel="noopener">${esc(r.group_id)}</a></span></td>
      <td>${esc(r.technique)}<span class="ms-id"><a href="${techUrl(r.technique_id)}" target="_blank" rel="noopener">${esc(r.technique_id)}</a></span></td>
      <td>${esc(r.tactic)}</td>
      <td>${via(r.attribution)}<div>${procedure(r.procedure)}</div></td>
      <td>${indicators(r.indicators)}</td></tr>`).join('');
    $('ms-page').textContent = `Page ${d.page} of ${d.pages}`;
    $('ms-prev').disabled = d.page <= 1;
    $('ms-next').disabled = d.page >= d.pages;
  }

  let debounce;
  const research = () => { clearTimeout(debounce); debounce = setTimeout(() => { page = 1; search(); }, 250); };
  ['ms-q', 'ms-group', 'ms-technique'].forEach(id => $(id).addEventListener('input', research));
  ['ms-tactic', 'ms-attribution'].forEach(id => $(id).addEventListener('change', research));
  $('ms-prev').addEventListener('click', () => { page--; search(); });
  $('ms-next').addEventListener('click', () => { page++; search(); });

  json('/api/mitresaw/groups').then(d => {
    $('ms-group-list').innerHTML = d.groups.map(g => `<option value="${esc(g.name)}">${esc(g.id)} · ${g.techniques} techniques</option>`).join('');
  }).catch(() => {});

  // ---------- Exclusions ----------
  function exclRow(r = { indicator: '', reason: '' }) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><input class="form-input" data-k="indicator" value="${esc(r.indicator)}" aria-label="Indicator"></td>
      <td><input class="form-input" data-k="reason" value="${esc(r.reason)}" aria-label="Reason"></td>
      <td><button type="button" class="ms-remove" aria-label="Remove" title="Remove">×</button></td>`;
    tr.querySelectorAll('input').forEach(i => { i.disabled = !signedIn; });
    tr.querySelector('.ms-remove').disabled = !signedIn;
    tr.querySelector('.ms-remove').addEventListener('click', () => tr.remove());
    $('ms-excl-body').appendChild(tr);
    return tr;
  }

  async function loadExclusions() {
    try {
      const d = await json('/api/mitresaw/exclusions');
      $('ms-excl-body').innerHTML = '';
      d.exclusions.forEach(exclRow);
      $('ms-excl-state').textContent = d.exclusions.length ? '' : 'No exclusions.';
    } catch (e) { $('ms-excl-state').textContent = e.message; }
  }

  $('ms-excl-add').disabled = $('ms-excl-save').disabled = !signedIn;
  if (!signedIn) $('ms-excl-state').textContent = 'Log in to change exclusions.';
  $('ms-excl-add').addEventListener('click', () => { exclRow().querySelector('input').focus(); $('ms-excl-state').textContent = ''; });
  $('ms-excl-save').addEventListener('click', async () => {
    const rows = [...$('ms-excl-body').rows].map(tr => Object.fromEntries([...tr.querySelectorAll('input')].map(i => [i.dataset.k, i.value])));
    try {
      const d = await json('/api/mitresaw/exclusions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ exclusions: rows }) });
      await loadExclusions();
      $('ms-excl-state').textContent = `Saved ${d.saved} exclusion${d.saved === 1 ? '' : 's'}.`;
    } catch (e) { $('ms-excl-state').textContent = e.message; }
  });

  status();
  osint();
  search();
  loadExclusions();
})();
