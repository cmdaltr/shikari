// Agents page (templates/agents.html): start an agent, follow its trace, answer approvals.
(function () {
  const run = document.getElementById('ag-run');
  const trace = document.getElementById('ag-trace');
  const status = document.getElementById('ag-status');
  const usage = document.getElementById('ag-usage');
  const answer = document.getElementById('ag-answer');
  const stopBtn = document.getElementById('ag-stop');
  const continueBtn = document.getElementById('ag-continue');
  let session = null, since = 0, timer = null;
  const LABELS = { running: 'Running', needs_approval: 'Waiting for you', done: 'Done', stopped: 'Stopped', error: 'Error', interrupted: 'Interrupted' };

  // --- agent picker ---
  document.querySelectorAll('.ag-pick').forEach(btn => btn.addEventListener('click', () => {
    document.querySelectorAll('.ag-pick').forEach(b => {
      const on = b === btn;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-selected', on);
    });
    document.querySelectorAll('.ag-form').forEach(f => { f.hidden = f.dataset.agent !== btn.dataset.agent; });
  }));

  // --- start ---
  document.querySelectorAll('.ag-form').forEach(form => form.addEventListener('submit', async e => {
    e.preventDefault();
    if (session && timer) return;
    const input = {};
    form.querySelectorAll('input[name]:not([type=checkbox]), textarea[name]').forEach(el => {
      if (el.value.trim()) input[el.name] = el.value.trim();
    });
    const autoApprove = !form.querySelector('input[name=approve]').checked;
    const provider = document.getElementById('ag-provider')?.value || '';
    const res = await fetch(`/api/agents/${form.dataset.agent}/start`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input, auto_approve: autoApprove, provider }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { showError(data.error || `HTTP ${res.status}`); return; }
    open(data.session_id);
  }));

  function open(id) {
    clearTimeout(timer);
    session = id; since = 0;
    trace.innerHTML = ''; answer.hidden = true; answer.innerHTML = '';
    run.hidden = false; stopBtn.hidden = false; continueBtn.hidden = true;
    setStatus('running');
    poll();
    run.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // --- recent runs (saved in the database) ---
  async function history() {
    const res = await fetch('/api/agents/sessions?limit=15');
    const data = await res.json().catch(() => ({}));
    const list = document.getElementById('ag-history-list');
    const sessions = data.sessions || [];
    document.getElementById('ag-history').hidden = !sessions.length;
    list.innerHTML = sessions.map(s => `<li><button type="button" data-id="${esc(s.session_id)}">`
      + `<span class="ag-status is-${esc(s.status)}">${esc(LABELS[s.status] || s.status)}</span>`
      + `<span class="ag-history-agent">${esc(s.agent)}</span>`
      + `<span class="ag-history-task">${esc(s.task)}</span>`
      + `<span class="ag-history-meta">${new Date(s.created).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })}`
      + ` · ${esc(s.model)} · ${s.turns} turns</span></button></li>`).join('');
    list.querySelectorAll('button').forEach(b => b.addEventListener('click', () => open(b.dataset.id)));
  }
  history();

  stopBtn.addEventListener('click', () => session && fetch(`/api/agents/sessions/${session}/stop`, { method: 'POST' }));

  // An interrupted, stopped or turn-limited run carries on from its saved conversation
  continueBtn.addEventListener('click', async () => {
    if (!session) return;
    continueBtn.disabled = true;
    const res = await fetch(`/api/agents/sessions/${session}/resume`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    });
    const data = await res.json().catch(() => ({}));
    continueBtn.disabled = false;
    if (!res.ok) { showError(data.error || `HTTP ${res.status}`); return; }
    continueBtn.hidden = true; stopBtn.hidden = false;
    trace.querySelectorAll('.ag-ev-error').forEach(el => el.remove());
    setStatus('running');
    poll();
  });

  async function poll() {
    clearTimeout(timer);
    let view;
    try {
      const res = await fetch(`/api/agents/sessions/${session}?since=${since}`);
      view = await res.json();
      if (!res.ok) throw new Error(view.error || res.status);
    } catch (err) {
      showError(`Lost the session: ${err.message}`); timer = null; return;
    }
    view.events.forEach(addEvent);
    since = view.next;
    usage.textContent = `${view.turns} turn${view.turns === 1 ? '' : 's'} · ${view.tokens.input.toLocaleString()} in / ${view.tokens.output.toLocaleString()} out tokens`;
    setStatus(view.status);
    if (view.status === 'needs_approval' && view.pending) showApproval(view.pending);
    if (['done', 'stopped', 'error', 'interrupted'].includes(view.status)) {
      timer = null; stopBtn.hidden = true;
      continueBtn.hidden = !view.resumable;
      if (view.answer) { answer.innerHTML = markdown(view.answer); answer.hidden = false; }
      history();
      return;
    }
    timer = setTimeout(poll, 1200);
  }

  function setStatus(s) {
    status.textContent = LABELS[s] || s;
    status.className = `ag-status is-${s}`;
  }

  // --- trace ---
  function addEvent(e) {
    const li = document.createElement('li');
    li.className = `ag-ev ag-ev-${e.type}`;
    switch (e.type) {
      case 'task':
        li.innerHTML = `<span class="ag-ev-icon">▶</span><div><strong>Task</strong> ${esc(e.text)}<div class="ag-ev-sub">${esc(e.model)}${e.provider ? ` (${esc(e.provider)})` : ''} · tools: ${e.tools.map(t => `<code>${esc(t)}</code>`).join(' ')}</div></div>`;
        break;
      case 'text':
        if (e.final) return;  // the answer is shown below the trace
        li.innerHTML = `<span class="ag-ev-icon">💭</span><div class="ag-ev-text">${markdown(e.text)}</div>`;
        break;
      case 'tool_call':
        li.innerHTML = `<span class="ag-ev-icon">→</span><div><code class="ag-tool${e.changes ? ' is-change' : ''}">${esc(e.tool)}</code>`
          + `<details><summary>input</summary><pre>${esc(JSON.stringify(e.input, null, 2))}</pre></details></div>`;
        break;
      case 'tool_result':
        li.innerHTML = `<span class="ag-ev-icon">${e.error ? '✗' : '←'}</span><div><details><summary>${esc(e.tool)} ${e.error ? 'failed' : 'returned'} `
          + `${e.size.toLocaleString()} characters</summary><pre>${esc(e.preview)}${e.size > e.preview.length ? '\n…' : ''}</pre></details></div>`;
        break;
      case 'approval_needed':
        return;  // shown as the approval box
      case 'approval':
        li.innerHTML = `<span class="ag-ev-icon">${e.approved ? '✓' : '✗'}</span><div>${e.approved ? 'Allowed' : 'Declined'} <code>${esc(e.tool)}</code></div>`;
        document.querySelectorAll('.ag-approval').forEach(el => el.remove());
        break;
      case 'resumed':
        li.innerHTML = `<span class="ag-ev-icon">↻</span><div>${esc(e.text)}</div>`;
        break;
      case 'done':
        li.innerHTML = `<span class="ag-ev-icon">■</span><div>Finished (${esc(e.stop_reason || '')})</div>`;
        break;
      default:
        li.innerHTML = `<span class="ag-ev-icon">!</span><div>${esc(e.text || e.type)}</div>`;
    }
    trace.appendChild(li);
  }

  function showApproval(p) {
    if (trace.querySelector('.ag-approval')) return;
    const li = document.createElement('li');
    li.className = 'ag-ev ag-approval';
    li.innerHTML = `<span class="ag-ev-icon">⚠</span><div><strong>Allow <code>${esc(p.tool)}</code>?</strong> ${esc(p.description || '')}`
      + `<pre>${esc(JSON.stringify(p.input, null, 2))}</pre>`
      + `<div class="ag-approval-actions"><button type="button" data-ok="1">Allow</button><button type="button" data-ok="0">Decline</button></div></div>`;
    li.querySelectorAll('button').forEach(b => b.addEventListener('click', async () => {
      li.querySelectorAll('button').forEach(x => { x.disabled = true; });
      await fetch(`/api/agents/sessions/${session}/decision`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ approve: b.dataset.ok === '1' }),
      });
    }));
    trace.appendChild(li);
    li.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function showError(msg) {
    run.hidden = false;
    setStatus('error');
    const li = document.createElement('li');
    li.className = 'ag-ev ag-ev-error';
    li.innerHTML = `<span class="ag-ev-icon">!</span><div>${esc(msg)}</div>`;
    trace.appendChild(li);
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Minimal Markdown for agent answers: escaped first, then headings, code, tables, lists, emphasis
  function markdown(src) {
    const blocks = [];
    let text = esc(src).replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
      blocks.push(`<pre class="ag-code"><code>${code.replace(/\n$/, '')}</code></pre>`);
      return `\u0000${blocks.length - 1}\u0000`;
    });
    const inline = s => s
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
      .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    const out = [];
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\u0000\d+\u0000$/.test(line.trim())) { out.push(blocks[+line.trim().slice(1, -1)]); continue; }
      const h = line.match(/^(#{1,4})\s+(.*)/);
      if (h) { out.push(`<h${h[1].length + 2}>${inline(h[2])}</h${h[1].length + 2}>`); continue; }
      if (/^\|.*\|\s*$/.test(line) && /^\|[\s:|-]+\|\s*$/.test(lines[i + 1] || '')) {
        const row = l => l.trim().replace(/^\||\|$/g, '').split('|').map(c => inline(c.trim()));
        let html = '<div class="ag-table"><table><thead><tr>' + row(line).map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>';
        i += 2;
        while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) { html += '<tr>' + row(lines[i]).map(c => `<td>${c}</td>`).join('') + '</tr>'; i++; }
        i--;
        out.push(html + '</tbody></table></div>');
        continue;
      }
      const li = line.match(/^\s*(?:[-*]|(\d+)\.)\s+(.*)/);
      if (li) {
        const tag = li[1] ? 'ol' : 'ul';
        let html = `<${tag}>`;
        while (i < lines.length && (lines[i].match(/^\s*(?:[-*]|\d+\.)\s+(.*)/))) {
          html += `<li>${inline(lines[i].match(/^\s*(?:[-*]|\d+\.)\s+(.*)/)[1])}</li>`; i++;
        }
        i--;
        out.push(html + `</${tag}>`);
        continue;
      }
      out.push(line.trim() ? `<p>${inline(line)}</p>` : '');
    }
    return out.join('\n');
  }
})();
