// Threat Feed page (templates/feed.html): a searchable wall of tagged posts, refreshed in the background.
(function () {
  const $ = id => document.getElementById(id);
  let timer = null, posts = [], show = 'both';

  async function load() {
    clearTimeout(timer);
    let data;
    try {
      const res = await fetch('/api/feed');
      data = await res.json();
      if (!res.ok) throw new Error(data.error || res.status);
    } catch (err) {
      $('fd-status').textContent = `Couldn't load the feed: ${err.message}`;
      return;
    }
    posts = data.posts;
    $('fd-days').textContent = data.days;
    $('fd-industries').textContent = data.labels.length ? data.labels.join(', ') : 'none set';
    sources(data);
    const when = data.last_refresh ? new Date(data.last_refresh * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never';
    $('fd-status').textContent = data.refreshing
      ? 'Collecting this week\'s posts…'
      : `${data.considered} posts read, ${data.posts.length} with technical content; last collected ${when}.`;
    $('fd-refresh').disabled = data.refreshing;
    render();
    if (data.refreshing) timer = setTimeout(load, 4000);
  }

  // Sources: each one's last collection; an admin can add and remove their own
  function sources(data) {
    const bad = data.sources.filter(s => s.ok === false).length;
    $('fd-sources-count').textContent = `${data.sources.length}${bad ? `, ${bad} not responding` : ''}`;
    $('fd-sources').innerHTML = data.sources.map(s => {
      const state = s.ok === undefined ? ['', 'Not collected yet'] : s.ok
        ? ['is-ok', `${s.posts} post${s.posts === 1 ? '' : 's'} this week`] : ['is-bad', `Failed: ${s.error}`];
      return `<li class="${state[0]}"><a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.name)}</a>
        <span class="fd-source-state">${esc(state[1])}</span>${s.custom ? '<span class="fd-source-own">Added</span>' : ''}
        ${s.custom && data.can_edit_sources ? `<button type="button" class="fd-source-remove" data-url="${esc(s.url)}" title="Remove ${esc(s.name)}">Remove</button>` : ''}</li>`;
    }).join('');
    $('fd-add-source').hidden = !data.can_edit_sources;
    document.querySelectorAll('.fd-source-remove').forEach(b => b.addEventListener('click', async () => {
      await fetch('/api/feed/sources', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: b.dataset.url }) });
      load();
    }));
  }

  $('fd-add-source')?.addEventListener('submit', async e => {
    e.preventDefault();
    const msg = $('fd-source-msg'), btn = $('fd-source-add');
    btn.disabled = true;
    msg.className = 'fd-source-msg';
    msg.textContent = 'Checking the feed…';
    try {
      const res = await fetch('/api/feed/sources', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: $('fd-source-name').value, url: $('fd-source-url').value }) });
      const r = await res.json();
      if (!r.ok) throw new Error(r.error || res.status);
      msg.classList.add('is-ok');
      msg.textContent = `Added: ${r.items} posts in the feed. Its posts arrive at the next collection.`;
      $('fd-source-name').value = $('fd-source-url').value = '';
      fetch('/api/feed/refresh', { method: 'POST' }).then(load);
    } catch (err) {
      msg.classList.add('is-bad');
      msg.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  function visible(p, words) {
    if (show === 'both' && !p.relevant) return false;
    if (show === 'yours' && !Object.keys(p.yours).length) return false;
    if (show === 'motive' && !p.tags.motives.length) return false;
    const hay = `${p.title} ${p.description || ''}`.toLowerCase();
    return words.every(w => hay.includes(w));
  }

  function render() {
    const words = $('fd-search').value.toLowerCase().split(/\s+/).filter(Boolean);
    const shown = posts.filter(p => visible(p, words));
    $('fd-count').textContent = `${shown.length} of ${posts.length}`;
    const wall = $('fd-wall');
    if (!shown.length) {
      wall.innerHTML = `<li class="fd-empty">${posts.length ? 'No posts match.' : 'No posts yet.'}</li>`;
      return;
    }
    wall.innerHTML = shown.map(p => {
      const date = p.published ? new Date(p.published).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }) : '';
      const yours = new Set(Object.keys(p.yours));
      const tag = (cls, text, title) => `<li class="fd-tag ${cls}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</li>`;
      const tags = [
        ...p.tags.industries.map(i => tag(yours.has(i) ? 'is-yours' : 'is-industry', i, yours.has(i) ? `Your industry: ${p.yours[i].join(', ')}` : '')),
        ...p.tags.nations.map(n => tag('is-nation', n)),
        ...p.tags.motives.map(m => tag(m === 'Opportunistic' ? 'is-opp' : 'is-fin', m,
          (m === 'Opportunistic' ? p.opportunistic : p.financial).join(', '))),
      ].join('');
      return `<li class="fd-card">
        <div class="fd-head"><span class="fd-source">${esc(p.source)}</span><span class="fd-date">${esc(date)}</span></div>
        <a class="fd-title" href="${esc(p.url)}" target="_blank" rel="noopener" title="${esc(p.title)}">${mark(p.title, words)}</a>
        <p class="fd-desc" title="${esc(p.description || '')}">${mark(p.description || '', words)}</p>
        ${tags ? `<ul class="fd-tags">${tags}</ul>` : ''}
        <a class="fd-analyse" href="/?report=${encodeURIComponent(p.url)}">Analyse in Archer →</a>
      </li>`;
    }).join('');
  }

  function mark(text, words) {
    let html = esc(text);
    words.forEach(w => {
      html = html.replace(new RegExp(`(${esc(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'), '<mark>$1</mark>');
    });
    return html;
  }

  document.querySelectorAll('.fd-filter').forEach(b => b.addEventListener('click', () => {
    show = b.dataset.show;
    document.querySelectorAll('.fd-filter').forEach(x => {
      x.classList.toggle('is-active', x === b);
      x.setAttribute('aria-checked', String(x === b));
    });
    render();
  }));
  $('fd-search').addEventListener('input', render);

  $('fd-refresh').addEventListener('click', async () => {
    $('fd-refresh').disabled = true;
    await fetch('/api/feed/refresh', { method: 'POST' });
    load();
  });

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  load();
})();
