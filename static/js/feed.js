// Threat Feed page (templates/feed.html): a searchable wall of tagged posts, refreshed in the background.
(function () {
  const $ = id => document.getElementById(id);
  let timer = null, posts = [], show = 'both', watchedUrls = {};

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
    watchedUrls = data.watched || {};
    $('fd-days').textContent = data.days;
    $('fd-industries').textContent = data.labels.length ? data.labels.join(', ') : 'none set';
    $('fd-stack').textContent = data.stack && data.stack.length ? `${data.stack.length} product${data.stack.length === 1 ? '' : 's'}` : 'none set';
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
    if (show === 'stack' && !(p.stack || []).length) return false;
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
        ...(watchedUrls[p.url] || []).map(q => tag('is-watch', `Watching: ${q}`, 'Matches your watchlist')),
        ...(p.stack || []).map(s => tag('is-yours', s, 'In your technology stack')),
        ...((p.off_stack || []).length ? [tag('is-off-stack', 'Not your stack', `Aimed at ${p.off_stack.join(', ')}, which your technology stack doesn't have`)] : []),
        ...p.tags.nations.map(n => tag('is-nation', n)),
        ...p.tags.motives.map(m => tag(m === 'Opportunistic' ? 'is-opp' : 'is-fin', m,
          (m === 'Opportunistic' ? p.opportunistic : p.financial).join(', '))),
      ].join('');
      return `<li class="fd-card">
        <div class="fd-head"><span class="fd-source">${esc(p.source)}</span><span class="fd-date">${esc(date)}</span></div>
        <a class="fd-title" href="${esc(p.url)}" target="_blank" rel="noopener" title="${esc(p.title)}">${mark(p.title, words)}</a>
        <p class="fd-desc" title="${esc(p.description || '')}">${mark(p.description || '', words)}</p>
        ${tags ? `<ul class="fd-tags">${tags}</ul>` : ''}
        <a class="fd-analyse" href="/?report=${encodeURIComponent(p.url)}">Analyse in Shikari →</a>
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

  // Search all research: the source archive, ATT&CK and (optionally) web news
  $('fd-research-form').addEventListener('submit', async e => {
    e.preventDefault();
    const q = $('fd-research-q').value.trim(), out = $('fd-research-results'), btn = $('fd-research-go');
    btn.disabled = true;
    out.innerHTML = `<p class="fd-empty">Searching${$('fd-research-web').checked ? ' (the web takes a few seconds)' : ''}…</p>`;
    let r;
    try {
      const res = await fetch(`/api/feed/search?q=${encodeURIComponent(q)}&web=${$('fd-research-web').checked}`);
      r = await res.json();
      if (!res.ok) throw new Error(r.error || res.status);
    } catch (err) {
      out.innerHTML = `<p class="fd-empty">${esc(err.message)}</p>`;
      return;
    } finally {
      btn.disabled = false;
    }
    const words = r.query.toLowerCase().split(/\s+/);
    const day = d => d ? new Date(d).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '';
    const story = (src, p) => `<li><span class="fd-r-meta">${esc(src)}${p.published ? ` · ${esc(day(p.published))}` : ''}</span>
        <a href="${esc(p.url)}" target="_blank" rel="noopener">${mark(p.title, words)}</a>
        ${p.summary ? `<p>${mark(p.summary, words)}</p>` : ''}
        <a class="fd-analyse" href="/?report=${encodeURIComponent(p.url)}">Analyse in Shikari →</a></li>`;
    const groups = [
      ["Shikari's sources", `${r.archive_size.toLocaleString()} posts collected so far`, r.sources.map(p => story(p.source, p))],
      ['MITRE ATT&amp;CK', '', r.attack.map(a => `<li><span class="fd-r-meta">${esc(a.kind)} · ${esc(a.id || '')}${a.named ? '' : ' · mentioned in its description'}</span>
        <a href="${esc(a.url || '#')}" target="_blank" rel="noopener">${mark(a.name, words)}</a>
        ${a.aliases.length ? `<p>Also: ${mark(a.aliases.join(', '), words)}</p>` : ''}</li>`)],
      ...(r.web ? [['Web news', 'Google News and Bing News, security stories only', r.web.map(p => story(`${p.outlet} (${p.via})`, p))]] : []),
    ];
    // Groups with results get a column each; the empty ones share one line
    const empty = groups.filter(g => !g[2].length).map(g => g[0] + (g[0] === "Shikari's sources" ? ` (${g[1]})` : ''));
    out.innerHTML = groups.filter(g => g[2].length).map(([title, note, items]) => `<div class="fd-r-group">
        <h3 class="ui-subtitle">${title} <span class="fd-count">${items.length}</span></h3>
        ${note ? `<p class="fd-r-note">${note}</p>` : ''}<ul>${items.join('')}</ul></div>`).join('')
      + (empty.length ? `<p class="fd-empty">Nothing in ${empty.join(empty.length > 2 ? ', ' : ' or ')}.</p>` : '')
      + `<p class="fd-empty"><button type="button" class="fd-watch-btn fd-watch-this" data-q="${esc(r.query)}">Watch “${esc(r.query)}” for new posts</button></p>`;
  });

  // Watchlists: saved searches flagging new posts at each collection
  async function watchLoad() {
    let r;
    try {
      const res = await fetch('/api/feed/watchlists');
      r = await res.json();
      if (!res.ok) throw new Error(r.error || res.status);
    } catch (err) {
      $('fd-watch-list').innerHTML = `<li class="fd-empty">${esc(err.message)}</li>`;
      return;
    }
    const email = $('fd-watch-email');
    email.disabled = !r.email_available;
    $('fd-watch-email-label').title = r.email_available ? 'One email per collection with new matches' : 'Email needs SMTP configured (EMAIL_ENABLED and SMTP_* in .env)';
    $('fd-watch-total').hidden = !r.new_count;
    $('fd-watch-total').textContent = `${r.new_count} new`;
    const day = d => d ? new Date(d).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '';
    $('fd-watch-list').innerHTML = r.watchlists.length ? r.watchlists.map(w => `<li class="fd-watch-item" data-id="${esc(w.id)}">
        <div class="fd-watch-row">
          <strong>${esc(w.query)}</strong>
          <span class="fd-watch-flags">${w.web ? 'Sources and web' : 'Sources'}${w.email ? ' · email' : ''}${w.checked ? ` · checked ${esc(new Date(w.checked * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }))}` : ''}</span>
          <span class="fd-watch-new${w.new_count ? ' has-new' : ''}">${w.new_count ? `${w.new_count} new` : 'Nothing new'}</span>
          ${w.new_count ? '<button type="button" class="fd-watch-btn" data-act="seen">Mark seen</button>' : ''}
          <button type="button" class="fd-watch-btn is-remove" data-act="remove">Remove</button>
        </div>
        ${w.new_count ? `<ul class="fd-watch-matches">${w.new.map(m => `<li><span class="fd-r-meta">${esc(m.source || m.via || '')}${m.published ? ` · ${esc(day(m.published))}` : ''}</span>
          <a href="${esc(m.url)}" target="_blank" rel="noopener">${esc(m.title)}</a>
          <a class="fd-analyse" href="/?report=${encodeURIComponent(m.url)}">Analyse in Shikari →</a></li>`).join('')}</ul>` : ''}
      </li>`).join('') : '<li class="fd-empty">No watchlists yet.</li>';
  }

  $('fd-watch-form').addEventListener('submit', async e => {
    e.preventDefault();
    const msg = $('fd-watch-msg'), btn = $('fd-watch-add');
    btn.disabled = true;
    msg.className = 'fd-source-msg';
    msg.textContent = 'Saving (finding what already matches)…';
    try {
      const res = await fetch('/api/feed/watchlists', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: $('fd-watch-q').value, web: $('fd-watch-web').checked, email: $('fd-watch-email').checked }) });
      const r = await res.json();
      if (!res.ok) throw new Error(r.error || res.status);
      msg.classList.add('is-ok');
      msg.textContent = `Watching “${r.watchlist.query}”. New posts appear here after each collection.`;
      $('fd-watch-q').value = '';
      watchLoad();
    } catch (err) {
      msg.classList.add('is-bad');
      msg.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  $('fd-watch-list').addEventListener('click', async e => {
    const btn = e.target.closest('.fd-watch-btn');
    if (!btn) return;
    const id = btn.closest('.fd-watch-item').dataset.id;
    btn.disabled = true;
    if (btn.dataset.act === 'seen') {
      await fetch('/api/feed/watchlists/seen', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
    } else {
      await fetch(`/api/feed/watchlists/${encodeURIComponent(id)}`, { method: 'DELETE' });
    }
    watchLoad();
    window.dispatchEvent(new Event('shikari:watch-changed'));
  });

  // A research search can become a watchlist
  $('fd-research-results').addEventListener('click', e => {
    const btn = e.target.closest('.fd-watch-this');
    if (!btn) return;
    $('fd-watch-q').value = btn.dataset.q;
    $('fd-watch-web').checked = $('fd-research-web').checked;
    $('fd-watch').scrollIntoView({ behavior: 'smooth', block: 'start' });
    $('fd-watch-q').focus();
  });

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  load();
  watchLoad();
})();
