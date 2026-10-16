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
    $('fd-sources').textContent = data.sources.join(' · ');
    const when = data.last_refresh ? new Date(data.last_refresh * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never';
    $('fd-status').textContent = data.refreshing
      ? 'Collecting this week\'s posts…'
      : `${data.considered} posts read, ${data.posts.length} with technical content; last collected ${when}.`;
    $('fd-refresh').disabled = data.refreshing;
    render();
    if (data.refreshing) timer = setTimeout(load, 4000);
  }

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
