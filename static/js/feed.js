// Threat Feed page (templates/feed.html): the user's industry feed, refreshed in the background.
(function () {
  const $ = id => document.getElementById(id);
  let timer = null;

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
    $('fd-days').textContent = data.days;
    $('fd-industries').textContent = data.labels.length ? data.labels.join(', ') : 'your industries (none set yet)';
    $('fd-sources').textContent = data.sources.join(' · ');
    const when = data.last_refresh ? new Date(data.last_refresh * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never';
    $('fd-status').textContent = data.refreshing
      ? 'Collecting and reading this week\'s posts… (a minute or two the first time)'
      : `${data.considered} posts read; last collected ${when}.`;
    $('fd-refresh').disabled = data.refreshing;
    render('fd-industry', data.industry, data.labels.length
      ? 'Nothing this week names a group that targets your industries.'
      : 'Choose your industries in your profile to see posts about groups that target them.');
    render('fd-opportunistic', data.opportunistic, 'No opportunistic activity this week.');
    $('fd-industry-count').textContent = data.industry.length ? `(${data.industry.length})` : '';
    $('fd-opp-count').textContent = data.opportunistic.length ? `(${data.opportunistic.length})` : '';
    if (data.refreshing) timer = setTimeout(load, 5000);
  }

  function render(id, posts, empty) {
    const list = $(id);
    if (!posts.length) { list.innerHTML = `<li class="fd-empty">${esc(empty)}</li>`; return; }
    list.innerHTML = posts.map(p => {
      const date = p.published ? new Date(p.published).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }) : '';
      const why = [...p.why.industry.map(w => `<li class="fd-why is-industry">${esc(w)}</li>`),
                   ...p.why.opportunistic.map(w => `<li class="fd-why is-opp">${esc(w)}</li>`)].join('');
      const ttps = (p.techniques || []).slice(0, 12).map(t =>
        `<a class="fd-ttp" href="https://attack.mitre.org/techniques/${t.replace('.', '/')}/" target="_blank" rel="noopener">${esc(t)}</a>`).join('');
      const more = (p.techniques || []).length > 12 ? `<span class="fd-more">+${p.techniques.length - 12}</span>` : '';
      return `<li class="fd-post">
        <div class="fd-head"><span class="fd-source">${esc(p.source)}</span><span class="fd-date">${esc(date)}</span></div>
        <a class="fd-title" href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.title)}</a>
        ${p.summary ? `<p class="fd-summary">${esc(p.summary.slice(0, 280))}${p.summary.length > 280 ? '…' : ''}</p>` : ''}
        <ul class="fd-whys">${why}</ul>
        <div class="fd-facts">
          ${p.groups.length ? `<span><b>Groups</b> ${p.groups.map(esc).join(', ')}</span>` : ''}
          ${p.cves.length ? `<span><b>CVEs</b> ${p.cves.map(esc).join(', ')}</span>` : ''}
          ${p.iocs ? `<span><b>IOCs</b> ${p.iocs}</span>` : ''}
        </div>
        ${ttps ? `<div class="fd-ttps">${ttps}${more}</div>` : ''}
        <a class="fd-analyse" href="/?report=${encodeURIComponent(p.url)}">Analyse in Archer →</a>
      </li>`;
    }).join('');
  }

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
