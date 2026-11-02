// Organisation exposure map (templates/partials/exposure.html, shikari.visualization.exposure).
// Selecting a component lights its links and shows what's behind it; the breach node also carries
// a link-out and any recorded breach metadata.
(function () {
  const root = document.getElementById('exposure');
  const dataEl = document.getElementById('ex-data');
  if (!root || !dataEl) return;
  const view = JSON.parse(dataEl.textContent);
  const detail = document.getElementById('ex-detail');
  const body = document.getElementById('ex-detail-body');
  const byId = Object.fromEntries(view.nodes.map(n => [n.id, n]));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let selected = null;

  function sections(n) {
    return (n.sections || []).map(s =>
      (s.title ? `<h4>${esc(s.title)}</h4>` : '') + '<ul class="an-members">' +
      s.items.map(m => `<li>${esc(m)}</li>`).join('') + '</ul>').join('');
  }

  function breachBlock(n) {
    if (n.kind !== 'breach') return '';
    let html = '';
    if (n.link) html += `<a class="ex-breach-link" href="${esc(n.link)}" target="_blank" rel="noopener">Check this domain on Have I Been Pwned →</a>`;
    const b = n.breaches || [];
    if (b.length) {
      html += '<h4>Recorded breaches</h4><ul class="ex-breach-list">' + b.map(x =>
        `<li>${esc(x.title || x.name)}${x.date ? ` <span class="pwn">· ${esc(x.date)}</span>` : ''}` +
        `${x.pwn_count ? ` <span class="pwn">· ${Number(x.pwn_count).toLocaleString()} accounts</span>` : ''}</li>`).join('') + '</ul>';
    }
    html += '<p class="pwn" style="color:var(--af-muted);font-size:.88em;margin-top:8px;">Metadata only — no accounts or credentials are retrieved.</p>';
    return html;
  }

  function cveBlock(n) {
    if (n.kind !== 'cve' || !(n.cves || []).length) return '';
    return '<h4>Known CVEs</h4><ul class="ex-cve-list">' + n.cves.map(c =>
      `<li><a href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener">${esc(c)}</a></li>`).join('') + '</ul>' +
      '<p class="pwn" style="color:var(--af-muted);font-size:.88em;margin-top:8px;">Reported by Shodan InternetDB against the exposed services — confirm before acting.</p>';
  }

  function linksTo(id, end) {
    const es = view.edges.filter(e => e[end === 'source' ? 'target' : 'source'] === id);
    if (!es.length) return '';
    const label = end === 'source' ? 'Derived from' : 'Leads to';
    return `<h4>${label}</h4><ul class="an-links">` + es.map(e => {
      const other = byId[e[end]];
      return `<li><button type="button" data-goto="${esc(other.id)}">${esc(other.title)}</button>` +
        (e.label ? ` <span style="color:var(--af-muted)">(${esc(e.label)})</span>` : '') + '</li>';
    }).join('') + '</ul>';
  }

  function highlight() {
    const lit = new Set();
    root.querySelectorAll('.an-edge').forEach(el => {
      const e = view.edges[el.dataset.edge];
      const on = selected && (selected.node ? (e.source === selected.node || e.target === selected.node)
                                            : String(selected.edge) === el.dataset.edge);
      el.classList.toggle('is-lit', !!on);
      el.classList.toggle('is-selected', !!(selected && selected.edge !== undefined && on));
      if (on) { lit.add(e.source); lit.add(e.target); }
    });
    root.querySelectorAll('.an-node').forEach(el => {
      el.classList.toggle('is-selected', !!(selected && selected.node === el.dataset.id));
      el.classList.toggle('is-lit', lit.has(el.dataset.id));
    });
    root.classList.toggle('has-selection', !!selected);
  }

  function showNode(id) {
    const n = byId[id];
    if (!n) return;
    selected = { node: id };
    body.innerHTML = `<h3>${esc(n.title)}</h3>${n.sub ? `<p class="an-sub-text">${esc(n.sub)}</p>` : ''}` +
      breachBlock(n) + cveBlock(n) + sections(n) + linksTo(id, 'target') + linksTo(id, 'source');
    detail.hidden = false;
    highlight();
  }

  function showEdge(i) {
    const e = view.edges[i];
    selected = { edge: i };
    const s = byId[e.source], t = byId[e.target];
    body.innerHTML = `<h3>${esc(s.title)} <span style="color:var(--af-muted)">${esc(e.label || '→')}</span> ${esc(t.title)}</h3>` +
      `<ul class="an-links"><li><button type="button" data-goto="${esc(s.id)}">${esc(s.title)}</button></li>` +
      `<li><button type="button" data-goto="${esc(t.id)}">${esc(t.title)}</button></li></ul>`;
    detail.hidden = false;
    highlight();
  }

  function clear() { selected = null; detail.hidden = true; highlight(); }

  root.querySelectorAll('.an-node').forEach(el => {
    const go = () => showNode(el.dataset.id);
    el.addEventListener('click', go);
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
  root.querySelectorAll('.an-edge').forEach(el => {
    const go = () => showEdge(+el.dataset.edge);
    el.addEventListener('click', go);
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
  body.addEventListener('click', e => {
    const b = e.target.closest('[data-goto]');
    if (b) showNode(b.dataset.goto);
  });
  document.getElementById('ex-detail-close').addEventListener('click', clear);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') clear(); });
})();
