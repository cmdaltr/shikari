// Results page: anatomy workflow (templates/partials/anatomy.html, archer/visualization/anatomy.py)
(function () {
  const root = document.getElementById('anatomy');
  const dataEl = document.getElementById('an-data');
  if (!root || !dataEl) return;
  const view = JSON.parse(dataEl.textContent);
  const detail = document.getElementById('an-detail');
  const body = document.getElementById('an-detail-body');
  const byId = Object.fromEntries(view.nodes.map(n => [n.id, n]));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let selected = null;  // {node: id} or {edge: index}

  function techniques(list) {
    if (!list.length) return '';
    return '<h4>Techniques</h4><ul class="an-techniques">' + list.map(t =>
      `<li class="is-${t.detected ? 'detected' : 'gap'}"><strong>${esc(t.id)}</strong> ${esc(t.name && t.name !== t.id ? t.name : '')}` +
      ` · ${t.detected ? 'detected' : 'no detection'}</li>`).join('') + '</ul>';
  }
  function evidence(list) {
    return list.length ? '<h4>Procedures</h4>' + list.map(s => `<blockquote class="an-evidence">${esc(s)}</blockquote>`).join('') : '';
  }
  function links(edges, end) {
    return '<ul class="an-links">' + edges.map(e => {
      const other = byId[e[end]];
      return `<li><button type="button" data-goto="${esc(other.id)}">${esc(other.label)}</button>` +
        (e.label ? ` <span style="color:var(--af-muted)">(${esc(e.label)})</span>` : '') + '</li>';
    }).join('') + '</ul>';
  }

  function highlight() {
    const litNodes = new Set();
    root.querySelectorAll('.an-edge').forEach(el => {
      const e = view.edges[el.dataset.edge];
      const on = selected && (selected.node ? (e.source === selected.node || e.target === selected.node)
                                            : String(selected.edge) === el.dataset.edge);
      el.classList.toggle('is-lit', !!on);
      el.classList.toggle('is-selected', !!(selected && selected.edge !== undefined && on));
      if (on) { litNodes.add(e.source); litNodes.add(e.target); }
    });
    root.querySelectorAll('.an-node').forEach(el => {
      el.classList.toggle('is-selected', !!(selected && selected.node === el.dataset.id));
      el.classList.toggle('is-lit', litNodes.has(el.dataset.id));
    });
    root.classList.toggle('has-selection', !!selected);
  }

  function showNode(id) {
    const n = byId[id];
    const into = view.edges.filter(e => e.target === id);
    const out = view.edges.filter(e => e.source === id);
    body.innerHTML = `<p class="an-detail-title">${esc(n.label)}</p><p>${esc(n.sub || n.kind)}</p>` +
      techniques(n.techniques || []) + evidence(n.evidence || []) +
      (into.length ? '<h4>From</h4>' + links(into, 'source') : '') +
      (out.length ? '<h4>To</h4>' + links(out, 'target') : '');
  }
  function showEdge(i) {
    const e = view.edges[i];
    body.innerHTML = `<p class="an-detail-title">${esc(byId[e.source].label)} → ${esc(byId[e.target].label)}</p>` +
      `<p>${esc(e.roles.join(', ') || 'Link')}</p>` + techniques(e.techniques) + evidence(e.evidence);
  }

  function select(next) {
    const same = selected && next && selected.node === next.node && selected.edge === next.edge;
    selected = same ? null : next;
    highlight();
    if (!selected) { detail.hidden = true; return; }
    selected.node ? showNode(selected.node) : showEdge(selected.edge);
    detail.hidden = false;
  }

  function pick(target) {
    const node = target.closest('.an-node');
    if (node) return select({ node: node.dataset.id }), true;
    const edge = target.closest('.an-edge[tabindex]');
    if (edge) return select({ edge: Number(edge.dataset.edge) }), true;
    const go = target.closest('[data-goto]');
    if (go) return select({ node: go.dataset.goto }), true;
    return false;
  }
  root.addEventListener('click', ev => pick(ev.target));
  root.addEventListener('keydown', ev => {
    if ((ev.key === 'Enter' || ev.key === ' ') && pick(ev.target)) ev.preventDefault();
    if (ev.key === 'Escape' && selected) select(null);
  });
  document.getElementById('an-detail-close').addEventListener('click', () => select(null));
  const gaps = document.getElementById('an-gaps-only');
  gaps.addEventListener('click', () => {
    const on = !gaps.classList.contains('is-on');
    gaps.classList.toggle('is-on', on);
    gaps.setAttribute('aria-pressed', on);
    root.classList.toggle('gaps-only', on);
  });
})();
