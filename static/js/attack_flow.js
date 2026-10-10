// Results page: interactive kill-chain attack flow (templates/partials/attack_flow.html)
(function () {
  const dataEl = document.getElementById('af-data');
  if (!dataEl) return;
  const flow = JSON.parse(dataEl.textContent);
  const section = document.getElementById('attack-flow');
  const canvas = document.getElementById('af-canvas');
  const svg = document.getElementById('af-edges');
  const detail = document.getElementById('af-detail');
  const detailBody = document.getElementById('af-detail-body');

  const VENDOR_NAMES = { googlesecops: 'Google SecOps', mde: 'MDE', splunk: 'Splunk', elastic: 'Elastic' };
  const EDGE_COLOURS = { googlesecops: '#4285F4', mde: '#00A2AD', splunk: '#E91E8C', elastic: '#F0A500', mixed: '#64748B' };
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const nodes = {};
  flow.lanes.forEach(l => l.nodes.forEach(n => { nodes[n.id] = n; }));
  const nodeEls = {};
  section.querySelectorAll('.af-node').forEach(el => { nodeEls[el.dataset.id] = el; });

  const state = {
    vendors: new Set(flow.vendors.map(v => v.key)),
    gaps: true,
    edges: true,
    selected: null,
    query: '',
  };

  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const logo = v => `<svg class="af-logo" aria-hidden="true"><use href="#af-logo-${v}"/></svg>`;

  // An edge is shown when one of its correlation vendors is selected
  const edgeVendors = e => e.vendors.filter(v => state.vendors.has(v));
  const visibleEdges = () => (state.edges ? flow.edges.filter(e =>
    edgeVendors(e).length && !nodeEls[e.from].hidden && !nodeEls[e.to].hidden) : []);

  function nodeDetected(n) {
    return Object.keys(n.vendors).some(v => state.vendors.has(v));
  }

  function applyFilters() {
    const q = state.query;
    Object.values(nodes).forEach(n => {
      const el = nodeEls[n.id];
      const detected = nodeDetected(n);
      el.classList.toggle('is-gap', !detected);
      el.hidden = !detected && !state.gaps;
      el.querySelectorAll('.af-node-cov .af-logo').forEach(l => { l.style.display = state.vendors.has(l.dataset.vendor) ? '' : 'none'; });
      const mark = el.querySelector('.af-gap-mark');
      if (!detected && !mark) el.querySelector('.af-node-cov').insertAdjacentHTML('beforeend', '<span class="af-gap-mark" title="No detection">No detection</span>');
      if (detected && mark) mark.remove();
      el.classList.toggle('is-match', !!q && (n.id.toLowerCase().includes(q) || n.name.toLowerCase().includes(q)));
    });
    section.classList.toggle('af-searching', !!q);
    section.querySelectorAll('.af-lane').forEach(lane => {
      const shown = lane.querySelectorAll('.af-node:not([hidden])').length;
      lane.querySelector('.af-lane-count').textContent = shown;
      lane.hidden = shown === 0;
    });
    draw();
    if (state.selected) focus(state.selected);
  }

  // Forward links run right edge to left edge. Backward links (B's tactic is earlier) run
  // left edge to right edge through the gutter; same-lane links bulge out to the right.
  function path(a, b) {
    const box = canvas.getBoundingClientRect();
    const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
    const ox = canvas.scrollLeft - box.left, oy = canvas.scrollTop - box.top;
    const ya = ra.top + ra.height / 2 + oy, yb = rb.top + rb.height / 2 + oy;
    if (rb.left >= ra.right - 1) {
      const x1 = ra.right + ox, x2 = rb.left + ox, dx = Math.max(30, (x2 - x1) / 2);
      return { d: `M${x1},${ya} C${x1 + dx},${ya} ${x2 - dx},${yb} ${x2},${yb}`, back: false };
    }
    if (rb.right <= ra.left + 1) {
      const x1 = ra.left + ox, x2 = rb.right + ox, dx = Math.max(30, (x1 - x2) / 2);
      return { d: `M${x1},${ya} C${x1 - dx},${ya} ${x2 + dx},${yb} ${x2},${yb}`, back: true };
    }
    const x = ra.right + ox, bulge = 14 + Math.min(40, Math.abs(yb - ya) / 6);
    return { d: `M${x},${ya} C${x + bulge},${ya} ${x + bulge},${yb} ${x},${yb}`, back: false };
  }

  function draw() {
    svg.querySelectorAll('path.af-edge').forEach(p => p.remove());
    const lanes = canvas.querySelector('.af-lanes');
    svg.setAttribute('width', lanes.scrollWidth);
    svg.setAttribute('height', lanes.scrollHeight);
    visibleEdges().forEach(e => {
      const vs = edgeVendors(e);
      const key = vs.length === 1 ? vs[0] : 'mixed';
      const p = document.createElementNS(SVG_NS, 'path');
      const route = path(nodeEls[e.from], nodeEls[e.to]);
      p.setAttribute('d', route.d);
      p.setAttribute('class', route.back ? 'af-edge is-back' : 'af-edge');
      p.setAttribute('stroke', EDGE_COLOURS[key]);
      p.setAttribute('marker-end', `url(#af-arrow-${key})`);
      p.dataset.from = e.from;
      p.dataset.to = e.to;
      svg.appendChild(p);
    });
  }

  function linksOf(id) {
    return visibleEdges().filter(e => e.from === id || e.to === id);
  }

  function focus(id) {
    const links = linksOf(id);
    const linked = new Set(links.flatMap(e => [e.from, e.to]));
    section.classList.add('af-focused');
    Object.entries(nodeEls).forEach(([nid, el]) => {
      el.classList.toggle('is-focus', nid === id);
      el.classList.toggle('is-linked', linked.has(nid) && nid !== id);
    });
    svg.querySelectorAll('path.af-edge').forEach(p => {
      p.classList.toggle('is-hot', p.dataset.from === id || p.dataset.to === id);
    });
  }

  function unfocus() {
    if (state.selected) return focus(state.selected);
    section.classList.remove('af-focused');
    Object.values(nodeEls).forEach(el => el.classList.remove('is-focus', 'is-linked'));
    svg.querySelectorAll('path.af-edge.is-hot').forEach(p => p.classList.remove('is-hot'));
  }

  // Detection cards on the page carry data-technique as "T1234 - Name" or the bare name
  function detectionCards(n) {
    const name = n.name.toLowerCase();
    return Array.from(document.querySelectorAll('.detection-item[data-technique]')).filter(el => {
      const t = el.dataset.technique.toLowerCase();
      return t.startsWith(n.id.toLowerCase() + ' ') || t === n.id.toLowerCase() || t === name;
    });
  }

  function showDetail(id) {
    const n = nodes[id];
    const out = flow.edges.filter(e => e.from === id), inc = flow.edges.filter(e => e.to === id);
    const linkList = (edges, key, label) => edges.length ? `
      <h4>${label}</h4>
      <ul class="af-detail-links">${edges.map(e => {
        const o = nodes[e[key]];
        return `<li><button type="button" class="af-jump" data-id="${esc(o.id)}">${e.vendors.map(logo).join('')}<span><b>${esc(o.id)}</b> ${esc(o.name)}</span></button></li>`;
      }).join('')}</ul>` : '';
    const coverage = Object.keys(VENDOR_NAMES).filter(v => n.vendors[v]).map(v =>
      `<li>${logo(v)} ${VENDOR_NAMES[v]}: ${n.vendors[v]} detection${n.vendors[v] === 1 ? '' : 's'}</li>`).join('');
    const cards = detectionCards(n);
    detailBody.innerHTML = `
      <p class="af-detail-id"><a href="${esc(n.url)}" target="_blank" rel="noopener">${esc(n.id)} ↗</a></p>
      <h3>${esc(n.name)}</h3>
      <p class="af-detail-tactics">${n.tactics.map(esc).join(' · ')}</p>
      ${coverage ? `<ul class="af-detail-cov">${coverage}</ul>` : `<p class="af-detail-gap">No detection${n.attributed ? '. ATT&amp;CK attributes this technique to the group.' : ''}</p>`}
      ${cards.length ? `<button type="button" class="af-chip af-show-detections">Show detection${cards.length === 1 ? '' : 's'} (${cards.length})</button>` : ''}
      ${linkList(inc, 'from', 'Preceded by')}
      ${linkList(out, 'to', 'Followed by')}`;
    detail.hidden = false;
    const showBtn = detailBody.querySelector('.af-show-detections');
    if (showBtn) showBtn.addEventListener('click', () => revealDetections(cards));
  }

  function revealDetections(cards) {
    if (section.classList.contains('af-fullscreen')) toggleExpand();
    cards.forEach(card => {
      const vendor = card.closest('.vendor-section');
      const content = vendor && vendor.querySelector('.vendor-content');
      if (content && !content.classList.contains('show')) vendor.querySelector('.vendor-header').click();
      card.classList.remove('af-flash');
      void card.offsetWidth;
      card.classList.add('af-flash');
    });
    cards[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function select(id) {
    state.selected = state.selected === id ? null : id;
    Object.values(nodeEls).forEach(el => el.setAttribute('aria-pressed', String(el.dataset.id === state.selected)));
    if (state.selected) {
      focus(state.selected);
      showDetail(state.selected);
    } else {
      detail.hidden = true;
      unfocus();
    }
  }

  function toggleExpand() {
    const on = section.classList.toggle('af-fullscreen');
    document.body.classList.toggle('af-noscroll', on);
    const btn = document.getElementById('af-expand');
    btn.classList.toggle('is-on', on);
    btn.setAttribute('aria-pressed', String(on));
    btn.textContent = on ? 'Close' : 'Expand';
    requestAnimationFrame(draw);
  }

  Object.values(nodeEls).forEach(el => {
    el.setAttribute('aria-pressed', 'false');
    el.addEventListener('mouseenter', () => focus(el.dataset.id));
    el.addEventListener('mouseleave', unfocus);
    el.addEventListener('focus', () => focus(el.dataset.id));
    el.addEventListener('blur', unfocus);
    el.addEventListener('click', () => select(el.dataset.id));
  });

  detailBody.addEventListener('click', e => {
    const jump = e.target.closest('.af-jump');
    if (!jump) return;
    const el = nodeEls[jump.dataset.id];
    if (el.hidden) { state.gaps = true; syncChip('af-toggle-gaps', true); applyFilters(); }
    state.selected = null;
    select(jump.dataset.id);
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    el.focus({ preventScroll: true });
  });
  document.getElementById('af-detail-close').addEventListener('click', () => select(state.selected));

  function syncChip(id, on) {
    const b = document.getElementById(id);
    b.classList.toggle('is-on', on);
    b.setAttribute('aria-pressed', String(on));
  }

  section.querySelectorAll('.af-vendor-toggle').forEach(btn => btn.addEventListener('click', () => {
    const v = btn.dataset.vendor;
    if (state.vendors.has(v)) state.vendors.delete(v); else state.vendors.add(v);
    btn.classList.toggle('is-on', state.vendors.has(v));
    btn.setAttribute('aria-pressed', String(state.vendors.has(v)));
    applyFilters();
  }));
  document.getElementById('af-toggle-gaps').addEventListener('click', () => {
    state.gaps = !state.gaps; syncChip('af-toggle-gaps', state.gaps); applyFilters();
  });
  document.getElementById('af-toggle-edges').addEventListener('click', () => {
    state.edges = !state.edges; syncChip('af-toggle-edges', state.edges); draw();
    if (state.selected) focus(state.selected);
  });
  document.getElementById('af-search').addEventListener('input', e => {
    state.query = e.target.value.trim().toLowerCase();
    applyFilters();
    const first = section.querySelector('.af-node.is-match:not([hidden])');
    if (first) first.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  });
  document.getElementById('af-expand').addEventListener('click', toggleExpand);
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (state.selected) select(state.selected);
    else if (section.classList.contains('af-fullscreen')) toggleExpand();
  });

  let pending = null;
  const redraw = () => { cancelAnimationFrame(pending); pending = requestAnimationFrame(() => { draw(); if (state.selected) focus(state.selected); }); };
  window.addEventListener('resize', redraw);
  if ('ResizeObserver' in window) new ResizeObserver(redraw).observe(canvas);
  // Fonts and the collapsible sections above can shift layout after load
  window.addEventListener('load', redraw);
  applyFilters();
})();
