// Results page: IOC flow (templates/partials/ioc_flow.html, shikari/build/ioc_flow.py)
(function () {
  const root = document.getElementById('ioc-flow');
  const dataEl = document.getElementById('if-data');
  if (!root || !dataEl) return;
  const flow = JSON.parse(dataEl.textContent);
  const svg = document.getElementById('if-edges');
  const canvas = document.getElementById('if-canvas');
  const detail = document.getElementById('if-detail');
  const detailBody = document.getElementById('if-detail-body');
  const byId = {};
  flow.stages.forEach(s => s.nodes.forEach(n => { byId[n.id] = { ...n, stageLabel: s.label }; }));
  const nodeEl = id => root.querySelector(`.if-node[data-id="${id}"]`);
  let selected = null;

  // A linked indicator is never folded away behind "+N more"
  flow.edges.forEach(e => [e.from, e.to].forEach(id => {
    const el = nodeEl(id);
    if (el) { el.hidden = false; el.removeAttribute('data-more'); }
  }));
  function syncMore() {
    root.querySelectorAll('.if-more').forEach(btn => {
      const n = root.querySelectorAll(`.if-stage[data-stage="${btn.dataset.stage}"] .if-node[hidden]`).length;
      btn.hidden = !n;
      btn.textContent = `+${n} more`;
    });
  }

  function draw() {
    svg.querySelectorAll('path').forEach(p => p.remove());
    const box = canvas.getBoundingClientRect();
    svg.setAttribute('width', canvas.scrollWidth);
    svg.setAttribute('height', canvas.scrollHeight);
    const vertical = getComputedStyle(root.querySelector('.if-stages')).flexDirection === 'column';
    flow.edges.forEach(e => {
      const a = nodeEl(e.from), b = nodeEl(e.to);
      if (!a || !b || a.hidden || b.hidden) return;
      const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
      const ox = canvas.scrollLeft - box.left, oy = canvas.scrollTop - box.top;
      let d;
      if (vertical) {
        const x1 = ra.left + ra.width / 2 + ox, y1 = ra.bottom + oy, x2 = rb.left + rb.width / 2 + ox, y2 = rb.top + oy;
        d = `M${x1},${y1} C${x1},${(y1 + y2) / 2} ${x2},${(y1 + y2) / 2} ${x2},${y2}`;
      } else {
        const x1 = ra.right + ox, y1 = ra.top + ra.height / 2 + oy, x2 = rb.left + ox, y2 = rb.top + rb.height / 2 + oy;
        const mid = (x1 + x2) / 2;
        d = `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
      }
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      path.setAttribute('marker-end', 'url(#if-arrow)');
      path.dataset.from = e.from;
      path.dataset.to = e.to;
      svg.appendChild(path);
    });
    highlight();
  }

  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function marked(sentence, value) {
    const i = sentence.toLowerCase().indexOf(value.toLowerCase());
    if (i < 0) return esc(sentence);
    return esc(sentence.slice(0, i)) + '<mark>' + esc(sentence.slice(i, i + value.length)) + '</mark>' + esc(sentence.slice(i + value.length));
  }
  function linkList(ids) {
    return '<ul class="if-detail-links">' + ids.map(id =>
      `<li><button type="button" data-goto="${id}">${esc(byId[id].value)}</button> <span style="color:var(--af-muted)">(${esc(byId[id].stageLabel)})</span></li>`).join('') + '</ul>';
  }

  function highlight() {
    const lit = new Set();
    svg.querySelectorAll('path').forEach(p => {
      const on = selected && (p.dataset.from === selected || p.dataset.to === selected);
      p.classList.toggle('is-lit', !!on);
      if (on) { lit.add(p.dataset.from); lit.add(p.dataset.to); }
    });
    svg.classList.toggle('is-dim', !!selected);
    root.classList.toggle('has-selection', !!selected);
    root.querySelectorAll('.if-node').forEach(el => {
      el.classList.toggle('is-selected', el.dataset.id === selected);
      el.classList.toggle('is-lit', el.dataset.id !== selected && lit.has(el.dataset.id));
    });
  }

  function select(id) {
    selected = id === selected ? null : id;
    highlight();
    if (!selected) { detail.hidden = true; return; }
    const n = byId[selected];
    const from = flow.edges.filter(e => e.to === n.id).map(e => e.from);
    const to = flow.edges.filter(e => e.from === n.id).map(e => e.to);
    detailBody.innerHTML =
      `<p class="if-detail-value">${esc(n.value)}</p>` +
      `<p>${esc(n.kind.toUpperCase())} · ${esc(n.stageLabel)}</p>` +
      (n.evidence.length
        ? '<h4>What the report says</h4>' + n.evidence.map(s => `<blockquote class="if-evidence">${marked(s, n.value)}</blockquote>`).join('')
        : '<p style="color:var(--af-muted)">The report lists this indicator without context; it is placed by type.</p>') +
      (from.length ? '<h4>Comes after</h4>' + linkList(from) : '') +
      (to.length ? '<h4>Leads to</h4>' + linkList(to) : '');
    detail.hidden = false;
  }

  root.addEventListener('click', ev => {
    const node = ev.target.closest('.if-node');
    if (node) return select(node.dataset.id);
    const go = ev.target.closest('[data-goto]');
    if (go) {
      const el = nodeEl(go.dataset.goto);
      el.hidden = false;
      syncMore();
      draw();
      el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      return select(go.dataset.goto);
    }
    const more = ev.target.closest('.if-more');
    if (more) {
      root.querySelectorAll(`.if-stage[data-stage="${more.dataset.stage}"] .if-node[hidden]`).forEach(el => { el.hidden = false; });
      syncMore();
      draw();
    }
  });
  document.getElementById('if-detail-close').addEventListener('click', () => select(selected));
  document.getElementById('if-expand-all').addEventListener('click', () => {
    root.querySelectorAll('.if-node[hidden]').forEach(el => { el.hidden = false; });
    syncMore();
    draw();
  });
  const edgesBtn = document.getElementById('if-toggle-edges');
  edgesBtn.addEventListener('click', () => {
    const on = !edgesBtn.classList.contains('is-on');
    edgesBtn.classList.toggle('is-on', on);
    edgesBtn.setAttribute('aria-pressed', on);
    root.classList.toggle('no-edges', !on);
  });

  syncMore();
  draw();
  window.addEventListener('resize', draw);
  canvas.addEventListener('scroll', draw);
  // Sections above can expand or collapse and move the canvas
  if ('ResizeObserver' in window) new ResizeObserver(draw).observe(canvas);
})();
