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
  const $ = id => document.getElementById(id);

  const VENDOR_NAMES = { googlesecops: 'Google SecOps', mde: 'MDE', splunk: 'Splunk', elastic: 'Elastic' };
  const EDGE_COLOURS = { googlesecops: '#4285F4', mde: '#00A2AD', splunk: '#E91E8C', elastic: '#F0A500', mixed: '#64748B' };
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const nodes = {};
  const laneOf = {};
  flow.lanes.forEach((l, i) => l.nodes.forEach(n => { nodes[n.id] = n; laneOf[n.id] = i; }));
  const nodeEls = {};
  section.querySelectorAll('.af-node').forEach(el => { nodeEls[el.dataset.id] = el; });
  const edgeKey = e => `${e.from}>${e.to}`;

  const DEFAULTS = {
    vendors: flow.vendors.map(v => v.key),
    gaps: true,
    edges: true,
    removed: [],   // techniques the user has hidden
    unlinked: [],  // edge keys the user has removed
    offsets: {},   // id -> [dx, dy] from dragging
    vertical: false,
    reversed: false,
  };
  const state = {
    selected: null,
    query: '',
    picked: new Set(),  // multi-selection for Hide Selected / Hide Others and group drags
    picking: false,
  };
  const history = [];
  let layout = {};
  try { layout = JSON.parse(($('af-layout') || {}).textContent || '{}') || {}; } catch (e) { layout = {}; }
  let persist = !!layout.persist;

  // Everything Undo and Reset restore; filters ride along so Undo can reverse a Reset
  function snapshot() {
    return {
      vendors: [...state.vendors], gaps: state.gaps, edges: state.edges,
      removed: [...state.removed], unlinked: [...state.unlinked],
      offsets: JSON.parse(JSON.stringify(state.offsets)),
      vertical: state.vertical, reversed: state.reversed,
    };
  }

  function restore(s) {
    state.vendors = new Set(s.vendors);
    state.gaps = s.gaps;
    state.edges = s.edges;
    state.removed = new Set(s.removed);
    state.unlinked = new Set(s.unlinked);
    state.offsets = JSON.parse(JSON.stringify(s.offsets));
    state.vertical = s.vertical;
    state.reversed = s.reversed;
  }

  function record() {
    history.push(snapshot());
    if (history.length > 100) history.shift();
    $('af-undo').disabled = false;
    scheduleSave();
  }

  function undo() {
    if (!history.length) return;
    restore(history.pop());
    $('af-undo').disabled = !history.length;
    render();
    scheduleSave();
  }

  // Saved per user and group once the group's results are in the library;
  // otherwise edits last until the page is left
  let saveTimer = null;
  function status(text, kind) {
    const el = $('af-save-status');
    el.hidden = !text;
    el.textContent = text || '';
    el.dataset.kind = kind || '';
  }

  function scheduleSave() {
    if (!persist) {
      status(layout.logged_in ? 'Edits not kept: save the results to your library to keep them'
                              : 'Edits not kept: log in and save to your library to keep them', 'muted');
      return;
    }
    clearTimeout(saveTimer);
    status('Saving…', 'muted');
    // Runs after the change that called it, so it captures the new state
    saveTimer = setTimeout(saveNow, 600);
  }

  async function saveNow() {
    if (drag && drag.moved) { saveTimer = setTimeout(saveNow, 600); return; }
    try {
      const r = await fetch('/api/flow-layout', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_name: layout.group_name, state: snapshot() }),
      });
      if (r.ok) status('Edits saved to your library', 'ok');
      else if (r.status === 409) { persist = false; status('Edits not kept: save the results to your library to keep them', 'muted'); }
      else status(`Couldn't save edits (HTTP ${r.status})`, 'error');
    } catch (e) {
      status("Couldn't save edits: network error", 'error');
    }
  }

  document.addEventListener('archer:library-saved', () => {
    if (!layout.logged_in) return;
    persist = true;
    clearTimeout(saveTimer);
    saveNow();
  });

  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const logo = v => `<svg class="af-logo" aria-hidden="true"><use href="#af-logo-${v}"/></svg>`;

  // An edge is shown when one of its correlation vendors is selected
  const edgeVendors = e => e.vendors.filter(v => state.vendors.has(v));
  const liveEdges = () => flow.edges.filter(e => !state.unlinked.has(edgeKey(e)));
  const visibleEdges = () => (state.edges ? liveEdges().filter(e =>
    edgeVendors(e).length && !nodeEls[e.from].hidden && !nodeEls[e.to].hidden) : []);

  function nodeDetected(n) {
    return Object.keys(n.vendors).some(v => state.vendors.has(v));
  }

  function syncChip(id, on) {
    const b = $(id);
    b.classList.toggle('is-on', on);
    b.setAttribute('aria-pressed', String(on));
  }

  // Full redraw after Undo/Reset/layout changes: controls, layout, positions, filters
  function render() {
    section.querySelectorAll('.af-vendor-toggle').forEach(btn => {
      const on = state.vendors.has(btn.dataset.vendor);
      btn.classList.toggle('is-on', on);
      btn.setAttribute('aria-pressed', String(on));
    });
    syncChip('af-toggle-gaps', !state.gaps);
    syncChip('af-toggle-edges', state.edges);
    section.classList.toggle('af-vertical', state.vertical);
    section.classList.toggle('af-reversed', state.reversed);
    $('af-orient').textContent = state.vertical ? 'Vertical' : 'Horizontal';
    $('af-order').textContent = state.reversed ? 'Reverse' : 'Forward';
    Object.entries(nodeEls).forEach(([id, el]) => {
      const o = state.offsets[id];
      el.style.transform = o ? `translate(${o[0]}px, ${o[1]}px)` : '';
      el.classList.toggle('is-moved', !!o);
    });
    $('af-stat-edges').textContent = liveEdges().length;
    syncPicks();
    applyFilters();
    if (state.selected) showDetail(state.selected);
  }

  function applyFilters() {
    const q = state.query;
    Object.values(nodes).forEach(n => {
      const el = nodeEls[n.id];
      const detected = nodeDetected(n);
      el.classList.toggle('is-gap', !detected);
      el.hidden = (!detected && !state.gaps) || state.removed.has(n.id);
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
    if (state.selected && nodeEls[state.selected].hidden) select(state.selected);
    else if (state.selected) focus(state.selected);
  }

  function syncPicks() {
    Object.entries(nodeEls).forEach(([id, el]) => el.classList.toggle('is-picked', state.picked.has(id)));
    const n = state.picked.size;
    $('af-hide-picked').disabled = $('af-hide-others').disabled = n === 0;
    $('af-hide-picked').textContent = n ? `Hide Selected (${n})` : 'Hide Selected';
    $('af-show-all').hidden = state.removed.size === 0;
    $('af-show-all').textContent = `Show All (${state.removed.size} hidden)`;
  }

  function togglePick(id) {
    if (state.picked.has(id)) state.picked.delete(id); else state.picked.add(id);
    syncPicks();
  }

  function hide(ids) {
    record();
    ids.forEach(id => state.removed.add(id));
    state.picked.clear();
    syncPicks();
    applyFilters();
  }

  // Links follow the layout's flow direction: tactic to tactic across the main axis,
  // and around the cards when both ends share a lane. Dashed when the second
  // technique's tactic comes earlier in the kill chain, wherever it has been dragged.
  function path(a, b) {
    const box = canvas.getBoundingClientRect();
    const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
    const ox = canvas.scrollLeft - box.left, oy = canvas.scrollTop - box.top;
    const ya = ra.top + ra.height / 2 + oy, yb = rb.top + rb.height / 2 + oy;
    const xa = ra.left + ra.width / 2 + ox, xb = rb.left + rb.width / 2 + ox;
    const across = (x1, x2) => {
      const dx = Math.sign(x2 - x1) * Math.max(30, Math.abs(x2 - x1) / 2);
      return `M${x1},${ya} C${x1 + dx},${ya} ${x2 - dx},${yb} ${x2},${yb}`;
    };
    const down = (y1, y2) => {
      const dy = Math.sign(y2 - y1) * Math.max(24, Math.abs(y2 - y1) / 2);
      return `M${xa},${y1} C${xa},${y1 + dy} ${xb},${y2 - dy} ${xb},${y2}`;
    };
    if (state.vertical) {
      if (rb.top >= ra.bottom - 1) return down(ra.bottom + oy, rb.top + oy);
      if (rb.bottom <= ra.top + 1) return down(ra.top + oy, rb.bottom + oy);
      const y = Math.max(ra.bottom, rb.bottom) + oy, bulge = 14 + Math.min(40, Math.abs(xb - xa) / 6);
      return `M${xa},${ra.bottom + oy} C${xa},${y + bulge} ${xb},${y + bulge} ${xb},${rb.bottom + oy}`;
    }
    if (rb.left >= ra.right - 1) return across(ra.right + ox, rb.left + ox);
    if (rb.right <= ra.left + 1) return across(ra.left + ox, rb.right + ox);
    const x = Math.max(ra.right, rb.right) + ox, bulge = 14 + Math.min(40, Math.abs(yb - ya) / 6);
    return `M${ra.right + ox},${ya} C${x + bulge},${ya} ${x + bulge},${yb} ${rb.right + ox},${yb}`;
  }

  function draw() {
    svg.querySelectorAll('path.af-edge, path.af-edge-hit').forEach(p => p.remove());
    const lanes = canvas.querySelector('.af-lanes');
    svg.setAttribute('width', lanes.scrollWidth);
    svg.setAttribute('height', lanes.scrollHeight);
    visibleEdges().forEach(e => {
      const vs = edgeVendors(e);
      const key = vs.length === 1 ? vs[0] : 'mixed';
      const d = path(nodeEls[e.from], nodeEls[e.to]);
      const back = laneOf[e.to] < laneOf[e.from];
      const p = document.createElementNS(SVG_NS, 'path');
      p.setAttribute('d', d);
      p.setAttribute('class', back ? 'af-edge is-back' : 'af-edge');
      p.setAttribute('stroke', EDGE_COLOURS[key]);
      p.setAttribute('marker-end', `url(#af-arrow-${key})`);
      p.dataset.from = e.from;
      p.dataset.to = e.to;
      // Wide invisible twin so a 1.6px line is easy to hit
      const hit = document.createElementNS(SVG_NS, 'path');
      hit.setAttribute('d', d);
      hit.setAttribute('class', 'af-edge-hit');
      hit.dataset.key = edgeKey(e);
      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = `${e.from} → ${e.to}: click to remove this link`;
      hit.appendChild(title);
      svg.append(p, hit);
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

  function unlink(key) {
    record();
    state.unlinked.add(key);
    $('af-stat-edges').textContent = liveEdges().length;
    applyFilters();
    if (state.selected) showDetail(state.selected);
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
    const edges = liveEdges();
    const out = edges.filter(e => e.from === id), inc = edges.filter(e => e.to === id);
    const linkList = (list, key, label) => list.length ? `
      <h4>${label}</h4>
      <ul class="af-detail-links">${list.map(e => {
        const o = nodes[e[key]];
        return `<li><button type="button" class="af-jump" data-id="${esc(o.id)}">${e.vendors.map(logo).join('')}<span><b>${esc(o.id)}</b> ${esc(o.name)}</span></button>` +
          `<button type="button" class="af-unlink" data-key="${esc(edgeKey(e))}" title="Remove this link" aria-label="Remove link ${esc(e.from)} to ${esc(e.to)}">×</button></li>`;
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
    const btn = $('af-expand');
    btn.classList.toggle('is-on', on);
    btn.setAttribute('aria-pressed', String(on));
    btn.textContent = on ? 'Close' : 'Expand';
    requestAnimationFrame(draw);
  }

  // Dragging: a picked card carries the whole selection with it
  let drag = null;
  let swallowClick = false;
  let pending = null;
  const redraw = () => {
    cancelAnimationFrame(pending);
    pending = requestAnimationFrame(() => { draw(); if (state.selected) focus(state.selected); });
  };

  Object.values(nodeEls).forEach(el => {
    el.setAttribute('aria-pressed', 'false');
    el.addEventListener('mouseenter', () => { if (!drag) focus(el.dataset.id); });
    el.addEventListener('mouseleave', () => { if (!drag) unfocus(); });
    el.addEventListener('focus', () => focus(el.dataset.id));
    el.addEventListener('blur', unfocus);
    el.addEventListener('click', e => {
      if (swallowClick) { swallowClick = false; return; }
      if (state.picking || e.metaKey || e.ctrlKey || e.shiftKey) togglePick(el.dataset.id);
      else select(el.dataset.id);
    });
    el.addEventListener('pointerdown', e => {
      if (e.button !== 0) return;
      const id = el.dataset.id;
      const ids = state.picked.has(id) ? [...state.picked] : [id];
      drag = { x: e.clientX, y: e.clientY, moved: false, ids,
               start: Object.fromEntries(ids.map(i => [i, state.offsets[i] || [0, 0]])) };
      el.setPointerCapture(e.pointerId);
    });
    el.addEventListener('pointermove', e => {
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!drag.moved) {
        if (Math.hypot(dx, dy) < 4) return;
        drag.moved = true;
        record();
        section.classList.add('af-dragging');
      }
      drag.ids.forEach(i => {
        const [sx, sy] = drag.start[i];
        state.offsets[i] = [sx + dx, sy + dy];
        nodeEls[i].style.transform = `translate(${sx + dx}px, ${sy + dy}px)`;
        nodeEls[i].classList.add('is-moved');
      });
      redraw();
    });
    const endDrag = () => {
      if (!drag) return;
      if (drag.moved) { swallowClick = true; drag.moved = false; scheduleSave(); }
      drag = null;
      section.classList.remove('af-dragging');
    };
    el.addEventListener('pointerup', endDrag);
    el.addEventListener('pointercancel', endDrag);
  });

  svg.addEventListener('click', e => {
    const hit = e.target.closest('.af-edge-hit');
    if (hit) unlink(hit.dataset.key);
  });
  svg.addEventListener('mouseover', e => {
    const hit = e.target.closest('.af-edge-hit');
    if (!hit) return;
    const [from, to] = hit.dataset.key.split('>');
    const line = svg.querySelector(`path.af-edge[data-from="${from}"][data-to="${to}"]`);
    if (line) line.classList.add('is-hover');
  });
  svg.addEventListener('mouseout', e => {
    if (e.target.closest('.af-edge-hit')) svg.querySelectorAll('path.af-edge.is-hover').forEach(p => p.classList.remove('is-hover'));
  });

  detailBody.addEventListener('click', e => {
    const cut = e.target.closest('.af-unlink');
    if (cut) return unlink(cut.dataset.key);
    const jump = e.target.closest('.af-jump');
    if (!jump) return;
    const el = nodeEls[jump.dataset.id];
    if (el.hidden) {
      state.removed.delete(jump.dataset.id);
      if (!nodeDetected(nodes[jump.dataset.id])) { state.gaps = true; syncChip('af-toggle-gaps', false); }
      syncPicks();
      applyFilters();
    }
    state.selected = null;
    select(jump.dataset.id);
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    el.focus({ preventScroll: true });
  });
  $('af-detail-close').addEventListener('click', () => select(state.selected));

  section.querySelectorAll('.af-vendor-toggle').forEach(btn => btn.addEventListener('click', () => {
    const v = btn.dataset.vendor;
    record();
    if (state.vendors.has(v)) state.vendors.delete(v); else state.vendors.add(v);
    btn.classList.toggle('is-on', state.vendors.has(v));
    btn.setAttribute('aria-pressed', String(state.vendors.has(v)));
    applyFilters();
  }));
  $('af-toggle-gaps').addEventListener('click', () => {
    record(); state.gaps = !state.gaps; syncChip('af-toggle-gaps', !state.gaps); applyFilters();
  });
  $('af-toggle-edges').addEventListener('click', () => {
    record(); state.edges = !state.edges; syncChip('af-toggle-edges', state.edges); draw();
    if (state.selected) focus(state.selected);
  });
  $('af-search').addEventListener('input', e => {
    state.query = e.target.value.trim().toLowerCase();
    applyFilters();
    const first = section.querySelector('.af-node.is-match:not([hidden])');
    if (first) first.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  });
  $('af-expand').addEventListener('click', toggleExpand);
  $('af-pick-mode').addEventListener('click', () => {
    state.picking = !state.picking;
    syncChip('af-pick-mode', state.picking);
    section.classList.toggle('af-picking', state.picking);
  });
  $('af-hide-picked').addEventListener('click', () => hide([...state.picked]));
  $('af-hide-others').addEventListener('click', () =>
    hide(Object.keys(nodes).filter(id => !state.picked.has(id))));
  $('af-show-all').addEventListener('click', () => {
    record();
    state.removed.clear();
    syncPicks();
    applyFilters();
  });
  // Dragged positions belong to the old layout, so a layout change drops them (Undo brings them back)
  $('af-orient').addEventListener('click', () => {
    record(); state.vertical = !state.vertical; state.offsets = {}; render();
  });
  $('af-order').addEventListener('click', () => {
    record(); state.reversed = !state.reversed; state.offsets = {}; render();
  });
  // Export what's shown: the server applies the edits to the flow and builds the bundle
  const stix = $('af-stix');
  if (stix) stix.addEventListener('click', async e => {
    const edited = state.vendors.size !== DEFAULTS.vendors.length || !state.gaps
      || state.removed.size || state.unlinked.size;
    if (!edited) return;  // the unedited flow: the file written with the results
    e.preventDefault();
    try {
      const r = await fetch('/api/attack-flow/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_name: stix.dataset.group, state: snapshot() }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement('a');
      a.href = url;
      a.download = `${stix.dataset.group}_edited_flow.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      status(`Couldn't export the edited flow (${err.message})`, 'error');
    }
  });
  $('af-undo').addEventListener('click', undo);
  $('af-reset').addEventListener('click', () => {
    record();
    restore(DEFAULTS);
    state.picked.clear();
    state.query = '';
    $('af-search').value = '';
    render();
  });
  document.addEventListener('keydown', e => {
    const typing = e.target.closest && e.target.closest('input, textarea, [contenteditable]');
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'z' && !e.shiftKey && !typing && history.length
        && (section.contains(e.target) || e.target === document.body)) {
      e.preventDefault();
      undo();
      return;
    }
    if (e.key !== 'Escape') return;
    if (state.picked.size) { state.picked.clear(); syncPicks(); }
    else if (state.selected) select(state.selected);
    else if (section.classList.contains('af-fullscreen')) toggleExpand();
  });

  window.addEventListener('resize', redraw);
  if ('ResizeObserver' in window) new ResizeObserver(redraw).observe(canvas);
  // Fonts and the collapsible sections above can shift layout after load
  window.addEventListener('load', redraw);
  restore(layout.state ? Object.assign({}, DEFAULTS, layout.state) : DEFAULTS);
  render();
  if (persist && layout.state) status('Edits saved to your library', 'ok');
})();
