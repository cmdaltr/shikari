// Cyber Powers page (templates/cyber_powers.html). Three views of one map: Nations (IISS
// tier), Groups (attribution confidence of ATT&CK groups) and Targets (how many groups
// target the country). Hovering a country shows its motivation and groups; hovering a key
// item, or pressing it, fades the rest. The user's Profile country is green throughout.
(function () {
  const map = document.getElementById('cp-map');
  if (!map) return;
  const DATA = JSON.parse(document.getElementById('cp-data').textContent);
  const C = DATA.countries;
  const tip = document.getElementById('cp-tip');
  const shapes = [...map.querySelectorAll('.country')];
  shapes.forEach(s => s.querySelector('title')?.remove());  // our tooltip instead
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const flag = n => C[n] && C[n].flag ? `<img class="cp-flag" src="${esc(C[n].flag)}" alt="" width="20" height="15">` : '';
  const BUCKETS = [[11, '11+'], [7, '7–10'], [4, '4–6'], [2, '2–3'], [1, '1']];
  const bucket = n => BUCKETS.find(([min]) => n >= min);

  const VIEWS = {
    nations: {
      hint: 'States the IISS assesses as cyber powers, by tier',
      level: c => c.tier ? `tier-${c.tier}` : null,
      key: DATA.tiers.map(t => ({ level: t.key, label: t.label, summary: t.summary })),
    },
    groups: {
      hint: 'States ATT&CK attributes groups to; darker, the firmer the attribution',
      level: c => c.confidence ? `conf-${c.confidence.toLowerCase()}` : null,
      key: ['High', 'Moderate', 'Low'].map(l => ({ level: `conf-${l.toLowerCase()}`, label: `${l} confidence`,
        summary: { High: 'A government body or unit is named, or an indictment', Moderate: 'Stated plainly ("North Korea-based")',
          Low: 'Hedged ("suspected", "likely")' }[l] })),
    },
    targets: {
      hint: 'States ATT&CK groups are described as targeting; darker, the more groups',
      level: c => c.targeted ? `tgt-${BUCKETS.indexOf(bucket(c.targeted))}` : null,
      key: BUCKETS.map(([, label], i) => ({ level: `tgt-${i}`, label: `${label} group${label === '1' ? '' : 's'}` })),
    },
  };
  let view = 'nations', pinned = null;

  function paint() {
    const v = VIEWS[view];
    shapes.forEach(s => {
      const c = C[s.dataset.name] || {};
      const level = v.level(c);
      if (level) s.dataset.level = level; else delete s.dataset.level;
      s.classList.toggle('is-home', s.dataset.name === DATA.home);
    });
    document.getElementById('cp-hint').textContent = v.hint;
    const count = level => Object.values(C).filter(c => v.level(c) === level).length;
    document.getElementById('cp-key').innerHTML = v.key.map(k => `<li><button type="button" class="cp-key-item" data-level="${k.level}"
        aria-pressed="${pinned === k.level}"${k.summary ? ` title="${esc(k.summary)}"` : ''}>
        <span class="cp-swatch" data-level="${k.level}"></span><strong>${esc(k.label)}</strong><span class="cp-count">${count(k.level)}</span></button></li>`).join('')
      + (DATA.home ? `<li><span class="cp-key-item is-static"><span class="cp-swatch is-home"></span><strong>Your country</strong></span></li>` : '');
    document.querySelectorAll('#cp-key .cp-key-item[data-level]').forEach(b => {
      b.addEventListener('mouseenter', () => focus(b.dataset.level));
      b.addEventListener('mouseleave', () => focus(pinned));
      b.addEventListener('click', () => { pinned = pinned === b.dataset.level ? null : b.dataset.level; paint(); focus(pinned); });
    });
    lists();
  }

  function focus(level) {
    map.classList.toggle('has-focus', !!level);
    shapes.forEach(s => s.classList.toggle('is-focus', !!level && s.dataset.level === level));
  }

  function lists() {
    const v = VIEWS[view];
    const chips = names => `<ul class="cp-states">${names.map(([n, extra]) =>
      `<li data-map="${esc(n)}">${flag(n)}${esc(C[n].name)}${extra ? `<sup>${esc(extra)}</sup>` : ''}</li>`).join('')}</ul>`;
    const sorted = level => Object.keys(C).filter(n => v.level(C[n]) === level);
    let cards;
    if (view === 'targets') {
      const top = Object.keys(C).filter(n => C[n].targeted).sort((a, b) => C[b].targeted - C[a].targeted).slice(0, 24);
      cards = [`<div class="cp-group is-wide"><h2>Most targeted</h2><p class="cp-summary">By the number of ATT&CK groups described as targeting them</p>
        ${chips(top.map(n => [n, C[n].targeted]))}</div>`];
    } else {
      cards = v.key.map(k => `<div class="cp-group"><h2><span class="cp-swatch" data-level="${k.level}"></span>${esc(k.label)}</h2>
        <p class="cp-summary">${esc(k.summary || '')}</p>${chips(sorted(k.level).sort((a, b) => C[a].name.localeCompare(C[b].name))
          .map(n => [n, view === 'nations' ? (C[n].volume === 2 ? '2' : '') : C[n].group_count]))}</div>`);
    }
    const box = document.getElementById('cp-lists');
    box.innerHTML = cards.join('');
    box.querySelectorAll('[data-map]').forEach(li => {
      li.addEventListener('mouseenter', e => { highlight(li.dataset.map); show(li.dataset.map, e); });
      li.addEventListener('mouseleave', () => { highlight(null); focus(pinned); hide(); });
    });
  }

  function highlight(name) {
    if (!name) return;
    map.classList.add('has-focus');
    shapes.forEach(s => s.classList.toggle('is-focus', s.dataset.name === name));
  }

  const motives = m => m && m.length ? m.map(x => `${esc(x.motive)} ${x.share}%`).join(' · ') : '';
  function content(name) {
    const c = C[name];
    if (!c) return '';
    const rows = [];
    const row = (label, value) => value && rows.push(`<dt>${label}</dt><dd>${value}</dd>`);
    if (view === 'targets') {
      row('Targeted by', c.targeted ? `${c.targeted} ATT&CK group${c.targeted === 1 ? '' : 's'}` : 'No ATT&CK group described as targeting it');
      row('Mostly from', esc((c.attackers || []).join(', ')));
      row('Their motivation', motives(c.target_motivation));
      row('Groups', esc((c.targeted_by || []).join(', ')) + (c.targeted > (c.targeted_by || []).length ? ' …' : ''));
    } else {
      if (view === 'nations') row('IISS', c.tier ? `${esc(c.tier_label)}${c.volume === 2 ? ' (volume 2)' : ''}` : 'Not assessed');
      if (c.group_count) {
        const a = c.attributed || {};
        row('Attribution', `${esc(c.confidence)} · ${['High', 'Moderate', 'Low'].filter(l => a[l]).map(l => `${a[l]} ${l.toLowerCase()}`).join(', ')}`);
        row('Primary motivation', motives(c.motivation));
        row('Groups', esc(c.groups.join(', ')) + (c.group_count > c.groups.length ? ` … (${c.group_count})` : ''));
      } else {
        row('Groups', 'No ATT&CK groups attributed');
      }
    }
    return `<strong class="cp-tip-name">${flag(name)}${esc(c.name)}${name === DATA.home ? ' <span class="cp-tip-home">Your country</span>' : ''}</strong><dl>${rows.join('')}</dl>`;
  }

  function show(name, e) {
    const html = content(name);
    if (!html) return hide();
    tip.innerHTML = html;
    tip.hidden = false;
    move(e);
  }
  function move(e) {
    // Clear of the pointer: further right and down than the arrow itself. The page is zoomed
    // (common.css), so the pointer's viewport position is scaled into the page's own pixels
    const z = parseFloat(getComputedStyle(document.documentElement).zoom) || 1;
    const dx = 22, dy = 26, w = tip.offsetWidth * z, h = tip.offsetHeight * z;
    let x = e.clientX + dx, y = e.clientY + dy;
    if (x + w > window.innerWidth - 8) x = e.clientX - w - 12;
    if (y + h > window.innerHeight - 8) y = e.clientY - h - 12;
    tip.style.left = `${Math.max(8, x) / z}px`;
    tip.style.top = `${Math.max(8, y) / z}px`;
  }
  const hide = () => { tip.hidden = true; };

  shapes.forEach(s => {
    s.addEventListener('mouseenter', e => show(s.dataset.name, e));
    s.addEventListener('mousemove', move);
    s.addEventListener('mouseleave', hide);
  });

  document.querySelectorAll('.cp-view').forEach(b => b.addEventListener('click', () => {
    view = b.dataset.view;
    pinned = null;
    document.querySelectorAll('.cp-view').forEach(x => {
      x.classList.toggle('is-active', x === b);
      x.setAttribute('aria-checked', String(x === b));
    });
    paint();
    focus(null);
  }));

  paint();
})();
