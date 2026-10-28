/*
 * The guide, tips and tricks, and the dialog offering both when Archer starts.
 *
 * Start-up means the first page of a browser session: each launch of the desktop app, or a new
 * browser window on a server. Whether each part shows then, and which tips were shown last, are
 * kept in this browser only (localStorage), so there's nothing to migrate and nothing to share.
 *
 * The guide's pictures and section positions come from scripts/guide/capture.py, which writes
 * static/guide/guide.json; its words live in scripts/guide/pages.yaml.
 */
(function () {
  if (window.ArcherGuide) return;

  const KEY_GUIDE = 'archer.guide.atStartup';
  const KEY_TIPS = 'archer.tips.atStartup';
  const KEY_RECENT = 'archer.tips.recent';
  const KEY_SESSION = 'archer.started';
  const RECENT = 10;
  const NO_STARTUP = ['/login', '/register', '/forgot-password', '/reset-password', '/clear-browser-cache'];

  const store = {
    get(k, fallback) { try { const v = localStorage.getItem(k); return v === null ? fallback : JSON.parse(v); } catch (e) { return fallback; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private window */ } },
  };
  const once = {
    seen() { try { return sessionStorage.getItem(KEY_SESSION) === '1'; } catch (e) { return true; } },
    mark() { try { sessionStorage.setItem(KEY_SESSION, '1'); } catch (e) { /* ignore */ } },
  };

  let guideData = null, tipsData = null;
  const load = (url) => fetch(url, { cache: 'no-cache' }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
  const guide = () => guideData ? Promise.resolve(guideData) : load('/static/guide/guide.json').then(d => (guideData = d));
  const tips = () => tipsData ? Promise.resolve(tipsData) : load('/static/guide/tips.json').then(d => (tipsData = d));

  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid != null) n.append(kid.nodeType ? kid : document.createTextNode(kid));
    return n;
  };

  // ---- Tips: random, but never one of the last ten shown ----

  function nextTip(list) {
    const recent = store.get(KEY_RECENT, []).filter(id => list.some(t => t.id === id));
    const avoid = new Set(recent.slice(-Math.min(RECENT, list.length - 1)));
    const pool = list.filter(t => !avoid.has(t.id));
    const tip = pool[Math.floor(Math.random() * pool.length)];
    store.set(KEY_RECENT, [...recent.filter(id => id !== tip.id), tip.id].slice(-RECENT));
    return tip;
  }

  function tipCard(list) {
    const body = el('div', { class: 'gd-tip-body' });
    const show = () => {
      const t = nextTip(list);
      body.replaceChildren(
        el('h3', {}, t.title),
        el('p', {}, t.text),
        t.href ? el('a', { class: 'gd-tip-where', href: t.href }, t.where || 'Open') : null,
      );
    };
    show();
    return { body, show };
  }

  // ---- Dialog shell ----

  let open = null;
  function dialog(cls, label, content, onClose) {
    close();
    const box = el('div', { class: `gd-dialog ${cls}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': label }, content);
    const shade = el('div', { class: 'gd-shade', onclick: e => { if (e.target === shade) close(); } }, box);
    const keys = e => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', keys);
    document.body.append(shade);
    document.documentElement.classList.add('gd-locked');
    open = { shade, keys, onClose };
    const first = box.querySelector('button, a, input');
    if (first) first.focus();
    return box;
  }
  function close() {
    if (!open) return;
    document.removeEventListener('keydown', open.keys);
    open.shade.remove();
    document.documentElement.classList.remove('gd-locked');
    const cb = open.onClose;
    open = null;
    if (cb) cb();
  }

  const tick = (key, label) => {
    const box = el('input', { type: 'checkbox', checked: store.get(key, true) });
    box.addEventListener('change', () => store.set(key, box.checked));
    return el('label', { class: 'gd-tick' }, box, ' ', label);
  };
  const closeBtn = () => el('button', { type: 'button', class: 'gd-x', 'aria-label': 'Close', onclick: close }, '×');

  // ---- Start-up dialog ----

  function startup(force) {
    const showGuide = force || store.get(KEY_GUIDE, true);
    const showTips = force || store.get(KEY_TIPS, true);
    if (!showGuide && !showTips) return Promise.resolve();
    return tips().catch(() => []).then(list => {
      const parts = [];
      if (showGuide) parts.push(el('div', { class: 'gd-start-guide' },
        el('h2', {}, 'New to Archer, or to a page?'),
        el('p', {}, 'A picture of every page, each part highlighted in turn: what it’s for, who uses it, and when it helps most.'),
        el('button', { type: 'button', class: 'gd-btn', onclick: () => showGuideViewer() }, 'Take the guide'),
        tick(KEY_GUIDE, 'Show the guide at startup'),
      ));
      if (showTips && list.length) {
        const card = tipCard(list);
        parts.push(el('div', { class: 'gd-start-tip' },
          el('div', { class: 'gd-tip-label' }, 'Tip'),
          card.body,
          el('div', { class: 'gd-tip-foot' },
            el('button', { type: 'button', class: 'gd-btn gd-btn-quiet', onclick: card.show }, 'Another tip'),
            tick(KEY_TIPS, 'Show tips at startup'),
          ),
        ));
      }
      if (!parts.length) return;
      dialog('gd-start', 'Getting started', [closeBtn(), el('div', { class: 'gd-start-grid' }, parts)]);
    });
  }

  function showTips() {
    tips().then(list => {
      const card = tipCard(list);
      dialog('gd-tips', 'Tips and tricks', [
        closeBtn(),
        el('div', { class: 'gd-tip-label' }, 'Tips and tricks'),
        card.body,
        el('div', { class: 'gd-tip-foot' },
          el('button', { type: 'button', class: 'gd-btn', onclick: card.show }, 'Another tip'),
          tick(KEY_TIPS, 'Show tips at startup'),
        ),
      ]);
    });
  }

  // ---- The guide ----

  function showGuideViewer(pageId) {
    guide().then(data => {
      const pages = data.pages;
      let p = Math.max(0, pages.findIndex(x => x.id === pageId || x.path === location.pathname));
      let s = 0, timer = null;

      const nav = el('nav', { class: 'gd-pages', 'aria-label': 'Guide pages' });
      const menus = [...new Set(pages.map(x => x.menu))];
      for (const m of menus) {
        nav.append(el('div', { class: 'gd-menu' }, m));
        pages.forEach((pg, i) => { if (pg.menu === m) nav.append(el('button', { type: 'button', class: 'gd-page', 'data-i': i, onclick: () => go(i, 0) }, pg.title)); });
      }

      const shot = el('div', { class: 'gd-shot' });
      const frame = el('div', { class: 'gd-frame' }, shot);
      const head = el('header', { class: 'gd-head' });
      const caption = el('div', { class: 'gd-caption', 'aria-live': 'polite' });
      const prev = el('button', { type: 'button', class: 'gd-btn gd-btn-quiet', onclick: () => step(-1) }, '← Back');
      const next = el('button', { type: 'button', class: 'gd-btn', onclick: () => step(1) }, 'Next →');
      const play = el('button', { type: 'button', class: 'gd-btn gd-btn-quiet', 'aria-pressed': 'false', onclick: () => autoplay(!timer) }, 'Play');
      const foot = el('footer', { class: 'gd-foot' }, tick(KEY_GUIDE, 'Show the guide at startup'), el('span', { class: 'gd-grow' }), play, prev, next);

      const box = dialog('gd-guide', 'Guide', [
        closeBtn(),
        nav,
        el('div', { class: 'gd-main' }, head, el('div', { class: 'gd-body' }, frame, caption), foot),
      ], () => autoplay(false));

      function autoplay(on) {
        clearInterval(timer); timer = null;
        play.textContent = on ? 'Pause' : 'Play';
        play.setAttribute('aria-pressed', on ? 'true' : 'false');
        if (on) timer = setInterval(() => step(1, true), 8000);
      }

      function step(d, auto) {
        const pg = pages[p];
        if (s + d >= 0 && s + d < pg.sections.length) return go(p, s + d);
        if (d > 0 && p < pages.length - 1) return go(p + 1, 0);
        if (d < 0 && p > 0) return go(p - 1, pages[p - 1].sections.length - 1);
        if (auto) autoplay(false);
      }

      function go(i, j) {
        const changed = i !== p || !shot.firstChild;
        p = i; s = j;
        const pg = pages[p], sec = pg.sections[s];
        nav.querySelectorAll('.gd-page').forEach(b => b.classList.toggle('is-active', +b.dataset.i === p));
        if (changed) {
          head.replaceChildren(
            el('div', {},
              el('h2', {}, pg.title),
              el('p', {}, pg.summary)),
            pg.open !== false ? el('a', { class: 'gd-open', href: pg.href || pg.path }, 'Open this page') : null,
          );
          const img = el('img', { src: pg.image, alt: `${pg.title}, as it appears in Archer`, width: pg.width, height: pg.height, draggable: 'false' });
          const marks = pg.sections.map((x, k) => el('button', {
            type: 'button', class: 'gd-mark', 'aria-label': `${k + 1}. ${x.title}`,
            style: `left:${x.box[0] / pg.width * 100}%;top:${x.box[1] / pg.height * 100}%;width:${x.box[2] / pg.width * 100}%;height:${x.box[3] / pg.height * 100}%`,
            onclick: () => go(p, k),
          }, el('span', { class: 'gd-num' }, String(k + 1))));
          shot.replaceChildren(img, ...marks);
          shot.style.aspectRatio = `${pg.width} / ${pg.height}`;
          frame.scrollTop = 0;
        }
        shot.querySelectorAll('.gd-mark').forEach((m, k) => m.classList.toggle('is-on', k === s));
        caption.replaceChildren(
          el('div', { class: 'gd-count' }, `${s + 1} of ${pg.sections.length}`),
          el('h3', {}, sec.title),
          el('dl', {},
            el('dt', {}, 'What it’s for'), el('dd', {}, sec.what),
            el('dt', {}, 'Who uses it'), el('dd', {}, sec.who),
            el('dt', {}, 'When it helps most'), el('dd', {}, sec.when)),
        );
        prev.disabled = p === 0 && s === 0;
        next.disabled = p === pages.length - 1 && s === pg.sections.length - 1;
        // Bring the highlighted part into the middle of the picture once the image has its size
        requestAnimationFrame(() => {
          const scale = shot.clientWidth / pg.width;
          const top = (sec.box[1] + sec.box[3] / 2) * scale - frame.clientHeight / 2;
          frame.scrollTo({ top: Math.max(0, top), behavior: changed ? 'auto' : 'smooth' });
        });
      }

      box.addEventListener('keydown', e => {
        if (e.target.closest('input')) return;
        if (e.key === 'ArrowRight') { e.preventDefault(); step(1); }
        if (e.key === 'ArrowLeft') { e.preventDefault(); step(-1); }
      });
      go(p, 0);
    }).catch(() => {
      dialog('gd-tips', 'Guide', [closeBtn(), el('p', {}, 'The guide’s pictures aren’t available on this installation.')]);
    });
  }

  // ---- Wiring ----

  document.addEventListener('click', e => {
    const a = e.target.closest('[data-guide], [data-tips]');
    if (!a) return;
    e.preventDefault();
    const menu = a.closest('.nav-menu');
    if (menu) menu.classList.remove('is-open');
    if (a.hasAttribute('data-guide')) showGuideViewer(a.getAttribute('data-guide') || undefined);
    else showTips();
  });

  // The home page's log-in-or-guest welcome comes first; offer the guide once it's gone
  function welcomeOpen() {
    const w = document.getElementById('auth-modal');
    return w && getComputedStyle(w).display !== 'none';
  }
  function atStartup() {
    if (once.seen() || NO_STARTUP.includes(location.pathname) || navigator.webdriver) return;
    if (welcomeOpen()) return setTimeout(atStartup, 600);
    once.mark();
    startup(false);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', atStartup);
  else atStartup();

  window.ArcherGuide = { open: showGuideViewer, tips: showTips, startup: () => startup(true) };
})();
