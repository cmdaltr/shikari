// Click a card's title to collapse the card; click again to expand it. Every page.
// A card is the nearest box (rounded, with a background or border) round its first
// heading. Collapsing hides everything in the card but the part holding the title.
// The choice is remembered per page and title. A card that already has its own
// Collapse/Expand control (an .expand-btn with "toggle" in its id) keeps it: the title works it.
// A card drawn in more than one box names the others: data-collapse-with="<selector>".
// A card that starts collapsed until opened says so: data-collapsed-default.
(function () {
  const TITLES = 'h2, h3, .section-title, .tactic-section-title, .tactic-filter-label, .mn-card-title, .hiw-section-title';
  // Page titles, dialogs, sub-headings and lanes aren't card titles
  const SKIP = '.global-nav-controls, .modal-dialog, .modal, .mapping-overlay, [role="dialog"], details, .af-canvas';
  const HIDDEN = 'data-card-hidden';

  const transparent = c => c === 'transparent' || c === 'rgba(0, 0, 0, 0)';
  function isCard(el) {
    if (el.classList.contains('ui-card')) return true;
    const cs = getComputedStyle(el);
    return parseFloat(cs.borderTopLeftRadius) > 0 &&
      (!transparent(cs.backgroundColor) || parseFloat(cs.borderTopWidth) > 0);
  }

  function cardOf(title) {
    if (title.closest(SKIP) || title.classList.contains('ui-subtitle')) return null;
    let card = title.parentElement;
    while (card && card !== document.body && !isCard(card)) card = card.parentElement;
    if (!card || card === document.body) return null;
    // Only the card's first heading is its title, at the top of the card
    if (card.querySelector(TITLES) !== title) return null;
    for (let el = title; el !== card; el = el.parentElement) {
      const first = [...el.parentElement.children].find(c => !['SCRIPT', 'STYLE', 'TEMPLATE'].includes(c.tagName));
      if (first !== el) return null;
    }
    return card;
  }

  const ownToggle = card => card.querySelector('.expand-btn[id*="toggle"]');
  const ownExpanded = btn => btn.textContent.trim() !== 'Expand';

  // The children to hide: the card's other children, going down a level while one child holds it all
  function bodyOf(card, title) {
    let box = card;
    for (;;) {
      const head = [...box.children].find(c => c.contains(title));
      const rest = [...box.children].filter(c => c !== head);
      if (rest.length || !head || head === title) return rest;
      box = head;
    }
  }

  const keyOf = title => `archer.collapsed:${location.pathname}:${title.textContent.trim().replace(/\s+/g, ' ').slice(0, 60)}`;
  // '1' collapsed, '0' opened (only kept for cards collapsed by default), nothing: the card's default
  const remembered = (key, dflt) => { try { const v = localStorage.getItem(key); return v === null ? dflt : v === '1'; } catch (e) { return dflt; } };
  const remember = (key, on, dflt) => { try { on ? localStorage.setItem(key, '1') : dflt ? localStorage.setItem(key, '0') : localStorage.removeItem(key); } catch (e) {} };
  const collapsedByDefault = card => card.hasAttribute('data-collapsed-default');

  function set(title, card, on) {
    card.classList.toggle('is-card-collapsed', on);
    title.setAttribute('aria-expanded', String(!on));
    const also = card.dataset.collapseWith ? [...document.querySelectorAll(card.dataset.collapseWith)] : [];
    card.querySelectorAll(`[${HIDDEN}]`).forEach(el => el.removeAttribute(HIDDEN));
    also.forEach(el => el.toggleAttribute(HIDDEN, on));
    if (on) bodyOf(card, title).forEach(el => el.setAttribute(HIDDEN, ''));
  }

  // Mark titles (cursor, keyboard, chevron) and apply remembered state; cards drawn later get it too
  function scan() {
    document.querySelectorAll(TITLES).forEach(title => {
      const card = cardOf(title);
      if (!card) return;
      const own = ownToggle(card);
      if (!title.classList.contains('card-title-toggle')) {
        title.classList.add('card-title-toggle');
        title.setAttribute('role', 'button');
        title.tabIndex = 0;
        if (!own) set(title, card, remembered(keyOf(title), collapsedByDefault(card)));
      }
      if (own) title.setAttribute('aria-expanded', String(ownExpanded(own)));
      else if (card.classList.contains('is-card-collapsed')) {
        set(title, card, true);   // re-hide anything added since
      }
    });
  }

  function toggle(title) {
    const card = cardOf(title);
    if (!card) return;
    const own = ownToggle(card);
    if (own) {
      // Some titles already work it themselves (onclick), and that has run by now
      if (!title.hasAttribute('onclick')) own.click();
      title.setAttribute('aria-expanded', String(ownExpanded(own)));
      return;
    }
    const on = !card.classList.contains('is-card-collapsed');
    set(title, card, on);
    remember(keyOf(title), on, collapsedByDefault(card));
  }

  document.addEventListener('click', e => {
    const title = e.target.closest('.card-title-toggle');
    // Buttons and links inside a title keep their own job
    if (!title || e.target.closest('a, button, input, select, textarea, label')) return;
    toggle(title);
  });
  document.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('card-title-toggle')) {
      e.preventDefault();
      toggle(e.target);
    }
  });

  let queued = false;
  const later = () => { if (!queued) { queued = true; requestAnimationFrame(() => { queued = false; scan(); }); } };
  const start = () => { scan(); new MutationObserver(later).observe(document.body, { childList: true, subtree: true }); };
  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', start) : start();
})();
