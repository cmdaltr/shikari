// Cyber Powers page (templates/cyber_powers.html): hovering or pressing a key item, or a
// state, fades the rest of the map.
(function () {
  const map = document.getElementById('cp-map');
  if (!map) return;
  const countries = [...map.querySelectorAll('.country')];
  const groups = {};
  document.querySelectorAll('.cp-group').forEach(g => {
    groups[g.dataset.group] = [...g.querySelectorAll('[data-map]')].map(li => li.dataset.map);
  });
  let pinned = null;

  function focus(names) {
    const set = names ? new Set(names) : null;
    map.classList.toggle('has-focus', !!set);
    countries.forEach(c => c.classList.toggle('is-focus', !!set && set.has(c.dataset.name)));
  }
  const rest = () => focus(pinned ? groups[pinned] : null);

  document.querySelectorAll('.cp-key-item').forEach(b => {
    b.addEventListener('mouseenter', () => focus(groups[b.dataset.group]));
    b.addEventListener('mouseleave', rest);
    b.addEventListener('click', () => {
      pinned = pinned === b.dataset.group ? null : b.dataset.group;
      document.querySelectorAll('.cp-key-item').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.group === pinned)));
      rest();
    });
  });
  document.querySelectorAll('.cp-states [data-map]').forEach(li => {
    li.addEventListener('mouseenter', () => focus([li.dataset.map]));
    li.addEventListener('mouseleave', rest);
  });
})();
