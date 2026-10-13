// Change or restore a detection's ATT&CK mapping (templates/partials/attack_mapping.html).
// A comment is required either way. Buttons say which endpoint and which detections:
// data-endpoint, data-ref ({"files": [...]} or {"ids": [...]}).
(function () {
  const modal = document.getElementById('mapping-modal');
  if (!modal) return;
  const $ = id => document.getElementById(id);
  const form = $('mapping-form'), input = $('mapping-technique'), nameEl = $('mapping-technique-name');
  const tacticBox = $('mapping-tactics'), comment = $('mapping-comment'), errorEl = $('mapping-error');
  const renameWrap = $('mapping-rename-wrap'), rename = $('mapping-rename');
  let attack = null, current = null, lastTid = '';

  async function loadAttack() {
    if (attack) return attack;
    const res = await fetch('/api/attack/techniques');
    attack = await res.json();
    attack.byId = Object.fromEntries(attack.techniques.map(t => [t.id, t]));
    const esc = s => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    $('mapping-technique-list').innerHTML = attack.techniques
      .map(t => `<option value="${t.id} — ${esc(t.name)}"></option>`).join('');
    tacticBox.innerHTML = attack.tactics.map(t =>
      `<label class="mapping-tactic"><input type="checkbox" value="${esc(t)}"> ${esc(t)}</label>`).join('');
    return attack;
  }

  const techniqueId = () => (input.value.match(/T\d{4}(\.\d{3})?/i) || [''])[0].toUpperCase();
  const setTactics = list => tacticBox.querySelectorAll('input').forEach(cb => { cb.checked = list.includes(cb.value); });
  const ruleFor = tid => 'archer_' + tid.toLowerCase().replace(/\W+/g, '_');

  function onTechnique() {
    const tid = techniqueId(), t = attack && attack.byId[tid];
    nameEl.textContent = t ? `${t.name} · ATT&CK tactics: ${t.tactics.join(', ')}` : (tid ? 'Not a current ATT&CK technique' : '');
    // A different technique starts from its own ATT&CK tactics
    if (t && tid !== lastTid) setTactics(t.tactics);
    lastTid = tid;
    // A SecOps rule can be renamed after a new technique
    const rule = current && current.rule;
    renameWrap.hidden = !rule || !t || ruleFor(tid) === rule;
    if (!renameWrap.hidden) {
      $('mapping-rename-to').textContent = ruleFor(tid);
      $('mapping-rename-from').textContent = rule;
    }
  }

  async function open(btn) {
    current = { action: btn.dataset.mappingAction, endpoint: btn.dataset.endpoint,
                ref: JSON.parse(btn.dataset.ref), rule: btn.dataset.rule || '' };
    const restore = current.action === 'restore', upgrade = current.action === 'upgrade';
    const tactics = JSON.parse(btn.dataset.tactics || '[]');
    errorEl.hidden = true;
    comment.value = '';
    rename.checked = false;
    renameWrap.hidden = true;
    $('mapping-title').textContent = restore ? 'Restore ATT&CK mapping' : upgrade ? 'Upgrade the technique' : 'Edit ATT&CK mapping';
    $('mapping-fields').hidden = restore;
    $('mapping-save').textContent = restore ? 'Restore default' : upgrade ? 'Upgrade' : 'Save';
    const items = current.ref.files || current.ref.ids || [], n = items.length;
    const what = current.ref.ids ? 'Library detection' : 'detection file';
    const scope = current.ref.legacy_id ? `every detection on ${current.ref.legacy_id}` : `${n} ${what}${n === 1 ? '' : 's'} on this card`;
    if (upgrade) {
      const lg = JSON.parse(btn.dataset.legacy || '{}');
      const why = `ATT&CK ${lg.status} ${lg.id} ${lg.name}` + (lg.by ? `, replaced by ${lg.by} ${lg.by_name}` : ', with no replacement named');
      $('mapping-intro').textContent = `${why}. Applies to ${scope}. The technique you choose becomes ` +
        'its ATT&CK default' + (current.ref.ids ? '.' : ', and the file is renamed after it so later runs update it.');
      comment.value = why + '.';
    } else {
      $('mapping-intro').textContent = restore
        ? `Back to ${btn.dataset.technique} (${tactics.join(', ')}), as ATT&CK maps it.` +
          (btn.dataset.renamed ? ` The SecOps rule goes back to ${current.rule}, which SecOps treats as a new rule.` : '')
        : `Applies to ${scope}. Severity follows the tactics.`;
    }
    modal.hidden = false;
    if (!restore) {
      try { await loadAttack(); } catch (e) { errorEl.textContent = 'Couldn\'t load ATT&CK techniques'; errorEl.hidden = false; }
      input.value = btn.dataset.technique;
      lastTid = btn.dataset.technique;
      onTechnique();
      setTactics(tactics);
      input.focus();
    } else {
      comment.focus();
    }
  }

  const close = () => { modal.hidden = true; current = null; };

  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-mapping-action]');
    if (btn) open(btn);
  });
  input.addEventListener('input', onTechnique);
  $('mapping-cancel').addEventListener('click', close);
  modal.addEventListener('click', e => { if (e.target === modal) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !modal.hidden) close(); });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (!current) return;
    const body = { ...current.ref, action: current.action, comment: comment.value.trim() };
    if (current.action !== 'restore') {
      body.technique_id = techniqueId();
      body.tactics = [...tacticBox.querySelectorAll('input:checked')].map(cb => cb.value);
      body.rename_rule = !renameWrap.hidden && rename.checked;
    }
    const fail = msg => { errorEl.textContent = msg; errorEl.hidden = false; };
    if (!body.comment) return fail('A comment is required.');
    const save = $('mapping-save');
    save.disabled = true;
    try {
      const res = await fetch(current.endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || data.detail || res.statusText);
      // The results page warns before leaving unsaved work; this reload isn't leaving
      if (typeof navigationConfirmed !== 'undefined') navigationConfirmed = true;
      window.location.reload();
    } catch (err) {
      fail(err.message);
      save.disabled = false;
    }
  });
})();
