// Review page (templates/review.html): the branding, summary and exposure map are server-rendered;
// this wires the group selection and kicks off detection generation (reusing /profile/generate-detections).

// Logo fallback chain: Clearbit company logo -> the site's favicon -> a monogram. Global so the
// <img onerror> can reach it.
function rvLogoError(img) {
  const fb = img.getAttribute('data-fallback');
  if (fb) { img.removeAttribute('data-fallback'); img.src = fb; return; }
  img.hidden = true;
  const mono = img.parentElement && img.parentElement.querySelector('.rv-logo-mono');
  if (mono) mono.hidden = false;
}

(function () {
  const page = document.querySelector('.rv-page');
  if (!page) return;
  const domain = page.dataset.domain;
  const boxes = () => Array.from(document.querySelectorAll('.rv-group-cb'));
  const selectAll = document.getElementById('rv-select-all');
  const estimate = document.getElementById('rv-estimate');
  const genBtn = document.getElementById('rv-generate');

  function checked() { return boxes().filter(b => b.checked); }

  function updateEstimate() {
    const n = checked().length;
    genBtn.disabled = n === 0;
    if (!n) { estimate.textContent = 'Select at least one group'; return; }
    // Each group is a full run; a rough span so the wait isn't a surprise
    estimate.textContent = `${n} group${n === 1 ? '' : 's'} · about ${n}–${n * 2} min`;
    if (selectAll) selectAll.checked = n === boxes().length;
  }

  boxes().forEach(b => b.addEventListener('change', updateEstimate));
  if (selectAll) selectAll.addEventListener('change', () => {
    boxes().forEach(b => { b.checked = selectAll.checked; });
    updateEstimate();
  });
  updateEstimate();

  genBtn.addEventListener('click', async function () {
    const groups = checked().map(b => b.value);
    if (!groups.length) return;
    genBtn.disabled = true;
    genBtn.textContent = 'Starting…';
    const body = new URLSearchParams({
      domain: domain,
      selected_groups: groups.join(','),
      run_correlation: document.getElementById('rv-correlation').checked ? 'true' : 'false',
    });
    try {
      const res = await fetch('/profile/generate-detections', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
      });
      const data = await res.json();
      if (data && data.redirect_url) { window.location = data.redirect_url; return; }
      throw new Error((data && data.error) || 'Could not start generation');
    } catch (e) {
      genBtn.disabled = false;
      genBtn.textContent = 'Generate detections';
      estimate.textContent = e.message;
    }
  });

  // Add detected products to the user's own technology stack (same endpoint the old modal used)
  const addStack = document.getElementById('rv-add-stack');
  if (addStack) addStack.addEventListener('click', async function () {
    const status = document.getElementById('rv-add-stack-status');
    const ids = (addStack.dataset.stackIds || '').split(',').map(s => s.trim()).filter(Boolean);
    addStack.disabled = true;
    try {
      const cur = await (await fetch('/api/profile/stack')).json();
      const stack = (cur.stack || []).slice();
      ids.forEach(id => { if (stack.indexOf(id) < 0) stack.push(id); });
      const res = await (await fetch('/api/profile/stack', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stack }),
      })).json();
      if (status) status.textContent = res.success
        ? `Added: your stack has ${res.stack.length} product${res.stack.length === 1 ? '' : 's'}`
        : (res.error || 'Not saved');
    } catch (e) {
      if (status) status.textContent = 'Could not add';
      addStack.disabled = false;
    }
  });
})();
