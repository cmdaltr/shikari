// Profiling progress (templates/profile_progress.html): poll the same /progress_status the hunt
// progress page uses, drive the seven profiler stages, and go to the Review page when it finishes.
(function () {
  const wrap = document.querySelector('.pp-wrap');
  if (!wrap) return;
  const domain = wrap.dataset.domain;
  const group = wrap.dataset.group;
  const steps = Array.from(document.querySelectorAll('.pp-step'));
  const foot = document.getElementById('pp-foot');
  const errEl = document.getElementById('pp-error');
  let done = false;

  function setState(el, state) {
    el.dataset.state = state;
    const ic = el.querySelector('.pp-ic');
    if (state === 'done') ic.textContent = '✓';
    else if (state === 'active') ic.innerHTML = '<span class="pp-spin"></span>';
    else if (state === 'failed') ic.textContent = '✗';
    else ic.textContent = el.dataset.stage;
  }

  function render(stage, failed) {
    steps.forEach(el => {
      const s = Number(el.dataset.stage);
      setState(el, failed && s === stage ? 'failed' : s < stage ? 'done' : s === stage ? 'active' : 'waiting');
    });
  }

  render(1, false);

  async function poll() {
    if (done) return;
    let p;
    try {
      const body = await (await fetch(`/progress_status?group_name=${encodeURIComponent(group)}`)).json();
      p = body.progress || body;  // /progress_status wraps the record under `progress`
    } catch (e) {
      setTimeout(poll, 1500);
      return;
    }
    const status = p.status || '';
    const stage = Math.max(1, Math.min(7, Number(p.stage) || 1));

    if (status === 'profile_complete') {
      done = true;
      steps.forEach(el => setState(el, 'done'));
      foot.textContent = 'Profile complete — opening the review…';
      window.location = '/review?domain=' + encodeURIComponent(domain);
      return;
    }
    if (status === 'failed') {
      done = true;
      render(stage, true);
      errEl.style.display = 'block';
      errEl.textContent = (p.error ? 'Profiling failed: ' + p.error : 'Profiling failed.') + ' You can try again from the home page.';
      foot.textContent = '';
      return;
    }
    render(stage, false);
    setTimeout(poll, 1200);
  }
  poll();
})();
