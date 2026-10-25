// Watches the viewer's *effective* role so a just-in-time elevation (or its expiry) reveals or
// removes role-gated UI without a page reload. One poll loop, many subscribers.
//
// A grant activates a minute after approval and expires on its own, so beyond a slow fallback poll
// we schedule exact re-checks at each open request's start and expiry, and re-check on tab focus.
(function (global) {
  const subs = [];
  let started = false, current = null, iv = null, timers = [];
  const clearTimers = () => { timers.forEach(clearTimeout); timers = []; };
  function stop() { if (iv) clearInterval(iv); iv = null; clearTimers(); started = false; }

  async function check() {
    let res;
    try { res = await fetch('/api/access/mine', { headers: { Accept: 'application/json' } }); }
    catch (e) { return; }                 // network blip — try again next tick
    if (res.status === 401) { stop(); return; }   // not signed in: nothing to watch
    if (!res.ok) return;
    let data;
    try { data = await res.json(); } catch (e) { return; }

    const eff = data.effective_role || data.base_role;
    if (current === null) current = eff;          // first read matches what the server rendered
    else if (eff !== current) {
      current = eff;
      subs.forEach(cb => { try { cb(eff, data); } catch (e) { /* subscriber's problem */ } });
    }

    // Re-check precisely when an open grant starts or ends.
    clearTimers();
    const now = Date.now();
    (data.requests || []).forEach(r => {
      [r.starts_at, r.expires_at].forEach(t => {
        if (!t) return;
        const ms = Date.parse(t) - now;
        if (ms > 500 && ms < 26 * 3600 * 1000) timers.push(setTimeout(check, ms + 1500));
      });
    });
  }

  function onRoleChange(cb) {
    if (typeof cb === 'function') subs.push(cb);
    if (!started) { started = true; check(); iv = setInterval(check, 30000); }
  }

  document.addEventListener('visibilitychange', () => { if (!document.hidden && started) check(); });
  global.onRoleChange = onRoleChange;
})(window);
