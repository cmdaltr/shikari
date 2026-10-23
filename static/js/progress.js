// Progress page: poll /progress_status and draw the server's progress record.
//
// The server owns the phase (preparing -> detections -> correlations -> finalising ->
// complete); this page never advances it. Correlations show nothing until the server
// has finished every detection and moved the run on.
//
// A Profile run generates several groups one after another: ?queue=A,B,C lists them and
// the page follows each in turn, then opens the first one's results.
const params = new URLSearchParams(window.location.search);
let group = params.get('group_name') || '';
const queue = (params.get('queue') || '').split(',').map(g => g.trim()).filter(Boolean);
if (queue.length && !queue.includes(group)) group = queue[0];
const queueState = {};     // group -> waiting | active | done | failed

const PHASES = ['preparing', 'detections', 'correlations', 'finalising', 'complete'];
const POLL_MS = 1000;

const CORRELATION_STEPS = {
  starting: 'Loading detections',
  loading: 'Loading detections',
  pairing: 'Pairing techniques',
  scoring: 'Scoring and ranking pairs',
  grouping: 'Grouping and saving correlations',
  done: 'Correlations saved',
};

let redirecting = false;
let pollTimer = null;
const phaseStarted = {};   // phase -> ms timestamp, for the elapsed-time readout
const phaseEnded = {};
let detPctShown = 0;       // never let a bar go backwards between polls
let corrPctShown = 0;

function resetRun() {
  for (const k of Object.keys(phaseStarted)) delete phaseStarted[k];
  for (const k of Object.keys(phaseEnded)) delete phaseEnded[k];
  detPctShown = 0;
  corrPctShown = 0;
}

// The run just finished; the results page can switch to all runs
function resultsUrl(g) { return `/results?group_name=${encodeURIComponent(g)}&run=latest`; }

function renderQueue() {
  const box = document.getElementById('pg-queue');
  if (!box || queue.length < 2) return;
  box.hidden = false;
  const idx = queue.indexOf(group);
  box.querySelector('.pg-queue-pos').textContent = `Group ${idx + 1} of ${queue.length}`;
  const list = box.querySelector('.pg-queue-list');
  list.replaceChildren(...queue.map(g => {
    const state = queueState[g] || (g === group ? 'active' : 'waiting');
    const el = document.createElement(state === 'done' ? 'a' : 'span');
    el.className = 'pg-chip';
    el.dataset.state = state;
    el.textContent = g;
    if (state === 'done') { el.href = resultsUrl(g); el.target = '_blank'; el.rel = 'noopener'; }
    return el;
  }));
  const name = document.getElementById('progress-group');
  if (name) name.textContent = group;
}

// Queue the next group once this one ends; false when this was the last one.
// The switch happens with the next group's first render, so the address bar and the
// bars never disagree about which group is on screen.
let pendingNext = null;
function advanceQueue(outcome) {
  queueState[group] = outcome;
  pendingNext = queue[queue.indexOf(group) + 1] || null;
  renderQueue();
  return !!pendingNext;
}

function switchToPending() {
  group = pendingNext;
  pendingNext = null;
  resetRun();
  const url = new URL(window.location.href);
  url.searchParams.set('group_name', group);
  history.replaceState(null, '', url);
  renderQueue();
}

function fmt(n) { return Number(n || 0).toLocaleString('en-GB'); }

function elapsed(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

// Older records (and the upload routes before generation starts) carry only `status`
function phaseOf(p) {
  if (PHASES.includes(p.phase)) return p.phase;
  const st = p.status || '';
  if (st === 'complete') return 'complete';
  if (st === 'creating_yamls') return 'detections';
  if (st.startsWith('genai')) return 'correlations';
  return 'preparing';
}

function card(kind) {
  const el = document.getElementById('pg-' + kind);
  return el && {
    el,
    badge: el.querySelector('.pg-badge'),
    pct: el.querySelector('.pg-pct'),
    count: el.querySelector('.pg-count'),
    track: el.querySelector('.pg-track'),
    fill: el.querySelector('.pg-fill'),
    detail: el.querySelector('.pg-detail'),
    time: el.querySelector('.pg-time'),
  };
}

function paint(c, { state, pct, count, detail, indeterminate, time }) {
  if (!c) return;
  const badge = { waiting: 'Waiting', active: 'In progress', done: 'Complete', failed: 'Failed' }[state];
  c.el.dataset.state = state;
  c.el.classList.toggle('is-indeterminate', !!indeterminate);
  c.badge.textContent = badge;
  c.pct.textContent = indeterminate ? '—' : `${pct}%`;
  c.fill.style.width = `${indeterminate ? 0 : pct}%`;
  c.track.setAttribute('aria-valuenow', String(indeterminate ? 0 : pct));
  c.count.textContent = count || '';
  if (typeof detail === 'string') c.detail.textContent = detail;
  else if (detail) c.detail.replaceChildren(...detail);
  c.time.textContent = time || '';
}

function strong(text) {
  const el = document.createElement('strong');
  el.textContent = text;
  return el;
}

function hideLoading() {
  const indicator = document.getElementById('loading-indicator');
  if (indicator) indicator.classList.add('fade-out', 'hidden');
}

function setState(text) {
  const state = document.getElementById('progress-state');
  if (state) state.textContent = text;
}

// Server timestamps (seconds) when the record has them, else when this page saw the phase
function timing(phase, now, p) {
  const stamps = (p && p.phase_started) || {};
  // The correlation card also covers finalising (building the ATT&CK Flow)
  const next = phase === 'correlations' ? 'complete' : PHASES[PHASES.indexOf(phase) + 1];
  const start = stamps[phase] ? stamps[phase] * 1000 : phaseStarted[phase];
  const end = stamps[next] ? stamps[next] * 1000 : phaseEnded[next === 'complete' ? 'finalising' : phase];
  if (!start) return '';
  return elapsed((end || now) - start);
}

function render(p) {
  const now = Date.now();
  const phase = phaseOf(p);
  const rank = PHASES.indexOf(phase);
  PHASES.forEach((ph, i) => {
    if (i <= rank && !phaseStarted[ph]) phaseStarted[ph] = now;
    if (i < rank && !phaseEnded[ph]) phaseEnded[ph] = now;
  });

  const det = card('detection');
  const corr = card('correlation');
  const total = Number(p.total_yaml) || 0;
  const processed = Number(p.processed_yaml ?? p.created_yaml) || 0;
  const created = Number(p.created_yaml) || 0;
  // The *_yaml counts are procedures; a technique can have several. Older runs lack technique counts.
  const techTotal = Number(p.total_techniques) || 0;
  const techMade = Number(p.created_techniques) || 0;
  const procs = n => `${fmt(n)} procedure${n === 1 ? '' : 's'}`;
  const sweeps = Number(p.ioc_sweeps) || 0;   // report IOC sweeps, one per SIEM
  const sweepNote = sweeps ? `IOC sweeps for ${sweeps} SIEM${sweeps === 1 ? '' : 's'}` : '';

  if (p.status === 'failed') {
    const err = document.createElement('span');
    err.className = 'pg-error';
    err.textContent = 'Error: ';
    const failed = rank >= PHASES.indexOf('correlations') ? corr : det;
    paint(failed, {
      state: 'failed', pct: failed === det ? detPctShown : corrPctShown,
      detail: [err, document.createTextNode(p.error || 'Processing failed. Check the server log or try again.')],
    });
    hideLoading();
    setState('Failed');
    return 'stop';
  }

  if (phase === 'complete' && !(created > 0) && !(sweeps > 0)) {
    paint(det, { state: 'done', pct: 100, detail: p.error || 'No detections were generated: none of the selected techniques produced a query.' });
    hideLoading();
    setState('Nothing generated');
    return 'stop';
  }

  // Detections
  if (phase === 'preparing') {
    paint(det, {
      state: 'active', indeterminate: true,
      detail: p.current_step || p.stage_label || (p.stage && p.stage !== 'queued' && p.stage !== 'init' ? p.stage : 'Collecting techniques'),
    });
  } else if (phase === 'detections') {
    const pct = total > 0 ? Math.min(99, Math.floor((processed / total) * 100)) : 0;
    detPctShown = Math.max(detPctShown, pct);
    paint(det, {
      state: 'active', indeterminate: total === 0, pct: detPctShown,
      count: total ? `${fmt(processed)} / ${procs(total)}${techTotal ? ` (${fmt(techTotal)} techniques)` : ''}` : '',
      detail: p.current_technique ? `Building ${p.current_technique}` : 'Building detections',
      time: timing('detections', now, p),
    });
    hideLoading();
  } else {
    detPctShown = 100;
    const made = total || created
      ? `${techTotal ? `${fmt(techMade)} of ${fmt(techTotal)} techniques (${procs(created)})` : procs(created)} produced detections${sweeps ? `, plus ${sweepNote}` : ''}`
      : `${sweepNote} (no techniques were selected)`;
    paint(det, {
      state: 'done', pct: 100,
      count: total ? `${fmt(processed || total)} / ${procs(total)}` : '',
      detail: [strong('Complete: '), document.createTextNode(made)],
      time: timing('detections', now, p),
    });
    hideLoading();
  }

  // Correlations: untouched until the server has moved the run past detections
  if (rank < PHASES.indexOf('correlations')) {
    paint(corr, { state: 'waiting', pct: 0, detail: 'Starts when every detection is built' });
  } else if (phase === 'correlations') {
    const step = p.step || (p.status === 'genai_processing' ? 'pairing' : 'starting');
    const pairs = Number(p.total_pairs) || 0;
    const done = Math.min(Number(p.processed) || 0, pairs);
    const toScore = Number(p.to_score) || 0;
    const scored = Math.min(Number(p.scored) || 0, toScore);
    // Pairing is the long part (0-90%), scoring the next (90-96%); grouping takes the rest
    let pct = 0;
    if (step === 'pairing' && pairs > 0) pct = Math.floor((done / pairs) * 90);
    else if (step === 'scoring') pct = 90 + (toScore ? Math.floor((scored / toScore) * 6) : 0);
    else if (step === 'grouping') pct = 96;
    else if (step === 'done') pct = 98;
    corrPctShown = Math.max(corrPctShown, pct);
    paint(corr, {
      state: 'active', pct: corrPctShown,
      indeterminate: step === 'starting' || step === 'loading' || (step === 'pairing' && pairs === 0),
      count: step === 'scoring' && toScore ? `${fmt(scored)} / ${fmt(toScore)} scored`
        : pairs ? `${fmt(done)} / ${fmt(pairs)} pairs` : '',
      detail: CORRELATION_STEPS[step] || 'Correlating',
      time: timing('correlations', now, p),
    });
  } else if (phase === 'finalising') {
    corrPctShown = 99;
    paint(corr, {
      state: 'active', pct: 99, count: p.total_pairs ? `${fmt(p.total_pairs)} / ${fmt(p.total_pairs)} pairs` : '',
      detail: 'Building the ATT&CK Flow', time: timing('correlations', now, p),
    });
  } else {
    const ran = phaseStarted.correlations || p.total_pairs || p.vendor_count != null;
    if (p.correlation_error) {
      const err = document.createElement('span');
      err.className = 'pg-error';
      err.textContent = 'Correlation failed: ';
      paint(corr, { state: 'failed', pct: corrPctShown, detail: [err, document.createTextNode(p.correlation_error)] });
    } else {
      paint(corr, ran ? {
        state: 'done', pct: 100,
        count: p.total_pairs ? `${fmt(p.total_pairs)} / ${fmt(p.total_pairs)} pairs` : '',
        detail: [strong('Complete: '), document.createTextNode(`${fmt(p.vendor_count || 0)} correlated technique pairs (merged on the results page)`)],
        time: timing('correlations', now, p),
      } : { state: 'waiting', pct: 0, detail: total || created ? 'Correlation was not requested for this run' : 'No techniques to correlate' });
    }
  }

  setState({
    preparing: 'Preparing', detections: 'Generating detections', correlations: 'Correlating',
    finalising: 'Finishing', complete: 'Complete',
  }[phase]);

  if (phase === 'complete') return 'done';
  return 'continue';
}

let pausedUntil = 0;   // a moment on each finished group before the next one

async function refresh() {
  if (!group || redirecting || Date.now() < pausedUntil) return;
  try {
    const polled = pendingNext || group;
    const res = await fetch(`/progress_status?group_name=${encodeURIComponent(polled)}`);
    const j = await res.json();
    if (pendingNext && polled === pendingNext) switchToPending();
    if (polled !== group) return;
    const outcome = render(j.progress || {});
    if (outcome === 'continue') return;
    if (queue.length > 1 && advanceQueue(outcome === 'done' ? 'done' : 'failed')) {
      pausedUntil = Date.now() + (outcome === 'done' ? 1000 : 3000);
      return;
    }
    if (queue.length > 1) {
      queueState[group] = outcome === 'done' ? 'done' : 'failed';
      renderQueue();
    }
    // The first group that produced something, else this one
    const target = queue.find(g => queueState[g] === 'done') || (outcome === 'done' ? group : null);
    clearInterval(pollTimer);
    if (!target) { nothingGenerated(group, j.progress || {}); return; }
    redirecting = true;
    // A moment on the finished bars, then a card that says the results page is being built:
    // a big run's page takes a while to render, and the browser shows nothing until it arrives
    setTimeout(() => {
      const card = document.getElementById('pg-opening');
      if (card) {
        card.hidden = false;
        const started = Date.now(), clock = document.getElementById('pg-opening-time');
        setInterval(() => { clock.textContent = `${Math.round((Date.now() - started) / 1000)}s`; }, 1000);
        card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
      window.location.href = resultsUrl(target);
    }, 1000);
  } catch (e) {
    console.error('Progress polling error:', e);
  }
}

// Nothing to show: say why and offer the next step, rather than leaving a finished page
function nothingGenerated(name, p) {
  const box = document.getElementById('pg-nothing');
  if (!box || p.status === 'failed') return;
  const cve = /^CVE-\d{4}-\d+$/i.test(name);
  box.querySelector('h2').textContent = `Nothing generated for ${name.replace(/_/g, ' ')}`;
  box.querySelector('.pg-nothing-why').textContent = cve
    ? 'Archer found no ATT&CK techniques with indicators for this CVE, so there was nothing to build a query from. '
      + 'If there is a report on it (a vendor advisory or threat brief with IOCs and TTPs), analyse that instead.'
    : (p.error || 'None of the selected techniques produced a query.');
  box.hidden = false;
  box.querySelector('a, button').focus();
}

renderQueue();
pollTimer = setInterval(refresh, POLL_MS);
refresh();
