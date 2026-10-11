// Progress page: poll /progress_status and draw the server's progress record.
//
// The server owns the phase (preparing -> detections -> correlations -> finalising ->
// complete); this page never advances it. Correlations show nothing until the server
// has finished every detection and moved the run on.
const params = new URLSearchParams(window.location.search);
const group = params.get('group_name') || '';

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

  if (phase === 'complete' && !(created > 0)) {
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
      count: total ? `${fmt(processed)} / ${fmt(total)} techniques` : '',
      detail: p.current_technique ? `Building ${p.current_technique}` : 'Building detections',
      time: timing('detections', now, p),
    });
    hideLoading();
  } else {
    detPctShown = 100;
    paint(det, {
      state: 'done', pct: 100,
      count: total ? `${fmt(processed || total)} / ${fmt(total)} techniques` : '',
      detail: [strong('Complete: '), document.createTextNode(`${fmt(created)} techniques produced detections`)],
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
    // Pairing is the long part (0-90%); scoring and grouping take the rest
    let pct = 0;
    if (step === 'pairing' && pairs > 0) pct = Math.floor((done / pairs) * 90);
    else if (step === 'scoring') pct = 92;
    else if (step === 'grouping') pct = 96;
    else if (step === 'done') pct = 98;
    corrPctShown = Math.max(corrPctShown, pct);
    paint(corr, {
      state: 'active', pct: corrPctShown,
      indeterminate: step === 'starting' || step === 'loading' || (step === 'pairing' && pairs === 0),
      count: pairs ? `${fmt(done)} / ${fmt(pairs)} pairs` : '',
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
      } : { state: 'waiting', pct: 0, detail: 'Correlation was not requested for this run' });
    }
  }

  setState({
    preparing: 'Preparing', detections: 'Generating detections', correlations: 'Correlating',
    finalising: 'Finishing', complete: 'Complete',
  }[phase]);

  if (phase === 'complete') return 'done';
  return 'continue';
}

async function refresh() {
  if (!group || redirecting) return;
  try {
    const res = await fetch(`/progress_status?group_name=${encodeURIComponent(group)}`);
    const j = await res.json();
    const outcome = render(j.progress || {});
    if (outcome === 'stop') {
      clearInterval(pollTimer);
    } else if (outcome === 'done') {
      clearInterval(pollTimer);
      redirecting = true;
      // A moment on the finished bars before the results page
      setTimeout(() => {
        window.location.href = `/results?group_name=${encodeURIComponent(group)}`;
      }, 1000);
    }
  } catch (e) {
    console.error('Progress polling error:', e);
  }
}

pollTimer = setInterval(refresh, POLL_MS);
refresh();
