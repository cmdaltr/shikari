// Regex page matcher (static/js/regex.js starts it, and stops it after a time limit).
// Each flavour runs in its own engine where one runs in the browser:
//   re2   Defender XDR, Google SecOps: re2js, the JavaScript port of RE2/J (Google's Java RE2)
//   pcre2 Splunk: PCRE2 built to WebAssembly from the official release (scripts/build/pcre2_wasm),
//         with Splunk's default [rex] match_limit and depth_limit
//   js    Python, Elastic, JavaScript: the browser's engine, on the pattern translated by regex.js
// The engines are loaded on first use and stay loaded for the worker's life.

const VENDOR = new URL('../vendor/', self.location.href).href;
let re2 = null, pcre2 = null;

function loadRe2() {
  if (!re2) {
    importScripts(VENDOR + 're2js/re2js.umd.js');
    re2 = self.RE2JS.RE2JS || self.RE2JS;
  }
  return re2;
}

async function loadPcre2() {
  if (!pcre2) {
    importScripts(VENDOR + 'pcre2/pcre2.js');
    const mod = await self.createPcre2({ locateFile: f => VENDOR + 'pcre2/' + f });
    pcre2 = {
      mod,
      compile: mod.cwrap('rx_compile', 'number', ['string', 'number']),
      error: mod.cwrap('rx_error', 'string', []),
      errorOffset: mod.cwrap('rx_error_offset', 'number', []),
      match: mod.cwrap('rx_match', 'number', ['number', 'number', 'number', 'number']),
      ovector: mod.cwrap('rx_ovector', 'number', []),
      names: mod.cwrap('rx_names', 'string', []),
      version: mod.cwrap('rx_version', 'string', []),
    };
  }
  return pcre2;
}

// $1 \1 $<name> ${name} \g<name> \g<1> $& $0 $$, the same for every engine
function expand(rep, groups, named, whole) {
  return rep.replace(/\$\$|\$[&0]|\$(\d+)|\$<(\w+)>|\$\{(\w+)\}|\\g<(\w+)>|\\(\d)/g, (tok, d1, n1, n2, g, d2) => {
    if (tok === '$$') return '$';
    if (tok === '$&' || tok === '$0') return whole;
    const key = d1 || d2 || n1 || n2 || g;
    if (/^\d+$/.test(key)) return groups[+key - 1] ?? '';
    return named && named[key] != null ? named[key] : '';
  });
}

function replaceAll(text, matches, rep) {
  let out = '', last = 0;
  for (const m of matches) {
    out += text.slice(last, m.i) + expand(rep, m.g, m.n, m.t);
    last = m.i + m.t.length;
  }
  return out + text.slice(last);
}

function runRe2(pattern, flags, text, max) {
  const R = loadRe2();
  const f = (flags.includes('i') ? R.CASE_INSENSITIVE : 0) | (flags.includes('m') ? R.MULTILINE : 0) | (flags.includes('s') ? R.DOTALL : 0);
  const re = R.compile(pattern, f);
  const count = re.groupCount(), names = Object.entries(re.namedGroups() || {});
  const m = re.matcher(text), matches = [];
  while (matches.length < max && m.find()) {
    const g = [], d = [];
    for (let k = 1; k <= count; k++) {
      const s = m.start(k);
      g.push(s < 0 ? undefined : m.group(k));
      d.push(s < 0 ? null : [s, m.end(k)]);
    }
    const n = names.length ? Object.fromEntries(names.map(([name, k]) => [name, g[k - 1]])) : null;
    matches.push({ i: m.start(), t: m.group(), g, n, d });
  }
  return { matches, engine: 'RE2 (re2js)' };
}

const PCRE2_CASELESS = 0x8, PCRE2_DOTALL = 0x20, PCRE2_MULTILINE = 0x400, PCRE2_UTF = 0x80000;
const PCRE2_ERROR_NOMATCH = -1, PCRE2_ERROR_MATCHLIMIT = -47, PCRE2_ERROR_DEPTHLIMIT = -52;

async function runPcre2(pattern, flags, text, max) {
  const P = await loadPcre2();
  const opts = PCRE2_UTF | (flags.includes('i') ? PCRE2_CASELESS : 0) | (flags.includes('m') ? PCRE2_MULTILINE : 0) | (flags.includes('s') ? PCRE2_DOTALL : 0);
  const count = P.compile(pattern, opts);
  if (count < 0) {
    const at = P.errorOffset();
    throw new Error(`${P.error()} at offset ${at}`);
  }
  // The subject in UTF-8 in the module's memory, and each byte offset's UTF-16 index
  const bytes = new TextEncoder().encode(text);
  const toUtf16 = new Uint32Array(bytes.length + 1);
  for (let b = 0, u = 0; b <= bytes.length; ) {
    toUtf16[b] = u;
    if (b === bytes.length) break;
    const c = bytes[b], len = c < 0x80 ? 1 : c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
    for (let k = 1; k < len; k++) toUtf16[b + k] = u;
    b += len; u += len === 4 ? 2 : 1;
  }
  const ptr = P.mod._malloc(bytes.length + 1);
  P.mod.HEAPU8.set(bytes, ptr);
  P.mod.HEAPU8[ptr + bytes.length] = 0;
  const names = (P.names() || '').split('\n').filter(Boolean).map(e => e.split('=')).map(([n, k]) => [n, +k]);
  const matches = [];
  let start = 0, notice = null;
  try {
    while (matches.length < max && start <= bytes.length) {
      const rc = P.match(ptr, bytes.length, start, 0);
      if (rc === PCRE2_ERROR_NOMATCH) break;
      if (rc === PCRE2_ERROR_MATCHLIMIT || rc === PCRE2_ERROR_DEPTHLIMIT) {
        notice = rc === PCRE2_ERROR_MATCHLIMIT ? 'match_limit' : 'depth_limit';
        break;
      }
      if (rc < 0) throw new Error(`matching failed (PCRE2 error ${rc})`);
      const ov = new Uint32Array(P.mod.HEAPU8.buffer, P.ovector(), 2 * (count + 1));
      const s = ov[0], e = ov[1];
      const g = [], d = [];
      for (let k = 1; k <= count; k++) {
        const gs = ov[2 * k], ge = ov[2 * k + 1];
        const unset = gs === 0xffffffff || k >= rc;
        g.push(unset ? undefined : text.slice(toUtf16[gs], toUtf16[ge]));
        d.push(unset ? null : [toUtf16[gs], toUtf16[ge]]);
      }
      const n = names.length ? Object.fromEntries(names.map(([name, k]) => [name, g[k - 1]])) : null;
      matches.push({ i: toUtf16[s], t: text.slice(toUtf16[s], toUtf16[e]), g, n, d });
      // After an empty match, move on one character (UTF-8 aware)
      start = e > s ? e : e + (bytes[e] < 0x80 ? 1 : bytes[e] < 0xe0 ? 2 : bytes[e] < 0xf0 ? 3 : 4);
    }
  } finally {
    P.mod._free(ptr);
  }
  return { matches, engine: `PCRE2 ${P.version()}`, limit: notice };
}

function runJs(src, flags, text, perLine, max) {
  const re = new RegExp(src, flags + 'gd');
  const matches = [];
  const lines = perLine ? text.split('\n') : [text];
  let offset = 0;
  for (const line of lines) {
    if (perLine) {
      const whole = new RegExp('^(?:' + src + ')$', flags + 'd').exec(line);
      if (whole) matches.push({ i: whole.index + offset, t: whole[0], g: [...whole].slice(1), n: whole.groups || null, d: whole.indices.slice(1).map(x => x ? [x[0] + offset, x[1] + offset] : null) });
    } else {
      let m;
      while ((m = re.exec(line)) && matches.length < max) {
        matches.push({ i: m.index, t: m[0], g: [...m].slice(1), n: m.groups || null, d: m.indices.slice(1).map(x => x || null) });
        if (m[0] === '') re.lastIndex++;
      }
    }
    offset += line.length + 1;
  }
  return { matches, engine: 'JavaScript' };
}

onmessage = async e => {
  const { engine, pattern, src, flags, text, perLine, replace, max } = e.data;
  try {
    const r = engine === 're2' ? runRe2(pattern, flags, text, max)
      : engine === 'pcre2' ? await runPcre2(pattern, flags, text, max)
      : runJs(src, flags, text, perLine, max);
    r.replaced = replace === null ? null : replaceAll(text, r.matches, replace);
    postMessage(r);
  } catch (err) {
    postMessage({ error: String(err.message || err).replace(/^Invalid regular expression: /, ''), engine });
  }
};
