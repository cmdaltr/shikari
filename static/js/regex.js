// Regex page (templates/regex.html): test a pattern and check it for the SIEM it will run in.
// Everything runs here, in the browser: the pattern is tokenised once, and the tokens drive
// the explanation and the flavour checks. Matching runs in a worker (regex_worker.js) that's
// stopped after a time limit, so a pattern that backtracks without end can't hang the page:
// RE2 flavours in RE2, Splunk in PCRE2, and the rest in JavaScript on a translated pattern.
(function () {
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const STORE = 'archer.regex';
  const TIME_LIMIT = 1500;  // ms
  const MAX_MATCHES = 1000;

  // ------------------------------------------------------------------ flavours
  // Support: true, false, or a string (supported, with a caveat)
  const F = {
    kql: { name: 'Defender XDR', engine: 'RE2', unanchored: true, backtracks: false, caseNote: 'matches regex is case-sensitive: turn on i to add (?i)' },
    yaral: { name: 'Google SecOps', engine: 'RE2', unanchored: true, backtracks: false, caseNote: 'UDM regex is case-sensitive: turn on i to add nocase' },
    spl: { name: 'Splunk', engine: 'PCRE2', unanchored: true, backtracks: true, caseNote: 'regex and rex are case-sensitive: turn on i to add (?i)' },
    elastic: { name: 'Elastic', engine: 'Lucene', unanchored: false, backtracks: false, caseNote: 'regex is case-sensitive: turn on i to use regex~ (EQL) or case_insensitive' },
    python: { name: 'Python', engine: 're', unanchored: true, backtracks: true, caseNote: '' },
    js: { name: 'JavaScript', engine: 'ECMAScript', unanchored: true, backtracks: true, caseNote: '' },
  };
  const FEATURES = [
    // key, label, kql, yaral, spl, elastic, python, js
    ['lookahead', 'Lookahead (?= (?!', false, false, true, false, true, true],
    ['lookbehind', 'Lookbehind (?<= (?<!', false, false, 'fixed or bounded length', false, 'fixed length only', true],
    ['backref', 'Back-reference \\1 \\k<name>', false, false, true, false, true, true],
    ['atomic', 'Atomic group (?>…)', false, false, true, false, 'Python 3.11+', false],
    ['possessive', 'Possessive quantifier *+ ++ ?+', false, false, true, false, 'Python 3.11+', false],
    ['inlineFlags', 'Inline flags (?i) (?s) (?m)', true, true, true, false, 'at the start only', false],
    ['scopedFlags', 'Scoped flags (?i:…)', true, true, true, false, true, false],
    ['namedP', 'Named group (?P<name>…)', true, true, true, false, true, false],
    ['namedAngle', 'Named group (?<name>…)', 'recent RE2; (?P<name>) is safer', 'recent RE2; (?P<name>) is safer', true, false, false, true],
    ['namedQuote', "Named group (?'name'…)", false, false, true, false, false, false],
    ['group', 'Capturing group (…)', true, true, true, 'grouping only', true, true],
    ['unicodeProp', 'Unicode class \\p{L}', true, true, true, false, false, true],
    ['absAnchors', 'String anchors \\A \\z', true, true, true, false, '\\A and \\Z (not \\z)', false],
    ['endZ', 'End before final newline \\Z', false, false, true, false, 'end of string', false],
    ['contG', 'Continue anchor \\G', false, false, true, false, false, false],
    ['quote', 'Literal run \\Q…\\E', true, true, true, false, false, false],
    ['comment', 'Comment (?#…)', false, false, true, false, true, false],
    ['conditional', 'Conditional (?(1)…|…)', false, false, true, false, true, false],
    ['posix', 'POSIX class [[:alpha:]]', true, true, true, false, false, false],
    ['shorthand', 'Shorthand \\d \\w \\s', true, true, true, 'newer Lucene only; [0-9] is safe', true, true],
    ['lineAnchors', 'Anchors ^ $', true, true, true, false, true, true],
    ['wordBoundary', 'Word boundary \\b \\B', true, true, true, false, true, true],
    ['lazy', 'Lazy quantifier *? +? ??', true, true, true, false, true, true],
    ['bigRepeat', 'Repeat count over 1000 {n,m}', false, false, true, true, true, true],
  ];
  const ORDER = ['kql', 'yaral', 'spl', 'elastic', 'python', 'js'];
  const support = (feature, flavour) => {
    const row = FEATURES.find(r => r[0] === feature);
    return row ? row[2 + ORDER.indexOf(flavour)] : true;
  };

  // ------------------------------------------------------------------ tokeniser
  const CLASS_ESC = { d: 'a digit 0–9', D: 'not a digit', w: 'a word character (letter, digit, _)', W: 'not a word character',
    s: 'whitespace', S: 'not whitespace', h: 'horizontal whitespace', v: 'vertical whitespace' };
  const CHAR_ESC = { n: 'new line', r: 'carriage return', t: 'tab', f: 'form feed', e: 'escape', a: 'bell', '0': 'NUL' };
  const ANCHOR_ESC = { b: ['wordBoundary', 'a word boundary'], B: ['wordBoundary', 'not a word boundary'],
    A: ['absAnchors', 'the start of the text'], z: ['absAnchors', 'the end of the text'],
    Z: ['endZ', 'the end of the text, or before a final new line'], G: ['contG', 'where the last match ended'] };

  function tokenise(p) {
    const out = [];
    const stack = [];
    let i = 0;
    const push = t => { t.depth = stack.length; out.push(t); return t; };
    while (i < p.length) {
      const start = i, c = p[i];
      if (c === '\\') {
        const n = p[i + 1];
        if (n === undefined) { push({ type: 'error', text: '\\', start, end: ++i, desc: 'a trailing backslash escapes nothing' }); break; }
        if (n === 'Q') {
          const close = p.indexOf('\\E', i + 2);
          const end = close < 0 ? p.length : close + 2;
          push({ type: 'quote', feature: 'quote', text: p.slice(i, end), literal: p.slice(i + 2, close < 0 ? p.length : close), start, end, desc: 'the literal text between \\Q and \\E' });
          i = end; continue;
        }
        if (n === 'p' || n === 'P') {
          const m = /^\\[pP](\{[^}]*\}|[A-Za-z])/.exec(p.slice(i));
          const text = m ? m[0] : p.slice(i, i + 2);
          push({ type: 'class', feature: 'unicodeProp', text, start, end: i += text.length, desc: `${n === 'P' ? 'not ' : ''}a character in Unicode class ${text.slice(2)}` });
          continue;
        }
        if (n === 'k') {
          const m = /^\\k(<[^>]*>|\{[^}]*\}|'[^']*')/.exec(p.slice(i));
          const text = m ? m[0] : '\\k';
          push({ type: 'backref', feature: 'backref', text, start, end: i += text.length, desc: `the text group ${text.slice(3, -1)} matched` });
          continue;
        }
        if (/[1-9]/.test(n)) {
          const m = /^\\[1-9]\d*/.exec(p.slice(i));
          push({ type: 'backref', feature: 'backref', text: m[0], start, end: i += m[0].length, desc: `the text group ${m[0].slice(1)} matched` });
          continue;
        }
        if (n === 'x') {
          const m = /^\\x(\{[0-9A-Fa-f]+\}|[0-9A-Fa-f]{2})/.exec(p.slice(i));
          const text = m ? m[0] : '\\x';
          push({ type: 'char', text, start, end: i += text.length, desc: m ? `the character with code 0x${text.replace(/[\\x{}]/g, '')}` : 'an incomplete hex escape' });
          continue;
        }
        if (n === 'u') {
          const m = /^\\u([0-9A-Fa-f]{4}|\{[0-9A-Fa-f]+\})/.exec(p.slice(i));
          const text = m ? m[0] : '\\u';
          push({ type: 'char', text, start, end: i += text.length, desc: m ? `the character U+${text.replace(/[\\u{}]/g, '').toUpperCase()}` : 'an incomplete Unicode escape' });
          continue;
        }
        i += 2;
        const text = p.slice(start, i);
        if (CLASS_ESC[n]) push({ type: 'class', feature: 'shorthand', text, start, end: i, desc: CLASS_ESC[n] });
        else if (ANCHOR_ESC[n]) push({ type: 'anchor', feature: ANCHOR_ESC[n][0], text, start, end: i, desc: ANCHOR_ESC[n][1] });
        else if (CHAR_ESC[n]) push({ type: 'char', text, start, end: i, desc: CHAR_ESC[n] });
        else if (/[A-Za-z]/.test(n)) push({ type: 'char', text, start, end: i, unknownEscape: true, desc: `\\${n}: not an escape most engines know` });
        else push({ type: 'literal', text, char: n, start, end: i, desc: `the character ${n}` });
        continue;
      }
      if (c === '[') {
        let j = i + 1;
        if (p[j] === '^') j++;
        if (p[j] === ']') j++;  // a leading ] is literal
        let posix = false;
        while (j < p.length && p[j] !== ']') {
          if (p[j] === '\\') j += 2;
          else if (p[j] === '[' && p[j + 1] === ':') { const k = p.indexOf(':]', j + 2); if (k > 0) { posix = true; j = k + 2; } else j++; }
          else j++;
        }
        if (j >= p.length) { push({ type: 'error', text: p.slice(i), start, end: p.length, desc: 'a character class with no closing ]' }); i = p.length; break; }
        const text = p.slice(i, j + 1);
        const t = push({ type: 'set', text, start, end: j + 1, negated: text[1] === '^', desc: describeSet(text) });
        if (posix) t.feature = 'posix';
        i = j + 1; continue;
      }
      if (c === '(') {
        const rest = p.slice(i);
        let m, t;
        if ((m = /^\(\?#[^)]*\)/.exec(rest))) { push({ type: 'comment', feature: 'comment', text: m[0], start, end: i += m[0].length, desc: 'a comment (ignored)' }); continue; }
        if ((m = /^\(\?P<([A-Za-z_]\w*)>/.exec(rest))) t = { type: 'open', feature: 'namedP', capture: true, name: m[1], desc: `start of group "${m[1]}"` };
        else if ((m = /^\(\?<([A-Za-z_]\w*)>/.exec(rest))) t = { type: 'open', feature: 'namedAngle', capture: true, name: m[1], desc: `start of group "${m[1]}"` };
        else if ((m = /^\(\?'([A-Za-z_]\w*)'/.exec(rest))) t = { type: 'open', feature: 'namedQuote', capture: true, name: m[1], desc: `start of group "${m[1]}"` };
        else if ((m = /^\(\?P=([A-Za-z_]\w*)\)/.exec(rest))) { push({ type: 'backref', feature: 'backref', text: m[0], start, end: i += m[0].length, desc: `the text group "${m[1]}" matched` }); continue; }
        else if ((m = /^\(\?<=/.exec(rest))) t = { type: 'open', feature: 'lookbehind', look: true, desc: 'start of a lookbehind: what comes before must match' };
        else if ((m = /^\(\?<!/.exec(rest))) t = { type: 'open', feature: 'lookbehind', look: true, desc: 'start of a negative lookbehind: what comes before must not match' };
        else if ((m = /^\(\?=/.exec(rest))) t = { type: 'open', feature: 'lookahead', look: true, desc: 'start of a lookahead: what follows must match' };
        else if ((m = /^\(\?!/.exec(rest))) t = { type: 'open', feature: 'lookahead', look: true, desc: 'start of a negative lookahead: what follows must not match' };
        else if ((m = /^\(\?>/.exec(rest))) t = { type: 'open', feature: 'atomic', desc: 'start of an atomic group: no backtracking into it' };
        else if ((m = /^\(\?\((?:\d+|<\w+>|\w+)\)/.exec(rest))) t = { type: 'open', feature: 'conditional', desc: 'start of a conditional: one branch if the group matched, the other if not' };
        else if ((m = /^\(\?([imsxU]*)(?:-([imsxU]*))?\)/.exec(rest)) && (m[1] || m[2])) {
          push({ type: 'flags', feature: 'inlineFlags', text: m[0], on: m[1] || '', off: m[2] || '', start, end: i += m[0].length, desc: flagDesc(m[1], m[2]) });
          continue;
        } else if ((m = /^\(\?([imsxU]*)(?:-([imsxU]*))?:/.exec(rest)) && (m[1] || m[2])) t = { type: 'open', feature: 'scopedFlags', on: m[1], off: m[2] || '', desc: `start of a group with ${flagDesc(m[1], m[2])}` };
        else if ((m = /^\(\?:/.exec(rest))) t = { type: 'open', desc: 'start of a non-capturing group' };
        else if ((m = /^\(\?/.exec(rest))) { push({ type: 'error', text: '(?', start, end: i += 2, desc: 'an unknown group type' }); stack.push(null); continue; }
        else { m = ['(']; t = { type: 'open', feature: 'group', capture: true, desc: 'start of a capturing group' }; }
        t.text = m[0]; t.start = start; t.end = i += m[0].length;
        if (t.capture) t.number = out.filter(x => x.capture).length + 1;
        if (t.number) t.desc = t.desc.replace('start of', `start of group ${t.number}${t.name ? ',' : ':'}`).replace(/group (\d+), group "/, 'group $1, "');
        push(t); stack.push(t);
        continue;
      }
      if (c === ')') {
        const open = stack.pop();
        if (open === undefined) { push({ type: 'error', text: ')', start, end: ++i, desc: 'a ) with no matching (' }); continue; }
        const t = { type: 'close', text: ')', start, end: ++i, open, desc: open && open.number ? `end of group ${open.number}` : 'end of the group' };
        t.depth = stack.length; out.push(t);
        continue;
      }
      if ('*+?{'.includes(c)) {
        let m = /^(\*|\+|\?|\{\d+(?:,\d*)?\})([?+]?)/.exec(p.slice(i));
        if (!m) {  // a { that isn't a quantifier is literal
          push({ type: 'literal', text: c, char: c, start, end: ++i, desc: `the character ${c}` });
          continue;
        }
        const prev = out[out.length - 1];
        const q = { type: 'quant', text: m[0], start, end: i += m[0].length, mode: m[2] === '?' ? 'lazy' : m[2] === '+' ? 'possessive' : 'greedy' };
        if (m[2] === '+') q.feature = 'possessive';
        else if (m[2] === '?') q.feature = 'lazy';
        const base = m[1];
        const nums = /\{(\d+)(?:(,)(\d*))?\}/.exec(base);
        q.min = base === '+' ? 1 : base === '*' || base === '?' ? 0 : +nums[1];
        q.max = base === '?' ? 1 : base === '*' || base === '+' ? Infinity : nums[2] ? (nums[3] === '' ? Infinity : +nums[3]) : +nums[1];
        if ((q.max !== Infinity && q.max > 1000) || q.min > 1000) q.big = true;
        if (!prev || ['open', 'alt', 'quant', 'flags'].includes(prev.type) || (prev.type === 'anchor' && prev.text !== '$')) {
          q.type = 'error'; q.desc = `${m[0]} has nothing to repeat`;
        } else {
          const what = q.min === q.max ? `exactly ${q.min} time${q.min === 1 ? '' : 's'}`
            : q.max === Infinity ? `${q.min} or more times` : `between ${q.min} and ${q.max} times`;
          q.desc = `repeat the previous item ${what}${q.mode === 'lazy' ? ', as few as possible' : q.mode === 'possessive' ? ', never giving any back' : ', as many as possible'}`;
          q.target = prev;
        }
        push(q);
        continue;
      }
      if (c === '|') { push({ type: 'alt', text: '|', start, end: ++i, desc: 'or' }); continue; }
      if (c === '^') { push({ type: 'anchor', feature: 'lineAnchors', text: '^', start, end: ++i, desc: 'the start of the text (of each line with m)' }); continue; }
      if (c === '$') { push({ type: 'anchor', feature: 'lineAnchors', text: '$', start, end: ++i, desc: 'the end of the text (of each line with m)' }); continue; }
      if (c === '.') { push({ type: 'dot', text: '.', start, end: ++i, desc: 'any character (except a new line, unless s)' }); continue; }
      push({ type: 'literal', text: c, char: c, start, end: ++i, desc: c === ' ' ? 'a space' : `the character ${c}` });
    }
    stack.filter(Boolean).forEach(open => out.push({ type: 'error', text: '', start: open.start, end: open.end, depth: 0, desc: `${open.text} is never closed` }));
    return out;
  }

  function flagDesc(on = '', off = '') {
    const names = { i: 'case-insensitive', m: 'multi-line', s: 'dot matches new lines', x: 'free-spacing', U: 'lazy by default' };
    const parts = [...on].map(f => names[f]).concat([...off].map(f => `not ${names[f]}`));
    return `flags: ${parts.join(', ')}`;
  }

  function describeSet(text) {
    const body = text.slice(text[1] === '^' ? 2 : 1, -1);
    return `${text[1] === '^' ? 'any character except' : 'one of'}: ${body.length > 40 ? body.slice(0, 40) + '…' : body}`;
  }

  // ------------------------------------------------------------------ translation to JavaScript
  function toJs(tokens, flags) {
    let src = '', f = new Set(flags);
    const untestable = [];
    for (const t of tokens) {
      if (t.type === 'error') return { error: t.desc };
      if (t.type === 'flags') {
        if (t.start === 0 || tokens.indexOf(t) === 0) { [...t.on].forEach(x => 'ims'.includes(x) && f.add(x)); [...t.off].forEach(x => f.delete(x)); }
        else untestable.push(`${t.text} part-way through`);
        if (/[xU]/.test(t.on)) untestable.push(`(?${t.on.replace(/[ims]/g, '')})`);
        continue;
      }
      if (t.type === 'comment') continue;
      if (t.type === 'quote') { src += t.literal.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'); continue; }
      if (t.feature === 'namedP' || t.feature === 'namedQuote') { src += `(?<${t.name}>`; continue; }
      if (t.feature === 'scopedFlags') { src += '(?:'; untestable.push(`${t.text} (tested without its flags)`); continue; }
      if (t.type === 'backref' && /^\(\?P=/.test(t.text)) { src += `\\k<${t.text.slice(4, -1)}>`; continue; }
      if (t.type === 'backref' && /^\\k[{']/.test(t.text)) { src += `\\k<${t.text.slice(3, -1)}>`; continue; }
      if (t.text === '\\A') { src += '(?<![\\s\\S])'; continue; }
      if (t.text === '\\z') { src += '(?![\\s\\S])'; continue; }
      if (t.text === '\\Z') { src += '(?=\\n?(?![\\s\\S]))'; continue; }
      if (t.feature === 'posix') {
        const P = { alpha: 'A-Za-z', digit: '0-9', alnum: 'A-Za-z0-9', upper: 'A-Z', lower: 'a-z', space: '\\s', xdigit: '0-9A-Fa-f', punct: '!-\\/:-@\\[-`{-~', word: '\\w' };
        src += t.text.replace(/\[:(\w+):\]/g, (_, n) => P[n] || '');
        continue;
      }
      if (t.feature === 'possessive' || t.feature === 'atomic' || t.feature === 'contG' || t.feature === 'conditional') {
        untestable.push(t.text); return { untestable };
      }
      if (t.type === 'char' && t.unknownEscape) { src += t.text.slice(1); continue; }
      if (t.type === 'char' && /^\\x\{/.test(t.text)) { src += `\\u{${t.text.slice(3, -1)}}`; f.add('u'); continue; }
      if (t.feature === 'unicodeProp') f.add('u');
      src += t.text;
    }
    return { src, flags: [...f].filter(x => 'imsu'.includes(x)).join(''), untestable };
  }

  // ------------------------------------------------------------------ checks
  const WIN_DIRS = /\\(Windows|System32|SysWOW64|Users|ProgramData|Program Files|Temp|AppData|Local|Roaming|Microsoft|Device|HarddiskVolume\d*|Start Menu|Startup|Tasks|Prefetch)\b/i;

  function checks(pattern, tokens, flags, flavour) {
    const out = [];
    const add = (level, text) => out.push({ level, text });
    const fl = F[flavour];
    tokens.filter(t => t.type === 'error').forEach(t => add('error', `Won't compile: ${t.desc}.`));

    // What this flavour can't do
    const seen = new Set();
    tokens.forEach(t => {
      const feature = t.feature || (t.type === 'quant' && t.big ? 'bigRepeat' : null);
      const features = [feature, t.big ? 'bigRepeat' : null].filter(Boolean);
      features.forEach(k => {
        if (seen.has(k)) return;
        seen.add(k);
        const s = support(k, flavour);
        const label = FEATURES.find(r => r[0] === k)[1];
        if (k === 'inlineFlags' && flavour === 'python') return;  // its own check below
        if (s === false) add('error', `${fl.name} (${fl.engine}) doesn't support ${label[0].toLowerCase() + label.slice(1)}: ${t.text}`);
        else if (typeof s === 'string') add(k === 'group' ? 'info' : 'warn', `${label} in ${fl.name}: ${s}.`);
      });
    });
    const firstFlags = tokens.findIndex(t => t.type === 'flags');
    if (flavour === 'python' && firstFlags > 0) add('error', 'Python only accepts inline flags such as (?i) at the very start of the pattern.');

    // Windows paths written with single backslashes
    const path = WIN_DIRS.exec(pattern);
    if (path && !/\\\\/.test(pattern.slice(Math.max(0, path.index - 1), path.index + 2))) {
      add('error', `${path[0]} reads as the regex escape \\${path[1][0]} followed by "${path[1].slice(1)}", not a backslash and "${path[1]}". Write \\\\${path[1]}.`);
    }
    tokens.filter(t => t.unknownEscape).forEach(t => add(flavour === 'spl' || flavour.startsWith('k') || flavour === 'yaral' ? 'error' : 'warn',
      `${t.text} isn't an escape ${fl.engine} knows${flavour === 'js' ? ' (JavaScript reads it as the letter alone)' : ''}. For a backslash, write \\\\.`));

    // Unescaped dots in file names and domains
    const dots = tokens.filter((t, i) => t.type === 'dot' && tokens[i - 1] && tokens[i + 1]
      && /^[A-Za-z0-9]$/.test(tokens[i - 1].char || '') && /^[A-Za-z0-9]$/.test(tokens[i + 1].char || ''));
    if (dots.length) {
      const sample = dots.slice(0, 3).map(d => pattern.slice(Math.max(0, d.start - 4), d.end + 3)).join(', ');
      add('warn', `An unescaped . matches any character (${sample}): "cmd.exe" also matches "cmdxexe". Write \\. for a literal dot.`);
    }

    // Matches everything
    const js = toJs(tokens, flags);
    if (js.src !== undefined && !js.error) {
      try {
        if (new RegExp(js.src, js.flags).test('')) add('error', 'It matches an empty string, so it matches every event. Check for an empty alternative (a|), a trailing |, or everything being optional.');
      } catch (e) { /* reported by the matcher */ }
    }
    const alts = tokens.filter(t => t.type === 'alt');
    if (alts.some((a, i) => { const n = tokens[tokens.indexOf(a) + 1]; return !n || n.type === 'alt' || n.type === 'close'; })
        || tokens.some((t, i) => t.type === 'open' && tokens[i + 1] && tokens[i + 1].type === 'alt')) {
      add('warn', 'An empty alternative (| at the start or end of a group, or ||) matches nothing, so the group can match without its text.');
    }
    if (alts.some(a => a.depth === 0) && (tokens[0] && tokens[0].text === '^' || (tokens[tokens.length - 1] || {}).text === '$')) {
      add('warn', '^ and $ only bind to the first and last alternatives: ^a|b$ is (^a)|(b$). Group them: ^(?:a|b)$.');
    }

    // Anchoring: most SIEMs search inside the value; Elastic matches the whole of it
    const lead = /^(\(\?[a-zA-Z]+\))?\.\*/.test(pattern), trail = /\.\*\$?$/.test(pattern) && !/\\\.\*\$?$/.test(pattern);
    if (fl.unanchored && (lead || trail)) add('info', `${fl.name} finds the pattern anywhere in the value, so ${lead && trail ? 'the leading and trailing' : lead ? 'a leading' : 'a trailing'} .* adds nothing but work.`);
    if (!fl.unanchored) {
      if (!lead || !trail) add('info', 'Elastic matches the whole value, as if the pattern were wrapped in ^…$. To match anywhere in it, start and end with .*');
    }

    // Backtracking: nested quantifiers
    const nested = tokens.some(q => q.type === 'quant' && q.max > 1 && q.target && q.target.type === 'close'
      && tokens.slice(tokens.indexOf(q.target.open), tokens.indexOf(q.target)).some(t => t.type === 'quant' && t.max > 1));
    if (nested) {
      add(fl.backtracks ? 'warn' : 'info', fl.backtracks
        ? `A repeated group containing a repeat, like (a+)+, can take exponential time on a near-miss in ${fl.engine}. Make the inner part unambiguous, or use a possessive quantifier or atomic group.`
        : `A repeated group containing a repeat, like (a+)+, would backtrack badly elsewhere; ${fl.engine} doesn't backtrack, so it's safe here.`);
    }
    if (/\.\*.*\.\*/.test(pattern) && fl.backtracks) add('info', 'Several .* in one pattern backtrack a lot on long values. Use a narrower class, such as [^\\\\]* within a path, where you can.');

    // Classes
    tokens.filter(t => t.type === 'set' && /A-z/.test(t.text)).forEach(t => add('warn', `${t.text}: A-z also includes [ \\ ] ^ _ and \`. Use A-Za-z.`));
    tokens.filter(t => t.type === 'set' && /^\[\^?\|/.test(t.text) === false && /\w\|\w/.test(t.text)).forEach(t =>
      add('warn', `${t.text}: | inside [ ] is a literal |, not "or". Use (?:a|b) for alternatives.`));

    // Case sensitivity for Windows artefacts
    const caseless = flags.includes('i') || tokens.some(t => (t.type === 'flags' || t.feature === 'scopedFlags') && (t.on || '').includes('i'));
    if (!caseless && /\\\\|\.exe|\.dll|\.ps1|\.bat|\.vbs|powershell|cmd|rundll32|regsvr32/i.test(pattern)) {
      add('info', `Windows file names, paths and switches aren't case-sensitive, but ${fl.name}${fl.caseNote ? `'s ${fl.caseNote.split(':')[0]}` : ' matching is'}. Turn on i unless the case matters.`);
    }
    if (!out.some(o => o.level === 'error')) add('ok', out.some(o => o.level === 'warn')
      ? `No errors for ${fl.name} (${fl.engine}); the warnings above are worth a look.` : `No problems for ${fl.name} (${fl.engine}).`);
    return out;
  }

  // ------------------------------------------------------------------ copy as
  function snippets(pattern, flags) {
    const i = flags.includes('i'), extra = (flags.includes('m') ? 'm' : '') + (flags.includes('s') ? 's' : '');
    const inline = (i ? 'i' : '') + extra;
    const withInline = inline && !/^\(\?[a-zA-Z]+\)/.test(pattern) ? `(?${inline})${pattern}` : pattern;
    // Triple-quoted (raw) strings, unless the pattern would close them early
    const triple = v => /"""|"$/.test(v) ? `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : `"""${v}"""`;
    return [
      ['Defender XDR (KQL)', `| where ProcessCommandLine matches regex @"${withInline.replace(/"/g, '""')}"`],
      // UDM Search: a /regex/ literal, so an unescaped / in the pattern is escaped
      ['Google SecOps (UDM search)', `target.process.command_line = /${udmSlash((extra ? `(?${extra})` : '') + pattern)}/${i ? ' nocase' : ''}`],
      ['Splunk (SPL)', `| regex CommandLine="${withInline.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`],
      ['Elastic (EQL)', `process where process.command_line regex${i ? '~' : ''} ${triple(pattern)}`],
      ['Elastic (ES|QL)', i ? `| WHERE TO_LOWER(process.command_line) RLIKE ${triple(pattern)}  // RLIKE has no (?i): write the pattern's letters in lower case`
        : `| WHERE process.command_line RLIKE ${triple(pattern)}`],
      ['Python', `re.compile(r${pattern.includes('"') ? "'" : '"'}${pattern}${pattern.includes('"') ? "'" : '"'}${flags ? ', ' + [...flags].map(f => ({ i: 're.I', m: 're.M', s: 're.S' })[f]).join(' | ') : ''})`],
      ['JavaScript', `/${pattern.replace(/\//g, '\\/')}/${flags}`],
    ];
  }

  // ------------------------------------------------------------------ matching (in a worker)
  // RE2 flavours run in RE2 and Splunk in PCRE2 (regex_worker.js); the rest in JavaScript
  // A / ends a UDM /regex/ literal unless escaped; escapes are followed pair by pair
  function udmSlash(p) {
    let out = '', esc = false;
    for (const ch of p) { if (ch === '/' && !esc) out += '\\'; out += ch; esc = ch === '\\' && !esc; }
    return out;
  }

  const ENGINE = { kql: 're2', yaral: 're2', spl: 'pcre2' };
  const workerUrl = (document.currentScript && document.currentScript.src || location.href).replace(/regex\.js(\?[^/]*)?$/, 'regex_worker.js$1');
  let worker = null, timer = null, runId = 0;

  function runMatch(job) {
    return new Promise(resolve => {
      if (worker) worker.terminate();
      clearTimeout(timer);
      const id = ++runId;
      worker = new Worker(workerUrl);
      worker.onmessage = e => { if (id === runId) { clearTimeout(timer); resolve(e.data); } };
      worker.onerror = e => { if (id === runId) { clearTimeout(timer); resolve({ error: e.message }); } };
      // Loading PCRE2 the first time takes a moment; the limit is for matching
      const limit = job.engine === 'pcre2' ? TIME_LIMIT + 3000 : TIME_LIMIT;
      timer = setTimeout(() => { worker.terminate(); worker = null; if (id === runId) resolve({ timeout: true }); }, limit);
      worker.postMessage({ ...job, max: MAX_MATCHES });
    });
  }

  // ------------------------------------------------------------------ rendering
  let flavour = 'kql';
  const flagsOn = () => [...document.querySelectorAll('[data-flag]')].filter(b => b.checked).map(b => b.dataset.flag).join('');

  function renderExplain(tokens) {
    const box = $('rx-explain');
    if (!tokens.length) { box.innerHTML = '<li class="rx-empty">Nothing to explain yet.</li>'; return; }
    // Runs of literal characters read as one item ("the text psexec"), except the last
    // character before a quantifier, which the quantifier applies to on its own
    const items = [];
    tokens.filter(t => t.text || t.type === 'error').forEach((t, n, all) => {
      const prev = items[items.length - 1], next = all[n + 1];
      const joinable = t.type === 'literal' && !(next && next.type === 'quant');
      if (joinable && prev && prev.run && prev.depth === t.depth) {
        prev.text += t.text; prev.chars += t.char;
        prev.desc = `the text ${prev.chars}`;
      } else {
        items.push(joinable ? { ...t, run: true, chars: t.char } : t);
      }
    });
    box.innerHTML = items.map(t => {
      const s = t.feature && support(t.feature, flavour) === false ? ' is-unsupported' : '';
      return `<li class="rx-tok rx-${t.type}${s}" style="--depth:${t.depth || 0}"><code>${esc(t.text || '∅')}</code><span>${esc(t.desc)}</span></li>`;
    }).join('');
  }

  function renderChecks(list) {
    const icon = { error: '✕', warn: '!', info: 'i', ok: '✓' };
    $('rx-findings').innerHTML = list.map(f => `<li class="rx-f is-${f.level}"><span class="rx-f-icon" aria-hidden="true">${icon[f.level]}</span><span>${esc(f.text)}</span></li>`).join('');
    const problems = list.filter(f => f.level === 'error' || f.level === 'warn').length;
    $('rx-check-count').textContent = problems ? `${problems} to look at` : '';
  }

  function renderCopy(pattern, flags) {
    if (!pattern) { $('rx-copy').innerHTML = '<p class="rx-empty">Type a pattern.</p>'; return; }
    $('rx-copy').innerHTML = snippets(pattern, flags).map(([name, code], n) => `<div class="rx-snip">
      <div class="rx-snip-head"><strong>${esc(name)}</strong><button type="button" class="rx-copy-btn" data-i="${n}">Copy</button></div>
      <pre><code>${esc(code)}</code></pre></div>`).join('');
    const all = snippets(pattern, flags);
    $('rx-copy').querySelectorAll('.rx-copy-btn').forEach(b => b.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(all[+b.dataset.i][1]); b.textContent = 'Copied'; setTimeout(() => { b.textContent = 'Copy'; }, 1200); } catch (e) { /* clipboard blocked */ }
    }));
  }

  function renderBackdrop(text, matches) {
    let html = '', at = 0;
    for (const m of matches) {
      if (m.i < at) continue;
      html += esc(text.slice(at, m.i));
      const end = m.i + m.t.length;
      if (m.t === '') { html += '<mark class="rx-zero"></mark>'; at = m.i; continue; }
      // Groups inside the match, outermost first, non-overlapping
      let inner = '', pos = m.i;
      const spans = (m.d || []).map((d, k) => d && d[1] > d[0] ? { s: d[0], e: d[1], k } : null).filter(Boolean)
        .sort((a, b) => a.s - b.s || b.e - a.e);
      for (const g of spans) {
        if (g.s < pos) continue;
        inner += esc(text.slice(pos, g.s)) + `<span class="rx-g rx-g${g.k % 4}">${esc(text.slice(g.s, g.e))}</span>`;
        pos = g.e;
      }
      inner += esc(text.slice(pos, end));
      html += `<mark>${inner}</mark>`;
      at = end;
    }
    html += esc(text.slice(at));
    $('rx-backdrop').innerHTML = html + '\n';
  }

  function renderMatches(matches, tokens) {
    const box = $('rx-matches');
    if (!matches.length) { box.innerHTML = '<p class="rx-empty">No matches.</p>'; return; }
    const names = {};
    tokens.filter(t => t.capture).forEach(t => { if (t.name) names[t.number] = t.name; });
    box.innerHTML = matches.slice(0, 50).map((m, n) => `<div class="rx-match">
      <div class="rx-match-head">Match ${n + 1} <span>${m.i}–${m.i + m.t.length}</span></div>
      <code class="rx-match-text">${esc(m.t) || '<em>empty</em>'}</code>
      ${m.g.length ? `<dl>${m.g.map((g, k) => `<dt>Group ${k + 1}${names[k + 1] ? ` <em>${esc(names[k + 1])}</em>` : ''}</dt><dd>${g === undefined ? '<em>not matched</em>' : `<code>${esc(g)}</code>`}</dd>`).join('')}</dl>` : ''}
    </div>`).join('') + (matches.length > 50 ? `<p class="rx-note">and ${matches.length - 50} more.</p>` : '');
  }

  function renderSupport() {
    $('rx-support').innerHTML = `<thead><tr><th>Construct</th>${ORDER.map(k => `<th>${esc(F[k].name)}<span>${esc(F[k].engine)}</span></th>`).join('')}</tr></thead>
      <tbody>${FEATURES.map(r => `<tr><td>${esc(r[1])}</td>${r.slice(2).map(v => `<td class="${v === true ? 'is-yes' : v === false ? 'is-no' : 'is-part'}">${v === true ? 'Yes' : v === false ? 'No' : esc(v)}</td>`).join('')}</tr>`).join('')}
      <tr><td>Where it matches</td>${ORDER.map(k => `<td class="is-part">${F[k].unanchored ? 'Anywhere in the value' : 'The whole value'}</td>`).join('')}</tr>
      <tr><td>Backtracking (can hang)</td>${ORDER.map(k => `<td class="${F[k].backtracks ? 'is-part' : 'is-yes'}">${F[k].backtracks ? 'Yes' : 'No, linear time'}</td>`).join('')}</tr></tbody>`;
  }

  async function update() {
    const pattern = $('rx-pattern').value, text = $('rx-text').value, flags = flagsOn();
    const replaceRaw = $('rx-replace').value;
    save();
    const perLine = flavour === 'elastic';
    $('rx-test-note').textContent = perLine ? 'Elastic matches a whole value: each line is tested as one value.' : '';
    if (!pattern) {
      $('rx-status').textContent = 'Type a pattern.';
      $('rx-status').className = 'rx-status';
      renderExplain([]); renderChecks([]); renderCopy('', flags);
      $('rx-matches').innerHTML = ''; $('rx-count').textContent = ''; $('rx-replaced').textContent = '';
      renderBackdrop(text, []);
      return;
    }
    const tokens = tokenise(pattern);
    renderExplain(tokens);
    renderChecks(checks(pattern, tokens, flags, flavour));
    renderCopy(pattern, flags);
    const js = toJs(tokens, flags);
    const status = $('rx-status');
    const engine = ENGINE[flavour] || 'js';
    const clear = () => { renderBackdrop(text, []); $('rx-matches').innerHTML = ''; $('rx-count').textContent = ''; $('rx-replaced').textContent = ''; };
    if (engine === 'js' && (js.error || js.untestable && js.src === undefined)) {
      status.textContent = js.error ? `Won't compile: ${js.error}` : `Can't be run in the browser: ${js.untestable.join(', ')} has no JavaScript equivalent. The checks still apply.`;
      status.className = 'rx-status is-bad';
      clear();
      return;
    }
    const r = await runMatch({ engine, pattern, src: js.src, flags: engine === 'js' ? js.flags : flags, text, perLine,
      replace: replaceRaw ? replaceRaw : null });
    if (r.timeout) {
      status.textContent = `Stopped after ${TIME_LIMIT / 1000}s: the pattern backtracks without end on this text. In PCRE, Python or JavaScript that would hang the search; RE2 would finish.`;
      status.className = 'rx-status is-bad';
      clear();
      return;
    }
    if (r.error) {
      status.textContent = `Won't compile in ${r.engine === 're2' ? 'RE2' : r.engine === 'pcre2' ? 'PCRE2' : 'JavaScript'}: ${r.error}`;
      status.dataset.for = `${flavour}|${pattern}|${text}`;
      status.className = 'rx-status is-bad';
      clear();
      return;
    }
    const approx = engine === 'js' && flavour !== 'js'
      ? ` ${F[flavour].engine} has no engine in the browser: run as JavaScript${js.untestable && js.untestable.length ? `, approximately (${js.untestable.join(', ')})` : ', translated where it spells something differently'}.`
      : '';
    const limit = r.limit ? ` Stopped at Splunk's ${r.limit} (limits.conf [rex]): Splunk would stop this search with an error.` : '';
    status.textContent = `Compiles. Matched with ${r.engine}.${approx}${limit}`;
    status.dataset.for = `${flavour}|${pattern}|${text}`;  // which input this status is for (tests wait on it)
    status.className = r.limit ? 'rx-status is-bad' : 'rx-status is-ok';
    $('rx-count').textContent = `${r.matches.length}${r.matches.length >= MAX_MATCHES ? '+' : ''} match${r.matches.length === 1 ? '' : 'es'}`;
    renderBackdrop(text, r.matches);
    renderMatches(r.matches, tokens);
    $('rx-replaced').textContent = r.replaced === null ? '' : r.replaced;
  }

  // ------------------------------------------------------------------ state
  function save() {
    try {
      localStorage.setItem(STORE, JSON.stringify({ flavour, pattern: $('rx-pattern').value, text: $('rx-text').value,
        replace: $('rx-replace').value, flags: flagsOn() }));
    } catch (e) { /* storage unavailable */ }
  }
  function restore() {
    let s = null;
    try { s = JSON.parse(localStorage.getItem(STORE) || 'null'); } catch (e) { s = null; }
    s = s || {
      flavour: 'kql', flags: 'i', replace: '',
      pattern: '\\\\(?:psexec|paexec)(?:64)?\\.exe\\s+\\\\\\\\(?P<host>[^\\\\\\s]+)',
      text: 'C:\\Tools\\PsExec64.exe \\\\FS01 -accepteula -s cmd.exe\nC:\\Windows\\System32\\cmd.exe /c whoami\nC:\\ProgramData\\paexec.exe \\\\DC02 -s powershell.exe -enc SQBFAFgA',
    };
    flavour = F[s.flavour] ? s.flavour : 'kql';
    $('rx-pattern').value = s.pattern || '';
    $('rx-text').value = s.text || '';
    $('rx-replace').value = s.replace || '';
    document.querySelectorAll('[data-flag]').forEach(b => { b.checked = (s.flags || '').includes(b.dataset.flag); });
    document.querySelectorAll('.rx-flavour').forEach(b => {
      b.classList.toggle('is-active', b.dataset.flavour === flavour);
      b.setAttribute('aria-checked', String(b.dataset.flavour === flavour));
    });
  }

  let pending = null;
  const later = () => { clearTimeout(pending); pending = setTimeout(update, 120); };
  ['rx-pattern', 'rx-text', 'rx-replace'].forEach(id => $(id).addEventListener('input', later));
  document.querySelectorAll('[data-flag]').forEach(b => b.addEventListener('change', update));
  document.querySelectorAll('.rx-flavour').forEach(b => b.addEventListener('click', () => {
    flavour = b.dataset.flavour;
    document.querySelectorAll('.rx-flavour').forEach(x => {
      x.classList.toggle('is-active', x === b);
      x.setAttribute('aria-checked', String(x === b));
    });
    update();
  }));
  // Keep the highlights under the text as it scrolls and resizes
  const text = $('rx-text'), back = $('rx-backdrop');
  text.addEventListener('scroll', () => { back.scrollTop = text.scrollTop; back.scrollLeft = text.scrollLeft; });
  new ResizeObserver(() => { back.style.height = `${text.offsetHeight}px`; }).observe(text);

  // For tests and the console: the pure parts
  window.archerRegex = { tokenise, toJs, checks: (p, f, fl) => checks(p, tokenise(p), f || '', fl || 'kql'), snippets };

  restore();
  renderSupport();
  update();
})();
