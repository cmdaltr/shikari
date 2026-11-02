# Regex

**Build → Regex** tests a regular expression against your own sample text and checks it for the SIEM it will run in. A pattern that works in one engine can fail to compile, match nothing, or match everything in another. This page catches that before the query reaches the SIEM.

Everything runs in your browser. Nothing you type is sent to Shikari or anywhere else. The page remembers your last pattern, text and flavour in your browser only.

## Using it

1. **Choose the flavour**: the SIEM (or language) the pattern is for.
2. **Type the pattern** between the slashes, and tick the flags you need: `i` case-insensitive, `m` multi-line (`^` and `$` at each line), `s` dot matches new lines.
3. **Paste test text**: command lines, paths or log lines, one per line. Matches are highlighted as you type, with capture groups shaded inside them.

| Panel | What it shows |
|---|---|
| Checks | Problems for the chosen flavour: errors (it won't compile or can't work), warnings (it works but probably not as meant), notes |
| Match information | Each match, where it is, and what each group captured, named groups included |
| Explanation | The pattern taken apart, one construct per line, indented by group |
| Substitution | The test text with each match replaced; `$1`, `\1`, `$<name>` and `\g<name>` all work |
| Use it in a query | The pattern written into a query for each SIEM, escaped for that SIEM's strings, with the flags in its own spelling |
| What each flavour supports | A table of constructs against flavours (collapsed; click its title) |

## The flavours

| Flavour | Engine | Where the regex runs | Matches | Tested with |
|---|---|---|---|---|
| Defender XDR | RE2 | `matches regex`, `extract()`, `replace_regex()` | Anywhere in the value | RE2 (re2js) |
| Google SecOps | RE2 | `re.regex()`, `re.capture()` in YARA-L | Anywhere in the value | RE2 (re2js) |
| Splunk | PCRE2 | `regex`, `rex`, `match()` | Anywhere in the value | PCRE2 10.49, with Splunk's limits |
| Elastic | Lucene regexp | EQL `regex`, ES\|QL `RLIKE`, the `regexp` query | **The whole value** | JavaScript, translated |
| Python | `re` | Shikari's own code, scripts | Anywhere (with `search`) | JavaScript, translated |
| JavaScript | ECMAScript | Browsers, Node | Anywhere | JavaScript |

The status line names the engine each result came from. Defender XDR and Google SecOps patterns run in re2js, the JavaScript port of Google's RE2/J, so a pattern RE2 refuses fails here with RE2's own message. Splunk patterns run in PCRE2 built to WebAssembly from the official release, with Splunk's default `[rex]` limits from `limits.conf` (`match_limit = 100000`, `depth_limit = 1000`). A pattern that reaches them is reported as Splunk would stop it.

RE2 never backtracks, so a pattern can't hang a Defender XDR or Google SecOps search. That's also why it has no lookarounds or back-references. PCRE, Python and JavaScript backtrack, and a badly nested pattern can take exponential time on a near-miss.

## What the checks look for

| Check | Example | Why it matters |
|---|---|---|
| Constructs the flavour can't compile | `(?<=…)` or `\1` in RE2; `^`, `$` or `(?i)` in Lucene | The query errors, or the rule won't save |
| Single backslashes in Windows paths | `C:\Windows\cmd.exe` | `\W` is "not a word character", so the path never matches as written. Write `\\` |
| Unknown escapes | `\T`, `\c` from a path | Some engines refuse them, others quietly read a different character |
| Unescaped dots | `cmd.exe` | `.` matches any character, so it also matches `cmdxexe` |
| Matches an empty string | `foo\|`, `(a\|)`, `.*` | Matches every event |
| `^` and `$` with alternation | `^a\|b$` | Means `(^a)\|(b$)`, not `^(a\|b)$` |
| Redundant `.*` at the ends | `.*mimikatz.*` in KQL | Adds work and nothing else where matching is already "anywhere" |
| Missing `.*` at the ends | `mimikatz` in Elastic | Elastic matches the whole value, so this only matches a value that is exactly `mimikatz` |
| Nested quantifiers | `(a+)+` | Catastrophic backtracking in PCRE, Python and JavaScript; harmless in RE2 |
| Repeat counts over 1000 | `a{1,2000}` | RE2 refuses them |
| `A-z` in a class | `[A-z]` | Also matches `[ \ ] ^ _` and the backtick |
| Case sensitivity | `powershell` with no `i` | Windows names and switches aren't case-sensitive, but most SIEM regex is |

## Limits

- Elastic and Python have no engine that runs in a browser. Their patterns run in JavaScript, translated where the flavour only spells something differently (`(?P<name>)`, a leading `(?i)`, `\A`, `\z`, `\Q…\E`, POSIX classes). Python constructs JavaScript can't express, such as possessive quantifiers and atomic groups, are checked but not run: the status line says so.
- Splunk's own PCRE2 build may differ in options from the one here (Unicode is on here); results for plain ASCII text are the same.
- The engines are vendored under `static/vendor/` with their licences. `scripts/build/pcre2_wasm/build.sh` rebuilds PCRE2 from the release, checked against its published SHA-256.
- Matching stops after 1.5 seconds, and reports that the pattern backtracks without end on that text.
- The checks cover common mistakes. They don't prove a pattern is right for your data: test it on real events in your SIEM before you deploy it.
