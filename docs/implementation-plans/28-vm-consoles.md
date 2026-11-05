# In-browser VM consoles for team-server set-ups (#28)

Give a team-server user an interactive shell on a lab machine from the browser, without SSH clients,
jump boxes or exposing the machines on the network. The machines already run on the host Shikari runs on
(Docker containers, Tart VMs, UTM VMs); this bridges a shell on them to an in-page terminal.

## Approach

A terminal in the browser (xterm.js) ↔ a WebSocket ↔ a forked PTY on the server that execs the engine's
own `exec` into the machine. No new daemon and no guest agent beyond what each engine already uses. Byte
stream both ways; a small JSON control frame carries terminal resizes.

```
browser (xterm.js)  ──WS /api/lab/console?engine=&name=──  server
                                                             │  pty.fork()
                                                             ▼
                              docker exec -it <name> sh      (fully interactive)
                              tart  exec    <name> sh        (best-effort tty)
                              utmctl exec --hide <name> …     (best-effort tty)
```

## Pieces (this increment)

- **`shikari/lab/console.py`**
  - `console_argv(engine, name, windows)` — pure, tested: the argv that opens an interactive shell
    (`docker exec -it`; Tart/UTM `exec`; POSIX `bash`-with-`sh`-fallback, or `powershell` on Windows).
  - `ConsoleSession` — `pty.fork()` + `execvpe`, non-blocking master fd, `read`/`write`/`resize`/`close`.
- **`WS /api/lab/console`** (`shikari/lab/web.py`) — gated by `_can_lab` + `_owns` (operational analyst /
  admin who owns the machine), exactly like every other lab action. Reads `engine`/`name` query params,
  infers Windows from the machine's OS (or a `-win` name), bridges fd ↔ socket with `loop.add_reader` and
  a sender queue, and tears the PTY down on disconnect.
- **`static/lab-console.html`** + vendored **`static/vendor/xterm/`** (xterm 5.3.0, MIT) — a standalone
  terminal page opened in a new tab from the Lab machine row ("Console", shown when the machine is
  running). The session cookie rides the same-origin WS handshake, so the page needs no auth of its own.
- **Lab UI** — a Console link per running machine in `static/js/lab.js`.

## Security

- Authorisation is the WebSocket's first act: reject with 4401 (not logged in / not operational) or 4403
  (not your machine) **before** `accept()`. Same `machines.can_manage` check as start/stop/delete.
- `name` is validated against a strict charset and passed as an argv element (never a shell string), so
  it can't inject. `engine` is allow-listed.
- A console is a real shell on a lab machine; lab machines can run live adversary emulation (CALDERA,
  atomics). Treat console access as privileged — it already requires the operational-analyst role.

## Reconnect & reaping (done)

A session registry (`shikari.lab.console.REGISTRY`) decouples the shell from the socket:

- Each session has an unguessable id and a capped scrollback ring (`RING_BYTES`). On connect the server
  sends `{"type":"session","sid":…}`; the page stores it in the URL.
- A dropped socket does **not** kill the shell — the session is *detached* and survives `DETACH_GRACE`
  (5 min) for a reconnect, which replays the scrollback. The client auto-reconnects (backoff, 10 tries)
  with `?sid=`, unless it got `{"type":"exit"}` (the shell itself ended).
- A daemon reaper closes sessions that exited, went idle past `IDLE_LIMIT` (30 min), or stayed detached
  past the grace window — so abandoned PTYs can't leak. A reconnect must still match owner+engine+name.

Covered by `tests/unit/test_lab_console.py` (ring trimming, reconnect identity check, expiry rules, reap).

## Graphical Windows / GUI console — the real blocker (not yet built)

A text PTY can't drive a Windows desktop; that needs a pixel protocol (VNC via noVNC, or SPICE via
spice-html5). The snag is **getting an endpoint out of UTM**:

- `utmctl` exposes `list/status/start/stop/exec/ip-address/clone/snapshot` — **no display/VNC/port
  command**. UTM's own viewer uses **SPICE**, not VNC/RFB, so noVNC (which speaks RFB) can't connect to a
  stock UTM VM, and Shikari has no API to discover a SPICE/VNC port either.
- So a graphical console can't be *auto-wired* to a UTM VM the way the text console is. Two sound paths:
  1. **User-provided VNC endpoint.** The VM is configured with a QEMU `-vnc` display (or any VNC target —
     a QEMU/Tart VM, a bare host), and its `host:port` is saved as trusted **per-machine config** (same
     pattern as the CALDERA server URL). Shikari then runs a WebSocket↔TCP bridge to *that* endpoint and
     serves noVNC. The port must come from trusted config, never client input (SSRF).
  2. **SPICE path.** Bridge UTM's SPICE socket to spice-html5 — more work, but matches UTM's default.
- Shippable foundation when we build it: a generic, SSRF-safe WS↔TCP proxy (bridges only to the stored
  per-machine endpoint) + vendored noVNC + a `vnc-console` page, reusing the same `_owns` gate. Testable
  against a local VNC server; the UTM-specific wiring is the environment-dependent part.

## Other follow-ups

- **Read-only / audited sessions** for shared review.

## Testing

- `tests/unit/test_lab_console.py` — pure coverage of `console_argv`/`valid_name`.
- The PTY bridge and WS need a real engine; verify manually against a running Docker container:
  create one in Emulate → Lab, click **Console**, confirm an interactive shell. Do live CALDERA/implant
  work inside `sbx`.
