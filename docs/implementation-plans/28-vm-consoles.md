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

## Graphical Windows / GUI console — VNC + SPICE (done)

A text PTY can't drive a Windows desktop; that needs a pixel protocol. Shikari supports both — **VNC**
(noVNC) and **SPICE** (spice-html5) — chosen per machine. The snag is **getting an endpoint out of UTM**:

- `utmctl` exposes `list/status/start/stop/exec/ip-address/clone/snapshot` — **no display/VNC/port
  command**. UTM's own viewer uses **SPICE** over an internal socket, so neither protocol can be
  *auto-wired* to a stock UTM VM, and Shikari has no API to discover the port.
- So the owner stands up the endpoint out-of-band and records it: a QEMU `-vnc` or `-spice port=` display,
  a Tart VM, or any VNC/SPICE server the Shikari host can reach. Its `host:port` + `kind` (vnc|spice) is
  saved as trusted per-machine config; Shikari bridges a WebSocket↔TCP to *that* endpoint and serves the
  matching client. The transport is a raw byte pump, identical for both protocols — only the client lib
  and the stored kind differ. (SPICE must be **single-port**: spice-html5 opens one WebSocket per channel
  to the same URL, so all SPICE channels must multiplex over the one port, e.g. QEMU `-spice port=N`.)

### Pieces (shipped)

- **`shikari/lab/desktop.py`** — `valid_endpoint(host, port)` (pure, tested: port 1-65535 and a
  loopback/private/link-local host or `localhost`; public addresses refused), `KINDS = ("vnc","spice")`,
  and an async protocol-agnostic `bridge(websocket, host, port)` (WS↔TCP byte pump via
  `asyncio.open_connection`).
- **`shikari/lab/registry.py`** — `set_desktop`/`get_desktop`/`clear_desktop` store `{host, port, kind}`
  on the machine's entry in `data/lab/machines.json` (upsert; survives re-record). `machines._decorate`
  surfaces `desktop: bool` and `desktop_kind` so the UI knows what's configured.
- **`WS /api/lab/desktop`** + **`GET`/`POST /api/lab/desktop-endpoint`** (`shikari/lab/web.py`) — same
  `_can_lab` + `_owns` gate as the text console (4401/4403 before `accept`; 4404 when no endpoint is set).
  The bridge resolves `host:port` from the registry by engine+name and **ignores any address in the
  request** — the SSRF guarantee. The accepted subprotocol is echoed back (noVNC asks for `binary`).
- **`static/lab-desktop.html`** + vendored **`static/vendor/novnc/`** (noVNC 1.4.0, MPL-2.0) and
  **`static/vendor/spice-html5/`** (spice-html5, LGPL-3.0+) — one standalone page opened from the machine
  row ("Desktop", shown when running). It reads the endpoint's kind and loads noVNC or spice-html5
  accordingly. If nothing is configured it shows a form (protocol + host + port; SPICE suggested for UTM),
  then connects; a trailing `*` on the link flags "not yet configured".
- **Lab UI** — a Desktop link per running machine in `static/js/lab.js`.

### Security

The endpoint is **trusted config set out-of-band by the owner**, never client input, so the bridge can't
be aimed at an arbitrary address. `valid_endpoint` is defence in depth: even a mis-set endpoint can't
reach the public internet. Everything else is the text console's model — owner/admin gate, strict name
validation, allow-listed engine.

### Testing

`tests/unit/test_lab_desktop.py` covers `valid_endpoint` (accept/refuse table) and the registry round-trip
(set/get/clear with kind, upsert preserves the rest of the entry). The live bridge needs a real target:
stand one up (VNC: `x11vnc`/`Xvnc` or a QEMU `-vnc 127.0.0.1:0` VM; SPICE: QEMU `-spice port=5930,addr=127.0.0.1,disable-ticketing=on`),
set it via the Desktop panel, and confirm the desktop renders. Do live VM work inside `sbx`.

## Other follow-ups

- **Read-only / audited sessions** for shared review.
- **Auto-discovering a UTM SPICE port** — UTM keeps SPICE on an internal socket with no `utmctl` way to
  surface it; if a future UTM/utmctl exposes one, the manual endpoint step could be skipped for UTM VMs.

## Testing

- `tests/unit/test_lab_console.py` — pure coverage of `console_argv`/`valid_name`.
- The PTY bridge and WS need a real engine; verify manually against a running Docker container:
  create one in Emulate → Lab, click **Console**, confirm an interactive shell. Do live CALDERA/implant
  work inside `sbx`.
