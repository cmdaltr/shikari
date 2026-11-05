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

## Not in this increment (follow-ups)

- **Graphical Windows consoles.** `powershell` over the PTY is text-only and depends on the guest tool
  forwarding a tty. A proper Windows (or GUI) console wants VNC: UTM exposes a SPICE/VNC port, so a
  `websockify` → noVNC bridge, surfaced the same way, is the follow-up for `-win` machines.
- **Scrollback persistence / session reconnect**, and an idle timeout to reap abandoned PTYs.
- **Read-only / audited sessions** for shared review.

## Testing

- `tests/unit/test_lab_console.py` — pure coverage of `console_argv`/`valid_name`.
- The PTY bridge and WS need a real engine; verify manually against a running Docker container:
  create one in Emulate → Lab, click **Console**, confirm an interactive shell. Do live CALDERA/implant
  work inside `sbx`.
