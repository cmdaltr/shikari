# Deploying Shikari as a team server

A **team server** is the central Shikari instance that browsers and desktop clients connect to. This
covers running it as a managed service on Linux (Ubuntu 22.04+, Debian 12+, Rocky/RHEL 9) and Windows
Server 2022+, with TLS, upgrades, backups and monitoring (#29).

For a single-user machine, `shikari start` or the desktop app is enough — you don't need any of this.

## What you get

| | Linux | Windows Server |
|---|---|---|
| Runs as | `shikari` systemd service | `Shikari` Scheduled Task (boot-start) |
| Code | `/opt/shikari` | `C:\Program Files\Shikari` |
| Data (`SHIKARI_HOME`) | `/var/lib/shikari` | `%ProgramData%\Shikari` |
| Config | `/etc/shikari/shikari.env` | `%ProgramData%\Shikari\run-shikari.cmd` |
| Starts at boot | yes | yes |
| Restarts on failure | yes (`Restart=on-failure`) | yes (task restart) |

Both run a single uvicorn worker. Shikari keeps session, lab-job and in-browser-console state
in-process, so **more than one worker breaks reconnect and job polling** — don't raise it.

The table shows the checkout + `install.sh`/`install-service.ps1` route. Both platforms also have a
self-contained native package that bundles its own Python and installs a real service — see
[Native packages](#native-packages-deb--rpm) (Linux) and
[Self-contained Windows bundle](#self-contained-windows-bundle-first-class-service).

## Linux (Ubuntu / Debian / Rocky / RHEL 9)

From a Shikari checkout on the server, as root:

```bash
sudo deploy/linux/install.sh
```

It creates the `shikari` system user, copies the code to `/opt/shikari`, builds a virtualenv, writes
`/etc/shikari/shikari.env`, installs and starts `shikari.service`, and waits for `/health`. Re-running it
is an in-place upgrade (new code + dependencies, then restart) — it never touches `/var/lib/shikari`.

```bash
systemctl status shikari
journalctl -u shikari -f
```

Prerequisites: Python 3.11+ (`apt install python3.11 python3.11-venv` / `dnf install python3.11`), plus
`curl`. On Rocky, `policycoreutils-python-utils` provides `semanage` for the SELinux step.

### Bind address and port

Edit `/etc/shikari/shikari.env`, then `systemctl restart shikari`. Keep `SHIKARI_HOST=127.0.0.1` behind a
reverse proxy (recommended); set `0.0.0.0` only to serve directly. To bind a port below 1024 directly,
uncomment `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit — but prefer a proxy on 443.

### TLS

Terminate TLS in a reverse proxy in front of Shikari. Caddy gets you a certificate automatically:

```
shikari.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

nginx with your own certificate:

```nginx
server {
    listen 443 ssl;
    server_name shikari.example.com;
    ssl_certificate     /etc/ssl/certs/shikari.crt;
    ssl_certificate_key /etc/ssl/private/shikari.key;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # In-browser consoles (#28) and live updates use WebSockets:
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

The WebSocket headers matter — without them the Console/Desktop consoles and live role/job updates won't
connect.

### Firewall

Open only the proxy's port (443), not Shikari's:

```bash
sudo ufw allow 443/tcp                              # Ubuntu/Debian
sudo firewall-cmd --permanent --add-service=https   # Rocky/RHEL
sudo firewall-cmd --reload
```

### SELinux (Rocky / RHEL)

`install.sh` labels the Shikari port as `http_port_t` when SELinux is enforcing and `semanage` is present.
If you let the proxy reach `127.0.0.1:8000`, also allow proxy egress:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

## Windows Server 2022+

From a checkout, in an elevated PowerShell:

```powershell
.\deploy\windows\install-service.ps1 -Port 8000
```

It copies the code to `C:\Program Files\Shikari`, builds a virtualenv, writes a launcher wrapper under
`%ProgramData%\Shikari`, and registers the boot-start `Shikari` Scheduled Task running as `LocalService`.
Put IIS (with ARR) or another reverse proxy on 443 in front of `127.0.0.1:8000`, and open the firewall.

For a **true Windows service** instead of a task, point [NSSM](https://nssm.cc) at the same wrapper:

```powershell
nssm install Shikari "%ProgramData%\Shikari\run-shikari.cmd"
nssm set Shikari AppDirectory "C:\Program Files\Shikari"
nssm set Shikari Start SERVICE_AUTO_START
```

## Upgrading

- **Linux:** pull a new checkout and re-run `sudo deploy/linux/install.sh` — it syncs code, updates
  dependencies and restarts, leaving `/var/lib/shikari` (database, `bespoke/`, telemetry) untouched.
- **Windows:** re-run `install-service.ps1` from the new checkout.

Take a backup first.

## Backup and restore

Everything stateful lives under `SHIKARI_HOME` (the database, `bespoke/`, telemetry). Code is a checkout —
don't back it up, reinstall it.

```bash
sudo deploy/backup.sh backup                        # -> shikari-backup-<date>.tar.gz
sudo systemctl stop shikari
sudo deploy/backup.sh restore shikari-backup-<date>.tar.gz
sudo systemctl start shikari
```

On Windows, archive `%ProgramData%\Shikari` while the task is stopped.

## Health check and monitoring

`GET /health` returns 200 when the server is up — point your monitoring at it (through the proxy, or
`http://127.0.0.1:<port>/health` on the box). systemd restarts the service on failure; the Scheduled Task
does the same on Windows.

## Native packages (`.deb` / `.rpm`)

As an alternative to the checkout + `install.sh` route above, `deploy/packaging/build_server_pkg.py` builds
a native package carrying its **own** Python — a SHA-256-pinned standalone CPython (python-build-standalone),
the same mechanism as the desktop `.deb`. No system Python, no venv, no checkout on the server. It installs
as `shikari-server` and puts the `shikari` CLI on `PATH`. It can't be installed alongside the desktop
`shikari` `.deb` (both own `/usr/bin/shikari` and `/usr/lib/shikari`), and dpkg refuses to; a server doesn't
need the desktop app.

Build on the **oldest** distro you support (the compiled dependency wheels link against its glibc), matching
the target architecture:

```bash
python3 deploy/packaging/build_server_pkg.py --format deb --out dist   # Debian/Ubuntu (needs dpkg-dev)
python3 deploy/packaging/build_server_pkg.py --format rpm --out dist   # Rocky/RHEL 9 (needs rpm-build)
```

The package lays down:

| | Path |
|---|---|
| Bundled Python + deps | `/usr/lib/shikari/python` |
| App code (`shikari`/`templates`/`static`) | `/usr/lib/shikari/app` |
| CLI launcher | `/usr/bin/shikari` |
| systemd unit | `/lib/systemd/system/shikari.service` |
| Config (first install only) | `/etc/shikari/shikari.env` |
| Data (`SHIKARI_HOME`) | `/var/lib/shikari` |

Install, and the post-install script creates the `shikari` user and data dir, seeds the config, labels the
SELinux port when enforcing, and enables + starts the service:

```bash
sudo apt install ./dist/shikari-server_2.0.0-1_amd64.deb      # Debian/Ubuntu
sudo dnf install ./dist/shikari-server-2.0.0-1.*.rpm          # Rocky/RHEL
```

Upgrade by installing the newer package; `/etc/shikari/shikari.env` is generated on first install and left
alone afterwards, and `/var/lib/shikari` is untouched. A full purge (`apt purge shikari-server` / `dnf remove`
then manual cleanup) removes the data and the user. TLS, firewall and monitoring are exactly as above — the
package only changes how the code and Python get onto the box.

The package ships the ATT&CK STIX bundle and seeds it into `SHIKARI_HOME` on install, so the server **starts
without network** on first boot and refreshes when it can reach MITRE. On a host with no egress (air-gapped,
or SELinux denying the service outbound), the server still starts on the seeded data; the parts that need
the internet (threat-feed enrichment, periodic ATT&CK refresh, cloud LLM) stay unavailable until egress is
allowed. Under SELinux enforcing, permit the service's outbound with `setsebool -P nis_enabled 1` (or a
dedicated policy module) if you want live refresh — startup does not require it.

### Self-contained Windows bundle (first-class service)

`deploy/packaging/build_server_pkg_windows.ps1` is the Windows counterpart of the Linux native package: it
builds a zip carrying its **own** Python (the same SHA-256-verified standalone CPython) with the server's
dependencies and pywin32, the app, and an installer. No system Python, no venv, no checkout — and it
registers a genuine SCM service (`shikari.win_service`), not the Scheduled Task.

Build on Windows (matching the target architecture), then copy the zip to the server:

```powershell
pwsh -File deploy\packaging\build_server_pkg_windows.ps1 -Arch x86_64   # or aarch64
```

On the server, unpack and install in an elevated PowerShell:

```powershell
Expand-Archive shikari-server_2.0.0_windows-x64.zip -DestinationPath C:\Temp\shikari
cd C:\Temp\shikari
.\install.ps1          # -> C:\Program Files\Shikari, data in %ProgramData%\Shikari, service "Shikari"
```

It lays the code and Python under `C:\Program Files\Shikari`, seeds `%ProgramData%\Shikari\shikari.env`,
registers the boot-start `Shikari` service with crash-restart recovery, starts it, and waits for `/health`.
Re-running upgrades in place (data and `shikari.env` untouched); `uninstall.ps1` removes the service and
files, keeping the data unless you pass `-Purge`. Put a reverse proxy on 443 in front of `127.0.0.1:8000`
and open the firewall exactly as on Linux.

ARM64 is best-effort: pywin32 ARM64 wheels are newer and may be missing for the bundled interpreter, in
which case the build stops at the pip step — use the x64 bundle (it runs under emulation) or the NSSM route
below until that lands.

### Checkout route (system Python)

If you'd rather not bundle Python, `deploy\windows\install-service.ps1` installs from a checkout into a
venv and registers a boot-start Scheduled Task. For a genuine service from that layout, point
[NSSM](https://nssm.cc) at the wrapper under `%ProgramData%\Shikari` as shown under
[Windows Server](#windows-server-2022).
