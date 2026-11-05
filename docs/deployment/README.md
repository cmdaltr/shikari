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

## Not yet packaged

Native `.deb`/`.rpm` packages and a bundled Python (the install scripts use the system Python and a
checkout) are a follow-up; the bundled-CPython approach from the desktop build carries over when we do it.
A first-class Windows service (vs. the Scheduled Task) is the NSSM route above until then.
