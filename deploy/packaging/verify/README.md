# On-target verify scripts (#29)

The native server packages are built but **unverified** — they can't be built or run from the macOS dev
box. These scripts build, install and smoke-test a package on a throwaway VM that matches a shipping
target, then tear it down. Copy the checkout (or just this repo) onto each VM and run the one for its OS.

| Target VM | Script | Produces |
|---|---|---|
| Debian 12+ / Ubuntu 22.04+ | `verify-linux.sh` (auto-picks `.deb`) | `.deb`, installed as the `shikari` systemd service |
| Rocky / RHEL 9 | `verify-linux.sh --format rpm` | `.rpm`, installed as the `shikari` systemd service |
| Windows Server 2022+ | `verify-windows.ps1` | zip bundle, installed as the `Shikari` SCM service |

Each one: builds the package (downloading its own SHA-verified CPython + the deps), installs it, waits on
`/health` (`healthcheck.py`, shared, stdlib-only), prints the service state, and uninstalls — unless you
pass `--keep` / `-Keep` to leave it running.

## Linux

Build on the **oldest** distro you support for that family (the compiled dependency wheels link against
its glibc), matching the CPU architecture you ship.

```bash
# Debian/Ubuntu: needs dpkg-dev
sudo apt install -y python3 dpkg-dev
# Rocky/RHEL: needs rpm-build
sudo dnf install -y python3 rpm-build

sudo ./verify-linux.sh            # auto deb/rpm; add --format rpm to force, --keep to leave it installed
```

Prints `PASS` / `FAIL`. On failure it dumps `systemctl status shikari` and the last 60 journal lines.

## Windows

In an **elevated** PowerShell on the VM:

```powershell
.\verify-windows.ps1              # x64 (or ARM64 on an ARM64 host); -Keep to leave it installed
```

ARM64 is best-effort — if no pywin32 wheel exists for the bundled interpreter the build stops at the pip
step; use the x64 bundle under emulation. On failure the script dumps recent `Shikari` Application-log
events.

## Notes

- The scripts find the checkout automatically when run from inside it; otherwise set `SHIKARI_REPO`
  (`$env:SHIKARI_REPO` on Windows) to its path.
- Do lab/detonation work inside `sbx`; these just exercise the packaging and the web service, so a plain
  VM is fine.
- Built artifacts land in `<repo>/dist/`.
