# Getting Started with Shikari

Installing Shikari, signing in, and the configuration it needs before its queries fit your environment. Once it's running, the [user guide](docs/guide/README.md) covers every page.

## Prerequisites

- **Git**: `brew install git` (macOS), `apt install git` (Ubuntu/Debian), or [Git for Windows](https://git-scm.com/download/win).
- **Either** Docker Desktop (includes Compose; WSL2 on Windows) **or** Python 3.11 or later.
- Optional: [Ollama](https://ollama.com) for local AI, or an API key for a cloud model. Shikari works without AI.

## Capabilities and dependencies

Shikari's core runs on Python alone, or in Docker, with nothing optional added: hunts, report analysis, company profiles and exposure maps, research, SIEM query generation for all four platforms, ATT&CK traversal and MITRESaw, Coverage, Flows, the Library, Detections as code, the threat feed, Cyber Powers, and IOC search with STIX, TAXII and MISP import and export. The maps render as server-side SVG and geolocate over a public HTTP service, and STIX, TAXII and MISP are handled with `samarkand` and `requests` — all core dependencies, so none of this needs an extra.

Everything else is opt-in. Each capability below is simply unavailable when its tool is missing; nothing breaks the app.

| Capability | Needs | Without it |
|---|---|---|
| Emulate lab — Linux containers (Ubuntu, Rocky 10) | Docker or OrbStack on the host | the Lab tab loads; container machine types are greyed out |
| Emulate lab — macOS / Linux VMs | Tart (Apple Silicon only) | those machine types are unavailable |
| Emulate lab — Windows VM | UTM | the Windows machine type is unavailable |
| CALDERA operations | Docker (CALDERA itself runs as a container) | the Lab → CALDERA panel is inert |
| AI: Ask Shikari, Agents, AI-written queries, threat briefings | a cloud model API key, or Ollama; local in-process models also need `pip install 'shikari[local-ai]'` | AI is opt-in and off by default; everything else is unaffected |
| Desktop app window (`shikari app`) | `pip install 'shikari[desktop]'` (Linux also needs GTK or Qt) | run Shikari in a browser instead |

Rocky 10 is the sharpest case: it runs only as a Docker container, so a host without Docker loses both Rocky and the Ubuntu container — its Tart VM and the other machines still work. The `analysis`, `viz` and `geo` extras in `pyproject.toml` are for ancillary notebook and offline tooling; no page in the app requires them.

## Install

**Just using Shikari?** The desktop installers on the Releases page (macOS, Windows, Linux) need no Git, Python or Docker. Each connects to your organisation's Shikari server or runs Shikari on that computer: see [desktop/README.md](desktop/README.md). The rest of this page is for running Shikari from a checkout, including as the central server those apps connect to.

```bash
git clone https://github.com/cmdaltr/shikari.git
cd shikari
```

**Option A: Docker**

```bash
SHIKARI_ADMIN_EMAIL=you@example.org BASE_URL=http://localhost:32453 docker compose up --build
docker compose down        # stop
```

Docker runs Shikari as a team server (`SHIKARI_MODE=server`, set in `docker-compose.yml`): there's no default admin. On its first start with no admin, it issues `SHIKARI_ADMIN_EMAIL` a one-time first-admin invitation and prints the link in `docker compose logs shikari`; open it within 24 hours to choose a password and set up an authenticator. Without the variable, or to issue a new link, run `docker compose exec shikari python shikari/service.py first-admin you@example.org`. `BASE_URL` is the address the link names. To run the container as a local Shikari instead, set `SHIKARI_MODE=local`; it still won't seed the default admin, because inside the container Shikari listens on `0.0.0.0`.

Data lives in the checkout's `data/` folder (bind-mounted into the container), so it survives restarts, rebuilds and `docker compose down -v`.

**Option B: local Python**

```bash
python3 -m venv .venv            # add --copies if the checkout is in a synced folder (OneDrive, Dropbox)
source .venv/bin/activate
pip install -r requirements.txt
./bin/shikari install  # once: puts `shikari` on your PATH (~/.local/bin)
shikari start      # background, restarted if it crashes
shikari status | shikari logs -f | shikari restart | shikari stop
```

Day-to-day running, start-up options and what Shikari updates when it starts: [Running Shikari](docs/guide/01-running-shikari.md).

## Sign in

Open `http://localhost:32453`.

### Default login (local Shikari)

A local Shikari (`shikari start` from a checkout, or the desktop app running Shikari on your computer) seeds a default administrator into an empty database:

```
Sign in as: admin
Password:   BigGameHunter
```

`admin` is a username, not an email: it's the one account that signs in without one. Change the password after the first sign-in (Profile → Security). The account is created (and recorded in the audit log, `default_admin_seeded`) only while Shikari listens on this machine alone (`127.0.0.1`, the default). Started with `--host 0.0.0.0`, `UVICORN_HOST` or `SHIKARI_HOST` set to a network address, it creates no default admin, because the password is public; get one with `shikari first-admin you@example.org` instead. A database from before this change has `admin@shikari.app`, which a local Shikari renames to `admin` on start.

A team server (Docker, `deploy/linux/install.sh`, the Windows service: anything with `SHIKARI_MODE=server`) seeds no account at all. Its first admin comes from a one-time invitation: the install asks for the admin's email and prints the link, the first start logs one for `SHIKARI_ADMIN_EMAIL`, and `shikari first-admin <email>` issues one on demand (refused, exit status 5, once an active admin exists, unless `--force`; only the newest works). Links name `BASE_URL`; without it they name localhost, and the command line and the start-up message warn about that on stderr each time.

### Adding people

Accounts on a team server come by invitation. An admin invites someone from Settings → Users → Invite (email, role, and a name if you like) and gives them the link; or, from the server:

```bash
shikari invite user@example.org --role standard            # local; --role operator or admin, --name "Full Name"
docker compose exec shikari python shikari/service.py invite user@example.org --role standard   # Docker
```

The link works once, within 24 hours: they give their name, choose a password and set up an authenticator app (always required for an invited account), and the account is made, with that role, when a code from it checks out. Opening the link again (a second tab, or clicking it again) shows the same authenticator, so one already scanned still works. Five wrong codes close the invitation, and the admin issues a new one. An expired link says it has expired; a used, revoked or replaced one says it isn't valid. They're signed in and see their backup codes once. Pending invitations are listed under Users, where they can be revoked. Each open invitation counts towards the licence's seats until it's accepted, revoked or expires. There's no self-registration on a team server, or on a local Shikari listening on a network address: `/register` sends people to the sign-in page to ask for an invitation. A local Shikari on `127.0.0.1` keeps it.

A first admin's invitation, when there's no admin to send one:

```bash
shikari first-admin admin@example.org                     # local (or: python scripts/admin/create_admin.py admin@example.org)
docker compose exec shikari python shikari/service.py first-admin admin@example.org   # Docker
```

It's refused, with exit status 5, while an active admin exists (a local Shikari's default `admin` counts) unless you add `--force`.

Someone who can't sign in (a forgotten password, a lost authenticator or backup codes) gets a one-time link from an admin, Settings → Users → Reset access, or from the server when no admin can sign in:

```bash
shikari reset-access user@example.org                      # local (or: python scripts/admin/reset_password.py user@example.org)
docker compose exec shikari python shikari/service.py reset-access user@example.org   # Docker
```

The link works once, within 24 hours: they choose a new password and set up a new authenticator, then see fresh backup codes once. Their sessions end and their API tokens are revoked as soon as the link is made, and again when it's used. Until then their old password and authenticator keep working: nothing refuses sign-in because a reset is open. Wrong codes on the link count towards the sign-in lockout (five, then 15 minutes).

With email set up (`EMAIL_ENABLED=true`, the `SMTP_*` settings, and `BASE_URL`), people can also use **Forgot password** on the sign-in page: they enter their email, and if it has an active account Shikari emails the same reset-access link. The answer is the same whether or not an account matched, and requests are limited per address and per IP. Asking ends no sessions and revokes nothing (anyone could ask); that happens when the link is used. A new request replaces an earlier emailed link but never an open one an admin issued. Without email, the page says to ask an administrator. The old 1-hour `?token=` password-reset email is gone.

## Tell Shikari about your environment

### SIEMs

Shikari generates for **Google SecOps** (YARA-L 2.0), **Defender XDR** (KQL), **Splunk** (SPL) and **Elastic** (ES|QL). Choose yours under **Profile → SIEM platforms**; Shikari generates only for those.

### Mapping files

Query generation reads mapping files from `bespoke/mappings/`: index and table names, field mappings, and which indicators each log source can see. A new install starts with generic ones: at start-up Shikari copies in whatever is missing from `shikari/mappings/defaults/` (Splunk set up for CEF-formatted indexes and sourcetypes; see [its README](shikari/mappings/defaults/README.md)) and never overwrites a file that's there. Replace them with your organisation's own. Those are gitignored, because they describe your estate, so keep a copy somewhere safe.

```
bespoke/mappings/
  indicatorMapping.json
  techniquePlatformIndicators.json
  schemas/   schemaMDE.json, schemaGoogleSecOps.json (and Splunk, Elastic)
  sources/   platforms.json, dataSources.json, entityMappings.json, logSourceCategories.json
```

The server lists any missing file at start-up ("N required bespoke mapping file(s) absent"). The wizard adds your Defender tables and Splunk indexes to the schema overrides:

```bash
python scripts/validation/setup_mappings.py
```

The full layout, and what each file does: [bespoke/README.md](bespoke/README.md) and [BESPOKE.md](docs/BESPOKE.md).

### Organisation settings (recommended)

```bash
cp bespoke/exclusions.yaml.example bespoke/exclusions.yaml   # global exclusions
cp bespoke/config.yaml.example bespoke/config.yaml           # organisation settings
```

Then, in **Profile**:

| Setting | What it changes |
|---|---|
| SIEM platforms | Which SIEMs Shikari generates for |
| Technology stack | Group hunts leave out techniques and procedures for platforms and products you don't run |
| Threat Feed industries | Which posts the Feed shows as relevant |
| API keys | AI providers and models, and the optional OSINT keys |

Details: [Profile and settings](docs/guide/16-profile-and-settings.md).

## First steps

1. **Hunt a group.** Home → Hunt → type a group ("APT29", "Scattered Spider") → **Hunt**. The [Results](docs/guide/06-results.md) page shows the threat briefing, detections per SIEM, correlations, the attack flow and the IOC flow. Save what you want to the [Library](docs/guide/07-library.md).
2. **Analyse a report.** Home → Analyse → a URL or an uploaded PDF, DOCX or text file. Shikari extracts the techniques and IOCs and hunts them ([Analyse](docs/guide/03-analyse.md)).
3. **See your coverage.** Detections → [Coverage](docs/guide/08-coverage.md): the ATT&CK matrix, coloured by reference queries or your own detections.
4. **Check what your logs can see.** Build → [Emulate](docs/guide/19-emulate.md): which logs record each technique, from attacks recorded in labs, and your detections' indicators checked against them.
5. **Watch the news.** Intel → [Feed](docs/guide/10-threat-feed.md): the week's research, tagged for your industries, with watchlists.

Detections are YAML files, one per technique and SIEM. Copy a query into Defender XDR's custom detection rules or a SecOps rule; Results and the Library also export them.

## Without the browser

```bash
shikari console                               # Metasploit-style console
shikari offline generate "APT29" --correlate  # the pipeline, locally
shikari offline correlate "APT29"             # correlations from its detections
shikari offline hunt "PowerShell"             # one technique, by name or ID
```

The console, the Python client, the REST API (live reference at `http://localhost:32453/docs`, once signed in) and the MCP server: [Console, API and MCP](docs/guide/17-console-api-mcp.md).

## Troubleshooting

| Problem | Fix |
|---|---|
| Can't sign in | `shikari reset-access <email>` prints a one-time link to a new password and authenticator; or `shikari first-admin <email>` for an admin invitation |
| Queries don't match my SIEM's tables or fields | The mapping files (above): start-up names any that are missing |
| Port 32453 in use | `lsof -i :32453`, or `shikari start --port 8001` |
| Docker won't start | `docker compose logs shikari`; rebuild with `docker compose down && docker compose up --build` (your data in `data/` is kept) |
| A page shows old data after an update | `shikari restart --skip-index` |

More: the [documentation index](docs/DOCS_INDEX.md), or open an [issue](https://github.com/cmdaltr/shikari/issues).
