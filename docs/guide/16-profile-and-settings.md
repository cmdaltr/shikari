# Profile and settings

**Profile** (top right) holds your account and the settings Archer works to. It has six tabs; **Config** and **Users** are for administrators only.

## Profile

| Setting | What it does |
|---|---|
| Name, email, team, type | Your account details |
| Country | Shown in green on the [Cyber Powers](11-cyber-powers.md) map |
| SIEM platforms | Hunts, uploads and reports generate detections only for the ticked SIEMs, which saves time. None ticked means all of them |
| Threat Feed industries | The industries the [Threat Feed](10-threat-feed.md)'s "Your industries" filter keeps |

## Security

| Setting | What it does |
|---|---|
| Change Password | At least 16 characters, with letters, numbers and special characters |
| Two-Factor Authentication | Scan the QR code with an authenticator app (or type the key), enter a code to turn it on |
| Backup Codes | One-time codes for when you lose your authenticator. Shown once: download or copy them |
| API Tokens | For the console, the MCP server and your own scripts: set `ARCHER_TOKEN` instead of a password. Works with MFA. A token acts as you, so revoke it here if it leaks |

## Timeline

Your past runs (all, groups or CVEs), with links to their results and downloads.

## API Keys

| Section | What goes here |
|---|---|
| AI Models | A cloud provider's API key, or a local model's server URL (Ollama, LM Studio, llama.cpp) |
| AI Assignment | Which provider and model answer Ask Archer, and which generate detections |
| Max LLM calls per detection run | A cap on AI calls in one run (one call per procedure, each a large prompt). Past it, the standard pipeline carries on alone |
| Hunt prompt | Whether Archer asks about AI on every hunt; **Ask again** resets a remembered answer |
| OSINT Sources | Shodan, SecurityTrails and GitHub keys for [Company profile](04-company-profile.md) |
| SIEM Platforms | API keys for Google SecOps, Splunk, Defender XDR and Elastic |
| Emulation Tools | Coming soon |

Keys are stored encrypted. Keys in `.env` in the project root work too.

## Config (administrators)

System-wide correlation settings, applied to every run from then on:

| Setting | Meaning | Recommended |
|---|---|---|
| Correlation Threshold | Minimum relevance a correlation needs. Higher means fewer, stronger correlations | 30–50% |
| Per-Vendor Limit | Most correlations kept per SIEM | 25–100 |
| Tech Frequency Limit | Most times one technique can start a correlation | 20–40 |

## Users (administrators)

Create, edit and remove accounts: name, email, role (Standard or Administrator) and state (an inactive account can't sign in). **Reset Password** sets a new password for the user. Users who forget their own can use **Forgot password** on the sign-in page, which emails a reset link when SMTP is configured.
