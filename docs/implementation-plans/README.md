# Implementation plans

Each outstanding feature is blocked on something only a live environment can provide — a SIEM tenant, a model on the homelab, a running VECTR. These plans split that cleanly:

- **Part A — Setup you provide.** What to stand up or configure, the current blockers, and the concrete *expected outcome* (credentials, endpoints, a running service) that unblocks the build.
- **Part B — Implementation plan.** The build I'll follow once Part A's expected outcome exists, including what stays unit-tested offline versus what needs the live environment to validate.

The two are meant to be used together: Part A's expected outcome is Part B's starting assumption.

| Plan | Issue | Blocked on |
|---|---|---|
| [Hit counts](16-hit-counts.md) | #16 | A SIEM tenant with read-only API access |
| [Local LLM detection generation](09-local-llm.md) | #9 | Ollama + a model on the Mac Mini |
| [VECTR integration](26-vectr.md) | #26 | A running VECTR instance + API key |
| [SIEM mappings: editor + live test](12-siem-mappings-remainder.md) | #12 | A SIEM tenant (test step) + your field/index values |

Everything that could be built offline for these has been — see each plan's "Already done" note.
