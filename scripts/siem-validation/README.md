# SIEM query execution & hit counts (#16)

Run a generated detection read-only against a real SIEM and report how many events it matches — a
false-positive signal before the rule is deployed. Two backends, mirroring the same shape:

- **Splunk** — `shikari/query/splunk.py` (`SplunkClient`), previously untested. This directory stands up
  a local Splunk and validates the client against real indexed events.
- **Defender XDR** — `shikari/query/mde.py` (`MDEClient`), new: runs KQL over Microsoft Graph
  `runHuntingQuery`, reusing the token/query code in `shikari/telemetry/mde.py`.

> ⚠ **sbx recommended** — standing up Splunk pulls and runs a third-party Docker image and makes
> outbound connections; the Defender path sends queries to Microsoft Graph. To have the agent run any of
> it, use `sbx run claude` first. Running it yourself on the homelab is fine.

## Splunk (fully runnable locally)

```bash
cd scripts/siem-validation/splunk
SPLUNK_PASSWORD=Shikari!23 docker compose up -d          # ~2GB pull, ~1-2 min first boot
# wait for health: docker compose ps  (status 'healthy')

# from the repo root:
export SPLUNK_HOST=localhost SPLUNK_USERNAME=admin SPLUNK_PASSWORD=Shikari!23
export SPLUNK_HEC_TOKEN=shikari-hec-token-0000
.venv/bin/python scripts/siem-validation/splunk/validate.py \
    --events scripts/siem-validation/splunk/sample_events.jsonl \
    --spl    scripts/siem-validation/splunk/sample_rule.spl
```

The sample event set is a positive control: four Windows process events, two of which are encoded
PowerShell (**T1059.001**). `sample_rule.spl` should report **HIT COUNT: 2**. Swap in any detection with
`--detection path/to/rule.yaml` (its `query` field is used) and your own `--events`. Tear down with
`docker compose down -v`.

## Defender XDR (client ready; needs a tenant to validate)

`MDEClient` needs an app registration with `ThreatHunting.Read.All` (admin-consented) and the same
environment the telemetry export uses:

```bash
export SHIKARI_MDE_TENANT_ID=... SHIKARI_MDE_CLIENT_ID=... SHIKARI_MDE_CLIENT_SECRET=...
.venv/bin/python -c "from shikari.query.mde import MDEClient; print(MDEClient().hit_count('DeviceProcessEvents | where FileName =~ \"powershell.exe\" | where ProcessCommandLine has \"-enc\"'))"
```

`hit_count(kql)` appends `| count` and returns the number; `execute_query(kql)` returns the rows. There
is no live tenant in CI, so this half is validated by the mocked `tests/unit/test_query_mde.py`; a real
run against a tenant closes the loop.

## What's left for #16

- Run the Splunk harness against the local instance and confirm the positive control (needs Docker).
- Run `MDEClient.hit_count` against a real tenant (needs the app registration).
- Then wire both into a "measure false positives" action on the Results/Library pages (the UI surface
  is the remaining product work; the execution clients are done).
