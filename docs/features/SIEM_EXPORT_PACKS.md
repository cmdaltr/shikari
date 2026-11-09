# SIEM export packs

A zip per SIEM, imported by hand into your own Elastic, Splunk or Wazuh. Shikari never connects to it (#41). Build one from **Detections as code → Export to a SIEM**, or from the command line:

```
shikari export siem --siem elastic --group "Sandworm Team"
shikari export siem --siem splunk --all --telemetry win11-sysmon-20261108-1244 -o pack.zip
shikari export runs
```

| SIEM | Pack holds | Import |
|---|---|---|
| Elastic | `rules.ndjson`: Kibana ES\|QL rules, created disabled | Security → Rules → Import |
| Splunk | `shikari_detections.tgz`: an app with the saved searches (enabled, unscheduled), indexes and JSON field extraction | Apps → Install app from file |
| Wazuh | `shikari_rules.xml`: custom rules from the detections' indicators, Windows (Sysmon and Security 4688) only | `/var/ossec/etc/rules/`, then restart |

Each pack has a `README.txt` with the steps and a `manifest.json` listing what went in and what was left out. With `--telemetry`, a lab run's events come too, under `telemetry/`, in each SIEM's own shape. The timestamps are moved so the run ends at export time.

## Tested against

These were checked against real products in the #41 spike (November 2026):

| Product | Version | Result |
|---|---|---|
| Elasticsearch and Kibana | 8.19.23 | 226 of 226 rules imported; **T1033** and **T1057** return rows from the lab run |
| Splunk | 9.4.17 | App installs; `$$` runs as a literal `$` via `\| savedsearch`, dispatch and the scheduler; **T1033** returns rows once the Splunk detections have been regenerated after 8fadda2 |
| Wazuh manager | 4.14.10 | All rules load; **T1033** and **T1057** fire on the lab events, nothing else does |

## Known limits

- **Elastic's minimum version isn't confirmed.** The README says ES|QL rules need Elastic 8.14 or later. They were tested on 8.19 only, where Kibana accepted them with no preview setting. The spike couldn't reach Elastic's documentation to confirm when the ES|QL rule type became generally available. Elastic's release notes put its technical preview at 8.13 and general availability at 8.14, but that is unverified here. Anyone on 8.13–8.15 should import one rule first.
- **Splunk needs an x86_64 host.** `splunk/splunk` has no arm64 image, and it doesn't run under emulation on Apple silicon (16 KiB pages).
- **Wazuh practice events need their own parent rules.** A manager reads `telemetry/events.json` with its json decoder, not `windows_eventchannel`, so the built-in Sysmon rules never fire on it. `telemetry/shikari_practice_rules.xml` (rules 100090–100095) supplies the parent groups; install it on a practice manager only. Replaying the whole file needs `logcollector.queue_size` raised above its default of 1,024 lines, or events are dropped.
- **Wazuh rules are Windows only.** There's nothing yet for Linux or macOS.

## Master hunt query (Defender XDR)

**Detections as code → Master hunt query**, or `shikari export kql`, combines a run's Defender XDR detections into one advanced hunting query. Each detection becomes a KQL function over a window you choose; the functions are unioned (`isfuzzy`, so a table the tenant lacks doesn't fail the rest), and the result is one row per device and account, ranked by how many of the run's techniques it shows, with the commands behind them. Several of one group's techniques on a device is the campaign signal a single detection can't give. It came from ETHAN, rebuilt from Shikari's own library with no AI.

```
shikari export kql --group "Sandworm Team" --techniques T1016,T1033,T1057,T1082 --tlp amber
shikari export kql --all --per-technique 0 --lookback 7d -o hunt.kql
```

A group's whole library is too much for one query (Sandworm Team: 497 detections, about 400 KB), so each technique keeps one detection by default, from the table most likely to see it (process events first). List a campaign's techniques to scope it, and raise `--per-technique` for more. A detection that fails Shikari's static check, or would break the union (unbalanced quotes or brackets, a backslash escape in an ordinary string), is left out and named in the header. The header also carries the TLP label it's shared under.

It hasn't been run against a live Defender XDR tenant: the KQL is checked by Shikari's own static checker, not Microsoft's parser.
