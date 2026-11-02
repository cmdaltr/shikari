# Default Mappings

What a new install's `bespoke/mappings/` starts with. `shikari.paths.seed_bespoke()` copies these in at startup and never overwrites: the six files that name Splunk indexes (`indicatorMapping.json`, `schemas/schemaSplunk.json`, `sources/platforms.json`, `sources/logSourceCategories.json`, `sources/dataSources.json`, `sources/display_names.json`) go in together and only into an empty folder, so they never mix with an organisation's own index names. The vendor schemas (MDE, Elastic, Google SecOps), `entityMappings.json` and `techniquePlatformIndicators.json` fill gaps one at a time. Team assignments (`sources/members.json`) are organisation data and don't ship.

To use your own mappings, replace the files in `bespoke/mappings/`. Shikari reads them from there, not from here.

## Splunk: CEF Indexes and Sourcetypes

Splunk has no common schema to ship, so the defaults assume events arrive as CEF, split into indexes by category:

| Index | Sourcetypes | Holds |
|---|---|---|
| `edr` | `cef:edr`, `cef:av` | EDR and anti-malware process, file, registry and network events |
| `os` | `cef:windows`, `cef:sysmon`, `cef:linux`, `cef:macos` | OS audit logs: Windows Security and Sysmon, auditd, macOS unified log |
| `network` | `cef:firewall`, `cef:ips` | Firewalls, IDS/IPS |
| `proxy` | `cef:proxy`, `cef:waf` | Web proxies, WAFs, ADCs |
| `dns` | `cef:dns` | DNS resolvers and DNS security |
| `identity` | `cef:idp`, `cef:ad` | Entra ID, Okta, Active Directory |
| `aws` | `cef:aws` | CloudTrail, GuardDuty |
| `azure` | `cef:azure` | Azure Activity log |
| `gcp` | `cef:gcp` | GCP Audit logs |
| `saas` | `cef:o365`, `cef:casb` | Microsoft 365, CASB |
| `email` | `cef:email` | Mail gateways |

Queries use the CEF extension keys as Splunk extracts them from the event (`src`, `dst`, `dpt`, `proto`, `suser`, `sproc`, `dproc`, `fname`, `filePath`, `fileHash`, `request`, `destinationDnsDomain`, `destinationServiceName`, `act`, `outcome`) and the header fields by their CEF names (`deviceVendor`, `deviceProduct`, `deviceEventClassId`, `name`, `severity`). If your CEF add-on renames them, change the `| fields` lines in `schemas/schemaSplunk.json` and the field lists in `indicatorMapping.json` to match.

CEF has no keys for a command line or registry activity, so the defaults use labelled custom strings:

| Key | Label | Holds |
|---|---|---|
| `cs1` | Command Line | Process command line |
| `cs2` | Parent Command Line | Parent process command line |
| `cs3` | Registry Key | Registry key path |
| `cs4` | Registry Value | Registry value data |
| `cs5` | Account | Cloud account, subscription or tenant |
| `cs6` | Signature | IPS/WAF signature or CVE |

`sproc` is the parent process and `dproc` the process itself. Windows event IDs are matched on `deviceEventClassId`.

Each index's pipeline starts with `sourcetype IN (...)`, so an index can hold several sourcetypes; drop the ones you don't collect, or rename indexes throughout all six Splunk files if yours differ.
