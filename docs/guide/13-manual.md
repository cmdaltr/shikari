# Manual

**Build → Manual** writes detections from techniques and procedures you supply yourself. Use it for a group ATT&CK doesn't know (a [Hunt](02-hunt.md) for an unknown name opens this page), or for your own intelligence on a known one.

## How to use it

1. **Group Description** (optional): a line about the group or your hypothesis.
2. **Technique**: choose one ATT&CK technique from the list.
3. **Tactics**: the tactic or tactics it served.
4. **Platforms**: where it ran (ATT&CK's platform names, five to a row: Windows, Linux, macOS, ESXi, IaaS and so on; PRE isn't offered, because it maps to no log source). Choosing a technique ticks its own ATT&CK platforms; untick the ones that don't apply. The detections only use log sources for the platforms left ticked, so a Linux-only entry gets no Windows event sources, and the results page warns when nothing in your technology stack (Profile) runs them.
5. **Procedures**: the attack examples, the commands or behaviour seen, one per line. This is the description: it goes into each detection, and AI reads it when you use AI, but on its own it builds no query condition.
6. **Indicators** (optional, but what the queries are built from): what the queries should match, one per line. Defanged input is refanged (`hxxp`, `[.]`, `(.)`, `[dot]`). Each line is classified into the indicator kinds a Hunt detection gets from ATT&CK's procedure examples:

   | You write | It becomes |
   |---|---|
   | A registry key (`HKLM\...`, `HKCU\...`, `HKEY_...\...`) | A registry condition |
   | A domain, IP or URL | A network condition (a URL gives its host too), and part of the IOC sweep |
   | A hash (MD5, SHA-1, SHA-256) | Part of the IOC sweep only: no technique query has a hash column |
   | A cloud API call (`DescribeInstances`) or Windows API (`CreateRemoteThread`) | As in ATT&CK text: the API call (and its AWS CLI form), or Defender's ActionType |
   | Anything else: commands, file names, paths, tool names | A command-line condition, matched anywhere in the command line |

   Hashes, domains and IPs from every entry go into one IOC sweep each for Defender XDR and Google SecOps, as an uploaded report's do (public IPs only, known-good domains left out).
7. **References** (optional): where the procedures come from, one `http://` or `https://` URL per line. Anything else is refused. They're saved in each detection's description as links, where a Hunt detection carries its ATT&CK sources, so Results and the Library show them the same way.
8. **Append** adds the entry. Repeat for each technique.
9. **Additional Options** apply to the whole submission. They're the Hunt tab's own, with its defaults: Auto-validate (off; needs Docker), LOL datasets (on), OSINT Enhancement (on) and OSINT Comparison (off). **Generate correlations** (on, as every Hunt correlates) sits beneath them, to the left of **Append**.
10. **Submit** asks whether to use AI, as a Hunt does, when your profile has a provider that can generate detections (the one assigned to detection generation is preselected, and a remembered choice skips the question). It then builds detections for every appended entry and opens the progress page, then [Results](06-results.md).

## Tips

- One technique per entry. Split mixed procedures across entries.
- An entry with no indicators can't become a query without AI or the LOL datasets. Put what was observed in Indicators: `powershell -enc ...`, `C:\ProgramData\svc.exe`, `HKCU\...\Run\Updater`.
- A command is matched by its words in order, so leave out what changes between runs (random file names, a victim's user name).
- Your entries are kept as a draft for auditing, beside the run.
- Entries appended before Platforms, Indicators and References existed still submit: they take the technique's ATT&CK platforms, no indicators and no references.
