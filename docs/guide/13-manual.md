# Manual

**Build → Manual** writes detections from techniques and procedures you supply yourself. Use it for a group ATT&CK doesn't know (a [Hunt](02-hunt.md) for an unknown name opens this page), or for your own intelligence on a known one.

## How to use it

1. **Group Description** (optional): a line about the group or your hypothesis.
2. **Technique**: choose one ATT&CK technique from the list.
3. **Tactics**: the tactic or tactics it served.
4. **Procedures**: what the group did, one procedure per line. Be concrete: commands, file paths, registry keys and tool names become the query's indicators.
5. **Append** adds the entry and clears the form for the next technique. Repeat for each technique.
6. **Submit** builds detections for every appended entry and opens the progress page, then [Results](06-results.md).

## Tips

- One technique per entry. Split mixed procedures across entries.
- Procedures with no concrete indicator ("used phishing") can't become a query without AI. Write what was observed: `powershell -enc ...`, `C:\ProgramData\svc.exe`, `HKCU\...\Run\Updater`.
- Your entries are kept as a draft for auditing, beside the run.
