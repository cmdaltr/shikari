# Detections as code

A run's detections are files, so they belong in version control. **Detections → Detections as code** commits a group's detections to a git repository and diffs two commits, so a Regenerate after an ATT&CK release shows exactly which queries moved. No AI is involved.

## Export a run to git

Pick a run and commit its detections. Each one is written to a stable path — `<group>/<siem>/<technique>_<name>.yaml` — under the repository at `data/detections_git/`, one tree per group. The SIEM comes from the detection's connector (`mde`, `secops`, `elastic`), and the original filename is kept so several detections for one technique and SIEM (one per data table) stay distinct.

Re-exporting rewrites the group's tree, so a detection that a Regenerate dropped disappears from the commit rather than lingering. If nothing changed since the last export, no commit is made.

The repository is a plain git repo. An admin sets where it lives, and optionally a remote to push to, under **Profile → Config → Detections as code**: a repository path, a git remote URL, and whether to push after each commit. **Test connectivity** checks the path is writable and, if a remote is set, that git can reach it (a read-only `git ls-remote`). Credentials aren't stored — a push uses this host's own git auth (SSH key, credential helper, or a token in the URL). With no remote configured it stays local, and you can `git push` by hand.

## History and diff

Every export is a commit. Pick two and compare: added, removed and changed detections, by path. Rename detection is off, so a renamed detection reads as the old path removed and the new one added rather than a silent move. This is the run-to-run diff — what a new ATT&CK version, a new attribution or an edited query actually changed in your detections.

## Push to a SIEM

Pushing detections into a SIEM's own rule store — Defender XDR custom detection rules via the Graph security API, or Google SecOps rules via the Detection Engine — is a **dry run**. Archer builds the rule payloads and the API calls a push would make and shows the count, but sends nothing: rules would be created disabled, and live push stays off until a tenant and credentials are wired up. It exists so you can see the shape of what would be pushed, not to push from a single-machine install.

## Where its data lives

The repository is `data/detections_git/`, gitignored (it's its own repo, and its contents are your detections). Deleting the directory resets the history; exporting again recreates it.
