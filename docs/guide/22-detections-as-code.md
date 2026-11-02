# Detections as code

A run's detections are files, so they belong in version control. **Detections → Detections as code** commits a group's detections to a git repository and diffs two commits, so a Regenerate after an ATT&CK release shows exactly which queries moved. No AI is involved.

## Export a run to git

Pick a run and commit its detections. Each one is written to a stable path — `<group>/<siem>/<technique>_<name>.yaml` — under the repository at `data/detections_git/`, one tree per group. The SIEM comes from the detection's connector (`mde`, `secops`, `elastic`), and the original filename is kept so several detections for one technique and SIEM (one per data table) stay distinct.

Re-exporting rewrites the group's tree, so a detection that a Regenerate dropped disappears from the commit rather than lingering. If nothing changed since the last export, no commit is made.

A detection that needs a data source the estate doesn't ingest is left out of the commit (it can't fire, so there's no point committing it) and listed separately as excluded. This follows what you set under [SIEM data sources](24-siem-data-sources.md); with nothing configured, everything is committed.

The repository is a plain git repo. An admin sets where it lives, and optionally a remote to push to, under **Profile → Config → Detections as code**: a repository path, a git remote URL, and whether to push after each commit. **Test connectivity** checks the path is writable and, if a remote is set, that git can reach it (a read-only `git ls-remote`). Credentials aren't stored — a push uses this host's own git auth (SSH key, credential helper, or a token in the URL). With no remote configured it stays local, and you can `git push` by hand.

## History and diff

Every export is a commit. Pick two and compare: added, removed and changed detections, by path. Rename detection is off, so a renamed detection reads as the old path removed and the new one added rather than a silent move. This is the run-to-run diff — what a new ATT&CK version, a new attribution or an edited query actually changed in your detections.

## Push to a SIEM

Pushing detections into a SIEM's own rule store — Defender XDR custom detection rules via the Graph security API, or Google SecOps rules via the Detection Engine — is a **dry run**. Shikari builds the rule payloads and the API calls a push would make and shows the count, but sends nothing: rules would be created disabled, and live push stays off until a tenant and credentials are wired up. It exists so you can see the shape of what would be pushed, not to push from a single-machine install.

## Check detections in CI

`shikari/validation/ci.py` gates detection files the way a pull request should: the static and precision checks, the quality grade, the false-positive risk and the run cost ([Results](06-results.md#quality-and-false-positive-risk)). A static error always fails. The thresholds fail the rest.

```bash
python -m shikari.validation.ci data/groups --min-grade C --max-fp-risk medium --max-cost medium
```

It exits 0 when everything passes, 1 when anything fails and 2 when there was nothing to check. The options:

- `--format github` writes workflow annotations, so failures show on the pull request's diff.
- `--changed-only origin/main` checks only what differs from that ref.
- `--fail-on-warnings` makes warnings fail too.

A detections repository doesn't need Shikari installed. With `--server https://your-shikari` (and an API token in `SHIKARI_TOKEN`), the checks run on your Shikari server through `POST /api/validate/assess`. The script then needs only Python, `requests` and `PyYAML`.

`examples/ci/shikari-detections.yml` is a ready GitHub Actions workflow. Copy it to the detections repository's `.github/workflows/`, with `shikari/validation/ci.py` beside it as `.github/shikari_ci.py`, and set the secrets `SHIKARI_URL` and `SHIKARI_TOKEN`. A server on a private network needs a self-hosted runner that can reach it.

## Where its data lives

The repository is `data/detections_git/`, gitignored (it's its own repo, and its contents are your detections). Deleting the directory resets the history; exporting again recreates it.
