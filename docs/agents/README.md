# Agents in Archer

An agent is a model in a loop with tools. You give it a task; it picks a tool, reads what comes back, and picks again until it can answer. That's the whole idea. The rest is about which tools it gets, what its instructions say, and what it's allowed to do without asking.

Archer has three agents, an MCP server that gives the same tools to any MCP client, and a one-file example you can read in five minutes.

| Where | What |
|---|---|
| Web | **Agents** page (robot icon in the top bar) |
| Console | `adfconsole` → `use agent/repair`, `agent/ask`, `agent/triage` |
| MCP | `archer-mcp`: Archer's tools and the three agents' prompts in Claude Code, Claude Desktop or your own agent |
| Example | [`examples/agents/minimal_agent.py`](../../examples/agents/minimal_agent.py): about 100 lines, no Archer dependency |

Agents run on Claude through tool use, with the Anthropic key in your profile (Profile → API Keys). Your Ask Archer model is used if you've assigned an Anthropic one; otherwise `claude-sonnet-5-5`.

## The loop

```python
messages = [{"role": "user", "content": task}]
while True:
    response = client.messages.create(model=MODEL, system=SYSTEM, tools=TOOLS, messages=messages)
    messages.append({"role": "assistant", "content": response.content})
    calls = [b for b in response.content if b.type == "tool_use"]
    if not calls:
        return the text of response            # the answer
    results = [run(call) for call in calls]     # your code, not the model's
    messages.append({"role": "user", "content": results})
```

The model never runs anything. It asks for a tool by name with arguments, your code runs it, and the result goes back as the next message. So the model's reach is exactly the set of tools you give it, and each tool is ordinary code you can test, log and restrict.

[`minimal_agent.py`](../../examples/agents/minimal_agent.py) is this loop with two tools (`search_files`, `read_file`) over a folder of detection YAMLs:

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...
python examples/agents/minimal_agent.py data/groups "Do we have a detection for LSASS dumping with comsvcs.dll?"
```

It searched for `comsvcs`, `MiniDump` and `T1003.001`, read the two LSASS Memory files, and pointed out that the SecOps regex expects the literal text `PID`, so it can never match a real command line. A grep would have found the files; the agent also judged them.

## Archer's three agents

All three are the same runtime ([`archer/agents/runtime.py`](../../archer/agents/runtime.py)) with different instructions and tool sets ([`definitions.py`](../../archer/agents/definitions.py)). Each shows a different pattern.

### Detection repair: check, fix, check again

The tools are `find_query_errors`, `get_detection`, `check_query`, `mde_columns`, `technique_info` and `save_query_fix`.

The agent runs the static checks over a run's queries, reads each failing detection, fixes only what the checks flag, re-checks its fix, and saves it with a reason. This is the evaluator-optimiser pattern: the checker ([`archer/validation/static_check.py`](../../archer/validation/static_check.py)) is deterministic code, and the model is only trusted with the fix. The save route refuses any query that still has errors, so a confused model can't write a broken query. The previous query goes into the file's `repair_history`.

The checks:

| Platform | Errors (won't parse or can't match) | Warnings (contract style) |
|---|---|---|
| MDE (KQL) | Column not in the table (MDE schema), unbalanced quotes or brackets, malformed string lists | `contains`, backslashes in ordinary literals, summarize shape, mixed and/or |
| SecOps (YARA-L) | UDM field the event type never carries (YL-21), structure | Rule naming, generic regex tokens |
| Splunk (SPL) | Unknown command after a pipe, empty stage, structure, leftover template placeholders | Unscoped base search |
| Elastic | Structure | |

The contract lint never covered SPL; these SPL checks are new and deliberately conservative.

The first real run found an IOC sweep projecting `FileName`, `FolderPath` and `SHA256` from `DeviceNetworkEvents`, which MDE refuses ("Failed to resolve column"). The agent looked up the table's columns, projected the `InitiatingProcess*` equivalents, checked the result and saved it, in 5 turns. The sweep generator now gets this right too. Across the library, the checks find about 40 errors in roughly 1,250 queries, mostly SecOps rules testing a field their event type never carries.

### Ask Archer (agent): look it up, don't recall it

The tools are the read tools (coverage, results, ATT&CK, library, `check_query`) plus the hunts.

The plain Ask Archer panel answers from the model's memory. The agent answers from Archer: asked which of FIN7's Execution techniques have no detection, it called `group_coverage`, then `technique_coverage` and `technique_info`, wrote an MDE query for the biggest gap and ran it through `check_query` before showing it. It can start hunts, but only with your approval and only when you ask for detections Archer doesn't have.

### Intel triage: plan across steps

The tools are `analyse_report`, `technique_coverage`, `technique_info`, `find_actors`, `group_coverage`, `hunt_report`, `wait_for_run` and `get_run_results`.

Given a report URL, it extracts the techniques and IOCs, checks coverage, works out who the actor is, decides what to hunt, runs the hunt, waits, reads the results and writes a briefing (summary, technique table, IOCs, gaps, next steps). Here the model chooses the order and stops when it has enough; the instructions give it a plan, but nothing forces the sequence.

On CISA AA23-320A (Scattered Spider) it found 35 of 43 techniques uncovered, hunted them with the IOC sweeps, and called out that the run created no technique detections. That's a real gap in the pipeline (see below), not an agent fault, and the agent said so rather than inventing results.

## Approvals

Tools that change something (`hunt_*`, `save_query_fix`) are marked `changes=True`. Before running one, the agent pauses: the web page shows Allow and Decline, and the console asks y/N. A declined action goes back to the model as "the user declined", and it carries on without it. Untick **Ask before actions** (web) or `set APPROVE all` (console) to let it run unattended.

Read tools never need approval. The model can't reach anything that isn't a tool.

## Costs

Every turn resends the conversation so far, so input tokens grow with the number of turns. Typical runs on Sonnet 5.5:

| Run | Turns | Tokens in / out |
|---|---|---|
| Repair one query | 5 | 18k / 1.7k |
| Ask with three lookups and a query | 5 | 31k / 2.3k |
| Triage a CISA advisory with a hunt | 8 | 60k / 4.9k |

Each agent has a turn limit (repair 60, ask 20, triage 25). Hunts that an agent starts don't use AI unless it passes `use_ai`; then your profile's per-run call cap applies.

## MCP: Archer as tools for any agent

```bash
claude mcp add archer --env ARCHER_EMAIL=you@example.com --env ARCHER_PASSWORD=... \
    -- /path/to/archer/.venv/bin/python -m archer.mcp_server
```

`archer-mcp` exposes the same 20 tools the agents use, with the 5 changing tools marked as not read-only so the client asks first, plus the three agents' instructions as prompts (`repair`, `ask`, `triage`). It signs in to a running Archer as you, so hunts use your AI settings and your keys stay on the server.

## Building your own

**A tool** is a `Tool(name, description, input_schema, fn, changes=False)` in [`archer/agents/tools.py`](../../archer/agents/tools.py). Write the description for the model: say what it returns and when to use it. Keep results small (the runtime truncates at 20,000 characters) and return errors as text the model can act on. If the tool needs server logic, add it to `archer/client.py` so the console and MCP server get it too.

**An agent** is an `Agent(name, title, summary, system, inputs, tools, task)` in [`definitions.py`](../../archer/agents/definitions.py). Most of the work is in the system prompt: what good looks like, the order to work in, what not to do, and what to finish with. Give it the fewest tools that do the job; every extra tool is another wrong turn it can take.

**Testing** without spending money: [`tests/unit/test_agent_runtime.py`](../../tests/unit/test_agent_runtime.py) scripts the model's responses and checks the loop, approvals, errors and turn limits.

## Known gaps

- **Technique hunts create nothing without AI or OSINT.** With neither, no indicators are found in the ATT&CK data and no detection is written. That's why the triage hunt and a plain T1003.001 hunt produced 0 technique files. Fix: fall back to the bespoke template generator (`MODE fallback`) when extraction finds no indicators, so a hunt always produces something reviewable.
- **Agents need an Anthropic key.** The runtime uses Claude's tool use. Fix: add an OpenAI-compatible tool-calling path in `runtime.py` for OpenAI, DeepSeek and Qwen, and local models that support tools.
- **Sessions live in memory.** A server restart loses running agents. Fix: persist the session events to SQLite; the transcript would also make a useful audit log.
