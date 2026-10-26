# Agents in Archer

An agent is a model in a loop with tools. You give it a task; it picks a tool, reads what comes back, and picks again until it can answer. That's the whole idea. The rest is about which tools it gets, what its instructions say, and what it's allowed to do without asking.

Archer has five agents, an MCP server that gives the same tools to any MCP client, and a one-file example you can read in five minutes.

| Where | What |
|---|---|
| Web | **Agents** page (robot icon in the top bar) |
| Console | `archer-cli console` → `use agent/repair`, `agent/ask`, `agent/triage`, `agent/sweep`, `agent/audit` |
| MCP | `archer-cli mcp`: Archer's tools and the five agents' prompts in Claude Code, Claude Desktop or your own agent |
| Example | [`examples/agents/minimal_agent.py`](../../examples/agents/minimal_agent.py): about 100 lines, no Archer dependency |

Agents run on any provider in your profile that can call tools (Profile → API Keys): Anthropic, OpenAI, Gemini, DeepSeek, Qwen, Grok, or a local endpoint (Ollama, LM Studio, llama.cpp). Pick one on the Agents page or with `set PROVIDER` in the console. Without a choice, Claude is used if you have an Anthropic key (it's the most reliable at multi-step tool use), otherwise your Ask Archer provider.

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

## Archer's five agents

All five are the same runtime ([`archer/agents/runtime.py`](../../archer/agents/runtime.py)) with different instructions and tool sets ([`definitions.py`](../../archer/agents/definitions.py)). Each shows a different pattern.

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

On CISA AA23-320A (Scattered Spider) it found 35 of 43 techniques uncovered, hunted them with the IOC sweeps, and called out that the run created no technique detections rather than inventing results. That was a pipeline gap, since fixed: technique hunts now borrow indicators from ATT&CK procedure examples.

### Coverage sweep: find the gaps, close them

The tools are `group_coverage`, `technique_coverage`, `technique_info`, `hunt_techniques`, `hunt_group`, `wait_for_run`, `get_run_results` and `run_status`.

Given a group (optionally one tactic), it lists the techniques with no detection, hunts those gaps, waits, and reports what closed and what couldn't. Triage starts from a report; this starts from a group you already care about and works the gap list to the end. The hunts need your approval like any changing tool.

### Library audit: duplicates, overlaps and noise

The tools are `search_library`, `get_detection`, `technique_coverage`, `technique_info` and `noisy_indicators`. It reports only — it has no tool that changes or deletes anything.

It gathers the saved library, groups detections by what they detect, compares the queries of suspected pairs (same technique and platform, same logic and indicators is a duplicate), notes lopsided coverage, and flags detections resting on indicators that `noisy_indicators` shows recorded across many unrelated techniques — a likely false-positive source. The output is a report: duplicates to consolidate, overlaps to reconcile, and notes.

`noisy_indicators` is the recorded-telemetry false-positive check ([Emulate](../guide/19-emulate.md)) as a tool: give it a detection's match values, or a technique whose own recorded values it should vet, and it says which appear in enough other techniques' recordings to be poor discriminators. Ask Archer has it too.

## Two APIs, one loop

[`llm.py`](../../archer/agents/llm.py) adapts the loop to Anthropic's Messages API and to the OpenAI-compatible Chat Completions API that every other provider speaks. The differences are only in shape: where the system prompt goes, how a tool request is marked up (a `tool_use` content block, or `tool_calls` with the arguments as a JSON string), and how results go back (one user message of `tool_result` blocks, or one `tool` message per result). The loop, the tools and the approvals don't change.

## History

Each session is saved to SQLite (`agent_runs`) as it runs: the task, every tool call and result preview, approvals, the answer and token counts. The Agents page lists recent runs and replays any of them; the console has `agent/history`. A run the server was in the middle of when it restarted shows as interrupted. The model's conversation is saved after every complete turn, so an interrupted run, one you stopped, or one that hit its turn limit can carry on: **Continue** on the Agents page, or `agent/history` with `SESSION <id>` and `CONTINUE true`. It gets another full set of turns.

> **Continue needs the same provider.** A run continues only on the provider it started on, because the saved conversation is in that provider's API shape: Anthropic's tool_use and tool_result blocks, with thinking blocks, can't be sent to an OpenAI-compatible API, and the reverse. The model can change within the provider (e.g. Sonnet to Opus), not the provider. If that provider is no longer configured in your profile, Continue is refused with that reason; add the key back, or start a new run on another provider. The Agents page names the provider on the Continue button, and `agent/history` prints it before continuing. Runs from before this change have no saved conversation and can only be replayed.

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
claude mcp add archer --env ARCHER_TOKEN=arch_... -- /path/to/archer/.venv/bin/python -m archer.mcp_server
```

Create the token in Profile → Security → API Tokens. It's shown once, works with MFA, and revoking it signs out whatever uses it; `ARCHER_EMAIL` and `ARCHER_PASSWORD` still work for accounts without MFA.

`archer-cli mcp` exposes the same 21 tools the agents use, with the 5 changing tools marked as not read-only so the client asks first, plus the five agents' instructions as prompts (`repair`, `ask`, `triage`, `sweep`, `audit`). It signs in to a running Archer as you, so hunts use your AI settings and your keys stay on the server.

## Building your own

**A tool** is a `Tool(name, description, input_schema, fn, changes=False)` in [`archer/agents/tools.py`](../../archer/agents/tools.py). Write the description for the model: say what it returns and when to use it. Keep results small (the runtime truncates at 20,000 characters) and return errors as text the model can act on. If the tool needs server logic, add it to `archer/client.py` so the console and MCP server get it too.

**An agent** is an `Agent(name, title, summary, system, inputs, tools, task)` in [`definitions.py`](../../archer/agents/definitions.py). Most of the work is in the system prompt: what good looks like, the order to work in, what not to do, and what to finish with. Give it the fewest tools that do the job; every extra tool is another wrong turn it can take.

**Testing** without spending money: [`tests/unit/test_agent_runtime.py`](../../tests/unit/test_agent_runtime.py) scripts the model's responses and checks the loop, approvals, errors and turn limits.

## Local models

On local `qwen3:8b` through Ollama, the Ask agent answered "which of FIN7's Execution techniques have no detection?" correctly in 2 turns (one `group_coverage` call), taking about 110 seconds on an Intel Mac Mini. Small models get through short lookups like that; on longer runs (repair, triage) they tend to stop early, skip the check step, or call tools with malformed arguments. Two settings matter:

- **Context.** Ollama defaults to 4k tokens and truncates silently, and one tool result can be 5k. `archer-cli start` runs Ollama with `OLLAMA_CONTEXT_LENGTH=16384` unless you set it yourself.
- **Tool support.** The model has to support tool calling (qwen3, qwen2.5, llama3.1, mistral do; base and coder-base models don't).

## Known gaps


- **A run continues only on the provider it started on.** Anthropic and OpenAI-compatible APIs shape tool calls and results differently, and the saved conversation is in the original shape. Fix: convert between the two shapes on resume (tool_use/tool_result blocks ↔ tool_calls/tool messages; Anthropic thinking blocks would be dropped).
