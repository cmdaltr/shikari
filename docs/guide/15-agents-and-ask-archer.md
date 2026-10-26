# Agents and Ask Archer

Both need an AI model. Set one up under Profile → API Keys first: a cloud provider's API key, or a local model's server URL (Ollama, LM Studio, llama.cpp).

## Ask Archer

The **Ask Archer** button (bottom right of the Home page) opens a chat about ATT&CK techniques, threat groups, SIEM queries and your own detections: "Give me a Splunk query for Scattered Spider", "What does T1003.006 look like in Defender?". **⛶** expands it.

It uses the provider assigned to Ask Archer in Profile → API Keys → AI Assignment, and falls back to another configured provider if that one fails. A local model can answer Ask Archer; for now, detection generation needs a cloud provider.

## Agents

**Build → Agents** runs a model in a loop with Archer's tools: it picks a tool, reads the result, and picks again until it has an answer. Every step is shown as it happens and kept, so you can read back what it did.

| Agent | Give it | It does |
|---|---|---|
| Detection repair | A run | Runs the static and precision checks over the run's queries, fixes only what they flag, re-checks each fix, and saves it with a reason. A query that still fails the checks can't be saved |
| Ask Archer with tools | A question | Answers from your Library, coverage, ATT&CK and hunts, not only the model's memory |
| Intel triage | A threat report | Finds your coverage gaps for it, suggests hunts, and writes a briefing |
| Coverage sweep | A group (optionally one tactic) | Lists the group's techniques with no detection, hunts the gaps, and reports what closed and what can't be |
| Library audit | Optional focus (platform, tag or technique) | Reviews the saved library for duplicate and overlapping detections, and flags ones resting on noisy indicators (recorded across many unrelated techniques — a likely false-positive source). Reports only — it changes nothing |

| Control | What it does |
|---|---|
| Model | Which provider runs it. Claude is the most reliable at multi-step tool use; small local models often stop early or call tools wrongly |
| Ask before actions that change something | On by default: a hunt, a saved query fix and anything else that changes something waits for you to allow it |
| Stop, Continue | Stop a run, or carry a stopped one on |
| Recent runs | Every step and every decision, kept across restarts |

**How this agent is built** shows each agent's instructions, its tools, and which tools need approval.

The same agents are in the console (`agent/repair`, `agent/ask`, `agent/triage`, `agent/sweep`, `agent/audit`) and in any MCP client through `archer-cli mcp`. The design, the loop and the checks are explained in [Agents in Archer](../agents/README.md).
