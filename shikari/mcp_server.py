"""
Shikari as an MCP server: any MCP client (Claude Code, Claude Desktop, your own agent)
gets Shikari's tools, the same definitions Shikari's own agents use (shikari/agents/tools.py),
plus the three agents' instructions as prompts.

It talks to a running Shikari server as a user (shikari.client), so it does what the web
app does with that user's AI settings and keys, which never reach the MCP client.

  SHIKARI_URL=http://127.0.0.1:32453 SHIKARI_TOKEN=shik_... python -m shikari.mcp_server

Claude Code (the token is from Profile → Security → API tokens; SHIKARI_EMAIL and
SHIKARI_PASSWORD also work for accounts without MFA):
  claude mcp add shikari --env SHIKARI_TOKEN=shik_... -- /path/to/shikari/.venv/bin/python -m shikari.mcp_server

Tools that change something (hunts, saving a query fix) are marked as not read-only, so
the client asks before calling them.
"""

import json
import logging
import sys

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from shikari.agents.definitions import AGENTS
from shikari.agents.tools import ToolContext, build_tools
from shikari.client import ShikariClient, ShikariError

# stdout is the MCP channel: everything else goes to stderr
logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

INSTRUCTIONS = """Shikari generates SIEM detections (Google SecOps UDM searches, Defender XDR KQL, Splunk SPL, Elastic) from \
MITRE ATT&CK groups, CVEs, techniques and threat reports. Read tools look things up (coverage, results, \
ATT&CK, the library) and check queries; hunt_* tools start runs that take minutes (follow with wait_for_run, \
then get_run_results); save_query_fix rewrites a query in a detection file (refused while it has errors). \
The prompts repair, ask and triage carry the instructions Shikari's own agents use."""


def build_server(client: ShikariClient) -> Server:
    server = Server("shikari", instructions=INSTRUCTIONS)
    tools = {t.name: t for t in build_tools(ToolContext(client=client))}

    @server.list_tools()
    async def list_tools():
        return [types.Tool(
            name=t.name, description=t.description, inputSchema=t.input_schema,
            annotations=types.ToolAnnotations(readOnlyHint=not t.changes, destructiveHint=False,
                                              openWorldHint=t.name in ("analyse_report", "hunt_report", "hunt_cve")),
        ) for t in tools.values()]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        tool = tools.get(name)
        if tool is None:
            raise ValueError(f"No tool named {name}")
        try:
            # Tools make blocking HTTP calls (wait_for_run for up to 30 minutes)
            output = await anyio.to_thread.run_sync(lambda: tool.fn(**(arguments or {})))
        except ShikariError as e:
            raise ValueError(str(e))
        text = output if isinstance(output, str) else json.dumps(output, indent=1, default=str)
        return [types.TextContent(type="text", text=text)]

    @server.list_prompts()
    async def list_prompts():
        return [types.Prompt(
            name=a.name, title=a.title, description=a.summary,
            arguments=[types.PromptArgument(name=k, description=v.get("label"), required=bool(v.get("required")))
                       for k, v in a.inputs.items()],
        ) for a in AGENTS.values()]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None):
        agent = AGENTS.get(name)
        if agent is None:
            raise ValueError(f"No prompt named {name}")
        args = arguments or {}
        missing = [k for k, v in agent.inputs.items() if v.get("required") and not args.get(k)]
        if missing:
            raise ValueError(f"Missing: {', '.join(missing)}")
        text = f"{agent.system}\n\n---\n\n{agent.task(args)}"
        return types.GetPromptResult(description=agent.summary, messages=[
            types.PromptMessage(role="user", content=types.TextContent(type="text", text=text))])

    return server


def main() -> None:
    client = ShikariClient()
    try:
        client.login()  # fail now with a clear message rather than on the first tool call
    except ShikariError as e:
        print(f"shikari mcp: {e}", file=sys.stderr)
        sys.exit(1)
    server = build_server(client)

    async def run():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(run)


if __name__ == "__main__":
    main()
