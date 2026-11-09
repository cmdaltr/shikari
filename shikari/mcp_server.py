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

Over HTTP, the running server answers MCP itself at /mcp (http_app, mounted by shikari/app.py):
nothing to install on the client, and each request acts as the owner of its bearer token.
  claude mcp add --transport http shikari https://<your-shikari-host>/mcp \
    --header "Authorization: Bearer shik_..."

Tools that change something (hunts, saving a query fix) are marked as not read-only, so
the client asks before calling them.
"""

import json
import logging
import os
import sys
from typing import Optional

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from shikari.agents.definitions import AGENTS
from shikari.agents.tools import ToolContext, build_tools
from shikari.client import ShikariClient, ShikariError

INSTRUCTIONS = """Shikari generates SIEM detections (Google SecOps UDM searches, Defender XDR KQL, Splunk SPL, Elastic) from \
MITRE ATT&CK groups, CVEs, techniques and threat reports. Read tools look things up (coverage, results, \
ATT&CK, the library) and check queries; hunt_* tools start runs that take minutes (follow with wait_for_run, \
then get_run_results); save_query_fix rewrites a query in a detection file (refused while it has errors). \
The prompts repair, ask and triage carry the instructions Shikari's own agents use."""


def _request_client(request) -> ShikariClient:
    """Over HTTP: the server's own routes as the bearer token's owner (the token middleware has checked it)."""
    port = (request.scope.get("server") or ("", 32453))[1]
    url = os.getenv("SHIKARI_INTERNAL_URL") or f"http://127.0.0.1:{port}"
    return ShikariClient(url=url, token=request.headers["authorization"][7:].strip(), timeout=300)


def build_server(client: Optional[ShikariClient] = None) -> Server:
    """client: stdio's one signed-in client; None for HTTP, where each request brings its own."""
    server = Server("shikari", instructions=INSTRUCTIONS)
    # definitions only: over HTTP the tools that run are bound to the request's client
    tools = {t.name: t for t in build_tools(ToolContext(client=client or ShikariClient(url="http://127.0.0.1")))}

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
        if client is None:
            caller = await anyio.to_thread.run_sync(_request_client, server.request_context.request)
            tool = build_tools(ToolContext(client=caller), names=[name])[0]
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


_http_server: Optional[Server] = None


async def _serve_http(scope, receive, send) -> None:
    """MCP over streamable HTTP, stateless with JSON responses: one transport per request, so no
    session state to lose on a restart. A request without an API token is refused."""
    from starlette.responses import JSONResponse
    from mcp.server.streamable_http import StreamableHTTPServerTransport

    global _http_server
    headers = dict(scope.get("headers") or [])
    if not headers.get(b"authorization", b"").lower().startswith(b"bearer "):
        await JSONResponse({"error": "Send an API token: Authorization: Bearer shik_... "
                                     "(Profile → Security → API tokens)"}, status_code=401)(scope, receive, send)
        return
    if _http_server is None:
        _http_server = build_server()
    transport = StreamableHTTPServerTransport(mcp_session_id=None, is_json_response_enabled=True)

    async def serve(*, task_status=anyio.TASK_STATUS_IGNORED):
        async with transport.connect() as (read, write):
            task_status.started()
            await _http_server.run(read, write, _http_server.create_initialization_options(), stateless=True)

    async with anyio.create_task_group() as tg:
        await tg.start(serve)
        try:
            await transport.handle_request(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                await transport.terminate()


class _HttpApp:
    # an ASGI app, not a function, so a Starlette Route at /mcp hands it the raw request
    async def __call__(self, scope, receive, send) -> None:
        await _serve_http(scope, receive, send)


http_app = _HttpApp()


def main() -> None:
    # stdout is the MCP channel: everything else goes to stderr
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
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
