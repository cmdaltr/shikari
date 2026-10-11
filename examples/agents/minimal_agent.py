"""
A complete agent in one file: a model, two tools and the loop that connects them.

It answers questions about a folder of detection YAML files ("do we detect T1003.001?",
"which detections use DeviceProcessEvents?") by searching and reading the files itself.
Nothing here depends on Archer: point it at any folder.

    pip install anthropic
    export ANTHROPIC_API_KEY=...
    python minimal_agent.py data/groups "Do we have a detection for LSASS dumping with comsvcs.dll?"

Archer's own agents (archer/agents) are this loop plus approvals, a trace and sessions.
"""

import json
import pathlib
import sys

import anthropic

MODEL = "claude-sonnet-5-5"
FOLDER = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")


# 1. Tools: ordinary functions, plus a description the model reads to decide when to use them.

def search_files(text: str) -> list:
    """Files whose content contains the text (case-insensitive), with the first matching line."""
    hits = []
    for path in sorted(FOLDER.glob("*.y*ml")):
        for line in path.read_text(errors="ignore").splitlines():
            if text.lower() in line.lower():
                hits.append({"file": path.name, "line": line.strip()[:200]})
                break
    return hits[:30]


def read_file(name: str) -> str:
    """One file's full content."""
    path = (FOLDER / name).resolve()
    if path.parent != FOLDER.resolve() or not path.is_file():  # stay inside the folder
        return f"No file named {name}"
    return path.read_text(errors="ignore")[:20000]


TOOLS = {
    "search_files": (search_files, "Search the detection files for text: a technique ID, table, process name.",
                     {"text": {"type": "string", "description": "Text to look for"}}),
    "read_file": (read_file, "Read one detection file in full.",
                  {"name": {"type": "string", "description": "File name from search_files"}}),
}
TOOL_SPECS = [{"name": name, "description": desc,
               "input_schema": {"type": "object", "properties": props, "required": list(props)}}
              for name, (_, desc, props) in TOOLS.items()]

SYSTEM = ("You answer questions about a folder of SIEM detection files. Search and read the files "
          "before answering; quote the file names you relied on. If nothing covers the question, say so.")


# 2. The loop: ask the model; run any tools it asks for; send the results back; repeat.

def run(question: str, max_turns: int = 10) -> str:
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": question}]
    for turn in range(max_turns):
        response = client.messages.create(model=MODEL, max_tokens=4000, system=SYSTEM,
                                          tools=TOOL_SPECS, messages=messages)
        messages.append({"role": "assistant", "content": response.content})

        calls = [block for block in response.content if block.type == "tool_use"]
        if not calls:  # no tools requested: this is the answer
            return "".join(block.text for block in response.content if block.type == "text")

        results = []
        for call in calls:
            fn = TOOLS[call.name][0]
            print(f"  → {call.name}({json.dumps(call.input)})", file=sys.stderr)
            try:
                output = fn(**call.input)
                results.append({"type": "tool_result", "tool_use_id": call.id, "content": json.dumps(output)})
            except Exception as e:  # errors go back to the model, which can try something else
                results.append({"type": "tool_result", "tool_use_id": call.id, "content": str(e), "is_error": True})
        messages.append({"role": "user", "content": results})
    return f"(stopped after {max_turns} turns)"


if __name__ == "__main__":
    question = sys.argv[2] if len(sys.argv) > 2 else "Which techniques do these detections cover?"
    print(run(question))
