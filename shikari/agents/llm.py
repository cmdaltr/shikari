"""
The model side of the agent loop, for two tool-calling APIs.

Anthropic's Messages API, and the OpenAI-compatible Chat Completions API that OpenAI,
DeepSeek, Qwen (DashScope), Grok, Gemini and local servers (Ollama, LM Studio, llama.cpp)
all speak. The loop in runtime.py is the same for both; only the message shapes differ:

                    Anthropic                              OpenAI-compatible
    tools           {name, description, input_schema}      {type: function, function: {name, description, parameters}}
    system prompt   system=...                             first message, role "system"
    tool request    content block {type: tool_use}         message.tool_calls[] (arguments as a JSON string)
    tool result     user message, block {type: tool_result} one message per result, role "tool"
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

# OpenAI-compatible base URLs for the cloud providers in shikari.ai.assignment
OPENAI_COMPATIBLE = {
    "openai": "https://api.openai.com/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "grok": "https://api.x.ai/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai",
}

_THINK = re.compile(r"<think>.*?</think>\s*", re.S)


@dataclass
class Call:
    id: str
    name: str
    input: Dict


@dataclass
class Reply:
    text: str
    calls: List[Call]
    input_tokens: int
    output_tokens: int
    stop_reason: str
    message: Any = None              # the assistant message to send back next turn
    extra: Dict = field(default_factory=dict)


def _block(block) -> Dict:
    if block.type == "text":
        return {"type": "text", "text": block.text}
    if block.type == "tool_use":
        return {"type": "tool_use", "id": block.id, "name": block.name, "input": block.input or {}}
    return block.model_dump(exclude_none=True)


class AnthropicChat:
    def __init__(self, llm: Dict):
        import anthropic

        self.client = anthropic.Anthropic(api_key=llm["api_key"])
        self.model = llm["model"]

    def turn(self, system: str, tools: List[Dict], messages: List, max_tokens: int) -> Reply:
        from shikari.ai.llm.providers import _create_message

        response = _create_message(self.client, {
            "model": self.model, "max_tokens": max_tokens, "system": system,
            "tools": tools, "messages": messages,
        })
        # The whole response goes back next turn, thinking blocks included: the API needs
        # them to continue a tool-using turn. As plain dicts, so a saved session can resume
        return Reply(
            text="".join(b.text for b in response.content if b.type == "text").strip(),
            calls=[Call(b.id, b.name, b.input or {}) for b in response.content if b.type == "tool_use"],
            input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens,
            stop_reason=response.stop_reason or "", message={"role": "assistant", "content": [_block(b) for b in response.content]},
        )

    def results(self, results: List[Dict]) -> List[Dict]:
        return [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": r["id"], "content": r["content"], "is_error": r["error"]}
            for r in results]}]


class OpenAIChat:
    def __init__(self, llm: Dict):
        from openai import OpenAI

        self.client = OpenAI(api_key=llm.get("api_key") or "not-required", base_url=llm["base_url"], timeout=600)
        self.model = llm["model"]

    def turn(self, system: str, tools: List[Dict], messages: List, max_tokens: int) -> Reply:
        functions = [{"type": "function", "function": {
            "name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools]
        response = self.client.chat.completions.create(
            model=self.model, max_tokens=max_tokens, tools=functions,
            messages=[{"role": "system", "content": system}] + messages,
        )
        choice = response.choices[0]
        message = choice.message
        calls = []
        for tc in message.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except ValueError:
                args = {"_unparsed": tc.function.arguments}
            calls.append(Call(tc.id, tc.function.name, args if isinstance(args, dict) else {"value": args}))
        # Local reasoning models (qwen3, deepseek-r1) can put their reasoning inline
        text = _THINK.sub("", message.content or "").strip()
        sent = {"role": "assistant", "content": message.content or ""}
        if message.tool_calls:
            sent["tool_calls"] = [{"id": tc.id, "type": "function", "function": {
                "name": tc.function.name, "arguments": tc.function.arguments or "{}"}} for tc in message.tool_calls]
        usage = response.usage
        return Reply(
            text=text, calls=calls,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            stop_reason=choice.finish_reason or "", message=sent,
        )

    def results(self, results: List[Dict]) -> List[Dict]:
        return [{"role": "tool", "tool_call_id": r["id"],
                 "content": ("Error: " if r["error"] else "") + r["content"]} for r in results]


def chat_for(llm: Dict):
    """The adapter for a resolved agent model (shikari.agents.agent_llm)."""
    return AnthropicChat(llm) if llm.get("provider", "anthropic") == "anthropic" else OpenAIChat(llm)
