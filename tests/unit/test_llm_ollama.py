"""Ollama gets a context that fits the prompt; reasoning blocks don't hide the answer."""
from unittest.mock import MagicMock, patch

import pytest

from archer.build import llm_queries


@pytest.mark.unit
def test_ollama_context_fits_the_prompt():
    # The OpenAI-compatible endpoint ran at 4096 tokens and cut a ~29k-token prompt
    resp = MagicMock(ok=True)
    resp.json.return_value = {"message": {"content": "{}"}, "prompt_eval_count": 30000}
    with patch("requests.get", return_value=MagicMock(ok=True)), patch("requests.post", return_value=resp) as post:
        llm_queries._call_local("x" * 115_000, "http://localhost:11434", {"model": "qwen3:8b"})
    url, body = post.call_args.args[0], post.call_args.kwargs["json"]
    assert url.endswith("/api/chat")
    assert body["options"]["num_ctx"] >= 115_000 / 3.5 + 4096
    assert body["think"] is False


@pytest.mark.unit
def test_think_block_is_ignored():
    text = '<think>{"maybe": 1}</think>{"technique_id": "T1003.001", "queries": [{"source_index": "DeviceProcessEvents", "query": "q"}]}'
    assert llm_queries.parse_llm_response(text)[0]["platform"] == "MDE"
