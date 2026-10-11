"""
LLM Provider Abstraction Layer
Unified interface for multiple AI model providers
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import os


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider"""
    content: str
    model: str
    provider: str
    tokens_used: int
    cost_estimate: float
    metadata: Dict[str, Any]


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> LLMResponse:
        """Generate completion from prompt"""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return provider name (anthropic, openai, etc)"""
        pass

    @abstractmethod
    def estimate_cost(self, tokens: int) -> float:
        """Estimate cost for token count"""
        pass


def _create_message(client, kwargs: Dict):
    """
    messages.create, dropping the parameters a model refuses: newer models (Sonnet 5.5
    on) reject temperature, older ones reject thinking type "between_tools".
    """
    import anthropic

    for _ in range(3):
        try:
            return client.messages.create(**kwargs)
        except anthropic.BadRequestError as e:
            refused = [k for k in ("temperature", "thinking") if k in kwargs and k in str(e)]
            if not refused:
                raise
            for key in refused:
                kwargs.pop(key)
    return client.messages.create(**kwargs)


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
        # False for long structured answers: newer models think by default and can spend
        # the whole output budget thinking (a 116k-char detection prompt did, 16k tokens)
        self.think = True

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> LLMResponse:
        messages = [{"role": "user", "content": prompt}]

        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        if not self.think:
            kwargs["thinking"] = {"type": "between_tools"}

        response = _create_message(self.client, kwargs)

        tokens_used = response.usage.input_tokens + response.usage.output_tokens

        return LLMResponse(
            content="".join(b.text for b in response.content if b.type == "text"),  # thinking blocks come first on newer models
            model=self.model,
            provider="anthropic",
            tokens_used=tokens_used,
            cost_estimate=self.estimate_cost(tokens_used),
            metadata={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "stop_reason": response.stop_reason,
            }
        )

    def get_provider_name(self) -> str:
        return "anthropic"

    def estimate_cost(self, tokens: int) -> float:
        # Claude Sonnet 4.5 pricing (as of 2025)
        # $3 per million input tokens, $15 per million output tokens
        # Rough estimate: 70/30 split input/output
        input_tokens = tokens * 0.7
        output_tokens = tokens * 0.3
        cost = (input_tokens * 3 / 1_000_000) + (output_tokens * 15 / 1_000_000)
        return round(cost, 6)


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
            self.model = model
        except ImportError:
            raise ImportError("OpenAI package not installed. Install with: pip install openai")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> LLMResponse:
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )

        tokens_used = response.usage.total_tokens

        return LLMResponse(
            content=response.choices[0].message.content,
            model=self.model,
            provider="openai",
            tokens_used=tokens_used,
            cost_estimate=self.estimate_cost(tokens_used),
            metadata={
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
                "finish_reason": response.choices[0].finish_reason
            }
        )

    def get_provider_name(self) -> str:
        return "openai"

    def estimate_cost(self, tokens: int) -> float:
        # GPT-4o pricing: $2.50 per million input, $10 per million output
        input_tokens = tokens * 0.7
        output_tokens = tokens * 0.3
        cost = (input_tokens * 2.5 / 1_000_000) + (output_tokens * 10 / 1_000_000)
        return round(cost, 6)


class GeminiProvider(LLMProvider):
    """Google Gemini provider"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.0-flash-exp"):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key or os.getenv("GOOGLE_API_KEY"))
            self.model_obj = genai.GenerativeModel(model)
            self.model_name = model
        except ImportError:
            raise ImportError("Google Generative AI package not installed. Install with: pip install google-generativeai")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> LLMResponse:
        # Combine system and user prompts for Gemini
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        response = self.model_obj.generate_content(
            full_prompt,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens
            }
        )

        # Gemini doesn't provide token counts in response
        # Rough estimate based on character count
        tokens_used = len(full_prompt + response.text) // 4

        return LLMResponse(
            content=response.text,
            model=self.model_name,
            provider="google",
            tokens_used=tokens_used,
            cost_estimate=self.estimate_cost(tokens_used),
            metadata={
                "finish_reason": response.candidates[0].finish_reason.name if response.candidates else None
            }
        )

    def get_provider_name(self) -> str:
        return "google"

    def estimate_cost(self, tokens: int) -> float:
        # Gemini 2.0 Flash pricing: Free tier, then $0.075 per million input
        input_tokens = tokens * 0.7
        output_tokens = tokens * 0.3
        cost = (input_tokens * 0.075 / 1_000_000) + (output_tokens * 0.30 / 1_000_000)
        return round(cost, 6)


class OllamaProvider(LLMProvider):
    """Local Ollama provider for on-premise LLMs"""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama2"):
        try:
            import requests
            self.base_url = base_url.rstrip("/")
            self.model = model
            self.session = requests.Session()
        except ImportError:
            raise ImportError("Requests package not installed. Install with: pip install requests")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> LLMResponse:
        import requests

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        response = self.session.post(
            f"{self.base_url}/api/generate",
            json=payload
        )
        response.raise_for_status()

        data = response.json()

        return LLMResponse(
            content=data["response"],
            model=self.model,
            provider="ollama",
            tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
            cost_estimate=0.0,  # Local models are free
            metadata={
                "eval_count": data.get("eval_count", 0),
                "prompt_eval_count": data.get("prompt_eval_count", 0),
                "eval_duration": data.get("eval_duration", 0)
            }
        )

    def get_provider_name(self) -> str:
        return "ollama"

    def estimate_cost(self, tokens: int) -> float:
        return 0.0  # Local models have no API cost


# Rough per-million-token rates (USD, input/output) for cost estimation only —
# see the disclaimer in OpenAICompatibleProvider.estimate_cost. Last checked
# against public pricing pages 2026-07-17.
_CLOUD_RATES = {
    "deepseek": (0.27, 1.10),
    "qwen": (0.50, 1.50),
    "grok": (2.00, 10.00),
    "ollama": (0.0, 0.0),
    "osaurus": (0.0, 0.0),
}


class OpenAICompatibleProvider(LLMProvider):
    """
    Generic provider for any OpenAI-compatible chat/completions API.

    Covers cloud providers that mirror the OpenAI wire format (DeepSeek, Qwen's
    DashScope compatible-mode endpoint, xAI/Grok) as well as local OpenAI-compatible
    servers (Ollama's /v1 endpoint, Osaurus) -- the only differences are base_url,
    whether an API key is required, and the model name.
    """

    def __init__(
        self,
        provider_name: str,
        base_url: str,
        api_key: Optional[str] = None,
        model: str = "default",
        requires_key: bool = True,
    ):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("OpenAI package not installed. Install with: pip install openai")

        if requires_key and not api_key:
            raise ValueError(f"{provider_name} requires an API key but none was provided")

        self.provider_name = provider_name
        self.model = model
        # Local OpenAI-compatible servers (Ollama, Osaurus) ignore the key but the
        # client still requires a non-empty string.
        self.client = OpenAI(api_key=api_key or "not-required", base_url=base_url.rstrip("/"))

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )

        usage = getattr(response, "usage", None)
        tokens_used = usage.total_tokens if usage else 0

        return LLMResponse(
            content=response.choices[0].message.content,
            model=self.model,
            provider=self.provider_name,
            tokens_used=tokens_used,
            cost_estimate=self.estimate_cost(tokens_used),
            metadata={
                "input_tokens": getattr(usage, "prompt_tokens", None) if usage else None,
                "output_tokens": getattr(usage, "completion_tokens", None) if usage else None,
                "finish_reason": response.choices[0].finish_reason,
            }
        )

    def get_provider_name(self) -> str:
        return self.provider_name

    def estimate_cost(self, tokens: int) -> float:
        """
        Rough, non-authoritative cost estimate. None of these vendors expose a
        machine-readable pricing API — their rates live on human-facing pricing
        pages only — so this cannot be a live lookup. _CLOUD_RATES below is a
        static table, last checked against public pricing pages 2026-07-17;
        treat it as a ballpark for relative cost comparison, not a billing figure,
        and re-check vendor pricing pages before relying on it for cost control.
        """
        input_rate, output_rate = _CLOUD_RATES.get(self.provider_name, (0.0, 0.0))
        input_tokens = tokens * 0.7
        output_tokens = tokens * 0.3
        cost = (input_tokens * input_rate / 1_000_000) + (output_tokens * output_rate / 1_000_000)
        return round(cost, 6)


class DeepSeekProvider(OpenAICompatibleProvider):
    """DeepSeek cloud provider (OpenAI-compatible API)."""

    def __init__(self, api_key: Optional[str] = None, model: str = "deepseek-chat", base_url: Optional[str] = None):
        super().__init__(
            provider_name="deepseek",
            base_url=base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            api_key=api_key or os.getenv("DEEPSEEK_API_KEY"),
            model=model,
            requires_key=True,
        )


class QwenProvider(OpenAICompatibleProvider):
    """Alibaba Qwen cloud provider via DashScope's OpenAI-compatible mode."""

    def __init__(self, api_key: Optional[str] = None, model: str = "qwen-plus", base_url: Optional[str] = None):
        super().__init__(
            provider_name="qwen",
            base_url=base_url or os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
            api_key=api_key or os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY"),
            model=model,
            requires_key=True,
        )


class GrokProvider(OpenAICompatibleProvider):
    """xAI Grok cloud provider (OpenAI-compatible API)."""

    def __init__(self, api_key: Optional[str] = None, model: str = "grok-2-latest", base_url: Optional[str] = None):
        super().__init__(
            provider_name="grok",
            base_url=base_url or os.getenv("XAI_BASE_URL", "https://api.x.ai/v1"),
            api_key=api_key or os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY"),
            model=model,
            requires_key=True,
        )


class OsaurusProvider(OpenAICompatibleProvider):
    """
    Local Osaurus provider -- a native macOS local LLM server with an
    OpenAI-compatible API, defaulting to port 1337.
    """

    def __init__(self, base_url: Optional[str] = None, model: str = "default"):
        super().__init__(
            provider_name="osaurus",
            base_url=base_url or os.getenv("OSAURUS_BASE_URL", "http://localhost:1337/v1"),
            api_key=None,
            model=model,
            requires_key=False,
        )


class LLMFactory:
    """Factory for creating LLM provider instances"""

    @staticmethod
    def create(
        provider: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs
    ) -> LLMProvider:
        """
        Create LLM provider instance

        Args:
            provider: Provider name (anthropic, openai, google, ollama)
            api_key: API key for the provider (if needed)
            model: Specific model to use
            **kwargs: Additional provider-specific arguments
        """

        provider = provider.lower()

        if provider == "anthropic":
            return AnthropicProvider(api_key=api_key, model=model)
        elif provider == "openai":
            return OpenAIProvider(api_key=api_key, model=model or "gpt-4o")
        elif provider == "google" or provider == "gemini":
            return GeminiProvider(api_key=api_key, model=model or "gemini-2.0-flash-exp")
        elif provider == "ollama":
            base_url = kwargs.get("base_url", "http://localhost:11434")
            return OllamaProvider(base_url=base_url, model=model or "llama2")
        elif provider == "deepseek":
            return DeepSeekProvider(api_key=api_key, model=model or "deepseek-chat", base_url=kwargs.get("base_url"))
        elif provider == "qwen":
            return QwenProvider(api_key=api_key, model=model or "qwen-plus", base_url=kwargs.get("base_url"))
        elif provider == "grok":
            return GrokProvider(api_key=api_key, model=model or "grok-2-latest", base_url=kwargs.get("base_url"))
        elif provider == "osaurus":
            return OsaurusProvider(base_url=kwargs.get("base_url"), model=model or "default")
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    @staticmethod
    def get_available_providers() -> List[str]:
        """Get list of available providers"""
        return ["anthropic", "openai", "google", "deepseek", "qwen", "grok", "ollama", "osaurus"]
