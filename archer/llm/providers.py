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


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")

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

        response = self.client.messages.create(**kwargs)

        tokens_used = response.usage.input_tokens + response.usage.output_tokens

        return LLMResponse(
            content=response.content[0].text,
            model=self.model,
            provider="anthropic",
            tokens_used=tokens_used,
            cost_estimate=self.estimate_cost(tokens_used),
            metadata={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
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
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    @staticmethod
    def get_available_providers() -> List[str]:
        """Get list of available providers"""
        return ["anthropic", "openai", "google", "ollama"]
