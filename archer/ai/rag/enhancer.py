"""
Query Enhancement using LLMs and Retrieved Examples.

Enhances detection queries using few-shot learning with high-quality examples.
"""

import os
from typing import List, Dict, Optional


class QueryEnhancer:
    """
    Enhance detection queries using LLMs and retrieved examples.

    Supports multiple LLM providers:
    - OpenAI (GPT-4, GPT-3.5)
    - Anthropic (Claude)
    - Ollama (local models)
    """

    def __init__(
        self,
        llm_provider: str = "openai",
        model: Optional[str] = None,
        temperature: float = 0.2
    ):
        """
        Initialize query enhancer.

        Args:
            llm_provider: LLM provider ("openai", "anthropic", "ollama")
            model: Optional model name (uses defaults if not specified)
            temperature: Temperature for generation (lower = more deterministic)
        """
        self.llm_provider = llm_provider.lower()
        self.model = model or self._get_default_model()
        self.temperature = temperature

    def _get_default_model(self) -> str:
        """Get default model for provider."""
        defaults = {
            "openai": "gpt-4",
            "anthropic": "claude-sonnet-5-5",
            "ollama": "llama2"
        }
        return defaults.get(self.llm_provider, "gpt-4")

    def enhance_query(
        self,
        original_query: str,
        examples: List[Dict],
        technique_id: Optional[str] = None,
        platform: Optional[str] = None
    ) -> str:
        """
        Enhance query using retrieved examples.

        Args:
            original_query: Original detection query
            examples: List of high-quality example detections
            technique_id: Optional technique ID for context
            platform: Optional platform for context

        Returns:
            Enhanced query
        """
        # Build prompt with examples
        prompt = self._build_prompt(
            original_query=original_query,
            examples=examples,
            technique_id=technique_id,
            platform=platform
        )

        # Call LLM
        try:
            if self.llm_provider == "openai":
                enhanced_query = self._call_openai(prompt)
            elif self.llm_provider == "anthropic":
                enhanced_query = self._call_anthropic(prompt)
            elif self.llm_provider == "ollama":
                enhanced_query = self._call_ollama(prompt)
            else:
                print(f"Warning: Unsupported provider {self.llm_provider}, returning original")
                return original_query

            return enhanced_query

        except Exception as e:
            print(f"Warning: LLM enhancement failed: {e}")
            return original_query

    def _build_prompt(
        self,
        original_query: str,
        examples: List[Dict],
        technique_id: Optional[str] = None,
        platform: Optional[str] = None
    ) -> str:
        """Build few-shot prompt with examples."""

        # System context
        context_parts = []
        if technique_id:
            context_parts.append(f"Technique: {technique_id}")
        if platform:
            context_parts.append(f"Platform: {platform}")

        context = " | ".join(context_parts) if context_parts else "detection query"

        # Format examples
        examples_text = []
        for i, example in enumerate(examples[:3], 1):  # Use top 3 examples
            detection = example['detection']
            fidelity = detection.get('fidelity_score', 'N/A')

            example_text = f"""Example {i} (Fidelity: {fidelity}):
{detection.get('query', '')}

Explanation: {detection.get('explanation', 'N/A')[:200]}"""

            examples_text.append(example_text)

        examples_section = "\n\n".join(examples_text)

        # Build complete prompt
        prompt = f"""You are an expert security detection engineer. Your task is to improve a {context} to reduce false positives and increase detection accuracy.

Below are {len(examples_text)} high-quality detection examples for reference:

{examples_section}

Original Query:
{original_query}

Instructions:
1. Analyze the high-quality examples above
2. Identify patterns that make them effective (specific indicators, appropriate filters, exclusions)
3. Improve the original query using lessons from the examples
4. Focus on: reducing false positives, increasing precision, and maintaining detection coverage
5. Keep the query syntax consistent with the original platform
6. Add appropriate exclusions for known false positive sources
7. Provide ONLY the improved query, no explanation

Improved Query:"""

        return prompt

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai package not installed. Install with: pip install openai")

        client = OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert security detection engineer specializing in writing high-fidelity threat detection queries."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=self.temperature,
            max_tokens=1000
        )

        enhanced_query = response.choices[0].message.content.strip()
        return enhanced_query

    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package not installed. Install with: pip install anthropic")

        client = anthropic.Anthropic(api_key=api_key)

        message = client.messages.create(
            model=self.model,
            max_tokens=1000,
            temperature=self.temperature,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        enhanced_query = "".join(b.text for b in message.content if b.type == "text").strip()
        return enhanced_query

    def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama API."""
        try:
            import requests
        except ImportError:
            raise ImportError("requests package not installed")

        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")

        response = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "temperature": self.temperature,
                "stream": False
            }
        )

        if response.status_code == 200:
            result = response.json()
            return result.get("response", "").strip()
        else:
            raise RuntimeError(f"Ollama API error: {response.status_code}")


def main():
    """Test query enhancement."""
    import sys

    # Test with sample query
    original_query = """index=windows EventCode=10 TargetImage="*lsass.exe" | stats count by SourceImage"""

    example = {
        'detection': {
            'query': '''index=windows EventCode=10 TargetImage="*\\\\lsass.exe"
(GrantedAccess=0x1010 OR GrantedAccess=0x1410)
| where NOT match(SourceImage, "(?i)(MsMpEng|MsSense|services)")
| stats count by SourceImage, GrantedAccess''',
            'explanation': 'Detects LSASS access with specific rights, excludes security software',
            'fidelity_score': 0.92
        },
        'similarity': 0.95
    }

    provider = sys.argv[1] if len(sys.argv) > 1 else "openai"

    print(f"Testing query enhancement with {provider}...")
    print()
    print("Original Query:")
    print(original_query)
    print()

    enhancer = QueryEnhancer(llm_provider=provider)
    enhanced = enhancer.enhance_query(
        original_query=original_query,
        examples=[example],
        technique_id="T1003.001",
        platform="Splunk"
    )

    print("Enhanced Query:")
    print(enhanced)


if __name__ == "__main__":
    main()
