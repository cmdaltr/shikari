#!/usr/bin/env python3
"""
Test script for LLM provider abstraction layer
"""

import os
import sys

# Add archer to path
sys.path.insert(0, os.path.dirname(__file__))

from archer.ai.llm.providers import LLMFactory, AnthropicProvider


def test_llm_factory():
    """Test LLM factory and provider creation"""

    print("Testing LLM Provider Abstraction Layer...")
    print("=" * 60)

    # Test 1: List available providers
    print("\n1. Available Providers:")
    providers = LLMFactory.get_available_providers()
    for provider in providers:
        print(f"   - {provider}")

    # Test 2: Create Anthropic provider (without API call)
    print("\n2. Testing Anthropic Provider:")
    try:
        # Note: This will work even without API key since we're not making calls
        anthropic = LLMFactory.create("anthropic")
        print(f"   ✓ Provider created: {anthropic.get_provider_name()}")
        print(f"   ✓ Cost estimation works: ${anthropic.estimate_cost(1000):.6f} per 1K tokens")
    except Exception as e:
        print(f"   ✗ Failed: {e}")
        return False

    # Test 3: Test provider switching via environment
    print("\n3. Testing Provider Selection:")
    original_provider = os.getenv("LLM_PROVIDER")

    # Test Anthropic (default)
    os.environ["LLM_PROVIDER"] = "anthropic"
    provider = LLMFactory.create(os.getenv("LLM_PROVIDER", "anthropic"))
    print(f"   ✓ Default provider: {provider.get_provider_name()}")

    # Restore original
    if original_provider:
        os.environ["LLM_PROVIDER"] = original_provider
    else:
        os.environ.pop("LLM_PROVIDER", None)

    # Test 4: Test invalid provider
    print("\n4. Testing Error Handling:")
    try:
        LLMFactory.create("invalid_provider")
        print("   ✗ Should have raised ValueError")
        return False
    except ValueError as e:
        print(f"   ✓ Correctly rejects invalid provider: {e}")

    # Test 5: Test cost estimation for different providers
    print("\n5. Cost Estimation Comparison (per 1K tokens):")
    test_tokens = 1000

    try:
        anthropic = LLMFactory.create("anthropic")
        print(f"   - Anthropic Claude: ${anthropic.estimate_cost(test_tokens):.6f}")
    except Exception as e:
        print(f"   - Anthropic Claude: Not available ({e})")

    try:
        openai = LLMFactory.create("openai")
        print(f"   - OpenAI GPT-4o: ${openai.estimate_cost(test_tokens):.6f}")
    except Exception as e:
        print(f"   - OpenAI GPT-4o: Not installed (install with: pip install openai)")

    try:
        gemini = LLMFactory.create("google")
        print(f"   - Google Gemini: ${gemini.estimate_cost(test_tokens):.6f}")
    except Exception as e:
        print(f"   - Google Gemini: Not installed (install with: pip install google-generativeai)")

    try:
        ollama = LLMFactory.create("ollama")
        print(f"   - Ollama (Local): ${ollama.estimate_cost(test_tokens):.6f} (Free)")
    except Exception as e:
        print(f"   - Ollama: Not available ({e})")

    print("\n" + "=" * 60)
    print("✓ All basic tests passed!")
    print("\nNote: To test actual API calls, set the appropriate API keys:")
    print("  - ANTHROPIC_API_KEY for Claude")
    print("  - OPENAI_API_KEY for GPT")
    print("  - GOOGLE_API_KEY for Gemini")
    print("  - Ollama server running at http://localhost:11434")

    return True


def test_integration_with_generators():
    """Test that generators can use the LLM abstraction"""

    print("\n" + "=" * 60)
    print("Testing Integration with Detection Generators...")
    print("=" * 60)

    # Test SecOps generator
    print("\n1. Testing SecOps Generator:")
    try:
        from archer.build.secops import SecOpsGenerator

        # Create with default provider
        gen = SecOpsGenerator()
        print(f"   ✓ SecOps generator created with LLM provider")

        # Create with specific provider
        provider = LLMFactory.create("anthropic")
        gen_with_provider = SecOpsGenerator(llm_provider=provider)
        print(f"   ✓ SecOps generator accepts custom LLM provider")
    except Exception as e:
        print(f"   ✗ Failed: {e}")
        return False

    # Test Elastic generator
    print("\n2. Testing Elastic Generator:")
    try:
        from archer.build.elastic import ElasticQueryGenerator

        # Create with default provider
        gen = ElasticQueryGenerator()
        print(f"   ✓ Elastic generator created with LLM provider")

        # Create with specific provider
        provider = LLMFactory.create("anthropic")
        gen_with_provider = ElasticQueryGenerator(llm_provider=provider)
        print(f"   ✓ Elastic generator accepts custom LLM provider")
    except Exception as e:
        print(f"   ✗ Failed: {e}")
        return False

    print("\n✓ Integration tests passed!")
    return True


if __name__ == "__main__":
    success = test_llm_factory()
    if success:
        success = test_integration_with_generators()

    sys.exit(0 if success else 1)
