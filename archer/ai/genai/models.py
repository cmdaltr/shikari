"""
Advanced query generation using AI models with domain-specific knowledge.
"""

import os
import json
import requests
from typing import Dict, List, Optional, Tuple
import importlib.util
import time
import hashlib
from ...config import AI_CACHE_DIR


class QueryGeneratorBase:
    """Base class for query generation with AI models."""
    
    def __init__(self, config_file: str = None):
        """
        Initialize the query generator.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config = self._load_config(config_file)
        self.cache_dir = self.config.get("cache_dir", AI_CACHE_DIR)
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _load_config(self, config_file: str = None) -> Dict:
        """Load configuration from file or use defaults."""
        default_config = {
            "cache_dir": AI_CACHE_DIR,
            "cache_ttl": 86400,  # 1 day in seconds
            "model": "default",
            "temperature": 0.2,
            "max_tokens": 1024
        }
        
        if not config_file or not os.path.exists(config_file):
            # Look for config in standard locations
            locations = [
                os.path.join("config", "ai_models.json"),
                os.path.join(os.path.dirname(__file__), "config.json")
            ]
            for loc in locations:
                if os.path.exists(loc):
                    config_file = loc
                    break
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except Exception as e:
                print(f"Error loading config file: {e}")
        
        return default_config
    
    def _cache_key(self, data: Dict) -> str:
        """Generate a cache key for the input data."""
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.md5(serialized.encode('utf-8')).hexdigest()
    
    def _check_cache(self, cache_key: str) -> Optional[Dict]:
        """Check if a result is cached."""
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                
                # Check if cache is expired
                if time.time() - cached.get("timestamp", 0) < self.config.get("cache_ttl", 86400):
                    return cached.get("result")
            except Exception:
                pass
        return None
    
    def _save_to_cache(self, cache_key: str, result: Dict):
        """Save a result to cache."""
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    "timestamp": time.time(),
                    "result": result
                }, f)
        except Exception as e:
            print(f"Error saving to cache: {e}")
    
    def combine_queries(self, query_a: str, query_b: str, platform: str, use_cache: bool = True) -> Dict:
        """
        Combine two queries using the AI model.
        
        Args:
            query_a: First query
            query_b: Second query
            platform: Query platform/vendor
            use_cache: Whether to use cached results
            
        Returns:
            Dict with combined query and metadata
        """
        # This is an abstract method to be implemented by subclasses
        raise NotImplementedError("Subclasses must implement this method")


class LocalLLMGenerator(QueryGeneratorBase):
    """Query generator using local LLM models."""
    
    def __init__(self, config_file: str = None):
        super().__init__(config_file)
        self.model = self._load_model()
    
    def _load_model(self):
        """Load the local LLM model based on configuration."""
        model_name = self.config.get("model", "default")
        model_path = self.config.get("model_path")
        
        # Check if llama-cpp-python is available
        if importlib.util.find_spec("llama_cpp"):
            try:
                from llama_cpp import Llama
                return Llama(model_path=model_path)
            except Exception as e:
                print(f"Error loading llama model: {e}")
        
        # Check if transformers is available
        elif importlib.util.find_spec("transformers"):
            try:
                from transformers import pipeline
                return pipeline("text-generation", model=model_name)
            except Exception as e:
                print(f"Error loading transformers model: {e}")
        
        print("No compatible LLM library found")
        return None
    
    def combine_queries(self, query_a: str, query_b: str, platform: str, use_cache: bool = True) -> Dict:
        """Combine queries using a local LLM model."""
        if not self.model:
            return {"error": "No LLM model available"}
        
        # Generate cache key
        cache_data = {"query_a": query_a, "query_b": query_b, "platform": platform}
        cache_key = self._cache_key(cache_data)
        
        # Check cache first
        if use_cache:
            cached = self._check_cache(cache_key)
            if cached:
                return cached
        
        # Prepare prompt
        prompt = self._create_prompt(query_a, query_b, platform)
        
        try:
            # Check model type and generate response
            if hasattr(self.model, "create_completion"):
                # llama-cpp model
                response = self.model.create_completion(
                    prompt=prompt, 
                    max_tokens=self.config.get("max_tokens", 1024),
                    temperature=self.config.get("temperature", 0.2)
                )
                generated_text = response.get("choices", [{}])[0].get("text", "")
            else:
                # Transformers pipeline
                response = self.model(
                    prompt,
                    max_length=len(prompt) + self.config.get("max_tokens", 1024),
                    temperature=self.config.get("temperature", 0.2),
                    do_sample=True
                )
                generated_text = response[0].get("generated_text", "")
                # Remove the prompt from the generated text
                if generated_text.startswith(prompt):
                    generated_text = generated_text[len(prompt):].strip()
            
            # Extract the combined query from the response
            result = self._extract_query(generated_text, platform)
            
            # Cache the result
            if use_cache:
                self._save_to_cache(cache_key, result)
            
            return result
        
        except Exception as e:
            return {"error": f"Error generating combined query: {str(e)}"}
    
    def _create_prompt(self, query_a: str, query_b: str, platform: str) -> str:
        """Create a prompt for the LLM."""
        platform_guides = {
            "splunk": """
            For Splunk queries:
            1. Use the same index for both queries if possible
            2. Combine search terms with OR in parentheses
            3. Include a time range (earliest=) if present in either query
            4. End with a stats or table command showing relevant fields
            5. Format with proper Splunk syntax
            """,
            
            "mde": """
            For Microsoft Defender (KQL) queries:
            1. If queries use the same table, combine where clauses with OR
            2. If different tables, use join or union operators
            3. Include a time filter (timestamp > ago(1d)) in the query
            4. Use project to select relevant fields
            5. Format with proper KQL syntax including line breaks
            """
        }
        
        platform_guide = platform_guides.get(platform.lower(), "")
        
        prompt = f"""
        You are a cybersecurity query expert. Combine these two queries into a single, efficient query.
        
        Platform: {platform}
        
        {platform_guide}
        
        Query A:
        ```
        {query_a}
        ```
        
        Query B:
        ```
        {query_b}
        ```
        
        Generate a combined query that searches for either query A's conditions OR query B's conditions.
        Return only the combined query without explanation, formatted with proper syntax.
        """
        
        return prompt
    
    def _extract_query(self, generated_text: str, platform: str) -> Dict:
        """Extract the combined query from the generated text."""
        # Look for code blocks
        import re
        code_block_pattern = r'```(?:\w*\n)?([\s\S]*?)```'
        matches = re.findall(code_block_pattern, generated_text)
        
        if matches:
            # Use the first code block
            combined_query = matches[0].strip()
        else:
            # No code blocks, use the whole text
            combined_query = generated_text.strip()
        
        return {
            "combined_query": combined_query,
            "platform": platform,
            "model": self.config.get("model", "local")
        }


# Provider ids that RemoteAPIGenerator can route to via LLMFactory. "local" endpoints
# (ollama/osaurus) accept an optional base_url override -- set at request time from
# whatever the startup detection actually found, via AI_LOCAL_BASE_URL/AI_LOCAL_MODEL.
_KNOWN_PROVIDERS = {"anthropic", "openai", "google", "deepseek", "qwen", "grok", "ollama", "osaurus"}
_LOCAL_PROVIDERS = {"ollama", "osaurus"}


class RemoteAPIGenerator(QueryGeneratorBase):
    """Query generator that delegates to any configured LLM provider (cloud or local-HTTP)."""

    def __init__(self, config_file: str = None, provider: str = "openai"):
        super().__init__(config_file)
        self.provider = provider if provider in _KNOWN_PROVIDERS else "openai"
        self.model = self.config.get("model") or None

    def combine_queries(self, query_a: str, query_b: str, platform: str, use_cache: bool = True) -> Dict:
        """Combine queries using the configured LLM provider."""
        # Generate cache key
        cache_data = {
            "query_a": query_a,
            "query_b": query_b,
            "platform": platform,
            "provider": self.provider,
            "model": self.model,
        }
        cache_key = self._cache_key(cache_data)

        # Check cache first
        if use_cache:
            cached = self._check_cache(cache_key)
            if cached:
                return cached

        # Prepare the messages for the API
        messages = self._create_messages(query_a, query_b, platform)
        system_prompt = messages[0]["content"] if messages and messages[0]["role"] == "system" else None
        user_prompt = messages[-1]["content"]

        try:
            from archer.ai.llm.providers import LLMFactory

            kwargs = {}
            if self.provider in _LOCAL_PROVIDERS:
                base_url = os.environ.get("AI_LOCAL_BASE_URL")
                if base_url:
                    kwargs["base_url"] = base_url
                model = self.model or os.environ.get("AI_LOCAL_MODEL")
            else:
                model = self.model

            llm = LLMFactory.create(self.provider, model=model, **kwargs)
            response = llm.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                temperature=self.config.get("temperature", 0.2),
                max_tokens=self.config.get("max_tokens", 1024),
            )

            result = self._extract_query(response.content, platform)
            result["provider"] = self.provider
            result["model"] = response.model

            if use_cache:
                self._save_to_cache(cache_key, result)

            return result

        except Exception as e:
            return {"error": f"Error calling {self.provider}: {str(e)}"}

    def _create_messages(self, query_a: str, query_b: str, platform: str) -> List[Dict]:
        """Create messages for the chat API."""
        system_prompts = {
            "splunk": """
            You are a Splunk query expert. Your task is to combine two Splunk queries into a single efficient query.
            Follow these guidelines:
            1. Use the same index for both queries if possible
            2. Combine search terms with OR in parentheses
            3. Include a time range (earliest=) if present in either query
            4. End with a stats or table command showing relevant fields
            5. Format with proper Splunk syntax
            Return ONLY the combined query without explanation or markdown formatting.
            """,
            
            "mde": """
            You are a Microsoft Defender and KQL query expert. Your task is to combine two queries into a single efficient query.
            Follow these guidelines:
            1. If queries use the same table, combine where clauses with OR
            2. If different tables, use join or union operators
            3. Include a time filter (timestamp > ago(1d)) in the query
            4. Use project to select relevant fields
            5. Format with proper KQL syntax including line breaks
            Return ONLY the combined query without explanation or markdown formatting.
            """
        }
        
        system_message = system_prompts.get(platform.lower(), 
            "You are a cybersecurity query expert. Combine two queries into one efficient query. Return only the combined query.")
        
        return [
            {"role": "system", "content": system_message},
            {"role": "user", "content": f"Combine these queries:\n\nQuery A:\n{query_a}\n\nQuery B:\n{query_b}"}
        ]
    
    def _extract_query(self, generated_text: str, platform: str) -> Dict:
        """Extract the combined query from the generated text."""
        # Clean up the generated text
        import re
        
        # Remove markdown code blocks if present
        code_block_pattern = r'```(?:\w*\n)?([\s\S]*?)```'
        matches = re.findall(code_block_pattern, generated_text)
        
        if matches:
            combined_query = matches[0].strip()
        else:
            combined_query = generated_text.strip()
        
        return {
            "combined_query": combined_query,
            "platform": platform,
            "model": self.model
        }


def get_generator(model_type: str = None, config_file: str = None):
    """
    Factory function to get an appropriate query generator.

    Args:
        model_type: 'local' (llama_cpp/transformers file-based model), 'api' (legacy
            alias for OpenAI), an explicit provider id (anthropic, openai, google,
            deepseek, qwen, grok, ollama, osaurus), or None for auto-detect.
        config_file: Path to configuration file

    Returns:
        A QueryGeneratorBase instance
    """
    if model_type:
        provider = model_type.lower()
        if provider in _KNOWN_PROVIDERS:
            return RemoteAPIGenerator(config_file, provider=provider)
        if provider == "api":
            return RemoteAPIGenerator(config_file, provider="openai")
        # Anything else ("local" or unrecognized) falls through to the
        # file-based local model loader below.

    # If no model_type specified, try to determine from environment
    if not model_type:
        # Check for API keys
        if os.environ.get("OPENAI_API_KEY"):
            model_type = "api"
        # Check for local models
        elif importlib.util.find_spec("llama_cpp") or importlib.util.find_spec("transformers"):
            model_type = "local"
        else:
            # Default to local as a fallback
            model_type = "local"

    if model_type.lower() == "api":
        return RemoteAPIGenerator(config_file, provider="openai")
    else:
        return LocalLLMGenerator(config_file)
