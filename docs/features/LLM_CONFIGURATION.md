# LLM Configuration Guide

Shikari's `--llm` mode generates high-fidelity detection queries by sending technique data and bespoke prompt templates to an LLM. This guide covers how to configure each supported provider.

## Supported Providers

| Provider | Use Case | Auth |
|----------|----------|------|
| **Anthropic Claude** | Cloud API (Claude Sonnet/Opus) | API key |
| **OpenAI** | ChatGPT API (GPT-4o, etc.) | API key |
| **ChatGPT Enterprise** | Corporate OpenAI with custom domain | API key + base URL |
| **Azure OpenAI** | Corporate Azure-hosted GPT models | API key + endpoint + deployment |
| **Microsoft Copilot** | Same as Azure OpenAI | API key + endpoint + deployment |
| **Local / Self-hosted** | Ollama, vLLM, LiteLLM, llama.cpp | HTTP endpoint |

## Quick Start

### Option A: Environment Variables (simplest)

Set the variables for your provider and run:

```bash
# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
shikari console
shikari > use generate
shikari (generate) > set GROUP APT29
shikari (generate) > set MODE llm
shikari (generate) > run

# OpenAI / ChatGPT
export OPENAI_API_KEY="sk-..."

# Azure OpenAI / Copilot
export AZURE_OPENAI_KEY="your-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"

# Local (Ollama, vLLM, etc.)
export LLM_ENDPOINT="http://localhost:11434"
```

### Option B: Config File (recommended for teams)

Edit `bespoke/config.yaml`:

```bash
cp bespoke/config.yaml.example bespoke/config.yaml
```

Then configure the `llm:` section (see provider-specific examples below).

## Provider Configuration

### Anthropic Claude

**Environment variables:**
```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

**Or in `bespoke/config.yaml`:**
```yaml
llm:
  provider: anthropic
  api_key: "sk-ant-api03-..."
  model: "claude-sonnet-4-20250514"    # or claude-opus-4-20250514
  max_tokens: 4096
```

### OpenAI / ChatGPT

**Environment variables:**
```bash
export OPENAI_API_KEY="sk-..."
```

**Or in `bespoke/config.yaml`:**
```yaml
llm:
  provider: openai
  api_key: "sk-..."
  model: "gpt-4o"
  max_tokens: 4096
```

### ChatGPT Enterprise

ChatGPT Enterprise uses the OpenAI API with a custom base URL provided by your organisation.

**In `bespoke/config.yaml`:**
```yaml
llm:
  provider: openai
  api_key: "your-enterprise-api-key"
  base_url: "https://your-org.api.openai.com"   # Your corporate endpoint
  model: "gpt-4o"
  max_tokens: 4096
```

Your IT/security team will provide the `base_url` and API key. The model name depends on what your organisation has deployed.

### Azure OpenAI / Microsoft Copilot

Azure OpenAI uses a different authentication mechanism (API key header instead of Bearer token) and a URL that includes your resource name and deployment.

**Environment variables:**
```bash
export AZURE_OPENAI_KEY="your-azure-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"           # Your deployment name
export AZURE_OPENAI_API_VERSION="2024-06-01"       # Optional, defaults to 2024-06-01
```

**Or in `bespoke/config.yaml`:**
```yaml
llm:
  provider: azure
  api_key: "your-azure-key"
  endpoint: "https://your-resource.openai.azure.com"
  deployment: "gpt-4o"
  api_version: "2024-06-01"
```

**Finding your Azure OpenAI details:**
1. Go to [Azure Portal](https://portal.azure.com) > your Azure OpenAI resource
2. **Endpoint**: Under "Resource Management" > "Keys and Endpoint"
3. **API Key**: Same page, Key 1 or Key 2
4. **Deployment name**: Under "Resource Management" > "Model deployments"

Microsoft Copilot uses Azure OpenAI under the hood — use `provider: azure` with your Copilot endpoint.

### Local / Self-hosted LLMs

Any OpenAI-compatible HTTP endpoint works. This covers:
- [Ollama](https://ollama.ai) — `http://localhost:11434`
- [vLLM](https://github.com/vllm-project/vllm) — `http://localhost:8000`
- [LiteLLM](https://github.com/BerriAI/litellm) — proxy that unifies 100+ providers
- [llama.cpp server](https://github.com/ggerganov/llama.cpp) — `http://localhost:8080`
- [text-generation-inference](https://github.com/huggingface/text-generation-inference)

**Environment variables:**
```bash
export LLM_ENDPOINT="http://localhost:11434"
```

**Or in `bespoke/config.yaml`:**
```yaml
llm:
  provider: local
  endpoint: "http://localhost:11434"
  model: "llama3"                      # Model name as your server knows it
  max_tokens: 4096
```

**Ollama example:**
```bash
# Start Ollama with a model
ollama pull llama3
ollama serve

# Configure Shikari
export LLM_ENDPOINT="http://localhost:11434"
shikari console
shikari > use generate
shikari (generate) > set MODE llm
shikari (generate) > set GROUP APT29
shikari (generate) > run
```

## Resolution Order

When `--llm` mode is used, Shikari resolves the LLM provider in this order:

1. **Explicit config** passed via code (API/shikari console)
2. **`bespoke/config.yaml`** → `llm:` section
3. **Environment variables** (auto-detected by provider)

Within environment variable auto-detection, the order is:
1. `ANTHROPIC_API_KEY`
2. `AZURE_OPENAI_KEY` + `AZURE_OPENAI_ENDPOINT`
3. `OPENAI_API_KEY`
4. `LLM_ENDPOINT`

## Security Notes

- **Never commit API keys** to git. The `bespoke/config.yaml` file is gitignored by default.
- For CI/CD or shared environments, use environment variables instead of the config file.
- Azure OpenAI keys can be rotated in the Azure Portal without downtime (use Key 1/Key 2 rotation).
- Local LLM endpoints don't require API keys but should be firewalled to localhost.

## Troubleshooting

### "No LLM configured"
Set at least one provider via env vars or `bespoke/config.yaml`.

### Azure OpenAI 401 Unauthorized
- Check your API key is correct (Key 1 or Key 2 from Azure Portal)
- Verify the endpoint URL includes your resource name
- Ensure the deployment exists and is active

### Azure OpenAI 404 Not Found
- Check the deployment name matches exactly (case-sensitive)
- Verify the API version is supported (try `2024-06-01`)

### ChatGPT Enterprise connection refused
- Confirm the `base_url` with your IT team — it may require VPN access
- Some enterprise deployments use a proxy; set `HTTPS_PROXY` if needed

### Local LLM timeout
- Increase timeout: the default is 300s for local endpoints
- Check the model is loaded: `curl http://localhost:11434/api/tags` (Ollama)
- Ensure enough RAM/VRAM for the model
