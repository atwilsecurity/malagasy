# AIProbe

**AI Security Testing Framework** — covers the gaps that existing tools miss: **RAG Security**, **Agent/Tool-Use Testing**, and **Multi-Modal Attacks**.

Built to complement frameworks like PyRIT, Garak, NeMo Guardrails, TextAttack, PromptInject, LLM Guard, and Rebuff by targeting attack surfaces they don't cover.

## What It Tests

### RAG Security (5 modules)
- **Knowledge Poisoning** — adversarial documents that corrupt model outputs
- **Retrieval Manipulation** — SQL injection, cross-tenant access, metadata extraction via RAG queries
- **Indirect Injection** — hidden instructions in retrieved documents that hijack model behavior
- **Citation Hallucination** — fabricated sources, misattributed references, confident hallucination under pressure
- **Context Overflow** — lost-in-the-middle attacks, attention dilution, context boundary spoofing

### Agent / Tool-Use Security (5 modules)
- **Unauthorized Tool Use** — tricking models into calling non-existent or restricted tools
- **Privilege Escalation** — path traversal, write via read-only interfaces, social engineering
- **Tool Chain Abuse** — dangerous multi-step tool sequences (read → exfiltrate, write → execute)
- **Agent Hijacking** — malicious instructions in web pages, file contents, or API responses that redirect agent behavior
- **Scope Creep** — gradual role expansion, capability assertion, authority chain manipulation

### Multi-Modal Attacks (4 modules)
- **Image Injection** — adversarial text embedded in images
- **Cross-Modal Exploits** — split instructions across text + image to bypass filters
- **Steganographic Attacks** — LSB-encoded hidden data in image pixels
- **OCR Bypass** — rotated text, font obfuscation, adversarial typography

## Quick Start

```bash
# Install
pip install -e .

# Generate config template
aiprobe init -o myconfig.yaml

# Run full scan
aiprobe scan \
  -e https://your-model.openai.azure.com \
  -k $AZURE_OPENAI_API_KEY \
  -m gpt-4 \
  -i medium

# Run specific module category
aiprobe scan -e $ENDPOINT -k $KEY --modules rag
aiprobe scan -e $ENDPOINT -k $KEY --modules agent
aiprobe scan -e $ENDPOINT -k $KEY --modules multimodal

# List all modules
aiprobe modules
```

## Configuration

### CLI Options
```
-e, --endpoint     LLM API endpoint URL (required)
-k, --api-key      API key (required)
-p, --provider     azure_openai | openai | anthropic | custom
-m, --model        Model name or deployment
--modules          all | rag | agent | multimodal
-i, --intensity    low | medium | high
-o, --output       Output directory (default: ./aiprobe_results)
--format           json | html | both
-c, --config       Path to YAML config file
```

### YAML Config
Copy `aiprobe.example.yaml` and customize:
```yaml
llm:
  provider: azure_openai
  endpoint: https://your-model.openai.azure.com
  api_key: your-key
  model: gpt-4

rag:
  enabled: true
agent:
  enabled: true
multimodal:
  enabled: true
  vision_enabled: true

attack_intensity: medium
```

## Supported Providers

| Provider | Config Value | Notes |
|----------|-------------|-------|
| Azure OpenAI | `azure_openai` | Requires `deployment_name` and `api_version` |
| OpenAI | `openai` | Standard OpenAI API |
| Anthropic | `anthropic` | Claude models |
| Custom | `custom` | Any OpenAI-compatible endpoint |

## Reports

Reports are generated in JSON and/or HTML format. The HTML report includes:
- Overall risk score with severity breakdown
- Per-module results table
- Detailed findings with attack payloads, model responses, evidence, remediation guidance, and OWASP mappings

## OWASP LLM Top 10 Coverage

| OWASP | Coverage |
|-------|----------|
| LLM01: Prompt Injection | RAG indirect injection, image injection, cross-modal, agent hijacking |
| LLM02: Insecure Output Handling | Tool parameter validation, dangerous output patterns |
| LLM03: Training Data Poisoning | RAG knowledge poisoning (runtime equivalent) |
| LLM06: Sensitive Info Disclosure | Retrieval manipulation, context overflow, metadata extraction |
| LLM07: Insecure Plugin Design | Unauthorized tool use, tool chain abuse |
| LLM08: Excessive Agency | Privilege escalation, scope creep, agent hijacking |
| LLM09: Overreliance | Citation hallucination, fabricated sources |

## Architecture

```
aiprobe/
├── cli.py                          # CLI entry point
├── core/
│   ├── config.py                   # Configuration management
│   ├── engine.py                   # Test orchestration
│   ├── llm_client.py               # Multi-provider LLM client
│   ├── models.py                   # Data models (findings, results)
│   └── reporter.py                 # JSON + HTML report generation
└── modules/
    ├── base.py                     # Base test module class
    ├── rag/
    │   ├── knowledge_poisoning.py  # 8 poisoning payloads
    │   ├── retrieval_manipulation.py # 5 retrieval attack vectors
    │   ├── indirect_injection.py   # 6 indirect injection techniques
    │   ├── citation_hallucination.py # 3 hallucination tests
    │   └── context_overflow.py     # 3 context window exploits
    ├── agent/
    │   ├── unauthorized_tools.py   # 5 unauthorized tool tests
    │   ├── privilege_escalation.py # 4 escalation scenarios
    │   ├── tool_chain_abuse.py     # 4 chain abuse patterns
    │   ├── agent_hijacking.py      # 4 hijacking via tool results
    │   └── scope_creep.py          # 4 incremental scope tests
    └── multimodal/
        ├── image_injection.py      # 5 image-based injections
        ├── cross_modal_exploit.py  # 4 cross-modal attacks
        ├── steganographic_attack.py # 3 steganographic tests
        └── ocr_bypass.py           # 4 OCR bypass techniques
```

## Requirements

- Python 3.10+
- Dependencies: `openai`, `httpx`, `rich`, `click`, `pydantic`, `Pillow`, `jinja2`, `pyyaml`, `numpy`

## License

Apache 2.0
