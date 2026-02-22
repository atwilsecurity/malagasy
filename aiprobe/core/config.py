"""Configuration management for AIProbe."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: str = "azure_openai"  # azure_openai | openai | anthropic | custom
    endpoint: str = ""
    api_key: str = ""
    model: str = "gpt-4"
    deployment_name: str = ""  # Azure-specific
    api_version: str = "2024-02-01"  # Azure-specific
    max_tokens: int = 4096
    temperature: float = 0.0
    timeout: int = 60


class RAGConfig(BaseModel):
    """RAG-specific test configuration."""

    enabled: bool = True
    knowledge_base_url: Optional[str] = None  # URL to RAG knowledge base API
    embedding_endpoint: Optional[str] = None
    retrieval_endpoint: Optional[str] = None
    document_upload_endpoint: Optional[str] = None
    num_poisoning_attempts: int = 10
    num_retrieval_probes: int = 15
    num_injection_payloads: int = 20
    test_indirect_injection: bool = True
    test_citation_hallucination: bool = True
    test_context_overflow: bool = True


class AgentConfig(BaseModel):
    """Agent/tool-use test configuration."""

    enabled: bool = True
    available_tools: list[str] = Field(default_factory=lambda: [
        "web_search", "code_execution", "file_read", "file_write",
        "database_query", "api_call", "email_send", "calculator"
    ])
    agent_endpoint: Optional[str] = None  # Agent API endpoint
    function_calling_enabled: bool = True
    max_tool_calls_per_turn: int = 5
    num_escalation_attempts: int = 10
    num_hijacking_attempts: int = 15
    test_tool_chain_abuse: bool = True
    test_scope_creep: bool = True


class MultiModalConfig(BaseModel):
    """Multi-modal attack test configuration."""

    enabled: bool = True
    vision_enabled: bool = True
    audio_enabled: bool = False  # Most models don't support yet
    image_generation_enabled: bool = False
    num_image_injection_tests: int = 10
    num_cross_modal_tests: int = 10
    num_steganographic_tests: int = 5
    test_ocr_bypass: bool = True
    generated_image_dir: str = "/tmp/aiprobe_images"


class ProbeConfig(BaseModel):
    """Main configuration for AIProbe."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    multimodal: MultiModalConfig = Field(default_factory=MultiModalConfig)

    # General settings
    output_dir: str = "./aiprobe_results"
    report_format: str = "json"  # json | html | both
    verbose: bool = False
    parallel: bool = False
    max_concurrent: int = 3
    attack_intensity: str = "medium"  # low | medium | high

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ProbeConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @classmethod
    def from_env(cls) -> "ProbeConfig":
        """Build config from environment variables."""
        return cls(
            llm=LLMConfig(
                provider=os.getenv("AIPROBE_PROVIDER", "azure_openai"),
                endpoint=os.getenv("AIPROBE_ENDPOINT", os.getenv("AZURE_OPENAI_ENDPOINT", "")),
                api_key=os.getenv("AIPROBE_API_KEY", os.getenv("AZURE_OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))),
                model=os.getenv("AIPROBE_MODEL", "gpt-4"),
                deployment_name=os.getenv("AIPROBE_DEPLOYMENT", ""),
                api_version=os.getenv("AIPROBE_API_VERSION", "2024-02-01"),
            )
        )

    def to_yaml(self, path: str | Path):
        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)

    def validate_config(self) -> list[str]:
        """Return list of validation errors, empty if valid."""
        errors = []
        if not self.llm.endpoint:
            errors.append("LLM endpoint is required")
        if not self.llm.api_key:
            errors.append("LLM API key is required")
        if self.rag.enabled and not self.llm.endpoint:
            errors.append("RAG tests require a valid LLM endpoint")
        if self.multimodal.enabled and not self.multimodal.vision_enabled:
            errors.append("Multi-modal tests require vision_enabled=true")
        return errors
